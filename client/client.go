package client

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"smiletun-client/crypto"
	"smiletun-client/logger"
	"smiletun-client/tunnel"
	"time"

	"github.com/vishvananda/netlink"
)

type Client struct {
	host           string
	port           int
	initPassword   [32]byte
	username       [16]byte
	password       [16]byte
	conn           *net.TCPConn
	sessionSentKey []byte
	sessionRecvKey []byte
	tunnel         *tunnel.Tunnel
	logger         *logger.Logger
	countRecv      uint32
	countSent      uint32

	stopCh chan struct{}
}

func NewClient(host string, port int, initPassword [32]byte, username, password [16]byte, logger *logger.Logger) (client *Client, err error) {
	routeInfo, err := getDefaultRouteNetlink()
	if err != nil {
		logger.Error("Failed to get route information: %v", err)
		return nil, fmt.Errorf("error retrieving route information: %w", err)
	}

	cmd := exec.Command("ip", "route", "add", host,
		"via", routeInfo.Gateway, "dev", routeInfo.Interface)

	if err := cmd.Run(); err != nil && err.Error() != "exit status 2" {
		logger.Error("Failed to add server route: %v", err)
		return nil, fmt.Errorf("failed to add server route: %w", err)
	}

	return &Client{
		host:         host,
		port:         port,
		initPassword: initPassword,
		username:     username,
		password:     password,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}, nil
}

func (c *Client) Run() (err error) {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn.(*net.TCPConn)
	c.conn.SetNoDelay(true)

	c.sessionRecvKey = c.initPassword[:]
	c.sessionSentKey = c.initPassword[:]

	packet := NewPlainPacket()

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(time.Now().Unix()))

	packet.AddData(c.username[:])
	packet.AddData(timestampBytes)

	packet.PackageAssembly(c.initPassword[:], []byte{})
	if _, err = c.conn.Write(packet.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet with username: %v", err)
		return err
	}

	saltPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the salt packet: %v", err)
		return err
	}

	err = saltPacket.DecodeAndDecrypt(c.initPassword[:], false)
	if err != nil {
		c.logger.Error("Error decoding and decrypting a salted packet: %v", err)
		return err
	}

	sessionSentKeyHasher := sha256.New()
	sessionSentKeyHasher.Write(c.password[:])
	sessionSentKeyHasher.Write([]byte(":"))
	sessionSentKeyHasher.Write(saltPacket.GetPlainData()[0:16])

	c.sessionSentKey = sessionSentKeyHasher.Sum(nil)

	sessionRecvKeyHasher := sha256.New()
	sessionRecvKeyHasher.Write(c.password[:])
	sessionRecvKeyHasher.Write([]byte(":"))
	sessionRecvKeyHasher.Write(saltPacket.GetPlainData()[16:32])

	c.sessionRecvKey = sessionRecvKeyHasher.Sum(nil)

	okPacket := NewPlainPacket()
	okPacket.AddData([]byte{0xFF})

	okPacket.PackageAssembly(c.sessionSentKey, []byte{})
	if _, err = c.conn.Write(okPacket.GetRawData()); err != nil {
		c.logger.Error("Error sending the connection establishment acknowledgment packet: %v", err)
		return err
	}

	ipPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the packet with IP address: %v", err)
		return err
	}
	ipPacket.DecodeAndDecrypt(c.sessionRecvKey, false)

	ip := ipPacket.GetPlainData()

	tun, err := tunnel.NewTunnel(
		"smile-tun0",
		1500,
		net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])),
		net.IPv4Mask(255, 255, 255, 0),
	)

	if err != nil {
		c.logger.Error("Failed to create tunnel: %v", err)
		return fmt.Errorf("error create tunnel: %v", err)
	}

	err = tun.Up()
	if err != nil {
		c.logger.Error("Failed to up tunnel: %v", err)
		return err
	}

	c.tunnel = &tun

	go c.startTunnel()
	go c.writerTunnel()

	return nil
}

func (c *Client) Stop() {
	close(c.stopCh)
}

func (c *Client) writerTunnel() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
			packet, err := c.readPacket()
			c.countRecv++
			if err != nil {
				c.logger.Error("Failed to read packet: %v", err)
				if err.Error() == "EOF" {
					return
				}
				continue
			}

			err = packet.DecodeAndDecrypt(c.sessionRecvKey, true)
			if err != nil {
				c.logger.Error("Failed to decrypt packet: %v", err)
				continue
			}

			_, err = (*c.tunnel).Write(packet.GetPlainData())

			if err != nil {
				c.logger.Error("Failed to write packet in tun: %v", err)
			}

			c.computNextSessionRecvKey(packet.GetSalt())
		}
	}
}

func (c *Client) readPacket() (packet *StreamingPacket, err error) {
	lenPacketBytes, err := c.read(2)
	if err != nil {
		c.logger.Error("%v", err)
		return nil, err
	}

	packet = NewRawPacket()
	packet.AddData(lenPacketBytes)

	lenPacketBytes[0] = lenPacketBytes[0] ^ c.sessionRecvKey[0]
	lenPacketBytes[1] = lenPacketBytes[1] ^ c.sessionRecvKey[1]
	lenPacket := binary.BigEndian.Uint16(lenPacketBytes)

	rawPacket, err := c.read(lenPacket - 2)
	if err != nil {
		return nil, err
	}
	packet.AddData(rawPacket)

	return packet, nil
}

func (c *Client) read(length uint16) (data []byte, err error) {
	if length == 0 {
		return []byte{}, nil
	}

	data = make([]byte, length)
	remaining := length
	offset := 0

	for remaining > 0 {
		n, err := c.conn.Read(data[offset:])
		if err != nil {
			return nil, err
		}
		remaining -= uint16(n)
		offset += n
	}

	return data, nil
}

func (c *Client) startTunnel() {
	if err := (*c.tunnel).Up(); err != nil {
		c.logger.Error("Failed to bring TUN interface up: %v", err)
		return
	}
	defer (*c.tunnel).Down()

	rawPacket := make([]byte, (*c.tunnel).MTU())

	for {
		select {
		case <-c.stopCh:
			return
		default:
			n, err := (*c.tunnel).Read(rawPacket)
			if err != nil {
				c.logger.Error("Failed to read from tunnel: %v", err)
				return
			}

			c.countSent++

			packet := NewPlainPacket()

			salt := crypto.RandomBytes(8)
			packet.AddData(rawPacket[:n])

			err = packet.PackageAssembly(c.sessionSentKey, salt)
			if err != nil {
				c.logger.Error("Error while building the package: %v", err)
				continue
			}

			if _, err := c.conn.Write(packet.GetRawData()); err != nil {
				c.logger.Error("Failed to send packet to server: %v", err)
				continue
			}

			c.computNextSessionSentKey(salt)

		}
	}
}

func (c *Client) computNextSessionSentKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionSentKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionSentKey = hasher.Sum(nil)
}

func (c *Client) computNextSessionRecvKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionRecvKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionRecvKey = hasher.Sum(nil)
}

type RouteInfo struct {
	Gateway   string
	Interface string
	Metric    int
}

func getDefaultRouteNetlink() (*RouteInfo, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)

	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	for _, route := range routes {
		if route.Dst != nil {
			info := &RouteInfo{}

			if route.Gw != nil {
				info.Gateway = route.Gw.String()
			}

			if route.LinkIndex > 0 {
				link, err := netlink.LinkByIndex(route.LinkIndex)
				if err == nil {
					info.Interface = link.Attrs().Name
				}
			}

			if info.Gateway != "" && info.Interface != "" {
				return info, nil
			}
		}
	}

	return nil, fmt.Errorf("default route not found")
}
