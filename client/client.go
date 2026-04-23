package client

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"smiletun-client/crypto"
	"smiletun-client/logger"
	"smiletun-client/tunnel"
	"time"

	"github.com/vishvananda/netlink"
)

type Client struct {
	host         string
	port         int
	initPassword [32]byte
	username     [16]byte
	password     [16]byte
	conn         *net.TCPConn
	sessionKey   []byte
	tunnel       *tunnel.Tunnel
	logger       *logger.Logger
	countRecv    uint32
	countSent    uint32
}

func NewClient(host string, port int, initPassword [32]byte, username, password [16]byte, logger *logger.Logger) (client *Client, err error) {
	logger.Info("Getting default route information for host: %s", host)

	routeInfo, err := getDefaultRouteNetlink()
	if err != nil {
		logger.Error("Failed to get route information: %v", err)
		return nil, fmt.Errorf("error retrieving route information: %w", err)
	}

	logger.Debug("Default route found - Gateway: %s, Interface: %s", routeInfo.Gateway, routeInfo.Interface)

	logger.Debug("Adding server route: %s via %s dev %s", host, routeInfo.Gateway, routeInfo.Interface)
	cmd := exec.Command("ip", "route", "add", host,
		"via", routeInfo.Gateway, "dev", routeInfo.Interface)

	if err := cmd.Run(); err != nil && err.Error() != "exit status 2" {
		logger.Error("Failed to add server route: %v", err)
		return nil, fmt.Errorf("failed to add server route: %w", err)
	}

	logger.Debug("Server route added successfully")

	logger.Info("Creating TUN interface: smile-tun0")
	tun, err := tunnel.NewTunnel(
		"smile-tun0",
		1500,
		net.ParseIP("10.0.83.2"),
		net.IPv4Mask(255, 255, 255, 0),
		[]*net.IPNet{
			{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
		},
	)

	if err != nil {
		logger.Error("Failed to create tunnel: %v", err)
		return nil, fmt.Errorf("error create tunnel: %v", err)
	}

	logger.Info("TUN interface created successfully")

	return &Client{
		host:         host,
		port:         port,
		initPassword: initPassword,
		username:     username,
		password:     password,
		tunnel:       &tun,
		logger:       logger,
	}, nil
}

func (c *Client) Run() (err error) {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	c.logger.Info("Connecting to the server at %s", addr)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn.(*net.TCPConn)
	c.logger.Info("Connected to server successfully")

	timestamp := time.Now().Unix()
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

	c.logger.Debug("Creating authentication packet with timestamp: %d", timestamp)

	packet := make([]byte, 24)
	copy(packet[:16], c.username[:])
	copy(packet[16:], timestampBytes)

	c.logger.Debug("Encrypting authentication packet with init password")
	cipherPacket, nonce, _ := crypto.EncryptChaCha20Poly1305(packet, c.initPassword[:])

	rawPacket := make([]byte, len(nonce)+len(cipherPacket))

	copy(rawPacket[:12], nonce)
	copy(rawPacket[12:], cipherPacket)

	packet = crypto.Trashfication(rawPacket, 400, 1317)

	c.logger.Debug("Sending authentication packet (size: %d bytes)", len(packet))
	c.conn.Write(packet)
	c.logger.Info("Authentication packet sent")

	c.logger.Debug("Waiting for salt packet from server")
	saltPacket := make([]byte, 60)
	if _, err = io.ReadFull(conn, saltPacket); err != nil {
		c.logger.Error("Failed to read salt packet: %v", err)
		return
	}
	c.logger.Debug("Salt packet received (size: %d bytes)", len(saltPacket))

	nonce = saltPacket[:12]
	salt, err := crypto.DecryptChaCha20Poly1305(saltPacket[12:], nonce, c.initPassword[:])
	if err != nil {
		c.logger.Error("Failed to decrypt salt packet: %v", err)
		return
	}
	c.logger.Debug("Salt decrypted successfully")

	c.logger.Debug("Deriving session key from password and salt")
	sessionKeyHasher := sha256.New()
	sessionKeyHasher.Write(c.password[:])
	sessionKeyHasher.Write([]byte(":"))
	sessionKeyHasher.Write(salt)

	c.sessionKey = sessionKeyHasher.Sum(nil)
	c.logger.Info("Session key derived successfully")

	c.logger.Info("Starting tunnel")
	c.conn.SetNoDelay(true)
	c.startTunnel()

	return nil
}

func (c *Client) startTunnel() (err error) {
	c.logger.Info("Bringing TUN interface up")
	if err := (*c.tunnel).Up(); err != nil {
		c.logger.Error("Failed to bring TUN interface up: %v", err)
		return err
	}

	c.logger.Info("Tunnel %s is up with IP %s", (*c.tunnel).Name(), (*c.tunnel).IP())

	rawPacket := make([]byte, (*c.tunnel).MTU())

	c.logger.Info("Starting packet processing loop")
	for {
		n, err := (*c.tunnel).Read(rawPacket)

		if err != nil {
			c.logger.Error("Failed to read from tunnel: %v", err)
			return err
		}

		c.countSent++
		sourceAddress := rawPacket[12:16]
		destinationAddress := rawPacket[16:20]

		c.logger.Trace("Packet #%d", c.countSent)

		c.logger.Trace("\tSource: %d.%d.%d.%d", sourceAddress[0], sourceAddress[1], sourceAddress[2], sourceAddress[3])
		c.logger.Trace("\tDestination: %d.%d.%d.%d", destinationAddress[0], destinationAddress[1], destinationAddress[2], destinationAddress[3])
		c.logger.Trace("\tProtocol: %d", rawPacket[9])

		c.logger.Debug("Processing packet #%d (size: %d bytes)", c.countSent, n)

		packet := make([]byte, 4+8+n)
		serialNumber := make([]byte, 4)
		binary.BigEndian.PutUint32(serialNumber, c.countSent)

		salt := crypto.RandomBytes(8)

		copy(packet[:4], serialNumber)
		copy(packet[4:12], salt)
		copy(packet[12:n+12], packet[:n])

		c.logger.Trace("Encrypting packet with session key")
		cipherPacket, nonce, err := crypto.EncryptChaCha20Poly1305(packet, c.sessionKey[:])
		if err != nil {
			c.logger.Error("Failed to encrypt packet: %v", err)
			log.Printf("%v", err)
		}
		c.logger.Trace("Packet encrypted (cipher size: %d bytes)", len(cipherPacket))

		lenCipherPacketBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenCipherPacketBytes[0:2], uint16(len(nonce)+len(cipherPacket)+2))
		c.logger.Trace("Total packet size: %d bytes", len(nonce)+len(cipherPacket)+2)

		finallyPacket := make([]byte, len(nonce)+len(cipherPacket)+2+2)
		copy(finallyPacket[4:16], nonce)
		copy(finallyPacket[16:16+len(cipherPacket)], cipherPacket)
		finallyPacket = crypto.Trashfication(finallyPacket, 400, 1300)
		lenPacketBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenPacketBytes[0:2], uint16(len(finallyPacket)))

		finallyPacket[0] = lenPacketBytes[0] ^ c.sessionKey[0]
		finallyPacket[1] = lenPacketBytes[1] ^ c.sessionKey[1]
		finallyPacket[2] = lenCipherPacketBytes[0] ^ c.sessionKey[2]
		finallyPacket[3] = lenCipherPacketBytes[1] ^ c.sessionKey[3]

		c.logger.Trace("Added trashfication (final size: %d bytes)", len(finallyPacket))

		if _, err := c.conn.Write(finallyPacket); err != nil {
			c.logger.Error("Failed to send packet to server: %v", err)
			log.Printf("%v", err)
		}

		c.computNextSessionKey(salt)

		c.logger.Debug("Packet #%d sent to server", c.countSent)
		c.logger.Debug("_________________________")
	}

	return nil
}

func (c *Client) computNextSessionKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionKey = hasher.Sum(nil)
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
