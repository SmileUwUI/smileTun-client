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
	conn         net.Conn
	sessionKey   []byte
	tunnel       *tunnel.Tunnel
}

func NewClient(host string, port int, initPassword [32]byte, username, password [16]byte) (client *Client, err error) {
	routeInfo, err := getDefaultRouteNetlink()
	if err != nil {
		return nil, fmt.Errorf("error retrieving route information: %w", err)
	}

	cmd := exec.Command("ip", "route", "add", host,
		"via", routeInfo.Gateway, "dev", routeInfo.Interface)

	if err := cmd.Run(); err != nil && err.Error() != "exit status 2" {
		return nil, fmt.Errorf("failed to add server route: %w", err)
	}

	tun, err := tunnel.NewTunnel(
		"smile-tun0",
		1500,
		net.ParseIP("10.0.83.1"),
		net.IPv4Mask(255, 255, 255, 0),
		[]*net.IPNet{
			{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("error create tunnel: %v", err)
	}

	return &Client{
		host:         host,
		port:         port,
		initPassword: initPassword,
		username:     username,
		password:     password,
		tunnel:       &tun,
	}, nil
}

func (c *Client) Run() (err error) {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn

	timestamp := time.Now().Unix()
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp))

	packet := make([]byte, 24)
	copy(packet[:16], c.username[:])
	copy(packet[16:], timestampBytes)

	cipherPacket, nonce, _ := crypto.EncryptChaCha20Poly1305(packet, c.initPassword[:])

	rawPacket := make([]byte, len(nonce)+len(cipherPacket))

	copy(rawPacket[:12], nonce)
	copy(rawPacket[12:], cipherPacket)

	packet = crypto.Trashfication(rawPacket, 400, 1317)

	c.conn.Write(packet)

	saltPacket := make([]byte, 60)
	if _, err = io.ReadFull(conn, saltPacket); err != nil {
		return
	}

	nonce = saltPacket[:12]
	salt, err := crypto.DecryptChaCha20Poly1305(saltPacket[12:], nonce, c.initPassword[:])

	sessionKeyHasher := sha256.New()
	sessionKeyHasher.Write(c.password[:])
	sessionKeyHasher.Write([]byte(":"))
	sessionKeyHasher.Write(salt)

	c.sessionKey = sessionKeyHasher.Sum(nil)

	c.startTunnel()

	return nil
}

func (c *Client) startTunnel() (err error) {
	if err := (*c.tunnel).Up(); err != nil {
		return err
	}

	log.Printf("Tunnel %s is up with IP %s", (*c.tunnel).Name(), (*c.tunnel).IP())

	packet := make([]byte, (*c.tunnel).MTU())
	for {
		n, err := (*c.tunnel).Read(packet)

		if err != nil {
			return err
		}

		sourceAddress := packet[12:16]
		destinationAddress := packet[16:20]

		log.Printf("Packet")
		log.Printf("\tSource: %d.%d.%d.%d", sourceAddress[0], sourceAddress[1], sourceAddress[2], sourceAddress[3])
		log.Printf("\tDestination: %d.%d.%d.%d", destinationAddress[0], destinationAddress[1], destinationAddress[2], destinationAddress[3])
		log.Printf("\tProtocol: %d", packet[9])

		packet = packet[:n]

		cipherPacket, nonce, err := crypto.EncryptChaCha20Poly1305(packet, c.sessionKey[:])
		if err != nil {
			log.Printf("%v", err)
		}

		lenPacketBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenPacketBytes[0:2], uint16(len(nonce)+len(cipherPacket)+2))

		finallyPacket := make([]byte, len(nonce)+len(cipherPacket)+2)
		finallyPacket[0] = lenPacketBytes[0] ^ c.sessionKey[0]
		finallyPacket[1] = lenPacketBytes[1] ^ c.sessionKey[1]

		copy(finallyPacket[2:14], nonce)
		copy(finallyPacket[14:14+len(cipherPacket)], cipherPacket)

		if _, err := c.conn.Write(crypto.Trashfication(finallyPacket, 400, 1300)); err != nil {
			log.Printf("%v", err)
		}

	}

	return nil
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

			fmt.Println(route)

			if info.Gateway != "" && info.Interface != "" {
				return info, nil
			}
		}
	}

	return nil, fmt.Errorf("default route not found")
}
