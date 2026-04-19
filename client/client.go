package client

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"smiletun-client/crypto"
	"time"
)

type Client struct {
	host         string
	port         int
	initPassword [32]byte
	username     [16]byte
	password     [16]byte
	conn         net.Conn
	sessionKey   []byte
}

func NewClient(host string, port int, initPassword [32]byte, username, password [16]byte) (client *Client, err error) {

	return &Client{
		host:         host,
		port:         port,
		initPassword: initPassword,
		username:     username,
		password:     password,
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

	return nil
}
