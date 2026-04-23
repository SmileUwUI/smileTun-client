package client

import (
	"encoding/binary"
	"net"
	"smiletun-client/crypto"
	"smiletun-client/logger"
)

type Packet struct {
	SourceAddress      *net.IP
	DestinationAddress *net.IP
	Data               []byte
	logger             *logger.Logger
}

func NewPacket(data []byte, logger *logger.Logger) (packet *Packet) {
	sourceIP := net.IP(data[12:16])
	destIP := net.IP(data[16:20])
	return &Packet{
		SourceAddress:      &sourceIP,
		DestinationAddress: &destIP,
		Data:               data,
		logger:             logger,
	}
}

func (p *Packet) PackageAssembly(serialNumber uint32, salt [8]byte, key []byte) (finallyPacket []byte, err error) {
	plainPacket := make([]byte, 8+len(p.Data)) // salt (8 bytes) + data (n bytes)

	copy(plainPacket[0:8], salt[:])
	copy(plainPacket[8:len(p.Data)+8], p.Data)

	cipherPacket, nonce, err := crypto.EncryptChaCha20Poly1305(plainPacket, key)
	if err != nil {
		p.logger.Error("Failed to encrypt packet: %v", err)
		return nil, err

	}
	p.logger.Trace("Packet encrypted (cipher size: %d bytes)", len(cipherPacket))

	lenCipherPacketBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenCipherPacketBytes[0:2], uint16(len(nonce)+len(cipherPacket)+2))
	p.logger.Trace("Total packet size: %d bytes", len(nonce)+len(cipherPacket)+2)

	finallyPacket = make([]byte, len(nonce)+len(cipherPacket)+2+2)
	copy(finallyPacket[4:16], nonce)
	copy(finallyPacket[16:16+len(cipherPacket)], cipherPacket)
	finallyPacket = crypto.Trashfication(finallyPacket, 400, 1300)
	lenPacketBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPacketBytes[0:2], uint16(len(finallyPacket)))

	finallyPacket[0] = lenPacketBytes[0] ^ key[0]
	finallyPacket[1] = lenPacketBytes[1] ^ key[1]
	finallyPacket[2] = lenCipherPacketBytes[0] ^ key[2]
	finallyPacket[3] = lenCipherPacketBytes[1] ^ key[3]

	p.logger.Trace("Added trashfication (final size: %d bytes)", len(finallyPacket))

	return finallyPacket, nil
}
