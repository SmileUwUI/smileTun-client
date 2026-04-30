package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"smiletun-client/crypto"
)

type TypePacket uint8

const (
	PlainPacket TypePacket = 0
	RawPacket   TypePacket = 1
)

type StreamingPacket struct {
	salt       []byte
	rawData    []byte
	plainData  []byte
	cipherData []byte
	publicKey  []byte
	fakeFlag   bool
	ecdhFlag   bool
	typePacket TypePacket
}

func NewPlainPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: PlainPacket,
		fakeFlag:   false,
		ecdhFlag:   false,
	}
}

func NewRawPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: RawPacket,
		fakeFlag:   false,
		ecdhFlag:   false,
	}
}

func (s *StreamingPacket) AddData(data []byte) {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	if s.typePacket == PlainPacket {
		s.plainData = append(s.plainData, dataCopy...)
	} else if s.typePacket == RawPacket {
		s.rawData = append(s.rawData, dataCopy...)
	}
}

func (s *StreamingPacket) PackageAssembly(key, salt, publicKey []byte, fake, ecdh bool) (err error) {
	if s.typePacket != PlainPacket {
		return errors.New("this operation is available only for the PlainPacket package type")
	}

	s.fakeFlag = fake
	s.ecdhFlag = ecdh
	s.publicKey = publicKey
	s.salt = salt
	var nonce []byte
	plainData := make([]byte, len(s.plainData)+len(salt)+len(s.publicKey))
	copy(plainData[:len(salt)], salt)
	if s.ecdhFlag {
		copy(plainData[len(salt):len(salt)+len(s.publicKey)], s.publicKey)
	}
	copy(plainData[len(salt)+len(s.publicKey):], s.plainData)

	s.cipherData, nonce, err = crypto.EncryptChaCha20Poly1305(plainData, key)
	if err != nil {
		return fmt.Errorf("packet decryption error: %v", err)
	}

	s.rawData = make([]byte, len(s.cipherData)+len(nonce)+2+2+1) // size CipherData + size Nonce + size length RawData + size length CipherData + size flags byte

	binary.BigEndian.PutUint16(s.rawData[3:5], uint16(len(s.cipherData)+len(nonce)+2))
	copy(s.rawData[5:17], nonce)
	copy(s.rawData[17:], s.cipherData)

	s.rawData = crypto.Trashfication(s.rawData, 300, 800)

	binary.BigEndian.PutUint16(s.rawData[:2], uint16(len(s.rawData)))

	flagsBytes, err := crypto.RandomBytes(1)
	flags := flagsBytes[0] & 0b11111100
	if s.fakeFlag {
		flags = flags | 0b00000001
	}
	if s.ecdhFlag {
		flags = flags | 0b00000010
	}

	s.rawData[0] = s.rawData[0] ^ key[0]
	s.rawData[1] = s.rawData[1] ^ key[1]
	s.rawData[2] = flags ^ key[2]
	s.rawData[3] = s.rawData[3] ^ key[3]
	s.rawData[4] = s.rawData[4] ^ key[4]

	return nil
}

func (s *StreamingPacket) DecodeAndDecrypt(key []byte, withSalt bool) (err error) {
	if s.typePacket != RawPacket {
		return errors.New("this operation is available only for the RawPacket package type")
	}

	lengthCipherDataBytes := s.rawData[3:5]
	flags := s.rawData[2] ^ key[2]
	lengthCipherDataBytes[0] = lengthCipherDataBytes[0] ^ key[3]
	lengthCipherDataBytes[1] = lengthCipherDataBytes[1] ^ key[4]

	s.ecdhFlag = (flags>>1)&1 == 1
	s.fakeFlag = flags&1 == 1
	if s.fakeFlag {
		return nil
	}

	lengthCipherData := binary.BigEndian.Uint16(lengthCipherDataBytes)
	s.cipherData = s.rawData[5 : lengthCipherData+3]

	s.plainData, err = crypto.DecryptChaCha20Poly1305(s.cipherData[12:], s.cipherData[:12], key)
	if err != nil {
		return fmt.Errorf("packet encryption error: %v", err)
	}

	offsetPlainData := 0
	if withSalt {
		s.salt = s.plainData[:8]
		offsetPlainData += 8
	}
	if s.ecdhFlag {
		s.publicKey = s.plainData[offsetPlainData : offsetPlainData+32]
		offsetPlainData += 32
	}
	s.plainData = s.plainData[offsetPlainData:]

	return nil
}

func (s *StreamingPacket) GetRawData() (data []byte) {
	return s.rawData
}

func (s *StreamingPacket) GetPlainData() (data []byte) {
	return s.plainData
}

func (s *StreamingPacket) GetSalt() (salt []byte) {
	return s.salt
}

func (s *StreamingPacket) GetPublicKey() (publicLey []byte) {
	return s.publicKey
}

func (s *StreamingPacket) GetEcdhFlag() (ecdhFlag bool) {
	return s.ecdhFlag
}
