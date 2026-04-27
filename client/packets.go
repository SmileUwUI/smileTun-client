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
	typePacket TypePacket
}

func NewPlainPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: PlainPacket,
	}
}

func NewRawPacket() (packet *StreamingPacket) {
	return &StreamingPacket{
		typePacket: RawPacket,
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

func (s *StreamingPacket) PackageAssembly(key, salt []byte) (err error) {
	if s.typePacket != PlainPacket {
		return errors.New("this operation is available only for the PlainPacket package type")
	}

	s.salt = salt
	var nonce []byte
	plainDataWithSalt := make([]byte, len(s.plainData)+len(salt))
	copy(plainDataWithSalt[:len(salt)], salt)
	copy(plainDataWithSalt[len(salt):], s.plainData)

	s.cipherData, nonce, err = crypto.EncryptChaCha20Poly1305(plainDataWithSalt, key)
	if err != nil {
		return fmt.Errorf("packet decryption error: %v", err)
	}

	s.rawData = make([]byte, len(s.cipherData)+len(nonce)+2+2) // size CipherData + size Nonce + size length RawData + size length CipherData

	binary.BigEndian.PutUint16(s.rawData[2:4], uint16(len(s.cipherData)+len(nonce)+2))
	copy(s.rawData[4:16], nonce)
	copy(s.rawData[16:], s.cipherData)

	s.rawData = crypto.Trashfication(s.rawData, 300, 1500)

	binary.BigEndian.PutUint16(s.rawData[:2], uint16(len(s.rawData)))

	s.rawData[0] = s.rawData[0] ^ key[0]
	s.rawData[1] = s.rawData[1] ^ key[1]
	s.rawData[2] = s.rawData[2] ^ key[2]
	s.rawData[3] = s.rawData[3] ^ key[3]

	return nil
}

func (s *StreamingPacket) DecodeAndDecrypt(key []byte, withSalt bool) (err error) {
	if s.typePacket != RawPacket {
		return errors.New("this operation is available only for the RawPacket package type")
	}

	lengthCipherDataBytes := s.rawData[2:4]
	lengthCipherDataBytes[0] = lengthCipherDataBytes[0] ^ key[2]
	lengthCipherDataBytes[1] = lengthCipherDataBytes[1] ^ key[3]

	lengthCipherData := binary.BigEndian.Uint16(lengthCipherDataBytes)
	s.cipherData = s.rawData[4 : lengthCipherData+2]

	s.plainData, err = crypto.DecryptChaCha20Poly1305(s.cipherData[12:], s.cipherData[:12], key)
	if err != nil {
		return fmt.Errorf("packet encryption error: %v", err)
	}

	if withSalt {
		s.salt = s.plainData[:8]
		s.plainData = s.plainData[8:]
	}

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
