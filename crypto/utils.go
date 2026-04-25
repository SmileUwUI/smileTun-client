package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	mathRand "math/rand/v2"
	"time"
)

func RandomBytes(lengthOutput int) (output []byte) {
	rawSeed := make([]byte, 8)
	binary.BigEndian.PutUint64(rawSeed, uint64(time.Now().UnixNano()))

	seedHash := sha256.New()
	seedHash.Write(rawSeed)

	generator := mathRand.NewChaCha8([32]byte(seedHash.Sum(nil)))
	output = make([]byte, lengthOutput)
	for i := range output {
		output[i] = byte(generator.Uint64() % 256)
	}

	return output
}

func Trashfication(source []byte, minLength, maxLength int) (result []byte) {
	if minLength > maxLength {
		minLength, maxLength = maxLength, minLength
	}

	if len(source) >= maxLength {
		result = make([]byte, len(source))
		copy(result, source)
		return result
	}

	targetLen := len(source)

	if minLength > targetLen {
		targetLen = minLength
	}

	if targetLen < maxLength {
		extra := rand.Intn(maxLength - targetLen + 1)
		targetLen += extra
	}

	result = make([]byte, targetLen)

	copy(result, source)

	for i := len(source); i < targetLen; i++ {
		result[i] = byte(rand.Intn(256))
	}

	return result
}
