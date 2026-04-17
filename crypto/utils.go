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
	seedHash.Sum(rawSeed)

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

	currentLen := len(source)

	var targetLen int

	if currentLen > maxLength {
		targetLen = maxLength
	} else if currentLen < minLength {
		targetLen = minLength
	} else {
		targetLen = currentLen + rand.Intn(maxLength-currentLen+1)
	}

	result = make([]byte, targetLen)
	copy(result, source)

	for i := currentLen; i < targetLen; i++ {
		result[i] = byte(rand.Intn(256))
	}

	return result
}
