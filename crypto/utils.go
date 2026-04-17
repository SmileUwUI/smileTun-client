package crypto

import (
	"crypto/sha256"
	"encoding/binary"
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
