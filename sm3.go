package gmtls

import (
	"crypto/hmac"
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

const (
	// SM3Size SM3 哈希输出大小（字节）
	SM3Size = 32
	// SM3BlockSize SM3 分组大小（字节）
	SM3BlockSize = 64
	// SM3WordSize SM3 字大小（字节）
	SM3WordSize = 4
)

// NewSM3 returns a new SM3 hash.Hash.
func NewSM3() hash.Hash {
	return sm3.New()
}

// SM3 computes the SM3 hash of data.
func SM3(data []byte) [SM3Size]byte {
	return sm3.Sum(data)
}

// NewSM3HMAC returns an SM3 HMAC using key.
func NewSM3HMAC(key []byte) hash.Hash {
	return hmac.New(sm3.New, key)
}

// SM3HMAC computes SM3 HMAC.
func SM3HMAC(key, data []byte) []byte {
	h := NewSM3HMAC(key)
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// SM3KDF SM3 密钥派生函数 (Key Derivation Function).
func SM3KDF(z []byte, klen int) []byte {
	ct := (klen + SM3Size - 1) / SM3Size
	var out []byte
	for i := 1; i <= ct; i++ {
		msg := make([]byte, len(z)+4)
		copy(msg, z)
		msg[len(z)] = byte(i >> 24)
		msg[len(z)+1] = byte(i >> 16)
		msg[len(z)+2] = byte(i >> 8)
		msg[len(z)+3] = byte(i)
		h := SM3(msg)
		out = append(out, h[:]...)
	}
	return out[:klen]
}
