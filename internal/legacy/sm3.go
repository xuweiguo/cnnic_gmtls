//go:build ignore
// +build ignore

package gmtls

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"
)

// SM3 哈希算法实现
// 基于 GM/T 0004-2012 标准

const (
	// SM3Size SM3 哈希输出大小（字节）
	SM3Size = 32
	// SM3BlockSize SM3 分组大小（字节）
	SM3BlockSize = 64
	// SM3WordSize SM3 字大小（字节）
	SM3WordSize = 4
)

// SM3 初始向量
var sm3InitIV = [8]uint32{
	0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
	0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
}

// SM3 压缩函数常量 T
func sm3T(j int) uint32 {
	if j < 16 {
		return 0x79cc4519
	}
	return 0x7a879d8a
}

// rotl 循环左移
func rotl(x uint32, n int) uint32 {
	// 确保 n 在 [0, 31] 范围内
	n &= 31
	return (x << n) | (x >> (32 - n))
}

// SM3 布尔函数 FF
func sm3FF(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

// SM3 布尔函数 GG
func sm3GG(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

// SM3 置换函数 P0
func sm3P0(x uint32) uint32 {
	return x ^ rotl(x, 9) ^ rotl(x, 17)
}

// SM3 置换函数 P1
func sm3P1(x uint32) uint32 {
	return x ^ rotl(x, 15) ^ rotl(x, 23)
}

// sm3 represents the partial evaluation of a checksum.
type sm3 struct {
	digest [8]uint32 // 当前哈希状态
	length uint64    // 消息总长度（位）
	x      [64]byte  // 缓冲区
	nx     int       // 缓冲区中的字节数
}

// New returns a new hash.Hash computing the SM3 checksum.
func NewSM3() hash.Hash {
	d := new(sm3)
	d.Reset()
	return d
}

// Reset resets the Hash to its initial state.
func (d *sm3) Reset() {
	d.digest = sm3InitIV
	d.length = 0
	d.nx = 0
}

// Write adds more data to the running hash.
// It never returns an error.
func (d *sm3) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.length += uint64(nn) * 8

	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == SM3BlockSize {
			d.block(d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}

	if len(p) >= SM3BlockSize {
		n := len(p) &^ (SM3BlockSize - 1)
		d.block(p[:n])
		p = p[n:]
	}

	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (d *sm3) Sum(b []byte) []byte {
	d0 := *d
	hash := d0.checkSum()
	return append(b, hash[:]...)
}

// Size returns the number of bytes Sum will return.
func (d *sm3) Size() int {
	return SM3Size
}

// BlockSize returns the hash's underlying block size.
func (d *sm3) BlockSize() int {
	return SM3BlockSize
}

// checkSum finalizes the hash and returns the digest
func (d *sm3) checkSum() [SM3Size]byte {
	// Save current state
	digest := d.digest
	length := d.length
	nx := d.nx
	var x [64]byte
	copy(x[:], d.x[:])

	// Padding
	var tmp [64]byte

	// Copy existing data
	copy(tmp[:], x[:nx])

	// Append 0x80
	tmp[nx] = 0x80

	if nx > 56 {
		// Need two blocks
		// First block: fill rest with zeros
		for i := nx + 1; i < 64; i++ {
			tmp[i] = 0
		}
		d.block(tmp[:])

		// Second block: all zeros except length
		for i := 0; i < 64; i++ {
			tmp[i] = 0
		}
	} else {
		// Single block: fill with zeros from nx+1 to 56
		for i := nx + 1; i < 56; i++ {
			tmp[i] = 0
		}
	}

	// Append length (in bits) at the end
	binary.BigEndian.PutUint64(tmp[56:], length)

	// Process final block
	d.block(tmp[:])

	// Convert digest to bytes
	var result [SM3Size]byte
	for i, s := range d.digest {
		binary.BigEndian.PutUint32(result[i*4:i*4+4], s)
	}

	// Restore state (in case Sum is called again)
	d.digest = digest
	d.length = length
	d.nx = nx
	copy(d.x[:], x[:])

	return result
}

// block processes a 64-byte (512-bit) block
func (d *sm3) block(p []byte) {
	var w [68]uint32
	var w1 [64]uint32

	for len(p) >= SM3BlockSize {
		block := p[:SM3BlockSize]

		// 消息扩展
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
		}

		for i := 16; i < 68; i++ {
			w[i] = sm3P1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
		}

		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		// 压缩函数
		A, B, C, D, E, F, G, H := d.digest[0], d.digest[1], d.digest[2], d.digest[3],
			d.digest[4], d.digest[5], d.digest[6], d.digest[7]

		for j := 0; j < 64; j++ {
			// SM3 压缩函数的一轮
			// SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj, j)), 7)
			ss1 := rotl(rotl(A, 12)+E+rotl(sm3T(j), j), 7)
			ss2 := ss1 ^ rotl(A, 12)
			tt1 := sm3FF(j, A, B, C) + D + ss2 + w1[j]
			tt2 := sm3GG(j, E, F, G) + H + ss1 + w[j]

			// 移位和更新（顺序很重要！）
			D = C
			C = rotl(B, 9)
			B = A
			A = tt1
			H = G
			G = rotl(F, 19)
			F = E
			E = sm3P0(tt2)
		}

		d.digest[0] ^= A
		d.digest[1] ^= B
		d.digest[2] ^= C
		d.digest[3] ^= D
		d.digest[4] ^= E
		d.digest[5] ^= F
		d.digest[6] ^= G
		d.digest[7] ^= H

		p = p[SM3BlockSize:]
	}
}

// SM3 SM3 哈希函数，返回数据的 SM3 哈希值
func SM3(data []byte) [SM3Size]byte {
	h := NewSM3()
	h.Write(data)
	var hash [SM3Size]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

// NewSM3HMAC 返回使用 key 的 SM3 HMAC
func NewSM3HMAC(key []byte) hash.Hash {
	return hmac.New(NewSM3, key)
}

// SM3HMAC 计算 SM3 HMAC
func SM3HMAC(key, data []byte) []byte {
	h := NewSM3HMAC(key)
	h.Write(data)
	return h.Sum(nil)
}

// SM3KDF SM3 密钥派生函数 (Key Derivation Function)
// 基于 GM/T 0004-2012
func SM3KDF(z []byte, klen int) []byte {
	if klen <= 0 {
		return nil
	}

	// 计算需要的迭代次数（每次输出 SM3Size 字节）
	ct := (klen + SM3Size - 1) / SM3Size
	if ct <= 0 {
		return nil
	}
	if uint64(ct) >= 0x100000000 {
		return nil // klen 太大
	}

	var result []byte
	for i := uint32(1); i <= uint32(ct); i++ {
		// 拼接 Z || counter (4字节大端序)
		data := make([]byte, len(z)+4)
		copy(data, z)
		binary.BigEndian.PutUint32(data[len(z):], i)

		// 计算 SM3 哈希
		hash := SM3(data)
		result = append(result, hash[:]...)
	}

	// 截取到所需长度
	if len(result) > klen {
		return result[:klen]
	}
	return result
}
