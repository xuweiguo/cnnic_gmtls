//go:build ignore
// +build ignore

package gmtls

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// SM4 对称加密算法实现
// 基于 GM/T 0002-2012 标准

const (
	// SM4BlockSize SM4 分组大小（字节）
	SM4BlockSize = 16
	// SM4KeySize SM4 密钥大小（字节）
	SM4KeySize = 16
	// SM4NumRounds SM4 轮数
	SM4NumRounds = 32
)

// SM4 S盒 (标准 GM/T 0002-2012) - 256字节
var sm4Sbox = [256]byte{
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
}

// SM4 系统参数 CK
var sm4CK = [32]uint32{
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
}

// sm4Cipher SM4 密码结构
type sm4Cipher struct {
	encRK [SM4NumRounds]uint32 // 加密轮密钥
	decRK [SM4NumRounds]uint32 // 解密轮密钥
}

// sm4Tau S盒变换
func sm4Tau(a uint32) uint32 {
	b0 := sm4Sbox[a&0xff]
	b1 := sm4Sbox[(a>>8)&0xff]
	b2 := sm4Sbox[(a>>16)&0xff]
	b3 := sm4Sbox[(a>>24)&0xff]
	return uint32(b0) | uint32(b1)<<8 | uint32(b2)<<16 | uint32(b3)<<24
}

// sm4Tau4 4个uint32的S盒变换
func sm4Tau4(a []uint32) []byte {
	b := make([]byte, 16)
	for i := 0; i < 4; i++ {
		b[i*4] = sm4Sbox[a[i]&0xff]
		b[i*4+1] = sm4Sbox[(a[i]>>8)&0xff]
		b[i*4+2] = sm4Sbox[(a[i]>>16)&0xff]
		b[i*4+3] = sm4Sbox[(a[i]>>24)&0xff]
	}
	return b
}

// sm4T 线性变换L
func sm4T(a uint32) uint32 {
	b := sm4Tau(a)
	return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24)
}

// sm4T4 4个uint32的线性变换
func sm4T4(a []uint32) []uint32 {
	b := sm4Tau4(a)
	b32 := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		b32[i] = binary.BigEndian.Uint32(b[i*4 : i*4+4])
	}
	c := make([]uint32, 4)
	c[0] = b32[0] ^ rotl(b32[0], 2) ^ rotl(b32[0], 10) ^ rotl(b32[0], 18) ^ rotl(b32[0], 24)
	c[1] = b32[1] ^ rotl(b32[1], 2) ^ rotl(b32[1], 10) ^ rotl(b32[1], 18) ^ rotl(b32[1], 24)
	c[2] = b32[2] ^ rotl(b32[2], 2) ^ rotl(b32[2], 10) ^ rotl(b32[2], 18) ^ rotl(b32[2], 24)
	c[3] = b32[3] ^ rotl(b32[3], 2) ^ rotl(b32[3], 10) ^ rotl(b32[3], 18) ^ rotl(b32[3], 24)
	return c
}

// sm4KeyExpansion 密钥扩展
func sm4KeyExpansion(key []byte) *sm4Cipher {
	if len(key) != SM4KeySize {
		panic("sm4: invalid key size")
	}

	// SM4 系统参数 FK (Family Key)
	var FK = [4]uint32{
		0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
	}

	c := new(sm4Cipher)

	// 将密钥转换为4个uint32，并异或FK
	K := make([]uint32, 4)
	for i := 0; i < 4; i++ {
		K[i] = binary.BigEndian.Uint32(key[i*4:i*4+4]) ^ FK[i]
	}

	// 生成32个轮密钥
	for i := 0; i < SM4NumRounds; i++ {
		// 计算中间值
		tmp := K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ sm4CK[i]

		// S盒变换
		b0 := sm4Sbox[(tmp>>24)&0xff]
		b1 := sm4Sbox[(tmp>>16)&0xff]
		b2 := sm4Sbox[(tmp>>8)&0xff]
		b3 := sm4Sbox[tmp&0xff]
		t := uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)

		// 线性变换L'
		t = t ^ rotl(t, 13) ^ rotl(t, 23)

		// 更新K并保存轮密钥
		K[i%4] ^= t
		c.encRK[i] = K[i%4]
	}

	// 解密轮密钥（加密轮密钥的逆序）
	for i := 0; i < SM4NumRounds; i++ {
		c.decRK[i] = c.encRK[SM4NumRounds-1-i]
	}

	return c
}

// sm4EncryptBlock 加密单个分组
func sm4EncryptBlock(c *sm4Cipher, dst, src []byte) {
	B := [4]uint32{}
	for i := 0; i < 4; i++ {
		B[i] = binary.BigEndian.Uint32(src[i*4 : i*4+4])
	}

	// 32轮迭代，每轮使用4个轮密钥
	rkIdx := 0
	for round := 0; round < 8; round++ {
		// 每轮使用4个轮密钥
		B[0] ^= sm4T(B[1] ^ B[2] ^ B[3] ^ c.encRK[rkIdx])
		B[1] ^= sm4T(B[0] ^ B[2] ^ B[3] ^ c.encRK[rkIdx+1])
		B[2] ^= sm4T(B[0] ^ B[1] ^ B[3] ^ c.encRK[rkIdx+2])
		B[3] ^= sm4T(B[0] ^ B[1] ^ B[2] ^ c.encRK[rkIdx+3])
		rkIdx += 4
	}

	// 逆序变换输出
	binary.BigEndian.PutUint32(dst[0:4], B[3])
	binary.BigEndian.PutUint32(dst[4:8], B[2])
	binary.BigEndian.PutUint32(dst[8:12], B[1])
	binary.BigEndian.PutUint32(dst[12:16], B[0])
}

// sm4DecryptBlock 解密单个分组
func sm4DecryptBlock(c *sm4Cipher, dst, src []byte) {
	B := [4]uint32{}
	for i := 0; i < 4; i++ {
		B[i] = binary.BigEndian.Uint32(src[i*4 : i*4+4])
	}

	// 32轮迭代，每轮使用4个轮密钥（逆序）
	rkIdx := 0
	for round := 0; round < 8; round++ {
		B[0] ^= sm4T(B[1] ^ B[2] ^ B[3] ^ c.decRK[rkIdx])
		B[1] ^= sm4T(B[0] ^ B[2] ^ B[3] ^ c.decRK[rkIdx+1])
		B[2] ^= sm4T(B[0] ^ B[1] ^ B[3] ^ c.decRK[rkIdx+2])
		B[3] ^= sm4T(B[0] ^ B[1] ^ B[2] ^ c.decRK[rkIdx+3])
		rkIdx += 4
	}

	// 逆序变换输出
	binary.BigEndian.PutUint32(dst[0:4], B[3])
	binary.BigEndian.PutUint32(dst[4:8], B[2])
	binary.BigEndian.PutUint32(dst[8:12], B[1])
	binary.BigEndian.PutUint32(dst[12:16], B[0])
}

// NewSM4Cipher 创建 SM4 密码
func NewSM4Cipher(key []byte) cipher.Block {
	if len(key) != SM4KeySize {
		panic("sm4: invalid key size")
	}
	return sm4KeyExpansion(key)
}

// BlockSize 返回分组大小
func (c *sm4Cipher) BlockSize() int {
	return SM4BlockSize
}

// Encrypt 加密分组
func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < SM4BlockSize || len(dst) < SM4BlockSize {
		panic("sm4: input not full block")
	}
	sm4EncryptBlock(c, dst, src)
}

// Decrypt 解密分组
func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < SM4BlockSize || len(dst) < SM4BlockSize {
		panic("sm4: input not full block")
	}
	sm4DecryptBlock(c, dst, src)
}

// ============= SM4 ECB 模式 =============

type sm4ECB struct {
	b         cipher.Block
	blockSize int
}

// NewSM4ECB 创建 SM4 ECB 模式
func NewSM4ECB(key []byte) cipher.BlockMode {
	return &sm4ECB{
		b:         NewSM4Cipher(key),
		blockSize: SM4BlockSize,
	}
}

func (x *sm4ECB) BlockSize() int {
	return x.blockSize
}

func (x *sm4ECB) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("sm4/ecb: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("sm4/ecb: output smaller than input")
	}

	for i := 0; i < len(src); i += x.blockSize {
		x.b.Encrypt(dst[i:i+x.blockSize], src[i:i+x.blockSize])
	}
}

// ============= SM4 CBC 模式 =============

type sm4CBC struct {
	b         cipher.Block
	blockSize int
	iv        []byte
}

// NewSM4CBC 创建 SM4 CBC 模式
func NewSM4CBC(key, iv []byte) cipher.BlockMode {
	if len(iv) != SM4BlockSize {
		panic("sm4/cbc: invalid IV size")
	}
	c := &sm4CBC{
		b:         NewSM4Cipher(key),
		blockSize: SM4BlockSize,
		iv:        make([]byte, SM4BlockSize),
	}
	copy(c.iv, iv)
	return c
}

func (x *sm4CBC) BlockSize() int {
	return x.blockSize
}

func (x *sm4CBC) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("sm4/cbc: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("sm4/cbc: output smaller than input")
	}

	for i := 0; i < len(src); i += x.blockSize {
		// CBC 加密: 先异再加密
		subtle.XORBytes(dst[i:i+x.blockSize], src[i:i+x.blockSize], x.iv)
		x.b.Encrypt(dst[i:i+x.blockSize], dst[i:i+x.blockSize])
		copy(x.iv, dst[i:i+x.blockSize])
	}
}

// ============= SM4 GCM 模式 =============

const (
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
)

// gcmFieldElement represents a field element in GF(2^128)
type gcmFieldElement [16]byte

// mulGCM multiplies two elements in GF(2^128) with the GCM polynomial
// Uses GCM's "little-endian" convention where bit 0 of each byte is the MSB polynomial coefficient
func mulGCM(x, y gcmFieldElement) gcmFieldElement {
	var z gcmFieldElement
	var v gcmFieldElement
	copy(v[:], x[:])

	for i := 0; i < 128; i++ {
		// GCM uses MSB-first bit order within each byte.
		if (y[i/8]>>(7-(i%8)))&1 == 1 {
			z = gcmAdd(z, v)
		}
		v = gcmDouble(v)
	}
	return z
}

// gcmAdd adds two field elements
func gcmAdd(x, y gcmFieldElement) gcmFieldElement {
	var z gcmFieldElement
	for i := 0; i < 16; i++ {
		z[i] = x[i] ^ y[i]
	}
	return z
}

// gcmDouble doubles a field element
func gcmDouble(x gcmFieldElement) gcmFieldElement {
	var z gcmFieldElement
	var carry uint8
	for i := 15; i >= 0; i-- {
		z[i] = x[i] << 1
		if carry != 0 {
			z[i] |= 1
		}
		carry = x[i] >> 7
	}
	if carry != 0 {
		z[15] ^= 0x87 // GCM reduction polynomial
	}
	return z
}

// ghash implements the GHASH function
func ghash(h gcmFieldElement, data []byte) gcmFieldElement {
	var y gcmFieldElement
	for len(data) >= 16 {
		var block gcmFieldElement
		copy(block[:], data[:16])
		y = gcmAdd(y, block)
		y = mulGCM(y, h)
		data = data[16:]
	}
	if len(data) > 0 {
		var block gcmFieldElement
		copy(block[:], data)
		y = gcmAdd(y, block)
		y = mulGCM(y, h)
	}
	return y
}

type sm4GCM struct {
	cipher *sm4Cipher
	nonce  []byte
}

// NewSM4GCM 创建 SM4 GCM 模式
func NewSM4GCM(key, nonce []byte) cipher.AEAD {
	if len(nonce) != gcmStandardNonceSize {
		panic("sm4/gcm: incorrect nonce length")
	}
	block := sm4KeyExpansion(key)
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic("sm4/gcm: failed to create AEAD")
	}
	return aead
}

func (g *sm4GCM) NonceSize() int {
	return gcmStandardNonceSize
}

func (g *sm4GCM) Overhead() int {
	return gcmTagSize
}

// incCounter increments the last 32 bits of the counter
func incCounter(counter []byte) {
	if len(counter) < 4 {
		return
	}
	// 从 counter 的最后开始递增
	for i := len(counter) - 1; i >= len(counter)-4; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// gctr implements the GCTR function
func (g *sm4GCM) gctr(plaintext []byte, counter []byte) []byte {
	ciphertext := make([]byte, len(plaintext))
	block := make([]byte, SM4BlockSize)

	for i := 0; i < len(plaintext); i += SM4BlockSize {
		g.cipher.Encrypt(block, counter)
		incCounter(counter)

		end := i + SM4BlockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		for j := i; j < end; j++ {
			ciphertext[j] = plaintext[j] ^ block[j-i]
		}
	}

	return ciphertext
}

// Seal 加密并认证数据
func (g *sm4GCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != gcmStandardNonceSize {
		panic("sm4/gcm: incorrect nonce length")
	}

	// 计算 H = E(K, 0^128)
	var hBlock [SM4BlockSize]byte
	g.cipher.Encrypt(hBlock[:], hBlock[:])
	var hField gcmFieldElement
	copy(hField[:], hBlock[:])

	// 构造初始计数器 J0
	var j0 [SM4BlockSize]byte
	copy(j0[:], nonce)
	j0[15] = 1 // 设置最后32位为1

	// 计算 S = GHASH(H, A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	aLen := uint64(len(additionalData)) * 8
	cLen := uint64(len(plaintext)) * 8

	// 构造 GHASH 输入
	var ghashInput []byte
	ghashInput = append(ghashInput, additionalData...)

	// 添加填充使 A 长度为 128 的倍数
	if padLen := (16 - (len(additionalData) % 16)) % 16; padLen > 0 {
		ghashInput = append(ghashInput, make([]byte, padLen)...)
	}

	// 加密明文得到密文（使用 J0 的副本，因为 gctr 会修改 counter）
	counter := make([]byte, SM4BlockSize)
	copy(counter, j0[:])
	ciphertext := g.gctr(plaintext, counter)
	ghashInput = append(ghashInput, ciphertext...)

	// 添加填充使 C 长度为 128 的倍数
	if padLen := (16 - (len(ciphertext) % 16)) % 16; padLen > 0 {
		ghashInput = append(ghashInput, make([]byte, padLen)...)
	}

	// 添加长度字段
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:], aLen)
	binary.BigEndian.PutUint64(lenBlock[8:], cLen)
	ghashInput = append(ghashInput, lenBlock...)

	// 计算 GHASH
	s := ghash(hField, ghashInput)

	// 计算 T = MSB_t(GCTR(K, J0, S))
	var tBlock [SM4BlockSize]byte
	g.cipher.Encrypt(tBlock[:], j0[:])
	var t gcmFieldElement
	for i := 0; i < gcmTagSize; i++ {
		t[i] = tBlock[i] ^ s[i]
	}

	// 组合输出
	ret, out := sliceForAppend(dst, len(ciphertext)+gcmTagSize)
	copy(out, ciphertext)
	copy(out[len(ciphertext):], t[:gcmTagSize])
	return ret
}

// Open 解密并验证数据
func (g *sm4GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != gcmStandardNonceSize {
		panic("sm4/gcm: incorrect nonce length")
	}

	if len(ciphertext) < gcmTagSize {
		return nil, errors.New("sm4/gcm: ciphertext too short")
	}

	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// 计算 H = E(K, 0^128)
	var hBlock [SM4BlockSize]byte
	g.cipher.Encrypt(hBlock[:], hBlock[:])
	var hField gcmFieldElement
	copy(hField[:], hBlock[:])

	// 构造初始计数器 J0
	var j0 [SM4BlockSize]byte
	copy(j0[:], nonce)
	j0[15] = 1 // 设置最后32位为1

	// 计算 S = GHASH(H, A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	aLen := uint64(len(additionalData)) * 8
	cLen := uint64(len(ciphertext)) * 8

	// 构造 GHASH 输入
	var ghashInput []byte
	ghashInput = append(ghashInput, additionalData...)

	// 添加填充使 A 长度为 128 的倍数
	if padLen := (16 - (len(additionalData) % 16)) % 16; padLen > 0 {
		ghashInput = append(ghashInput, make([]byte, padLen)...)
	}

	// 添加密文
	ghashInput = append(ghashInput, ciphertext...)

	// 添加填充使 C 长度为 128 的倍数
	if padLen := (16 - (len(ciphertext) % 16)) % 16; padLen > 0 {
		ghashInput = append(ghashInput, make([]byte, padLen)...)
	}

	// 添加长度字段
	lenBlock := make([]byte, 16)
	binary.BigEndian.PutUint64(lenBlock[0:], aLen)
	binary.BigEndian.PutUint64(lenBlock[8:], cLen)
	ghashInput = append(ghashInput, lenBlock...)

	// 计算 GHASH
	s := ghash(hField, ghashInput)

	// 计算 T = MSB_t(GCTR(K, J0, S))
	var tBlock [SM4BlockSize]byte
	g.cipher.Encrypt(tBlock[:], j0[:])
	var computedTag gcmFieldElement
	for i := 0; i < gcmTagSize; i++ {
		computedTag[i] = tBlock[i] ^ s[i]
	}

	// 验证标签
	if subtle.ConstantTimeCompare(tag, computedTag[:gcmTagSize]) != 1 {
		return nil, errors.New("sm4/gcm: message authentication failed")
	}

	// 解密
	plaintext := g.gctr(ciphertext, j0[:])

	ret, out := sliceForAppend(dst, len(plaintext))
	copy(out, plaintext)
	return ret, nil
}

// sliceForAppend 辅助函数
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// ============= 便捷函数 =============

// SM4Encrypt SM4 ECB 模式加密
func SM4Encrypt(key, plaintext []byte) []byte {
	block := NewSM4Cipher(key)

	// PKCS#7 填充
	padded := PKCS7Pad(plaintext, SM4BlockSize)
	ciphertext := make([]byte, len(padded))

	// 逐块加密
	for i := 0; i < len(padded); i += SM4BlockSize {
		block.Encrypt(ciphertext[i:i+SM4BlockSize], padded[i:i+SM4BlockSize])
	}

	return ciphertext
}

// SM4Decrypt SM4 ECB 模式解密
func SM4Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, errors.New("sm4: ciphertext is not a multiple of the block size")
	}

	block := NewSM4Cipher(key)
	plaintext := make([]byte, len(ciphertext))

	// 逐块解密
	for i := 0; i < len(ciphertext); i += SM4BlockSize {
		block.Decrypt(plaintext[i:i+SM4BlockSize], ciphertext[i:i+SM4BlockSize])
	}

	// 去除 PKCS#7 填充
	return PKCS7Unpad(plaintext), nil
}

// SM4EncryptCBC SM4 CBC 模式加密
func SM4EncryptCBC(key, iv, plaintext []byte) []byte {
	block := NewSM4Cipher(key)

	// PKCS#7 填充
	padded := PKCS7Pad(plaintext, SM4BlockSize)
	ciphertext := make([]byte, len(padded))

	// CBC 加密: C[i] = E(P[i] ^ C[i-1])
	prevBlock := make([]byte, SM4BlockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(padded); i += SM4BlockSize {
		// 先异或
		for j := 0; j < SM4BlockSize; j++ {
			ciphertext[i+j] = padded[i+j] ^ prevBlock[j]
		}
		// 再加密
		block.Encrypt(ciphertext[i:i+SM4BlockSize], ciphertext[i:i+SM4BlockSize])
		// 更新前一个块
		copy(prevBlock, ciphertext[i:i+SM4BlockSize])
	}

	return ciphertext
}

// SM4DecryptCBC SM4 CBC 模式解密
func SM4DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, errors.New("sm4/cbc: ciphertext is not a multiple of the block size")
	}

	block := NewSM4Cipher(key)
	plaintext := make([]byte, len(ciphertext))

	// CBC 解密: P[i] = D(C[i]) ^ C[i-1]
	prevBlock := make([]byte, SM4BlockSize)
	copy(prevBlock, iv)

	for i := 0; i < len(ciphertext); i += SM4BlockSize {
		// 先解密
		block.Decrypt(plaintext[i:i+SM4BlockSize], ciphertext[i:i+SM4BlockSize])
		// 再异或
		for j := 0; j < SM4BlockSize; j++ {
			plaintext[i+j] ^= prevBlock[j]
		}
		// 更新前一个块
		copy(prevBlock, ciphertext[i:i+SM4BlockSize])
	}

	// 去除 PKCS#7 填充
	return PKCS7Unpad(plaintext), nil
}

// PKCS7Pad PKCS#7 填充
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// PKCS7Unpad 去除 PKCS#7 填充
func PKCS7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > len(data) {
		return data
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return data
		}
	}
	return data[:len(data)-padding]
}
