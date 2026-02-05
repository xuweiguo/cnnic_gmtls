package gmtls

import (
	"crypto/cipher"
	"errors"

	"github.com/emmansun/gmsm/sm4"
)

const (
	// SM4BlockSize SM4 分组大小（字节）
	SM4BlockSize = 16
	// SM4KeySize SM4 密钥大小（字节）
	SM4KeySize = 16
)

// NewSM4Cipher 创建 SM4 分组密码实例。
func NewSM4Cipher(key []byte) cipher.Block {
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return block
}

// NewSM4ECB 创建 SM4 ECB 模式。
func NewSM4ECB(key []byte) cipher.BlockMode {
	return &sm4ECB{b: NewSM4Cipher(key), blockSize: SM4BlockSize}
}

type sm4ECB struct {
	b         cipher.Block
	blockSize int
}

func (x *sm4ECB) BlockSize() int { return x.blockSize }

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

// NewSM4CBC 创建 SM4 CBC 模式（默认返回加密器）。
func NewSM4CBC(key, iv []byte) cipher.BlockMode {
	return NewSM4CBCEncrypter(key, iv)
}

// NewSM4CBCEncrypter 创建 SM4 CBC 加密器。
func NewSM4CBCEncrypter(key, iv []byte) cipher.BlockMode {
	block := NewSM4Cipher(key)
	if len(iv) != SM4BlockSize {
		panic("sm4/cbc: invalid IV size")
	}
	return cipher.NewCBCEncrypter(block, iv)
}

// NewSM4CBCDecrypter 创建 SM4 CBC 解密器。
func NewSM4CBCDecrypter(key, iv []byte) cipher.BlockMode {
	block := NewSM4Cipher(key)
	if len(iv) != SM4BlockSize {
		panic("sm4/cbc: invalid IV size")
	}
	return cipher.NewCBCDecrypter(block, iv)
}

// NewSM4GCM 创建 SM4 GCM 模式（nonce 仅用于指定 nonce 长度）。
func NewSM4GCM(key, nonce []byte) cipher.AEAD {
	block := NewSM4Cipher(key)
	nonceSize := len(nonce)
	if nonceSize == 0 {
		nonceSize = 12
	}
	aead, err := cipher.NewGCMWithNonceSize(block, nonceSize)
	if err != nil {
		panic("sm4/gcm: failed to create AEAD")
	}
	return aead
}

// SM4Encrypt SM4 ECB 模式加密。
func SM4Encrypt(key, plaintext []byte) []byte {
	block := NewSM4Cipher(key)
	padded := PKCS7Pad(plaintext, SM4BlockSize)
	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += SM4BlockSize {
		block.Encrypt(ciphertext[i:i+SM4BlockSize], padded[i:i+SM4BlockSize])
	}
	return ciphertext
}

// SM4Decrypt SM4 ECB 模式解密。
func SM4Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, errors.New("sm4: ciphertext is not a multiple of the block size")
	}
	block := NewSM4Cipher(key)
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += SM4BlockSize {
		block.Decrypt(plaintext[i:i+SM4BlockSize], ciphertext[i:i+SM4BlockSize])
	}
	return PKCS7UnpadStrict(plaintext)
}

// SM4EncryptCBC SM4 CBC 模式加密。
func SM4EncryptCBC(key, iv, plaintext []byte) []byte {
	if len(iv) != SM4BlockSize {
		panic("sm4/cbc: invalid IV size")
	}
	block := NewSM4Cipher(key)
	padded := PKCS7Pad(plaintext, SM4BlockSize)
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)
	return ciphertext
}

// SM4DecryptCBC SM4 CBC 模式解密。
func SM4DecryptCBC(key, iv, ciphertext []byte) ([]byte, error) {
	if len(iv) != SM4BlockSize {
		return nil, errors.New("sm4/cbc: invalid IV size")
	}
	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, errors.New("sm4/cbc: ciphertext is not a multiple of the block size")
	}
	block := NewSM4Cipher(key)
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	return PKCS7UnpadStrict(plaintext)
}

// PKCS7Pad PKCS#7 填充。
func PKCS7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

// PKCS7Unpad 去除 PKCS#7 填充。
func PKCS7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > len(data) {
		return data
	}
	return data[:len(data)-padding]
}

// PKCS7UnpadStrict 去除 PKCS#7 填充（严格校验）。
func PKCS7UnpadStrict(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: empty data")
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > len(data) {
		return nil, errors.New("pkcs7: invalid padding size")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("pkcs7: invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
