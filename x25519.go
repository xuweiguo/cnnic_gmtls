package gmtls

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ============= X25519 密钥交换 =============
// 用于 TLS 1.3 的 (EC)DHE 密钥交换

// GenerateX25519Key 生成 X25519 密钥对
func GenerateX25519Key() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, curve25519.ScalarSize)
	publicKey = make([]byte, curve25519.ScalarSize)

	_, err = io.ReadFull(rand.Reader, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// 修正 private key 的某些位以符合 X25519 规范
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// 转换为指针类型调用 ScalarBaseMult
	privKeyArr := new([32]byte)
	pubKeyArr := new([32]byte)
	copy(privKeyArr[:], privateKey)

	curve25519.ScalarBaseMult(pubKeyArr, privKeyArr)
	copy(publicKey, pubKeyArr[:])

	return privateKey, publicKey, nil
}

// DeriveX25519SharedSecret 从私钥和对方公钥派生共享密钥
func DeriveX25519SharedSecret(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != curve25519.ScalarSize {
		return nil, errorInvalidKeyLength
	}
	if len(peerPublicKey) != curve25519.ScalarSize {
		return nil, errorInvalidKeyLength
	}

	sharedSecret := new([32]byte)
	privKeyArr := new([32]byte)
	pubKeyArr := new([32]byte)

	copy(privKeyArr[:], privateKey)
	copy(pubKeyArr[:], peerPublicKey)

	curve25519.ScalarMult(sharedSecret, privKeyArr, pubKeyArr)

	// RFC 8446 §7.4.1 / RFC 7748 §6.1:全零共享密钥(低阶输入导致)必须视为错误。
	if isAllZero(sharedSecret[:]) {
		return nil, errors.New("gmtls: X25519 shared secret is all-zero (invalid peer public key)")
	}

	return sharedSecret[:], nil
}

// GenerateX25519KeyWithReader 使用指定随机源生成密钥对
func GenerateX25519KeyWithReader(reader io.Reader) (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, curve25519.ScalarSize)
	publicKey = make([]byte, curve25519.ScalarSize)

	_, err = io.ReadFull(reader, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// 修正 private key 的某些位以符合 X25519 规范
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// 转换为指针类型调用 ScalarBaseMult
	privKeyArr := new([32]byte)
	pubKeyArr := new([32]byte)
	copy(privKeyArr[:], privateKey)

	curve25519.ScalarBaseMult(pubKeyArr, privKeyArr)
	copy(publicKey, pubKeyArr[:])

	return privateKey, publicKey, nil
}

var errorInvalidKeyLength = &errorString{"gmtls: invalid key length for X25519"}

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}
