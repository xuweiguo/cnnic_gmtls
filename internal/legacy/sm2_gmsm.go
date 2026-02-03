//go:build ignore
// +build ignore

package gmtls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
)

func sm2UserID() []byte {
	// Default per RFC 8998 / Tongsuo CERTVRIFY_SM2_ID for TLS 1.3 CertificateVerify
	return []byte("1234567812345678")
}

func sm2TLS13CertVerifyID() []byte {
	// Tongsuo CERTVRIFY_SM2_ID
	return []byte("1234567812345678")
}

func sm2TLS13HandshakeID() []byte {
	// Tongsuo HANDSHAKE_SM2_ID
	return []byte("TLSv1.3+GM+Cipher+Suite")
}

func sm2GMSMPrivateKey(priv *PrivateKey) (*sm2.PrivateKey, error) {
	if priv == nil || priv.D == nil || priv.D.Sign() <= 0 {
		return nil, errors.New("gmtls: invalid SM2 private key")
	}
	return sm2.NewPrivateKeyFromInt(priv.D)
}

func sm2GMSMPublicKey(pub *PublicKey) (*ecdsa.PublicKey, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, errors.New("gmtls: invalid SM2 public key")
	}
	keyBytes := make([]byte, 65)
	keyBytes[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	if len(xBytes) > 32 || len(yBytes) > 32 {
		return nil, errors.New("gmtls: invalid SM2 public key size")
	}
	copy(keyBytes[1+32-len(xBytes):33], xBytes)
	copy(keyBytes[33+32-len(yBytes):65], yBytes)
	return sm2.NewPublicKey(keyBytes)
}

func sm2TLS13SignWithID(priv *PrivateKey, msg []byte, raw bool, uid []byte) ([]byte, error) {
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}

	if raw {
		r, s, err := sm2.SignWithSM2(rand.Reader, &sm2Priv.PrivateKey, uid, msg)
		if err != nil {
			return nil, err
		}
		rBytes := r.Bytes()
		sBytes := s.Bytes()
		rFull := make([]byte, 32)
		sFull := make([]byte, 32)
		copy(rFull[32-len(rBytes):], rBytes)
		copy(sFull[32-len(sBytes):], sBytes)
		return append(rFull, sFull...), nil
	}

	return sm2.SignASN1(rand.Reader, sm2Priv, msg, sm2.NewSM2SignerOption(true, uid))
}

// sm2TLS13SignHash signs a precomputed hash without applying ZA (non-standard).
func sm2TLS13SignHashWithID(priv *PrivateKey, hash []byte, uid []byte) ([]byte, error) {
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	// Use SM2 signer option without GM-specific hashing (treat input as hash).
	return sm2.SignASN1(rand.Reader, sm2Priv, hash, sm2.NewSM2SignerOption(false, uid))
}

func sm2TLS13VerifyWithID(pub *PublicKey, msg, sig []byte, uid []byte) (bool, error) {
	sm2Pub, err := sm2GMSMPublicKey(pub)
	if err != nil {
		return false, err
	}

	if len(sig) == 64 {
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return sm2.VerifyWithSM2(sm2Pub, uid, msg, r, s), nil
	}
	return sm2.VerifyASN1WithSM2(sm2Pub, uid, msg, sig), nil
}

func sm2TLS13Sign(priv *PrivateKey, msg []byte, raw bool) ([]byte, error) {
	return sm2TLS13SignWithID(priv, msg, raw, sm2UserID())
}

// sm2TLS13SignHash signs a precomputed hash without applying ZA (non-standard).
func sm2TLS13SignHash(priv *PrivateKey, hash []byte) ([]byte, error) {
	return sm2TLS13SignHashWithID(priv, hash, sm2UserID())
}

func sm2TLS13Verify(pub *PublicKey, msg, sig []byte) (bool, error) {
	return sm2TLS13VerifyWithID(pub, msg, sig, sm2UserID())
}
