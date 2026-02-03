package gmtls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSM3Vectors(t *testing.T) {
	sum := SM3([]byte("abc"))
	expect := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	if hex.EncodeToString(sum[:]) != expect {
		t.Fatalf("SM3 vector mismatch: got=%s", hex.EncodeToString(sum[:]))
	}
}

func TestSM3HMAC(t *testing.T) {
	mac := SM3HMAC([]byte("key"), []byte("data"))
	if len(mac) != SM3Size {
		t.Fatalf("SM3HMAC length: got=%d", len(mac))
	}
}

func TestSM3KDFLength(t *testing.T) {
	out := SM3KDF([]byte("z"), 48)
	if len(out) != 48 {
		t.Fatalf("SM3KDF length: got=%d", len(out))
	}
}

func TestSM4ECB(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, SM4KeySize)
	plain := []byte("hello sm4")
	ct := SM4Encrypt(key, plain)
	pt, err := SM4Decrypt(key, ct)
	if err != nil {
		t.Fatalf("SM4Decrypt err: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("SM4 ECB mismatch: %q", pt)
	}
}

func TestSM4CBC(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, SM4KeySize)
	iv := bytes.Repeat([]byte{0x33}, SM4BlockSize)
	plain := []byte("hello sm4 cbc")
	ct := SM4EncryptCBC(key, iv, plain)
	pt, err := SM4DecryptCBC(key, iv, ct)
	if err != nil {
		t.Fatalf("SM4DecryptCBC err: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("SM4 CBC mismatch: %q", pt)
	}
}

func TestSM4CBCInvalidCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, SM4KeySize)
	iv := bytes.Repeat([]byte{0x33}, SM4BlockSize)
	_, err := SM4DecryptCBC(key, iv, []byte{1, 2, 3})
	if err == nil {
		t.Fatalf("expected error for invalid ciphertext length")
	}
}

func TestSM4GCMWrapper(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x55}, 12)
	aead := NewSM4GCM(key, nonce)
	ad := []byte("ad")
	pt := []byte("hello gcm")
	ct := aead.Seal(nil, nonce, pt, ad)
	out, err := aead.Open(nil, nonce, ct, ad)
	if err != nil {
		t.Fatalf("SM4GCM open err: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("SM4 GCM mismatch")
	}
}

func TestSM4GCMWrapperNonceSize(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, SM4KeySize)
	nonce := bytes.Repeat([]byte{0x55}, 8)
	aead := NewSM4GCM(key, nonce)
	if aead.NonceSize() != 8 {
		t.Fatalf("SM4GCM nonce size mismatch: got=%d", aead.NonceSize())
	}
}

func TestSM4GCMModeTLS12ExplicitIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, SM4KeySize)
	fixedIV := bytes.Repeat([]byte{0x11}, 4)
	mode, err := NewSM4GCMMode(key, fixedIV, true, false)
	if err != nil {
		t.Fatalf("NewSM4GCMMode err: %v", err)
	}

	// Make explicit IV deterministic.
	prev := RandReader
	RandReader = bytes.NewReader(bytes.Repeat([]byte{0x99}, 8))
	defer func() { RandReader = prev }()

	pt := []byte("hello tls12 gcm")
	ct, err := mode.Encrypt(recordTypeApplicationData, pt)
	if err != nil {
		t.Fatalf("Encrypt err: %v", err)
	}
	if len(ct) != 8+len(pt)+16 {
		t.Fatalf("ciphertext length mismatch: got=%d", len(ct))
	}
	out, err := mode.Decrypt(recordTypeApplicationData, ct)
	if err != nil {
		t.Fatalf("Decrypt err: %v", err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatalf("TLS12 GCM mismatch")
	}
}

func TestSM4DecryptCBCInvalidIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, SM4KeySize)
	_, err := SM4DecryptCBC(key, []byte("short"), bytes.Repeat([]byte{0x11}, 16))
	if err == nil {
		t.Fatalf("expected error for invalid IV length")
	}
}

func TestPKCS7UnpadStrict(t *testing.T) {
	_, err := PKCS7UnpadStrict([]byte{})
	if err == nil {
		t.Fatalf("expected error for empty data")
	}
	_, err = PKCS7UnpadStrict([]byte{1, 2, 0})
	if err == nil {
		t.Fatalf("expected error for invalid padding size")
	}
	_, err = PKCS7UnpadStrict([]byte{1, 2, 2, 3})
	if err == nil {
		t.Fatalf("expected error for invalid padding bytes")
	}
	out, err := PKCS7UnpadStrict([]byte{1, 2, 2, 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, []byte{1, 2}) {
		t.Fatalf("unpad mismatch")
	}
}

func TestSM2SignVerify(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := SM3([]byte("msg"))
	sig, err := Sign(priv, hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(pub, hash[:], sig) {
		t.Fatalf("Verify failed")
	}
}

func TestSM2SignVerifyMessage(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("hello")
	sig, err := SignMessage(priv, msg)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if !VerifyMessage(pub, msg, sig) {
		t.Fatalf("VerifyMessage failed")
	}
}

func TestSM2NoZASignVerify(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	msg := []byte("noza")
	sig, err := SignMessageNoZA(priv, msg)
	if err != nil {
		t.Fatalf("SignMessageNoZA: %v", err)
	}
	if !VerifyMessageNoZA(pub, msg, sig) {
		t.Fatalf("VerifyMessageNoZA failed")
	}
}

func TestSM2KeyShareRoundTrip(t *testing.T) {
	priv, pubBytes, err := GenerateSM2KeyPairForTLS13()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPairForTLS13: %v", err)
	}
	pub, err := ParseSM2PublicKey(pubBytes)
	if err != nil {
		t.Fatalf("ParseSM2PublicKey: %v", err)
	}
	if priv.Public() == nil || pub == nil {
		t.Fatalf("invalid public key")
	}
}
