package gmtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
)

// sm2Curve wraps the SM2 curve implementation from gmsm.
type sm2Curve struct {
	curve elliptic.Curve
}

// SM2Curve is the SM2 curve instance.
var SM2Curve = &sm2Curve{curve: sm2ec.P256()}

func (c *sm2Curve) Params() *elliptic.CurveParams { return c.curve.Params() }
func (c *sm2Curve) IsOnCurve(x, y *big.Int) bool  { return c.curve.IsOnCurve(x, y) }
func (c *sm2Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return c.curve.Add(x1, y1, x2, y2)
}
func (c *sm2Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return c.curve.Double(x1, y1)
}
func (c *sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	return c.curve.ScalarMult(x1, y1, k)
}
func (c *sm2Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.curve.ScalarBaseMult(k)
}
func (c *sm2Curve) CombinedMult(k0 []byte, x1, y1 *big.Int, k1 []byte) (*big.Int, *big.Int) {
	x0, y0 := c.ScalarBaseMult(k0)
	x, y := c.ScalarMult(x1, y1, k1)
	return c.Add(x0, y0, x, y)
}

// PrivateKey 表示 SM2 私钥（保持对外 API 兼容）。
type PrivateKey struct {
	D *big.Int
}

// PublicKey 表示 SM2 公钥（保持对外 API 兼容）。
type PublicKey struct {
	X, Y *big.Int
}

// Signature 表示 SM2 签名，包含 (R, S)。
type Signature struct {
	R, S *big.Int
}

func parseSM2Signature(derOrRaw []byte) (*Signature, error) {
	if len(derOrRaw) == 64 {
		r := new(big.Int).SetBytes(derOrRaw[:32])
		s := new(big.Int).SetBytes(derOrRaw[32:])
		return &Signature{R: r, S: s}, nil
	}
	return signatureFromASN1(derOrRaw)
}

func validSignatureInput(pub *PublicKey, sig *Signature) bool {
	return pub != nil && sig != nil && sig.R != nil && sig.S != nil
}

// GenerateKey 生成 SM2 密钥对。
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	return GenerateKeyWithReader(rand.Reader)
}

// GenerateKeyWithReader 使用指定随机源生成密钥对。
func GenerateKeyWithReader(reader io.Reader) (*PrivateKey, *PublicKey, error) {
	priv, err := sm2.GenerateKey(reader)
	if err != nil {
		return nil, nil, err
	}
	return &PrivateKey{D: new(big.Int).Set(priv.D)}, &PublicKey{X: priv.X, Y: priv.Y}, nil
}

// Public 从私钥派生公钥。
func (priv *PrivateKey) Public() *PublicKey {
	if priv == nil || priv.D == nil {
		return nil
	}
	x, y := SM2Curve.ScalarBaseMult(priv.D.Bytes())
	return &PublicKey{X: x, Y: y}
}

// Sign 使用 SM2 对哈希值签名。
//
// 注意：此函数会按 GM 逻辑对输入做 ZA 处理（与旧实现一致）。
func Sign(priv *PrivateKey, hash []byte) (*Signature, error) {
	if priv == nil || priv.D == nil {
		return nil, errors.New("sm2: invalid private key")
	}
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	r, s, err := sm2.SignWithSM2(rand.Reader, &sm2Priv.PrivateKey, sm2UserID(), hash)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

// SignMessage 使用 SM2 私钥对原始消息进行签名。
func SignMessage(priv *PrivateKey, msg []byte) (*Signature, error) {
	if priv == nil || priv.D == nil {
		return nil, errors.New("sm2: invalid private key")
	}
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	r, s, err := sm2.SignWithSM2(rand.Reader, &sm2Priv.PrivateKey, sm2UserID(), msg)
	if err != nil {
		return nil, err
	}
	return &Signature{R: r, S: s}, nil
}

// Verify 使用 SM2 验证哈希值签名。
//
// 注意：此函数会按 GM 逻辑对输入做 ZA 处理（与旧实现一致）。
func Verify(pub *PublicKey, hash []byte, sig *Signature) bool {
	if !validSignatureInput(pub, sig) {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.VerifyWithSM2(ecdsaPub, sm2UserID(), hash, sig.R, sig.S)
}

// VerifyMessage 使用 SM2 公钥验证原始消息签名。
func VerifyMessage(pub *PublicKey, msg []byte, sig *Signature) bool {
	if !validSignatureInput(pub, sig) {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.VerifyWithSM2(ecdsaPub, sm2UserID(), msg, sig.R, sig.S)
}

// VerifyWithUserID 使用指定用户 ID 验证哈希。
func VerifyWithUserID(pub *PublicKey, hash []byte, sig *Signature, userID []byte) bool {
	if !validSignatureInput(pub, sig) {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.VerifyWithSM2(ecdsaPub, userID, hash, sig.R, sig.S)
}

// VerifyMessageWithUserID 使用指定用户 ID 验证原始消息。
func VerifyMessageWithUserID(pub *PublicKey, msg []byte, sig *Signature, userID []byte) bool {
	if !validSignatureInput(pub, sig) {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.VerifyWithSM2(ecdsaPub, userID, msg, sig.R, sig.S)
}

// VerifyMessageNoZA 验证 SM3(msg) 的签名，不包含 ZA（非标准，供互通使用）。
func VerifyMessageNoZA(pub *PublicKey, msg []byte, sig *Signature) bool {
	if !validSignatureInput(pub, sig) {
		return false
	}
	hash := SM3(msg)
	der, err := signatureToASN1(sig)
	if err != nil {
		return false
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.VerifyASN1(ecdsaPub, hash[:], der)
}

// SignMessageNoZA 对 SM3(msg) 进行签名，不包含 ZA（非标准，供互通使用）。
func SignMessageNoZA(priv *PrivateKey, msg []byte) (*Signature, error) {
	if priv == nil || priv.D == nil {
		return nil, errors.New("sm2: invalid private key")
	}
	hash := SM3(msg)
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	sigDER, err := sm2.SignASN1(rand.Reader, sm2Priv, hash[:], nil)
	if err != nil {
		return nil, err
	}
	return signatureFromASN1(sigDER)
}

// Encrypt 使用 SM2 加密。
func Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("sm2: invalid public key")
	}
	ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
	return sm2.Encrypt(rand.Reader, ecdsaPub, plaintext, nil)
}

// Decrypt 使用 SM2 解密。
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, errors.New("sm2: invalid private key")
	}
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(sm2Priv, ciphertext)
}

// DeriveSharedKey 使用 SM2 进行密钥派生。
func DeriveSharedKey(priv *PrivateKey, pub *PublicKey) []byte {
	x, _ := SM2Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return SM3KDF(x.Bytes(), 48)
}

// DeriveSM2ECDHSharedSecret 派生 SM2 ECDH 共享密钥（用于 TLS 1.3）。
func DeriveSM2ECDHSharedSecret(priv *PrivateKey, pub *PublicKey) []byte {
	x, _ := SM2Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	xBytes := x.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(xBytes):], xBytes)
	return result
}

// GenerateSM2KeyPairForTLS13 生成 SM2 密钥对（用于 TLS 1.3 key_share）。
func GenerateSM2KeyPairForTLS13() (*PrivateKey, []byte, error) {
	priv, pub, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(pubBytes[1+32-len(xBytes):33], xBytes)
	copy(pubBytes[33+32-len(yBytes):65], yBytes)
	return priv, pubBytes, nil
}

// ParseSM2PublicKey 解析 SM2 公钥（从 TLS key_share）。
func ParseSM2PublicKey(pubBytes []byte) (*PublicKey, error) {
	if len(pubBytes) != 65 {
		return nil, errors.New("sm2: invalid public key length")
	}
	if pubBytes[0] != 0x04 {
		return nil, errors.New("sm2: invalid public key format (not uncompressed)")
	}
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	if !SM2Curve.IsOnCurve(x, y) {
		return nil, errors.New("sm2: public key not on curve")
	}
	return &PublicKey{X: x, Y: y}, nil
}

func signatureFromASN1(der []byte) (*Signature, error) {
	var sig Signature
	if _, err := asn1.Unmarshal(der, &sig); err != nil || sig.R == nil || sig.S == nil {
		return nil, errors.New("sm2: invalid signature")
	}
	return &Signature{R: sig.R, S: sig.S}, nil
}

func signatureToASN1(sig *Signature) ([]byte, error) {
	if sig == nil || sig.R == nil || sig.S == nil {
		return nil, errors.New("sm2: invalid signature")
	}
	return asn1.Marshal(*sig)
}
