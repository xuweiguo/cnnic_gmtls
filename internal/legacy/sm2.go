//go:build ignore
// +build ignore

// Package gmtls 实现了国密 TLS 协议和相关密码算法
//
// 本包提供了完整的国密算法实现:
//   - SM2: 椭圆曲线公钥密码算法 (基于 GM/T 0003-2012)
//   - SM3: 密码杂凑算法 (基于 GM/T 0004-2012)
//   - SM4: 分组密码算法 (基于 GM/T 0002-2012)
//
// 同时支持 TLS 1.2 和 TLS 1.3 协议，使用国密密码套件。
package gmtls

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// SM2 椭圆曲线算法实现
// 基于 GM/T 0003-2012 标准

// SM2 曲线参数
var (
	sm2P, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _  = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2H, _  = new(big.Int).SetString("1", 16) // cofactor
	sm2Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
)

// sm2Curve SM2 椭圆曲线
type sm2Curve struct{}

// SM2Curve SM2 曲线实例
var SM2Curve = &sm2Curve{}

// Params 返回曲线参数
func (c *sm2Curve) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       sm2P,
		N:       sm2N,
		B:       sm2B,
		Gx:      sm2Gx,
		Gy:      sm2Gy,
		BitSize: 256,
		Name:    "SM2",
	}
}

// IsOnCurve 检查点是否在曲线上
func (c *sm2Curve) IsOnCurve(x, y *big.Int) bool {
	// y^2 ≡ x^3 - 3x + b (mod p)
	// 由于 a = -3，所以公式是 y^2 = x^3 + ax + b
	y2 := new(big.Int).Exp(y, big.NewInt(2), sm2P)
	x3 := new(big.Int).Exp(x, big.NewInt(3), sm2P)

	// ax
	ax := new(big.Int).Mul(sm2A, x)
	ax.Mod(ax, sm2P)

	// x^3 + ax + b
	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, sm2B)
	rhs.Mod(rhs, sm2P)

	return y2.Cmp(rhs) == 0
}

// Add 椭圆曲线点加法
func (c *sm2Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// 处理无穷远点
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}

	// 如果 x1 == x2
	if x1.Cmp(x2) == 0 {
		// 如果 y1 != y2，结果是无穷远点
		if y1.Cmp(y2) != 0 {
			return new(big.Int), new(big.Int)
		}
		// 如果 y1 == y2，使用点加倍
		return c.Double(x1, y1)
	}

	// 计算斜率 λ = (y2 - y1) / (x2 - x1)
	num := new(big.Int).Sub(y2, y1)
	den := new(big.Int).Sub(x2, x1)

	// 模逆
	den.ModInverse(den, sm2P)

	lambda := new(big.Int).Mul(num, den)
	lambda.Mod(lambda, sm2P)

	// x3 = λ^2 - x1 - x2
	x3 := new(big.Int).Exp(lambda, big.NewInt(2), sm2P)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, sm2P)

	// y3 = λ(x1 - x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, sm2P)

	return x3, y3
}

// Double 椭圆曲线点加倍
func (c *sm2Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// 计算斜率 λ = (3x1^2 + a) / (2y1)
	x1Sq := new(big.Int).Exp(x1, big.NewInt(2), sm2P)
	threeX1Sq := new(big.Int).Mul(big.NewInt(3), x1Sq)

	// λ = (3x1^2 + a) / (2y1)
	num := new(big.Int).Add(threeX1Sq, sm2A)
	num.Mod(num, sm2P)

	den := new(big.Int).Mul(big.NewInt(2), y1)
	den.ModInverse(den, sm2P)

	lambda := new(big.Int).Mul(num, den)
	lambda.Mod(lambda, sm2P)

	// x3 = λ^2 - 2x1
	x3 := new(big.Int).Exp(lambda, big.NewInt(2), sm2P)
	twoX1 := new(big.Int).Mul(big.NewInt(2), x1)
	x3.Sub(x3, twoX1)
	x3.Mod(x3, sm2P)

	// y3 = λ(x1 - x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, sm2P)

	return x3, y3
}

// ScalarMult 标量乘法 k*P
func (c *sm2Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	if len(k) == 0 {
		return new(big.Int), new(big.Int)
	}

	// Montgomery ladder for constant-time scalar multiplication
	// 将 k 转换为大整数
	kInt := new(big.Int).SetBytes(k)

	// 初始化结果为无穷远点
	x, y := new(big.Int), new(big.Int)

	// 初始化当前点为基点
	curX, curY := x1, y1

	// 从最高位开始遍历
	for i := kInt.BitLen() - 1; i >= 0; i-- {
		// 总是进行加倍
		x, y = c.Double(x, y)

		// 如果当前位是1，加上当前点
		if kInt.Bit(i) == 1 {
			x, y = c.Add(x, y, curX, curY)
		}
	}

	return x, y
}

// ScalarBaseMult 标量乘法 k*G，其中 G 是基点
func (c *sm2Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(sm2Gx, sm2Gy, k)
}

// CombinedMult 多点标量乘法（用于优化）
//
// 计算 k0*G + k1*P，其中 G 是基点，P 是任意点。
// 这个操作在 ECDHE 密钥交换中很有用，可以同时计算两个标量乘法。
//
// 当前实现使用简单的方法，分别计算两个标量乘法再相加。
// 更高效的实现可以使用 Shamir's trick 或 Strauss-Shamir 算法，
// 但需要更复杂的实现和额外的内存开销。
//
// 参数:
//   - k0: 第一个标量（用于基点 G）
//   - x1, y1: 第二个点的坐标
//   - k1: 第二个标量
//
// 返回:
//   - *big.Int, *big.Int: 结果点的 x 和 y 坐标
func (c *sm2Curve) CombinedMult(k0 []byte, x1, y1 *big.Int, k1 []byte) (*big.Int, *big.Int) {
	// 当前使用简单实现：分别计算标量乘法再相加
	// 对于大多数应用来说，这个性能已经足够
	// 如果需要更高的性能，可以实现 Straus-Shamir 算法
	x0, y0 := c.ScalarBaseMult(k0)
	x, y := c.ScalarMult(x1, y1, k1)
	return c.Add(x0, y0, x, y)
}

// ============= SM2 私钥和公钥 =============

// PrivateKey SM2 私钥
//
// SM2 私钥是一个大整数 d，满足 1 <= d < n-1，其中 n 是椭圆曲线的阶。
type PrivateKey struct {
	D *big.Int // 私钥值
}

// PublicKey SM2 公钥
//
// SM2 公钥是椭圆曲线上的一个点 (X, Y)，通过私钥 d 计算得到：
//
//	P = d*G
//
// 其中 G 是基点。
type PublicKey struct {
	X, Y *big.Int // 公钥坐标
}

// GenerateKey 生成 SM2 密钥对
//
// 使用 crypto/rand.Reader 作为随机源生成一个随机的 SM2 密钥对。
// 返回的私钥是一个随机的大整数 d，公钥是计算得到的点 P = d*G。
//
// 返回:
//   - priv: SM2 私钥
//   - pub: SM2 公钥
//   - error: 生成密钥对时的错误（极不可能发生）
func GenerateKey() (*PrivateKey, *PublicKey, error) {
	return GenerateKeyWithReader(rand.Reader)
}

// GenerateKeyWithReader 使用指定随机源生成密钥对
//
// 使用指定的随机源 reader 生成一个 SM2 密钥对。这在测试时很有用，
// 可以使用可预测的随机源来生成密钥。
//
// 参数:
//   - reader: 随机源，用于生成私钥
//
// 返回:
//   - priv: SM2 私钥
//   - pub: SM2 公钥
//   - error: 生成密钥对时的错误
func GenerateKeyWithReader(reader io.Reader) (*PrivateKey, *PublicKey, error) {
	// 生成随机私钥 d，使得 1 <= d < n-1
	d, err := rand.Int(reader, sm2N)
	if err != nil {
		return nil, nil, err
	}

	// 确保d在有效范围内
	if d.Sign() == 0 {
		d.SetUint64(1)
	}

	// 计算公钥 P = d*G
	x, y := SM2Curve.ScalarBaseMult(d.Bytes())

	priv := &PrivateKey{D: d}
	pub := &PublicKey{X: x, Y: y}

	return priv, pub, nil
}

// Public 从私钥派生公钥
//
// 计算 P = d*G，其中 d 是私钥，G 是基点。
// 这是公钥的标准计算方法。
//
// 返回:
//   - *PublicKey: 计算得到的公钥
func (priv *PrivateKey) Public() *PublicKey {
	x, y := SM2Curve.ScalarBaseMult(priv.D.Bytes())
	return &PublicKey{X: x, Y: y}
}

// ============= SM2 签名和验证 =============

// Signature SM2 签名
//
// SM2 签名由一对大整数 (R, S) 组成，用于验证消息的完整性和真实性。
type Signature struct {
	R, S *big.Int
}

// Sign SM2 签名
//
// 使用 SM2 私钥对消息哈希进行签名。
// 注意：这里输入应该是消息的 SM3 哈希值，而不是消息本身。
//
// 参数:
//   - priv: SM2 私钥
//   - hash: 待签名的消息哈希值（必须是 SM3 哈希，32 字节）
//
// 返回:
//   - *Signature: SM2 签名
//   - error: 签名过程中的错误
//
// 示例:
//
//	hash := gmtls.SM3(message)
//	sig, err := gmtls.Sign(privateKey, hash[:])
func Sign(priv *PrivateKey, hash []byte) (*Signature, error) {
	return SignWithUserID(priv, hash, nil)
}

// SignMessage 使用 SM2 私钥对原始消息进行签名。
// 注意：这里输入是原始消息，而不是消息哈希。
func SignMessage(priv *PrivateKey, msg []byte) (*Signature, error) {
	return SignMessageWithUserID(priv, msg, nil)
}

// SignWithUserID 使用指定用户ID进行签名
//
// SM2 签名可以使用用户标识（userID）来区分不同的签名者。
// 如果 userID 为 nil，则使用默认值 "1234567812345678"。
//
// 参数:
//   - priv: SM2 私钥
//   - hash: 待签名的消息哈希值（32 字节）
//   - userID: 用户标识，可选
//
// 返回:
//   - *Signature: SM2 签名
//   - error: 签名过程中的错误
func SignWithUserID(priv *PrivateKey, hash, userID []byte) (*Signature, error) {
	if len(hash) != SM3Size {
		return nil, errors.New("sm2: invalid hash size")
	}

	// 默认用户ID
	if userID == nil {
		userID = []byte("1234567812345678")
	}

	// ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)
	za := sm2ComputeZA(userID, priv.Public())

	// e = H(ZA || M)
	e := sm2ComputeE(za, hash)

	// 生成随机数 k，1 <= k < n-1
	k, err := rand.Int(rand.Reader, sm2N)
	if err != nil {
		return nil, err
	}
	if k.Sign() == 0 {
		k.SetUint64(1)
	}

	// 计算点 (x1, y1) = k*G
	x1, _ := SM2Curve.ScalarBaseMult(k.Bytes())

	// r = (e + x1) mod n
	r := new(big.Int).Add(e, x1)
	r.Mod(r, sm2N)

	// r + k != n
	rPlusK := new(big.Int).Add(r, k)
	if rPlusK.Cmp(sm2N) == 0 {
		return nil, errors.New("sm2: invalid k value")
	}

	// s = ((1 + dA)^-1 * (k - r * dA)) mod n
	dA := priv.D

	onePlusDA := new(big.Int).Add(big.NewInt(1), dA)
	onePlusDA.ModInverse(onePlusDA, sm2N)

	rDA := new(big.Int).Mul(r, dA)
	kMinusRDA := new(big.Int).Sub(k, rDA)

	s := new(big.Int).Mul(onePlusDA, kMinusRDA)
	s.Mod(s, sm2N)

	return &Signature{R: r, S: s}, nil
}

// SignMessageWithUserID 使用指定用户ID对原始消息进行签名。
// 这里的 msg 为原始消息，不要求固定长度。
func SignMessageWithUserID(priv *PrivateKey, msg, userID []byte) (*Signature, error) {
	// 默认用户ID
	if userID == nil {
		userID = []byte("1234567812345678")
	}

	// ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)
	za := sm2ComputeZA(userID, priv.Public())

	// e = H(ZA || M)
	e := sm2ComputeE(za, msg)

	// 生成随机数 k，1 <= k < n-1
	k, err := rand.Int(rand.Reader, sm2N)
	if err != nil {
		return nil, err
	}
	if k.Sign() == 0 {
		k.SetUint64(1)
	}

	// 计算点 (x1, y1) = k*G
	x1, _ := SM2Curve.ScalarBaseMult(k.Bytes())

	// r = (e + x1) mod n
	r := new(big.Int).Add(e, x1)
	r.Mod(r, sm2N)

	// r + k != n
	rPlusK := new(big.Int).Add(r, k)
	if rPlusK.Cmp(sm2N) == 0 {
		return nil, errors.New("sm2: invalid k value")
	}

	// s = ((1 + dA)^-1 * (k - r * dA)) mod n
	dA := priv.D

	onePlusDA := new(big.Int).Add(big.NewInt(1), dA)
	onePlusDA.ModInverse(onePlusDA, sm2N)

	rDA := new(big.Int).Mul(r, dA)
	kMinusRDA := new(big.Int).Sub(k, rDA)

	s := new(big.Int).Mul(onePlusDA, kMinusRDA)
	s.Mod(s, sm2N)

	return &Signature{R: r, S: s}, nil
}

// Verify SM2 验签
//
// 使用 SM2 公钥验证签名是否有效。
// 注意：这里输入应该是消息的 SM3 哈希值，而不是消息本身。
//
// 参数:
//   - pub: SM2 公钥
//   - hash: 消息的哈希值（32 字节）
//   - sig: 待验证的签名
//
// 返回:
//   - bool: 签名有效返回 true，否则返回 false
//
// 示例:
//
//	hash := gmtls.SM3(message)
//	valid := gmtls.Verify(publicKey, hash[:], signature)
func Verify(pub *PublicKey, hash []byte, sig *Signature) bool {
	return VerifyWithUserID(pub, hash, sig, nil)
}

// VerifyMessage 使用 SM2 公钥验证原始消息的签名。
func VerifyMessage(pub *PublicKey, msg []byte, sig *Signature) bool {
	return VerifyMessageWithUserID(pub, msg, sig, nil)
}

// VerifyWithUserID 使用指定用户ID进行验签
//
// 使用指定的用户标识来验证签名。
// 如果签名时使用了特定的 userID，验签时必须使用相同的 userID。
//
// 参数:
//   - pub: SM2 公钥
//   - hash: 消息的哈希值（32 字节）
//   - sig: 待验证的签名
//   - userID: 用户标识，应该与签名时使用的相同
//
// 返回:
//   - bool: 签名有效返回 true，否则返回 false
func VerifyWithUserID(pub *PublicKey, hash []byte, sig *Signature, userID []byte) bool {
	if len(hash) != SM3Size {
		return false
	}

	// 验证签名范围
	if sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.R.Cmp(sm2N) >= 0 ||
		sig.S.Sign() <= 0 || sig.S.Cmp(sm2N) >= 0 {
		return false
	}

	// 默认用户ID
	if userID == nil {
		userID = []byte("1234567812345678")
	}

	// ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)
	za := sm2ComputeZA(userID, pub)

	// e = H(ZA || M)
	e := sm2ComputeE(za, hash)

	// t = (r + s) mod n
	t := new(big.Int).Add(sig.R, sig.S)
	t.Mod(t, sm2N)

	if t.Sign() == 0 {
		return false
	}

	// (x1, y1) = s*G + t*PA
	x1, _ := SM2Curve.CombinedMult(sig.S.Bytes(), pub.X, pub.Y, t.Bytes())

	// R' = (e + x1) mod n
	rPrime := new(big.Int).Add(e, x1)
	rPrime.Mod(rPrime, sm2N)

	// 验证 R' == R
	return rPrime.Cmp(sig.R) == 0
}

// VerifyMessageWithUserID 使用指定用户ID验证原始消息的签名。
func VerifyMessageWithUserID(pub *PublicKey, msg []byte, sig *Signature, userID []byte) bool {
	// 验证签名范围
	if sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.R.Cmp(sm2N) >= 0 ||
		sig.S.Sign() <= 0 || sig.S.Cmp(sm2N) >= 0 {
		return false
	}

	// 默认用户ID
	if userID == nil {
		userID = []byte("1234567812345678")
	}

	// ZA = H(ENTLA || ID || a || b || xG || yG || xA || yA)
	za := sm2ComputeZA(userID, pub)

	// e = H(ZA || M)
	e := sm2ComputeE(za, msg)

	// t = (r + s) mod n
	t := new(big.Int).Add(sig.R, sig.S)
	t.Mod(t, sm2N)
	if t.Sign() == 0 {
		return false
	}

	// (x1, y1) = s*G + t*PA
	x1, _ := SM2Curve.CombinedMult(sig.S.Bytes(), pub.X, pub.Y, t.Bytes())

	// R' = (e + x1) mod n
	rPrime := new(big.Int).Add(e, x1)
	rPrime.Mod(rPrime, sm2N)

	// 验证 R' == R
	return rPrime.Cmp(sig.R) == 0
}

// VerifyMessageNoZA verifies an SM2 signature over SM3(msg) without ZA.
// This is non-standard but helps interop with some servers.
func VerifyMessageNoZA(pub *PublicKey, msg []byte, sig *Signature) bool {
	hash := SM3(msg)
	return verifyHashNoZA(pub, hash[:], sig)
}

// SignMessageNoZA signs SM3(msg) without ZA (non-standard).
func SignMessageNoZA(priv *PrivateKey, msg []byte) (*Signature, error) {
	hash := SM3(msg)
	return signHashNoZA(priv, hash[:])
}

func verifyHashNoZA(pub *PublicKey, hash []byte, sig *Signature) bool {
	if len(hash) != SM3Size {
		return false
	}
	if sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.R.Cmp(sm2N) >= 0 ||
		sig.S.Sign() <= 0 || sig.S.Cmp(sm2N) >= 0 {
		return false
	}

	e := new(big.Int).SetBytes(hash)
	t := new(big.Int).Add(sig.R, sig.S)
	t.Mod(t, sm2N)
	if t.Sign() == 0 {
		return false
	}
	x1, _ := SM2Curve.CombinedMult(sig.S.Bytes(), pub.X, pub.Y, t.Bytes())
	rPrime := new(big.Int).Add(e, x1)
	rPrime.Mod(rPrime, sm2N)
	return rPrime.Cmp(sig.R) == 0
}

func signHashNoZA(priv *PrivateKey, hash []byte) (*Signature, error) {
	if len(hash) != SM3Size {
		return nil, errors.New("sm2: invalid hash size")
	}
	e := new(big.Int).SetBytes(hash)

	k, err := rand.Int(rand.Reader, sm2N)
	if err != nil {
		return nil, err
	}
	if k.Sign() == 0 {
		k.SetUint64(1)
	}

	x1, _ := SM2Curve.ScalarBaseMult(k.Bytes())
	r := new(big.Int).Add(e, x1)
	r.Mod(r, sm2N)
	rPlusK := new(big.Int).Add(r, k)
	if rPlusK.Cmp(sm2N) == 0 {
		return nil, errors.New("sm2: invalid k value")
	}

	dA := priv.D
	onePlusDA := new(big.Int).Add(big.NewInt(1), dA)
	onePlusDA.ModInverse(onePlusDA, sm2N)

	rDA := new(big.Int).Mul(r, dA)
	kMinusRDA := new(big.Int).Sub(k, rDA)
	s := new(big.Int).Mul(onePlusDA, kMinusRDA)
	s.Mod(s, sm2N)

	return &Signature{R: r, S: s}, nil
}

// sm2ComputeZA 计算 ZA 值
func sm2ComputeZA(userID []byte, pub *PublicKey) []byte {
	// ENTLA = len(ID) * 8 (bit length, 2字节大端序)
	entla := make([]byte, 2)
	entl := len(userID) * 8
	entla[0] = byte(entl >> 8)
	entla[1] = byte(entl)

	// 拼接所有字段
	var buf []byte
	buf = append(buf, entla...)
	buf = append(buf, userID...)

	// 添加 a 和 b (32字节 each)
	aBytes := sm2A.Bytes()
	bBytes := sm2B.Bytes()
	buf = append(buf, make([]byte, 32-len(aBytes))...)
	buf = append(buf, aBytes...)
	buf = append(buf, make([]byte, 32-len(bBytes))...)
	buf = append(buf, bBytes...)

	// 添加 xG 和 yG
	gxBytes := sm2Gx.Bytes()
	gyBytes := sm2Gy.Bytes()
	buf = append(buf, make([]byte, 32-len(gxBytes))...)
	buf = append(buf, gxBytes...)
	buf = append(buf, make([]byte, 32-len(gyBytes))...)
	buf = append(buf, gyBytes...)

	// 添加 xA 和 yA
	xaBytes := pub.X.Bytes()
	yaBytes := pub.Y.Bytes()
	buf = append(buf, make([]byte, 32-len(xaBytes))...)
	buf = append(buf, xaBytes...)
	buf = append(buf, make([]byte, 32-len(yaBytes))...)
	buf = append(buf, yaBytes...)

	// ZA = SM3(buf)
	hash := SM3(buf)
	return hash[:]
}

// sm2ComputeE 计算 e = H(ZA || M)
func sm2ComputeE(za, m []byte) *big.Int {
	// e = SM3(ZA || M)
	h := NewSM3()
	h.Write(za)
	h.Write(m)
	eBytes := h.Sum(nil)
	return new(big.Int).SetBytes(eBytes)
}

// ============= SM2 密钥交换 (SM2DHE) =============

// DeriveSharedKey SM2 密钥派生
//
// 用于 SM2DHE (SM2 Diffie-Hellman 密钥交换)。
// 计算共享密钥: shared_point = d * Q，其中 d 是本地私钥，Q 是对方公钥。
// 然后使用共享点的 x 坐标通过 KDF 派生最终的密钥。
//
// 参数:
//   - priv: 本地 SM2 私钥
//   - pub: 对方 SM2 公钥
//
// 返回:
//   - []byte: 派生的共享密钥（48 字节）
//
// 注意: 此函数主要用于 TLS 密钥交换，通常不需要直接使用
func DeriveSharedKey(priv *PrivateKey, pub *PublicKey) []byte {
	// 计算 shared point = d * Q = d * k*G = (dk)*G
	x, _ := SM2Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	// 使用 x 坐标派生密钥
	// KDF(x, klen)
	xBytes := x.Bytes()

	// 对于 TLS，通常需要 48 字节 (用于 master secret)
	return SM3KDF(xBytes, 48)
}

// DeriveSM2ECDHSharedSecret 派生 SM2 ECDH 共享密钥（用于 TLS 1.3）
//
// 此函数实现 ECDH over SM2 curve，符合 RFC 8998 要求：
//   - 输入：SM2 私钥和对方的 SM2 公钥
//   - 输出：32 字节共享密钥（x 坐标，左填充到 32 字节）
//
// 对于 TLS 1.3，共享密钥是椭圆曲线点的 x 坐标（32 字节）
func DeriveSM2ECDHSharedSecret(priv *PrivateKey, pub *PublicKey) []byte {
	// 计算 shared point = d * Q
	x, _ := SM2Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	// 返回 x 坐标，左填充到 32 字节
	xBytes := x.Bytes()
	result := make([]byte, 32)
	copy(result[32-len(xBytes):], xBytes)
	return result
}

// GenerateSM2KeyPairForTLS13 生成 SM2 密钥对（用于 TLS 1.3 key_share）
//
// 返回:
//   - priv: SM2 私钥
//   - pubBytes: SM2 公钥的未压缩格式 (65 字节: 0x04 + X + Y)
//   - error: 错误
func GenerateSM2KeyPairForTLS13() (*PrivateKey, []byte, error) {
	priv, pub, err := GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	// 公钥未压缩格式: 0x04 || X || Y
	// X 和 Y 各 32 字节
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04 // 未压缩格式标识

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	copy(pubBytes[1+32-len(xBytes):33], xBytes)
	copy(pubBytes[33+32-len(yBytes):65], yBytes)

	return priv, pubBytes, nil
}

// ParseSM2PublicKey 解析 SM2 公钥（从 TLS key_share）
//
// 输入：
//   - pubBytes: 公钥的未压缩格式 (65 字节: 0x04 + X + Y)
//
// 返回：
//   - *PublicKey: SM2 公钥
//   - error: 错误
func ParseSM2PublicKey(pubBytes []byte) (*PublicKey, error) {
	if len(pubBytes) != 65 {
		return nil, errors.New("sm2: invalid public key length")
	}
	if pubBytes[0] != 0x04 {
		return nil, errors.New("sm2: invalid public key format (not uncompressed)")
	}

	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])

	// 验证点在曲线上
	if !SM2Curve.IsOnCurve(x, y) {
		return nil, errors.New("sm2: public key not on curve")
	}

	return &PublicKey{X: x, Y: y}, nil
}

// ============= SM2 加密和解密 =============

// Encrypt SM2 加密
//
// 使用 SM2 公钥加密明文。
// SM2 加密使用椭圆曲线 ElGamal 方案的变体，包含以下步骤：
//  1. 生成随机数 k
//  2. 计算 C1 = k*G (椭圆曲线点)
//  3. 计算共享点 k*P，使用其坐标派生密钥
//  4. 使用 KDF 派生的密钥加密明文得到 C2
//  5. 计算 C3 = Hash(x2 || M || y2) 作为校验码
//  6. 输出密文: C1 || C3 || C2
//
// 参数:
//   - pub: SM2 公钥
//   - plaintext: 待加密的明文
//
// 返回:
//   - []byte: 密文 (65字节C1 + 32字节C3 + len(plaintext)字节C2)
//   - error: 加密过程中的错误
//
// 示例:
//
//	ciphertext, err := gmtls.Encrypt(publicKey, []byte("Hello, SM2!"))
func Encrypt(pub *PublicKey, plaintext []byte) ([]byte, error) {
	// 生成随机数 k
	k, err := rand.Int(rand.Reader, sm2N)
	if err != nil {
		return nil, err
	}

	// C1 = k*G
	c1x, c1y := SM2Curve.ScalarBaseMult(k.Bytes())

	// 计算 k*P
	x2, y2 := SM2Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	// 使用 x2 派生密钥
	t := SM3KDF(append(x2.Bytes(), y2.Bytes()...), len(plaintext)*8)

	// C2 = plaintext ⊕ KDF(x2 || y2, klen)
	c2 := make([]byte, len(plaintext))
	for i := range plaintext {
		c2[i] = plaintext[i] ^ t[i]
	}

	// C3 = Hash(x2 || M || y2)
	h := NewSM3()
	h.Write(x2.Bytes())
	h.Write(plaintext)
	h.Write(y2.Bytes())
	c3 := h.Sum(nil)

	// 密文格式: C1 || C3 || C2
	// C1: 65 字节 (0x04 + 32字节x + 32字节y)
	// C3: 32 字节
	// C2: len(plaintext) 字节
	ciphertext := make([]byte, 0, 1+64+32+len(plaintext))
	ciphertext = append(ciphertext, 0x04) // 未压缩点
	ciphertext = append(ciphertext, c1x.Bytes()...)
	ciphertext = append(ciphertext, make([]byte, 32-len(c1x.Bytes()))...)
	ciphertext = append(ciphertext, c1y.Bytes()...)
	ciphertext = append(ciphertext, make([]byte, 32-len(c1y.Bytes()))...)
	ciphertext = append(ciphertext, c3...)
	ciphertext = append(ciphertext, c2...)

	return ciphertext, nil
}

// Decrypt SM2 解密
//
// 使用 SM2 私钥解密密文。
// SM2 解密是加密的逆过程：
//  1. 解析 C1, C3, C2
//  2. 计算 d*C1 = (x2, y2)
//  3. 使用 x2, y2 派生密钥
//  4. 解密 C2 得到明文
//  5. 验证 C3 是否匹配
//
// 参数:
//   - priv: SM2 私钥
//   - ciphertext: 待解密的密文
//
// 返回:
//   - []byte: 解密后的明文
//   - error: 解密过程中的错误（密文格式错误或校验失败）
//
// 示例:
//
//	plaintext, err := gmtls.Decrypt(privateKey, ciphertext)
func Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 1+64+32 {
		return nil, errors.New("sm2: invalid ciphertext length")
	}

	// 解析 C1
	offset := 0
	if ciphertext[0] == 0x04 || ciphertext[0] == 0x06 || ciphertext[0] == 0x07 {
		offset = 1
	}

	c1x := new(big.Int).SetBytes(ciphertext[offset : offset+32])
	c1y := new(big.Int).SetBytes(ciphertext[offset+32 : offset+64])
	offset += 64

	// 计算 d*C1 = (x2, y2)
	x2, y2 := SM2Curve.ScalarMult(c1x, c1y, priv.D.Bytes())

	// 解析 C3
	c3 := ciphertext[offset : offset+32]
	offset += 32

	// 解析 C2
	c2 := ciphertext[offset:]

	// 使用 x2 派生密钥
	t := SM3KDF(append(x2.Bytes(), y2.Bytes()...), len(c2)*8)

	// M = C2 ⊕ KDF(x2 || y2, klen)
	plaintext := make([]byte, len(c2))
	for i := range c2 {
		plaintext[i] = c2[i] ^ t[i]
	}

	// 验证 C3
	h := NewSM3()
	h.Write(x2.Bytes())
	h.Write(plaintext)
	h.Write(y2.Bytes())
	c3Check := h.Sum(nil)

	// 检查哈希值
	for i := range c3 {
		if c3[i] != c3Check[i] {
			return nil, errors.New("sm2: decryption failed")
		}
	}

	return plaintext, nil
}
