//go:build ignore
// +build ignore

package gmtls

import (
	"encoding/binary"
	"hash"
)

// ============= TLS 1.3 密钥派生 =============
// 基于 RFC 8446 Section 7.1

// TLS 1.3 密钥派生标签
var (
	tls13LabelDerived         = []byte("derived")
	tls13LabelEarlySecret     = []byte("c e traffic")
	tls13LabelClientEarly     = []byte("c e traffic")
	tls13LabelEarlyExport     = []byte("e exp master")
	tls13LabelHandshakeSecret = []byte("handshake traffic")
	tls13LabelClientHandshake = []byte("c hs traffic")
	tls13LabelServerHandshake = []byte("s hs traffic")
	tls13LabelMasterSecret    = []byte("c ap traffic")
	tls13LabelClientTraffic   = []byte("c ap traffic")
	tls13LabelServerTraffic   = []byte("s ap traffic")
	tls13LabelKeyUpdate       = []byte("traffic upd")
	tls13LabelFinished        = []byte("finished")
	tls13LabelResumption      = []byte("resumption")
	tls13LabelResMaster       = []byte("res master")
)

// SM3HashSize 是 SM3 哈希输出大小
const SM3HashSize = 32

// ============= HKDF (HMAC-based Key Derivation) =============
// 基于 RFC 5869，使用 SM3 作为哈希函数

// HKDFExtract 提取密钥
// salt 可选，如果不提供则使用零哈希
func SM3HKDFExtract(secret, salt []byte) []byte {
	if salt == nil {
		// 如果没有 salt，使用零哈希
		salt = make([]byte, SM3HashSize)
	}

	hmac := NewSM3HMAC(salt)
	hmac.Write(secret)
	return hmac.Sum(nil)
}

// HKDFExpand 扩展密钥
func SM3HKDFExpand(secret, info []byte, keyLen int) []byte {
	var result []byte

	// 根据输出长度计算需要的迭代次数
	// SM3 输出 32 字节
	h := SM3HashSize
	n := (keyLen + h - 1) / h

	for i := 1; i <= n; i++ {
		// T(i) = HMAC(secret, T(i-1) | info | 0x01)
		hmac := NewSM3HMAC(secret)

		// T(i-1) (对于 i=1，这是空)
		if i > 1 {
			hmac.Write(result[(i-2)*h : (i-1)*h])
		}

		// info
		hmac.Write(info)

		// 迭代计数器
		hmac.Write([]byte{byte(i)})

		// 计算并追加结果
		result = append(result, hmac.Sum(nil)...)
	}

	return result[:keyLen]
}

// HKDFExpandLabel TLS 1.3 专用的 HKDF-Expand-Label
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//
//	HKDF-Expand(Secret, HkdfLabel, Length)
//
// HkdfLabel = length(2) || label_length(1) || "tls13 " || Label || context_length(1) || Context
func SM3HKDFExpandLabel(secret []byte, label string, context []byte, keyLen int) []byte {
	labelPrefix := "tls13 "
	fullLabelLen := len(labelPrefix) + len(label)
	if fullLabelLen > 255 || len(context) > 255 {
		panic("tls13: hkdf label/context too long")
	}

	hkdfLabel := make([]byte, 2+1+fullLabelLen+1+len(context))
	// Length (2 bytes)
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(keyLen))
	// label length (1 byte)
	hkdfLabel[2] = byte(fullLabelLen)
	// "tls13 " + label
	copy(hkdfLabel[3:], labelPrefix)
	copy(hkdfLabel[3+len(labelPrefix):], label)
	// context length (1 byte)
	hkdfLabel[3+fullLabelLen] = byte(len(context))
	// context
	copy(hkdfLabel[3+fullLabelLen+1:], context)

	return SM3HKDFExpand(secret, hkdfLabel, keyLen)
}

// DeriveSecret 派生密钥
// DeriveSecret(Secret, Label, Messages) =
//
//	HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.Length)
func DeriveSecret(secret, label []byte, hashValue []byte) []byte {
	return SM3HKDFExpandLabel(secret, string(label), hashValue, SM3HashSize)
}

// ============= TLS 1.3 密钥调度 =============
// 基于 RFC 8446 Section 7.1

// TranscriptHash 计算握手消息的哈希
func TranscriptHash(hash hash.Hash, messages ...[]byte) []byte {
	hash.Reset()
	for _, msg := range messages {
		hash.Write(msg)
	}
	return hash.Sum(nil)
}

// DeriveEarlySecret 派生早期密钥
// Early Secret = Derive-Secret(0-RTT, Label, "")
func DeriveEarlySecret(psk []byte) []byte {
	// Early Secret = HKDF-Extract(0, PSK)
	if len(psk) == 0 {
		psk = make([]byte, SM3HashSize)
	}
	salt := make([]byte, SM3HashSize)
	return SM3HKDFExtract(psk, salt)
}

// DeriveHandshakeSecret 派生握手密钥
// Handshake Secret = Derive-Secret(Derive-Secret(Early Secret,
//
//	                 "derived",
//	                 Hash(ClientHello...)),
//	"handshake traffic",
//	Hash(ClientHello...ServerHello...))
func DeriveHandshakeSecret(earlySecret, sharedSecret []byte) []byte {
	// derived_secret = Derive-Secret(Early Secret, "derived", "")
	emptyHash := TranscriptHash(NewSM3())
	derivedSecret := DeriveSecret(earlySecret, tls13LabelDerived, emptyHash)

	// handshake_secret = HKDF-Extract(derived_secret, shared_secret)
	return SM3HKDFExtract(sharedSecret, derivedSecret)
}

// DeriveMasterSecret 派生主密钥
// Master Secret = Derive-Secret(Derive-Secret(Handshake Secret,
//
//	             "derived",
//	             Hash(...ServerHello...)),
//	"derived",
//	Hash(...))
func DeriveMasterSecret(handshakeSecret []byte) []byte {
	// derived_secret = Derive-Secret(Handshake Secret, "derived", "")
	emptyHash := TranscriptHash(NewSM3())
	derivedSecret := DeriveSecret(handshakeSecret, tls13LabelDerived, emptyHash)

	// master_secret = HKDF-Extract(derived_secret, 0)
	zeroKey := make([]byte, SM3HashSize)
	return SM3HKDFExtract(zeroKey, derivedSecret)
}

// DeriveTrafficKeys 派生流量密钥
// 返回 key 和 iv
// TLS 1.3: key 和 IV 使用不同的标签派生
func DeriveTrafficKeys(secret []byte, unusedLabel []byte, keyLen int, ivLen int) ([]byte, []byte) {
	// 根据TLS 1.3 RFC 8446:
	// key = HKDF-Expand-Label(Secret, "key", "", key_length)
	// iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)

	// Context 应该是空字节数组
	context := []byte{}

	// 使用 "key" 标签派生密钥
	key := SM3HKDFExpandLabel(secret, "key", context, keyLen)

	// 使用 "iv" 标签派生IV
	iv := SM3HKDFExpandLabel(secret, "iv", context, ivLen)

	return key, iv
}

// ============= TLS 1.3 密钥材料 =============

// TLS13KeyMaterial TLS 1.3 密钥材料
type TLS13KeyMaterial struct {
	// Key Share 密钥交换
	ClientPrivateShare     interface{} // 客户端主私钥 (SM2: *PrivateKey)
	ClientX25519PrivateKey []byte      // 客户端 X25519 私钥 (如果使用 X25519)
	ServerPublicShare      []byte      // 服务端公钥 (X25519: 32字节 或 SM2: 65字节未压缩格式)
	SharedSecret           []byte      // ECDHE 共享密钥（用于派生）

	// 客户端密钥
	ClientHandshakeKey           []byte
	ClientHandshakeIV            []byte
	ClientHandshakeTrafficSecret []byte

	// 服务端密钥
	ServerHandshakeKey           []byte
	ServerHandshakeIV            []byte
	ServerHandshakeTrafficSecret []byte

	// 应用密钥
	ClientAppKey           []byte
	ClientAppIV            []byte
	ClientAppTrafficSecret []byte

	ServerAppKey           []byte
	ServerAppIV            []byte
	ServerAppTrafficSecret []byte

	// 主密钥
	MasterSecret []byte

	// Resumption master secret (for tickets)
	ResumptionMasterSecret []byte
}

// DeriveAllKeys 派生所有密钥
func DeriveAllKeys(suite *CipherSuiteInfo, sharedSecret, clientHelloHash, serverHelloHash, finishedHash []byte) *TLS13KeyMaterial {
	km := &TLS13KeyMaterial{}

	// 1. 派生 Early Secret
	earlySecret := DeriveEarlySecret(nil)

	// 2. 派生 Handshake Secret
	handshakeSecret := DeriveHandshakeSecret(earlySecret, sharedSecret)

	// 3. 派生握手流量密钥
	km.ClientHandshakeTrafficSecret = DeriveSecret(handshakeSecret, tls13LabelClientHandshake, serverHelloHash)
	km.ServerHandshakeTrafficSecret = DeriveSecret(handshakeSecret, tls13LabelServerHandshake, serverHelloHash)

	km.ClientHandshakeKey, km.ClientHandshakeIV = DeriveTrafficKeys(
		km.ClientHandshakeTrafficSecret,
		[]byte("key"),
		suite.KeyLen,
		suite.IVLen,
	)

	km.ServerHandshakeKey, km.ServerHandshakeIV = DeriveTrafficKeys(
		km.ServerHandshakeTrafficSecret,
		[]byte("iv"),
		suite.KeyLen,
		suite.IVLen,
	)

	// 4. 派生 Master Secret
	km.MasterSecret = DeriveMasterSecret(handshakeSecret)
	km.ResumptionMasterSecret = DeriveResumptionMasterSecret(km.MasterSecret)

	// 5. 派生应用流量密钥（需要完整握手 transcript hash）
	if len(finishedHash) > 0 {
		km.ClientAppTrafficSecret = DeriveSecret(km.MasterSecret, tls13LabelClientTraffic, finishedHash)
		km.ServerAppTrafficSecret = DeriveSecret(km.MasterSecret, tls13LabelServerTraffic, finishedHash)

		km.ClientAppKey, km.ClientAppIV = DeriveTrafficKeys(
			km.ClientAppTrafficSecret,
			[]byte("key"),
			suite.KeyLen,
			suite.IVLen,
		)

		km.ServerAppKey, km.ServerAppIV = DeriveTrafficKeys(
			km.ServerAppTrafficSecret,
			[]byte("key"),
			suite.KeyLen,
			suite.IVLen,
		)
	}

	return km
}

// DeriveResumptionMasterSecret derives the resumption master secret (RFC 8446).
func DeriveResumptionMasterSecret(masterSecret []byte) []byte {
	emptyHash := TranscriptHash(NewSM3())
	return SM3HKDFExpandLabel(masterSecret, string(tls13LabelResMaster), emptyHash, SM3HashSize)
}

// DeriveResumptionPSK derives the PSK for a NewSessionTicket.
func DeriveResumptionPSK(resumptionMasterSecret, nonce []byte) []byte {
	return SM3HKDFExpandLabel(resumptionMasterSecret, string(tls13LabelResumption), nonce, SM3HashSize)
}

// ============= TLS 1.3 Finished 消息计算 =============

// VerifyDataTLS13 计算 TLS 1.3 Finished 消息的 verify_data
// verify_data = HMAC(
//
//	finished_key,
//	Hash(Handshake Context + Transcript-Hash)
//
// )
func VerifyDataTLS13(finishedKey, transcriptHash []byte) []byte {
	hmac := NewSM3HMAC(finishedKey)
	hmac.Write(transcriptHash)
	return hmac.Sum(nil)[:32] // 使用前 32 字节
}

// DeriveFinishedKey 派生 TLS 1.3 Finished key
// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
func DeriveFinishedKey(baseKey []byte) []byte {
	// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
	return SM3HKDFExpandLabel(baseKey, string(tls13LabelFinished), []byte{}, SM3HashSize)
}
