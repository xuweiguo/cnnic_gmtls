package gmtls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// ============= TLS 密码套件常量 =============
// 与 Tongsuo 兼容的密码套件 ID

const (
	// TLS 1.2 国密密码套件
	TLS_SM2_WITH_SM4_CBC_SM3    uint16 = 0xE0 // 0x00E0
	TLS_SM2DHE_WITH_SM4_CBC_SM3 uint16 = 0xE1 // 0x00E1
	TLS_SM2_WITH_SM4_GCM_SM3    uint16 = 0xE2 // 0x00E2
	TLS_SM2DHE_WITH_SM4_GCM_SM3 uint16 = 0xE3 // 0x00E3
	TLS_SM2_WITH_SM4_CCM_SM3    uint16 = 0xE4 // 0x00E4
	TLS_SM2DHE_WITH_SM4_CCM_SM3 uint16 = 0xE5 // 0x00E5

	// TLS 1.3 国密密码套件
	// RFC 8998 §2 规定:ECC-SM4-GCM-SM3 = {0x00,0xC6}、ECC-SM4-CCM-SM3 = {0x00,0xC7}。
	// 0x1306/0x1307 在任何 RFC/IANA 均无赋值,仅作备用占位值保留。
	TLS_SM4_GCM_SM3     uint16 = 0x1306 // 备用值(RFC 8998 标准值为 0x00C6)
	TLS_SM4_CCM_SM3     uint16 = 0x1307 // 备用值(RFC 8998 标准值为 0x00C7)
	TLS_SM4_GCM_SM3_ALT uint16 = 0x00C6 // RFC 8998 标准值 ECC-SM4-GCM-SM3
	TLS_SM4_CCM_SM3_ALT uint16 = 0x00C7 // RFC 8998 标准值 ECC-SM4-CCM-SM3
)

// CipherSuiteInfo 密码套件信息
type CipherSuiteInfo struct {
	ID            uint16
	Name          string
	KeyExchange   string // "SM2", "SM2DHE"
	Encryption    string // "SM4-CBC", "SM4-GCM", "SM4-CCM"
	Hash          string // "SM3"
	KeyLen        int    // 密钥长度
	IVLen         int    // IV 长度
	FixedIVLen    int    // 固定 IV 长度
	ExplicitIVLen int    // 显式 IV 长度
	MACLen        int    // MAC 长度
	TagLen        int    // AEAD tag 长度
	IsAEAD        bool   // 是否为 AEAD 模式
	MinTLSVersion uint16 // 最低 TLS 版本
	MaxTLSVersion uint16 // 最高 TLS 版本
}

// 国密密码套件信息表
var cipherSuites = []*CipherSuiteInfo{
	// TLS 1.3 密码套件
	{
		ID:            TLS_SM4_GCM_SM3,
		Name:          "TLS_SM4_GCM_SM3",
		KeyExchange:   "Any", // TLS 1.3 密钥交换独立
		Encryption:    "SM4-GCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         12, // GCM nonce size (TLS 1.3)
		FixedIVLen:    12, // TLS 1.3 使用固定 IV
		ExplicitIVLen: 0,  // TLS 1.3 不使用显式 IV
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS13,
		MaxTLSVersion: VersionTLS13,
	},
	{
		ID:            TLS_SM4_CCM_SM3,
		Name:          "TLS_SM4_CCM_SM3",
		KeyExchange:   "Any", // TLS 1.3 密钥交换独立
		Encryption:    "SM4-CCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         12, // CCM nonce size (TLS 1.3)
		FixedIVLen:    12, // TLS 1.3 使用固定 IV
		ExplicitIVLen: 0,  // TLS 1.3 不使用显式 IV
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS13,
		MaxTLSVersion: VersionTLS13,
	},
}

var (
	cipherSuitesByID   map[uint16]*CipherSuiteInfo
	cipherSuitesByName map[string]*CipherSuiteInfo
)

func cloneSuiteWithID(suite *CipherSuiteInfo, id uint16) *CipherSuiteInfo {
	if suite == nil {
		return nil
	}
	clone := *suite
	clone.ID = id
	return &clone
}

func init() {
	cipherSuitesByID = make(map[uint16]*CipherSuiteInfo, len(cipherSuites)+2)
	cipherSuitesByName = make(map[string]*CipherSuiteInfo, len(cipherSuites))

	for _, suite := range cipherSuites {
		cipherSuitesByID[suite.ID] = suite
		cipherSuitesByName[suite.Name] = suite
	}

	if base := cipherSuitesByID[TLS_SM4_GCM_SM3]; base != nil {
		cipherSuitesByID[TLS_SM4_GCM_SM3_ALT] = cloneSuiteWithID(base, TLS_SM4_GCM_SM3_ALT)
	}
	if base := cipherSuitesByID[TLS_SM4_CCM_SM3]; base != nil {
		cipherSuitesByID[TLS_SM4_CCM_SM3_ALT] = cloneSuiteWithID(base, TLS_SM4_CCM_SM3_ALT)
	}
}

// GetCipherSuiteByID 根据 ID 获取密码套件信息
func GetCipherSuiteByID(id uint16) *CipherSuiteInfo {
	return cipherSuitesByID[id]
}

// GetCipherSuiteByName 根据名称获取密码套件信息
func GetCipherSuiteByName(name string) *CipherSuiteInfo {
	return cipherSuitesByName[name]
}

// AllCipherSuites 返回所有支持的密码套件
func AllCipherSuites() []*CipherSuiteInfo {
	out := make([]*CipherSuiteInfo, len(cipherSuites))
	copy(out, cipherSuites)
	return out
}

// ============= TLS 版本常量 =============

const (
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// ============= TLS 记录层 =============

const (
	recordHeaderLen     = 5
	maxHandshakeMessage = 1 << 24
)

// recordType TLS 记录类型
type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
)

// Record TLS 记录
type Record struct {
	Type     recordType
	Version  uint16
	Length   uint16
	Data     []byte
	Seq      uint64 // 序列号
	Extended bool   // 是否使用显式 IV
}

// ============= TLS 记录层加密/解密 =============

// SM4GCMMode SM4 GCM 模式实现 TLS 1.3 记录层加密
type SM4GCMMode struct {
	key      []byte
	fixedIV  []byte
	writeSeq uint64 // 发送序列号
	readSeq  uint64 // 接收序列号
}

const gcmTagSize = 16

// NewSM4GCMMode 创建 SM4 GCM 模式
func NewSM4GCMMode(key, fixedIV []byte) (*SM4GCMMode, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("gmtls: invalid key size for SM4-GCM")
	}

	// TLS 1.3 使用完整的 12 字节 IV
	if len(fixedIV) != 12 {
		return nil, errors.New("gmtls: invalid IV length for SM4-GCM")
	}

	// 只创建cipher，不要提前创建AEAD实例，因为每次加密需要不同的nonce
	c := &SM4GCMMode{
		key:      make([]byte, len(key)),
		fixedIV:  make([]byte, len(fixedIV)),
		writeSeq: 0,
		readSeq:  0,
	}
	copy(c.key, key)
	copy(c.fixedIV, fixedIV)

	return c, nil
}

// Encrypt TLS 1.2/1.3 风格加密
func (m *SM4GCMMode) Encrypt(recordType recordType, data []byte) ([]byte, error) {
	// TLS 1.3: append inner content type
	data = append(data, byte(recordType))

	// TLS 1.3: nonce = fixed_iv XOR seq_num
	nonce := make([]byte, 12)
	copy(nonce, m.fixedIV)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, m.writeSeq)
	for i := 0; i < 8; i++ {
		nonce[12-8+i] ^= seqBytes[i] // XOR 到最后 8 字节
	}

	// TLS 1.3: type || version || length
	// 注意：TLS 1.3 的 AD 中版本号仍然是 0x0303 (TLS 1.2)，用于兼容性
	ad := make([]byte, 5)
	// Encrypted TLS 1.3 records always use application_data as outer type
	ad[0] = byte(recordTypeApplicationData)
	binary.BigEndian.PutUint16(ad[1:3], 0x0303) // TLS 1.2 版本
	// TLS 1.3 record length = ciphertext length (plaintext + tag)
	adLen := len(data) + gcmTagSize
	binary.BigEndian.PutUint16(ad[3:5], uint16(adLen))

	// 创建 AEAD 实例
	aead := NewSM4GCM(m.key, nonce)

	// 加密
	ciphertext := aead.Seal(nil, nonce, data, ad)

	// 更新序列号
	m.writeSeq++

	return ciphertext, nil
}

// Decrypt TLS 1.2/1.3 风格解密
func (m *SM4GCMMode) Decrypt(recordType recordType, data []byte) ([]byte, error) {
	// TLS 1.3: nonce = fixed_iv XOR seq_num
	nonce := make([]byte, 12)
	copy(nonce, m.fixedIV)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, m.readSeq)
	for i := 0; i < 8; i++ {
		nonce[12-8+i] ^= seqBytes[i] // XOR 到最后 8 字节
	}

	// TLS 1.3: type || version || length
	// 注意：TLS 1.3 的 AD 中版本号仍然是 0x0303 (TLS 1.2)，用于兼容性
	ad := make([]byte, 5)
	// Encrypted TLS 1.3 records always use application_data as outer type
	ad[0] = byte(recordTypeApplicationData)
	binary.BigEndian.PutUint16(ad[1:3], 0x0303) // TLS 1.2 版本
	// TLS 1.3 record length equals ciphertext length (data already includes tag).
	adLen := len(data)
	binary.BigEndian.PutUint16(ad[3:5], uint16(adLen))

	// 创建 AEAD 实例
	aead := NewSM4GCM(m.key, nonce)

	// 解密
	plaintext, err := aead.Open(nil, nonce, data, ad)
	if err != nil {
		return nil, err
	}

	// 更新序列号
	m.readSeq++

	return plaintext, nil
}

// ============= 随机数生成器 =============

// RandReader 是全局随机数读取器，用于生成密钥和 IV 等敏感数据。
// 如需测试确定性行为，可在测试中覆盖它。
var RandReader io.Reader = rand.Reader

// defaultRandReader 默认的随机数读取器（仅供测试/演示使用）。
// 使用数学库 rng (math/rand) 作为基础，实际应用中必须使用 crypto/rand。
type defaultRandReader struct {
	seed uint64
}

func newDefaultRandReader() *defaultRandReader {
	return &defaultRandReader{seed: uint64(1)}
}

func (d *defaultRandReader) Read(b []byte) (int, error) {
	// 使用简单的伪随机数生成器
	// 注意：这只是用于演示的简单实现
	// 生产环境强烈建议使用 crypto/rand:
	//
	// 替换为:
	//   import crypto/rand
	//   var RandReader = rand.Reader
	//
	// 或在应用启动时设置:
	//   gmtls.RandReader = rand.Reader

	for i := range b {
		// 简单的线性同余生成器
		d.seed = d.seed*6364136223846793005 + 1442695040888963407
		b[i] = byte(d.seed >> 56)
	}
	return len(b), nil
}
