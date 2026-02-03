package gmtls

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
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

	// TLS 1.3 国密密码套件（与 BabaSSL 兼容）
	TLS_SM4_GCM_SM3 uint16 = 0x1306 // RFC 8446 标准值
	TLS_SM4_CCM_SM3 uint16 = 0x1307 // RFC 8446 标准值

	// 临时测试：BabaSSL 可能使用的值
	// TODO: 需要确认 BabaSSL 的实际值
	TLS_SM4_GCM_SM3_ALT uint16 = 0x00C6 // 可能的 BabaSSL 值
	TLS_SM4_CCM_SM3_ALT uint16 = 0x00C7 // 可能的 BabaSSL 值
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
	{
		ID:            TLS_SM2_WITH_SM4_CBC_SM3,
		Name:          "SM2-WITH-SM4-CBC-SM3",
		KeyExchange:   "SM2",
		Encryption:    "SM4-CBC",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         16,
		FixedIVLen:    0,
		ExplicitIVLen: 16,
		MACLen:        32, // SM3-256
		TagLen:        0,
		IsAEAD:        false,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS12,
	},
	{
		ID:            TLS_SM2DHE_WITH_SM4_CBC_SM3,
		Name:          "SM2DHE-WITH-SM4-CBC-SM3",
		KeyExchange:   "SM2DHE",
		Encryption:    "SM4-CBC",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         16,
		FixedIVLen:    0,
		ExplicitIVLen: 16,
		MACLen:        32, // SM3-256
		TagLen:        0,
		IsAEAD:        false,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS12,
	},
	{
		ID:            TLS_SM2_WITH_SM4_GCM_SM3,
		Name:          "SM2-WITH-SM4-GCM-SM3",
		KeyExchange:   "SM2",
		Encryption:    "SM4-GCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         4,  // TLS 1.2 fixed IV length
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS13,
	},
	{
		ID:            TLS_SM2DHE_WITH_SM4_GCM_SM3,
		Name:          "SM2DHE-WITH-SM4-GCM-SM3",
		KeyExchange:   "SM2DHE",
		Encryption:    "SM4-GCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         4,  // TLS 1.2 fixed IV length
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS13,
	},
	{
		ID:            TLS_SM2_WITH_SM4_CCM_SM3,
		Name:          "SM2-WITH-SM4-CCM-SM3",
		KeyExchange:   "SM2",
		Encryption:    "SM4-CCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         4,  // TLS 1.2 fixed IV length
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS12,
	},
	{
		ID:            TLS_SM2DHE_WITH_SM4_CCM_SM3,
		Name:          "SM2DHE-WITH-SM4-CCM-SM3",
		KeyExchange:   "SM2DHE",
		Encryption:    "SM4-CCM",
		Hash:          "SM3",
		KeyLen:        16, // SM4-128
		IVLen:         12, // CCM nonce size
		FixedIVLen:    4,
		ExplicitIVLen: 8,
		MACLen:        0,
		TagLen:        16,
		IsAEAD:        true,
		MinTLSVersion: VersionTLS12,
		MaxTLSVersion: VersionTLS12,
	},
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

// GetCipherSuiteByID 根据 ID 获取密码套件信息
func GetCipherSuiteByID(id uint16) *CipherSuiteInfo {
	// 首先查找标准 ID
	for _, suite := range cipherSuites {
		if suite.ID == id {
			return suite
		}
	}

	// 特殊处理 BabaSSL 的非标准 ID
	if id == TLS_SM4_GCM_SM3_ALT {
		// 返回对应的 TLS 1.3 密码套件信息（保留非标准 ID）
		for _, suite := range cipherSuites {
			if suite.ID == TLS_SM4_GCM_SM3 {
				clone := *suite
				clone.ID = id
				return &clone
			}
		}
	}
	if id == TLS_SM4_CCM_SM3_ALT {
		for _, suite := range cipherSuites {
			if suite.ID == TLS_SM4_CCM_SM3 {
				clone := *suite
				clone.ID = id
				return &clone
			}
		}
	}

	return nil
}

// GetCipherSuiteByName 根据名称获取密码套件信息
func GetCipherSuiteByName(name string) *CipherSuiteInfo {
	for _, suite := range cipherSuites {
		if suite.Name == name {
			return suite
		}
	}
	return nil
}

// AllCipherSuites 返回所有支持的密码套件
func AllCipherSuites() []*CipherSuiteInfo {
	return cipherSuites
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

// SM4CBCMode SM4 CBC 模式实现 TLS 1.2 记录层加密
type SM4CBCMode struct {
	key        []byte
	macKey     []byte
	iv         []byte
	hmac       hash.Hash
	encCipher  cipher.BlockMode
	decCipher  cipher.BlockMode
	seq        uint64
	explicitIV bool
}

// NewSM4CBCMode 创建 SM4 CBC 模式
func NewSM4CBCMode(key, macKey, iv []byte, explicitIV bool) (*SM4CBCMode, error) {
	if len(key) != SM4KeySize || len(macKey) != SM3Size || len(iv) != SM4BlockSize {
		return nil, errors.New("gmtls: invalid key size for SM4-CBC")
	}

	c := &SM4CBCMode{
		key:        make([]byte, len(key)),
		macKey:     make([]byte, len(macKey)),
		iv:         make([]byte, len(iv)),
		hmac:       NewSM3HMAC(macKey),
		seq:        0,
		explicitIV: explicitIV,
	}
	copy(c.key, key)
	copy(c.macKey, macKey)
	copy(c.iv, iv)

	return c, nil
}

// Encrypt 加密 TLS 记录
func (m *SM4CBCMode) Encrypt(recordType recordType, data []byte) ([]byte, error) {
	// CBC 模式: MAC || padding || encrypt
	// MAC = HMAC(MAC_key, seq_num || type || version || length || data)

	// 计算 MAC
	macData := make([]byte, 13+len(data))
	binary.BigEndian.PutUint64(macData[0:8], m.seq)
	macData[8] = byte(recordType)
	binary.BigEndian.PutUint16(macData[9:11], VersionTLS12)
	binary.BigEndian.PutUint16(macData[11:13], uint16(len(data)))
	copy(macData[13:], data)

	m.hmac.Reset()
	m.hmac.Write(macData)
	mac := m.hmac.Sum(nil)

	// 拼接数据 + MAC
	content := make([]byte, len(data)+len(mac))
	copy(content, data)
	copy(content[len(data):], mac)

	// PKCS#7 填充
	padding := SM4BlockSize - (len(content) % SM4BlockSize)
	paddedContent := make([]byte, len(content)+padding)
	copy(paddedContent, content)
	for i := len(content); i < len(paddedContent); i++ {
		paddedContent[i] = byte(padding)
	}

	// 准备 IV
	iv := make([]byte, SM4BlockSize)
	if m.explicitIV {
		// 使用显式 IV，从全局 RandReader 读取随机数据
		if _, err := RandReader.Read(iv); err != nil {
			return nil, err
		}
	} else {
		copy(iv, m.iv)
	}

	// 加密
	cbc := NewSM4CBCEncrypter(m.key, iv)
	ciphertext := make([]byte, len(paddedContent))
	cbc.CryptBlocks(ciphertext, paddedContent)

	// 如果使用显式 IV，在密文前添加 IV
	result := ciphertext
	if m.explicitIV {
		result = append(iv, ciphertext...)
	}

	// 更新序列号
	m.seq++

	return result, nil
}

// Decrypt 解密 TLS 记录
func (m *SM4CBCMode) Decrypt(recordType recordType, data []byte) ([]byte, error) {
	// 提取显式 IV（如果有）
	iv := make([]byte, SM4BlockSize)
	ciphertext := data

	if m.explicitIV {
		if len(data) < SM4BlockSize {
			return nil, errors.New("gmtls: ciphertext too short for explicit IV")
		}
		copy(iv, data[:SM4BlockSize])
		ciphertext = data[SM4BlockSize:]
	} else {
		copy(iv, m.iv)
	}

	if len(ciphertext)%SM4BlockSize != 0 {
		return nil, errors.New("gmtls: ciphertext is not a multiple of the block size")
	}

	// 解密
	cbc := NewSM4CBCDecrypter(m.key, iv)
	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	// 去除填充
	padding := int(plaintext[len(plaintext)-1])
	if padding < 1 || padding > SM4BlockSize {
		return nil, errors.New("gmtls: invalid padding")
	}
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, errors.New("gmtls: invalid padding")
		}
	}
	content := plaintext[:len(plaintext)-padding]

	// 验证 MAC
	if len(content) < SM3Size {
		return nil, errors.New("gmtls: content too short for MAC")
	}

	dataPart := content[:len(content)-SM3Size]
	mac := content[len(content)-SM3Size:]

	// 计算期望的 MAC
	macData := make([]byte, 13+len(dataPart))
	binary.BigEndian.PutUint64(macData[0:8], m.seq)
	macData[8] = byte(recordType)
	binary.BigEndian.PutUint16(macData[9:11], VersionTLS12)
	binary.BigEndian.PutUint16(macData[11:13], uint16(len(dataPart)))
	copy(macData[13:], dataPart)

	m.hmac.Reset()
	m.hmac.Write(macData)
	expectedMac := m.hmac.Sum(nil)

	// 验证 MAC
	if subtle.ConstantTimeCompare(mac, expectedMac) != 1 {
		return nil, errors.New("gmtls: MAC verification failed")
	}

	// 更新序列号
	m.seq++

	return dataPart, nil
}

// ============= TLS 1.3 AEAD 实现 =============

// SM4GCMMode SM4 GCM 模式实现 TLS 1.2/1.3 记录层加密
type SM4GCMMode struct {
	key        []byte
	fixedIV    []byte
	writeSeq   uint64 // 发送序列号
	readSeq    uint64 // 接收序列号
	explicitIV bool
	tls13      bool // 是否为 TLS 1.3 模式
}

const gcmTagSize = 16

// NewSM4GCMMode 创建 SM4 GCM 模式
func NewSM4GCMMode(key, fixedIV []byte, explicitIV bool, tls13 bool) (*SM4GCMMode, error) {
	if len(key) != SM4KeySize {
		return nil, errors.New("gmtls: invalid key size for SM4-GCM")
	}

	// 确保 IV 长度正确
	ivLen := 4
	if tls13 {
		ivLen = 12 // TLS 1.3 使用完整的 12 字节 IV
	}

	if len(fixedIV) != ivLen {
		return nil, errors.New("gmtls: invalid IV length for SM4-GCM")
	}

	// 只创建cipher，不要提前创建AEAD实例，因为每次加密需要不同的nonce
	c := &SM4GCMMode{
		key:        make([]byte, len(key)),
		fixedIV:    make([]byte, len(fixedIV)),
		writeSeq:   0,
		readSeq:    0,
		explicitIV: explicitIV,
		tls13:      tls13,
	}
	copy(c.key, key)
	copy(c.fixedIV, fixedIV)

	return c, nil
}

// Encrypt TLS 1.2/1.3 风格加密
func (m *SM4GCMMode) Encrypt(recordType recordType, data []byte) ([]byte, error) {
	var (
		nonce      []byte
		explicitIV []byte
	)

	if m.tls13 {
		// TLS 1.3: append inner content type
		data = append(data, byte(recordType))
		// TLS 1.3: nonce = fixed_iv XOR seq_num
		// 序列号 XOR 到 fixed_iv 的最后 8 字节 (RFC 8446 Section 5.3)
		nonce = make([]byte, 12)
		copy(nonce, m.fixedIV)
		seqBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqBytes, m.writeSeq)
		for i := 0; i < 8; i++ {
			nonce[12-8+i] ^= seqBytes[i] // XOR 到最后 8 字节
		}
		if debugEnabled {
			debugf("DEBUG Encrypt: seq=%d, innerType=%d, data_len=%d\n", m.writeSeq, recordType, len(data))
		}
	} else {
		// TLS 1.2: nonce = fixed_iv || explicit_iv (RFC 5288)
		nonce = make([]byte, 12)
		copy(nonce, m.fixedIV)
		explicitIV = make([]byte, 8)
		if m.explicitIV {
			if _, err := RandReader.Read(explicitIV); err != nil {
				return nil, err
			}
		} else {
			binary.BigEndian.PutUint64(explicitIV, m.writeSeq)
		}
		copy(nonce[4:], explicitIV)
	}

	// 构造 additional data
	var ad []byte
	if m.tls13 {
		// TLS 1.3: type || version || length
		// 注意：TLS 1.3 的 AD 中版本号仍然是 0x0303 (TLS 1.2)，用于兼容性
		ad = make([]byte, 5)
		// Encrypted TLS 1.3 records always use application_data as outer type
		ad[0] = byte(recordTypeApplicationData)
		binary.BigEndian.PutUint16(ad[1:3], 0x0303) // TLS 1.2 版本
		// TLS 1.3 record length = ciphertext length (plaintext + tag)
		adLen := len(data) + gcmTagSize
		binary.BigEndian.PutUint16(ad[3:5], uint16(adLen))
	} else {
		// TLS 1.2: seq || type || version || length
		ad = make([]byte, 13)
		binary.BigEndian.PutUint64(ad[0:8], m.writeSeq)
		ad[8] = byte(recordType)
		binary.BigEndian.PutUint16(ad[9:11], VersionTLS12)
		binary.BigEndian.PutUint16(ad[11:13], uint16(len(data)))
	}

	// 创建 AEAD 实例
	aead := NewSM4GCM(m.key, nonce)

	// 加密
	ciphertext := aead.Seal(nil, nonce, data, ad)

	// 更新序列号
	m.writeSeq++

	if !m.tls13 && m.explicitIV {
		// TLS 1.2: prepend explicit IV to ciphertext
		out := make([]byte, 0, len(explicitIV)+len(ciphertext))
		out = append(out, explicitIV...)
		out = append(out, ciphertext...)
		return out, nil
	}

	return ciphertext, nil
}

// Decrypt TLS 1.2/1.3 风格解密
func (m *SM4GCMMode) Decrypt(recordType recordType, data []byte) ([]byte, error) {
	var (
		nonce      []byte
		explicitIV []byte
		ciphertext []byte
	)

	if m.tls13 {
		// TLS 1.3: nonce = fixed_iv XOR seq_num
		// 序列号 XOR 到 fixed_iv 的最后 8 字节 (RFC 8446 Section 5.3)
		nonce = make([]byte, 12)
		copy(nonce, m.fixedIV)
		seqBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqBytes, m.readSeq)
		for i := 0; i < 8; i++ {
			nonce[12-8+i] ^= seqBytes[i] // XOR 到最后 8 字节
		}
	} else {
		// TLS 1.2: nonce = fixed_iv || explicit_iv (RFC 5288)
		if m.explicitIV {
			if len(data) < 8+gcmTagSize {
				return nil, errors.New("gmtls: ciphertext too short for explicit IV")
			}
			explicitIV = data[:8]
			ciphertext = data[8:]
		} else {
			ciphertext = data
			explicitIV = make([]byte, 8)
			binary.BigEndian.PutUint64(explicitIV, m.readSeq)
		}
		nonce = make([]byte, 12)
		copy(nonce, m.fixedIV)
		copy(nonce[4:], explicitIV)
	}

	// 构造 additional data
	// 在TLS中，解密时我们需要知道加密时使用的原始数据长度
	// 这个信息通常由接收方通过协议层面获知
	// 在真实的TLS实现中，这个长度是通过记录头或其他协议机制确定的
	// 为了使解密正确工作，我们需要使用与加密时相同的长度信息
	// 但实际中，我们无法仅从密文推断出原始数据长度

	// 实际的解决方案是：在TLS记录层，当我们收到一条加密记录时，
	// 我们需要知道这条记录在加密前的原始长度，这样才能构造正确的AD
	// 这意味着需要对API进行一些调整，或者在TLS实现中维护这种信息

	// 在当前实现中，我们采用一个变通方案：假设认证标签长度为16字节
	// 这在大多数GCM实现中是标准的，但严格来说这不是TLS标准的要求
	// 在实际的TLS实现中，标签长度是由密码套件确定的
	tagLen := gcmTagSize

	var ad []byte
	if m.tls13 {
		// TLS 1.3: type || version || length
		// 注意：TLS 1.3 的 AD 中版本号仍然是 0x0303 (TLS 1.2)，用于兼容性
		ad = make([]byte, 5)
		// Encrypted TLS 1.3 records always use application_data as outer type
		ad[0] = byte(recordTypeApplicationData)
		binary.BigEndian.PutUint16(ad[1:3], 0x0303) // TLS 1.2 版本
		// TLS 1.3 record length equals ciphertext length (data already includes tag).
		adLen := len(data)
		binary.BigEndian.PutUint16(ad[3:5], uint16(adLen))
	} else {
		// TLS 1.2: seq || type || version || length
		ad = make([]byte, 13)
		binary.BigEndian.PutUint64(ad[0:8], m.readSeq)
		ad[8] = byte(recordType)
		binary.BigEndian.PutUint16(ad[9:11], VersionTLS12)
		// 计算加密时的原始数据长度 (密文长度 - 标签长度)
		originalDataLen := len(ciphertext) - tagLen
		if originalDataLen < 0 {
			originalDataLen = 0 // 防止负数
		}
		binary.BigEndian.PutUint16(ad[11:13], uint16(originalDataLen))
	}

	// 创建 AEAD 实例
	aead := NewSM4GCM(m.key, nonce)

	// DEBUG: 输出解密参数
	if m.tls13 && debugEnabled {
		debugf("DEBUG Decrypt: seq=%d, nonce=%02x, ad=%02x, key=%02x, data_len=%d\n",
			m.readSeq, nonce, ad, m.key, len(data))
		debugf("DEBUG Decrypt: encrypted_data=%02x\n", data)
		// 解析加密数据
		tagLen := 16
		if len(data) > tagLen {
			ciphertext := data[:len(data)-tagLen]
			tag := data[len(data)-tagLen:]
			debugf("DEBUG Decrypt: ciphertext_len=%d, ciphertext=%02x\n", len(ciphertext), ciphertext)
			debugf("DEBUG Decrypt: tag=%02x\n", tag)
		}
	}

	// 解密
	if ciphertext == nil {
		ciphertext = data
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		if m.tls13 && debugEnabled {
			debugln("DEBUG Decrypt: authentication failed")
		}
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

// ============= 密钥派生 =============

// PRF TLS 伪随机函数 (使用 SM3)
func PRF(secret, label, seed []byte, keyLen int) []byte {
	// TLS 1.2 PRF with SM3
	// PRF(secret, label, seed) = P_SM3(secret, label + seed)
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	return pSM3(secret, labelAndSeed, keyLen)
}

// pSM3 SM3-based P_hash 函数
func pSM3(secret, seed []byte, keyLen int) []byte {
	// P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
	//                         HMAC_hash(secret, A(2) + seed) + ...
	// 其中 A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))

	var result []byte

	// 计算 HMAC 的块大小
	// SM3 块大小为 64 字节
	blockSize := 64

	// 如果 secret 太长，先进行哈希
	if len(secret) > blockSize {
		h := SM3(secret)
		secret = h[:]
	}

	A := seed
	for len(result) < keyLen {
		// A(i) = HMAC(secret, A(i-1))
		hmacA := NewSM3HMAC(secret)
		hmacA.Write(A)
		A = hmacA.Sum(nil)

		// HMAC(secret, A(i) + seed)
		hmacOut := NewSM3HMAC(secret)
		hmacOut.Write(A)
		hmacOut.Write(seed)
		result = append(result, hmacOut.Sum(nil)...)
	}

	return result[:keyLen]
}

// MasterSecretDerive 从预主密钥派生主密钥
func MasterSecretDerive(preMasterSecret, clientRandom, serverRandom []byte) []byte {
	// master_secret = PRF(pre_master_secret, "master secret",
	//                     ClientHello.random + ServerHello.random)[48]

	label := []byte("master secret")
	seed := make([]byte, len(clientRandom)+len(serverRandom))
	copy(seed, clientRandom)
	copy(seed[len(clientRandom):], serverRandom)

	return PRF(preMasterSecret, label, seed, 48)
}

// KeyBlockDerive 从主密钥派生密钥块
func KeyBlockDerive(masterSecret, clientRandom, serverRandom []byte, suite *CipherSuiteInfo) []byte {
	// key_block = PRF(master_secret, "key expansion",
	//                 ServerHello.random + ClientHello.random)
	//         = client_write_MAC_key + server_write_MAC_key +
	//           client_write_key + server_write_key +
	//           client_write_IV + server_write_IV

	label := []byte("key expansion")
	seed := make([]byte, len(serverRandom)+len(clientRandom))
	copy(seed, serverRandom)
	copy(seed[len(serverRandom):], clientRandom)

	keyLen := suite.MACLen*2 + suite.KeyLen*2 + suite.IVLen*2
	return PRF(masterSecret, label, seed, keyLen)
}

// ParseKeyBlock 解析密钥块
func ParseKeyBlock(keyBlock []byte, suite *CipherSuiteInfo) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	offset := 0

	clientMAC = keyBlock[offset : offset+suite.MACLen]
	offset += suite.MACLen

	serverMAC = keyBlock[offset : offset+suite.MACLen]
	offset += suite.MACLen

	clientKey = keyBlock[offset : offset+suite.KeyLen]
	offset += suite.KeyLen

	serverKey = keyBlock[offset : offset+suite.KeyLen]
	offset += suite.KeyLen

	if suite.IVLen > 0 {
		clientIV = keyBlock[offset : offset+suite.IVLen]
		offset += suite.IVLen

		serverIV = keyBlock[offset : offset+suite.IVLen]
		offset += suite.IVLen
	}

	return
}
