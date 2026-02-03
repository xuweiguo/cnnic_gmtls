package gmtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
)

// ============= TLS 握手消息类型 =============

const (
	typeClientHello        uint8 = 1
	typeServerHello        uint8 = 2
	typeNewSessionTicket   uint8 = 4
	typeCertificate        uint8 = 11
	typeServerKeyExchange  uint8 = 12
	typeCertificateRequest uint8 = 13
	typeServerHelloDone    uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	// TLS 1.3 新增消息类型
	typeEncryptedExtensions uint8 = 8
	typeKeyUpdate           uint8 = 24
	typeEndOfEarlyData      uint8 = 25
	typeMessageHash         uint8 = 254
)

// ============= TLS 握手消息结构 =============

func writeUint24(dst []byte, v int) {
	dst[0] = byte(v >> 16)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v)
}

func readUint24(src []byte) int {
	return int(src[0])<<16 | int(src[1])<<8 | int(src[2])
}

// clientHelloMsg TLS ClientHello 消息
type clientHelloMsg struct {
	Version            uint16
	Random             []byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []Extension // TLS 扩展
}

// marshal 序列化 ClientHello 消息
func (m *clientHelloMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeClientHello)

	// 长度（占位）
	_ = buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 版本
	binary.Write(&buf, binary.BigEndian, m.Version)

	// 随机数
	buf.Write(m.Random)

	// Session ID
	if m.SessionID == nil {
		buf.WriteByte(0) // 空 Session ID
	} else {
		buf.WriteByte(byte(len(m.SessionID)))
		buf.Write(m.SessionID)
	}

	// 密码套件
	binary.Write(&buf, binary.BigEndian, uint16(len(m.CipherSuites)*2))
	for _, suite := range m.CipherSuites {
		binary.Write(&buf, binary.BigEndian, suite)
	}

	// 压缩方法
	binary.Write(&buf, binary.BigEndian, uint8(len(m.CompressionMethods)))
	for _, method := range m.CompressionMethods {
		buf.WriteByte(method)
	}

	// 扩展（如果有的话）
	if len(m.Extensions) > 0 {
		// 计算扩展总长度
		extTotalLen := 0
		extData := make([][]byte, len(m.Extensions))

		for i, ext := range m.Extensions {
			extData[i] = make([]byte, 4+len(ext.Data))
			binary.BigEndian.PutUint16(extData[i][0:2], ext.Type)
			binary.BigEndian.PutUint16(extData[i][2:4], uint16(len(ext.Data)))
			copy(extData[i][4:], ext.Data)
			extTotalLen += len(extData[i])
		}

		binary.Write(&buf, binary.BigEndian, uint16(extTotalLen))
		for _, extBytes := range extData {
			buf.Write(extBytes)
		}
	} else {
		// 没有扩展时写入 0 长度
		binary.Write(&buf, binary.BigEndian, uint16(0))
	}

	// 写入长度
	data := buf.Bytes()
	length := len(data) - 4 // 减去类型和长度字段
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// unmarshal 反序列化 ClientHello 消息
func (m *clientHelloMsg) unmarshal(data []byte) error {
	if len(data) < 42 {
		return errors.New("gmtls: invalid ClientHello")
	}

	if data[0] != typeClientHello {
		return errors.New("gmtls: not a ClientHello")
	}

	// 跳过消息类型(1)和消息长度(3)，从data[4]开始
	m.Version = binary.BigEndian.Uint16(data[4:6])
	m.Random = data[6:38]

	// 跳过 session ID
	offset := 38
	if offset >= len(data) {
		return errors.New("gmtls: invalid ClientHello message")
	}
	sessionIDLen := int(data[offset])
	offset += 1
	if offset+sessionIDLen > len(data) {
		return errors.New("gmtls: invalid session ID")
	}
	if sessionIDLen > 0 {
		m.SessionID = make([]byte, sessionIDLen)
		copy(m.SessionID, data[offset:offset+sessionIDLen])
	}
	offset += sessionIDLen

	// 密码套件
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid cipher suites")
	}
	suiteLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+suiteLen > len(data) {
		return errors.New("gmtls: cipher suites length mismatch")
	}
	m.CipherSuites = make([]uint16, suiteLen/2)
	for i := 0; i < suiteLen/2; i++ {
		m.CipherSuites[i] = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// 压缩方法
	if offset >= len(data) {
		return errors.New("gmtls: invalid compression methods")
	}
	compressionLen := int(data[offset])
	offset += 1
	if offset+compressionLen > len(data) {
		return errors.New("gmtls: compression methods length mismatch")
	}
	m.CompressionMethods = make([]uint8, compressionLen)
	for i := 0; i < compressionLen; i++ {
		m.CompressionMethods[i] = data[offset+i]
	}
	offset += compressionLen

	// 扩展
	if offset+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+extLen <= len(data) {
			// 解析扩展
			extEnd := offset + extLen
			for offset < extEnd {
				if offset+4 > extEnd {
					return errors.New("gmtls: invalid extension data")
				}

				extType := binary.BigEndian.Uint16(data[offset : offset+2])
				extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
				offset += 4

				if offset+extDataLen > extEnd {
					return errors.New("gmtls: extension data length mismatch")
				}

				ext := Extension{
					Type: extType,
					Data: make([]byte, extDataLen),
				}
				copy(ext.Data, data[offset:offset+extDataLen])
				m.Extensions = append(m.Extensions, ext)

				offset += extDataLen
			}
		}
	}

	return nil
}

// serverHelloMsg TLS ServerHello 消息
type serverHelloMsg struct {
	Version     uint16
	Random      []byte
	SessionID   []byte
	CipherSuite uint16
	Compression uint8
	Extensions  []Extension // TLS 1.3 扩展
}

// marshal 序列化 ServerHello 消息
func (m *serverHelloMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeServerHello)

	// 长度（占位）
	_ = buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 版本
	binary.Write(&buf, binary.BigEndian, m.Version)

	// 随机数
	buf.Write(m.Random)

	// Session ID
	if m.SessionID == nil {
		buf.WriteByte(0) // 空 Session ID
	} else {
		buf.WriteByte(byte(len(m.SessionID)))
		buf.Write(m.SessionID)
	}

	// 密码套件
	binary.Write(&buf, binary.BigEndian, m.CipherSuite)

	// 压缩方法
	buf.WriteByte(m.Compression)

	// 扩展（如果有的话）
	if len(m.Extensions) > 0 {
		// 计算扩展总长度
		extTotalLen := 0
		extData := make([][]byte, len(m.Extensions))

		for i, ext := range m.Extensions {
			extData[i] = make([]byte, 4+len(ext.Data))
			binary.BigEndian.PutUint16(extData[i][0:2], ext.Type)
			binary.BigEndian.PutUint16(extData[i][2:4], uint16(len(ext.Data)))
			copy(extData[i][4:], ext.Data)
			extTotalLen += len(extData[i])
		}

		binary.Write(&buf, binary.BigEndian, uint16(extTotalLen))
		for _, extBytes := range extData {
			buf.Write(extBytes)
		}
	} else {
		// 没有扩展时写入 0 长度
		binary.Write(&buf, binary.BigEndian, uint16(0))
	}

	// 写入长度
	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// unmarshal 反序列化 ServerHello 消息
func (m *serverHelloMsg) unmarshal(data []byte) error {
	if len(data) < 42 {
		return errors.New("gmtls: invalid ServerHello")
	}

	if data[0] != typeServerHello {
		return errors.New("gmtls: not a ServerHello")
	}

	// 跳过消息类型(1)和消息长度(3)，从data[4]开始
	m.Version = binary.BigEndian.Uint16(data[4:6])
	m.Random = data[6:38]

	// 跳过 session ID
	offset := 38
	if offset >= len(data) {
		return errors.New("gmtls: invalid ServerHello message")
	}
	sessionIDLen := int(data[offset])
	offset += 1
	if offset+sessionIDLen > len(data) {
		return errors.New("gmtls: invalid session ID")
	}
	if sessionIDLen > 0 {
		m.SessionID = make([]byte, sessionIDLen)
		copy(m.SessionID, data[offset:offset+sessionIDLen])
	}
	offset += sessionIDLen

	// 密码套件
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid ServerHello message")
	}
	m.CipherSuite = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 压缩方法
	if offset >= len(data) {
		return errors.New("gmtls: invalid compression method")
	}
	m.Compression = data[offset]
	offset += 1

	// 扩展
	if offset+2 <= len(data) {
		extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+extLen <= len(data) {
			// 解析扩展
			extEnd := offset + extLen
			for offset < extEnd {
				if offset+4 > extEnd {
					return errors.New("gmtls: invalid extension data")
				}

				extType := binary.BigEndian.Uint16(data[offset : offset+2])
				extDataLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
				offset += 4

				if offset+extDataLen > extEnd {
					return errors.New("gmtls: extension data length mismatch")
				}

				ext := Extension{
					Type: extType,
					Data: make([]byte, extDataLen),
				}
				copy(ext.Data, data[offset:offset+extDataLen])
				m.Extensions = append(m.Extensions, ext)

				offset += extDataLen
			}
		}
	}

	return nil
}

// certificateMsg TLS Certificate 消息
type certificateMsg struct {
	Certificate *Certificate
}

// marshal 序列化 Certificate 消息
func (m *certificateMsg) marshal() []byte {
	var certs [][]byte
	if m.Certificate != nil {
		if len(m.Certificate.Chain) > 0 {
			certs = m.Certificate.Chain
		} else if len(m.Certificate.Raw) > 0 {
			certs = [][]byte{m.Certificate.Raw}
		}
	}

	listLen := 0
	for _, cert := range certs {
		listLen += 3 + len(cert)
	}
	msgLen := 3 + listLen

	data := make([]byte, 4+msgLen)
	data[0] = typeCertificate
	writeUint24(data[1:4], msgLen)
	writeUint24(data[4:7], listLen)

	off := 7
	for _, cert := range certs {
		writeUint24(data[off:off+3], len(cert))
		off += 3
		copy(data[off:off+len(cert)], cert)
		off += len(cert)
	}

	return data
}

// unmarshal 反序列化 Certificate 消息
func (m *certificateMsg) unmarshal(data []byte) error {
	if data[0] != typeCertificate {
		return errors.New("gmtls: not a Certificate")
	}
	if len(data) < 7 {
		return errors.New("gmtls: invalid Certificate")
	}

	msgLen := readUint24(data[1:4])
	if len(data) < 4+msgLen {
		return errors.New("gmtls: truncated Certificate")
	}

	off := 4
	listLen := readUint24(data[off : off+3])
	off += 3
	if listLen == 0 {
		m.Certificate = nil
		return nil
	}
	if len(data) < off+listLen {
		return errors.New("gmtls: invalid Certificate list length")
	}

	end := off + listLen
	var chain [][]byte
	for off < end {
		if end-off < 3 {
			return errors.New("gmtls: invalid Certificate entry length")
		}
		certLen := readUint24(data[off : off+3])
		off += 3
		if end-off < certLen {
			return errors.New("gmtls: truncated Certificate entry")
		}
		certRaw := make([]byte, certLen)
		copy(certRaw, data[off:off+certLen])
		off += certLen
		chain = append(chain, certRaw)
	}
	if len(chain) == 0 {
		m.Certificate = nil
		return nil
	}
	m.Certificate = &Certificate{
		Raw:   chain[0],
		Chain: chain,
	}
	return nil
}

// serverHelloDoneMsg TLS ServerHelloDone 消息
type serverHelloDoneMsg struct{}

// marshal 序列化 ServerHelloDone 消息
func (m *serverHelloDoneMsg) marshal() []byte {
	return []byte{typeServerHelloDone, 0, 0, 0}
}

// clientKeyExchangeMsg TLS ClientKeyExchange 消息
type clientKeyExchangeMsg struct {
	PublicKey *PublicKey
}

// marshal 序列化 ClientKeyExchange 消息
func (m *clientKeyExchangeMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeClientKeyExchange)
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 公钥编码 (简化: 64字节未压缩格式)
	pubKey := make([]byte, 1+64)
	pubKey[0] = 0x04 // 未压缩
	xBytes := m.PublicKey.X.Bytes()
	yBytes := m.PublicKey.Y.Bytes()
	copy(pubKey[1+32-len(xBytes):33], xBytes)
	copy(pubKey[33+32-len(yBytes):65], yBytes)

	// 长度
	binary.Write(&buf, binary.BigEndian, uint16(len(pubKey)))

	// 公钥
	buf.Write(pubKey)

	data := buf.Bytes()
	length := len(data) - 4
	writeUint24(data[lengthOffset:lengthOffset+3], length)

	return data
}

// unmarshal 反序列化 ClientKeyExchange 消息
func (m *clientKeyExchangeMsg) unmarshal(data []byte) error {
	if data[0] != typeClientKeyExchange {
		return errors.New("gmtls: not a ClientKeyExchange")
	}

	// 解析公钥
	if len(data) < 6 {
		return errors.New("gmtls: invalid ClientKeyExchange")
	}
	msgLen := readUint24(data[1:4])
	if len(data) < 4+msgLen {
		return errors.New("gmtls: truncated ClientKeyExchange")
	}
	offset := 4
	if len(data) < offset+2 {
		return errors.New("gmtls: invalid public key length")
	}
	keyLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if len(data) < offset+keyLen {
		return errors.New("gmtls: invalid public key size")
	}
	if data[offset] != 0x04 {
		return errors.New("gmtls: invalid public key format")
	}

	if keyLen != 65 {
		return errors.New("gmtls: unsupported public key length")
	}
	x := new(big.Int).SetBytes(data[offset+1 : offset+33])
	y := new(big.Int).SetBytes(data[offset+33 : offset+65])

	m.PublicKey = &PublicKey{X: x, Y: y}
	return nil
}

// finishedMsg TLS Finished 消息
type finishedMsg struct {
	VerifyData []byte
}

// marshal 序列化 Finished 消息
func (m *finishedMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeFinished)

	// 长度
	buf.Write([]byte{0, 0, 0})

	// Verify Data
	buf.Write(m.VerifyData)

	data := buf.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

// unmarshal 反序列化 Finished 消息
func (m *finishedMsg) unmarshal(data []byte) error {
	if data[0] != typeFinished {
		return errors.New("gmtls: not a Finished")
	}

	m.VerifyData = data[4:]
	return nil
}

// ============= TLS 1.2 ServerKeyExchange 消息 =============

// serverKeyExchangeMsg TLS 1.2 ServerKeyExchange 消息
// 用于 SM2DHE 密钥交换，服务端发送临时公钥和签名
type serverKeyExchangeMsg struct {
	// 临时公钥（未压缩格式）
	EphemeralPublicKey *PublicKey
	// 签名（对 ClientHello.random 和 ServerHello.random 的签名）
	Signature []byte
}

// marshal 序列化 ServerKeyExchange 消息
func (m *serverKeyExchangeMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeServerKeyExchange)

	// 长度占位
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 公钥编码（未压缩格式 0x04 + 64字节）
	buf.WriteByte(0x04)
	xBytes := m.EphemeralPublicKey.X.Bytes()
	yBytes := m.EphemeralPublicKey.Y.Bytes()
	buf.Write(make([]byte, 32-len(xBytes)))
	buf.Write(xBytes)
	buf.Write(make([]byte, 32-len(yBytes)))
	buf.Write(yBytes)

	// 签名算法（SM2 with SM3）
	binary.Write(&buf, binary.BigEndian, uint16(0x0100)) // sm2_sig_sm3

	// 签名
	binary.Write(&buf, binary.BigEndian, uint16(len(m.Signature)))
	buf.Write(m.Signature)

	// 更新长度
	data := buf.Bytes()
	length := len(data) - 4
	data[lengthOffset] = byte(length >> 16)
	data[lengthOffset+1] = byte(length >> 8)
	data[lengthOffset+2] = byte(length)

	return data
}

// unmarshal 反序列化 ServerKeyExchange 消息
func (m *serverKeyExchangeMsg) unmarshal(data []byte) error {
	if data[0] != typeServerKeyExchange {
		return errors.New("gmtls: not a ServerKeyExchange")
	}

	offset := 4 // 跳过消息头

	// 解析公钥
	if offset >= len(data) || data[offset] != 0x04 {
		return errors.New("gmtls: invalid public key format")
	}
	offset++

	if offset+64 > len(data) {
		return errors.New("gmtls: invalid public key length")
	}

	x := new(big.Int).SetBytes(data[offset : offset+32])
	y := new(big.Int).SetBytes(data[offset+32 : offset+64])
	m.EphemeralPublicKey = &PublicKey{X: x, Y: y}
	offset += 64

	// 解析签名算法
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid signature algorithm")
	}
	// algorithm := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 解析签名长度和签名
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid signature length")
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+sigLen > len(data) {
		return errors.New("gmtls: signature length mismatch")
	}
	m.Signature = data[offset : offset+sigLen]

	return nil
}

// ============= TLS 1.2 CertificateRequest 消息 =============

// certificateRequestMsg TLS 1.2 CertificateRequest 消息
// 请求客户端发送证书
type certificateRequestMsg struct {
	// 证书类型
	CertificateTypes []uint8
	// 签名算法
	SignatureAlgorithms []uint16
	// 可接受的 CA 名称
	CertificateAuthorities [][]byte
}

// marshal 序列化 CertificateRequest 消息
func (m *certificateRequestMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeCertificateRequest)

	// 长度占位
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 证书类型
	binary.Write(&buf, binary.BigEndian, uint8(len(m.CertificateTypes)))
	for _, certType := range m.CertificateTypes {
		buf.WriteByte(certType)
	}

	// 签名算法
	binary.Write(&buf, binary.BigEndian, uint16(len(m.SignatureAlgorithms)*2))
	for _, alg := range m.SignatureAlgorithms {
		binary.Write(&buf, binary.BigEndian, alg)
	}

	// CA 名称
	caTotalLen := 0
	for _, ca := range m.CertificateAuthorities {
		caTotalLen += 2 + len(ca)
	}
	binary.Write(&buf, binary.BigEndian, uint16(caTotalLen))
	for _, ca := range m.CertificateAuthorities {
		binary.Write(&buf, binary.BigEndian, uint16(len(ca)))
		buf.Write(ca)
	}

	// 更新长度
	data := buf.Bytes()
	length := len(data) - 4
	data[lengthOffset] = byte(length >> 16)
	data[lengthOffset+1] = byte(length >> 8)
	data[lengthOffset+2] = byte(length)

	return data
}

// unmarshal 反序列化 CertificateRequest 消息
func (m *certificateRequestMsg) unmarshal(data []byte) error {
	if data[0] != typeCertificateRequest {
		return errors.New("gmtls: not a CertificateRequest")
	}

	offset := 4 // 跳过消息头

	// 解析证书类型
	if offset >= len(data) {
		return errors.New("gmtls: invalid certificate types")
	}
	certTypesLen := int(data[offset])
	offset++

	if offset+certTypesLen > len(data) {
		return errors.New("gmtls: certificate types length mismatch")
	}
	m.CertificateTypes = make([]uint8, certTypesLen)
	copy(m.CertificateTypes, data[offset:offset+certTypesLen])
	offset += certTypesLen

	// 解析签名算法
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid signature algorithms length")
	}
	sigAlgsLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+sigAlgsLen > len(data) {
		return errors.New("gmtls: signature algorithms length mismatch")
	}
	m.SignatureAlgorithms = make([]uint16, sigAlgsLen/2)
	for i := 0; i < sigAlgsLen/2; i++ {
		m.SignatureAlgorithms[i] = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// 解析 CA 名称
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid CA names length")
	}
	caNamesLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+caNamesLen > len(data) {
		return errors.New("gmtls: CA names length mismatch")
	}
	end := offset + caNamesLen
	var cas [][]byte
	for offset < end {
		if offset+2 > end {
			return errors.New("gmtls: invalid CA name entry length")
		}
		nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+nameLen > end {
			return errors.New("gmtls: CA name entry truncated")
		}
		name := make([]byte, nameLen)
		copy(name, data[offset:offset+nameLen])
		offset += nameLen
		cas = append(cas, name)
	}
	m.CertificateAuthorities = cas

	return nil
}

// ============= TLS 1.2 CertificateVerify 消息 =============

// certificateVerifyMsgTLS12 TLS 1.2 CertificateVerify 消息
// 客户端发送，证明自己拥有私钥
type certificateVerifyMsgTLS12 struct {
	// 签名算法
	SignatureAlgorithm uint16
	// 签名
	Signature []byte
}

// marshal 序列化 CertificateVerify 消息
func (m *certificateVerifyMsgTLS12) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeCertificateVerify)

	// 长度占位
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 签名算法（SM2 with SM3）
	binary.Write(&buf, binary.BigEndian, m.SignatureAlgorithm)

	// 签名
	binary.Write(&buf, binary.BigEndian, uint16(len(m.Signature)))
	buf.Write(m.Signature)

	// 更新长度
	data := buf.Bytes()
	length := len(data) - 4
	data[lengthOffset] = byte(length >> 16)
	data[lengthOffset+1] = byte(length >> 8)
	data[lengthOffset+2] = byte(length)

	return data
}

// unmarshal 反序列化 CertificateVerify 消息
func (m *certificateVerifyMsgTLS12) unmarshal(data []byte) error {
	if data[0] != typeCertificateVerify {
		return errors.New("gmtls: not a CertificateVerify")
	}

	offset := 4 // 跳过消息头

	// 解析签名算法
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid signature algorithm")
	}
	m.SignatureAlgorithm = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// 解析签名
	if offset+2 > len(data) {
		return errors.New("gmtls: invalid signature length")
	}
	sigLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+sigLen > len(data) {
		return errors.New("gmtls: signature length mismatch")
	}
	m.Signature = data[offset : offset+sigLen]

	return nil
}

// ============= TLS 1.3 握手消息结构 =============

// encryptedExtensionsMsg TLS 1.3 EncryptedExtensions 消息
type encryptedExtensionsMsg struct {
	Extensions []Extension // 扩展列表
}

// marshal 序列化 EncryptedExtensions 消息
func (m *encryptedExtensionsMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeEncryptedExtensions)

	// 长度占位
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 扩展数据
	if len(m.Extensions) > 0 {
		extTotalLen := 0
		extData := make([][]byte, len(m.Extensions))
		for i, ext := range m.Extensions {
			extData[i] = make([]byte, 4+len(ext.Data))
			binary.BigEndian.PutUint16(extData[i][0:2], ext.Type)
			binary.BigEndian.PutUint16(extData[i][2:4], uint16(len(ext.Data)))
			copy(extData[i][4:], ext.Data)
			extTotalLen += len(extData[i])
		}
		binary.Write(&buf, binary.BigEndian, uint16(extTotalLen))
		for _, extBytes := range extData {
			buf.Write(extBytes)
		}
	} else {
		binary.Write(&buf, binary.BigEndian, uint16(0))
	}

	data := buf.Bytes()
	length := len(data) - 4
	data[lengthOffset] = byte(length >> 16)
	data[lengthOffset+1] = byte(length >> 8)
	data[lengthOffset+2] = byte(length)

	return data
}

// unmarshal 反序列化 EncryptedExtensions 消息
func (m *encryptedExtensionsMsg) unmarshal(data []byte) error {
	if data[0] != typeEncryptedExtensions {
		return errors.New("gmtls: not an EncryptedExtensions")
	}

	if len(data) < 4 {
		return errors.New("gmtls: invalid EncryptedExtensions message")
	}

	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return errors.New("gmtls: EncryptedExtensions message too short")
	}

	if msgLen < 2 {
		return errors.New("gmtls: invalid EncryptedExtensions length")
	}
	off := 4
	extLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if msgLen != 2+extLen {
		return errors.New("gmtls: invalid EncryptedExtensions length")
	}
	if len(data) < off+extLen {
		return errors.New("gmtls: EncryptedExtensions extensions truncated")
	}
	end := off + extLen
	for off < end {
		if end-off < 4 {
			return errors.New("gmtls: invalid EncryptedExtensions extension")
		}
		extType := binary.BigEndian.Uint16(data[off : off+2])
		extDataLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		off += 4
		if end-off < extDataLen {
			return errors.New("gmtls: EncryptedExtensions extension truncated")
		}
		ext := Extension{Type: extType, Data: make([]byte, extDataLen)}
		copy(ext.Data, data[off:off+extDataLen])
		m.Extensions = append(m.Extensions, ext)
		off += extDataLen
	}

	return nil
}

// certificateVerifyMsg TLS 1.3 CertificateVerify 消息
type certificateVerifyMsg struct {
	Algorithm uint16
	Signature []byte
}

// marshal 序列化 CertificateVerify 消息
func (m *certificateVerifyMsg) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(typeCertificateVerify)

	// 长度占位
	lengthOffset := buf.Len()
	buf.Write([]byte{0, 0, 0})

	// 算法
	binary.Write(&buf, binary.BigEndian, m.Algorithm)

	// 签名
	binary.Write(&buf, binary.BigEndian, uint16(len(m.Signature)))
	buf.Write(m.Signature)

	data := buf.Bytes()
	length := len(data) - 4
	data[lengthOffset] = byte(length >> 16)
	data[lengthOffset+1] = byte(length >> 8)
	data[lengthOffset+2] = byte(length)

	return data
}

// unmarshal 反序列化 CertificateVerify 消息
func (m *certificateVerifyMsg) unmarshal(data []byte) error {
	if data[0] != typeCertificateVerify {
		return errors.New("gmtls: not a CertificateVerify")
	}

	if len(data) < 8 {
		return errors.New("gmtls: invalid CertificateVerify")
	}

	m.Algorithm = binary.BigEndian.Uint16(data[4:6])
	sigLen := binary.BigEndian.Uint16(data[6:8])

	if uint16(len(data)) < 8+sigLen {
		return errors.New("gmtls: invalid signature length")
	}

	m.Signature = data[8 : 8+sigLen]
	return nil
}
