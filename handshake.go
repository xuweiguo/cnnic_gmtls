package gmtls

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	writeUint24(data[1:4], length)

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
	writeUint24(data[1:4], length)

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
	writeUint24(data[1:4], length)

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
	writeUint24(data[lengthOffset:lengthOffset+3], length)

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

	msgLen := readUint24(data[1:4])
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
	writeUint24(data[lengthOffset:lengthOffset+3], length)

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
