package gmtls

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ============= TLS 扩展类型 =============

const (
	extensionServerName           uint16 = 0
	extensionSupportedCurves      uint16 = 10
	extensionSupportedPoints      uint16 = 11
	extensionSignatureAlgorithms  uint16 = 13
	extensionALPN                 uint16 = 16
	extensionStatusRequest        uint16 = 5
	extensionEncryptThenMAC       uint16 = 22
	extensionExtendedMasterSecret uint16 = 23
	extensionSessionTicket        uint16 = 35
	extensionKeyShare             uint16 = 51 // TLS 1.3
	extensionSupportedVersions    uint16 = 43 // TLS 1.3
	extensionPSKModes             uint16 = 45 // TLS 1.3
	extensionEarlyData            uint16 = 42 // TLS 1.3
	extensionPreSharedKey         uint16 = 41 // TLS 1.3
)

// Extension TLS 扩展结构
type Extension struct {
	Type uint16
	Data []byte
}

// ============= SNI (Server Name Indication) 扩展 =============

// serverNameExtension SNI 扩展
type serverNameExtension struct {
	ServerName string
}

// marshalSNIExtension 编码 SNI 扩展
func marshalSNIExtension(serverName string) Extension {
	if serverName == "" {
		return Extension{}
	}

	// SNI 扩展格式：
	// ServerNameList length (2 bytes)
	//   ServerName type (1 byte) = 0 (host_name)
	//   ServerName length (2 bytes)
	//   ServerName (variable)

	var buf bytes.Buffer
	// ServerNameList 长度（先写占位符）
	buf.Write([]byte{0, 0})

	// ServerName type = 0 (host_name)
	buf.WriteByte(0)

	// ServerName 长度
	nameBytes := []byte(serverName)
	binary.Write(&buf, binary.BigEndian, uint16(len(nameBytes)))

	// ServerName
	buf.Write(nameBytes)

	// 更新 ServerNameList 长度
	data := buf.Bytes()
	listLen := len(data) - 2
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)

	return Extension{
		Type: extensionServerName,
		Data: data,
	}
}

// parseSNIExtension 解析 SNI 扩展
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("gmtls: invalid SNI extension")
	}

	// ServerNameList length
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return "", errors.New("gmtls: SNI extension truncated")
	}

	// 只读取第一个 ServerName
	offset := 2

	// ServerName type
	if data[offset] != 0 {
		return "", errors.New("gmtls: unsupported server name type")
	}
	offset++

	// ServerName length
	if offset+2 > len(data) {
		return "", errors.New("gmtls: SNI extension truncated")
	}
	nameLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// ServerName
	if offset+nameLen > len(data) {
		return "", errors.New("gmtls: SNI extension truncated")
	}
	return string(data[offset : offset+nameLen]), nil
}

// ============= ALPN (Application-Layer Protocol Negotiation) 扩展 =============

// alpnExtension ALPN 扩展
type alpnExtension struct {
	Protocols []string
}

// marshalALPNExtension 编码 ALPN 扩展
func marshalALPNExtension(protocols []string) Extension {
	if len(protocols) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer
	// ALPN 协议列表长度（先写占位符）
	buf.Write([]byte{0, 0})

	// 编码每个协议
	for _, proto := range protocols {
		protoBytes := []byte(proto)
		// 协议名称长度
		buf.WriteByte(byte(len(protoBytes)))
		// 协议名称
		buf.Write(protoBytes)
	}

	// 更新协议列表长度
	data := buf.Bytes()
	listLen := len(data) - 2
	data[0] = byte(listLen >> 8)
	data[1] = byte(listLen)

	return Extension{
		Type: extensionALPN,
		Data: data,
	}
}

// parseALPNExtension 解析 ALPN 扩展
func parseALPNExtension(data []byte) ([]string, error) {
	if len(data) < 2 {
		return nil, errors.New("gmtls: invalid ALPN extension")
	}

	// 协议列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return nil, errors.New("gmtls: ALPN extension truncated")
	}

	var protocols []string
	offset := 2

	for offset < 2+listLen {
		if offset >= len(data) {
			return nil, errors.New("gmtls: ALPN extension truncated")
		}

		// 协议名称长度
		protoLen := int(data[offset])
		offset++

		// 协议名称
		if offset+protoLen > len(data) {
			return nil, errors.New("gmtls: ALPN extension truncated")
		}
		protocols = append(protocols, string(data[offset:offset+protoLen]))
		offset += protoLen
	}

	return protocols, nil
}

// ============= SignatureAlgorithms 扩展 =============

// signatureAlgorithmsExtension SignatureAlgorithms 扩展
type signatureAlgorithmsExtension struct {
	SignatureSchemes []uint16
}

// marshalSignatureAlgorithmsExtension 编码签名算法扩展
func marshalSignatureAlgorithmsExtension(schemes []uint16) Extension {
	if len(schemes) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer
	// 算法列表长度
	binary.Write(&buf, binary.BigEndian, uint16(len(schemes)*2))

	// 编码每个算法
	for _, scheme := range schemes {
		binary.Write(&buf, binary.BigEndian, scheme)
	}

	return Extension{
		Type: extensionSignatureAlgorithms,
		Data: buf.Bytes(),
	}
}

// SignatureScheme 常量
const (
	PKCS1WithSM2SM3 uint16 = 0x0001 + iota // 自定义：SM2 + SM3 (PKCS#1 v1.5)
	PSSWithSM2SM3                          // 自定义：SM2 + SM3 (PSS)
	ECDSAWithSM2SM3                        // 自定义：ECDSA风格的SM2 + SM3
	PKCS1WithSHA256 uint16 = 0x0401
	PKCS1WithSHA384 uint16 = 0x0501
	PKCS1WithSHA512 uint16 = 0x0601
	Ed25519         uint16 = 0x0807
	Ed448           uint16 = 0x0808
	PKCS1WithSHA1   uint16 = 0x0201
	SM2SM3          uint16 = 0x0708 // RFC 8998: sm2sig_sm3
)

// parseSignatureAlgorithmsExtension 解析签名算法扩展
func parseSignatureAlgorithmsExtension(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, errors.New("gmtls: invalid signature algorithms extension")
	}

	// 算法列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return nil, errors.New("gmtls: signature algorithms extension truncated")
	}
	if listLen%2 != 0 {
		return nil, errors.New("gmtls: invalid signature algorithms extension length")
	}

	schemes := make([]uint16, listLen/2)
	for i := 0; i < listLen; i += 2 {
		schemes[i/2] = binary.BigEndian.Uint16(data[2+i : 4+i])
	}

	return schemes, nil
}

// ============= StatusRequest (OCSP Stapling) 扩展 =============

// statusRequestExtension StatusRequest 扩展
type statusRequestExtension struct {
	StatusType uint8
	Request    []byte
}

// marshalStatusRequestExtension 编码 OCSP Stapling 扩展
func marshalStatusRequestExtension() Extension {
	// OCSP Status Request (type = 1)
	// 简化版本：只发送类型，空的请求
	data := []byte{
		0x01,             // OCSP status request
		0x00, 0x00, 0x00, // ResponderID list (empty)
		0x00, 0x00, // RequestExtensions (empty)
	}

	return Extension{
		Type: extensionStatusRequest,
		Data: data,
	}
}

// parseStatusRequestExtension 解析 OCSP Stapling 扩展
func parseStatusRequestExtension(data []byte) (uint8, []byte, error) {
	if len(data) < 5 {
		return 0, nil, errors.New("gmtls: invalid status request extension")
	}

	statusType := data[0]
	if statusType != 1 {
		return 0, nil, errors.New("gmtls: unsupported status request type")
	}

	// responder_id_list length
	off := 1
	if len(data) < off+2 {
		return 0, nil, errors.New("gmtls: invalid responder id list length")
	}
	responderListLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data) < off+responderListLen+2 {
		return 0, nil, errors.New("gmtls: responder id list truncated")
	}
	off += responderListLen

	// request_extensions length
	if len(data) < off+2 {
		return 0, nil, errors.New("gmtls: invalid request extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(data[off : off+2]))
	off += 2
	if len(data) < off+extLen {
		return 0, nil, errors.New("gmtls: request extensions truncated")
	}
	request := data[1 : off+extLen]

	return statusType, request, nil
}

// ============= SupportedCurves (椭圆曲线) 扩展 =============

// supportedCurvesExtension SupportedCurves 扩展
type supportedCurvesExtension struct {
	Curves []uint16
}

// marshalSupportedCurvesExtension 编码支持的椭圆曲线扩展
func marshalSupportedCurvesExtension(curves []uint16) Extension {
	if len(curves) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer
	// 曲线列表长度
	binary.Write(&buf, binary.BigEndian, uint16(len(curves)*2))

	// 编码每个曲线
	for _, curve := range curves {
		binary.Write(&buf, binary.BigEndian, curve)
	}

	return Extension{
		Type: extensionSupportedCurves,
		Data: buf.Bytes(),
	}
}

// CurveID 常量
const (
	CurveP256   uint16 = 23 // secp256r1
	CurveP384   uint16 = 24 // secp384r1
	CurveP521   uint16 = 25 // secp521r1
	CurveX25519 uint16 = 29 // X25519
	CurveX448   uint16 = 30 // X448
	CurveSM2    uint16 = 41 // SM2 (国密椭圆曲线)
)

// marshalECPointFormatsExtension 编码 ec_point_formats 扩展
// 3 formats: uncompressed(0), ansiX962_compressed_prime(1), ansiX962_compressed_char2(2)
func marshalECPointFormatsExtension() Extension {
	return Extension{
		Type: extensionSupportedPoints,
		Data: []byte{0x03, 0x00, 0x01, 0x02},
	}
}

// marshalEmptyExtension encodes an extension with empty data.
func marshalEmptyExtension(extType uint16) Extension {
	return Extension{
		Type: extType,
		Data: []byte{},
	}
}

// parseSupportedCurvesExtension 解析支持的椭圆曲线扩展
func parseSupportedCurvesExtension(data []byte) ([]uint16, error) {
	if len(data) < 2 {
		return nil, errors.New("gmtls: invalid supported curves extension")
	}

	// 曲线列表长度
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return nil, errors.New("gmtls: supported curves extension truncated")
	}
	if listLen%2 != 0 {
		return nil, errors.New("gmtls: invalid supported curves extension length")
	}

	curves := make([]uint16, listLen/2)
	for i := 0; i < listLen; i += 2 {
		curves[i/2] = binary.BigEndian.Uint16(data[2+i : 4+i])
	}

	return curves, nil
}

// ============= TLS 1.3 Key Share 扩展 =============

// KeyShareEntry TLS 1.3 Key Share 条目
type KeyShareEntry struct {
	Group       uint16 // 曲线组 (如 X25519 = 29)
	KeyExchange []byte // 密钥交换数据 (公钥)
}

// marshalKeyShareExtension encodes the ClientHello key_share extension.
func marshalKeyShareExtension(entries []KeyShareEntry) Extension {
	if len(entries) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer

	// 先写 client_shares 的总长度（占位符）
	lengthOffset := buf.Len()
	binary.Write(&buf, binary.BigEndian, uint16(0))

	// 编码每个 KeyShareEntry
	for _, entry := range entries {
		// Group
		binary.Write(&buf, binary.BigEndian, entry.Group)
		// KeyExchange length
		binary.Write(&buf, binary.BigEndian, uint16(len(entry.KeyExchange)))
		// KeyExchange data
		buf.Write(entry.KeyExchange)
	}

	// 更新总长度
	totalLength := buf.Len() - lengthOffset - 2
	data := buf.Bytes()
	binary.BigEndian.PutUint16(data[lengthOffset:lengthOffset+2], uint16(totalLength))

	return Extension{
		Type: extensionKeyShare,
		Data: data,
	}
}

// marshalKeyShareServerHelloExtension encodes the ServerHello key_share extension.
// Format:
//
//	struct {
//	    KeyShareEntry server_share;
//	} KeyShareServerHello;
func marshalKeyShareServerHelloExtension(entry KeyShareEntry) Extension {
	if len(entry.KeyExchange) == 0 {
		return Extension{}
	}
	data := make([]byte, 4+len(entry.KeyExchange))
	binary.BigEndian.PutUint16(data[0:2], entry.Group)
	binary.BigEndian.PutUint16(data[2:4], uint16(len(entry.KeyExchange)))
	copy(data[4:], entry.KeyExchange)
	return Extension{
		Type: extensionKeyShare,
		Data: data,
	}
}

// parseKeyShareExtension 解析服务端的 Key Share 扩展
// 格式：
//
//	struct {
//	    KeyShareEntry server_share;
//	} KeyShareServerHello;
func parseKeyShareExtension(data []byte) (*KeyShareEntry, error) {
	if len(data) < 4 {
		return nil, errors.New("gmtls: invalid key share extension")
	}

	entry := &KeyShareEntry{}

	// Group
	entry.Group = binary.BigEndian.Uint16(data[0:2])

	// KeyExchange length
	keyLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+keyLen {
		return nil, errors.New("gmtls: key share extension truncated")
	}

	// KeyExchange data
	entry.KeyExchange = make([]byte, keyLen)
	copy(entry.KeyExchange, data[4:4+keyLen])

	return entry, nil
}

// parseKeyShareClientHello 解析 ClientHello 的 KeyShare 扩展
// 格式：
//
//	struct {
//	    KeyShareEntry client_shares<0..2^16-1>;
//	} KeyShareClientHello;
func parseKeyShareClientHello(data []byte) ([]KeyShareEntry, error) {
	if len(data) < 2 {
		return nil, errors.New("gmtls: invalid key share extension")
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen {
		return nil, errors.New("gmtls: key share extension truncated")
	}
	payload := data[2 : 2+listLen]
	var entries []KeyShareEntry
	for len(payload) > 0 {
		if len(payload) < 4 {
			return nil, errors.New("gmtls: invalid key share entry")
		}
		group := binary.BigEndian.Uint16(payload[0:2])
		keyLen := int(binary.BigEndian.Uint16(payload[2:4]))
		payload = payload[4:]
		if len(payload) < keyLen {
			return nil, errors.New("gmtls: key share entry truncated")
		}
		key := make([]byte, keyLen)
		copy(key, payload[:keyLen])
		payload = payload[keyLen:]
		entries = append(entries, KeyShareEntry{Group: group, KeyExchange: key})
	}
	return entries, nil
}

// ============= TLS 1.3 PSK Key Exchange Modes 扩展 =============

const (
	PSKModeKE  uint8 = 0 // psk_ke
	PSKModeDHE uint8 = 1 // psk_dhe_ke
)

// marshalPSKKexModesExtension 编码 PSK Key Exchange Modes 扩展
// 格式：
//
//	struct {
//	    uint8 modes<1..255>;
//	} PSKKeyExchangeModes;
func marshalPSKKexModesExtension(modes []uint8) Extension {
	if len(modes) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer

	// Modes length
	buf.WriteByte(uint8(len(modes)))

	// Modes
	for _, mode := range modes {
		buf.WriteByte(mode)
	}

	return Extension{
		Type: extensionPSKModes,
		Data: buf.Bytes(),
	}
}

// parsePSKKexModesExtension 解析 PSK Key Exchange Modes 扩展
func parsePSKKexModesExtension(data []byte) ([]uint8, error) {
	if len(data) < 1 {
		return nil, errors.New("gmtls: invalid psk kex modes extension")
	}

	modesLen := int(data[0])
	if len(data) < 1+modesLen {
		return nil, errors.New("gmtls: psk kex modes extension truncated")
	}

	modes := make([]uint8, modesLen)
	copy(modes, data[1:1+modesLen])

	return modes, nil
}

// marshalSignatureAlgorithmsCertExtension 编码 Signature Algorithms Cert 扩展
// 格式与 signature_algorithms 类似，用于指示支持的证书签名算法
func marshalSignatureAlgorithmsCertExtension(schemes []uint16) Extension {
	if len(schemes) == 0 {
		return Extension{}
	}

	var buf bytes.Buffer

	// 算法列表长度
	binary.Write(&buf, binary.BigEndian, uint16(len(schemes)*2))

	// 编码每个算法
	for _, scheme := range schemes {
		binary.Write(&buf, binary.BigEndian, scheme)
	}

	return Extension{
		Type: 50, // signature_algorithms_cert (0x0032)
		Data: buf.Bytes(),
	}
}
