package gmtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"time"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func recordTypeToString(rt recordType) string {
	switch rt {
	case 20:
		return "ChangeCipherSpec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(%d)", rt)
	}
}

var errHelloRetryRequest = errors.New("gmtls: hello retry request")

var helloRetryRequestRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

func stripTLS13InnerContentType(data []byte) ([]byte, recordType, error) {
	if len(data) == 0 {
		return nil, 0, errors.New("gmtls: empty TLS 1.3 record")
	}
	innerType := recordType(data[len(data)-1])
	content := data[:len(data)-1]
	i := len(content)
	for i > 0 && content[i-1] == 0 {
		i--
	}
	return content[:i], innerType, nil
}

func extractTLS13InnerContentType(data []byte) ([]byte, recordType, error) {
	if len(data) == 0 {
		return nil, 0, errors.New("gmtls: empty TLS 1.3 record")
	}
	innerType := recordType(data[len(data)-1])
	return data[:len(data)-1], innerType, nil
}

func isTLS13InnerTypeByte(b byte) bool {
	switch recordType(b) {
	case recordTypeChangeCipherSpec, recordTypeAlert, recordTypeHandshake, recordTypeApplicationData:
		return true
	default:
		return false
	}
}

func (c *Conn) readTLS13HandshakeMsg() ([]byte, error) {
	for {
		if len(c.tls13HandshakeBuf) >= 4 {
			msgLen := int(c.tls13HandshakeBuf[1])<<16 | int(c.tls13HandshakeBuf[2])<<8 | int(c.tls13HandshakeBuf[3])
			total := 4 + msgLen
			if len(c.tls13HandshakeBuf) >= total {
				msg := c.tls13HandshakeBuf[:total]
				c.tls13HandshakeBuf = c.tls13HandshakeBuf[total:]
				if debugEnabled {
					debugf("DEBUG: TLS1.3 handshake msg type=%d len=%d\n", msg[0], msgLen)
				}
				return msg, nil
			}
			if debugEnabled {
				debugf("DEBUG: TLS1.3 handshake msg type=%d need=%d have=%d\n", c.tls13HandshakeBuf[0], total, len(c.tls13HandshakeBuf))
			}
		}

		rec, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		if rec.Type == recordTypeChangeCipherSpec {
			continue
		}
		if rec.Type == recordTypeAlert {
			if len(rec.Data) >= 2 {
				return nil, fmt.Errorf("gmtls: alert level=%d, description=%d", rec.Data[0], rec.Data[1])
			}
			return nil, errors.New("gmtls: received alert")
		}
		if rec.Type != recordTypeApplicationData {
			return nil, fmt.Errorf("gmtls: expected encrypted ApplicationData record, got type=%d", rec.Type)
		}

		plaintext := rec.Data
		if c.version >= VersionTLS13 {
			stripped, innerType, err := extractTLS13InnerContentType(rec.Data)
			if err != nil {
				return nil, err
			}
			if innerType == recordTypeAlert {
				if len(stripped) >= 2 {
					return nil, fmt.Errorf("gmtls: alert level=%d, description=%d", stripped[0], stripped[1])
				}
				return nil, errors.New("gmtls: received alert")
			}
			if innerType != recordTypeHandshake {
				return nil, fmt.Errorf("gmtls: unexpected inner content type %d", innerType)
			}
			plaintext = stripped
		}

		if debugEnabled && len(plaintext) > 0 {
			debugf("DEBUG: TLS1.3 append %d bytes, first=%02x\n", len(plaintext), plaintext[0])
			if len(plaintext) <= 32 {
				debugf("DEBUG: TLS1.3 append data=%s\n", hex.EncodeToString(plaintext))
			}
		}
		c.tls13HandshakeBuf = append(c.tls13HandshakeBuf, plaintext...)
		for len(c.tls13HandshakeBuf) > 0 && c.tls13HandshakeBuf[0] == 0 {
			c.tls13HandshakeBuf = c.tls13HandshakeBuf[1:]
		}
	}
}

func trimTLS13Handshake(plaintext []byte) ([]byte, error) {
	if len(plaintext) < 4 {
		return nil, errors.New("gmtls: invalid TLS 1.3 handshake message")
	}
	msgLen := int(plaintext[1])<<16 | int(plaintext[2])<<8 | int(plaintext[3])
	total := 4 + msgLen
	if len(plaintext) < total {
		return nil, errors.New("gmtls: truncated TLS 1.3 handshake message")
	}
	return plaintext[:total], nil
}

// ============= TLS 连接 =============

type Conn struct {
	conn        net.Conn
	isClient    bool
	version     uint16
	cipherSuite *CipherSuiteInfo
	config      *Config

	// 密钥材料
	masterSecret                                                   []byte
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte

	// 随机数
	clientRandom, serverRandom [32]byte

	// 证书
	localCert    *Certificate
	peerCert     *Certificate
	localPriv    *PrivateKey
	localEncCert *Certificate
	localEncPriv *PrivateKey
	peerPubKey   *PublicKey

	// 握手状态
	handshakeBuf      []byte
	handshakeComplete bool
	clientHelloSent   bool
	serverHelloSent   bool

	// 加密/解密
	clientEnc, serverEnc interface{} // SM4CBCMode 或 SM4GCMMode

	// 读/写
	in, out    *halfConn
	appReadBuf []byte

	// 加密状态
	clientEncrypted, serverEncrypted bool // 是否已启用加密

	// TLS 1.3 特定字段
	tls13KeyMaterial *TLS13KeyMaterial // TLS 1.3 密钥材料
	transcriptHash   hash.Hash         // 握手消息哈希
	clientHelloHash  []byte            // ClientHello 的哈希（用于密钥派生）
	// 仅用于调试的握手消息副本
	lastClientHello []byte
	lastServerHello []byte
	// TLS 1.3 客户端证书请求标记
	tls13ClientCertRequested bool
	// TLS 1.3 CertificateRequest context (for client cert)
	tls13CertReqContext []byte
	// TLS 1.3: transcript hash before client Finished (server Finished hash)
	tls13ServerFinishedHash []byte
	// TLS 1.3 HelloRetryRequest tracking
	tls13HelloRetry     bool
	tls13RequestedGroup uint16
	tls13SessionID      []byte
	tls13ClientHelloCnt int
	nextRecordVersion   uint16
	tls13SM2NoZA        bool
	tls13HandshakeBuf   []byte
	tls13Tickets        []TLS13SessionTicket

	// 扩展协商结果
	clientServerName      string   // SNI - 客户端发送的服务器名称
	serverName            string   // SNI - 服务端接收到的服务器名称
	negotiatedProto       string   // ALPN - 协商的应用层协议
	peerProtos            []string // ALPN - 对方支持的协议列表
	clientSigSchemes      []uint16
	clientSupportedCurves []uint16
	clientCipherSuites    []uint16
	tls12StatusRequest    bool

	// TLS 1.3 server-side fields
	tls13ClientKeyShare *KeyShareEntry

	// TLS 1.2 interop helpers
	tls12ServerEphemeralPriv *PrivateKey
	tls12ServerEphemeralPub  *PublicKey
	tls12ClientCertRequested bool
}

type halfConn struct {
	cipher interface{} // SM4CBCMode 或 SM4GCMMode
	seq    uint64
}

// Certificate 表示 X.509 证书
type Certificate struct {
	Raw       []byte
	Chain     [][]byte
	PublicKey *PublicKey
}

// Client 创建客户端连接
func Client(conn net.Conn, config *Config) (*Conn, error) {
	if config == nil {
		config = &Config{}
	}
	// 确定使用的 TLS 版本
	var version uint16 = VersionTLS12
	if config.MaxVersion >= VersionTLS13 {
		version = VersionTLS13
	} else if config.MinVersion > VersionTLS12 {
		version = config.MinVersion
	}

	c := &Conn{
		conn:     conn,
		isClient: true,
		version:  version,
		config:   config,
		in:       &halfConn{},
		out:      &halfConn{},
	}

	// 生成客户端随机数
	if _, err := io.ReadFull(rand.Reader, c.clientRandom[:]); err != nil {
		return nil, err
	}

	// 设置证书（可选）
	if len(config.SignCertificates) > 0 {
		c.localCert = config.SignCertificates[0]
	} else if len(config.Certificates) > 0 {
		c.localCert = config.Certificates[0]
	}
	if config.SignPrivateKey != nil {
		c.localPriv = config.SignPrivateKey
	} else {
		c.localPriv = config.PrivateKey
	}
	if len(config.EncCertificates) > 0 {
		c.localEncCert = config.EncCertificates[0]
	}
	if config.EncPrivateKey != nil {
		c.localEncPriv = config.EncPrivateKey
	}

	// 保存扩展配置
	c.clientServerName = config.ServerName
	c.peerProtos = config.NextProtos

	// 开始握手
	if err := c.clientHandshake(); err != nil {
		return nil, err
	}

	return c, nil
}

// Server 创建服务端连接
func Server(conn net.Conn, config *Config) (*Conn, error) {
	if config == nil {
		config = &Config{}
	}
	// 确定使用的 TLS 版本
	var version uint16 = VersionTLS12
	if config.MaxVersion >= VersionTLS13 {
		version = VersionTLS13
	} else if config.MinVersion > VersionTLS12 {
		version = config.MinVersion
	}

	c := &Conn{
		conn:     conn,
		isClient: false,
		version:  version,
		config:   config,
		in:       &halfConn{},
		out:      &halfConn{},
	}

	// 生成服务端随机数
	if _, err := io.ReadFull(rand.Reader, c.serverRandom[:]); err != nil {
		return nil, err
	}

	// 设置证书（可选）
	if len(config.SignCertificates) > 0 {
		c.localCert = config.SignCertificates[0]
	} else if len(config.Certificates) > 0 {
		c.localCert = config.Certificates[0]
	}
	if config.SignPrivateKey != nil {
		c.localPriv = config.SignPrivateKey
	} else {
		c.localPriv = config.PrivateKey
	}
	if len(config.EncCertificates) > 0 {
		c.localEncCert = config.EncCertificates[0]
	}
	if config.EncPrivateKey != nil {
		c.localEncPriv = config.EncPrivateKey
	}

	// 开始握手
	if err := c.serverHandshake(); err != nil {
		return nil, err
	}

	return c, nil
}

// Config TLS 配置
type Config struct {
	CipherSuites []uint16
	Certificates []*Certificate
	PrivateKey   *PrivateKey
	// Dual-certificate support (GM/T). If set, Sign* is used for CertificateVerify.
	SignCertificates []*Certificate
	SignPrivateKey   *PrivateKey
	// Reserved for GM dual-certificate flows (e.g., TLCP/NTLS).
	EncCertificates    []*Certificate
	EncPrivateKey      *PrivateKey
	InsecureSkipVerify bool
	MinVersion         uint16 // 最低 TLS 版本
	MaxVersion         uint16 // 最高 TLS 版本

	// 扩展配置
	ServerName string   // SNI - 服务端名称指示
	NextProtos []string // ALPN - 应用层协议协商
	// OCSPStaple bool    // OCSP Stapling 支持（预留）

	// TLS 1.3 session resumption (client)
	SessionTickets     []TLS13SessionTicket
	OnNewSessionTicket func(TLS13SessionTicket)

	// ClientAuth requests a client certificate in TLS 1.2 handshakes.
	ClientAuth bool
}

func normalizeCipherSuiteID(id uint16) uint16 {
	switch id {
	case TLS_SM4_GCM_SM3_ALT:
		return TLS_SM4_GCM_SM3
	case TLS_SM4_CCM_SM3_ALT:
		return TLS_SM4_CCM_SM3
	default:
		return id
	}
}

func cipherSuiteForVersion(suite *CipherSuiteInfo, version uint16) bool {
	if suite == nil {
		return false
	}
	return version >= suite.MinTLSVersion && version <= suite.MaxTLSVersion
}

func containsUint16(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func supportsSM2Signature(list []uint16) bool {
	return containsUint16(list, SM2SM3) || containsUint16(list, PKCS1WithSM2SM3) || containsUint16(list, ECDSAWithSM2SM3)
}

func selectALPNProtocol(serverProtos, clientProtos []string) string {
	for _, sp := range serverProtos {
		for _, cp := range clientProtos {
			if sp == cp {
				return sp
			}
		}
	}
	return ""
}

func selectCipherSuite(clientSuites, serverSuites []uint16, version uint16, clientCurves, clientSigSchemes []uint16) *CipherSuiteInfo {
	// Build server preference list; if empty, use client order.
	var preferences []uint16
	if len(serverSuites) > 0 {
		preferences = serverSuites
	} else {
		preferences = clientSuites
	}

	for _, srvID := range preferences {
		normalizedSrv := normalizeCipherSuiteID(srvID)
		var chosenID uint16
		found := false

		// Prefer exact match from client list.
		for _, cliID := range clientSuites {
			if cliID == srvID {
				chosenID = cliID
				found = true
				break
			}
		}
		// Fall back to normalized match (for ALT values).
		if !found {
			for _, cliID := range clientSuites {
				if normalizeCipherSuiteID(cliID) == normalizedSrv {
					chosenID = cliID
					found = true
					break
				}
			}
		}
		if !found {
			continue
		}

		suite := GetCipherSuiteByID(chosenID)
		if !cipherSuiteForVersion(suite, version) {
			continue
		}
		// If client provided supported curves, ensure SM2DHE can work.
		if suite.KeyExchange == "SM2DHE" && len(clientCurves) > 0 && !containsUint16(clientCurves, CurveSM2) {
			continue
		}
		// If client provided signature schemes, ensure SM2 is supported.
		if len(clientSigSchemes) > 0 && !supportsSM2Signature(clientSigSchemes) {
			continue
		}
		return suite
	}
	return nil
}

func clientOfferedCipherSuite(offered []uint16, id uint16) bool {
	normalized := normalizeCipherSuiteID(id)
	for _, v := range offered {
		if normalizeCipherSuiteID(v) == normalized {
			return true
		}
	}
	return false
}

func parseSupportedVersionsClientHello(data []byte) ([]uint16, error) {
	if len(data) < 1 {
		return nil, errors.New("gmtls: invalid supported_versions extension")
	}
	listLen := int(data[0])
	if len(data) < 1+listLen {
		return nil, errors.New("gmtls: supported_versions truncated")
	}
	if listLen%2 != 0 {
		return nil, errors.New("gmtls: invalid supported_versions length")
	}
	versions := make([]uint16, listLen/2)
	for i := 0; i < listLen; i += 2 {
		versions[i/2] = binary.BigEndian.Uint16(data[1+i : 1+i+2])
	}
	return versions, nil
}

// ============= 客户端握手 =============

func (c *Conn) clientHandshake() error {
	// 检查是否支持 TLS 1.3
	if c.version >= VersionTLS13 {
		return c.clientHandshakeTLS13()
	}

	// TLS 1.2 握手
	// 发送 ClientHello
	if err := c.sendClientHello(); err != nil {
		return err
	}

	// 接收 ServerHello
	if err := c.readServerHello(); err != nil {
		return err
	}

	// 接收 ServerHelloDone (如果有)
	if err := c.readServerMessages(); err != nil {
		return err
	}

	// 如果服务端请求客户端证书，先发送 Certificate
	if c.tls12ClientCertRequested {
		if err := c.sendClientCertificateTLS12(); err != nil {
			return err
		}
	}

	// 发送 ClientKeyExchange
	if err := c.sendClientKeyExchange(); err != nil {
		return err
	}

	// 如果发送了客户端证书，发送 CertificateVerify
	if c.tls12ClientCertRequested && c.localCert != nil && c.localPriv != nil {
		if err := c.sendCertificateVerifyTLS12(); err != nil {
			return err
		}
	}

	// 发送 ChangeCipherSpec
	if err := c.sendChangeCipherSpec(); err != nil {
		return err
	}

	// 接收 ChangeCipherSpec
	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// 发送 Finished
	if err := c.sendFinished(); err != nil {
		return err
	}

	// 接收 Finished
	if err := c.readFinished(); err != nil {
		return err
	}

	c.handshakeComplete = true
	return nil
}

// sendClientHello 发送 ClientHello 消息
func (c *Conn) sendClientHello() error {
	// 选择密码套件（优先使用国密密码套件）
	var cipherSuites []uint16
	if c.config != nil && len(c.config.CipherSuites) > 0 {
		cipherSuites = append([]uint16(nil), c.config.CipherSuites...)
	} else if c.version >= VersionTLS13 {
		// TLS 1.3 使用国密密码套件
		cipherSuites = []uint16{
			TLS_SM4_GCM_SM3, // 0x1306 - SM4-GCM-SM3
			TLS_SM4_CCM_SM3, // 0x1307 - SM4-CCM-SM3
		}
	} else {
		// TLS 1.2 使用国密密码套件
		cipherSuites = []uint16{
			TLS_SM2_WITH_SM4_CBC_SM3,    // 0xE0 - SM2 with SM4-CBC-SM3
			TLS_SM2DHE_WITH_SM4_CBC_SM3, // 0xE1 - SM2DHE with SM4-CBC-SM3
			TLS_SM2_WITH_SM4_GCM_SM3,    // 0xE2 - SM2 with SM4-GCM-SM3
			TLS_SM2DHE_WITH_SM4_GCM_SM3, // 0xE3 - SM2DHE with SM4-GCM-SM3
		}
	}
	c.clientCipherSuites = append([]uint16(nil), cipherSuites...)

	// 构造握手消息
	hello := &clientHelloMsg{
		Version:            c.version,
		Random:             c.clientRandom[:],
		CipherSuites:       cipherSuites,
		CompressionMethods: []uint8{0}, // 无压缩
	}

	// 添加扩展
	var extensions []Extension

	// 1. SNI (Server Name Indication)
	if c.clientServerName != "" {
		extensions = append(extensions, marshalSNIExtension(c.clientServerName))
	}

	// 2. SignatureAlgorithms
	sigSchemes := []uint16{
		PKCS1WithSM2SM3, // SM2 + SM3
		ECDSAWithSM2SM3, // ECDSA风格的SM2 + SM3
		PKCS1WithSHA256, // RSA + SHA256
		PKCS1WithSHA384, // RSA + SHA384
		Ed25519,         // Ed25519
	}
	extensions = append(extensions, marshalSignatureAlgorithmsExtension(sigSchemes))

	// 3. SupportedCurves (椭圆曲线)
	curves := []uint16{
		CurveSM2,    // SM2 曲线
		CurveP256,   // P256
		CurveX25519, // X25519
	}
	extensions = append(extensions, marshalSupportedCurvesExtension(curves))

	// 4. ALPN (Application-Layer Protocol Negotiation)
	if len(c.peerProtos) > 0 {
		extensions = append(extensions, marshalALPNExtension(c.peerProtos))
	}

	// 5. OCSP Stapling (status_request)
	// 暂时注释掉，因为 BabaSSL 可能不支持
	// extensions = append(extensions, marshalStatusRequestExtension())

	hello.Extensions = extensions

	// 序列化
	data := hello.marshal()
	c.lastClientHello = append([]byte(nil), data...)

	// 作为握手记录发送
	return c.writeRecord(recordTypeHandshake, data)
}

// readServerHello 读取 ServerHello 消息
func (c *Conn) readServerHello() error {
	// 读取记录
	rec, err := c.readRecord()
	if err != nil {
		return err
	}

	if rec.Type != recordTypeHandshake {
		debugf("DEBUG readServerHello: Expected handshake record, got type=%d (%s), version=0x%04x, length=%d\n",
			rec.Type, recordTypeToString(rec.Type), rec.Version, rec.Length)
		if rec.Type == 21 && len(rec.Data) >= 2 {
			debugf("DEBUG: Alert level=%d, description=%d\n", rec.Data[0], rec.Data[1])
		}
		return errors.New("gmtls: expected handshake record")
	}

	// 解析 ServerHello
	hello := new(serverHelloMsg)
	if err := hello.unmarshal(rec.Data); err != nil {
		return err
	}

	// 保存服务器随机数
	copy(c.serverRandom[:], hello.Random)

	// 设置密码套件
	if len(c.clientCipherSuites) > 0 && !clientOfferedCipherSuite(c.clientCipherSuites, hello.CipherSuite) {
		return fmt.Errorf("gmtls: server selected unsupported cipher suite 0x%04x", hello.CipherSuite)
	}
	c.cipherSuite = GetCipherSuiteByID(hello.CipherSuite)
	if c.cipherSuite == nil {
		return fmt.Errorf("gmtls: unsupported cipher suite 0x%04x", hello.CipherSuite)
	}
	if !cipherSuiteForVersion(c.cipherSuite, c.version) {
		return fmt.Errorf("gmtls: cipher suite not valid for TLS version 0x%04x", c.version)
	}

	// 解析扩展（ALPN 协商结果等）
	for _, ext := range hello.Extensions {
		switch ext.Type {
		case extensionALPN:
			// ALPN 协商结果
			protocols, err := parseALPNExtension(ext.Data)
			if err != nil {
				return err
			}
			if len(protocols) == 1 {
				if len(c.peerProtos) > 0 && !containsString(c.peerProtos, protocols[0]) {
					return fmt.Errorf("gmtls: server selected unsupported ALPN protocol %q", protocols[0])
				}
				c.negotiatedProto = protocols[0]
			} else if len(protocols) > 1 {
				return errors.New("gmtls: invalid ALPN protocol list in ServerHello")
			}
		}
	}

	c.serverHelloSent = true
	return nil
}

// readServerMessages 读取服务器消息
func (c *Conn) readServerMessages() error {
	// 处理 TLS 1.2 服务器消息序列（Certificate, ServerKeyExchange, CertificateRequest, ServerHelloDone）
	for {
		rec, err := c.readRecord()
		if err != nil {
			return err
		}
		if rec.Type != recordTypeHandshake || len(rec.Data) == 0 {
			return errors.New("gmtls: expected handshake record")
		}

		switch rec.Data[0] {
		case typeCertificate:
			certMsg := new(certificateMsg)
			if err := certMsg.unmarshal(rec.Data); err != nil {
				return err
			}
			c.peerCert = certMsg.Certificate
			if c.peerCert != nil {
				c.peerPubKey = c.peerCert.PublicKey
				if c.peerPubKey == nil && len(c.peerCert.Raw) > 0 {
					if pub, err := ParseSM2PublicKeyFromCertificate(c.peerCert.Raw); err == nil {
						c.peerPubKey = pub
						c.peerCert.PublicKey = pub
					}
				}
			}
		case typeServerKeyExchange:
			msg := new(serverKeyExchangeMsg)
			if err := msg.unmarshal(rec.Data); err != nil {
				return err
			}
			c.tls12ServerEphemeralPub = msg.EphemeralPublicKey

			// 验证服务端签名（如果可用）
			if c.config == nil || !c.config.InsecureSkipVerify {
				if c.peerPubKey == nil {
					return errors.New("gmtls: missing server public key for ServerKeyExchange verify")
				}
				pubBytes := make([]byte, 65)
				pubBytes[0] = 0x04
				xBytes := msg.EphemeralPublicKey.X.Bytes()
				yBytes := msg.EphemeralPublicKey.Y.Bytes()
				copy(pubBytes[1+32-len(xBytes):33], xBytes)
				copy(pubBytes[33+32-len(yBytes):65], yBytes)
				signed := make([]byte, 0, 32+32+len(pubBytes))
				signed = append(signed, c.clientRandom[:]...)
				signed = append(signed, c.serverRandom[:]...)
				signed = append(signed, pubBytes...)
				sig, err := signatureFromASN1(msg.Signature)
				if err != nil || !VerifyMessage(c.peerPubKey, signed, sig) {
					return errors.New("gmtls: ServerKeyExchange signature verification failed")
				}
			}
		case typeCertificateRequest:
			req := new(certificateRequestMsg)
			if err := req.unmarshal(rec.Data); err != nil {
				return err
			}
			c.tls12ClientCertRequested = true
		case typeServerHelloDone:
			return nil
		default:
			return fmt.Errorf("gmtls: unexpected handshake message %d", rec.Data[0])
		}
	}
}

// sendClientKeyExchange 发送 ClientKeyExchange 消息
func (c *Conn) sendClientKeyExchange() error {
	// 生成临时密钥对
	priv, pub, err := GenerateKey()
	if err != nil {
		return err
	}

	// 派生共享密钥
	peerKey := c.peerPubKey
	if c.cipherSuite != nil && c.cipherSuite.KeyExchange == "SM2DHE" {
		if c.tls12ServerEphemeralPub == nil {
			return errors.New("gmtls: missing server ephemeral key for SM2DHE")
		}
		peerKey = c.tls12ServerEphemeralPub
	}
	sharedKey := DeriveSharedKey(priv, peerKey)
	if debugEnabled && len(sharedKey) >= 8 {
		debugf("DEBUG: client sharedKey=%02x\n", sharedKey[:8])
	}

	// 计算主密钥
	c.masterSecret = MasterSecretDerive(sharedKey, c.clientRandom[:], c.serverRandom[:])
	if debugEnabled && len(c.masterSecret) >= 8 {
		debugf("DEBUG: client masterSecret=%02x\n", c.masterSecret[:8])
	}

	// 派生密钥块
	keyBlock := KeyBlockDerive(c.masterSecret, c.clientRandom[:], c.serverRandom[:], c.cipherSuite)
	c.clientMAC, c.serverMAC, c.clientKey, c.serverKey, c.clientIV, c.serverIV = ParseKeyBlock(keyBlock, c.cipherSuite)
	if debugEnabled {
		if len(c.clientKey) >= 8 && len(c.serverKey) >= 8 {
			debugf("DEBUG: client keys clientKey=%02x serverKey=%02x\n", c.clientKey[:8], c.serverKey[:8])
		}
		if len(c.clientIV) >= 4 && len(c.serverIV) >= 4 {
			debugf("DEBUG: client IVs clientIV=%02x serverIV=%02x\n", c.clientIV[:4], c.serverIV[:4])
		}
	}

	// 初始化加密
	if c.cipherSuite.IsAEAD {
		// GCM 模式
		isTLS13 := c.version >= VersionTLS13
		c.clientEnc, _ = NewSM4GCMMode(c.clientKey, c.clientIV, true, isTLS13)
		c.serverEnc, _ = NewSM4GCMMode(c.serverKey, c.serverIV, true, isTLS13)
	} else {
		// CBC 模式
		c.clientEnc, _ = NewSM4CBCMode(c.clientKey, c.clientMAC, c.clientIV, true)
		c.serverEnc, _ = NewSM4CBCMode(c.serverKey, c.serverMAC, c.serverIV, true)
	}

	// 设置 halfConn 的加密器（此时还未启用加密）
	c.in.cipher = c.serverEnc  // 接收使用对方（服务端）的密钥
	c.out.cipher = c.clientEnc // 发送使用己方（客户端）的密钥

	// 构造消息
	msg := &clientKeyExchangeMsg{
		PublicKey: pub,
	}

	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// sendChangeCipherSpec 发送 ChangeCipherSpec
func (c *Conn) sendChangeCipherSpec() error {
	if err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	// 发送 CCS 后，启用写加密
	if c.isClient {
		c.clientEncrypted = true
	} else {
		c.serverEncrypted = true
	}
	return nil
}

// readChangeCipherSpec 读取 ChangeCipherSpec
func (c *Conn) readChangeCipherSpec() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}
	if rec.Type != recordTypeChangeCipherSpec {
		return errors.New("gmtls: expected ChangeCipherSpec")
	}
	// 接收 CCS 后，启用读加密
	if c.isClient {
		// 客户端接收服务端的 CCS，之后服务端发送的数据都将被加密
		c.serverEncrypted = true
	} else {
		// 服务端接收客户端的 CCS，之后客户端发送的数据都将被加密
		c.clientEncrypted = true
	}
	return nil
}

// sendFinished 发送 Finished 消息
func (c *Conn) sendFinished() error {
	// 计算 verify_data
	verifyData := c.finishedHash(c.isClient)

	msg := &finishedMsg{
		VerifyData: verifyData,
	}

	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// readFinished 读取 Finished 消息
func (c *Conn) readFinished() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}

	if rec.Data[0] != typeFinished {
		return errors.New("gmtls: expected Finished")
	}

	msg := new(finishedMsg)
	if err := msg.unmarshal(rec.Data); err != nil {
		return err
	}

	// 验证 verify_data
	expectedVerifyData := c.finishedHash(!c.isClient)
	if !bytes.Equal(msg.VerifyData, expectedVerifyData) {
		return errors.New("gmtls: finished verify data mismatch")
	}

	return nil
}

// ============= 服务端握手 =============

func (c *Conn) serverHandshake() error {
	// 检查是否支持 TLS 1.3
	if c.version >= VersionTLS13 {
		return c.serverHandshakeTLS13()
	}

	// TLS 1.2 握手
	// 接收 ClientHello
	if err := c.readClientHello(); err != nil {
		return err
	}

	// 发送 ServerHello
	if err := c.sendServerHello(); err != nil {
		return err
	}

	// 发送 Certificate
	if err := c.sendCertificate(); err != nil {
		return err
	}

	// 发送 ServerKeyExchange（SM2DHE）
	if c.cipherSuite != nil && c.cipherSuite.KeyExchange == "SM2DHE" {
		if err := c.sendServerKeyExchange(); err != nil {
			return err
		}
	}

	// 可选：请求客户端证书
	if c.config != nil && c.config.ClientAuth {
		if err := c.sendCertificateRequest(); err != nil {
			return err
		}
		c.tls12ClientCertRequested = true
	}

	// 发送 ServerHelloDone
	if err := c.sendServerHelloDone(); err != nil {
		return err
	}

	// 接收客户端证书（如果请求）
	if c.tls12ClientCertRequested {
		if err := c.readClientCertificateTLS12(); err != nil {
			return err
		}
	}

	// 接收 ClientKeyExchange
	if err := c.readClientKeyExchange(); err != nil {
		return err
	}

	// 接收 CertificateVerify（如果有客户端证书）
	if c.tls12ClientCertRequested && c.peerCert != nil && c.peerCert.PublicKey != nil {
		if err := c.readCertificateVerifyTLS12(); err != nil {
			return err
		}
	}

	// 发送 ChangeCipherSpec
	if err := c.sendChangeCipherSpec(); err != nil {
		return err
	}

	// 接收 ChangeCipherSpec
	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// 发送 Finished
	if err := c.sendFinished(); err != nil {
		return err
	}

	// 接收 Finished
	if err := c.readFinished(); err != nil {
		return err
	}

	c.handshakeComplete = true
	return nil
}

func (c *Conn) readClientHello() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}

	if rec.Type != recordTypeHandshake {
		return errors.New("gmtls: expected handshake")
	}

	hello := new(clientHelloMsg)
	if err := hello.unmarshal(rec.Data); err != nil {
		return err
	}

	copy(c.clientRandom[:], hello.Random)
	c.clientCipherSuites = append([]uint16(nil), hello.CipherSuites...)

	// 解析扩展
	for _, ext := range hello.Extensions {
		switch ext.Type {
		case extensionServerName:
			// SNI
			serverName, err := parseSNIExtension(ext.Data)
			if err != nil {
				return err
			}
			if serverName != "" {
				c.serverName = serverName
			}
		case extensionALPN:
			// ALPN
			protocols, err := parseALPNExtension(ext.Data)
			if err != nil {
				return err
			}
			c.peerProtos = protocols
		case extensionSignatureAlgorithms:
			// SignatureAlgorithms
			schemes, err := parseSignatureAlgorithmsExtension(ext.Data)
			if err != nil {
				return err
			}
			c.clientSigSchemes = schemes
		case extensionSupportedCurves:
			// SupportedCurves
			curves, err := parseSupportedCurvesExtension(ext.Data)
			if err != nil {
				return err
			}
			c.clientSupportedCurves = curves
		case extensionStatusRequest:
			// OCSP Stapling 请求
			statusType, _, err := parseStatusRequestExtension(ext.Data)
			if err != nil {
				return err
			}
			if statusType == 1 {
				c.tls12StatusRequest = true
			}
		}
	}

	// 选择密码套件
	var serverSuites []uint16
	if c.config != nil && len(c.config.CipherSuites) > 0 {
		serverSuites = c.config.CipherSuites
	} else {
		serverSuites = []uint16{
			TLS_SM2_WITH_SM4_CBC_SM3,
			TLS_SM2DHE_WITH_SM4_CBC_SM3,
			TLS_SM2_WITH_SM4_GCM_SM3,
			TLS_SM2DHE_WITH_SM4_GCM_SM3,
			TLS_SM2_WITH_SM4_CCM_SM3,
			TLS_SM2DHE_WITH_SM4_CCM_SM3,
		}
	}
	c.cipherSuite = selectCipherSuite(hello.CipherSuites, serverSuites, c.version, c.clientSupportedCurves, c.clientSigSchemes)

	if c.cipherSuite == nil {
		return errors.New("gmtls: no common cipher suite")
	}

	// ALPN: 按服务端优先级选择
	if c.config != nil && len(c.config.NextProtos) > 0 && len(c.peerProtos) > 0 {
		c.negotiatedProto = selectALPNProtocol(c.config.NextProtos, c.peerProtos)
	}

	return nil
}

func (c *Conn) sendServerHello() error {
	hello := &serverHelloMsg{
		Version:     c.version,
		Random:      c.serverRandom[:],
		CipherSuite: c.cipherSuite.ID,
	}
	var extensions []Extension
	if c.negotiatedProto != "" {
		extensions = append(extensions, marshalALPNExtension([]string{c.negotiatedProto}))
	}
	hello.Extensions = extensions

	data := hello.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

func (c *Conn) sendCertificate() error {
	if c.localCert == nil {
		return errors.New("gmtls: missing local certificate")
	}
	msg := &certificateMsg{
		Certificate: c.localCert,
	}

	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

func (c *Conn) sendServerHelloDone() error {
	msg := &serverHelloDoneMsg{}
	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// sendServerKeyExchange 发送 TLS 1.2 ServerKeyExchange（SM2DHE）
func (c *Conn) sendServerKeyExchange() error {
	// 生成临时密钥对
	priv, pub, err := GenerateKey()
	if err != nil {
		return err
	}
	c.tls12ServerEphemeralPriv = priv

	// 组装待签名数据：client_random || server_random || server_ephemeral_pub
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	copy(pubBytes[1+32-len(xBytes):33], xBytes)
	copy(pubBytes[33+32-len(yBytes):65], yBytes)
	signed := make([]byte, 0, 32+32+len(pubBytes))
	signed = append(signed, c.clientRandom[:]...)
	signed = append(signed, c.serverRandom[:]...)
	signed = append(signed, pubBytes...)

	sig, err := SignMessage(c.localPriv, signed)
	if err != nil {
		return err
	}
	sigDER, err := signatureToASN1(sig)
	if err != nil {
		return err
	}

	msg := &serverKeyExchangeMsg{
		EphemeralPublicKey: pub,
		Signature:          sigDER,
	}
	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// sendCertificateRequest 发送 TLS 1.2 CertificateRequest
func (c *Conn) sendCertificateRequest() error {
	msg := &certificateRequestMsg{
		CertificateTypes:    []uint8{1}, // rsa_sign (兼容性取值)
		SignatureAlgorithms: []uint16{SM2SM3},
	}
	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// sendClientCertificateTLS12 发送 TLS 1.2 客户端证书（可为空）
func (c *Conn) sendClientCertificateTLS12() error {
	if c.localCert == nil {
		msg := &certificateMsg{Certificate: nil}
		data := msg.marshal()
		return c.writeRecord(recordTypeHandshake, data)
	}
	return c.sendCertificate()
}

// readClientCertificateTLS12 读取 TLS 1.2 客户端证书（可为空）
func (c *Conn) readClientCertificateTLS12() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}
	if rec.Type != recordTypeHandshake || len(rec.Data) == 0 || rec.Data[0] != typeCertificate {
		return errors.New("gmtls: expected client Certificate")
	}
	certMsg := new(certificateMsg)
	if err := certMsg.unmarshal(rec.Data); err != nil {
		return err
	}
	c.peerCert = certMsg.Certificate
	if c.peerCert != nil {
		if c.peerCert.PublicKey == nil && len(c.peerCert.Raw) > 0 {
			if pub, err := ParseSM2PublicKeyFromCertificate(c.peerCert.Raw); err == nil {
				c.peerCert.PublicKey = pub
			}
		}
		c.peerPubKey = c.peerCert.PublicKey
	}
	return nil
}

// sendCertificateVerifyTLS12 发送 TLS 1.2 CertificateVerify
func (c *Conn) sendCertificateVerifyTLS12() error {
	if c.localPriv == nil {
		return errors.New("gmtls: missing client private key for CertificateVerify")
	}
	handshakeHash := SM3(c.handshakeBuf)
	sig, err := Sign(c.localPriv, handshakeHash[:])
	if err != nil {
		return err
	}
	sigDER, err := signatureToASN1(sig)
	if err != nil {
		return err
	}
	msg := &certificateVerifyMsgTLS12{
		SignatureAlgorithm: 0x0100, // sm2_sig_sm3 (兼容取值)
		Signature:          sigDER,
	}
	data := msg.marshal()
	return c.writeRecord(recordTypeHandshake, data)
}

// readCertificateVerifyTLS12 读取并验证 TLS 1.2 CertificateVerify
func (c *Conn) readCertificateVerifyTLS12() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}
	if rec.Type != recordTypeHandshake || len(rec.Data) == 0 || rec.Data[0] != typeCertificateVerify {
		return errors.New("gmtls: expected CertificateVerify")
	}
	msg := new(certificateVerifyMsgTLS12)
	if err := msg.unmarshal(rec.Data); err != nil {
		return err
	}
	if c.config != nil && c.config.InsecureSkipVerify {
		return nil
	}
	if c.peerPubKey == nil {
		return errors.New("gmtls: missing client public key for CertificateVerify")
	}

	// CertificateVerify 的签名应覆盖之前所有握手消息（不含自身）
	transcript := c.handshakeBuf
	if len(transcript) >= len(rec.Data) {
		transcript = transcript[:len(transcript)-len(rec.Data)]
	}
	h := SM3(transcript)
	sig, err := signatureFromASN1(msg.Signature)
	if err != nil || !Verify(c.peerPubKey, h[:], sig) {
		return errors.New("gmtls: CertificateVerify signature verification failed")
	}
	return nil
}

func (c *Conn) readClientKeyExchange() error {
	rec, err := c.readRecord()
	if err != nil {
		return err
	}

	if rec.Data[0] != typeClientKeyExchange {
		return errors.New("gmtls: expected ClientKeyExchange")
	}

	msg := new(clientKeyExchangeMsg)
	if err := msg.unmarshal(rec.Data); err != nil {
		return err
	}

	// 派生共享密钥
	priv := c.localPriv
	if c.cipherSuite != nil && c.cipherSuite.KeyExchange == "SM2DHE" {
		if c.tls12ServerEphemeralPriv == nil {
			return errors.New("gmtls: missing server ephemeral key for SM2DHE")
		}
		priv = c.tls12ServerEphemeralPriv
	}
	sharedKey := DeriveSharedKey(priv, msg.PublicKey)
	if debugEnabled && len(sharedKey) >= 8 {
		debugf("DEBUG: server sharedKey=%02x\n", sharedKey[:8])
	}

	// 计算主密钥
	c.masterSecret = MasterSecretDerive(sharedKey, c.clientRandom[:], c.serverRandom[:])
	if debugEnabled && len(c.masterSecret) >= 8 {
		debugf("DEBUG: server masterSecret=%02x\n", c.masterSecret[:8])
	}

	// 派生密钥块
	keyBlock := KeyBlockDerive(c.masterSecret, c.clientRandom[:], c.serverRandom[:], c.cipherSuite)
	c.clientMAC, c.serverMAC, c.clientKey, c.serverKey, c.clientIV, c.serverIV = ParseKeyBlock(keyBlock, c.cipherSuite)
	if debugEnabled {
		if len(c.clientKey) >= 8 && len(c.serverKey) >= 8 {
			debugf("DEBUG: server keys clientKey=%02x serverKey=%02x\n", c.clientKey[:8], c.serverKey[:8])
		}
		if len(c.clientIV) >= 4 && len(c.serverIV) >= 4 {
			debugf("DEBUG: server IVs clientIV=%02x serverIV=%02x\n", c.clientIV[:4], c.serverIV[:4])
		}
	}

	// 初始化加密
	if c.cipherSuite.IsAEAD {
		isTLS13 := c.version >= VersionTLS13
		c.clientEnc, _ = NewSM4GCMMode(c.clientKey, c.clientIV, true, isTLS13)
		c.serverEnc, _ = NewSM4GCMMode(c.serverKey, c.serverIV, true, isTLS13)
	} else {
		c.clientEnc, _ = NewSM4CBCMode(c.clientKey, c.clientMAC, c.clientIV, true)
		c.serverEnc, _ = NewSM4CBCMode(c.serverKey, c.serverMAC, c.serverIV, true)
	}

	// 设置 halfConn 的加密器（此时还未启用加密）
	c.in.cipher = c.clientEnc  // 接收使用对方（客户端）的密钥
	c.out.cipher = c.serverEnc // 发送使用己方（服务端）的密钥

	return nil
}

// ============= 记录层读/写 =============

func (c *Conn) writeRecord(typ recordType, data []byte) error {
	var payload []byte
	var err error
	outType := typ

	if c.version < VersionTLS13 && typ == recordTypeHandshake && len(data) > 0 && data[0] != typeFinished {
		// TLS 1.2: accumulate handshake transcript (exclude Finished itself)
		c.handshakeBuf = append(c.handshakeBuf, data...)
	}

	// 判断是否需要加密
	if c.isClient && c.clientEncrypted && c.out.cipher != nil {
		// 客户端发送，使用客户端加密
		if cbc, ok := c.out.cipher.(*SM4CBCMode); ok {
			payload, err = cbc.Encrypt(typ, data)
			if err != nil {
				return err
			}
		} else if gcm, ok := c.out.cipher.(*SM4GCMMode); ok {
			payload, err = gcm.Encrypt(typ, data)
			if err != nil {
				return err
			}
			if c.version >= VersionTLS13 {
				outType = recordTypeApplicationData
			}
		} else {
			payload = data // 不加密
		}
	} else if !c.isClient && c.serverEncrypted && c.out.cipher != nil {
		// 服务端发送，使用服务端加密
		if cbc, ok := c.out.cipher.(*SM4CBCMode); ok {
			payload, err = cbc.Encrypt(typ, data)
			if err != nil {
				return err
			}
		} else if gcm, ok := c.out.cipher.(*SM4GCMMode); ok {
			payload, err = gcm.Encrypt(typ, data)
			if err != nil {
				return err
			}
			if c.version >= VersionTLS13 {
				outType = recordTypeApplicationData
			}
		} else {
			payload = data // 不加密
		}
	} else {
		// 明文传输
		payload = data
	}

	// 构造记录层头部
	record := make([]byte, recordHeaderLen+len(payload))
	record[0] = byte(outType)
	// TLS 1.3 记录层版本固定为 0x0303
	vers := c.version
	if c.version >= VersionTLS13 {
		vers = VersionTLS12
	}
	if c.nextRecordVersion != 0 {
		vers = c.nextRecordVersion
		c.nextRecordVersion = 0
	}
	binary.BigEndian.PutUint16(record[1:3], vers)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[5:], payload)

	_, err = c.conn.Write(record)
	return err
}

func (c *Conn) readRecord() (*Record, error) {
	header := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	typ := recordType(header[0])
	vers := binary.BigEndian.Uint16(header[1:3])
	length := binary.BigEndian.Uint16(header[3:5])

	// Debug: log record header
	debugf("DEBUG readRecord: type=%d (%s), version=0x%04x, length=%d\n",
		typ, recordTypeToString(typ), vers, length)

	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}

	// Debug: log first 50 bytes for handshake/alert records
	if typ == recordTypeHandshake || typ == recordTypeAlert {
		debugf("DEBUG readRecord: data (first 50 bytes): %02x\n", data[:min(50, len(data))])
	}

	payload := data

	// 判断是否需要解密
	// TLS 1.3: ChangeCipherSpec (type=20) 和 Alert (type=21) 不加密
	shouldDecrypt := (typ != 20) && (typ != 21) // 不是 ChangeCipherSpec 或 Alert

	if shouldDecrypt {
		if c.isClient && c.serverEncrypted && c.in.cipher != nil {
			// 客户端接收，使用服务端密钥解密
			if cbc, ok := c.in.cipher.(*SM4CBCMode); ok {
				decrypted, err := cbc.Decrypt(typ, data)
				if err != nil {
					return nil, err
				}
				payload = decrypted
			} else if gcm, ok := c.in.cipher.(*SM4GCMMode); ok {
				// DEBUG: 显示原始加密数据
				if typ == 23 { // ApplicationData (encrypted)
					debugf("DEBUG readRecord: encrypted payload (hex): %02x\n", data)
				}
				decrypted, err := gcm.Decrypt(typ, data)
				if err != nil {
					return nil, err
				}
				payload = decrypted
			}
		} else if !c.isClient && c.clientEncrypted && c.in.cipher != nil {
			// 服务端接收，使用客户端密钥解密
			if cbc, ok := c.in.cipher.(*SM4CBCMode); ok {
				decrypted, err := cbc.Decrypt(typ, data)
				if err != nil {
					return nil, err
				}
				payload = decrypted
			} else if gcm, ok := c.in.cipher.(*SM4GCMMode); ok {
				decrypted, err := gcm.Decrypt(typ, data)
				if err != nil {
					return nil, err
				}
				payload = decrypted
			}
		}
	}

	if c.version < VersionTLS13 && typ == recordTypeHandshake && len(payload) > 0 && payload[0] != typeFinished {
		// TLS 1.2: accumulate handshake transcript (exclude Finished itself)
		c.handshakeBuf = append(c.handshakeBuf, payload...)
	}

	// TLS 1.3: after handshake, strip inner content type for callers.
	if c.version >= VersionTLS13 && typ == recordTypeApplicationData && c.handshakeComplete {
		if stripped, innerType, err := stripTLS13InnerContentType(payload); err == nil {
			if debugEnabled {
				debugf("DEBUG TLS13 innerType=%d (%s), innerLen=%d\n", innerType, recordTypeToString(innerType), len(stripped))
				if innerType == recordTypeAlert && len(stripped) >= 2 {
					debugf("DEBUG TLS13 alert: level=%d desc=%d\n", stripped[0], stripped[1])
				}
			}
			if innerType == recordTypeAlert {
				return &Record{
					Type:    recordTypeAlert,
					Version: vers,
					Length:  uint16(len(stripped)),
					Data:    stripped,
				}, nil
			}
			if innerType == recordTypeApplicationData {
				payload = stripped
			}
		}
	}

	return &Record{
		Type:    typ,
		Version: vers,
		Length:  length,
		Data:    payload,
	}, nil
}

// ============= 握手哈希 =============

// finishedHash 计算 Finished 消息的 verify_data
//
// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]
//
// 对于 TLS 1.2:
//   - finished_label: "client finished" 或 "server finished"
//   - Hash: SM3
//   - verify_data_length: 12
func (c *Conn) finishedHash(isClient bool) []byte {
	// 确定标签
	label := []byte("client finished")
	if !isClient {
		label = []byte("server finished")
	}

	// 计算握手消息哈希（包含 Finished 之前的所有握手消息）
	var handshakeHash []byte
	if len(c.handshakeBuf) > 0 {
		hash := SM3(c.handshakeBuf)
		handshakeHash = hash[:]
	} else {
		// 如果没有握手消息缓存，使用零哈希（仅用于向后兼容）
		handshakeHash = make([]byte, SM3Size)
	}

	// 计算 verify_data
	return PRF(c.masterSecret, label, handshakeHash, 12)
}

// ============= 应用数据读写 =============

func (c *Conn) Read(b []byte) (n int, err error) {
	if !c.handshakeComplete {
		return 0, errors.New("gmtls: handshake not complete")
	}

	if len(c.appReadBuf) > 0 {
		n = copy(b, c.appReadBuf)
		c.appReadBuf = c.appReadBuf[n:]
		return n, nil
	}

	for {
		rec, err := c.readRecord()
		if err != nil {
			return 0, err
		}

		if rec.Type == recordTypeAlert {
			if len(rec.Data) >= 2 {
				level := rec.Data[0]
				desc := rec.Data[1]
				if level == 1 && desc == 0 {
					return 0, io.EOF
				}
				return 0, fmt.Errorf("gmtls: alert level=%d desc=%d", level, desc)
			}
			return 0, errors.New("gmtls: invalid alert")
		}
		if rec.Type != recordTypeApplicationData {
			return 0, errors.New("gmtls: expected application data")
		}

		payload := rec.Data
		if c.version >= VersionTLS13 {
			if len(rec.Data) > 0 && !isTLS13InnerTypeByte(rec.Data[len(rec.Data)-1]) {
				payload = rec.Data
			} else {
				stripped, innerType, err := stripTLS13InnerContentType(rec.Data)
				if err != nil {
					return 0, err
				}
				switch innerType {
				case recordTypeApplicationData:
					payload = stripped
				case recordTypeAlert:
					if len(stripped) >= 2 {
						level := stripped[0]
						desc := stripped[1]
						if level == 1 && desc == 0 { // close_notify
							return 0, io.EOF
						}
						return 0, fmt.Errorf("gmtls: alert level=%d desc=%d", level, desc)
					}
					return 0, errors.New("gmtls: invalid alert")
				case recordTypeHandshake:
					if c.handshakeComplete && tls13ConsumeNewSessionTickets(stripped, c) {
						continue
					}
					return 0, fmt.Errorf("gmtls: unexpected inner content type %d", innerType)
				default:
					return 0, fmt.Errorf("gmtls: unexpected inner content type %d", innerType)
				}
			}
		}

		if len(payload) > len(b) {
			n = copy(b, payload)
			c.appReadBuf = append(c.appReadBuf[:0], payload[n:]...)
			return n, nil
		}

		// readRecord 已经处理了解密，这里直接返回数据
		n = copy(b, payload)
		return n, nil
	}
}

func tls13AllNewSessionTickets(data []byte) bool {
	for len(data) > 0 {
		if len(data) < 4 {
			return false
		}
		typ := data[0]
		ln := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		data = data[4:]
		if ln < 0 || len(data) < ln {
			return false
		}
		if typ != typeNewSessionTicket {
			return false
		}
		data = data[ln:]
	}
	return true
}

func tls13ConsumeNewSessionTickets(data []byte, c *Conn) bool {
	if !tls13LooksLikeNewSessionTicket(data) && !tls13AllNewSessionTickets(data) {
		return false
	}
	if err := tls13ParseAndStoreTickets(data, c); err != nil {
		if debugEnabled {
			debugf("DEBUG TLS13: failed to parse NewSessionTicket: %v (ignored)\n", err)
		}
		// best-effort: ignore tickets even if parsing fails
		return true
	}
	if debugEnabled {
		debugln("DEBUG TLS13: consumed post-handshake NewSessionTicket(s)")
	}
	return true
}

func tls13LooksLikeNewSessionTicket(data []byte) bool {
	return len(data) >= 1 && data[0] == typeNewSessionTicket
}

type TLS13SessionTicket struct {
	Lifetime   uint32
	AgeAdd     uint32
	Nonce      []byte
	Ticket     []byte
	PSK        []byte
	ReceivedAt time.Time
}

func tls13ParseAndStoreTickets(data []byte, c *Conn) error {
	for len(data) > 0 {
		if len(data) < 4 {
			return errors.New("short handshake header")
		}
		typ := data[0]
		ln := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		data = data[4:]
		if ln < 0 || len(data) < ln {
			return errors.New("truncated handshake body")
		}
		body := data[:ln]
		data = data[ln:]
		if typ != typeNewSessionTicket {
			return fmt.Errorf("unexpected post-handshake type %d", typ)
		}
		t, err := tls13ParseNewSessionTicket(body)
		if err != nil {
			return err
		}
		t.ReceivedAt = time.Now()
		if c != nil && c.tls13KeyMaterial != nil && len(c.tls13KeyMaterial.ResumptionMasterSecret) > 0 {
			t.PSK = DeriveResumptionPSK(c.tls13KeyMaterial.ResumptionMasterSecret, t.Nonce)
		}
		c.tls13Tickets = append(c.tls13Tickets, t)
		if c != nil && c.config != nil && c.config.OnNewSessionTicket != nil {
			c.config.OnNewSessionTicket(t)
		}
	}
	return nil
}

func tls13ParseNewSessionTicket(body []byte) (TLS13SessionTicket, error) {
	var t TLS13SessionTicket
	if len(body) < 4+4+1+2+2 {
		return t, errors.New("short NewSessionTicket body")
	}
	t.Lifetime = uint32(body[0])<<24 | uint32(body[1])<<16 | uint32(body[2])<<8 | uint32(body[3])
	t.AgeAdd = uint32(body[4])<<24 | uint32(body[5])<<16 | uint32(body[6])<<8 | uint32(body[7])
	nonceLen := int(body[8])
	if len(body) < 9+nonceLen+2 {
		return t, errors.New("short NewSessionTicket nonce")
	}
	t.Nonce = append([]byte(nil), body[9:9+nonceLen]...)
	off := 9 + nonceLen
	if len(body) < off+2 {
		return t, errors.New("short NewSessionTicket ticket length")
	}
	ticketLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if len(body) < off+ticketLen+2 {
		return t, errors.New("short NewSessionTicket ticket")
	}
	t.Ticket = append([]byte(nil), body[off:off+ticketLen]...)
	off += ticketLen
	if len(body) < off+2 {
		return t, errors.New("short NewSessionTicket extensions length")
	}
	extLen := int(body[off])<<8 | int(body[off+1])
	off += 2
	if len(body) < off+extLen {
		return t, errors.New("short NewSessionTicket extensions")
	}
	return t, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.handshakeComplete {
		return 0, errors.New("gmtls: handshake not complete")
	}

	// writeRecord 会处理加密，直接调用即可
	err = c.writeRecord(recordTypeApplicationData, b)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

// SessionTickets returns a copy of TLS 1.3 session tickets received on this connection.
func (c *Conn) SessionTickets() []TLS13SessionTicket {
	if c == nil || len(c.tls13Tickets) == 0 {
		return nil
	}
	out := make([]TLS13SessionTicket, len(c.tls13Tickets))
	for i, t := range c.tls13Tickets {
		out[i] = t
		if t.Nonce != nil {
			out[i].Nonce = append([]byte(nil), t.Nonce...)
		}
		if t.Ticket != nil {
			out[i].Ticket = append([]byte(nil), t.Ticket...)
		}
		if t.PSK != nil {
			out[i].PSK = append([]byte(nil), t.PSK...)
		}
	}
	return out
}

// ============= 握手消息结构 =============

// 注意：TLS 握手消息类型常量和结构体定义已在 handshake.go 中定义
// 注意：TLS 扩展类型常量已在 extensions.go 中定义
// Extension 结构体及其处理函数已在 extensions.go 中定义

// clientHelloMsg TLS ClientHello 消息
// 注意：完整的消息定义和序列化方法在 handshake.go 中

// ============= TLS 扩展解析和编码 =============
// 注意：所有扩展的类型定义和编码/解码函数已在 extensions.go 中定义
// 包括：SNI, ALPN, SignatureAlgorithms, StatusRequest, SupportedCurves 等
//
// CurveID 常量已在 extensions.go 中定义：
//   - CurveP256, CurveP384, CurveP521, CurveX25519, CurveSM2
//
// SignatureScheme 常量已在 extensions.go 中定义：
//   - PKCS1WithSM2SM3, ECDSAWithSM2SM3, PKCS1WithSHA256, etc.
//
// 编码函数：marshalSNIExtension, marshalALPNExtension, etc.
// 解析函数：parseSNIExtension, parseALPNExtension, etc.

// 注意：clientHelloMsg 的 marshal() 和 unmarshal() 方法已在 handshake.go 中定义

// ============= TLS 1.3 客户端握手 =============

func (c *Conn) clientHandshakeTLS13() error {
	debugln("DEBUG: Starting TLS 1.3 client handshake")
	// 初始化 transcript hash
	c.transcriptHash = NewSM3()

	// 发送 ClientHello
	debugln("DEBUG: Sending ClientHello...")
	if err := c.sendClientHelloTLS13(); err != nil {
		debugf("DEBUG: sendClientHelloTLS13 failed: %v\n", err)
		return err
	}
	debugln("DEBUG: ClientHello sent successfully")

	// 接收 ServerHello (可能是 HelloRetryRequest)
	debugln("DEBUG: Reading ServerHello...")
	if err := c.readServerHelloTLS13(); err != nil {
		if errors.Is(err, errHelloRetryRequest) && c.tls13HelloRetry {
			debugln("DEBUG: HelloRetryRequest received, sending second ClientHello...")
			// TLS 1.3 middlebox compatibility: send dummy ChangeCipherSpec
			if err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
				return err
			}
			if err := c.sendClientHelloTLS13WithGroup(c.tls13RequestedGroup); err != nil {
				debugf("DEBUG: sendClientHelloTLS13WithGroup failed: %v\n", err)
				return err
			}
			if err := c.readServerHelloTLS13(); err != nil {
				debugf("DEBUG: readServerHelloTLS13 failed after HRR: %v\n", err)
				return err
			}
		} else {
			debugf("DEBUG: readServerHelloTLS13 failed: %v\n", err)
			return err
		}
	}
	debugln("DEBUG: ServerHello received successfully")

	// 接收 EncryptedExtensions
	debugln("DEBUG: Reading EncryptedExtensions...")
	if err := c.readEncryptedExtensions(); err != nil {
		debugf("DEBUG: readEncryptedExtensions failed: %v\n", err)
		return err
	}
	debugln("DEBUG: EncryptedExtensions received successfully")

	// 接收 Certificate
	debugln("DEBUG: Reading Certificate...")
	if err := c.readCertificateTLS13(); err != nil {
		debugf("DEBUG: readCertificateTLS13 failed: %v\n", err)
		return err
	}
	debugln("DEBUG: Certificate received successfully")

	// 接收 CertificateVerify
	debugln("DEBUG: Reading CertificateVerify...")
	if err := c.readCertificateVerifyTLS13(); err != nil {
		debugf("DEBUG: readCertificateVerifyTLS13 failed: %v\n", err)
		return err
	}
	debugln("DEBUG: CertificateVerify received successfully")

	// 接收 Finished
	debugln("DEBUG: Reading Finished...")
	if err := c.readFinishedTLS13(); err != nil {
		debugf("DEBUG: readFinishedTLS13 failed: %v\n", err)
		return err
	}
	debugln("DEBUG: Finished received successfully")

	// 服务器在其 Finished 后可以立即发送应用数据，客户端需提前切换入站密钥
	if c.isClient {
		c.deriveTLS13ServerAppKeys()
		c.setupServerApplicationTrafficKeysForClient()
	}

	// 如果服务端请求客户端证书，发送 Certificate 和 CertificateVerify
	if c.tls13ClientCertRequested {
		if c.localCert == nil || c.localPriv == nil {
			return errors.New("gmtls: server requested client certificate, but none configured")
		}
		// TLS 1.3: client Certificate/CertificateVerify are encrypted with client handshake keys
		if !c.clientEncrypted {
			gcm, err := NewSM4GCMMode(c.tls13KeyMaterial.ClientHandshakeKey, c.tls13KeyMaterial.ClientHandshakeIV, false, true)
			if err != nil {
				return err
			}
			c.clientEncrypted = true
			c.out.cipher = gcm
		}
		if err := c.sendCertificateTLS13(); err != nil {
			return err
		}
		if err := c.sendCertificateVerifyTLS13(); err != nil {
			return err
		}
	}

	// 发送 Finished
	debugln("DEBUG: Sending Finished...")
	if err := c.sendFinishedTLS13(); err != nil {
		debugf("DEBUG: sendFinishedTLS13 failed: %v\n", err)
		return err
	}
	debugln("DEBUG: Finished sent successfully")

	// 派生应用流量密钥（包含客户端 Finished）
	c.deriveTLS13ApplicationKeys()

	// 设置应用流量密钥
	c.setupApplicationTrafficKeys()

	c.handshakeComplete = true
	debugln("DEBUG: TLS 1.3 handshake completed successfully")
	return nil
}

// sendClientHelloTLS13 发送 TLS 1.3 ClientHello
func (c *Conn) sendClientHelloTLS13() error {
	group := CurveSM2
	return c.sendClientHelloTLS13WithGroup(group)
}

func (c *Conn) sendClientHelloTLS13WithGroup(keyShareGroup uint16) error {
	// 固定 TLS 1.3 密码套件顺序，优先 0x00C6/0x00C7 以兼容 Tongsuo
	suites := []uint16{
		TLS_SM4_GCM_SM3_ALT, // 0x00C6 (BabaSSL/Tongsuo compat)
		TLS_SM4_CCM_SM3_ALT, // 0x00C7 (BabaSSL/Tongsuo compat)
		TLS_SM4_GCM_SM3,     // 0x1306 (RFC 8998)
		TLS_SM4_CCM_SM3,     // 0x1307 (RFC 8998)
	}
	c.clientCipherSuites = append([]uint16(nil), suites...)

	// 生成 key_share
	var keyShareEntries []KeyShareEntry
	km := &TLS13KeyMaterial{}
	switch keyShareGroup {
	case CurveSM2:
		sm2PrivKey, sm2PubKey, err := GenerateSM2KeyPairForTLS13()
		if err != nil {
			return fmt.Errorf("gmtls: failed to generate SM2 key pair: %v", err)
		}
		km.ClientPrivateShare = sm2PrivKey
		keyShareEntries = []KeyShareEntry{{Group: CurveSM2, KeyExchange: sm2PubKey}}
	case CurveX25519:
		x25519PrivKey, x25519PubKey, err := GenerateX25519Key()
		if err != nil {
			return fmt.Errorf("gmtls: failed to generate X25519 key pair: %v", err)
		}
		km.ClientX25519PrivateKey = x25519PrivKey
		keyShareEntries = []KeyShareEntry{{Group: CurveX25519, KeyExchange: x25519PubKey}}
	default:
		return fmt.Errorf("gmtls: unsupported key_share group 0x%04x", keyShareGroup)
	}
	if c.tls13KeyMaterial != nil {
		// preserve any existing keys needed for later
		if km.ClientPrivateShare == nil {
			km.ClientPrivateShare = c.tls13KeyMaterial.ClientPrivateShare
		}
		if km.ClientX25519PrivateKey == nil {
			km.ClientX25519PrivateKey = c.tls13KeyMaterial.ClientX25519PrivateKey
		}
	}
	c.tls13KeyMaterial = km

	// 生成/复用 Session ID（HelloRetryRequest 需保持一致）
	var sessionID []byte
	if len(c.tls13SessionID) > 0 {
		sessionID = c.tls13SessionID
	} else {
		sessionID = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
			return fmt.Errorf("gmtls: failed to generate session ID: %v", err)
		}
		c.tls13SessionID = sessionID
	}

	// 构造握手消息
	hello := &clientHelloMsg{
		Version:            VersionTLS12, // ClientHello.version 必须是 TLS 1.2
		Random:             c.clientRandom[:],
		SessionID:          sessionID,
		CipherSuites:       append(append([]uint16{}, suites...), 0x00FF), // EMPTY_RENEGOTIATION_INFO_SCSV
		CompressionMethods: []uint8{0},                                    // 无压缩
	}

	// 添加 TLS 1.3 扩展（顺序尽量匹配 BabaSSL）
	var extensions []Extension

	// 1. SNI
	if c.clientServerName != "" {
		extensions = append(extensions, marshalSNIExtension(c.clientServerName))
	}

	// 2. ec_point_formats
	extensions = append(extensions, marshalECPointFormatsExtension())

	// 3. supported_groups
	supportedGroupsExt := marshalSupportedCurvesExtension([]uint16{CurveSM2})
	extensions = append(extensions, supportedGroupsExt)

	// 4. session_ticket / encrypt_then_mac / extended_master_secret (empty)
	extensions = append(extensions, marshalEmptyExtension(extensionSessionTicket))
	extensions = append(extensions, marshalEmptyExtension(extensionEncryptThenMAC))
	extensions = append(extensions, marshalEmptyExtension(extensionExtendedMasterSecret))

	// 5. signature_algorithms
	sigSchemes := []uint16{SM2SM3}
	extensions = append(extensions, marshalSignatureAlgorithmsExtension(sigSchemes))
	// 5.1 signature_algorithms_cert (match signature_algorithms for strict servers)
	extensions = append(extensions, marshalSignatureAlgorithmsCertExtension(sigSchemes))

	// 6. supported_versions (only TLS 1.3)
	supportedVersionsExt := Extension{
		Type: extensionSupportedVersions,
		Data: []byte{
			0x02,       // length
			0x03, 0x04, // TLS 1.3
		},
	}
	extensions = append(extensions, supportedVersionsExt)

	// 7. psk_kex_modes
	extensions = append(extensions, marshalPSKKexModesExtension([]uint8{PSKModeDHE}))

	// 8. key_share
	extensions = append(extensions, marshalKeyShareExtension(keyShareEntries))

	// 9. ALPN (如有)
	if len(c.peerProtos) > 0 {
		extensions = append(extensions, marshalALPNExtension(c.peerProtos))
	}

	// 10. pre_shared_key (TLS 1.3 resumption) - must be last if present
	var pskInfo *tls13PSKInfo
	if c.config != nil && len(c.config.SessionTickets) > 0 {
		if info := buildTLS13PSKInfo(c.config.SessionTickets); info != nil {
			pskInfo = info
			extensions = append(extensions, info.Ext)
		}
	}

	hello.Extensions = extensions

	data := hello.marshal()
	if pskInfo != nil {
		// Compute binder over ClientHello with zeroed binders (current data).
		psk := pskInfo.PSK
		earlySecret := DeriveEarlySecret(psk)
		binderKey := SM3HKDFExpandLabel(earlySecret, "res binder", []byte{}, SM3HashSize)
		finishedKey := DeriveFinishedKey(binderKey)
		chHash := SM3(data)
		hmac := NewSM3HMAC(finishedKey)
		hmac.Write(chHash[:])
		binder := hmac.Sum(nil)[:SM3HashSize]
		pskInfo.SetBinder(binder)

		// Re-marshal ClientHello with real binder.
		hello.Extensions = rebuildExtensionsWithPSK(extensions, pskInfo)
		data = hello.marshal()
	}

	debugf("DEBUG ClientHello: %02x\n", data)
	c.lastClientHello = append([]byte(nil), data...)

	// 更新 transcript hash
	c.transcriptHash.Write(data)

	// 保存 ClientHello 哈希（用于后续密钥派生）
	h := NewSM3()
	h.Write(data)
	c.clientHelloHash = h.Sum(nil)

	debugHash := c.transcriptHash.Sum(nil)
	debugf("DEBUG Transcript hash after ClientHello: %02x\n", debugHash)

	var recordVers uint16 = VersionTLS12
	if c.tls13ClientHelloCnt == 0 {
		recordVers = VersionTLS10
	}
	c.tls13ClientHelloCnt++
	c.nextRecordVersion = recordVers
	return c.writeRecord(recordTypeHandshake, data)
}

type tls13PSKInfo struct {
	Ext         Extension
	PSK         []byte
	binderStart int
	binderLen   int
}

func (p *tls13PSKInfo) SetBinder(binder []byte) {
	if p == nil || len(binder) == 0 {
		return
	}
	if p.binderStart+p.binderLen > len(p.Ext.Data) {
		return
	}
	copy(p.Ext.Data[p.binderStart:p.binderStart+p.binderLen], binder[:p.binderLen])
}

func rebuildExtensionsWithPSK(exts []Extension, psk *tls13PSKInfo) []Extension {
	if psk == nil {
		return exts
	}
	out := make([]Extension, len(exts))
	for i, e := range exts {
		if e.Type == extensionPreSharedKey {
			out[i] = psk.Ext
		} else {
			out[i] = e
		}
	}
	return out
}

func buildTLS13PSKInfo(tickets []TLS13SessionTicket) *tls13PSKInfo {
	if len(tickets) == 0 {
		return nil
	}
	t := selectResumptionTicket(tickets)
	if t == nil || len(t.PSK) == 0 || len(t.Ticket) == 0 {
		return nil
	}

	// identities vector
	var identities []byte
	ticketLen := len(t.Ticket)
	identities = append(identities, byte(ticketLen>>8), byte(ticketLen))
	identities = append(identities, t.Ticket...)
	age := obfuscatedTicketAge(*t)
	identities = append(identities,
		byte(age>>24), byte(age>>16), byte(age>>8), byte(age))
	identitiesLen := len(identities)

	// binders vector (single binder, zeroed)
	binderLen := SM3HashSize
	binders := []byte{byte(binderLen)}
	binderStart := 2 + identitiesLen + 2 + 1
	binders = append(binders, make([]byte, binderLen)...)
	bindersLen := len(binders)

	extData := make([]byte, 0, 2+identitiesLen+2+bindersLen)
	extData = append(extData, byte(identitiesLen>>8), byte(identitiesLen))
	extData = append(extData, identities...)
	extData = append(extData, byte(bindersLen>>8), byte(bindersLen))
	extData = append(extData, binders...)

	return &tls13PSKInfo{
		Ext: Extension{
			Type: extensionPreSharedKey,
			Data: extData,
		},
		PSK:         t.PSK,
		binderStart: binderStart,
		binderLen:   binderLen,
	}
}

func selectResumptionTicket(tickets []TLS13SessionTicket) *TLS13SessionTicket {
	for i := range tickets {
		t := &tickets[i]
		if len(t.Ticket) == 0 || len(t.PSK) == 0 || t.Lifetime == 0 {
			continue
		}
		if t.ReceivedAt.IsZero() {
			continue
		}
		if time.Since(t.ReceivedAt) > time.Duration(t.Lifetime)*time.Second {
			continue
		}
		return t
	}
	return nil
}

func obfuscatedTicketAge(t TLS13SessionTicket) uint32 {
	if t.ReceivedAt.IsZero() {
		return t.AgeAdd
	}
	ageMs := uint32(time.Since(t.ReceivedAt).Milliseconds())
	return ageMs + t.AgeAdd
}

// readServerHelloTLS13 读取 TLS 1.3 ServerHello
func (c *Conn) readServerHelloTLS13() error {
	// 读取记录，跳过 ChangeCipherSpec
	var rec *Record
	for {
		r, err := c.readRecord()
		if err != nil {
			return err
		}
		if r.Type == recordTypeChangeCipherSpec {
			continue
		}
		rec = r
		break
	}

	// 检查是否是 HelloRetryRequest
	if rec.Type == recordTypeHandshake && len(rec.Data) > 0 && rec.Data[0] == typeServerHello {
		// 解析消息
		hello := new(serverHelloMsg)
		if err := hello.unmarshal(rec.Data); err != nil {
			return err
		}

		// 检查是否是 HelloRetryRequest (ServerHello with special random)
		isHelloRetry := len(hello.Random) == 32 && bytes.Equal(hello.Random, helloRetryRequestRandom)

		if isHelloRetry {
			// 解析 key_share 中的目标组
			var requestedGroup uint16
			for _, ext := range hello.Extensions {
				if ext.Type != extensionKeyShare {
					continue
				}
				// HRR key_share only contains selected group (2 bytes)
				if len(ext.Data) == 2 {
					requestedGroup = binary.BigEndian.Uint16(ext.Data)
					break
				}
				keyShare, err := parseKeyShareExtension(ext.Data)
				if err != nil {
					return fmt.Errorf("gmtls: failed to parse HRR key_share: %v", err)
				}
				requestedGroup = keyShare.Group
				break
			}
			if requestedGroup == 0 {
				return errors.New("gmtls: HelloRetryRequest missing key_share group")
			}

			if len(c.lastClientHello) == 0 {
				return errors.New("gmtls: missing ClientHello for HRR")
			}
			// Reset transcript hash: message_hash(CH1) || HRR
			chHash := SM3(c.lastClientHello)
			msgHash := make([]byte, 4+len(chHash))
			msgHash[0] = typeMessageHash
			msgHash[1] = 0
			msgHash[2] = 0
			msgHash[3] = byte(len(chHash))
			copy(msgHash[4:], chHash[:])

			c.transcriptHash = NewSM3()
			c.transcriptHash.Write(msgHash)
			c.transcriptHash.Write(rec.Data)

			c.tls13HelloRetry = true
			c.tls13RequestedGroup = requestedGroup
			return errHelloRetryRequest
		}
	}

	if rec.Type != recordTypeHandshake {
		debugf("DEBUG readServerHelloTLS13: Expected handshake record, got type=%d (%s), version=0x%04x, length=%d\n",
			rec.Type, recordTypeToString(rec.Type), rec.Version, rec.Length)
		if rec.Type == 21 && len(rec.Data) >= 2 {
			// Alert
			debugf("DEBUG: Alert level=%d, description=%d\n", rec.Data[0], rec.Data[1])
		}
		debugf("DEBUG: Data (first 50 bytes): %02x\n", rec.Data[:min(50, len(rec.Data))])
		return errors.New("gmtls: expected handshake record")
	}

	// 更新 transcript hash
	c.transcriptHash.Write(rec.Data)
	c.lastServerHello = append([]byte(nil), rec.Data...)

	// DEBUG: 输出完整的 ServerHello 数据
	debugf("DEBUG ServerHello data (%d bytes): %02x\n", len(rec.Data), rec.Data)

	// DEBUG: 输出更新后的 transcript hash
	serverHelloHashDebug := c.transcriptHash.Sum(nil)
	debugf("DEBUG Transcript hash after ServerHello: %02x\n", serverHelloHashDebug)

	// 解析 ServerHello
	hello := new(serverHelloMsg)
	if err := hello.unmarshal(rec.Data); err != nil {
		return err
	}

	// 保存服务器随机数
	copy(c.serverRandom[:], hello.Random)

	// 设置密码套件
	if len(c.clientCipherSuites) > 0 && !clientOfferedCipherSuite(c.clientCipherSuites, hello.CipherSuite) {
		return fmt.Errorf("gmtls: server selected unsupported cipher suite 0x%04x", hello.CipherSuite)
	}
	c.cipherSuite = GetCipherSuiteByID(hello.CipherSuite)
	if c.cipherSuite == nil {
		return fmt.Errorf("gmtls: unsupported cipher suite 0x%04x", hello.CipherSuite)
	}
	if !cipherSuiteForVersion(c.cipherSuite, VersionTLS13) {
		return fmt.Errorf("gmtls: cipher suite not valid for TLS 1.3: 0x%04x", hello.CipherSuite)
	}

	// 解析扩展中的 key_share
	var serverKeyShare *KeyShareEntry
	for _, ext := range hello.Extensions {
		if ext.Type == extensionKeyShare {
			keyShare, err := parseKeyShareExtension(ext.Data)
			if err != nil {
				return fmt.Errorf("gmtls: failed to parse key_share extension: %v", err)
			}
			serverKeyShare = keyShare
			c.tls13KeyMaterial.ServerPublicShare = serverKeyShare.KeyExchange
			// DEBUG: 输出服务器 key_share
			debugf("DEBUG Server key_share: group=0x%04x, key_len=%d\n", serverKeyShare.Group, len(serverKeyShare.KeyExchange))
			break
		}
	}

	if serverKeyShare == nil {
		return errors.New("gmtls: server did not send key_share extension")
	}

	// DEBUG: 输出服务器 key_share
	debugf("DEBUG Server key_share: group=0x%04x, key_len=%d\n", serverKeyShare.Group, len(serverKeyShare.KeyExchange))

	// 根据服务器选择的组使用对应的私钥
	var sharedSecret []byte
	var err error
	if serverKeyShare.Group == CurveX25519 {
		// 服务器选择了 X25519
		sharedSecret, err = DeriveX25519SharedSecret(c.tls13KeyMaterial.ClientX25519PrivateKey, serverKeyShare.KeyExchange)
		if err != nil {
			return fmt.Errorf("gmtls: failed to derive X25519 shared secret: %v", err)
		}
		debugf("DEBUG Using X25519 key exchange\n")
	} else if serverKeyShare.Group == CurveSM2 {
		// 服务器选择了 SM2
		serverPubKey, err := ParseSM2PublicKey(serverKeyShare.KeyExchange)
		if err != nil {
			return fmt.Errorf("gmtls: failed to parse server SM2 public key: %v", err)
		}
		sm2PrivKey := c.tls13KeyMaterial.ClientPrivateShare.(*PrivateKey)

		// 计算 ECDH 共享密钥（x 坐标）
		ecdhSecret := DeriveSM2ECDHSharedSecret(sm2PrivKey, serverPubKey)

		// RFC 8998 Section 6.1: For SM2 cipher suites in TLS 1.3,
		// the ECDH shared secret is the x-coordinate of the shared point
		// represented as an octet string in big-endian order.
		// This is then used directly in TLS 1.3 key derivation (HKDF).
		sharedSecret = ecdhSecret

		debugf("DEBUG Using SM2 ECDH key exchange (secret_len=%d)\n", len(sharedSecret))
		debugf("DEBUG Shared secret: %02x\n", sharedSecret)
	} else {
		return fmt.Errorf("gmtls: server selected unsupported group 0x%04x", serverKeyShare.Group)
	}

	// DEBUG: 输出共享密钥
	debugf("DEBUG Shared secret: %02x\n", sharedSecret)

	// 保存共享密钥供后续密钥派生使用
	c.tls13KeyMaterial.SharedSecret = sharedSecret

	// 派生 TLS 1.3 密钥
	c.deriveTLS13Keys()

	// DEBUG: 输出 transcript hash
	clientHelloHash := c.clientHelloHash
	serverHelloHash := c.transcriptHash.Sum(nil)
	debugf("DEBUG ClientHello hash: %02x\n", clientHelloHash)
	debugf("DEBUG ServerHello hash (transcript): %02x\n", serverHelloHash)

	// 启用服务端握手流量解密
	// 从现在开始，服务端发送的所有记录都使用 ServerHandshakeTrafficSecret 加密
	c.serverEncrypted = true
	gcm, err := NewSM4GCMMode(c.tls13KeyMaterial.ServerHandshakeKey, c.tls13KeyMaterial.ServerHandshakeIV, false, true)
	if err != nil {
		return fmt.Errorf("gmtls: failed to create server cipher: %v", err)
	}
	c.in.cipher = gcm
	debugln("DEBUG: Enabled server handshake traffic decryption")

	return nil
}

// readEncryptedExtensions 读取 EncryptedExtensions
func (c *Conn) readEncryptedExtensions() error {
	msgBytes, err := c.readTLS13HandshakeMsg()
	if err != nil {
		return err
	}

	msg := new(encryptedExtensionsMsg)
	if err := msg.unmarshal(msgBytes); err != nil {
		return fmt.Errorf("gmtls: failed to unmarshal EncryptedExtensions: %v", err)
	}

	debugln("DEBUG: Successfully parsed EncryptedExtensions")
	for _, ext := range msg.Extensions {
		if ext.Type == extensionALPN {
			protocols, err := parseALPNExtension(ext.Data)
			if err != nil {
				return err
			}
			if len(protocols) == 1 {
				if len(c.peerProtos) > 0 && !containsString(c.peerProtos, protocols[0]) {
					return fmt.Errorf("gmtls: server selected unsupported ALPN protocol %q", protocols[0])
				}
				c.negotiatedProto = protocols[0]
			} else if len(protocols) > 1 {
				return errors.New("gmtls: invalid ALPN protocol list in EncryptedExtensions")
			}
		}
	}
	c.transcriptHash.Write(msgBytes)
	return nil
}

// readCertificateTLS13 读取 TLS 1.3 Certificate
func (c *Conn) readCertificateTLS13() error {
	for {
		msgBytes, err := c.readTLS13HandshakeMsg()
		if err != nil {
			return err
		}

		switch msgBytes[0] {
		case typeCertificateRequest:
			c.tls13ClientCertRequested = true
			ctx, err := parseCertificateRequestTLS13(msgBytes)
			if err != nil {
				return err
			}
			c.tls13CertReqContext = ctx
			c.transcriptHash.Write(msgBytes)
			continue
		case typeCertificate:
			cert, err := parseCertificateTLS13(msgBytes)
			if err != nil {
				return err
			}
			c.peerCert = cert

			debugln("DEBUG: Successfully parsed Certificate")
			c.transcriptHash.Write(msgBytes)
			return nil
		default:
			return fmt.Errorf("gmtls: unexpected handshake message %d while waiting for Certificate", msgBytes[0])
		}
	}
}

// readCertificateVerifyTLS13 读取 TLS 1.3 CertificateVerify
func (c *Conn) readCertificateVerifyTLS13() error {
	msgBytes, err := c.readTLS13HandshakeMsg()
	if err != nil {
		return err
	}

	// 解析 CertificateVerify
	msg := new(certificateVerifyMsg)
	if err := msg.unmarshal(msgBytes); err != nil {
		return err
	}
	debugf("DEBUG: CertificateVerify algorithm=0x%04x, sig_len=%d\n", msg.Algorithm, len(msg.Signature))

	// 验证签名
	transcriptHash := c.transcriptHash.Sum(nil)
	if debugEnabled {
		debugf("DEBUG: CertificateVerify transcript hash=%02x\n", transcriptHash)
		debugf("DEBUG: CertificateVerify SM2 cert ID=%q\n", sm2TLS13CertVerifyID())
	}

	var sig *Signature
	if len(msg.Signature) == 64 {
		r := new(big.Int).SetBytes(msg.Signature[:32])
		s := new(big.Int).SetBytes(msg.Signature[32:])
		sig = &Signature{R: r, S: s}
	} else {
		var derSig struct {
			R *big.Int
			S *big.Int
		}
		if _, err := asn1.Unmarshal(msg.Signature, &derSig); err != nil || derSig.R == nil || derSig.S == nil {
			return errors.New("gmtls: invalid signature length for SM2")
		}
		sig = &Signature{R: derSig.R, S: derSig.S}
	}

	if c.config != nil && c.config.InsecureSkipVerify {
		// skip verification for interop/debugging
	} else {
		// 使用对等方的公钥验证签名
		if c.peerCert == nil || c.peerCert.PublicKey == nil {
			return errors.New("gmtls: no peer certificate for signature verification")
		}
		context := []byte("TLS 1.3, server CertificateVerify")
		signed := make([]byte, 0, 64+len(context)+1+len(transcriptHash))
		signed = append(signed, bytes.Repeat([]byte{0x20}, 64)...)
		signed = append(signed, context...)
		signed = append(signed, 0x00)
		signed = append(signed, transcriptHash...)

		verifyWithPub := func(pub *PublicKey) (bool, error) {
			ok, err := sm2TLS13VerifyWithID(pub, signed, msg.Signature, sm2TLS13CertVerifyID())
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
			// Fallback: some servers sign SM3(msg) without ZA (non-standard).
			if VerifyMessageNoZA(pub, signed, sig) {
				c.tls13SM2NoZA = true
				return true, nil
			}
			// Fallback: ZA + SM3(Signed) (non-standard).
			signedHash := SM3(signed)
			if altOk, altErr := sm2TLS13VerifyWithID(pub, signedHash[:], msg.Signature, sm2TLS13CertVerifyID()); altErr != nil {
				return false, altErr
			} else if altOk {
				return true, nil
			}
			// Fallback: sign transcript hash directly (non-standard).
			if altOk, altErr := sm2TLS13VerifyWithID(pub, transcriptHash, msg.Signature, sm2TLS13CertVerifyID()); altErr != nil {
				return false, altErr
			} else if altOk {
				return true, nil
			}
			th := SM3(transcriptHash)
			if altOk, altErr := sm2TLS13VerifyWithID(pub, th[:], msg.Signature, sm2TLS13CertVerifyID()); altErr != nil {
				return false, altErr
			} else if altOk {
				return true, nil
			}
			if verifyHashNoZA(pub, transcriptHash, sig) {
				c.tls13SM2NoZA = true
				return true, nil
			}
			if verifyHashNoZA(pub, th[:], sig) {
				c.tls13SM2NoZA = true
				return true, nil
			}
			// Fallback: ECDSA over SM2 curve with SM3(signed) (no ZA).
			ecdsaPub := &ecdsa.PublicKey{Curve: SM2Curve, X: pub.X, Y: pub.Y}
			h := SM3(signed)
			if ecdsa.Verify(ecdsaPub, h[:], sig.R, sig.S) {
				return true, nil
			}
			// Fallback: ECDSA over SM2 curve with SM3(ZA||signed).
			za := sm2ComputeZA(sm2TLS13CertVerifyID(), pub)
			zaMsg := append(za, signed...)
			h2 := SM3(zaMsg)
			if ecdsa.Verify(ecdsaPub, h2[:], sig.R, sig.S) {
				return true, nil
			}
			return false, nil
		}

		valid, err := verifyWithPub(c.peerCert.PublicKey)
		if err != nil {
			return err
		}
		if !valid && len(c.peerCert.Chain) > 1 {
			for _, certDER := range c.peerCert.Chain {
				pub, err := ParseSM2PublicKeyFromCertificate(certDER)
				if err != nil {
					continue
				}
				if pub.X.Cmp(c.peerCert.PublicKey.X) == 0 && pub.Y.Cmp(c.peerCert.PublicKey.Y) == 0 {
					continue
				}
				ok, err := verifyWithPub(pub)
				if err != nil {
					return err
				}
				if ok {
					c.peerCert.PublicKey = pub
					valid = true
					break
				}
			}
		}
		if !valid {
			return errors.New("gmtls: CertificateVerify signature verification failed")
		}
	}

	debugln("DEBUG: Successfully verified CertificateVerify")
	c.transcriptHash.Write(msgBytes)
	return nil
}

// readFinishedTLS13 读取 TLS 1.3 Finished
func (c *Conn) readFinishedTLS13() error {
	msgBytes, err := c.readTLS13HandshakeMsg()
	if err != nil {
		return err
	}

	// 解析 Finished
	msg := new(finishedMsg)
	if err := msg.unmarshal(msgBytes); err != nil {
		return err
	}

	// 根据连接角色确定使用哪个密钥进行验证
	var verifyKey []byte
	if c.isClient {
		// 客户端验证服务端的Finished
		verifyKey = c.tls13KeyMaterial.ServerHandshakeTrafficSecret
	} else {
		// 服务端验证客户端的Finished
		verifyKey = c.tls13KeyMaterial.ClientHandshakeTrafficSecret
	}

	// 验证 verify_data
	if c.config != nil && c.config.InsecureSkipVerify {
		// skip verify_data check for interop/debugging
	} else {
		transcriptHash := c.transcriptHash.Sum(nil)
		finishedKey := DeriveFinishedKey(verifyKey)
		expectedVerifyData := VerifyDataTLS13(finishedKey, transcriptHash)
		if !bytes.Equal(msg.VerifyData, expectedVerifyData) {
			return errors.New("gmtls: Finished verify_data verification failed")
		}
	}

	debugln("DEBUG: Successfully verified Finished")

	// 更新 transcript hash
	c.transcriptHash.Write(msgBytes)
	// Save transcript hash after including server Finished (for app key derivation variants)
	if c.isClient {
		c.tls13ServerFinishedHash = append([]byte(nil), c.transcriptHash.Sum(nil)...)
	}

	// 启用对方的加密
	if c.isClient {
		// 客户端接收服务端的Finished后，启用服务端的加密
		c.serverEncrypted = true
		gcm, err := NewSM4GCMMode(c.tls13KeyMaterial.ServerHandshakeKey, c.tls13KeyMaterial.ServerHandshakeIV, false, true)
		if err != nil {
			return err
		}
		c.in.cipher = gcm
	} else {
		// 服务端接收客户端的Finished后，启用客户端的加密
		c.clientEncrypted = true
		gcm, err := NewSM4GCMMode(c.tls13KeyMaterial.ClientHandshakeKey, c.tls13KeyMaterial.ClientHandshakeIV, false, true)
		if err != nil {
			return err
		}
		c.in.cipher = gcm
	}

	return nil
}

// sendFinishedTLS13 发送 TLS 1.3 Finished
func (c *Conn) sendFinishedTLS13() error {
	// 计算 verify_data
	transcriptHash := c.transcriptHash.Sum(nil)
	verifyKey := c.tls13KeyMaterial.ClientHandshakeTrafficSecret
	if !c.isClient {
		verifyKey = c.tls13KeyMaterial.ServerHandshakeTrafficSecret
	}
	finishedKey := DeriveFinishedKey(verifyKey)
	verifyData := VerifyDataTLS13(finishedKey, transcriptHash)
	if debugEnabled {
		debugf("DEBUG: Client Finished transcript hash=%02x\n", transcriptHash)
		debugf("DEBUG: Client Finished verify_data=%02x\n", verifyData)
	}

	msg := &finishedMsg{
		VerifyData: verifyData,
	}

	data := msg.marshal()

	// 更新 transcript hash
	c.transcriptHash.Write(data)
	if !c.isClient {
		c.tls13ServerFinishedHash = append([]byte(nil), c.transcriptHash.Sum(nil)...)
	}

	// 启用客户端加密（若已启用则不要重置序列号）
	if !c.clientEncrypted || c.out.cipher == nil {
		gcm, err := NewSM4GCMMode(c.tls13KeyMaterial.ClientHandshakeKey, c.tls13KeyMaterial.ClientHandshakeIV, false, true)
		if err != nil {
			return err
		}
		c.out.cipher = gcm
		c.clientEncrypted = true
	}

	return c.writeRecord(recordTypeHandshake, data)
}

// setupApplicationTrafficKeys 设置应用流量密钥
func (c *Conn) setupApplicationTrafficKeys() {
	// 切换到应用流量密钥
	if c.tls13KeyMaterial == nil {
		return
	}

	if c.isClient {
		// 客户端：入站用服务端密钥，出站用客户端密钥
		inKey := c.tls13KeyMaterial.ServerAppKey
		inIV := c.tls13KeyMaterial.ServerAppIV
		outKey := c.tls13KeyMaterial.ClientAppKey
		outIV := c.tls13KeyMaterial.ClientAppIV

		gcmServer, err := NewSM4GCMMode(inKey, inIV, false, true)
		if err != nil {
			return
		}
		c.in.cipher = gcmServer
		if c.version >= VersionTLS13 {
			gcmServer.readSeq = 0
			gcmServer.writeSeq = 0
		}

		gcmClient, err := NewSM4GCMMode(outKey, outIV, false, true)
		if err != nil {
			return
		}
		c.out.cipher = gcmClient
		if c.version >= VersionTLS13 {
			gcmClient.readSeq = 0
			gcmClient.writeSeq = 0
		}
	} else {
		// 服务端：入站用客户端密钥，出站用服务端密钥
		inKey := c.tls13KeyMaterial.ClientAppKey
		inIV := c.tls13KeyMaterial.ClientAppIV
		outKey := c.tls13KeyMaterial.ServerAppKey
		outIV := c.tls13KeyMaterial.ServerAppIV

		gcmClient, err := NewSM4GCMMode(inKey, inIV, false, true)
		if err != nil {
			return
		}
		c.in.cipher = gcmClient
		if c.version >= VersionTLS13 {
			gcmClient.readSeq = 0
			gcmClient.writeSeq = 0
		}

		gcmServer, err := NewSM4GCMMode(outKey, outIV, false, true)
		if err != nil {
			return
		}
		c.out.cipher = gcmServer
		if c.version >= VersionTLS13 {
			gcmServer.readSeq = 0
			gcmServer.writeSeq = 0
		}
	}
}

// setupServerApplicationTrafficKeysForClient switches only inbound keys for a client
// to decrypt server application data sent right after Server Finished.
func (c *Conn) setupServerApplicationTrafficKeysForClient() {
	if !c.isClient || c.tls13KeyMaterial == nil {
		return
	}
	if len(c.tls13KeyMaterial.ServerAppKey) == 0 || len(c.tls13KeyMaterial.ServerAppIV) == 0 {
		return
	}
	gcmServer, err := NewSM4GCMMode(c.tls13KeyMaterial.ServerAppKey, c.tls13KeyMaterial.ServerAppIV, false, true)
	if err != nil {
		return
	}
	c.in.cipher = gcmServer
	if c.version >= VersionTLS13 {
		gcmServer.readSeq = 0
		gcmServer.writeSeq = 0
	}
}

// deriveTLS13ApplicationKeys 在握手完成后派生应用流量密钥
func (c *Conn) deriveTLS13ApplicationKeys() {
	if c.tls13KeyMaterial == nil || c.transcriptHash == nil {
		return
	}
	if len(c.tls13KeyMaterial.MasterSecret) == 0 {
		return
	}

	// TLS 1.3: application traffic secrets are derived from the transcript
	// hash up to (and including) server Finished, even if we are called after
	// client Finished was added to the transcript.
	serverFinishedHash := c.tls13ServerFinishedHash
	if len(serverFinishedHash) == 0 {
		serverFinishedHash = c.transcriptHash.Sum(nil)
	}
	clientFinishedHash := serverFinishedHash
	baseSecret := c.tls13KeyMaterial.MasterSecret
	c.tls13KeyMaterial.ClientAppTrafficSecret = DeriveSecret(baseSecret, tls13LabelClientTraffic, clientFinishedHash)
	c.tls13KeyMaterial.ServerAppTrafficSecret = DeriveSecret(baseSecret, tls13LabelServerTraffic, serverFinishedHash)

	c.tls13KeyMaterial.ClientAppKey, c.tls13KeyMaterial.ClientAppIV = DeriveTrafficKeys(
		c.tls13KeyMaterial.ClientAppTrafficSecret,
		[]byte("key"),
		c.cipherSuite.KeyLen,
		c.cipherSuite.IVLen,
	)
	c.tls13KeyMaterial.ServerAppKey, c.tls13KeyMaterial.ServerAppIV = DeriveTrafficKeys(
		c.tls13KeyMaterial.ServerAppTrafficSecret,
		[]byte("key"),
		c.cipherSuite.KeyLen,
		c.cipherSuite.IVLen,
	)

}

// deriveTLS13ServerAppKeys derives only server application traffic keys for a client.
func (c *Conn) deriveTLS13ServerAppKeys() {
	if !c.isClient || c.tls13KeyMaterial == nil || c.transcriptHash == nil {
		return
	}
	if len(c.tls13KeyMaterial.MasterSecret) == 0 {
		return
	}
	serverFinishedHash := c.transcriptHash.Sum(nil)
	if len(c.tls13ServerFinishedHash) > 0 {
		serverFinishedHash = c.tls13ServerFinishedHash
	}
	baseSecret := c.tls13KeyMaterial.MasterSecret
	c.tls13KeyMaterial.ServerAppTrafficSecret = DeriveSecret(baseSecret, tls13LabelServerTraffic, serverFinishedHash)

	c.tls13KeyMaterial.ServerAppKey, c.tls13KeyMaterial.ServerAppIV = DeriveTrafficKeys(
		c.tls13KeyMaterial.ServerAppTrafficSecret,
		[]byte("key"),
		c.cipherSuite.KeyLen,
		c.cipherSuite.IVLen,
	)
}

// deriveTLS13Keys 派生 TLS 1.3 密钥
func (c *Conn) deriveTLS13Keys() {
	// 使用 X25519 key_share 派生的共享密钥
	// sharedSecret 已经在 readServerHelloTLS13 中保存到 c.tls13KeyMaterial.SharedSecret
	if c.tls13KeyMaterial.SharedSecret == nil || len(c.tls13KeyMaterial.SharedSecret) == 0 {
		// 如果还没有共享密钥，这是错误的情况
		sharedSecret := make([]byte, 32)
		c.tls13KeyMaterial.SharedSecret = sharedSecret
	}

	// TLS 1.3 密钥派生需要:
	// - clientHelloHash = Hash(ClientHello)
	// - serverHelloHash = Hash(ClientHello || ServerHello)

	// 使用保存的 ClientHello 哈希
	clientHelloHash := c.clientHelloHash

	// transcript hash 此时包含: Hash(ClientHello || ServerHello)
	serverHelloHash := c.transcriptHash.Sum(nil)

	// 派生所有密钥
	km := DeriveAllKeys(c.cipherSuite, c.tls13KeyMaterial.SharedSecret, clientHelloHash, serverHelloHash, nil)
	km.SharedSecret = c.tls13KeyMaterial.SharedSecret
	c.tls13KeyMaterial = km

}

// ============= TLS 1.3 服务端握手 =============

func (c *Conn) serverHandshakeTLS13() error {
	// 初始化 transcript hash
	c.transcriptHash = NewSM3()

	// 接收 ClientHello
	if err := c.readClientHelloTLS13(); err != nil {
		return err
	}

	// 发送 ServerHello
	if err := c.sendServerHelloTLS13(); err != nil {
		return err
	}

	// 发送 EncryptedExtensions
	if err := c.sendEncryptedExtensions(); err != nil {
		return err
	}

	// 发送 Certificate
	if err := c.sendCertificateTLS13(); err != nil {
		return err
	}

	// 发送 CertificateVerify
	if err := c.sendCertificateVerifyTLS13(); err != nil {
		return err
	}

	// 发送 Finished
	if err := c.sendFinishedTLS13(); err != nil {
		return err
	}

	// 接收 Finished
	if err := c.readFinishedTLS13(); err != nil {
		return err
	}

	// 派生应用流量密钥（包含客户端 Finished）
	c.deriveTLS13ApplicationKeys()

	// 设置应用流量密钥
	c.setupApplicationTrafficKeys()

	c.handshakeComplete = true
	return nil
}

// readClientHelloTLS13 读取 TLS 1.3 ClientHello
func (c *Conn) readClientHelloTLS13() error {
	// 读取记录
	rec, err := c.readRecord()
	if err != nil {
		return err
	}

	if rec.Type != recordTypeHandshake {
		return errors.New("gmtls: expected handshake record")
	}

	// 更新 transcript hash
	c.transcriptHash.Write(rec.Data)

	// 保存 ClientHello 哈希（用于后续密钥派生）
	h := NewSM3()
	h.Write(rec.Data)
	c.clientHelloHash = h.Sum(nil)

	// 解析 ClientHello
	hello := new(clientHelloMsg)
	if err := hello.unmarshal(rec.Data); err != nil {
		return err
	}

	// 保存客户端随机数
	copy(c.clientRandom[:], hello.Random)
	c.tls13SessionID = hello.SessionID
	c.clientCipherSuites = append([]uint16(nil), hello.CipherSuites...)

	// 解析 TLS 1.3 扩展
	var keyShares []KeyShareEntry
	var supportedVersions []uint16
	for _, ext := range hello.Extensions {
		switch ext.Type {
		case extensionKeyShare:
			shares, err := parseKeyShareClientHello(ext.Data)
			if err != nil {
				return err
			}
			keyShares = shares
		case extensionSupportedCurves:
			curves, err := parseSupportedCurvesExtension(ext.Data)
			if err != nil {
				return err
			}
			c.clientSupportedCurves = curves
		case extensionSignatureAlgorithms:
			schemes, err := parseSignatureAlgorithmsExtension(ext.Data)
			if err != nil {
				return err
			}
			c.clientSigSchemes = schemes
		case extensionALPN:
			protocols, err := parseALPNExtension(ext.Data)
			if err != nil {
				return err
			}
			c.peerProtos = protocols
		case extensionSupportedVersions:
			vers, err := parseSupportedVersionsClientHello(ext.Data)
			if err != nil {
				return err
			}
			supportedVersions = vers
		}
	}
	if len(supportedVersions) == 0 || !containsUint16(supportedVersions, VersionTLS13) {
		return errors.New("gmtls: client does not support TLS 1.3")
	}
	if len(c.clientSigSchemes) > 0 && !supportsSM2Signature(c.clientSigSchemes) {
		return errors.New("gmtls: client does not support SM2 signature algorithms")
	}
	// 选择密码套件
	var serverSuites []uint16
	if c.config != nil && len(c.config.CipherSuites) > 0 {
		serverSuites = c.config.CipherSuites
	} else {
		serverSuites = []uint16{
			TLS_SM4_GCM_SM3_ALT,
			TLS_SM4_CCM_SM3_ALT,
			TLS_SM4_GCM_SM3,
			TLS_SM4_CCM_SM3,
		}
	}
	c.cipherSuite = selectCipherSuite(hello.CipherSuites, serverSuites, VersionTLS13, c.clientSupportedCurves, c.clientSigSchemes)
	if c.cipherSuite == nil {
		return errors.New("gmtls: no common cipher suite for TLS 1.3")
	}
	if len(keyShares) == 0 {
		return errors.New("gmtls: missing key_share extension in ClientHello")
	}

	// 选择首选的 key_share（优先 SM2，其次 X25519）
	for i := range keyShares {
		if keyShares[i].Group == CurveSM2 {
			c.tls13ClientKeyShare = &keyShares[i]
			break
		}
	}
	if c.tls13ClientKeyShare == nil {
		for i := range keyShares {
			if keyShares[i].Group == CurveX25519 {
				c.tls13ClientKeyShare = &keyShares[i]
				break
			}
		}
	}
	if c.tls13ClientKeyShare == nil {
		return errors.New("gmtls: no supported key_share found in ClientHello")
	}

	if c.config != nil && len(c.config.NextProtos) > 0 && len(c.peerProtos) > 0 {
		c.negotiatedProto = selectALPNProtocol(c.config.NextProtos, c.peerProtos)
	}

	return nil
}

// sendServerHelloTLS13 发送 TLS 1.3 ServerHello
func (c *Conn) sendServerHelloTLS13() error {
	// 生成服务端随机数
	if _, err := io.ReadFull(rand.Reader, c.serverRandom[:]); err != nil {
		return err
	}

	if c.tls13ClientKeyShare == nil {
		return errors.New("gmtls: missing client key_share")
	}

	// 生成服务端 key_share 并派生共享密钥
	var serverKeyShare KeyShareEntry
	var sharedSecret []byte
	switch c.tls13ClientKeyShare.Group {
	case CurveSM2:
		sm2PrivKey, sm2PubKey, err := GenerateSM2KeyPairForTLS13()
		if err != nil {
			return fmt.Errorf("gmtls: failed to generate SM2 key pair: %v", err)
		}
		serverKeyShare = KeyShareEntry{Group: CurveSM2, KeyExchange: sm2PubKey}
		clientPubKey, err := ParseSM2PublicKey(c.tls13ClientKeyShare.KeyExchange)
		if err != nil {
			return fmt.Errorf("gmtls: failed to parse client SM2 public key: %v", err)
		}
		sharedSecret = DeriveSM2ECDHSharedSecret(sm2PrivKey, clientPubKey)
		if c.tls13KeyMaterial == nil {
			c.tls13KeyMaterial = &TLS13KeyMaterial{}
		}
		c.tls13KeyMaterial.ClientPrivateShare = sm2PrivKey
	case CurveX25519:
		privKey, pubKey, err := GenerateX25519Key()
		if err != nil {
			return fmt.Errorf("gmtls: failed to generate X25519 key pair: %v", err)
		}
		serverKeyShare = KeyShareEntry{Group: CurveX25519, KeyExchange: pubKey}
		sharedSecret, err = DeriveX25519SharedSecret(privKey, c.tls13ClientKeyShare.KeyExchange)
		if err != nil {
			return fmt.Errorf("gmtls: failed to derive X25519 shared secret: %v", err)
		}
		if c.tls13KeyMaterial == nil {
			c.tls13KeyMaterial = &TLS13KeyMaterial{}
		}
		c.tls13KeyMaterial.ClientX25519PrivateKey = privKey
	default:
		return fmt.Errorf("gmtls: unsupported key_share group 0x%04x", c.tls13ClientKeyShare.Group)
	}

	c.tls13KeyMaterial.SharedSecret = sharedSecret
	c.tls13KeyMaterial.ServerPublicShare = serverKeyShare.KeyExchange

	// 构造 ServerHello 扩展
	extensions := []Extension{
		{
			Type: extensionSupportedVersions,
			Data: []byte{0x03, 0x04}, // TLS 1.3
		},
		marshalKeyShareExtension([]KeyShareEntry{serverKeyShare}),
	}

	// 构造 ServerHello
	hello := &serverHelloMsg{
		Version:     VersionTLS12, // ServerHello.version 必须是 TLS 1.2
		Random:      c.serverRandom[:],
		SessionID:   c.tls13SessionID,
		CipherSuite: c.cipherSuite.ID,
		Extensions:  extensions,
	}

	// 序列化
	data := hello.marshal()

	// 更新 transcript hash
	c.transcriptHash.Write(data)

	// 作为握手记录发送
	err := c.writeRecord(recordTypeHandshake, data)
	if err != nil {
		return err
	}

	// 派生 TLS 1.3 密钥
	c.deriveTLS13Keys()

	return nil
}

// sendEncryptedExtensions 发送 EncryptedExtensions
func (c *Conn) sendEncryptedExtensions() error {
	// 构造 EncryptedExtensions 消息
	var extensions []Extension
	if c.negotiatedProto != "" {
		extensions = append(extensions, marshalALPNExtension([]string{c.negotiatedProto}))
	}
	msg := &encryptedExtensionsMsg{
		Extensions: extensions,
	}

	// 序列化
	data := msg.marshal()

	// 更新 transcript hash
	c.transcriptHash.Write(data)

	// 作为握手记录发送
	return c.writeRecord(recordTypeHandshake, data)
}

// sendCertificateTLS13 发送 TLS 1.3 Certificate
func (c *Conn) sendCertificateTLS13() error {
	if c.localCert == nil {
		return errors.New("gmtls: missing client certificate")
	}
	if debugEnabled {
		chainLen := len(c.localCert.Chain)
		debugf("DEBUG: Sending client Certificate (chain entries=%d, raw_len=%d)\n", chainLen, len(c.localCert.Raw))
	}
	data := marshalCertificateTLS13(c.localCert, c.tls13CertReqContext)

	// 更新 transcript hash
	c.transcriptHash.Write(data)

	// 作为握手记录发送
	return c.writeRecord(recordTypeHandshake, data)
}

// sendCertificateVerifyTLS13 发送 TLS 1.3 CertificateVerify
func (c *Conn) sendCertificateVerifyTLS13() error {
	// 计算 transcript hash
	transcriptHash := c.transcriptHash.Sum(nil)

	// 计算待签名的数据（TLS 1.3 格式）
	context := []byte("TLS 1.3, client CertificateVerify")
	signed := make([]byte, 0, 64+len(context)+1+len(transcriptHash))
	signed = append(signed, bytes.Repeat([]byte{0x20}, 64)...)
	signed = append(signed, context...)
	signed = append(signed, 0x00)
	signed = append(signed, transcriptHash...)
	if debugEnabled {
		debugf("DEBUG: Client CertificateVerify transcript hash=%02x\n", transcriptHash)
		debugf("DEBUG: Client CertificateVerify signed (len=%d)=%02x\n", len(signed), signed)
		debugf("DEBUG: Client CertificateVerify SM2 cert ID=%q\n", sm2TLS13HandshakeID())
	}

	// 使用本地私钥对原始消息签名
	var signatureBytes []byte
	var err error
	uid := sm2TLS13HandshakeID()
	signatureBytes, err = sm2TLS13SignWithID(c.localPriv, signed, false, uid)
	if err != nil {
		return err
	}

	// 构造 CertificateVerify 消息
	msg := &certificateVerifyMsg{
		Algorithm: SM2SM3, // SM2 with SM3 签名算法 (TLS 1.3)
		Signature: signatureBytes,
	}
	if debugEnabled {
		debugf("DEBUG: Client CertificateVerify signature (len=%d)=%02x\n", len(signatureBytes), signatureBytes)
	}

	// 序列化
	data := msg.marshal()

	// 更新 transcript hash
	c.transcriptHash.Write(data)

	// 作为握手记录发送
	return c.writeRecord(recordTypeHandshake, data)
}

// ============= 连接状态查询方法 =============

// ConnectionState 返回 TLS 连接状态信息
func (c *Conn) ConnectionState() ConnectionState {
	return ConnectionState{
		Version:           c.version,
		CipherSuite:       c.cipherSuite.ID,
		NegotiatedProto:   c.negotiatedProto,
		ServerName:        c.serverName,
		PeerCertificates:  []*Certificate{c.peerCert},
		HandshakeComplete: c.handshakeComplete,
	}
}

// ConnectionState TLS 连接状态
type ConnectionState struct {
	Version           uint16         // TLS 版本
	CipherSuite       uint16         // 密码套件 ID
	NegotiatedProto   string         // ALPN 协商的协议
	ServerName        string         // SNI 服务器名称
	PeerCertificates  []*Certificate // 对等方证书链
	HandshakeComplete bool           // 握手是否完成
}

// GetConnectionState 返回连接状态（替代方法）
func (c *Conn) GetConnectionState() ConnectionState {
	return c.ConnectionState()
}
