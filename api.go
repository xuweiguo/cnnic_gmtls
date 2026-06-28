package gmtls

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Dial connects to the given address and performs a GMTLS handshake.
func Dial(network, addr string, config *Config) (*Conn, error) {
	var d net.Dialer
	return DialWithDialer(&d, network, addr, config)
}

// DialWithDialer connects using d and performs a GMTLS handshake.
func DialWithDialer(d *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	cfg := config.Clone()
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	conn, err := d.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c, err := Client(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// Listen creates a GMTLS listener on the given network/address.
func Listen(network, addr string, config *Config) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln, config), nil
}

// NewListener wraps an existing net.Listener with GMTLS.
func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{inner: inner, config: config}
}

// Handshake performs a GMTLS handshake if it has not already completed.
func (c *Conn) Handshake() error {
	if c == nil {
		return nil
	}
	if c.handshakeComplete {
		return nil
	}
	if c.isClient {
		return c.clientHandshake()
	}
	return c.serverHandshake()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

// SetDeadline sets both read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.SetWriteDeadline(t)
}

type listener struct {
	inner  net.Listener
	config *Config
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	conn, err := Server(c, l.config)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return conn, nil
}

func (l *listener) Close() error {
	return l.inner.Close()
}

func (l *listener) Addr() net.Addr {
	return l.inner.Addr()
}

// Clone returns a shallow copy of the config with copied slices.
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}
	cc := Config{
		PrivateKey:           c.PrivateKey,
		SignPrivateKey:       c.SignPrivateKey,
		EncPrivateKey:        c.EncPrivateKey,
		InsecureSkipVerify:   c.InsecureSkipVerify,
		SkipServerNameVerify: c.SkipServerNameVerify,
		RequireClientCert:    c.RequireClientCert,
		MinVersion:           c.MinVersion,
		MaxVersion:           c.MaxVersion,
		RootCAs:              c.RootCAs,
		ClientCAs:            c.ClientCAs,
		ServerName:           c.ServerName,
		OnNewSessionTicket:   c.OnNewSessionTicket,
		SessionTicketLimit:   c.SessionTicketLimit,
	}
	if c.CipherSuites != nil {
		cc.CipherSuites = append([]uint16(nil), c.CipherSuites...)
	}
	if c.Certificates != nil {
		cc.Certificates = append([]*Certificate(nil), c.Certificates...)
	}
	if c.SignCertificates != nil {
		cc.SignCertificates = append([]*Certificate(nil), c.SignCertificates...)
	}
	if c.EncCertificates != nil {
		cc.EncCertificates = append([]*Certificate(nil), c.EncCertificates...)
	}
	if c.NextProtos != nil {
		cc.NextProtos = append([]string(nil), c.NextProtos...)
	}
	if c.SessionTickets != nil {
		cc.SessionTickets = make([]TLS13SessionTicket, len(c.SessionTickets))
		for i, t := range c.SessionTickets {
			cc.SessionTickets[i] = t
			if t.Nonce != nil {
				cc.SessionTickets[i].Nonce = append([]byte(nil), t.Nonce...)
			}
			if t.Ticket != nil {
				cc.SessionTickets[i].Ticket = append([]byte(nil), t.Ticket...)
			}
			if t.PSK != nil {
				cc.SessionTickets[i].PSK = append([]byte(nil), t.PSK...)
			}
		}
	}
	cc.sessionTicketsMu = sync.Mutex{}
	return &cc
}

// ============= 便利 API(基于 CNNIC EPP 实战经验)=============

// LoadGMKeyPair 一次性加载 SM2 客户端证书与加密私钥,便于双向认证。
// crtPath 的 PEM 文件可含完整证书链(leaf+中间+根),Chain 字段会自动填充。
// keyPath 为加密的 SM2 私钥,keyPassword 为其口令。
func LoadGMKeyPair(crtPath, keyPath, keyPassword string) (*Certificate, *PrivateKey, error) {
	cert, err := LoadCertificateFromPEM(crtPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := LoadSM2PrivateKeyFromPEM(keyPath, keyPassword)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// GMClientOptions 是构建 GM TLS 客户端 Config 的便利选项。
// 设计上覆盖 CNNIC EPP 这类场景:双向客户端证书 + 自签 CA 严格校验 +
// 服务器证书 CN 为通用名(无 SAN)时跳过主机名校验。
type GMClientOptions struct {
	// ServerName 用作 SNI。EPP 服务器证书 CN 为通用名(非域名)时可留空,
	// 配合 SkipServerNameVerify=true 跳过主机名校验。
	ServerName string

	// 客户端证书与私钥(双向认证)。CertPath 为空则不带客户端证书。
	CertPath    string
	KeyPath     string
	KeyPassword string

	// RootCAsPath 为 CA(PEM)文件路径,用于严格校验服务器证书链。
	// 为空时不设置 RootCAs(回退到系统证书池)。
	RootCAsPath string

	// SkipServerNameVerify 跳过证书 DNSName/SAN 校验。
	// 服务器证书 CN 为通用名(如 CNNIC EPP 的 CN=server)且无 SAN 时需要。
	SkipServerNameVerify bool

	// InsecureSkipVerify 跳过全部服务器证书校验,仅用于调试/互通排查。
	InsecureSkipVerify bool

	// MinVersion/MaxVersion 限定 TLS 版本,默认由 Config 自身默认值决定。
	MinVersion uint16
	MaxVersion uint16
}

// GMClientConfig 按选项构建一个安全可用的 GM TLS 客户端 Config,
// 封装证书/私钥/CA 加载与校验开关,避免调用方手写并误用 InsecureSkipVerify。
//
// 调用方随后用 gmtls.Dial("tcp", host, cfg) 即可建立严格校验的国密 TLS 连接。
// 典型用法见 cmd/internal/eppclient 与 README。
func GMClientConfig(opts GMClientOptions) (*Config, error) {
	cfg := &Config{
		ServerName:           opts.ServerName,
		InsecureSkipVerify:   opts.InsecureSkipVerify,
		SkipServerNameVerify: opts.SkipServerNameVerify,
		MinVersion:           opts.MinVersion,
		MaxVersion:           opts.MaxVersion,
	}

	// 加载并设置客户端证书与私钥(双向认证)。
	if opts.CertPath != "" || opts.KeyPath != "" {
		if opts.CertPath == "" || opts.KeyPath == "" {
			return nil, errors.New("gmtls: GMClientConfig requires both CertPath and KeyPath")
		}
		cert, key, err := LoadGMKeyPair(opts.CertPath, opts.KeyPath, opts.KeyPassword)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []*Certificate{cert}
		cfg.PrivateKey = key
		cfg.SignCertificates = []*Certificate{cert}
		cfg.SignPrivateKey = key
	}

	// 加载 CA 池用于严格校验服务器证书链。
	if opts.RootCAsPath != "" {
		pool, err := LoadCertPoolFromPEM(opts.RootCAsPath)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	return cfg, nil
}
