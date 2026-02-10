package gmtls

import (
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
		PrivateKey:         c.PrivateKey,
		SignPrivateKey:     c.SignPrivateKey,
		EncPrivateKey:      c.EncPrivateKey,
		InsecureSkipVerify: c.InsecureSkipVerify,
		RequireClientCert:  c.RequireClientCert,
		MinVersion:         c.MinVersion,
		MaxVersion:         c.MaxVersion,
		RootCAs:            c.RootCAs,
		ClientCAs:          c.ClientCAs,
		ServerName:         c.ServerName,
		OnNewSessionTicket: c.OnNewSessionTicket,
		SessionTicketLimit: c.SessionTicketLimit,
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
