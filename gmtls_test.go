package gmtls

import (
	"os"
	"testing"
	"time"
)

const testKeyPassword = "xmnwxmnw"

func loadTestCert(t *testing.T) (*Certificate, *PrivateKey) {
	t.Helper()
	certPath := "cnnic/gm/xmnw.crt"
	keyPath := "cnnic/gm/xmnw.key"
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("missing test cert: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("missing test key: %v", err)
	}
	cert, key, err := LoadX509KeyPairWithPassword(certPath, keyPath, testKeyPassword)
	if err != nil {
		t.Fatalf("LoadX509KeyPair failed: %v", err)
	}
	if cert == nil || key == nil || key.D == nil {
		t.Fatalf("invalid keypair loaded")
	}
	return cert, key
}

func TestLoadX509KeyPair(t *testing.T) {
	_, _, err := LoadX509KeyPair("cnnic/gm/xmnw.crt", "cnnic/gm/xmnw.key")
	if err == nil {
		t.Fatalf("expected error for encrypted key without password")
	}
	_, _, err = LoadX509KeyPairWithPassword("cnnic/gm/xmnw.crt", "cnnic/gm/xmnw.key", testKeyPassword)
	if err != nil {
		t.Fatalf("LoadX509KeyPairWithPassword failed: %v", err)
	}
}

func TestX509KeyPair(t *testing.T) {
	certPath := "cnnic/gm/xmnw.crt"
	keyPath := "cnnic/gm/xmnw.key"
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	_, _, err = X509KeyPair(certPEM, keyPEM)
	if err == nil {
		t.Fatalf("expected error for encrypted key without password")
	}
	cert, key, err := X509KeyPairWithPassword(certPEM, keyPEM, testKeyPassword)
	if err != nil {
		t.Fatalf("X509KeyPair failed: %v", err)
	}
	if cert == nil || len(cert.Chain) == 0 || key == nil || key.D == nil {
		t.Fatalf("invalid cert/key parsed")
	}
}

func TestKeyMatchesCert(t *testing.T) {
	cert, key := loadTestCert(t)
	if cert.PublicKey == nil {
		t.Fatalf("certificate public key is nil")
	}
	pub := key.Public()
	if pub.X.Cmp(cert.PublicKey.X) != 0 || pub.Y.Cmp(cert.PublicKey.Y) != 0 {
		t.Fatalf("private key does not match certificate public key")
	}
}

func TestConfigClone(t *testing.T) {
	cert, _ := loadTestCert(t)
	cfg := &Config{
		CipherSuites:     []uint16{1, 2},
		Certificates:     []*Certificate{cert},
		SignCertificates: []*Certificate{cert},
		EncCertificates:  []*Certificate{cert},
		NextProtos:       []string{"h2"},
		SessionTickets:   []TLS13SessionTicket{{Lifetime: 1, Ticket: []byte{1}}},
	}
	clone := cfg.Clone()
	if clone == cfg {
		t.Fatalf("Clone returned same pointer")
	}
	cfg.CipherSuites[0] = 99
	cfg.NextProtos[0] = "h1"
	cfg.SessionTickets[0].Ticket[0] = 9
	if clone.CipherSuites[0] == 99 {
		t.Fatalf("CipherSuites not copied")
	}
	if clone.NextProtos[0] == "h1" {
		t.Fatalf("NextProtos not copied")
	}
	if clone.SessionTickets[0].Ticket[0] == 9 {
		t.Fatalf("SessionTickets not copied")
	}
}

func TestSessionTicketsCopy(t *testing.T) {
	c := &Conn{tls13Tickets: []TLS13SessionTicket{{Lifetime: 1, Ticket: []byte{1}, Nonce: []byte{2}, PSK: []byte{3}}}}
	out := c.SessionTickets()
	if len(out) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(out))
	}
	out[0].Ticket[0] = 9
	out[0].Nonce[0] = 8
	out[0].PSK[0] = 7
	if c.tls13Tickets[0].Ticket[0] != 1 || c.tls13Tickets[0].Nonce[0] != 2 || c.tls13Tickets[0].PSK[0] != 3 {
		t.Fatalf("SessionTickets should return a copy")
	}
}

func TestListenDial(t *testing.T) {
	cert, key := loadTestCert(t)
	serverCfg := &Config{
		Certificates: []*Certificate{cert},
		PrivateKey:   key,
		MinVersion:   VersionTLS12,
		MaxVersion:   VersionTLS12,
		CipherSuites: []uint16{TLS_SM2_WITH_SM4_GCM_SM3},
	}
	ln, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Write(buf[:n])
		serverErr <- err
	}()

	clientCfg := &Config{
		MinVersion:   VersionTLS12,
		MaxVersion:   VersionTLS12,
		CipherSuites: []uint16{TLS_SM2_WITH_SM4_GCM_SM3},
	}
	client, err := Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		select {
		case serr := <-serverErr:
			t.Fatalf("Dial failed: %v (server error: %v)", err, serr)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("Dial failed: %v", err)
		}
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	msg := []byte("ping")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := client.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	} else if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected reply: %q", string(buf[:n]))
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestListenDialSM2DHEClientAuth(t *testing.T) {
	cert, key := loadTestCert(t)
	serverCfg := &Config{
		Certificates: []*Certificate{cert},
		PrivateKey:   key,
		ClientAuth:   true,
		MinVersion:   VersionTLS12,
		MaxVersion:   VersionTLS12,
		CipherSuites: []uint16{TLS_SM2DHE_WITH_SM4_GCM_SM3},
	}
	ln, err := Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = conn.Write(buf[:n])
		serverErr <- err
	}()

	clientCfg := &Config{
		Certificates: []*Certificate{cert},
		PrivateKey:   key,
		MinVersion:   VersionTLS12,
		MaxVersion:   VersionTLS12,
		CipherSuites: []uint16{TLS_SM2DHE_WITH_SM4_GCM_SM3},
	}
	client, err := Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		select {
		case serr := <-serverErr:
			t.Fatalf("Dial failed: %v (server error: %v)", err, serr)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("Dial failed: %v", err)
		}
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	msg := []byte("ping")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := client.Read(buf); err != nil {
		t.Fatalf("client read: %v", err)
	} else if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected reply: %q", string(buf[:n]))
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
