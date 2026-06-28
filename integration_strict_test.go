package gmtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

// newTestSM2CAAndLeaf 生成一个自签 CA 和由该 CA 签发的服务器叶子证书。
// 服务器证书 CN 为通用名(无 SAN),模拟 CNNIC EPP 服务器证书的形态。
func newTestSM2CAAndLeaf(t *testing.T) (*smx509.CertPool, *Certificate, *PrivateKey) {
	t.Helper()

	// 自签 CA。
	caPriv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() CA error = %v", err)
	}
	caSm2Priv, err := sm2GMSMPrivateKey(caPriv)
	if err != nil {
		t.Fatalf("sm2GMSMPrivateKey() CA error = %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caSm2Priv.Public(), caSm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate() CA error = %v", err)
	}
	caCert, err := smx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate() CA error = %v", err)
	}
	pool := smx509.NewCertPool()
	pool.AddCert(caCert)

	// 由 CA 签发的叶子证书(CN=server,无 SAN)。
	leafPriv, leafPub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() leaf error = %v", err)
	}
	leafSm2Priv, err := sm2GMSMPrivateKey(leafPriv)
	if err != nil {
		t.Fatalf("sm2GMSMPrivateKey() leaf error = %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(101),
		Subject:            pkix.Name{CommonName: "server"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1")},
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	leafDER, err := smx509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, leafSm2Priv.Public(), caSm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate() leaf error = %v", err)
	}

	cert := &Certificate{Raw: leafDER, Chain: [][]byte{leafDER}, PublicKey: leafPub}
	return pool, cert, leafPriv
}

// TestTLS13StrictHandshake 严格校验端到端:InsecureSkipVerify=false,用 RootCAs 验证
// 服务器证书链,SkipServerNameVerify 跳过主机名,并用 HANDSHAKE ID 验证服务器
// CertificateVerify。这是 CNNIC 严格模式的回归基线。
func TestTLS13StrictHandshake(t *testing.T) {
	roots, cert, key := newTestSM2CAAndLeaf(t)

	srvCfg := &Config{
		SignCertificates: []*Certificate{cert},
		SignPrivateKey:   key,
		MinVersion:       VersionTLS13,
		MaxVersion:       VersionTLS13,
	}

	ln, err := Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- fmt.Errorf("accept failed: %w", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			srvErr <- fmt.Errorf("server read failed: %w", err)
			return
		}
		srvErr <- nil
	}()

	clientCfg := &Config{
		InsecureSkipVerify:   false,
		SkipServerNameVerify: true,
		RootCAs:              roots,
		MinVersion:           VersionTLS13,
		MaxVersion:           VersionTLS13,
		ServerName:           "srs.ote.cnnic.cn", // 故意填真实域名,验证被跳过
	}
	client, err := Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial() with strict verify error = %v", err)
	}
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	state := client.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatalf("strict handshake not complete")
	}
	if state.Version != VersionTLS13 {
		t.Fatalf("version = 0x%04x, want 0x%04x", state.Version, VersionTLS13)
	}
	if _, err := client.Write([]byte("ping!")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server side timeout")
	}
}

// TestTLS13StrictHandshakeFailsWithoutRoot 严格模式下不配 RootCAs 必须握手失败,
// 确保不会误判证书链校验通过。
func TestTLS13StrictHandshakeFailsWithoutRoot(t *testing.T) {
	_, cert, key := newTestSM2CAAndLeaf(t)

	srvCfg := &Config{
		SignCertificates: []*Certificate{cert},
		SignPrivateKey:   key,
		MinVersion:       VersionTLS13,
		MaxVersion:       VersionTLS13,
	}

	ln, err := Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 5)
		_, _ = io.ReadFull(conn, buf)
	}()

	// 不配 RootCAs,严格模式应失败(系统证书池里没有自签 CA)。
	clientCfg := &Config{
		InsecureSkipVerify:   false,
		SkipServerNameVerify: true,
		MinVersion:           VersionTLS13,
		MaxVersion:           VersionTLS13,
		ServerName:           "127.0.0.1",
	}
	client, err := Dial("tcp", ln.Addr().String(), clientCfg)
	if err == nil {
		client.Close()
		t.Fatalf("Dial() should fail without RootCAs in strict mode")
	}
}
