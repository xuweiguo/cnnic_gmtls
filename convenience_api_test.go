package gmtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

// writeClientPEM 把 SM2 客户端证书和加密私钥写成 PEM 文件。
func writeClientPEM(t *testing.T, certDER []byte, key *PrivateKey, dir string) (string, string) {
	t.Helper()
	crtPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")

	if err := os.WriteFile(crtPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		t.Fatalf("write crt: %v", err)
	}
	sm2Priv, err := sm2GMSMPrivateKey(key)
	if err != nil {
		t.Fatalf("sm2 priv: %v", err)
	}
	keyDER, err := smx509.MarshalSM2PrivateKey(sm2Priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	encBlock, err := smx509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", keyDER, []byte("testpw"), smx509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(encBlock), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return crtPath, keyPath
}

// newTestCAAndClientPEM 生成自签 CA + CA 签发的客户端证书,均写成 PEM 文件,
// 用于 LoadGMKeyPair / GMClientConfig 测试。返回 caPath/crtPath/keyPath。
func newTestCAAndClientPEM(t *testing.T) (caPath, crtPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	caPriv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey CA: %v", err)
	}
	caSm2, err := sm2GMSMPrivateKey(caPriv)
	if err != nil {
		t.Fatalf("sm2 CA: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}
	caDER, err := smx509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caSm2.Public(), caSm2)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	caPath = filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	clientPriv, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey client: %v", err)
	}
	clientSm2, err := sm2GMSMPrivateKey(clientPriv)
	if err != nil {
		t.Fatalf("sm2 client: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "client"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1")},
		SignatureAlgorithm: smx509.SM2WithSM3,
	}
	clientDER, err := smx509.CreateCertificate(rand.Reader, clientTmpl, caTmpl, clientSm2.Public(), caSm2)
	if err != nil {
		t.Fatalf("CreateCertificate client: %v", err)
	}
	crtPath, keyPath = writeClientPEM(t, clientDER, clientPriv, dir)
	return caPath, crtPath, keyPath
}

// TestLoadGMKeyPair 验证 LoadGMKeyPair 能加载 PEM 证书+加密私钥。
func TestLoadGMKeyPair(t *testing.T) {
	_, crtPath, keyPath := newTestCAAndClientPEM(t)

	cert, key, err := LoadGMKeyPair(crtPath, keyPath, "testpw")
	if err != nil {
		t.Fatalf("LoadGMKeyPair error: %v", err)
	}
	if cert == nil || len(cert.Raw) == 0 {
		t.Fatal("cert not loaded")
	}
	if key == nil || key.D == nil {
		t.Fatal("key not loaded")
	}
	// 错误口令应失败。
	if _, _, err := LoadGMKeyPair(crtPath, keyPath, "wrongpw"); err == nil {
		t.Fatal("LoadGMKeyPair should fail with wrong password")
	}
}

// TestGMClientConfig 验证 GMClientConfig 构建的 Config 字段正确。
func TestGMClientConfig(t *testing.T) {
	caPath, crtPath, keyPath := newTestCAAndClientPEM(t)

	cfg, err := GMClientConfig(GMClientOptions{
		ServerName:           "epp.example.cn",
		CertPath:             crtPath,
		KeyPath:              keyPath,
		KeyPassword:          "testpw",
		RootCAsPath:          caPath,
		SkipServerNameVerify: true,
	})
	if err != nil {
		t.Fatalf("GMClientConfig error: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be false by default")
	}
	if !cfg.SkipServerNameVerify {
		t.Fatal("SkipServerNameVerify should be true")
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs should be loaded")
	}
	if len(cfg.Certificates) != 1 || cfg.PrivateKey == nil {
		t.Fatal("client cert/key not configured")
	}
	if cfg.ServerName != "epp.example.cn" {
		t.Fatalf("ServerName = %q", cfg.ServerName)
	}
}

// TestGMClientConfigErrors 验证选项校验。
func TestGMClientConfigErrors(t *testing.T) {
	_, crtPath, keyPath := newTestCAAndClientPEM(t)

	// 只给证书不给私钥应报错。
	if _, err := GMClientConfig(GMClientOptions{CertPath: crtPath}); err == nil {
		t.Fatal("should error when only CertPath given")
	}
	// 根 CA 路径不存在应报错。
	if _, err := GMClientConfig(GMClientOptions{RootCAsPath: crtPath + ".nope"}); err == nil {
		t.Fatal("should error on missing RootCAsPath")
	}
	// 私钥口令错误应报错。
	if _, err := GMClientConfig(GMClientOptions{CertPath: crtPath, KeyPath: keyPath, KeyPassword: "wrong"}); err == nil {
		t.Fatal("should error on wrong key password")
	}
}
