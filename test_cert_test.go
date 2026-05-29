package gmtls

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

func newTestSM2Certificate(t *testing.T) (*Certificate, *PrivateKey) {
	t.Helper()

	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sm2Priv, err := sm2GMSMPrivateKey(priv)
	if err != nil {
		t.Fatalf("sm2GMSMPrivateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{"localhost", "example.cn"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    smx509.SM2WithSM3,
	}

	der, err := smx509.CreateCertificate(rand.Reader, template, template, sm2Priv.Public(), sm2Priv)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return &Certificate{Raw: der, Chain: [][]byte{der}, PublicKey: pub}, priv
}
