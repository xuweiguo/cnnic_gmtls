package gmtls

import "testing"

func TestVerifyPeerCertificateMissing(t *testing.T) {
	c := &Conn{}
	if err := c.verifyPeerCertificate(nil, nil, 0, ""); err == nil {
		t.Fatalf("expected error for missing certificate")
	}
}

func TestVerifyServerCertificateNilConfigDoesNotPanic(t *testing.T) {
	cert, err := LoadCertificateFromPEM("cnnic/gm/xmnw.crt")
	if err != nil {
		t.Fatalf("LoadCertificateFromPEM() error = %v", err)
	}

	c := &Conn{clientServerName: "example.cn"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("verifyServerCertificate panicked: %v", r)
		}
	}()
	_ = c.verifyServerCertificate(cert)
}

func TestVerifyClientCertificateNilConfigDoesNotPanic(t *testing.T) {
	cert, err := LoadCertificateFromPEM("cnnic/gm/xmnw.crt")
	if err != nil {
		t.Fatalf("LoadCertificateFromPEM() error = %v", err)
	}

	c := &Conn{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("verifyClientCertificate panicked: %v", r)
		}
	}()
	_ = c.verifyClientCertificate(cert)
}
