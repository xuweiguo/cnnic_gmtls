package gmtls

import (
	"bytes"
	"errors"
)

// LoadX509KeyPair loads a certificate and private key from PEM files.
// The private key must be unencrypted, matching crypto/tls behavior.
func LoadX509KeyPair(certFile, keyFile string) (*Certificate, *PrivateKey, error) {
	return LoadX509KeyPairWithPassword(certFile, keyFile, "")
}

// LoadX509KeyPairWithPassword loads a certificate and private key from PEM files.
// Provide a password for encrypted PEM keys.
func LoadX509KeyPairWithPassword(certFile, keyFile, password string) (*Certificate, *PrivateKey, error) {
	cert, err := LoadCertificateFromPEM(certFile)
	if err != nil {
		return nil, nil, err
	}
	key, err := LoadSM2PrivateKeyFromPEM(keyFile, password)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// X509KeyPair parses a certificate and private key from PEM data.
// The private key must be unencrypted, matching crypto/tls behavior.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (*Certificate, *PrivateKey, error) {
	return X509KeyPairWithPassword(certPEMBlock, keyPEMBlock, "")
}

// X509KeyPairWithPassword parses a certificate and private key from PEM data.
// Provide a password for encrypted PEM keys.
func X509KeyPairWithPassword(certPEMBlock, keyPEMBlock []byte, password string) (*Certificate, *PrivateKey, error) {
	certs, err := parseCertificatesFromPEMBytes(certPEMBlock)
	if err != nil {
		return nil, nil, err
	}
	cert := &Certificate{Raw: certs[0], Chain: certs}
	if pub, err := ParseSM2PublicKeyFromCertificate(certs[0]); err == nil {
		cert.PublicKey = pub
	}
	key, err := LoadSM2PrivateKeyFromReader(bytes.NewReader(keyPEMBlock), password)
	if err != nil {
		return nil, nil, err
	}
	if key == nil {
		return nil, nil, errors.New("gmtls: failed to parse private key")
	}
	return cert, key, nil
}
