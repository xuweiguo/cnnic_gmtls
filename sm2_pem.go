package gmtls

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"

	"github.com/emmansun/gmsm/smx509"
)

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func isEncryptedPEMBlock(block *pem.Block) bool {
	if block == nil {
		return false
	}
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return true
	}
	if block.Headers["DEK-Info"] != "" {
		return true
	}
	return false
}

func LoadCertificateFromPEM(path string) (*Certificate, error) {
	certs, err := LoadCertificatesFromPEM(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("gmtls: no certificates found in PEM")
	}
	cert := &Certificate{Raw: certs[0], Chain: certs}
	if pub, err := ParseSM2PublicKeyFromCertificate(certs[0]); err == nil {
		cert.PublicKey = pub
	}
	return cert, nil
}

// LoadCertificatesFromPEM loads all CERTIFICATE blocks from a PEM file.
func LoadCertificatesFromPEM(path string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCertificatesFromPEMBytes(b)
}

// LoadCertPoolFromPEM loads a PEM file into a new SM2-capable cert pool.
func LoadCertPoolFromPEM(path string) (*smx509.CertPool, error) {
	certs, err := LoadCertificatesFromPEM(path)
	if err != nil {
		return nil, err
	}
	pool := smx509.NewCertPool()
	for _, der := range certs {
		cert, err := smx509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func parseCertificatesFromPEMBytes(b []byte) ([][]byte, error) {
	var certs [][]byte
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
		b = rest
	}
	if len(certs) == 0 {
		return nil, errors.New("gmtls: failed to decode certificate PEM")
	}
	return certs, nil
}

func LoadSM2PrivateKeyFromPEM(path, password string) (*PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSM2PrivateKeyFromPEMBytes(b, password)
}

// LoadSM2PrivateKeyFromReader allows loading a PEM key from any reader.
func LoadSM2PrivateKeyFromReader(r io.Reader, password string) (*PrivateKey, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseSM2PrivateKeyFromPEMBytes(b, password)
}

func parseSM2PrivateKeyFromPEMBytes(b []byte, password string) (*PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("gmtls: failed to decode private key PEM")
	}

	der := block.Bytes
	var err error
	if isEncryptedPEMBlock(block) {
		if password == "" {
			return nil, errors.New("gmtls: encrypted private key, password required")
		}
		der, err = smx509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, err
		}
	}

	var ecKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &ecKey); err != nil {
		return nil, err
	}
	if len(ecKey.PrivateKey) == 0 {
		return nil, errors.New("gmtls: empty private key")
	}

	d := new(big.Int).SetBytes(ecKey.PrivateKey)
	if d.Sign() <= 0 {
		return nil, errors.New("gmtls: invalid private key")
	}

	return &PrivateKey{D: d}, nil
}

// ParseSM2PublicKeyFromCertificate parses an SM2 public key from a DER-encoded X.509 certificate.
func ParseSM2PublicKeyFromCertificate(certDER []byte) (*PublicKey, error) {
	if cert, err := smx509.ParseCertificate(certDER); err == nil {
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return &PublicKey{X: pub.X, Y: pub.Y}, nil
		}
	}
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type subjectPublicKeyInfo struct {
		Algorithm        algorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	type tbsCertificate struct {
		Raw                  asn1.RawContent
		Version              int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber         *big.Int
		Signature            algorithmIdentifier
		Issuer               asn1.RawValue
		Validity             asn1.RawValue
		Subject              asn1.RawValue
		SubjectPublicKeyInfo subjectPublicKeyInfo
	}
	type certificate struct {
		TBSCertificate     tbsCertificate
		SignatureAlgorithm algorithmIdentifier
		SignatureValue     asn1.BitString
	}

	var cert certificate
	if _, err := asn1.Unmarshal(certDER, &cert); err != nil {
		return nil, err
	}
	spk := cert.TBSCertificate.SubjectPublicKeyInfo.SubjectPublicKey.Bytes
	if len(spk) != 65 || spk[0] != 0x04 {
		return nil, errors.New("gmtls: invalid SM2 public key encoding")
	}
	x := new(big.Int).SetBytes(spk[1:33])
	y := new(big.Int).SetBytes(spk[33:65])
	if !SM2Curve.IsOnCurve(x, y) {
		return nil, errors.New("gmtls: SM2 public key not on curve")
	}
	return &PublicKey{X: x, Y: y}, nil
}
