package gmtls

import (
	"errors"
	"time"

	"github.com/emmansun/gmsm/smx509"
)

func (c *Conn) verifyServerCertificate(cert *Certificate) error {
	roots := (*smx509.CertPool)(nil)
	if c.config != nil {
		roots = c.config.RootCAs
	}
	if roots == nil {
		roots, _ = smx509.SystemCertPool()
	}

	serverName := c.clientServerName
	if c.config != nil && c.config.ServerName != "" {
		serverName = c.config.ServerName
	}
	// 服务器证书为通用名(非域名)、不含 SAN 时(CNNIC EPP 服务器 CN=server),
	// 跳过主机名校验,只做证书链 + 有效期 + 用途校验。
	if c.config != nil && c.config.SkipServerNameVerify {
		serverName = ""
	}

	return c.verifyPeerCertificate(cert, roots, smx509.ExtKeyUsageServerAuth, serverName)
}

func (c *Conn) verifyClientCertificate(cert *Certificate) error {
	roots := (*smx509.CertPool)(nil)
	if c.config != nil {
		roots = c.config.ClientCAs
	}

	return c.verifyPeerCertificate(cert, roots, smx509.ExtKeyUsageClientAuth, "")
}

func (c *Conn) verifyPeerCertificate(cert *Certificate, roots *smx509.CertPool, keyUsage smx509.ExtKeyUsage, dnsName string) error {
	if cert == nil || len(cert.Raw) == 0 {
		return errors.New("gmtls: missing peer certificate")
	}
	leaf, err := smx509.ParseCertificate(cert.Raw)
	if err != nil {
		return err
	}

	var interPool *smx509.CertPool
	if len(cert.Chain) > 1 {
		interPool = smx509.NewCertPool()
		for _, der := range cert.Chain[1:] {
			ic, err := smx509.ParseCertificate(der)
			if err != nil {
				return err
			}
			interPool.AddCert(ic)
		}
	}

	opts := smx509.VerifyOptions{
		Intermediates: interPool,
		Roots:         roots,
		CurrentTime:   time.Now(),
		KeyUsages:     []smx509.ExtKeyUsage{keyUsage},
	}
	if dnsName != "" {
		opts.DNSName = dnsName
	}

	_, err = leaf.Verify(opts)
	return err
}
