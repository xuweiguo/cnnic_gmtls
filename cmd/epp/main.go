package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xuweiguo/cnnic_gmtls"
)

type configFile struct {
	EPP map[string]struct {
		Host        string `yaml:"host"`
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		GmCrt       string `yaml:"gmCrt"`
		GmKey       string `yaml:"gmKey"`
		GmPw        string `yaml:"gmPw"`
		GmSignCrt   string `yaml:"gmSignCrt"`
		GmSignKey   string `yaml:"gmSignKey"`
		GmSignPw    string `yaml:"gmSignPw"`
		GmEncCrt    string `yaml:"gmEncCrt"`
		GmEncKey    string `yaml:"gmEncKey"`
		GmEncPw     string `yaml:"gmEncPw"`
		CheckDomain string `yaml:"checkDomain"`
	} `yaml:"epp"`
}

func loadConfig(path, profile string) (*configFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg configFile
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if _, ok := cfg.EPP[profile]; !ok {
		return nil, fmt.Errorf("profile %q not found in %s", profile, path)
	}
	return &cfg, nil
}

func resolvePath(basePath, p string) string {
	if p == "" {
		return p
	}
	if strings.HasPrefix(p, "/") {
		return p
	}
	return basePath + string(os.PathSeparator) + p
}

func eppReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen < 4 || frameLen > 10*1024*1024 {
		return nil, fmt.Errorf("invalid EPP frame length: %d", frameLen)
	}
	payload := make([]byte, frameLen-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func eppWriteFrame(w io.Writer, payload []byte) error {
	frameLen := uint32(len(payload) + 4)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], frameLen)
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func eppLoginXML(clID, pw, clTRID string) string {
	// Basic EPP login; servers may require extensions.
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <login>
      <clID>%s</clID>
      <pw>%s</pw>
      <options>
        <version>1.0</version>
        <lang>en</lang>
      </options>
      <svcs>
        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
      </svcs>
    </login>
    <clTRID>%s</clTRID>
  </command>
</epp>`, xmlEscape(clID), xmlEscape(pw), xmlEscape(clTRID))
}

func eppHelloXML() string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <hello/>
</epp>`)
}

func eppDomainCheckXML(clTRID string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0">
  <command>
    <check>
      <domain:check xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>example.cn</domain:name>
      </domain:check>
    </check>
    <clTRID>%s</clTRID>
  </command>
</epp>`, xmlEscape(clTRID))
}

func main() {
	var (
		configPath = flag.String("config", "/cnnic/config.yml", "Path to config.yml")
		profile    = flag.String("profile", "cn", "Profile under epp")
		insec      = flag.Bool("insecure", true, "Skip certificate verification")

		servername = flag.String("servername", "", "SNI server name (default: host without port)")
	)
	flag.Parse()

	cfg, err := loadConfig(*configPath, *profile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	entry := cfg.EPP[*profile]
	if entry.Host == "" {
		log.Fatalf("Host is empty in config")
	}
	sni := *servername
	if sni == "" {
		sni = hostForSNI(entry.Host)
	}
	// 加载客户端证书
	// 加载客户端证书
	baseDir := "."
	if idx := strings.LastIndex(*configPath, string(os.PathSeparator)); idx >= 0 {
		baseDir = (*configPath)[:idx]
	}

	loadCertWithChain := func(certPath string) (*gmtls.Certificate, error) {
		cert, err := gmtls.LoadCertificateFromPEM(certPath)
		if err != nil {
			return nil, err
		}
		caPath := filepath.Join(filepath.Dir(certPath), "ca.crt")
		if _, err := os.Stat(caPath); err == nil {
			if cas, err := gmtls.LoadCertificatesFromPEM(caPath); err == nil && len(cas) > 0 {
				if len(cert.Chain) == 0 && len(cert.Raw) > 0 {
					cert.Chain = [][]byte{cert.Raw}
				}
				for _, ca := range cas {
					dup := false
					for _, existing := range cert.Chain {
						if bytes.Equal(existing, ca) {
							dup = true
							break
						}
					}
					if !dup {
						cert.Chain = append(cert.Chain, ca)
					}
				}
			}
		}

		return cert, nil
	}

	cert, err := loadCertWithChain(resolvePath(baseDir, entry.GmCrt))
	if err != nil {
		log.Fatalf("Failed to load client certificate: %v", err)
	}
	pem, err := gmtls.LoadSM2PrivateKeyFromPEM(resolvePath(baseDir, entry.GmKey), entry.GmPw)
	if err != nil {
		log.Fatalf("Failed to load client key: %v", err)
	}
	config := &gmtls.Config{
		//ServerName:         sni,
		InsecureSkipVerify: *insec,
		SignCertificates:   []*gmtls.Certificate{cert},
		SignPrivateKey:     pem,
	}
	config.SignCertificates = []*gmtls.Certificate{cert}
	config.SignPrivateKey = pem

	tlsConn, err := gmtls.Dial("tcp", entry.Host, config)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", entry.Host, err)
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	fmt.Printf("Negotiated TLS: version=0x%04x cipherSuite=0x%04x\n", state.Version, state.CipherSuite)

	// 读取 greeting
	greeting, err := eppReadFrame(tlsConn)
	if err != nil {
		log.Fatalf("Failed to read EPP greeting: %v", err)
	}
	fmt.Println("EPP Greeting:")
	fmt.Println(string(greeting))

	sendAndPrint := func(actionLabel, payload string) error {
		if err := eppWriteFrame(tlsConn, []byte(payload)); err != nil {
			log.Fatalf("Failed to send EPP %s: %v", actionLabel, err)
		}
		resp, err := eppReadFrame(tlsConn)
		if err != nil {
			log.Fatalf("Failed to read EPP %s response: %v", actionLabel, err)
		}
		fmt.Printf("EPP %s Response:\n", actionLabel)
		fmt.Println(string(resp))
		return nil
	}

	loginTRID := fmt.Sprintf("gmtls-login-%d", time.Now().UnixNano())
	if err := sendAndPrint("login", eppLoginXML(entry.Username, entry.Password, loginTRID)); err != nil {
		log.Fatalf("Failed to send EPP login: %v", err)
	}
	checkTRID := fmt.Sprintf("gmtls-check-%d", time.Now().UnixNano())
	if err := sendAndPrint("check", eppDomainCheckXML(checkTRID)); err != nil {
		log.Fatalf("Failed to send EPP check: %v", err)
	}

}

func hostForSNI(hostport string) string {
	host := hostport
	if strings.Contains(hostport, ":") {
		if h, _, err := net.SplitHostPort(hostport); err == nil {
			host = h
		}
	}
	return host
}

func xmlEscape(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
