package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
		configPath = flag.String("config", "cnnic/config.yml", "Path to config.yml")
		profile    = flag.String("profile", "cn", "Profile under epp")
		insec      = flag.Bool("insecure", true, "Skip certificate verification")
		tls13      = flag.Bool("tls13", true, "Use TLS 1.3")
		servername = flag.String("servername", "", "SNI server name (default: host without port)")
		action     = flag.String("action", "check", "Action: hello|login|check")
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

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	run := func(useTLS13 bool) error {
		conn, err := dialer.Dial("tcp", entry.Host)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %w", entry.Host, err)
		}
		defer conn.Close()

		var rw io.ReadWriter = conn
		config := &gmtls.Config{
			ServerName:         sni,
			MinVersion:         gmtls.VersionTLS12,
			MaxVersion:         gmtls.VersionTLS13,
			InsecureSkipVerify: *insec,
		}
		if !useTLS13 {
			config.MaxVersion = gmtls.VersionTLS12
		}

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
			// Append CA chain if a local ca.crt exists alongside the client cert.
			caPath := filepath.Join(filepath.Dir(certPath), "ca.crt")
			if _, err := os.Stat(caPath); err == nil {
				if cas, err := gmtls.LoadCertificatesFromPEM(caPath); err == nil && len(cas) > 0 {
					if len(cert.Chain) == 0 && len(cert.Raw) > 0 {
						cert.Chain = [][]byte{cert.Raw}
					}
					for _, ca := range cas {
						// Avoid duplicate append
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
		loadKey := func(keyPath, pw string) (*gmtls.PrivateKey, error) {
			return gmtls.LoadSM2PrivateKeyFromPEM(keyPath, pw)
		}

		// Sign certificate (preferred for TLS 1.3 CertificateVerify)
		signCrtPath := resolvePath(baseDir, entry.GmSignCrt)
		signKeyPath := resolvePath(baseDir, entry.GmSignKey)
		signPw := entry.GmSignPw
		if signPw == "" {
			signPw = entry.GmPw
		}
		if entry.GmSignCrt != "" && entry.GmSignKey != "" {
			cert, err := loadCertWithChain(signCrtPath)
			if err != nil {
				return fmt.Errorf("failed to load sign cert: %w", err)
			}
			key, err := loadKey(signKeyPath, signPw)
			if err != nil {
				return fmt.Errorf("failed to load sign key: %w", err)
			}
			config.SignCertificates = []*gmtls.Certificate{cert}
			config.SignPrivateKey = key
			// Keep legacy fields aligned
			config.Certificates = []*gmtls.Certificate{cert}
			config.PrivateKey = key
		} else if entry.GmCrt != "" && entry.GmKey != "" {
			// Backward-compatible single certificate
			crtPath := resolvePath(baseDir, entry.GmCrt)
			keyPath := resolvePath(baseDir, entry.GmKey)
			cert, err := loadCertWithChain(crtPath)
			if err != nil {
				return fmt.Errorf("failed to load client cert: %w", err)
			}
			key, err := loadKey(keyPath, entry.GmPw)
			if err != nil {
				return fmt.Errorf("failed to load client key: %w", err)
			}
			config.SignCertificates = []*gmtls.Certificate{cert}
			config.SignPrivateKey = key
			config.Certificates = []*gmtls.Certificate{cert}
			config.PrivateKey = key
		}

		// Optional encryption certificate (for dual-certificate deployments)
		if entry.GmEncCrt != "" && entry.GmEncKey != "" {
			encCrtPath := resolvePath(baseDir, entry.GmEncCrt)
			encKeyPath := resolvePath(baseDir, entry.GmEncKey)
			encPw := entry.GmEncPw
			if encPw == "" {
				encPw = entry.GmPw
			}
			encCert, err := loadCertWithChain(encCrtPath)
			if err != nil {
				return fmt.Errorf("failed to load enc cert: %w", err)
			}
			encKey, err := loadKey(encKeyPath, encPw)
			if err != nil {
				return fmt.Errorf("failed to load enc key: %w", err)
			}
			config.EncCertificates = []*gmtls.Certificate{encCert}
			config.EncPrivateKey = encKey
		}

		tlsConn, err := gmtls.Client(conn, config)
		if err != nil {
			return fmt.Errorf("gm tls handshake failed: %w", err)
		}
		defer tlsConn.Close()
		rw = tlsConn

		// 读取 greeting
		greeting, err := eppReadFrame(rw)
		if err != nil {
			return fmt.Errorf("failed to read EPP greeting: %w", err)
		}
		fmt.Println("EPP Greeting:")
		fmt.Println(string(greeting))

		sendAndPrint := func(actionLabel, payload string) error {
			if err := eppWriteFrame(rw, []byte(payload)); err != nil {
				return fmt.Errorf("failed to send EPP %s: %w", actionLabel, err)
			}
			resp, err := eppReadFrame(rw)
			if err != nil {
				return fmt.Errorf("failed to read EPP %s response: %w", actionLabel, err)
			}
			fmt.Printf("EPP %s Response:\n", actionLabel)
			fmt.Println(string(resp))
			return nil
		}

		switch *action {
		case "hello":
			if err := sendAndPrint("hello", eppHelloXML()); err != nil {
				return err
			}
		case "login":
			clTRID := fmt.Sprintf("gmtls-%d", time.Now().UnixNano())
			if err := sendAndPrint("login", eppLoginXML(entry.Username, entry.Password, clTRID)); err != nil {
				return err
			}
		case "check":
			loginTRID := fmt.Sprintf("gmtls-login-%d", time.Now().UnixNano())
			if err := sendAndPrint("login", eppLoginXML(entry.Username, entry.Password, loginTRID)); err != nil {
				return err
			}
			checkTRID := fmt.Sprintf("gmtls-check-%d", time.Now().UnixNano())
			if err := sendAndPrint("check", eppDomainCheckXML(checkTRID)); err != nil {
				return err
			}
		default:
			log.Fatalf("Unknown action: %s", *action)
		}
		return nil
	}

	err = run(*tls13)
	if err != nil {
		return
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
