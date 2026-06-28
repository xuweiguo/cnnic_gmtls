package eppclient

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	gmtls "github.com/xuweiguo/cnnic_gmtls"
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

type cliOptions struct {
	configPath string
	profile    string
	insecure   bool
	servername string
	action     string
}

func Execute(args []string, stdout, stderr io.Writer) error {
	opts := cliOptions{
		configPath: "cnnic/config.yml",
		profile:    "cn",
		insecure:   true,
		action:     "check",
	}

	fs := flag.NewFlagSet("epp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opts.configPath, "config", opts.configPath, "Path to config.yml")
	fs.StringVar(&opts.profile, "profile", opts.profile, "Profile under epp")
	fs.BoolVar(&opts.insecure, "insecure", opts.insecure, "Skip certificate verification")
	fs.StringVar(&opts.servername, "servername", opts.servername, "SNI server name (default: host without port)")
	fs.StringVar(&opts.action, "action", opts.action, "Action: hello|login|check")
	if err := fs.Parse(args); err != nil {
		return err
	}

	return run(opts, stdout)
}

func run(opts cliOptions, stdout io.Writer) error {
	if opts.action != "hello" && opts.action != "login" && opts.action != "check" {
		return fmt.Errorf("unknown action: %s", opts.action)
	}

	cfg, err := loadConfig(opts.configPath, opts.profile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	entry := cfg.EPP[opts.profile]
	if entry.Host == "" {
		return fmt.Errorf("host is empty in config")
	}

	sni := opts.servername
	if sni == "" {
		sni = hostForSNI(entry.Host)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	runOnce := func() error {
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
			InsecureSkipVerify: opts.insecure,
			// CNNIC EPP 服务器证书 CN=server(通用名,非域名)且无 SAN,
			// 跳过主机名校验,仅做证书链 + 有效期 + 用途校验。
			SkipServerNameVerify: true,
		}

		baseDir := "."
		if idx := strings.LastIndex(opts.configPath, string(os.PathSeparator)); idx >= 0 {
			baseDir = opts.configPath[:idx]
		}

		// 严格校验:加载 CA(与客户端证书同目录的 ca.crt)用于验证服务器证书链。
		if !opts.insecure {
			caPath := filepath.Join(baseDir, "gm", "ca.crt")
			if _, err := os.Stat(caPath); err != nil {
				caPath = filepath.Join(baseDir, "ca.crt")
			}
			if pool, err := gmtls.LoadCertPoolFromPEM(caPath); err == nil {
				config.RootCAs = pool
			}
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
		loadKey := func(keyPath, pw string) (*gmtls.PrivateKey, error) {
			return gmtls.LoadSM2PrivateKeyFromPEM(keyPath, pw)
		}

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
			config.Certificates = []*gmtls.Certificate{cert}
			config.PrivateKey = key
		} else if entry.GmCrt != "" && entry.GmKey != "" {
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

		state := tlsConn.ConnectionState()
		fmt.Fprintf(stdout, "Negotiated TLS: version=0x%04x cipherSuite=0x%04x\n", state.Version, state.CipherSuite)
		rw = tlsConn

		greeting, err := eppReadFrame(rw)
		if err != nil {
			return fmt.Errorf("failed to read EPP greeting: %w", err)
		}
		fmt.Fprintln(stdout, "EPP Greeting:")
		fmt.Fprintln(stdout, string(greeting))

		sendAndPrint := func(actionLabel, payload string) error {
			if err := eppWriteFrame(rw, []byte(payload)); err != nil {
				return fmt.Errorf("failed to send EPP %s: %w", actionLabel, err)
			}
			resp, err := eppReadFrame(rw)
			if err != nil {
				return fmt.Errorf("failed to read EPP %s response: %w", actionLabel, err)
			}
			fmt.Fprintf(stdout, "EPP %s Response:\n", actionLabel)
			fmt.Fprintln(stdout, string(resp))
			return nil
		}

		switch opts.action {
		case "hello":
			return sendAndPrint("hello", eppHelloXML())
		case "login":
			clTRID := fmt.Sprintf("gmtls-%d", time.Now().UnixNano())
			return sendAndPrint("login", eppLoginXML(entry.Username, entry.Password, clTRID))
		case "check":
			loginTRID := fmt.Sprintf("gmtls-login-%d", time.Now().UnixNano())
			if err := sendAndPrint("login", eppLoginXML(entry.Username, entry.Password, loginTRID)); err != nil {
				return err
			}
			checkTRID := fmt.Sprintf("gmtls-check-%d", time.Now().UnixNano())
			return sendAndPrint("check", eppDomainCheckXML(checkTRID))
		default:
			return fmt.Errorf("unknown action: %s", opts.action)
		}
	}

	err = runOnce()
	if err != nil {
		return fmt.Errorf("EPP run failed: %w", err)
	}
	return nil
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
