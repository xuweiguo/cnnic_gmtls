package eppclient

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEPPFrameRoundTrip(t *testing.T) {
	payload := []byte("<epp>ok</epp>")
	var buf bytes.Buffer
	if err := eppWriteFrame(&buf, payload); err != nil {
		t.Fatalf("eppWriteFrame() error = %v", err)
	}
	got, err := eppReadFrame(&buf)
	if err != nil {
		t.Fatalf("eppReadFrame() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestEPPReadFrameInvalidLength(t *testing.T) {
	bad := []byte{0, 0, 0, 3}
	_, err := eppReadFrame(bytes.NewReader(bad))
	if err == nil {
		t.Fatalf("expected invalid length error")
	}
}

func TestResolvePath(t *testing.T) {
	base := filepath.Join("a", "b")
	if got, want := resolvePath(base, "gm/x.crt"), filepath.Join(base, "gm/x.crt"); got != want {
		t.Fatalf("resolvePath(relative) = %q, want %q", got, want)
	}
	if got := resolvePath(base, "/tmp/x.crt"); got != "/tmp/x.crt" {
		t.Fatalf("resolvePath(absolute) = %q", got)
	}
}

func TestHostForSNI(t *testing.T) {
	if got := hostForSNI("example.com:443"); got != "example.com" {
		t.Fatalf("hostForSNI() = %q", got)
	}
	if got := hostForSNI("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("hostForSNI(ipv6) = %q", got)
	}
}

func TestXMLEscape(t *testing.T) {
	if got, want := xmlEscape("a<b&c"), "a&lt;b&amp;c"; got != want {
		t.Fatalf("xmlEscape() = %q, want %q", got, want)
	}
}

func TestLoadConfig(t *testing.T) {
	d := t.TempDir()
	cfgPath := filepath.Join(d, "config.yml")
	content := []byte("epp:\n  cn:\n    host: 127.0.0.1:1234\n    username: u\n    password: p\n")
	if err := os.WriteFile(cfgPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(cfgPath, "cn")
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.EPP["cn"].Host != "127.0.0.1:1234" {
		t.Fatalf("unexpected host = %q", cfg.EPP["cn"].Host)
	}

	if _, err := loadConfig(cfgPath, "missing"); err == nil {
		t.Fatalf("expected missing profile error")
	}
}
