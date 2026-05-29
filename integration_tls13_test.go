package gmtls

import (
	"fmt"
	"io"
	"testing"
	"time"
)

func TestTLS13OfflineHandshakeAndData(t *testing.T) {
	cert, key := newTestSM2Certificate(t)

	srvCfg := &Config{
		SignCertificates: []*Certificate{cert},
		SignPrivateKey:   key,
		MinVersion:       VersionTLS13,
		MaxVersion:       VersionTLS13,
	}

	ln, err := Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- fmt.Errorf("accept failed: %w", err)
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 5)
		if _, err := io.ReadFull(conn, buf); err != nil {
			srvErr <- fmt.Errorf("server read failed: %w", err)
			return
		}
		if string(buf) != "ping!" {
			srvErr <- fmt.Errorf("server got %q, want %q", string(buf), "ping!")
			return
		}
		if _, err := conn.Write([]byte("pong!")); err != nil {
			srvErr <- fmt.Errorf("server write failed: %w", err)
			return
		}
		srvErr <- nil
	}()

	clientCfg := &Config{
		InsecureSkipVerify: true,
		MinVersion:         VersionTLS13,
		MaxVersion:         VersionTLS13,
		ServerName:         "127.0.0.1",
	}
	client, err := Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer client.Close()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	state := client.ConnectionState()
	if !state.HandshakeComplete {
		t.Fatalf("handshake not complete")
	}
	if state.Version != VersionTLS13 {
		t.Fatalf("version = 0x%04x, want 0x%04x", state.Version, VersionTLS13)
	}

	if _, err := client.Write([]byte("ping!")); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(client, resp); err != nil {
		t.Fatalf("client read failed: %v", err)
	}
	if string(resp) != "pong!" {
		t.Fatalf("client got %q, want %q", string(resp), "pong!")
	}

	select {
	case err := <-srvErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("server side timeout")
	}
}
