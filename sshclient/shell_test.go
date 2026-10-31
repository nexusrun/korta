package sshclient

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testServer accepts one user key, records pty and window sizes, and echoes
// each input line back in upper case.
type testServer struct {
	addr    string
	hostKey string
	mu      sync.Mutex
	sizes   []string
}

func newKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	return signer, string(pem.EncodeToMemory(block))
}

func startServer(t *testing.T, user ssh.PublicKey) *testServer {
	t.Helper()
	hostSigner, _ := newKey(t)
	// Like a real host, also offer an ECDSA key, which Go clients prefer
	// unless told which type is pinned.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecSigner, _ := ssh.NewSignerFromKey(ecKey)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) != string(user.Marshal()) {
			return nil, net.ErrClosed
		}
		return nil, nil
	}}
	config.AddHostKey(ecSigner)
	config.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &testServer{addr: ln.Addr().String(), hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, config)
		}
	}()
	return s
}

func (s *testServer) record(kind string, payload []byte, offset int) {
	cols := binary.BigEndian.Uint32(payload[offset:])
	rows := binary.BigEndian.Uint32(payload[offset+4:])
	s.mu.Lock()
	s.sizes = append(s.sizes, kind+" "+strconv.Itoa(int(cols))+"x"+strconv.Itoa(int(rows)))
	s.mu.Unlock()
}

func (s *testServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, requests, _ := nc.Accept()
		go func() {
			for req := range requests {
				switch req.Type {
				case "pty-req":
					termLen := binary.BigEndian.Uint32(req.Payload)
					s.record("pty", req.Payload, 4+int(termLen))
				case "window-change":
					s.record("resize", req.Payload, 0)
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			}
		}()
		go func() {
			defer ch.Close()
			r := bufio.NewReader(ch)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				ch.Write([]byte(strings.ToUpper(line)))
			}
		}()
	}
}

func TestOpenShellPinsHostKeyAndSendsTerminalSize(t *testing.T) {
	userSigner, userKey := newKey(t)
	srv := startServer(t, userSigner.PublicKey())
	host, port, _ := net.SplitHostPort(srv.addr)
	p, _ := strconv.Atoi(port)
	cfg := Config{Host: host, Port: p, User: "ops", SecretID: "k", HostKey: srv.hostKey}

	sh, err := OpenShell(context.Background(), cfg, Identity{PrivateKey: userKey}, 120, 40)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sh.Stdin.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(sh.Stdout).ReadString('\n')
	if err != nil || line != "HELLO\n" {
		t.Fatalf("got %q %v", line, err)
	}
	if err := sh.Resize(200, 50); err != nil {
		t.Fatal(err)
	}
	sh.Close()
	srv.mu.Lock()
	sizes := strings.Join(srv.sizes, ",")
	srv.mu.Unlock()
	if !strings.HasPrefix(sizes, "pty 120x40") {
		t.Fatalf("sizes %q", sizes)
	}

	// A different pinned key is refused before authentication.
	_, otherHost := newKey(t)
	other, _ := ssh.ParsePrivateKey([]byte(otherHost))
	bad := cfg
	bad.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(other.PublicKey())))
	if _, err := OpenShell(context.Background(), bad, Identity{PrivateKey: userKey}, 80, 24); err == nil || !strings.Contains(err.Error(), "does not match the pinned key") {
		t.Fatalf("got %v", err)
	}
	// A key the server does not accept fails login.
	_, strangerKey := newKey(t)
	if _, err := OpenShell(context.Background(), cfg, Identity{PrivateKey: strangerKey}, 80, 24); err == nil || !strings.Contains(err.Error(), "SSH login failed") {
		t.Fatalf("got %v", err)
	}
}
