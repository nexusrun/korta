package sshclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Shell is an interactive login shell with a pseudo-terminal, for the
// browser console. Scripted work keeps using Run with the OpenSSH client.
type Shell struct {
	Stdin  io.WriteCloser
	Stdout io.Reader
	client *ssh.Client
	sess   *ssh.Session
}

// OpenShell connects with the pinned host key and starts a login shell.
func OpenShell(ctx context.Context, c Config, id Identity, cols, rows int) (*Shell, error) {
	if err := Validate(&c); err != nil {
		return nil, err
	}
	signer, err := parseKey(id)
	if err != nil {
		return nil, err
	}
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.HostKey))
	if err != nil {
		return nil, fmt.Errorf("invalid pinned host key")
	}
	config := &ssh.ClientConfig{
		User:            c.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(pinned),
		// Hosts usually have several keys; ask for the pinned one, or the
		// server may present another type and fail verification.
		HostKeyAlgorithms: hostKeyAlgorithms(pinned.Type()),
		Timeout:           15 * time.Second,
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	conn, err := (&net.Dialer{Timeout: config.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot reach %s; check the address, port and firewall", addr)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		if strings.Contains(err.Error(), "host key mismatch") {
			return nil, fmt.Errorf("the host key does not match the pinned key; if the host was reinstalled, trust its new key first")
		}
		return nil, fmt.Errorf("SSH login failed: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	s := &Shell{client: client, sess: sess}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", clamp(rows, 1, 500), clamp(cols, 1, 1000), modes); err != nil {
		return nil, fmt.Errorf("the host refused a terminal: %w", err)
	}
	if s.Stdin, err = sess.StdinPipe(); err != nil {
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	// With a pseudo-terminal the remote side merges stderr into stdout.
	s.Stdout = stdout
	if err := sess.Shell(); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// Resize changes the remote terminal size.
func (s *Shell) Resize(cols, rows int) error {
	return s.sess.WindowChange(clamp(rows, 1, 500), clamp(cols, 1, 1000))
}

// Wait returns when the remote shell exits.
func (s *Shell) Wait() error { return s.sess.Wait() }

func (s *Shell) Close() {
	s.sess.Close()
	s.client.Close()
}

func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

func parseKey(id Identity) (ssh.Signer, error) {
	if id.Passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(id.PrivateKey), []byte(id.Passphrase))
	}
	return ssh.ParsePrivateKey([]byte(id.PrivateKey))
}

func clamp(n, lo, hi int) int {
	return max(lo, min(n, hi))
}
