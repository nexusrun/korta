// Package sshclient runs commands with the system OpenSSH client, using explicit
// identities and pinned host keys.
package sshclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	SecretID string `json:"secretID"`
	HostKey  string `json:"hostKey"`
	Sudo     bool   `json:"sudo"`
}
type Identity struct {
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase,omitempty"`
}

var userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$`)

// Validate checks a complete configuration, including the pinned host key.
func Validate(c *Config) error {
	if err := ValidateAddress(c); err != nil {
		return err
	}
	_, err := HostFingerprint(c.HostKey)
	return err
}

// ValidateAddress checks everything except the host key, for hosts whose key
// is trusted on first connection.
func ValidateAddress(c *Config) error {
	c.Host = strings.TrimSpace(c.Host)
	c.HostKey = strings.TrimSpace(c.HostKey)
	if net.ParseIP(c.Host) == nil && (!hostPattern.MatchString(c.Host) || strings.Contains(c.Host, "..") || strings.Contains(c.Host, ":")) {
		return fmt.Errorf("enter a DNS name or IP address without a scheme or port")
	}
	if !userPattern.MatchString(c.User) {
		return fmt.Errorf("invalid SSH user")
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("SSH port must be 1–65535")
	}
	if c.SecretID == "" {
		return fmt.Errorf("select an SSH key from the secrets vault")
	}
	return nil
}

// ScanHostKey fetches the host's public key for trust on first use,
// preferring ed25519, then ECDSA, then RSA.
func ScanHostKey(ctx context.Context, host string, port int) (string, error) {
	c := Config{Host: host, Port: port, User: "scan", SecretID: "scan"}
	if err := ValidateAddress(&c); err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "ssh-keyscan", "-T", "10", "-t", "ed25519,ecdsa,rsa", "-p", strconv.Itoa(c.Port), "--", c.Host)
	cmd.Env = cleanEnv()
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return "", fmt.Errorf("cannot read the SSH host key from %s:%d; check the address, port and firewall", c.Host, c.Port)
	}
	keys := map[string]string{}
	for _, line := range strings.Split(out.String(), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && !strings.HasPrefix(line, "#") {
			key := f[1] + " " + f[2]
			if _, err := HostFingerprint(key); err == nil {
				keys[f[1]] = key
			}
		}
	}
	for _, t := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"} {
		if k, ok := keys[t]; ok {
			return k, nil
		}
	}
	return "", fmt.Errorf("%s:%d did not offer a supported SSH host key", c.Host, c.Port)
}
func HostFingerprint(key string) (string, error) {
	f := strings.Fields(key)
	if len(f) < 2 || len(f) > 3 || strings.ContainsAny(key, "\n\r\x00") {
		return "", fmt.Errorf("supply the host public key as 'ssh-ed25519 AAAA…' (not a fingerprint or private key)")
	}
	switch f[0] {
	case "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
	default:
		return "", fmt.Errorf("unsupported SSH host key type")
	}
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) < 8 || len(b) > 16384 {
		return "", fmt.Errorf("invalid SSH host public key")
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n > len(b)-4 || string(b[4:4+n]) != f[0] {
		return "", fmt.Errorf("invalid SSH host key encoding")
	}
	digest := sha256.Sum256(b)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]), nil
}

type Session struct {
	Config             Config
	dir                string
	env                []string
	keyPath, knownPath string
}

func New(c Config, id Identity, tempRoot string) (*Session, error) {
	if err := Validate(&c); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(tempRoot, 0700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(tempRoot, "session-")
	if err != nil {
		return nil, err
	}
	s := &Session{Config: c, dir: dir, keyPath: filepath.Join(dir, "identity"), knownPath: filepath.Join(dir, "known_hosts")}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if err := os.WriteFile(s.keyPath, []byte(id.PrivateKey), 0600); err != nil {
		return nil, err
	}
	host := c.Host
	if c.Port != 22 {
		host = fmt.Sprintf("[%s]:%d", c.Host, c.Port)
	}
	fields := strings.Fields(c.HostKey)
	if err := os.WriteFile(s.knownPath, []byte(host+" "+fields[0]+" "+fields[1]+"\n"), 0600); err != nil {
		return nil, err
	}
	s.env = askpassEnv(dir, id.Passphrase)
	if id.Passphrase != "" {
		if err := writeAskpass(dir); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}
func (s *Session) Close() { _ = os.RemoveAll(s.dir) }
func cleanEnv() []string {
	out := []string{}
	for _, v := range os.Environ() {
		key, _, _ := strings.Cut(v, "=")
		if key == "PATH" || key == "HOME" || key == "USER" || key == "LOGNAME" || key == "LANG" || key == "TMPDIR" || strings.HasPrefix(key, "LC_") {
			out = append(out, v)
		}
	}
	return out
}
func askpassEnv(dir, pass string) []string {
	env := cleanEnv()
	if pass != "" {
		env = append(env, "SSH_ASKPASS="+filepath.Join(dir, "askpass"), "SSH_ASKPASS_REQUIRE=force", "DISPLAY=korta:0", "KORTA_SSH_PASSPHRASE="+pass)
	}
	return env
}
func writeAskpass(dir string) error {
	return os.WriteFile(filepath.Join(dir, "askpass"), []byte("#!/bin/sh\nprintf '%s\\n' \"$KORTA_SSH_PASSPHRASE\"\n"), 0700)
}
func (s *Session) args() []string {
	batch := "yes"
	for _, v := range s.env {
		if strings.HasPrefix(v, "KORTA_SSH_PASSPHRASE=") {
			batch = "no"
		}
	}
	return []string{"-F", "/dev/null", "-T", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + strconv.Quote(s.knownPath), "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=" + batch, "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=1", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-i", s.keyPath, "-p", fmt.Sprint(s.Config.Port), "-l", s.Config.User}
}

// Run returns the last 64 KiB of the command's stdout, also when it fails.
// Remote stderr is discarded unless the command redirects it: a remote shell
// can echo secrets read from stdin. OpenSSH's own messages go to a separate
// -E log, which is safe to report.
func (s *Session) Run(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	var out limitedBuffer
	err := s.run(ctx, command, input, &out)
	return out.Bytes(), err
}

// Stream runs command with stdout copied to w in full, for file transfers.
func (s *Session) Stream(ctx context.Context, command string, input io.Reader, w io.Writer) error {
	return s.run(ctx, command, input, w)
}

func (s *Session) run(ctx context.Context, command string, input io.Reader, stdout io.Writer) error {
	log, err := os.CreateTemp(s.dir, "ssh-log-")
	if err != nil {
		return err
	}
	logPath := log.Name()
	log.Close()
	defer os.Remove(logPath)
	cmd := exec.CommandContext(ctx, "ssh", append(s.args(), "-E", logPath, "--", s.Config.Host, command)...)
	cmd.Env = s.env
	cmd.Stdin = input
	cmd.Stdout = stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 255 {
			if reason := connectionFailure(logPath, false); reason != "" {
				return fmt.Errorf("SSH connection failed: %s (%w)", reason, err)
			}
			return fmt.Errorf("SSH connection failed (%w); check the pinned host key, SSH access and sudo privileges", err)
		}
		return fmt.Errorf("SSH command failed (%w)", err)
	}
	return nil
}

// connectionFailure returns OpenSSH's last logged message with a hint for
// common causes. local is for the user's own SSH setup instead of the
// manager's pinned keys.
func connectionFailure(logPath string, local bool) string {
	f, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 16*1024))
	last := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, line)
		if line = strings.TrimSpace(line); line != "" {
			last = line
		}
	}
	if len(last) > 200 {
		last = last[:200] + "…"
	}
	if local {
		last = strings.TrimRight(last, ".")
	}
	switch {
	case last == "":
		return ""
	case local && (strings.Contains(last, "Host key verification failed") || strings.Contains(last, "No ED25519 host key is known") || strings.Contains(last, "No RSA host key") || strings.Contains(last, "No ECDSA host key")):
		return last + "; the host is not in ~/.ssh/known_hosts or its key changed. Connect once with ssh and check the fingerprint"
	case local && strings.Contains(last, "UNPROTECTED PRIVATE KEY FILE"), local && strings.Contains(last, "bad permissions"):
		return last + "; restrict the key file with chmod 600"
	case local && (strings.Contains(last, "incorrect passphrase") || strings.Contains(last, "Load key")):
		return last + "; keys with a passphrase must be loaded with ssh-add, since Korta never prompts"
	case local && strings.Contains(last, "Permission denied"):
		return last + "; check the SSH user and identity in the inventory, load the key into ssh-agent, or pass --identity"
	case strings.Contains(last, "Host key verification failed"), strings.Contains(last, "REMOTE HOST IDENTIFICATION"):
		return last + "; the pinned host key does not match /etc/ssh/ssh_host_*_key.pub on the host"
	case strings.Contains(last, "Permission denied"):
		return last + "; check the SSH user and that this key is in that user's authorized_keys"
	case strings.Contains(last, "timed out"), strings.Contains(last, "No route to host"), strings.Contains(last, "Connection refused"), strings.Contains(last, "Could not resolve"):
		return last + "; check the host, port, and firewall rules from the manager"
	}
	return last
}

type limitedBuffer struct{ bytes.Buffer }

// limitedBuffer keeps the most recent 64 KiB, where failures are reported.
func (b *limitedBuffer) Write(p []byte) (int, error) {
	const limit = 64 * 1024
	n := len(p)
	if len(p) > limit {
		p = p[len(p)-limit:]
	}
	_, _ = b.Buffer.Write(p)
	if extra := b.Len() - limit; extra > 0 {
		b.Next(extra)
	}
	return n, nil
}

// Fingerprint validates an imported private key using OpenSSH without putting its passphrase in argv.
func Fingerprint(ctx context.Context, id Identity, tempRoot string) (string, error) {
	if len(id.PrivateKey) > 65536 || len(id.Passphrase) > 4096 || strings.ContainsAny(id.Passphrase, "\n\r\x00") || !strings.Contains(id.PrivateKey, "PRIVATE KEY-----") {
		return "", fmt.Errorf("invalid SSH private key or passphrase")
	}
	if err := os.MkdirAll(tempRoot, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(tempRoot, "session-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	key := filepath.Join(dir, "identity")
	if err := os.WriteFile(key, []byte(id.PrivateKey), 0600); err != nil {
		return "", err
	}
	if id.Passphrase != "" {
		if err := writeAskpass(dir); err != nil {
			return "", err
		}
	}
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-y", "-f", key)
	cmd.Env = askpassEnv(dir, id.Passphrase)
	cmd.Stdin = strings.NewReader("")
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cannot read SSH private key; check its format and passphrase")
	}
	return HostFingerprint(strings.TrimSpace(out.String()))
}
