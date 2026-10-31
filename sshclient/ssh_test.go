package sshclient

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func identity(t *testing.T, pass string) (Identity, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "key")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", pass, "-f", file)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(file + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return Identity{PrivateKey: string(private), Passphrase: pass}, strings.TrimSpace(string(public))
}
func TestPrivateKeyValidationHandlesPassphrasesWithoutSecretArguments(t *testing.T) {
	for _, pass := range []string{"", "a-test-only-passphrase"} {
		t.Run(pass, func(t *testing.T) {
			id, pub := identity(t, pass)
			want, err := HostFingerprint(pub)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := Fingerprint(ctx, id, t.TempDir())
			if err != nil || got != want {
				t.Fatalf("fingerprint=%s err=%v", got, err)
			}
			if pass != "" {
				id.Passphrase = "incorrect"
				if _, err := Fingerprint(ctx, id, t.TempDir()); err == nil {
					t.Fatal("incorrect passphrase accepted")
				}
			}
		})
	}
}
func TestSessionPinsHostAndProtectsTemporaryIdentity(t *testing.T) {
	id, pub := identity(t, "")
	for _, host := range []string{"instance.example", "10.0.0.5", "::1"} {
		c := Config{Host: host, Port: 2222, User: "ubuntu", SecretID: "k", HostKey: pub}
		s, err := New(c, id, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(s.knownPath)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(string(b), "["+host+"]:2222 ") {
			t.Fatalf("invalid known_hosts: %s", b)
		}
		info, _ := os.Stat(s.keyPath)
		if info.Mode().Perm() != 0600 {
			t.Fatal("identity permissions are unsafe")
		}
		args := strings.Join(s.args(), " ")
		for _, wanted := range []string{"StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "PasswordAuthentication=no", "ForwardAgent=no", "-F /dev/null"} {
			if !strings.Contains(args, wanted) {
				t.Fatalf("missing %s", wanted)
			}
		}
		if strings.Contains(args, id.PrivateKey) {
			t.Fatal("private key in argv")
		}
		dir := s.dir
		s.Close()
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("temporary identity not deleted")
		}
	}
}
func TestConfigRejectsUnpinnedHostsAndCommandInjection(t *testing.T) {
	_, pub := identity(t, "")
	for _, host := range []string{"https://host", "-oProxyCommand=evil", "host; rm -rf /", "host/path", "host@user", "host\nother"} {
		c := Config{Host: host, User: "root", SecretID: "k", HostKey: pub}
		if Validate(&c) == nil {
			t.Fatalf("unsafe host accepted: %s", host)
		}
	}
	c := Config{Host: "host", User: "root", SecretID: "k"}
	if Validate(&c) == nil {
		t.Fatal("unverified host allowed")
	}
	c.HostKey = pub
	c.User = "root;evil"
	if Validate(&c) == nil {
		t.Fatal("unsafe SSH user allowed")
	}
}
func TestRunReportsOpenSSHFailureWithoutRemoteStderr(t *testing.T) {
	for _, tc := range []struct{ logLine, want string }{
		{"ec2-user@instance.test: Permission denied (publickey).", "authorized_keys"},
		{"Host key verification failed.", "pinned host key does not match"},
		{"ssh: connect to host instance.test port 22: Connection timed out", "firewall"},
		{"", "check the pinned host key, SSH access"},
	} {
		id, pub := identity(t, "")
		dir := t.TempDir()
		script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -E ] && log=$2; shift; done\n" +
			"printf '%s\\n' '" + tc.logLine + "' >> \"$log\"\necho remote-secret >&2\nexit 255\n"
		if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		s, err := New(Config{Host: "instance.test", User: "ec2-user", SecretID: "k", HostKey: pub}, id, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Run(context.Background(), "true", nil)
		s.Close()
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), tc.logLine) {
			t.Fatalf("log %q: got %v, want %q", tc.logLine, err, tc.want)
		}
		if strings.Contains(err.Error(), "remote-secret") {
			t.Fatal("remote stderr leaked into the error")
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 255 {
			t.Fatal("exit status is no longer wrapped")
		}
	}
}
func TestSSHChildEnvironmentDoesNotInheritControlPlaneSecrets(t *testing.T) {
	t.Setenv("KORTA_VAULT_KEY", "secret-master-key")
	t.Setenv("KORTA_ADMIN_TOKEN", "secret-admin-token")
	t.Setenv("SSH_AUTH_SOCK", "/private/socket")
	for _, v := range cleanEnv() {
		if strings.Contains(v, "secret-master-key") || strings.Contains(v, "secret-admin-token") || strings.HasPrefix(v, "SSH_AUTH_SOCK=") {
			t.Fatal("control-plane secret passed to SSH process")
		}
	}
}

func TestScanHostKeyPrefersEd25519(t *testing.T) {
	_, ed := identity(t, "")
	dir := t.TempDir()
	script := "#!/bin/sh\necho '# comment'\necho 'host ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ'\necho 'host " + ed + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh-keyscan"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := ScanHostKey(context.Background(), "db.internal", 22)
	if want := strings.Join(strings.Fields(ed)[:2], " "); err != nil || got != want {
		t.Fatalf("got %q %v, want %q", got, err, want)
	}
	if _, err := ScanHostKey(context.Background(), "bad host;rm", 22); err == nil {
		t.Fatal("accepted an invalid host")
	}
}
