package sshclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

// System connects with the user's own OpenSSH setup: ~/.ssh/config,
// ssh-agent and ~/.ssh/known_hosts. Unknown or changed host keys are
// refused rather than trusted, and it never asks for passwords.
type System struct {
	Host string
	Port int    // 0 uses ~/.ssh/config or 22
	User string // "" uses ~/.ssh/config or the local user name
	// ConfigFile replaces ~/.ssh/config, for example in CI.
	ConfigFile string
	// IdentityFile is the only private key offered when set. A key with a
	// passphrase must be loaded into ssh-agent: Korta never prompts.
	IdentityFile string
}

// Run returns the last 64 KiB of the command's stdout, also when it fails.
func (s System) Run(ctx context.Context, command string, input io.Reader) ([]byte, error) {
	if !hostPattern.MatchString(s.Host) || (s.User != "" && !userPattern.MatchString(s.User)) || s.Port < 0 || s.Port > 65535 {
		return nil, fmt.Errorf("invalid SSH address %s@%s:%d", s.User, s.Host, s.Port)
	}
	log, err := os.CreateTemp("", "korta-ssh-log-")
	if err != nil {
		return nil, err
	}
	logPath := log.Name()
	log.Close()
	defer os.Remove(logPath)
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-E", logPath}
	if s.ConfigFile != "" {
		args = append(args, "-F", s.ConfigFile)
	}
	if s.IdentityFile != "" {
		args = append(args, "-i", s.IdentityFile, "-o", "IdentitiesOnly=yes")
	}
	if s.Port != 0 {
		args = append(args, "-p", strconv.Itoa(s.Port))
	}
	if s.User != "" {
		args = append(args, "-l", s.User)
	}
	var out limitedBuffer
	cmd := exec.CommandContext(ctx, "ssh", append(args, "--", s.Host, command)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, &out, io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return out.Bytes(), ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 255 {
			if reason := connectionFailure(logPath, true); reason != "" {
				return out.Bytes(), fmt.Errorf("SSH connection to %s failed: %s", s.Host, reason)
			}
			return out.Bytes(), fmt.Errorf("SSH connection to %s failed (%w)", s.Host, err)
		}
		return out.Bytes(), fmt.Errorf("SSH command failed (%w)", err)
	}
	return out.Bytes(), nil
}
