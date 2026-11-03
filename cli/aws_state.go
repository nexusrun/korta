package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nexusrun/korta/internal/awsprovider"
	"github.com/nexusrun/korta/roles"
)

type awsReservation struct {
	Token      string            `json:"token"`
	InstanceID string            `json:"instanceID,omitempty"`
	Host       string            `json:"host,omitempty"`
	HostKey    string            `json:"hostKey,omitempty"`
	Spec       roles.AWSInstance `json:"spec"`
}
type awsLocalState struct {
	Version      int                       `json:"version"`
	OwnerName    string                    `json:"ownerName"`
	OwnerID      string                    `json:"ownerID"`
	Account      string                    `json:"account"`
	Spec         roles.AWSInstance         `json:"spec"`
	Fleet        cloud.Fleet               `json:"fleet"`
	Reservations map[string]awsReservation `json:"reservations"`
}

func awsStateDir(rolePath string) (string, error) {
	p, err := filepath.Abs(rolePath)
	if err != nil {
		return "", err
	}
	p, err = filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("XDG_STATE_HOME must be an absolute path")
	}
	hash := sha256.Sum256([]byte(p))
	return filepath.Join(root, "korta", "aws", hex.EncodeToString(hash[:])), nil
}
func readAWSState(dir string) (awsLocalState, error) {
	var s awsLocalState
	path := filepath.Join(dir, "state.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return s, fmt.Errorf("AWS state must be a private regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("cannot read AWS state; inspect %s", path)
	}
	if s.Version != 1 {
		return s, fmt.Errorf("unsupported AWS state version; upgrade Korta before continuing")
	}
	return s, nil
}
func writeAWSState(dir string, s awsLocalState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err = temp.Chmod(0600); err != nil {
		return err
	}
	if _, err = temp.Write(data); err != nil {
		return err
	}
	if err = temp.Sync(); err != nil {
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp.Name(), filepath.Join(dir, "state.json")); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func randomAWSID(prefix string) (string, error) {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(data[:]), nil
}
