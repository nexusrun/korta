//go:build !linux && !darwin

package cli

import "fmt"

func lockAWSState(string) (func(), error) {
	return nil, fmt.Errorf("standalone AWS roles require Linux or macOS; use WSL on Windows")
}
