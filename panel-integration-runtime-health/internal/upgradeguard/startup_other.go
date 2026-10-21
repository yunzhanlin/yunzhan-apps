//go:build !linux

package upgradeguard

import "errors"

// No substitute for Linux boot/process/FLOCK identity on unsupported hosts.
func CheckStartup() error {
	if Blocked() {
		return errors.New("pending program upgrade requires Linux startup evidence")
	}
	return nil
}
