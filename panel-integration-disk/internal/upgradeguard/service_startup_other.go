//go:build !linux

package upgradeguard

import "errors"

func CheckServiceStartup(unit string) error {
	return errors.New("program service interlock requires Linux startup evidence")
}
