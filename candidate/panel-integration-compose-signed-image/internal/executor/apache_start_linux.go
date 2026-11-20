//go:build linux

package executor

import (
	"errors"
	"os"
	"syscall"
)

// Fixed PID1 entrypoint: no caller-supplied binary, configuration, environment
// or child flags. A programme update preserves the root selected in the existing
// configuration, including old installations; a new installation alone cannot
// change it. The ordinary startup recovery and body checks run before this unit.
func StartApache() error {
	if os.Geteuid() != 0 {
		return errors.New("Apache 启动只能由 root 执行")
	}
	lock, err := runtimeUseLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	r, err := apacheRelease()
	if err != nil {
		return err
	}
	if _, err := LoadRuntime(r.ID); err != nil {
		return err
	}
	for _, path := range []string{r.Prefix(), r.Prefix() + "/bin"} {
		if err := ownedRuntimePath(path, true); err != nil {
			return err
		}
	}
	if err := ownedRuntimePath(r.CLI(), false); err != nil {
		return err
	}
	return syscall.Exec(r.CLI(), []string{r.CLI(), "-DFOREGROUND", "-f", "/etc/panel/apache/httpd.conf"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"})
}
