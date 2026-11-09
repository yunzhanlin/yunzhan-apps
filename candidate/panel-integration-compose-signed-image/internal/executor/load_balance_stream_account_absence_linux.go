//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Read-only prerequisite for the forthcoming original-authority-bound account
// job. Absence is NOT a permission to create, adopt, repair or retry an account.
func loadBalanceStreamAccountAbsent(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || threatIDSTrustedParents("/etc", false) != nil {
		return errLoadBalanceStreamAccount
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	configuration, err := holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return err
	}
	defer configuration.close()
	var sources []*memcachedUnixNSSFile
	var data [][]byte
	defer func() {
		for _, file := range sources {
			file.file.Close()
		}
		for _, raw := range data {
			clear(raw)
		}
	}()
	for _, name := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"} {
		if ctx.Err() != nil {
			return errLoadBalanceStreamAccount
		}
		file, raw, err := openMemcachedUnixNSSFile(name)
		if err != nil {
			return errLoadBalanceStreamAccount
		}
		sources, data = append(sources, file), append(data, raw)
	}
	if validateLoadBalanceStreamAccountAbsence(data[0], data[1], data[2], data[3]) != nil {
		return errLoadBalanceStreamAccount
	}
	const binary = "/usr/bin/getent"
	if threatIDSTrustedParents("/usr/bin", false) != nil {
		return errLoadBalanceStreamAccount
	}
	before, err := os.Lstat(binary)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 || before.Mode().Perm()&0022 != 0 {
		return errLoadBalanceStreamAccount
	}
	info, ok := before.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != 0 || info.Nlink != 1 {
		return errLoadBalanceStreamAccount
	}
	// Query actual host NSS, not PATH, a shell, caller name or only local files.
	for _, database := range []string{"passwd", "group"} {
		if ctx.Err() != nil {
			return errLoadBalanceStreamAccount
		}
		child, stop := context.WithTimeout(ctx, 3*time.Second)
		cmd := exec.CommandContext(child, binary, database, loadbalancestream.ServiceAccount)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		out, stderr := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
		cmd.Stdout, cmd.Stderr, cmd.WaitDelay = out, stderr, time.Second
		runErr := cmd.Run()
		timedOut := child.Err() != nil
		stop()
		var exit *exec.ExitError
		if timedOut || !errors.As(runErr, &exit) || exit.ExitCode() != 2 || out.String() != "" || stderr.String() != "" {
			return errLoadBalanceStreamAccount
		}
		after, err := os.Lstat(binary)
		if err != nil || !geoStoreStableInfo(before, after) {
			return errLoadBalanceStreamAccount
		}
	}
	for _, file := range sources {
		if !file.current() {
			return errLoadBalanceStreamAccount
		}
	}
	if ctx.Err() != nil || !configuration.current() || threatIDSTrustedParents("/etc", false) != nil {
		return errLoadBalanceStreamAccount
	}
	return nil
}
