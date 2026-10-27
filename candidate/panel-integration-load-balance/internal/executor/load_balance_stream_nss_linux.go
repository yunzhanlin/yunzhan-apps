//go:build linux

package executor

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/loadbalancestream"
)

// This only observes fixed Root-owned NSS files and independently resolves the
// fixed name through the host's actual getent/id NSS implementation. No useradd,
// permission change, repair, receipt creation, unit installation or adoption.
func loadBalanceStreamSystemIdentity(ctx context.Context) (loadBalanceStreamIdentity, error) {
	var empty loadBalanceStreamIdentity
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || threatIDSTrustedParents("/etc", false) != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	configuration, err := holdLoadBalanceStreamNSSConfiguration(ctx)
	if err != nil {
		return empty, err
	}
	defer configuration.close()
	var sources []*memcachedUnixNSSFile
	var data [][]byte
	defer func() {
		for _, source := range sources {
			source.file.Close()
		}
		for _, raw := range data {
			clear(raw)
		}
	}()
	for _, name := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"} {
		if ctx.Err() != nil {
			return empty, errLoadBalanceStreamIdentity
		}
		file, raw, err := openMemcachedUnixNSSFile(name)
		if err != nil {
			return empty, errLoadBalanceStreamIdentity
		}
		sources = append(sources, file)
		data = append(data, raw)
	}
	identity, err := validateLoadBalanceStreamNSS(data[0], data[1], data[2], data[3])
	if err != nil {
		return empty, err
	}
	command := func(binary string, args ...string) (string, error) {
		if ctx.Err() != nil || threatIDSTrustedParents("/usr/bin", false) != nil {
			return "", errLoadBalanceStreamIdentity
		}
		// Fixed OS tools, never PATH selection, a caller path or shell source.
		info, err := os.Lstat(binary)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 || info.Mode().Perm()&0022 != 0 {
			return "", errLoadBalanceStreamIdentity
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || stat.Nlink != 1 {
			return "", errLoadBalanceStreamIdentity
		}
		child, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(child, binary, args...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
		output, errors := &boundedBuffer{max: 8192}, &boundedBuffer{max: 8192}
		cmd.Stdout = output
		cmd.Stderr = errors
		cmd.WaitDelay = time.Second
		if cmd.Run() != nil || child.Err() != nil || errors.String() != "" || len(output.String()) == 0 || len(output.String()) >= 8192 {
			return "", errLoadBalanceStreamIdentity
		}
		visible, err := os.Lstat(binary)
		if err != nil || !geoStoreStableInfo(info, visible) {
			return "", errLoadBalanceStreamIdentity
		}
		return output.String(), nil
	}
	name := loadbalancestream.ServiceAccount
	for _, kind := range []string{"passwd", "group"} {
		output, err := command("/usr/bin/getent", kind, name)
		if err != nil {
			return empty, err
		}
		fields := 7
		index := 0
		if kind == "group" {
			fields = 4
			index = 1
		}
		rows, err := memcachedUnixNSSRows(data[index], fields)
		if err != nil {
			return empty, errLoadBalanceStreamIdentity
		}
		expected := ""
		for _, row := range rows {
			if row[0] == name {
				expected = strings.Join(row, ":") + "\n"
			}
		}
		if expected == "" || output != expected {
			return empty, errLoadBalanceStreamIdentity
		}
	}
	groups, err := command("/usr/bin/id", "-G", name)
	if err != nil || groups != strconv.FormatUint(uint64(identity.GID), 10)+"\n" {
		return empty, errLoadBalanceStreamIdentity
	}
	for _, source := range sources {
		if !source.current() {
			return empty, errLoadBalanceStreamIdentity
		}
		stat := source.before.Sys().(*syscall.Stat_t)
		if source.private && source.before.Mode().Perm()&0040 != 0 && stat.Gid == identity.GID {
			return empty, errLoadBalanceStreamIdentity
		}
	}
	if ctx.Err() != nil || !configuration.current() || threatIDSTrustedParents("/etc", false) != nil {
		return empty, errLoadBalanceStreamIdentity
	}
	return identity, nil
}
