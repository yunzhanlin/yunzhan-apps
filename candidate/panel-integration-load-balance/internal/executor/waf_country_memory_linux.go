//go:build linux

package executor

import (
	"bytes"
	"context"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"local/panel/internal/geodata"
)

// Kernel-provided cgroup membership is a read target, not caller-supplied
// authority. No path from HTTP/configuration, unit property or environment is
// used. Inspect every ancestor of BOTH the syntax-check caller and the actual
// selected Nginx master; the two processes can have different service limits.
func wafCountryMemoryCgroup(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 || !bytes.HasPrefix(raw, []byte("0::/")) || bytes.Count(raw, []byte{'\n'}) != 1 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return "", errWAFCountryMemoryInventory
	}
	name := string(raw[3 : len(raw)-1])
	if path.Clean(name) != name || strings.Count(name, "/") > 32 {
		return "", errWAFCountryMemoryInventory
	}
	for _, c := range name {
		if c != '/' && c != '-' && c != '_' && c != '.' && c != '@' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return "", errWAFCountryMemoryInventory
		}
	}
	return name, nil
}

func wafCountryMemoryRead(file string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(file, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errWAFCountryMemoryInventory
	}
	return raw, nil
}

func probeWAFCountryMemory(ctx context.Context, pid int, budget wafCountryMemoryBudget) error {
	if ctx == nil || os.Geteuid() != 0 || pid <= 1 {
		return errWAFCountryMemoryInventory
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	process, err := readWAFReloadProcess("/proc", pid)
	if err != nil || process.State == "Z" || process.State == "X" {
		return errWAFCountryMemoryInventory
	}
	status, err := wafCountryMemoryRead("/proc/"+strconv.Itoa(pid)+"/status", 64<<10)
	if err != nil {
		return errWAFCountryMemoryInventory
	}
	budget, err = wafCountryMemoryWithMaster(budget, status)
	if err != nil {
		return err
	}
	memberships := map[int][]byte{}
	needs := map[string]uint64{}
	for _, subject := range []struct {
		id   int
		need uint64
	}{{os.Getpid(), budget.Parser + wafCountryMemoryUnitReserve}, {pid, budget.Reload + wafCountryMemoryUnitReserve}} {
		raw, err := wafCountryMemoryRead("/proc/"+strconv.Itoa(subject.id)+"/cgroup", 4096)
		if err != nil {
			return errWAFCountryMemoryInventory
		}
		name, err := wafCountryMemoryCgroup(raw)
		if err != nil {
			return err
		}
		memberships[subject.id] = raw
		need := subject.need
		for {
			if needs[name] < need {
				needs[name] = need
			}
			if name == "/" {
				break
			}
			name = path.Dir(name)
			need = budget.Host // Shared ancestors must retain the host reserve.
		}
	}
	root, err := os.OpenRoot("/sys/fs/cgroup")
	if err != nil {
		return errWAFCountryMemoryInventory
	}
	defer root.Close()
	mount, err := root.Open(".")
	if err != nil {
		return errWAFCountryMemoryInventory
	}
	var filesystem unix.Statfs_t
	ferr := unix.Fstatfs(int(mount.Fd()), &filesystem)
	info, serr := mount.Stat()
	mount.Close()
	if ferr != nil || serr != nil || filesystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return errWAFCountryMemoryInventory
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != 0 {
		return errWAFCountryMemoryInventory
	}
	read := func(name string, limit int64) ([]byte, error) {
		f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil || int64(len(raw)) > limit {
			return nil, errWAFCountryMemoryInventory
		}
		return raw, nil
	}
	groups := make([]string, 0, len(needs))
	for group := range needs {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	for _, group := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		prefix := strings.TrimPrefix(group, "/")
		if prefix != "" {
			prefix += "/"
		}
		maximum, e1 := read(prefix+"memory.max", 32)
		high, e2 := read(prefix+"memory.high", 32)
		current, e3 := read(prefix+"memory.current", 32)
		if group == "/" && os.IsNotExist(e1) && os.IsNotExist(e2) && os.IsNotExist(e3) {
			_, typeError := read("cgroup.type", 32)
			controllers, err := read("cgroup.controllers", 4096)
			if err != nil || runtimePHPCompilerMemoryUncontrolledRoot(native.Ino, controllers, true, true, os.IsNotExist(typeError)) != nil {
				return errWAFCountryMemoryInventory
			}
			continue
		}
		if e1 != nil || e2 != nil || e3 != nil {
			return errWAFCountryMemoryInventory
		}
		if err := wafCountryGroupMemoryAdmission(maximum, high, current, needs[group]); err != nil {
			return err
		}
		// Limits cannot be substituted during an apparently successful read.
		m2, e1 := read(prefix+"memory.max", 32)
		h2, e2 := read(prefix+"memory.high", 32)
		c2, e3 := read(prefix+"memory.current", 32)
		if e1 != nil || e2 != nil || e3 != nil || !bytes.Equal(maximum, m2) || !bytes.Equal(high, h2) {
			return errWAFCountryMemoryInventory
		}
		if err := wafCountryGroupMemoryAdmission(m2, h2, c2, needs[group]); err != nil {
			return err
		}
	}
	for id, before := range memberships {
		after, err := wafCountryMemoryRead("/proc/"+strconv.Itoa(id)+"/cgroup", 4096)
		if err != nil || !bytes.Equal(before, after) {
			return errWAFCountryMemoryInventory
		}
	}
	after, err := readWAFReloadProcess("/proc", pid)
	if err != nil || after.PID != process.PID || after.Start != process.Start || after.Parent != process.Parent || after.State == "Z" || after.State == "X" {
		return errWAFCountryMemoryInventory
	}
	host, err := wafCountryMemoryRead("/proc/meminfo", 64<<10)
	if err != nil {
		return errWAFCountryMemoryInventory
	}
	if err := wafCountryHostMemoryAdmission(host, budget); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *Service) admitWAFCountryMemory(ctx context.Context, nginx string, metadata geodata.CountrySelectionMetadata) error {
	if s.Config.SystemRoot != "/" || s.Config.SitesDir != "/srv/panel/sites" || s.Config.SecurityDir != "/etc/panel/security-apps" || ctx == nil {
		return errWAFCountryMemoryInventory
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	budget, err := wafCountryReloadMemoryBudget(metadata)
	if err != nil {
		return err
	}
	pid, err := s.wafNginxPID(ctx, nginx)
	if err != nil {
		return err
	}
	return probeWAFCountryMemory(ctx, pid, budget)
}
