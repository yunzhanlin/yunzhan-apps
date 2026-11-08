//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

var errPM2ListenerOwnership = errors.New("PM2 回环监听的账户、进程启动身份及服务归属无法完整核对")

const pm2ListenerMaxProcesses = 128
const pm2ListenerMaxDescriptors = 65536

type pm2ListenerAccount struct{ UID, GID uint32 }

// Read only the exact site's public NSS records. This never provisions an
// account, reads shadow/environment bytes or accepts a caller-selected UID.
func decodePM2ListenerAccount(site, passwd, group string) (pm2ListenerAccount, error) {
	var result pm2ListenerAccount
	if !core.ValidID(site) || len(passwd) > 4096 || len(group) > 4096 ||
		!strings.HasSuffix(passwd, "\n") || strings.Count(passwd, "\n") != 1 ||
		!strings.HasSuffix(group, "\n") || strings.Count(group, "\n") != 1 ||
		strings.ContainsAny(passwd+group, "\x00\r") {
		return result, errPM2ListenerOwnership
	}
	p := strings.Split(strings.TrimSuffix(passwd, "\n"), ":")
	g := strings.Split(strings.TrimSuffix(group, "\n"), ":")
	if len(p) != 7 || len(g) != 4 || p[0] != siteUser(site) || g[0] != p[0] ||
		p[4] != "panel-managed-"+site || p[5] != "/srv/panel/sites/"+site ||
		p[6] != "/usr/sbin/nologin" {
		return result, errPM2ListenerOwnership
	}
	ids := [3]uint64{}
	for index, value := range []string{p[2], p[3], g[2]} {
		n, e := strconv.ParseUint(value, 10, 32)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != value {
			return result, errPM2ListenerOwnership
		}
		ids[index] = n
	}
	if ids[1] != ids[2] {
		return result, errPM2ListenerOwnership
	}
	return pm2ListenerAccount{uint32(ids[0]), uint32(ids[1])}, nil
}

func (s *Service) pm2ListenerAccount(ctx context.Context, app pm2App) (pm2ListenerAccount, error) {
	var empty pm2ListenerAccount
	if !core.ValidID(app.SiteID) {
		return empty, errPM2ListenerOwnership
	}
	passwd, e1 := s.Config.Run(ctx, "/usr/bin/getent", "passwd", siteUser(app.SiteID))
	group, e2 := s.Config.Run(ctx, "/usr/bin/getent", "group", siteUser(app.SiteID))
	account, e3 := decodePM2ListenerAccount(app.SiteID, passwd, group)
	if e1 != nil || e2 != nil || e3 != nil {
		return empty, errPM2ListenerOwnership
	}
	site, err := s.openFiles(app.SiteID)
	if err != nil {
		return empty, errPM2ListenerOwnership
	}
	defer site.Close()
	private, err := site.root.OpenFile("private", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return empty, errPM2ListenerOwnership
	}
	defer private.Close()
	info, err := private.Stat()
	if err != nil {
		return empty, errPM2ListenerOwnership
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || site.uid != int(account.UID) ||
		st.Uid != account.UID || st.Gid != account.GID {
		return empty, errPM2ListenerOwnership
	}
	return account, nil
}

func decodePM2CgroupPIDs(raw []byte) ([]int, error) {
	if len(raw) == 0 || len(raw) > 4096 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r\t ") {
		return nil, errPM2ListenerOwnership
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	if len(lines) > pm2ListenerMaxProcesses {
		return nil, errPM2ListenerOwnership
	}
	ids := make([]int, 0, len(lines))
	seen := map[int]bool{}
	for _, line := range lines {
		n, err := strconv.ParseUint(line, 10, 32)
		if err != nil || n <= 1 || strconv.FormatUint(n, 10) != line || seen[int(n)] {
			return nil, errPM2ListenerOwnership
		}
		seen[int(n)] = true
		ids = append(ids, int(n))
	}
	sort.Ints(ids)
	return ids, nil
}

func pm2ListenerProcessStatus(raw []byte, identity taskProcessIdentity, account pm2ListenerAccount) error {
	if !identity.SafeUser || identity.UID != account.UID || !taskSafeProcessStatus(string(raw), account.UID) {
		return errPM2ListenerOwnership
	}
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key != "Gid" {
			continue
		}
		if seen {
			return errPM2ListenerOwnership
		}
		seen = true
		fields := strings.Fields(value)
		if len(fields) != 4 {
			return errPM2ListenerOwnership
		}
		for _, field := range fields {
			if field != strconv.FormatUint(uint64(account.GID), 10) {
				return errPM2ListenerOwnership
			}
		}
	}
	if !seen {
		return errPM2ListenerOwnership
	}
	return nil
}

// Tables cover every listener that could receive the IPv4 loopback probe.
// Wildcard and mapped IPv6 bindings are not silently adopted as loopback-only.
// An unrelated exact address at the same port cannot intercept this probe.
func pm2LoopbackListeners(tables map[string][]byte, port int, uid uint32) (map[string]loadBalanceStreamHostSocket, error) {
	if port < 1024 || port > 65535 || uid == 0 {
		return nil, errPM2ListenerOwnership
	}
	result := map[string]loadBalanceStreamHostSocket{}
	if _, ok := tables["tcp"]; !ok {
		return nil, errPM2ListenerOwnership
	}
	for protocol, raw := range tables {
		if protocol != "tcp" && protocol != "tcp6" {
			return nil, errPM2ListenerOwnership
		}
		rows, err := decodeStreamSocketTable(raw, protocol)
		if err != nil {
			return nil, errPM2ListenerOwnership
		}
		for _, row := range rows {
			if row.State != 10 || int(row.Local.Port()) != port {
				continue
			}
			addr := row.Local.Addr()
			relevant := addr.IsUnspecified() || addr.Unmap() == netip.MustParseAddr("127.0.0.1")
			if !relevant {
				continue
			}
			if protocol != "tcp" || addr != netip.MustParseAddr("127.0.0.1") || row.UID != uid || row.Inode == 0 {
				return nil, errPM2ListenerOwnership
			}
			key := strconv.FormatUint(row.Inode, 10)
			if _, duplicate := result[key]; duplicate {
				return nil, errPM2ListenerOwnership
			}
			result[key] = row
		}
	}
	if len(result) == 0 {
		return nil, errPM2ListenerOwnership
	}
	return result, nil
}

type pm2ListenerWitness struct {
	Unit      pm2UnitState
	Group     string
	Account   pm2ListenerAccount
	Manifest  []byte
	PIDs      []int
	Processes map[int]taskProcessIdentity
	Listeners map[string]loadBalanceStreamHostSocket
	Owners    map[string]int
	pidfds    map[int]int
}

func (w *pm2ListenerWitness) Close() {
	for _, fd := range w.pidfds {
		_ = unix.Close(fd)
	}
	w.pidfds = nil
}
func (w *pm2ListenerWitness) live() bool {
	for pid, fd := range w.pidfds {
		current, err := compilerPIDFDTask(fd)
		if err != nil || current != pid {
			return false
		}
	}
	return true
}

func (s *Service) pm2ListenerTables() (map[string][]byte, error) {
	tables := map[string][]byte{}
	for _, protocol := range []string{"tcp", "tcp6"} {
		raw, err := readModuleProcFile(s.systemPath("/proc/net/"+protocol), streamSocketTableBytes)
		if errors.Is(err, os.ErrNotExist) && protocol == "tcp6" {
			continue
		}
		if err != nil {
			return nil, errPM2ListenerOwnership
		}
		tables[protocol] = raw
	}
	return tables, nil
}

func (s *Service) capturePM2Listener(ctx context.Context, unit string, port int) (result *pm2ListenerWitness, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	canonical := strings.TrimSuffix(unit, ".service") + ".service"
	id := strings.TrimSuffix(strings.TrimPrefix(canonical, "panel-pm2@"), ".service")
	if !moduleResourceID.MatchString(id) || canonical != "panel-pm2@"+id+".service" {
		return nil, errPM2ListenerOwnership
	}
	raw, err := s.pm2ConfigLiveBytes(id)
	if err != nil {
		return nil, errPM2ListenerOwnership
	}
	app, err := pm2ConfigApp(raw)
	if err != nil || app.ID != id || app.Port != port {
		return nil, errPM2ListenerOwnership
	}
	account, err := s.pm2ListenerAccount(ctx, app)
	if err != nil {
		return nil, err
	}
	state, err := s.readPM2UnitState(ctx, canonical)
	if err != nil || state.ActiveState != "active" {
		return nil, errPM2ListenerOwnership
	}
	groupRaw, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", canonical, "--property=ControlGroup")
	if err != nil || len(groupRaw) > 8192 || strings.Count(groupRaw, "\n") != 1 || !strings.HasSuffix(groupRaw, "\n") {
		return nil, errPM2ListenerOwnership
	}
	group, ok := strings.CutPrefix(strings.TrimSuffix(groupRaw, "\n"), "ControlGroup=")
	managed, checkedGroup, valid := taskManagedCgroup("0::" + group + "\n")
	if !ok || !valid || managed != canonical || checkedGroup != group {
		return nil, errPM2ListenerOwnership
	}
	procs := s.systemPath("/sys/fs/cgroup" + group + "/cgroup.procs")
	pidsRaw, err := readModuleProcFile(procs, 4096)
	if err != nil {
		return nil, errPM2ListenerOwnership
	}
	pids, err := decodePM2CgroupPIDs(pidsRaw)
	if err != nil {
		return nil, err
	}
	main, err := strconv.Atoi(state.MainPID)
	if err != nil || !sortContainsPM2PID(pids, main) {
		return nil, errPM2ListenerOwnership
	}
	w := &pm2ListenerWitness{Unit: state, Group: group, Account: account, Manifest: raw, PIDs: pids, Processes: map[int]taskProcessIdentity{}, Owners: map[string]int{}, pidfds: map[int]int{}}
	defer func() {
		if err != nil {
			w.Close()
		}
	}()
	root := s.systemPath("/proc")
	for _, pid := range pids {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if root == "/proc" {
			fd, e := unix.PidfdOpen(pid, 0)
			if e != nil {
				return nil, errPM2ListenerOwnership
			}
			w.pidfds[pid] = fd
		}
		identity, e := readTaskProcessIdentity(root, pid)
		if e != nil || identity.Unit != canonical || identity.Cgroup != group {
			return nil, errPM2ListenerOwnership
		}
		status, e := readModuleProcFile(filepath.Join(root, strconv.Itoa(pid), "status"), 16384)
		if e != nil || pm2ListenerProcessStatus(status, identity, account) != nil {
			return nil, errPM2ListenerOwnership
		}
		w.Processes[pid] = identity
	}
	binary := s.systemPath(pm2NodeBinaryOn(runtimecatalog.HostPlatform()))
	if err = verifyPM2ListenerExecutable(ctx, root, binary, w.Processes[main], account.GID); err != nil {
		return nil, err
	}
	tables, err := s.pm2ListenerTables()
	if err != nil {
		return nil, err
	}
	w.Listeners, err = pm2LoopbackListeners(tables, port, account.UID)
	if err != nil {
		return nil, err
	}
	descriptors := 0
	for _, pid := range pids {
		sockets, count, e := pm2ListenerProcessSockets(ctx, root, w.Processes[pid], account.GID)
		if e != nil {
			return nil, e
		}
		descriptors += count
		if descriptors > pm2ListenerMaxDescriptors {
			return nil, errPM2ListenerOwnership
		}
		for inode := range w.Listeners {
			if sockets[inode] {
				w.Owners[inode] = pid
			}
		}
		if len(w.Owners) == len(w.Listeners) {
			break
		}
	}
	if len(w.Owners) != len(w.Listeners) || !w.live() {
		return nil, errPM2ListenerOwnership
	}
	againRaw, e := readModuleProcFile(procs, 4096)
	again, e2 := decodePM2CgroupPIDs(againRaw)
	if e != nil || e2 != nil || !reflect.DeepEqual(pids, again) {
		return nil, errPM2ListenerOwnership
	}
	for pid, before := range w.Processes {
		current, e := readTaskProcessIdentity(root, pid)
		if e != nil || current != before {
			return nil, errPM2ListenerOwnership
		}
	}
	return w, nil
}

func sortContainsPM2PID(ids []int, pid int) bool {
	i := sort.SearchInts(ids, pid)
	return i < len(ids) && ids[i] == pid
}

// Two complete, positively owned observations bracket the only TCP connect.
// No HTTP/body, environment contents or signal is sent, and no UID-only or
// unit-name-only observation can claim a listener.
func (s *Service) verifyPM2OwnedLoopback(ctx context.Context, unit string, port int) error {
	before, err := s.capturePM2Listener(ctx, unit, port)
	if err != nil {
		return err
	}
	defer before.Close()
	conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return errPM2ListenerOwnership
	}
	_ = conn.Close()
	after, err := s.capturePM2Listener(ctx, unit, port)
	if err != nil {
		return err
	}
	defer after.Close()
	if !before.live() || !after.live() || before.Unit != after.Unit || before.Group != after.Group || before.Account != after.Account ||
		!bytes.Equal(before.Manifest, after.Manifest) || !reflect.DeepEqual(before.PIDs, after.PIDs) || !reflect.DeepEqual(before.Processes, after.Processes) || !reflect.DeepEqual(before.Listeners, after.Listeners) {
		return errPM2ListenerOwnership
	}
	return nil
}
