//go:build linux

package upgradeguard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// MaintenanceRead is an ephemeral read-only witness, not startup, migration,
// recovery or application-control authority. It never acquires a lock, writes
// a marker or accepts caller-selected paths/PIDs. The actual parent installer
// must still own BOTH existing exclusive kernel leases in this boot.
type MaintenanceRead struct {
	marker, other, release, runtime string
	raw                             []byte
	info                            unix.Stat_t
	owners                          [2]startupRecord
	pidfd                           int
}

func HoldMaintenanceRead(ctx context.Context) (*MaintenanceRead, error) {
	production, development := blockedAt(Marker), blockedAt(DevelopmentMarker)
	if production == development {
		return nil, errors.New("read-only maintenance requires one owned pending upgrade")
	}
	marker, other, release := Marker, DevelopmentMarker, "/opt/panel/releases/.release.lock"
	if development {
		marker, other, release = DevelopmentMarker, Marker, "/opt/panel/.development-update.lock"
	}
	return holdMaintenanceReadAt(ctx, marker, other, release, "/var/lib/panel-executor/runtime-lifecycle.lock")
}

// Private fixed-root fixture seam only. Exported production admission above
// has no path, PID, environment or alternate-root override.
func holdMaintenanceReadAt(ctx context.Context, marker, other, release, runtime string) (*MaintenanceRead, error) {
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || blockedAt(other) {
		return nil, errors.New("read-only maintenance owner unavailable")
	}
	raw, info, err := startupFile(marker)
	if err != nil {
		return nil, err
	}
	pid := os.Getppid()
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil || pid <= 1 {
		if err == nil {
			unix.Close(fd)
		}
		return nil, errors.New("read-only maintenance parent unavailable")
	}
	w := &MaintenanceRead{marker: marker, other: other, release: release, runtime: runtime, raw: raw, info: info, pidfd: fd}
	fail := func(err error) (*MaintenanceRead, error) { w.Close(); return nil, err }
	boot, err := procRead("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || !startupBoot.MatchString(strings.TrimSpace(string(boot))) {
		return fail(errors.New("read-only maintenance boot unavailable"))
	}
	process, err := procRead("/proc/"+strconv.Itoa(pid)+"/stat", 65536)
	if err != nil {
		return fail(err)
	}
	ticks, err := processTicks(process, pid)
	if err != nil {
		return fail(err)
	}
	for i, lock := range []string{release, runtime} {
		var st unix.Stat_t
		if err := unix.Lstat(lock, &st); err != nil {
			return fail(err)
		}
		w.owners[i] = startupRecord{PID: pid, StartTicks: ticks, BootID: strings.TrimSpace(string(boot)), LockDevice: st.Dev, LockInode: st.Ino}
	}
	if bytes.HasPrefix(raw, []byte("version=")) {
		version := strings.TrimSuffix(strings.TrimPrefix(string(raw), "version="), "\n")
		if !startupVersion.MatchString(version) || string(raw) != "version="+version+"\n" {
			return fail(errors.New("invalid plain maintenance marker"))
		}
	} else {
		r, err := parseStartup(raw)
		o := w.owners[0]
		if err != nil || r.PID != o.PID || r.StartTicks != o.StartTicks || r.BootID != o.BootID || r.LockDevice != o.LockDevice || r.LockInode != o.LockInode {
			return fail(errors.New("maintenance startup record is not owned by the actual parent"))
		}
	}
	if err := w.Current(ctx); err != nil {
		return fail(err)
	}
	return w, nil
}

func (w *MaintenanceRead) Current(ctx context.Context) error {
	if w == nil || w.pidfd < 0 || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getppid() != w.owners[0].PID || blockedAt(w.other) {
		return errors.New("read-only maintenance witness no longer current")
	}
	poll := []unix.PollFd{{Fd: int32(w.pidfd), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 0); err != nil || n != 0 || poll[0].Revents != 0 {
		return errors.New("read-only maintenance parent exited")
	}
	for i, lock := range []string{w.release, w.runtime} {
		if err := ownerLive(w.owners[i], lock); err != nil {
			return err
		}
	}
	raw, info, err := startupFile(w.marker)
	if err != nil || !sameStartupStat(w.info, info) || !bytes.Equal(w.raw, raw) || ctx.Err() != nil {
		return errors.New("read-only maintenance marker changed")
	}
	return nil
}

func (w *MaintenanceRead) Close() {
	if w == nil {
		return
	}
	if w.pidfd >= 0 {
		unix.Close(w.pidfd)
		w.pidfd = -1
	}
	clear(w.raw)
	w.raw = nil
}
