//go:build linux

package upgradeguard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type startupRecord struct {
	Format      int    `json:"format"`
	Version     string `json:"version"`
	PID         int    `json:"pid"`
	StartTicks  uint64 `json:"start_ticks"`
	BootID      string `json:"boot_id"`
	LockDevice  uint64 `json:"lock_device"`
	LockInode   uint64 `json:"lock_inode"`
	Phase       string `json:"phase"`
	PanelSHA    string `json:"panel_sha256"`
	ExecutorSHA string `json:"executor_sha256"`
}

var startupVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+([.-][a-z0-9]+)*$`)
var startupBoot = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
var startupSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sameStartupStat(a, b unix.Stat_t) bool {
	// Reads can advance atime, but cannot change identity, bytes or authority.
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// CheckStartup must run before database migration/recovery or daemon recovery.
// A retained marker alone is never authority. The exact root installer must
// still own the recorded exclusive FLOCK in this boot, with a non-reused PID,
// and have explicitly authorized the bytes of this program. Workers and HTTP
// mutations remain blocked until the marker disappears. This is not a durable
// recovery procedure or a guarantee against installer death during migration.
func CheckStartup() error {
	var pending string
	for _, path := range []string{Marker, DevelopmentMarker} {
		if !blockedAt(path) {
			continue
		}
		if pending != "" {
			return errors.New("multiple or unsafe program upgrade markers; startup refused")
		}
		pending = path
	}
	if pending == "" {
		return nil
	}
	lock := "/opt/panel/releases/.release.lock"
	if pending == DevelopmentMarker {
		lock = "/opt/panel/.development-update.lock"
	}
	return startupAt(pending, lock)
}

func parseStartup(raw []byte) (startupRecord, error) {
	var result startupRecord
	allowed := map[string]bool{"format": true, "version": true, "pid": true, "start_ticks": true, "boot_id": true, "lock_device": true, "lock_inode": true, "phase": true, "panel_sha256": true, "executor_sha256": true}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return result, errors.New("invalid startup authorization")
	}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return result, errors.New("unknown or duplicate startup authorization field")
		}
		seen[name] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return result, errors.New("invalid startup authorization value")
		}
	}
	if _, err := decoder.Token(); err != nil || len(seen) != len(allowed) {
		return result, errors.New("incomplete startup authorization")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || json.Unmarshal(raw, &result) != nil {
		return result, errors.New("invalid startup authorization suffix or type")
	}
	if result.Format != 2 || !startupVersion.MatchString(result.Version) || result.PID <= 1 || result.StartTicks == 0 || !startupBoot.MatchString(result.BootID) || result.LockInode == 0 || result.Phase != "program-start" || !startupSHA.MatchString(result.PanelSHA) || !startupSHA.MatchString(result.ExecutorSHA) {
		return result, errors.New("unsupported startup authorization")
	}
	return result, nil
}

func trustedStartupParents(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var st unix.Stat_t
		if err := unix.Lstat(parent, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return errors.New("untrusted startup authorization parent")
		}
		if parent == "/" {
			return nil
		}
	}
}

func startupFile(path string) ([]byte, unix.Stat_t, error) {
	var before, after, linked unix.Stat_t
	if err := trustedStartupParents(path); err != nil {
		return nil, before, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, before, errors.New("startup authorization unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Nlink != 1 || before.Mode&0777 != 0644 || before.Size > 2048 || before.Size <= 0 {
		return nil, before, errors.New("unsafe startup authorization file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 2049))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fd, &after) != nil || unix.Lstat(path, &linked) != nil || !sameStartupStat(before, after) || !sameStartupStat(after, linked) {
		return nil, before, errors.New("startup authorization changed")
	}
	return raw, before, nil
}

func procRead(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("kernel startup evidence unavailable")
	}
	defer file.Close()
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, errors.New("startup evidence is not procfs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("startup kernel evidence exceeds budget")
	}
	return raw, nil
}

func processTicks(raw []byte, pid int) (uint64, error) {
	text := string(raw)
	end := strings.LastIndex(text, ") ")
	if !strings.HasPrefix(text, strconv.Itoa(pid)+" (") || end < 0 {
		return 0, errors.New("invalid startup process identity")
	}
	fields := strings.Fields(text[end+2:])
	// fields[0] is stat field 3 (state); field 22 is index 19.
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
		return 0, errors.New("startup owner is not live")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errors.New("invalid startup process start time")
	}
	return ticks, nil
}

func ownsStartupLock(raw []byte, record startupRecord) bool {
	expected := fmt.Sprintf("%x:%x:%d", unix.Major(record.LockDevice), unix.Minor(record.LockDevice), record.LockInode)
	matches := 0
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 8 && fields[1] == "FLOCK" && fields[2] == "ADVISORY" && fields[3] == "WRITE" && fields[4] == strconv.Itoa(record.PID) && fields[6] == "0" && fields[7] == "EOF" {
			parts := strings.Split(fields[5], ":")
			if len(parts) != 3 {
				continue
			}
			major, e1 := strconv.ParseUint(parts[0], 16, 32)
			minor, e2 := strconv.ParseUint(parts[1], 16, 32)
			inode, e3 := strconv.ParseUint(parts[2], 10, 64)
			if e1 == nil && e2 == nil && e3 == nil && fmt.Sprintf("%x:%x:%d", major, minor, inode) == expected {
				matches++
			}
		}
	}
	return matches == 1
}

func ownerLive(record startupRecord, lock string) error {
	if err := trustedStartupParents(lock); err != nil {
		return err
	}
	var info unix.Stat_t
	if unix.Lstat(lock, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&0777 != 0600 || info.Uid != 0 || info.Nlink != 1 || info.Dev != record.LockDevice || info.Ino != record.LockInode {
		return errors.New("startup lock identity changed")
	}
	boot, err := procRead("/proc/sys/kernel/random/boot_id", 128)
	if err != nil || strings.TrimSpace(string(boot)) != record.BootID {
		return errors.New("startup authorization belongs to another boot")
	}
	process := "/proc/" + strconv.Itoa(record.PID)
	status, err := procRead(process+"/status", 65536)
	if err != nil {
		return err
	}
	rootOwner := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 5 && fields[0] == "Uid:" && strings.Join(fields[1:], " ") == "0 0 0 0" {
			rootOwner = true
		}
	}
	if !rootOwner {
		return errors.New("startup owner is not the root installer")
	}
	processStat, err := procRead(process+"/stat", 65536)
	if err != nil {
		return err
	}
	ticks, err := processTicks(processStat, record.PID)
	if err != nil || ticks != record.StartTicks {
		return errors.New("startup owner exited or PID was reused")
	}
	locks, err := procRead("/proc/locks", 4*1024*1024)
	if err != nil || !ownsStartupLock(locks, record) {
		return errors.New("root installer no longer holds its exclusive startup lease")
	}
	return nil
}

func runningProgramSHA() (string, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return "", errors.New("running program identity unavailable")
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Uid != 0 || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Nlink != 1 || before.Size <= 0 || before.Size > 256*1024*1024 {
		return "", errors.New("running program is not a retained root-controlled payload")
	}
	deadline := time.Now().Add(5 * time.Second)
	digest, buffer := sha256.New(), make([]byte, 1024*1024)
	var size int64
	for {
		if time.Now().After(deadline) {
			return "", errors.New("startup program verification exceeded deadline")
		}
		n, err := file.Read(buffer)
		digest.Write(buffer[:n])
		size += int64(n)
		if size > before.Size {
			return "", errors.New("startup program grew")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	if size != before.Size || unix.Fstat(int(file.Fd()), &after) != nil || !sameStartupStat(before, after) {
		return "", errors.New("running program changed")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func startupAt(marker, lock string) error {
	raw, info, err := startupFile(marker)
	if err != nil {
		return err
	}
	record, err := parseStartup(raw)
	if err != nil {
		return err
	}
	if err := ownerLive(record, lock); err != nil {
		return err
	}
	digest, err := runningProgramSHA()
	if err != nil || (digest != record.PanelSHA && digest != record.ExecutorSHA) {
		return errors.New("running program was not authorized by the active transaction")
	}
	if err := ownerLive(record, lock); err != nil {
		return err
	}
	after, latest, err := startupFile(marker)
	if err != nil || !bytes.Equal(raw, after) || !sameStartupStat(info, latest) {
		return errors.New("startup authority changed during verification")
	}
	return nil
}
