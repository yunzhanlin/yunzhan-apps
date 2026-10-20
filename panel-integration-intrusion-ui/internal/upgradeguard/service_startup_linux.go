//go:build linux

package upgradeguard

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// CheckServiceStartup is a read-only, out-of-process interlock. Unlike a guard
// compiled into the selected daemon, it protects retained older binaries too.
// It is not recovery: an orphaned marker blocks startup until a trusted
// transaction has restored or committed the program and data together.
func CheckServiceStartup(unit string) error {
	kind, recovery, err := startupService(unit)
	if err != nil {
		return err
	}
	var pending string
	for _, path := range []string{Marker, DevelopmentMarker} {
		blocked, err := serviceMarkerBlocked(path)
		if err != nil {
			return err
		}
		if blocked {
			if pending != "" {
				return errors.New("multiple upgrade markers; service startup refused")
			}
			pending = path
		}
	}
	if recovery && pending != "" {
		return errors.New("database recovery cannot start during program maintenance")
	}
	program, err := selectedServiceProgram(kind, pending)
	if err != nil {
		return err
	}
	if pending == "" {
		file, err := selectedStartupFile(program)
		if err != nil {
			return err
		}
		return file.Close()
	}
	lock := "/opt/panel/releases/.release.lock"
	if pending == DevelopmentMarker {
		lock = "/opt/panel/.development-update.lock"
	}
	return serviceStartupAt(pending, lock, program, kind)
}

func startupService(unit string) (kind string, recovery bool, err error) {
	switch unit {
	case "panel.service":
		return "panel", false, nil
	case "panel-executor.service", "panel-terminal.service", "panel-terminal-root.service":
		return "panel-executor", false, nil
	case "panel-mysql-overwrite-recovery.service":
		return "panel-executor", true, nil
	default:
		return "", false, errors.New("service startup outside fixed program scope")
	}
}

func serviceMarkerBlocked(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if !os.IsNotExist(err) {
		return true, errors.New("upgrade marker state unavailable")
	}
	// Missing layout-specific directories are permitted, but any existing
	// linked, foreign or writable parent makes absence untrustworthy.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var st unix.Stat_t
		err := unix.Lstat(parent, &st)
		if err != nil && !os.IsNotExist(err) {
			return true, errors.New("upgrade marker parent unavailable")
		}
		if err == nil && (st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0) {
			return true, errors.New("untrusted upgrade marker parent")
		}
		if parent == "/" {
			return false, nil
		}
	}
}

func selectedServiceProgram(kind, pending string) (string, error) {
	const current = "/opt/panel/current"
	const releases = "/opt/panel/releases"
	var st unix.Stat_t
	err := unix.Lstat(current, &st)
	if err != nil && !os.IsNotExist(err) {
		return "", errors.New("selected program layout unavailable")
	}
	if err == nil {
		if pending == DevelopmentMarker || st.Mode&unix.S_IFMT != unix.S_IFLNK || st.Uid != 0 || st.Nlink != 1 {
			return "", errors.New("unsafe or ambiguous selected program pointer")
		}
		if err := trustedStartupParents(current); err != nil {
			return "", err
		}
		target, err := os.Readlink(current)
		if err != nil || filepath.Dir(target) != releases || !startupVersion.MatchString(filepath.Base(target)) || filepath.Clean(target) != target {
			return "", errors.New("selected program pointer outside retained releases")
		}
		return filepath.Join(target, "bin", kind), nil
	}
	if pending == Marker {
		return "", errors.New("production maintenance lacks a selected release")
	}
	return filepath.Join("/opt/panel/bin", kind), nil
}

func selectedStartupFile(path string) (*os.File, error) {
	if err := trustedStartupParents(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("selected startup program unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0755 || st.Uid != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > 256*1024*1024 {
		file.Close()
		return nil, errors.New("selected startup program is not a public root-controlled payload")
	}
	return file, nil
}

func serviceStartupAt(marker, lock, program, kind string) error {
	return startupVerifyAt(marker, lock, func() (string, error) {
		file, err := selectedStartupFile(program)
		if err != nil {
			return "", err
		}
		defer file.Close()
		var before, after unix.Stat_t
		if unix.Fstat(int(file.Fd()), &before) != nil {
			return "", errors.New("selected startup program identity unavailable")
		}
		digest, err := startupProgramSHA(file)
		if err != nil {
			return "", err
		}
		if unix.Lstat(program, &after) != nil || !sameStartupStat(before, after) {
			return "", errors.New("selected startup program changed during verification")
		}
		return digest, nil
	}, kind)
}
