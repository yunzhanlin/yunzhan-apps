//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type threatIDSUnitRecord struct {
	Format      int    `json:"format"`
	Guard       string `json:"guard"`
	Prefix      string `json:"prefix"`
	UnitSHA     string `json:"unit_sha256"`
	RecoverySHA string `json:"recovery_sha256"`
}

func (s *Service) threatIDSUnitRecord(runtime threatIDSRuntime) (threatIDSUnitRecord, error) {
	var v threatIDSUnitRecord
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json"), 4096)
	if err != nil {
		return v, err
	}
	if decodeThreatIDSPrivateJSON(b, &v) != nil {
		return v, errors.New("IDS 单元来源记录损坏")
	}
	unit, unitErr := threatIDSGatedUnit(runtime.Prefix, v.Guard, runtime.Format == 3)
	recovery, recoveryErr := threatIDSRecoverySource(v.Guard, v.RecoverySHA)
	syntax, syntaxErr := threatIDSSyntaxUnit(runtime.Prefix, runtime.Format == 3)
	legacyBudget, legacyErr := threatIDSLegacySyntaxUnitV3(runtime.Prefix)
	if v.Format != 1 || v.Prefix != runtime.Prefix || unitErr != nil || recoveryErr != nil || syntaxErr != nil || v.UnitSHA != fmt.Sprintf("%x", sha256.Sum256([]byte(unit))) || v.RecoverySHA != fmt.Sprintf("%x", sha256.Sum256([]byte(recovery))) {
		return v, errors.New("IDS 单元来源或固定权限策略不符")
	}
	for path, wanted := range map[string]string{"/etc/systemd/system/panel-network-ids.service": unit, "/etc/systemd/system/panel-network-ids-recover.service": recovery, "/etc/systemd/system/panel-network-ids-check.service": syntax} {
		full := s.systemPath(path)
		if err := threatIDSTrustedParents(filepath.Dir(full), false); err != nil {
			return v, err
		}
		actual, err := apacheWAFReadStableFile(full, 32<<10)
		info, statErr := os.Lstat(full)
		knownLegacyCheck := runtime.Format < 3 && path == "/etc/systemd/system/panel-network-ids-check.service" && legacyErr == nil && string(actual) == legacyBudget
		if err != nil || statErr != nil || info.Mode().Perm() != 0644 || string(actual) != wanted && !knownLegacyCheck {
			return v, errors.New("IDS 实际单元被外部改变；未接管或覆盖")
		}
	}
	return v, nil
}

func threatIDSInstallExact(path string, data []byte, mode os.FileMode) error {
	if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		actual, readErr := apacheWAFReadStableFile(path, 1<<20)
		if readErr != nil || info.Mode().Perm() != mode || string(actual) != string(data) {
			return errors.New("IDS 已有文件不等于受管源；保留且拒绝覆盖")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWrite(path, data, mode)
}

func (s *Service) prepareThreatIDSLogs(account threatIDSAccount) error {
	parent := s.systemPath("/var/lib/panel-network-ids")
	if err := threatIDSTrustedParents(parent, true); err != nil {
		return err
	}
	path := filepath.Join(parent, "logs")
	if err := os.Mkdir(path, 0700); err == nil {
		if err := os.Chown(path, int(account.UID), int(account.GID)); err != nil {
			return err
		}
		if err := os.Chmod(path, 0700); err != nil {
			return err
		}
		f, err := os.Open(parent)
		if err != nil {
			return err
		}
		defer f.Close()
		if err = f.Sync(); err != nil {
			return err
		}
	} else if !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("IDS 已有日志目录不私有；未修复")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != account.UID || owner.Gid != account.GID {
		return errors.New("IDS 日志目录不是受管账户；未改所有者")
	}
	return nil
}

func preparePrivateThreatIDSService(ctx context.Context) error {
	guard, err := threatIDSInstalledGuard()
	if err != nil {
		return err
	}
	s := New(Config{})
	if _, err := os.Lstat(s.threatIDSRuntimeUpgradePath()); err == nil {
		return upgradePrivateThreatIDSRuntime(ctx, guard)
	} else if !os.IsNotExist(err) {
		return err
	}
	if previous, err := s.threatIDSRuntime(); err == nil {
		if threatIDSRequireSupported(previous.Package.Version) != nil {
			return upgradePrivateThreatIDSRuntime(ctx, guard)
		}
		if record, err := s.threatIDSUnitRecord(previous); err == nil {
			current, _ := threatIDSRecoveryUnit(record.Guard)
			if record.RecoverySHA != fmt.Sprintf("%x", sha256.Sum256([]byte(current))) {
				return upgradePrivateThreatIDSRuntime(ctx, guard)
			}
		}
	}
	if err := installPrivateThreatIDSRuntime(ctx); err != nil {
		return err
	}
	lock, err := threatIDSPrepareLock(s.moduleDir("network-threat-detection"))
	if err != nil {
		return err
	}
	defer lock.Close()
	configuration, err := s.threatIDSTransactionService().lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer configuration.Close()
	runtime, err := s.threatIDSRuntime()
	if err != nil {
		return err
	}
	if err := s.prepareThreatIDSAccount(ctx); err != nil {
		return err
	}
	account, err := s.threatIDSAccount(ctx)
	if err != nil {
		return err
	}
	if err := s.prepareThreatIDSLogs(account); err != nil {
		return err
	}
	if err := threatIDSTrustedParents("/etc/panel/network-ids", true); err != nil {
		return err
	}
	for name, data := range threatIDSOriginalRuleFiles() {
		if err := threatIDSInstallExact(filepath.Join(appNativeRoot, "network-threat-detection/rules", name), []byte(data), 0644); err != nil {
			return err
		}
	}
	unit, err := threatIDSGatedUnit(runtime.Prefix, guard, runtime.Format == 3)
	if err != nil {
		return err
	}
	recovery, err := threatIDSRecoveryUnit(guard)
	if err != nil {
		return err
	}
	syntax, err := threatIDSSyntaxUnit(runtime.Prefix, runtime.Format == 3)
	if err != nil {
		return err
	}
	files := map[string]string{"/etc/systemd/system/panel-network-ids.service": unit, "/etc/systemd/system/panel-network-ids-recover.service": recovery, "/etc/systemd/system/panel-network-ids-check.service": syntax}
	const syntaxPath = "/etc/systemd/system/panel-network-ids-check.service"
	legacySyntax, err := threatIDSLegacySyntaxUnit(runtime.Prefix)
	if err != nil {
		return err
	}
	migrateSyntax := false
	legacySyntaxV2, err := threatIDSLegacySyntaxUnitV2(runtime.Prefix)
	if err != nil {
		return err
	}
	legacySyntaxV3, err := threatIDSLegacySyntaxUnitV3(runtime.Prefix)
	if err != nil {
		return err
	}
	matchedSyntax := ""
	// Check all existing unit files before creating any missing member. Never
	// leave a newly installed capture unit beside an unrelated recovery unit.
	for path, data := range files {
		if err := threatIDSTrustedParents(filepath.Dir(path), false); err != nil {
			return err
		}
		if info, err := os.Lstat(path); err == nil {
			actual, err := apacheWAFReadStableFile(path, 32<<10)
			if runtime.Format < 3 && err == nil && info.Mode().Perm() == 0644 && path == syntaxPath && (string(actual) == legacySyntax || string(actual) == legacySyntaxV2 || string(actual) == legacySyntaxV3) {
				if err := s.threatIDSSyntaxMigrationOwned(runtime, guard); err != nil {
					return err
				}
				migrateSyntax = true
				matchedSyntax = string(actual)
				continue
			}
			if err != nil || info.Mode().Perm() != 0644 || string(actual) != data {
				return errors.New("IDS 现有单元不属于固定受管源；没有覆盖任何单元")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if migrateSyntax {
		if err := s.threatIDSSyntaxIdleSource(ctx); err != nil {
			return err
		}
		if err := s.migrateThreatIDSSyntaxUnit(s.systemPath(syntaxPath), matchedSyntax, syntax); err != nil {
			return err
		}
	}
	for path, data := range files {
		if err := threatIDSInstallExact(path, []byte(data), 0644); err != nil {
			return err
		}
	}
	if _, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/panel-network-ids.service", "/etc/systemd/system/panel-network-ids-recover.service", "/etc/systemd/system/panel-network-ids-check.service"); err != nil {
		return err
	}
	v := threatIDSUnitRecord{Format: 1, Guard: guard, Prefix: runtime.Prefix, UnitSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(unit))), RecoverySHA: fmt.Sprintf("%x", sha256.Sum256([]byte(recovery)))}
	path := filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json")
	if _, err := os.Lstat(path); err == nil {
		if _, err := s.threatIDSUnitRecord(runtime); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err := moduleWrite(path, v); err != nil {
		return err
	}
	_, err = s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "daemon-reload")
	return err // Explicit preparation does not configure, start or enable capture.
}

func threatIDSInstalledGuard() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	actual, err := os.Stat(executable)
	if err != nil {
		return "", err
	}
	guard := ""
	for _, candidate := range []string{"/opt/panel/current/bin/panel-executor", "/opt/panel/bin/panel-executor"} {
		info, err := os.Stat(candidate)
		if err == nil && os.SameFile(actual, info) {
			guard = candidate
			break
		}
	}
	if guard == "" {
		return "", errors.New("IDS 准备必须由已安装面板执行器运行；测试程序不能代替启动核对程序")
	}
	return guard, nil
}
