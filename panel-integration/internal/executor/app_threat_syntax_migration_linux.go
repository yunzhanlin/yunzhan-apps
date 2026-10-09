//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type threatIDSSyntaxBackup struct {
	Format  int    `json:"format"`
	Old     string `json:"old"`
	OldSHA  string `json:"old_sha256"`
	NextSHA string `json:"next_sha256"`
}

func threatIDSLegacySyntaxUnit(prefix string) (string, error) {
	v, err := threatIDSLegacySyntaxUnitV2(prefix)
	return strings.Replace(v, " -l /tmp -c ", " -c ", 1), err
}

func threatIDSLegacySyntaxUnitV2(prefix string) (string, error) {
	v, err := threatIDSLegacySyntaxUnitV3(prefix)
	return strings.Replace(v, "RemainAfterExit=yes\n", "", 1), err
}

// The first strict-parser generation was bounded for six small indicators.
// Its exact bytes remain identifiable for safe stop and explicit preparation;
// an arbitrary longer timeout or administrator override is NOT this source.
func threatIDSLegacySyntaxUnitV3(prefix string) (string, error) {
	v, err := threatIDSSyntaxUnit(prefix)
	return strings.Replace(v, "TimeoutStartSec=90s\n", "TimeoutStartSec=40s\n", 1), err
}

func (s *Service) threatIDSRequireCurrentSyntax(runtime threatIDSRuntime) error {
	wanted, err := threatIDSSyntaxUnit(runtime.Prefix, runtime.Format == 3)
	actual, readErr := apacheWAFReadStableFile(s.systemPath("/etc/systemd/system/panel-network-ids-check.service"), 32<<10)
	if err != nil || readErr != nil || string(actual) != wanted {
		return errors.New("IDS 配置检查单元仍使用旧预算或不能核对；请先重新准备原生组件，未自动迁移或执行旧检查")
	}
	return nil
}

func (s *Service) threatIDSRequireCurrentRecovery(runtime threatIDSRuntime) error {
	record, err := s.threatIDSUnitRecord(runtime)
	if err != nil {
		return err
	}
	current, err := threatIDSRecoveryUnit(record.Guard)
	if err != nil || record.RecoverySHA != fmt.Sprintf("%x", sha256.Sum256([]byte(current))) {
		return errors.New("IDS 恢复单元仍使用旧预算；请先显式停止并关闭开机采集，再重新准备原生组件，未自动迁移或启动")
	}
	return nil
}

// Caller holds both preparation and configuration locks. Never rewrite an
// executing parser or a loaded administrator override, and never stop either
// in order to make migration appear successful.
func (s *Service) threatIDSSyntaxIdleSource(ctx context.Context) error {
	return s.threatIDSIdleUnitSource(ctx, "panel-network-ids-check.service")
}

func (s *Service) threatIDSIdleUnitSource(ctx context.Context, unit string) error {
	if unit != "panel-network-ids-check.service" && unit != "panel-network-ids-recover.service" {
		return errors.New("IDS 空闲来源核对不允许任意单元")
	}
	value, err := s.moduleCommand(ctx, 5*time.Second, "/usr/bin/systemctl", "show", "--all", unit, "--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,Transient,NeedDaemonReload")
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		key, entry, ok := strings.Cut(line, "=")
		if !ok || len(value) > 4096 {
			return errors.New("IDS 检查单元状态不能核对；未检查、迁移或停止")
		}
		if _, duplicate := fields[key]; duplicate {
			return errors.New("IDS 检查单元状态字段重复；未检查、迁移或停止")
		}
		fields[key] = entry
	}
	idle := "ActiveState=" + fields["ActiveState"] + "\nSubState=" + fields["SubState"] + "\nMainPID=" + fields["MainPID"] + "\n"
	if err != nil || len(fields) != 8 || fields["LoadState"] != "loaded" || fields["FragmentPath"] != "/etc/systemd/system/"+unit || fields["DropInPaths"] != "" || fields["Transient"] != "no" || fields["NeedDaemonReload"] != "no" || !threatIDSSyntaxIdle(idle) {
		return errors.New("IDS 检查单元在执行、加载源不同或状态未知；未检查、迁移或停止")
	}
	return nil
}

// The old parser unit is a known fixed, non-capture generation, not an
// arbitrary administrator file. Only explicit dependency preparation may
// migrate it; a read-only report/start never overwrites a unit.
func (s *Service) threatIDSSyntaxMigrationOwned(runtime threatIDSRuntime, guard string) error {
	b, err := ftpPrivateRead(filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json"), 4096)
	if err != nil {
		return errors.New("IDS 旧配置检查服务没有受管来源记录；未替换")
	}
	var record threatIDSUnitRecord
	if decodeThreatIDSPrivateJSON(b, &record) != nil {
		return errors.New("IDS 旧配置检查服务来源记录不匹配；未替换")
	}
	unit, unitErr := threatIDSGatedUnit(runtime.Prefix, guard, runtime.Format == 3)
	recovery, recoveryErr := threatIDSRecoverySource(guard, record.RecoverySHA)
	if decodeThreatIDSPrivateJSON(b, &record) != nil || unitErr != nil || recoveryErr != nil || record.Format != 1 || record.Guard != guard || record.Prefix != runtime.Prefix || record.UnitSHA != fmt.Sprintf("%x", sha256.Sum256([]byte(unit))) || record.RecoverySHA != fmt.Sprintf("%x", sha256.Sum256([]byte(recovery))) {
		return errors.New("IDS 旧配置检查服务来源记录不匹配；未替换")
	}
	return nil
}

func (s *Service) migrateThreatIDSSyntaxUnit(path, old, next string) error {
	if path != s.systemPath("/etc/systemd/system/panel-network-ids-check.service") {
		return errors.New("IDS 配置检查迁移路径不固定；未替换")
	}
	backup := threatIDSSyntaxBackup{Format: 1, Old: old, OldSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(old))), NextSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(next)))}
	backupPath := filepath.Join(s.moduleDir("network-threat-detection"), "syntax-check-"+backup.OldSHA+"-backup.json")
	if b, err := ftpPrivateRead(backupPath, 32<<10); err == nil {
		var previous threatIDSSyntaxBackup
		if decodeThreatIDSPrivateJSON(b, &previous) != nil || previous != backup {
			return errors.New("IDS 配置检查服务备份被外部改变；未替换")
		}
	} else if !os.IsNotExist(err) {
		return err
	} else if err := moduleWrite(backupPath, backup); err != nil {
		return err
	}
	actual, err := apacheWAFReadStableFile(path, 32<<10)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || info.Mode().Perm() != 0644 || string(actual) != old {
		return errors.New("IDS 配置检查服务在迁移前发生外部变化；未替换")
	}
	return atomicWrite(path, []byte(next), 0644)
}
