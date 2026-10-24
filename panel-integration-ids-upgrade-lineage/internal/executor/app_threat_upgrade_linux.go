//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"time"
)

type threatIDSRuntimeUpgrade struct {
	Format     int               `json:"format"`
	ID         string            `json:"id"`
	State      string            `json:"state"`
	CreatedAt  string            `json:"created_at"`
	ConfigSHA  string            `json:"config_sha256"`
	YAMLSHA    string            `json:"yaml_sha256"`
	AccountSHA string            `json:"account_sha256"`
	Changes    []wafConfigChange `json:"changes"`
	BackupSHA  map[string]string `json:"backup_sha256"`
}

func (s *Service) threatIDSRuntimeUpgradePath() string {
	return filepath.Join(s.moduleDir("network-threat-detection"), "runtime-transactions/pending.json")
}
func (s *Service) threatIDSRuntimeUpgradePaths() []string {
	return []string{s.systemPath("/etc/systemd/system/panel-network-ids.service"), s.systemPath("/etc/systemd/system/panel-network-ids-check.service"), s.systemPath("/etc/systemd/system/panel-network-ids-recover.service"), filepath.Join(s.moduleDir("network-threat-detection"), "native-runtime.json"), filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json")}
}

// This namespace is intentionally separate from the two-file configuration
// journal. A runtime migration cannot borrow authority to change YAML, rules,
// account identities, network interfaces, firewalls, websites or event files.
func (s *Service) threatIDSRuntimeUpgradeContract(tx threatIDSRuntimeUpgrade) (threatIDSRuntime, threatIDSRuntime, error) {
	var old, next threatIDSRuntime
	created, err := time.Parse(time.RFC3339Nano, tx.CreatedAt)
	paths := s.threatIDSRuntimeUpgradePaths()
	if tx.Format != 1 || !core.ValidID(tx.ID) || err != nil || created.Year() < 2000 || created.Year() > 2100 || (tx.State != "applying" && tx.State != "committed" && tx.State != "rolled-back") || len(tx.Changes) != len(paths) || len(tx.BackupSHA) != len(paths) || !threatPackageSHA.MatchString(tx.ConfigSHA) || !threatPackageSHA.MatchString(tx.YAMLSHA) || !threatPackageSHA.MatchString(tx.AccountSHA) {
		return old, next, errors.New("IDS 原生迁移记录不完整或状态未知")
	}
	total := 0
	for i, c := range tx.Changes {
		total += len(c.OldData) + len(c.NextData)
		if total > 64<<10 {
			return old, next, errors.New("IDS 原生迁移备份集合超过私有恢复记录预算")
		}
		mode := os.FileMode(0644)
		if i >= 3 {
			mode = 0600
		}
		if c.Path != paths[i] || !c.OldExists || !c.NextExists || c.OldMode != mode || c.NextMode != mode || c.OldOwner == nil || c.NextOwner == nil || c.OldOwner.UID != 0 || *c.OldOwner != *c.NextOwner || len(c.OldData) < 1 || len(c.NextData) < 1 || len(c.OldData) > 32<<10 || len(c.NextData) > 32<<10 || tx.BackupSHA[c.Path] != core.Hash(string(c.OldData)) {
			return old, next, errors.New("IDS 原生迁移路径、所有者、模式或完整备份摘要不符")
		}
	}
	if decodeThreatIDSPrivateJSON(tx.Changes[3].OldData, &old) != nil || decodeThreatIDSPrivateJSON(tx.Changes[3].NextData, &next) != nil || (next.Format != 2 && next.Format != 3) || next.Source == nil || old.Platform != next.Platform || old.Package.Architecture != next.Package.Architecture {
		return old, next, errors.New("IDS 原生迁移不是同平台的不同受管候选")
	}
	if old.Prefix == next.Prefix {
		// Unit-only migration cannot claim a package change or edit provenance.
		if !bytes.Equal(tx.Changes[3].OldData, tx.Changes[3].NextData) || (old.Format != 2 && old.Format != 3) || old.Source == nil {
			return old, next, errors.New("IDS 同引擎单元迁移改变了原生来源")
		}
		var before, after threatIDSUnitRecord
		if decodeThreatIDSPrivateJSON(tx.Changes[4].OldData, &before) != nil || decodeThreatIDSPrivateJSON(tx.Changes[4].NextData, &after) != nil {
			return old, next, errors.New("IDS 同引擎单元迁移来源记录无效")
		}
		legacy, legacyErr := threatIDSLegacyRecoveryUnit(before.Guard)
		current, currentErr := threatIDSRecoveryUnit(after.Guard)
		if legacyErr != nil || currentErr != nil || before.RecoverySHA != core.Hash(legacy) || after.RecoverySHA != core.Hash(current) {
			return old, next, errors.New("IDS 同引擎迁移仅允许已知恢复预算代次升级")
		}
	}
	for _, v := range []threatIDSRuntime{old, next} {
		if validateThreatIDSRuntimeHeader(v) != nil {
			return old, next, errors.New("IDS 原生迁移来源记录结构异常")
		}
	}
	for i, v := range []threatIDSRuntime{old, next} {
		var record threatIDSUnitRecord
		blob := tx.Changes[4].OldData
		if i == 1 {
			blob = tx.Changes[4].NextData
		}
		if decodeThreatIDSPrivateJSON(blob, &record) != nil {
			return old, next, errors.New("IDS 原生迁移单元记录无效")
		}
		unit, e1 := threatIDSGatedUnit(v.Prefix, record.Guard, v.Format == 3)
		syntax, e2 := threatIDSSyntaxUnit(v.Prefix, v.Format == 3)
		recovery, e3 := threatIDSRecoverySource(record.Guard, record.RecoverySHA)
		if e1 != nil || e2 != nil || e3 != nil || record.Format != 1 || record.Prefix != v.Prefix || record.UnitSHA != core.Hash(unit) || record.RecoverySHA != core.Hash(recovery) {
			return old, next, errors.New("IDS 原生迁移单元权限来源无效")
		}
		for j, wanted := range []string{unit, syntax, recovery} {
			data := tx.Changes[j].OldData
			if i == 1 {
				data = tx.Changes[j].NextData
			}
			legacySyntax, legacyErr := threatIDSLegacySyntaxUnitV3(v.Prefix)
			knownPriorCheck := v.Format < 3 && j == 1 && legacyErr == nil && bytes.Equal(data, []byte(legacySyntax))
			if !bytes.Equal(data, []byte(wanted)) && !knownPriorCheck {
				return old, next, errors.New("IDS 原生迁移单元不是固定受管源")
			}
		}
	}
	var oldUnit, nextUnit threatIDSUnitRecord
	_ = decodeThreatIDSPrivateJSON(tx.Changes[4].OldData, &oldUnit)
	_ = decodeThreatIDSPrivateJSON(tx.Changes[4].NextData, &nextUnit)
	if oldUnit.Guard != nextUnit.Guard {
		return old, next, errors.New("IDS 原生迁移不能更换启动核对程序")
	}
	return old, next, nil
}

func (s *Service) threatIDSUpgradeBackup(path string) (fileBackup, error) {
	var b fileBackup
	allowed := false
	for _, p := range s.threatIDSRuntimeUpgradePaths() {
		if p == path {
			allowed = true
		}
	}
	if !allowed {
		return b, errors.New("IDS 原生迁移路径不在固定集合")
	}
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return b, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return b, err
	}
	owner, err := fileOwnerForInfo(before)
	if err != nil || owner.UID != 0 {
		return b, errors.New("IDS 原生迁移文件所有者异常")
	}
	data, err := apacheWAFReadStableFile(path, 32<<10)
	if err != nil {
		return b, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return b, err
	}
	afterOwner, err := fileOwnerForInfo(after)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || *owner != *afterOwner {
		return b, errors.New("IDS 原生迁移备份期间文件发生变化")
	}
	return fileBackup{path: path, data: data, existed: true, mode: before.Mode().Perm(), owner: owner}, nil
}

func (s *Service) threatIDSUpgradeMatches(c wafConfigChange, next bool) (bool, error) {
	b, err := s.threatIDSUpgradeBackup(c.Path)
	if err != nil {
		return false, err
	}
	data, mode, owner := c.OldData, c.OldMode, c.OldOwner
	if next {
		data, mode, owner = c.NextData, c.NextMode, c.NextOwner
	}
	return b.existed && b.mode == mode && owner != nil && *b.owner == *owner && bytes.Equal(b.data, data), nil
}

func (s *Service) threatIDSValidateUpgradeSet(tx threatIDSRuntimeUpgrade) error {
	if _, _, err := s.threatIDSRuntimeUpgradeContract(tx); err != nil {
		return err
	}
	for _, c := range tx.Changes {
		old, err := s.threatIDSUpgradeMatches(c, false)
		if err != nil {
			return err
		}
		next, err := s.threatIDSUpgradeMatches(c, true)
		if err != nil {
			return err
		}
		if tx.State == "applying" && !old && !next || tx.State == "committed" && !next || tx.State == "rolled-back" && !old {
			return errors.New("IDS 原生迁移集合含未知外部变更；保留且拒绝覆盖")
		}
	}
	return nil
}

func (s *Service) readThreatIDSRuntimeUpgrade() (threatIDSRuntimeUpgrade, error) {
	var tx threatIDSRuntimeUpgrade
	b, err := ftpPrivateRead(s.threatIDSRuntimeUpgradePath(), 128<<10)
	if err != nil {
		return tx, err
	}
	if decodeThreatIDSPrivateJSON(b, &tx) != nil {
		return tx, errors.New("IDS 原生迁移私有记录损坏")
	}
	_, _, err = s.threatIDSRuntimeUpgradeContract(tx)
	return tx, err
}

func (s *Service) writeThreatIDSRuntimeUpgrade(tx threatIDSRuntimeUpgrade) error {
	if _, _, err := s.threatIDSRuntimeUpgradeContract(tx); err != nil {
		return err
	}
	if err := s.wafOwnedDirectory(filepath.Dir(s.threatIDSRuntimeUpgradePath()), true); err != nil {
		return err
	}
	return moduleWrite(s.threatIDSRuntimeUpgradePath(), tx)
}

func (s *Service) finishThreatIDSRuntimeUpgrade(tx threatIDSRuntimeUpgrade) error {
	if tx.State != "committed" && tx.State != "rolled-back" {
		return errors.New("IDS 原生迁移尚未完成，不能归档")
	}
	if err := s.threatIDSValidateUpgradeSet(tx); err != nil {
		return err
	}
	pending := s.threatIDSRuntimeUpgradePath()
	dir := filepath.Dir(pending)
	archive := filepath.Join(dir, tx.ID+"-"+tx.State+".json")
	if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
		return err
	}
	// The caller archives exactly its verified pending inode, without
	// replacement. Backup data remains recoverable; no runtime tree is deleted.
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, archive, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Service) threatIDSUpgradeNoPending() error {
	if _, err := os.Lstat(s.threatIDSRuntimeUpgradePath()); os.IsNotExist(err) {
		return nil
	}
	return errors.New("IDS 原生引擎迁移仍待核对；禁止采集启动、配置变更或卸载，先显式恢复准备任务")
}

func (s *Service) threatIDSUpgradeStopped(ctx context.Context) error {
	state, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", threatIDSService, "--property=ActiveState,MainPID")
	if err != nil || !threatIDSStoppedUnit(state, false) {
		return errors.New("IDS 原生迁移要求采集明确停止且 MainPID=0；未自动停止或启动")
	}
	boot, err := s.threatIDSBootState(ctx)
	if err != nil || boot {
		return errors.New("IDS 原生迁移要求开机采集明确关闭；未修改原有开机选择")
	}
	if _, err := os.Lstat(s.threatIDSTransactionService().wafPendingPath()); !os.IsNotExist(err) {
		return errors.New("IDS 配置同时存在待恢复事务；不混合迁移")
	}
	return s.threatIDSStartOutputReady()
}

func (s *Service) threatIDSUpgradeBinding(ctx context.Context, tx threatIDSRuntimeUpgrade) error {
	if err := s.threatIDSUpgradeStopped(ctx); err != nil {
		return err
	}
	configuration, err := s.threatIDSConfig()
	if err != nil {
		return err
	}
	if err := s.threatIDSNativeConfig(configuration); err != nil {
		return err
	}
	if _, err := s.threatIDSAccount(ctx); err != nil {
		return err
	}
	for path, wanted := range map[string]string{filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json"): tx.ConfigSHA, s.systemPath("/etc/panel/network-ids/suricata.yaml"): tx.YAMLSHA, filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json"): tx.AccountSHA} {
		digest, err := nfsFileDigest(path, 32<<10)
		if err != nil || digest != wanted {
			return errors.New("IDS 原生迁移绑定的配置或账户已发生变化；保留且拒绝覆盖")
		}
	}
	for name, data := range threatIDSOriginalRuleFiles() {
		digest, err := nfsFileDigest(s.systemPath(filepath.Join(appNativeRoot, "network-threat-detection/rules", name)), 1<<20)
		if err != nil || digest != core.Hash(data) {
			return errors.New("IDS 原生迁移绑定的规则或许可已发生变化")
		}
	}
	return nil
}

func (s *Service) planThreatIDSRuntimeUpgrade(ctx context.Context, candidate threatIDSRuntime, guard string) (threatIDSRuntimeUpgrade, error) {
	tx := threatIDSRuntimeUpgrade{Format: 1, ID: core.ID(), State: "applying", CreatedAt: core.Now(), BackupSHA: map[string]string{}}
	unit, err := threatIDSGatedUnit(candidate.Prefix, guard, candidate.Format == 3)
	if err != nil {
		return tx, err
	}
	syntax, err := threatIDSSyntaxUnit(candidate.Prefix, candidate.Format == 3)
	if err != nil {
		return tx, err
	}
	recovery, err := threatIDSRecoveryUnit(guard)
	if err != nil {
		return tx, err
	}
	record := threatIDSUnitRecord{Format: 1, Prefix: candidate.Prefix, Guard: guard, UnitSHA: core.Hash(unit), RecoverySHA: core.Hash(recovery)}
	runtimeJSON, _ := json.Marshal(candidate)
	recordJSON, _ := json.Marshal(record)
	for i, data := range [][]byte{[]byte(unit), []byte(syntax), []byte(recovery), runtimeJSON, recordJSON} {
		path := s.threatIDSRuntimeUpgradePaths()[i]
		b, err := s.threatIDSUpgradeBackup(path)
		if err != nil {
			return tx, err
		}
		if i == 3 {
			var previous threatIDSRuntime
			if decodeThreatIDSPrivateJSON(b.data, &previous) != nil {
				return tx, errors.New("IDS 原生来源不能核对")
			}
			if previous.Prefix == candidate.Prefix {
				canonical, _ := json.Marshal(previous)
				if !bytes.Equal(canonical, runtimeJSON) {
					return tx, errors.New("IDS 同引擎候选改变了受管原生来源")
				}
				data = b.data // Preserve bytes, whitespace, mode and owner.
			}
		}
		tx.Changes = append(tx.Changes, wafConfigChange{Path: path, OldData: b.data, OldExists: true, OldMode: b.mode, OldOwner: b.owner, NextData: data, NextExists: true, NextMode: b.mode, NextOwner: b.owner})
		tx.BackupSHA[path] = core.Hash(string(b.data))
	}
	for path, target := range map[string]*string{filepath.Join(s.moduleDir("network-threat-detection"), "ids-config.json"): &tx.ConfigSHA, s.systemPath("/etc/panel/network-ids/suricata.yaml"): &tx.YAMLSHA, filepath.Join(s.moduleDir("network-threat-detection"), "capture-account.json"): &tx.AccountSHA} {
		digest, err := nfsFileDigest(path, 32<<10)
		if err != nil {
			return tx, err
		}
		*target = digest
	}
	_, _, err = s.threatIDSRuntimeUpgradeContract(tx)
	if err != nil {
		return tx, err
	}
	return tx, s.threatIDSUpgradeBinding(ctx, tx)
}

// Caller owns both preparation and configuration locks. Applying interruptions
// roll back every known old/new member as a set; committed interruptions finish
// forward. Neither path starts capture or modifies enablement.
func (s *Service) recoverThreatIDSRuntimeUpgrade(ctx context.Context) error {
	tx, err := s.readThreatIDSRuntimeUpgrade()
	if err != nil {
		return err
	}
	old, next, err := s.threatIDSRuntimeUpgradeContract(tx)
	if err != nil {
		return err
	}
	if err := s.threatIDSUpgradeBinding(ctx, tx); err != nil {
		return err
	}
	if _, err := s.validateThreatIDSRuntime(old); err != nil {
		return err
	}
	if _, err := s.validateThreatIDSRuntime(next); err != nil {
		return err
	}
	if err := s.threatIDSValidateUpgradeSet(tx); err != nil {
		return err
	}
	if tx.State == "applying" {
		for _, c := range tx.Changes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.threatIDSValidateUpgradeSet(tx); err != nil {
				return err
			}
			if err := wafApplyChange(c, false); err != nil {
				return err
			}
		}
		tx.State = "rolled-back"
		if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
			return err
		}
	}
	if _, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	return s.finishThreatIDSRuntimeUpgrade(tx)
}

func upgradePrivateThreatIDSRuntime(ctx context.Context, guard string) error {
	s := New(Config{})
	native, err := threatIDSPrepareLock(s.moduleDir("network-threat-detection"))
	if err != nil {
		return err
	}
	defer native.Close()
	lock, err := s.threatIDSTransactionService().lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := os.Lstat(s.threatIDSRuntimeUpgradePath()); err == nil {
		return s.recoverThreatIDSRuntimeUpgrade(ctx)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := s.threatIDSUpgradeStopped(ctx); err != nil {
		return err
	}
	old, account, record, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return err
	}
	currentRecovery, err := threatIDSRecoveryUnit(record.Guard)
	if err != nil {
		return err
	}
	if threatIDSRequireSupported(old.Package.Version) == nil && record.RecoverySHA == core.Hash(currentRecovery) {
		return nil
	}
	if _, err := s.threatIDSConfig(); err != nil {
		return errors.New("IDS 旧引擎没有完整受管配置，不能推断原生迁移范围")
	}
	candidate := old
	if threatIDSRequireSupported(old.Package.Version) != nil {
		if err := s.stagePrivateThreatIDSRuntime(ctx, &candidate); err != nil {
			return err
		}
	}
	// Do not stop/rewrite executing prerequisites or loaded overrides.
	for _, unit := range []string{"panel-network-ids-check.service", "panel-network-ids-recover.service"} {
		if err := s.threatIDSIdleUnitSource(ctx, unit); err != nil {
			return err
		}
	}
	if err := threatIDSRequireSupported(candidate.Package.Version); err != nil {
		return err
	}
	tx, err := s.planThreatIDSRuntimeUpgrade(ctx, candidate, guard)
	if err != nil {
		return err
	}
	if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
		return err
	}
	applyErr := func() error {
		for _, c := range tx.Changes {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := s.threatIDSUpgradeBinding(ctx, tx); err != nil {
				return err
			}
			if err := s.threatIDSValidateUpgradeSet(tx); err != nil {
				return err
			}
			if err := wafApplyChange(c, true); err != nil {
				return err
			}
		}
		if _, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemd-analyze", append([]string{"verify"}, s.threatIDSRuntimeUpgradePaths()[:3]...)...); err != nil {
			return err
		}
		if _, err := s.moduleCommand(ctx, 10*time.Second, "/usr/bin/systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := s.threatIDSSyntax(ctx, candidate, account); err != nil {
			return err
		}
		if err := s.threatIDSUpgradeBinding(ctx, tx); err != nil {
			return err
		}
		tx.State = "committed"
		if err := s.writeThreatIDSRuntimeUpgrade(tx); err != nil {
			return err
		}
		return s.finishThreatIDSRuntimeUpgrade(tx)
	}()
	if applyErr != nil {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := s.recoverThreatIDSRuntimeUpgrade(recoveryCtx); err != nil {
			return fmt.Errorf("IDS 原生迁移失败：%v；恢复未完成：%v。来源、备份和程序保留，未启动采集", applyErr, err)
		}
		return fmt.Errorf("IDS 原生迁移失败：%v；已恢复完整旧来源与单元，采集仍关闭，候选和备份保留", applyErr)
	}
	return nil
}
