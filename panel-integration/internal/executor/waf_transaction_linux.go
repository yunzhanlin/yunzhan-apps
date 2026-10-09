//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type wafTransaction struct {
	Format    int                     `json:"format"`
	ID        string                  `json:"id"`
	State     string                  `json:"state"`
	CreatedAt string                  `json:"created_at"`
	Changes   []wafConfigChange       `json:"changes"`
	Digests   map[string]string       `json:"backup_sha256"`
	IDS       *threatIDSRecoveryState `json:"ids,omitempty"`
}

// Returned only before a configuration lock is acquired; no mutation occurred.
var errWAFConfigurationBusy = errors.New("WAF 正在变更或恢复，请稍后重试")

func (s *Service) wafPendingPath() string {
	if s.fileTransactionApplication == "network-ids" {
		return filepath.Join(s.moduleDir("network-threat-detection"), "config-transactions", "pending.json")
	}
	if s.fileTransactionApplication == "analytics-html" {
		return s.systemPath("/etc/panel/analytics-html/config-transactions/pending.json")
	}
	if s.fileTransactionApplication == "apache-waf" {
		return filepath.Join(s.moduleDir("apache-waf"), "config-transactions", "pending.json")
	}
	return filepath.Join(s.Config.SecurityDir, "waf-transactions", "pending.json")
}

func (s *Service) wafChangePathAllowed(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if s.fileTransactionApplication == "network-ids" {
		for _, allowed := range s.threatIDSConfigurationPaths() {
			if path == allowed {
				return true
			}
		}
		return false
	}
	if s.fileTransactionApplication == "analytics-html" {
		for _, allowed := range s.analyticsHTMLConfigurationPaths() {
			if path == allowed {
				return true
			}
		}
		return false
	}
	if s.fileTransactionApplication == "apache-waf" {
		for _, allowed := range s.apacheWAFConfigurationPaths() {
			if path == allowed {
				return true
			}
		}
		return false
	}
	h, v := wafFiles(s)
	for _, allowed := range []string{s.Config.NginxConf, s.softwareManifestPath("nginx-waf"), h, v, s.systemPath("/etc/panel/waf/http.d/20-panel-native-waf.conf")} {
		if path == allowed {
			return true
		}
	}
	for _, base := range []string{s.Config.ConfDir, s.systemPath("/etc/panel/waf/body.d")} {
		if filepath.Dir(path) == base && strings.HasSuffix(path, ".conf") && core.ValidID(strings.TrimSuffix(filepath.Base(path), ".conf")) {
			return true
		}
	}
	return false
}

// Check every managed ancestor and create only missing root-owned directories.
// A symlink/foreign/writable parent is never followed, even when the leaf does
// not yet exist. Fixtures have explicit isolated trust roots, not /tmp itself.
func (s *Service) wafOwnedDirectory(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("WAF 配置目录不是绝对规范路径")
	}
	stop := path == "/"
	if s.Config.SystemRoot != "/" {
		stop = path == s.Config.SystemRoot || path == filepath.Dir(s.Config.ConfDir) || path == filepath.Dir(s.Config.StateDir)
	}
	if !stop {
		if err := s.wafOwnedDirectory(filepath.Dir(path), create); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) && create && !stop {
		if err := os.Mkdir(path, 0750); err != nil {
			return err
		}
	}
	return ownedRuntimePath(path, true)
}

func (s *Service) lockWAFConfiguration() (*os.File, error) {
	return s.lockWAFFile(syscall.LOCK_EX)
}

// Metadata observations are mutually compatible, but remain excluded from
// rotation, policy changes, recovery and deletion across executor processes.
func (s *Service) lockWAFObservation() (*os.File, error) {
	return s.lockWAFFile(syscall.LOCK_SH)
}

func (s *Service) lockWAFFile(operation int) (*os.File, error) {
	if operation != syscall.LOCK_EX && operation != syscall.LOCK_SH {
		return nil, errors.New("WAF 锁操作无效")
	}
	base := s.Config.SecurityDir
	if s.fileTransactionApplication == "apache-waf" {
		base = s.moduleDir("apache-waf")
	}
	if s.fileTransactionApplication == "network-ids" {
		base = s.moduleDir("network-threat-detection")
	}
	if err := s.wafOwnedDirectory(base, true); err != nil {
		return nil, err
	}
	path := filepath.Join(base, "waf-configuration.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("WAF 配置锁类型或权限异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("WAF 配置锁所有者或链接数异常")
	}
	if err := syscall.Flock(int(f.Fd()), operation|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errWAFConfigurationBusy
		}
		return nil, fmt.Errorf("无法取得 WAF 配置锁: %w", err)
	}
	if operation == syscall.LOCK_EX && s.fileTransactionApplication != "analytics-html" && s.fileTransactionApplication != "apache-waf" && s.fileTransactionApplication != "network-ids" {
		if _, err := os.Lstat(s.analyticsHTMLTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
			f.Close()
			return nil, errors.New("HTML 引擎有待恢复配置；禁止其他 Nginx 变更覆盖恢复集合")
		}
	}
	return f, nil
}

func (s *Service) wafTransactionContract(tx wafTransaction) error {
	if s.fileTransactionApplication == "network-ids" {
		paths := s.threatIDSConfigurationPaths()
		if tx.Format != 2 || len(tx.Changes) != len(paths) || tx.IDS == nil || tx.IDS.ApplyOwner == nil || tx.IDS.ApplyOwner.PID <= 1 || tx.IDS.ApplyOwner.StartTime == 0 || !threatPackageSHA.MatchString(tx.IDS.UnitSHA) || !threatPackageSHA.MatchString(tx.IDS.RuntimeRecordSHA) || tx.IDS.RecoveryOwner != nil && (tx.State == "applying" || tx.IDS.RecoveryOwner.PID <= 1 || tx.IDS.RecoveryOwner.StartTime == 0) {
			return errors.New("IDS 恢复事务缺少完整配置、原状态、程序来源或执行身份")
		}
		for i, path := range paths {
			if tx.Changes[i].Path != path {
				return errors.New("IDS 恢复集合路径或顺序错误")
			}
		}
		if err := validateThreatIDSJournal(tx); err != nil {
			return err
		}
	} else if tx.IDS != nil {
		return errors.New("非 IDS 事务不能包含 IDS 运行状态")
	}
	if s.fileTransactionApplication == "analytics-html" {
		paths := s.analyticsHTMLConfigurationPaths()
		if tx.Format != 2 || len(tx.Changes) != len(paths) {
			return errors.New("HTML 引擎恢复事务需要三个完整的 UID/GID 文件记录")
		}
		for i, path := range paths {
			if tx.Changes[i].Path != path {
				return errors.New("HTML 引擎恢复文件顺序或归属不匹配")
			}
		}
	}
	if s.fileTransactionApplication == "apache-waf" && (tx.Format != 2 || len(tx.Changes) != 3) {
		return errors.New("Apache 防护恢复事务需要三个完整的 UID/GID 文件记录")
	}
	if (tx.Format != 1 && tx.Format != 2) || !core.ValidID(tx.ID) || (tx.State != "applying" && tx.State != "committed" && tx.State != "recovered") || len(tx.Changes) < 1 || len(tx.Changes) > 4096 || len(tx.Digests) != len(tx.Changes)*2 {
		return errors.New("WAF 恢复记录身份、状态或条目数量异常")
	}
	if _, err := time.Parse(time.RFC3339, tx.CreatedAt); err != nil {
		return errors.New("WAF 恢复记录时间异常")
	}
	total, seen := 0, map[string]bool{}
	for _, c := range tx.Changes {
		if tx.Format == 2 && (c.OldExists != (c.OldOwner != nil) || c.NextExists != (c.NextOwner != nil)) {
			return errors.New("WAF 事务缺少原 UID/GID，未当成完整恢复证据")
		}
		for _, owner := range []*fileOwner{c.OldOwner, c.NextOwner} {
			if owner != nil && (owner.UID != uint32(os.Geteuid()) || owner.GID == ^uint32(0)) {
				return errors.New("WAF 事务文件所有者不可核验")
			}
		}
		if !s.wafChangePathAllowed(c.Path) || seen[c.Path] || c.OldMode&^0777 != 0 || c.NextMode&^0777 != 0 || c.OldMode&0022 != 0 || c.NextMode&0022 != 0 || (!c.OldExists && len(c.OldData) != 0) || (!c.NextExists && len(c.NextData) != 0) {
			return errors.New("WAF 恢复记录路径、权限或归属异常")
		}
		seen[c.Path] = true
		total += len(c.OldData) + len(c.NextData)
		if total > wafTransactionBytes || tx.Digests[c.Path+":old"] != core.Hash(string(c.OldData)) || tx.Digests[c.Path+":next"] != core.Hash(string(c.NextData)) {
			return errors.New("WAF 恢复备份超限或摘要损坏")
		}
	}
	return nil
}

func wafWriteTransaction(path string, tx wafTransaction) error {
	data, err := json.MarshalIndent(tx, "", "  ")
	if err != nil || len(data) > 16<<20 {
		return errors.New("WAF 恢复记录序列化失败或超过 16 MiB")
	}
	return atomicWrite(path, append(data, '\n'), 0600)
}

func (s *Service) readWAFTransaction() (wafTransaction, error) {
	var tx wafTransaction
	path := s.wafPendingPath()
	if err := s.wafOwnedDirectory(filepath.Dir(path), false); err != nil {
		return tx, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return tx, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 16<<20 {
		return tx, errors.New("WAF 恢复记录不是有界私有普通文件")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return tx, errors.New("WAF 恢复记录所有者或链接数异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return tx, errors.New("WAF 恢复记录读取失败或超限")
	}
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(st, current) || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) || current.Mode()&os.ModeSymlink != 0 {
		return tx, errors.New("WAF 恢复记录在读取期间被修改或替换")
	}
	afterOwner, ownerErr := fileOwnerForInfo(after)
	currentOwner, currentErr := fileOwnerForInfo(current)
	if ownerErr != nil || currentErr != nil || st.Mode() != after.Mode() || st.Mode() != current.Mode() || afterOwner.UID != stat.Uid || afterOwner.GID != stat.Gid || *afterOwner != *currentOwner || after.Sys().(*syscall.Stat_t).Nlink != 1 || current.Sys().(*syscall.Stat_t).Nlink != 1 {
		return tx, errors.New("WAF 恢复记录权限、所有者或链接数在读取期间变化")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&tx); err != nil {
		return tx, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return tx, errors.New("WAF 恢复记录包含额外数据")
	}
	return tx, s.wafTransactionContract(tx)
}

func (s *Service) wafCurrentMatches(c wafConfigChange, next bool) (bool, error) {
	if err := s.wafOwnedDirectory(filepath.Dir(c.Path), false); err != nil {
		return false, err
	}
	if _, err := os.Lstat(c.Path); err == nil {
		if err := ownedRuntimePath(c.Path, false); err != nil {
			return false, err
		}
		st, err := os.Lstat(c.Path)
		if err != nil || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Size() > wafTransactionBytes {
			return false, errors.New("WAF 配置大小或链接数异常")
		}
	}
	var b fileBackup
	var err error
	if s.fileTransactionApplication == "analytics-html" {
		b, err = s.analyticsHTMLStableBackup(c.Path)
	} else if s.fileTransactionApplication == "apache-waf" {
		b, err = s.apacheWAFStableBackup(c.Path)
	} else if s.fileTransactionApplication == "network-ids" {
		b, err = s.threatIDSStableBackup(c.Path)
	} else {
		b, err = backupFile(c.Path)
	}
	if err != nil {
		return false, err
	}
	data, exists, mode := c.OldData, c.OldExists, c.OldMode
	owner := c.OldOwner
	if next {
		data, exists, mode = c.NextData, c.NextExists, c.NextMode
		owner = c.NextOwner
	}
	return b.existed == exists && (!exists || (bytes.Equal(b.data, data) && b.mode == mode && (owner == nil || b.owner != nil && *b.owner == *owner))), nil
}

func wafApplyChange(c wafConfigChange, next bool) error {
	data, exists, mode := c.OldData, c.OldExists, c.OldMode
	owner := c.OldOwner
	if next {
		data, exists, mode = c.NextData, c.NextExists, c.NextMode
		owner = c.NextOwner
	}
	if exists {
		if owner != nil {
			return atomicWriteWithOwner(c.Path, data, mode, owner)
		}
		return atomicWrite(c.Path, data, mode)
	}
	if err := os.Remove(c.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.Open(filepath.Dir(c.Path))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Service) startWAFTransaction(changes []wafConfigChange) (wafTransaction, error) {
	return s.startWAFTransactionState(changes, nil)
}

func (s *Service) startWAFTransactionState(changes []wafConfigChange, ids *threatIDSRecoveryState) (wafTransaction, error) {
	changes = append([]wafConfigChange{}, changes...)
	for i := range changes {
		c := &changes[i]
		if c.OldExists && c.OldOwner == nil {
			b, err := backupFile(c.Path)
			if err != nil || !b.existed || b.owner == nil {
				return wafTransaction{}, errors.New("WAF 原文件 UID/GID 不可捕获，未开始写入")
			}
			c.OldOwner = b.owner
		}
		if c.NextExists && c.NextOwner == nil {
			c.NextOwner = c.OldOwner
			if c.NextOwner == nil {
				c.NextOwner = &fileOwner{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
			}
		}
	}
	tx := wafTransaction{Format: 2, ID: core.ID(), State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}, IDS: ids}
	for _, c := range changes {
		tx.Digests[c.Path+":old"], tx.Digests[c.Path+":next"] = core.Hash(string(c.OldData)), core.Hash(string(c.NextData))
	}
	if err := s.wafTransactionContract(tx); err != nil {
		return tx, err
	}
	dir := filepath.Dir(s.wafPendingPath())
	if err := s.wafOwnedDirectory(dir, true); err != nil {
		return tx, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) >= 100 {
		return tx, errors.New("WAF 配置事务已达 100 份，请先归档，未修改配置")
	}
	if _, err := os.Lstat(s.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return tx, errors.New("WAF 存在未完成恢复事务，拒绝开始下一次变更")
	}
	for _, c := range changes {
		if err := s.wafOwnedDirectory(filepath.Dir(c.Path), true); err != nil {
			return tx, err
		}
		match, err := s.wafCurrentMatches(c, false)
		if err != nil || !match {
			return tx, errors.New("WAF 配置在备份期间被外部修改，未开始写入")
		}
	}
	if err := wafWriteTransaction(filepath.Join(dir, tx.ID+".json"), tx); err != nil {
		return tx, err
	}
	return tx, wafWriteTransaction(s.wafPendingPath(), tx)
}

func (s *Service) finishWAFTransaction(tx wafTransaction) error {
	if err := s.wafTransactionContract(tx); err != nil {
		return err
	}
	if err := wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
		return err
	}
	if err := wafWriteTransaction(filepath.Join(filepath.Dir(s.wafPendingPath()), tx.ID+".json"), tx); err != nil {
		return err
	}
	if err := os.Remove(s.wafPendingPath()); err != nil {
		return err
	}
	f, err := os.Open(filepath.Dir(s.wafPendingPath()))
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Validate the entire recovery set before changing any file. Mixed old/new
// bytes represent an interrupted transaction; anything else is an external
// edit and stops recovery without overwriting either config or backup.
func (s *Service) recoverWAFTransaction() (bool, error) {
	tx, err := s.readWAFTransaction()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if tx.State != "applying" {
		if s.fileTransactionApplication == "apache-waf" || s.fileTransactionApplication == "analytics-html" || s.fileTransactionApplication == "network-ids" {
			for _, c := range tx.Changes {
				match, e := s.wafCurrentMatches(c, tx.State == "committed")
				if e != nil || !match {
					return false, errors.New("Apache 已提交或恢复文件被外部修改，保留事务且拒绝覆盖")
				}
			}
			// Apache acknowledges only after native validation and, if running,
			// reloading/probing the exact chosen version. Keep retry evidence.
			return false, nil
		}
		return false, s.finishWAFTransaction(tx)
	}
	if tx.Format == 1 {
		return false, errors.New("旧 WAF 未完成事务没有完整 UID/GID；无法保证原所有者，保留证据且不自动覆盖配置")
	}
	for _, c := range tx.Changes {
		old, err := s.wafCurrentMatches(c, false)
		if err != nil {
			return false, err
		}
		next, err := s.wafCurrentMatches(c, true)
		if err != nil || (!old && !next) {
			return false, errors.New("WAF 配置被外部修改，拒绝自动覆盖；恢复备份已保留")
		}
	}
	for i := len(tx.Changes) - 1; i >= 0; i-- {
		if err := wafApplyChange(tx.Changes[i], false); err != nil {
			return false, err
		}
	}
	tx.State = "recovered"
	if s.fileTransactionApplication == "apache-waf" || s.fileTransactionApplication == "analytics-html" || s.fileTransactionApplication == "network-ids" {
		return true, wafWriteTransaction(s.wafPendingPath(), tx)
	}
	return true, s.finishWAFTransaction(tx)
}

func RecoverWAFConfiguration() error {
	s := nativeWAFService()
	// An absent application has nothing to recover; do not create new dirs on
	// unrelated installations merely because this recovery unit is enabled.
	if _, err := os.Lstat(s.wafPendingPath()); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	_, err = s.recoverWAFTransaction()
	if err != nil {
		return err
	}
	nginx, err := s.nginxBinary()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := s.Config.Run(ctx, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return fmt.Errorf("WAF 启动恢复后 Nginx 校验失败: %w", err)
	}
	return nil
}
