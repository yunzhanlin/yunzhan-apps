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
	Format    int               `json:"format"`
	ID        string            `json:"id"`
	State     string            `json:"state"`
	CreatedAt string            `json:"created_at"`
	Changes   []wafConfigChange `json:"changes"`
	Digests   map[string]string `json:"backup_sha256"`
}

func (s *Service) wafPendingPath() string {
	return filepath.Join(s.Config.SecurityDir, "waf-transactions", "pending.json")
}

func (s *Service) wafChangePathAllowed(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
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
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(s.Config.SecurityDir, "waf-configuration.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
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
		return nil, errors.New("WAF 正在变更或恢复，请稍后重试")
	}
	return f, nil
}

func (s *Service) wafTransactionContract(tx wafTransaction) error {
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
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
	b, err := backupFile(c.Path)
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
	tx := wafTransaction{Format: 2, ID: core.ID(), State: "applying", CreatedAt: core.Now(), Changes: changes, Digests: map[string]string{}}
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
