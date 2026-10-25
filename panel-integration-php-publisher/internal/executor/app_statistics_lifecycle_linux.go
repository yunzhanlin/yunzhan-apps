//go:build linux

package executor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

const statisticsIdentityVersion = "2.5.0"
const statisticsGeographyVersion = "2.6.0"

// Even mode=ro SQLite may open a pending rollback journal while deciding that
// native recovery is required. Do not let a health observation enter that
// path: read only the small stable header through the owned directory handle.
// An active writer or an unknown/incomplete journal is a visible refusal too;
// only the explicit hash-bound maintenance entry may authorize recovery.
func statisticsReadOnlyJournalGuard(root *modulePrivateDirectory, before os.FileInfo) error {
	if before.Size() == 0 {
		return nil
	}
	if before.Size() > 512<<20 {
		return errors.New("统计恢复日志容量异常；只读检查未调用恢复器")
	}
	f, err := root.OpenFile("access.sqlite-journal", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameStatisticsRecoveryFile(before, opened) {
		return errors.New("统计日志只读检查期间文件身份变化")
	}
	header := make([]byte, min(before.Size(), 8))
	if _, err = io.ReadFull(f, header); err != nil {
		return err
	}
	after, statErr := f.Stat()
	visible, visibleErr := root.Lstat("access.sqlite-journal")
	if statErr != nil || visibleErr != nil || !sameStatisticsRecoveryFile(before, after) || !sameStatisticsRecoveryFile(before, visible) || !root.current() {
		return errors.New("统计日志只读检查期间源文件变化")
	}
	if !bytes.Equal(header, make([]byte, len(header))) {
		return errors.New("统计历史有未完成或未知写入日志；原库和日志保留，先核对写入进程或执行显式摘要绑定恢复")
	}
	return nil
}

func (s *Service) prepareStatisticsPrivateDirectory() error {
	if err := s.wafOwnedDirectory(s.Config.SecurityDir, true); err != nil {
		return err
	}
	for _, dir := range []string{filepath.Join(s.Config.SecurityDir, "modules"), s.moduleDir("website-statistics-v2")} {
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			if err = os.Mkdir(dir, 0700); err != nil {
				return err
			}
		}
		info, err := os.Lstat(dir)
		if err != nil || !moduleRecordInfo(info, true, false) {
			return errors.New("统计私有目录身份、链接或权限异常，未修复或接管")
		}
	}
	directory, err := s.moduleRecordDirectory("website-statistics-v2")
	if err != nil {
		return err
	}
	return directory.Close()
}

// Read-only health/preflight. Never creates a database, recovers a hot journal,
// changes its version or treats a missing/corrupt store as healthy.
func (s *Service) statisticsHistorySchemaReadOnly(ctx context.Context) (int, error) {
	directory, err := s.moduleRecordDirectory("website-statistics-v2")
	if err != nil {
		return -1, err
	}
	defer directory.Close()
	info, err := directory.Lstat("access.sqlite")
	if errors.Is(err, os.ErrNotExist) && directory.current() {
		return -1, nil
	}
	if err != nil || !moduleRecordInfo(info, false, false) || info.Size() > 512<<20 {
		return -1, errors.New("统计数据库类型、权限或容量异常，未覆盖原数据")
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		journal, err := directory.Lstat("access.sqlite" + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !moduleRecordInfo(journal, false, false) {
			return -1, errors.New("统计数据库恢复文件身份异常，未接管")
		}
		if suffix == "-journal" {
			if err = statisticsReadOnlyJournalGuard(directory, journal); err != nil {
				return -1, err
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return -1, err
	}
	path := filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return -1, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var version, pageSize int
	if err = db.QueryRowContext(bounded, "PRAGMA user_version").Scan(&version); err != nil || version < 0 || version > 2 {
		return -1, errors.New("统计历史版本或内容无法核对，原数据保留")
	}
	if err = db.QueryRowContext(bounded, "PRAGMA page_size").Scan(&pageSize); err != nil || pageSize != 4096 {
		return -1, errors.New("统计历史页大小无法核对")
	}
	if version == 0 {
		var objects int
		if err = db.QueryRowContext(bounded, "SELECT count(*) FROM sqlite_master WHERE type IN ('table','view','trigger') AND name NOT LIKE 'sqlite_%'").Scan(&objects); err != nil || objects != 0 {
			return -1, errors.New("未定版统计历史包含非空结构，未迁移或覆盖")
		}
	}
	if version > 0 {
		if err = validateStatisticsSchemaObjects(bounded, db, version); err != nil {
			return -1, err
		}
		var tables int
		want := 3
		if version == 2 {
			want = 5
		}
		if err = db.QueryRowContext(bounded, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('access_rows','access_streams','access_retention','access_receipts','access_archives')").Scan(&tables); err != nil || tables != want {
			return -1, errors.New("统计历史受管表集合不完整，未报告就绪")
		}
		var triggers, futureTables int
		if err = db.QueryRowContext(bounded, "SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('access_rows','access_streams','access_retention','access_receipts','access_archives')").Scan(&triggers); err != nil || triggers != 0 {
			return -1, errors.New("统计历史包含非受管触发器，未执行迁移或报告就绪")
		}
		if version == 1 {
			if err = db.QueryRowContext(bounded, "SELECT count(*) FROM sqlite_master WHERE name IN ('access_receipts','access_archives')").Scan(&futureTables); err != nil || futureTables != 0 {
				return -1, errors.New("旧统计历史包含未确认的新格式结构，未覆盖")
			}
		}
		queries := []string{
			"SELECT seq,site,stamp,ip,path,status,seconds,bot,payload FROM access_rows LIMIT 0",
			"SELECT site,identity,name,offset,anchor,size,seen,blocked,invalid FROM access_streams LIMIT 0",
			"SELECT site,evicted FROM access_retention LIMIT 0",
		}
		if version == 2 {
			queries = append(queries, "SELECT site,request_id,payload_sha,stamp FROM access_receipts LIMIT 0", "SELECT site,identity,metadata,digest,state,evidence_sha FROM access_archives LIMIT 0")
		}
		for _, query := range queries {
			rows, err := db.QueryContext(bounded, query)
			if err != nil {
				return -1, errors.New("统计历史表结构与安装版本不符，未报告就绪")
			}
			if err = rows.Close(); err != nil {
				return -1, err
			}
		}
		if version == 2 {
			for table, expected := range map[string][]string{
				"access_receipts": {"site:TEXT:1", "request_id:TEXT:2", "payload_sha:TEXT:0", "stamp:INTEGER:0"},
				"access_archives": {"site:TEXT:1", "identity:TEXT:2", "metadata:TEXT:0", "digest:TEXT:0", "state:INTEGER:0", "evidence_sha:TEXT:0"},
			} {
				rows, err := db.QueryContext(bounded, "PRAGMA table_info("+table+")")
				if err != nil {
					return -1, err
				}
				at := 0
				for rows.Next() {
					var cid, notNull, primary int
					var name, kind string
					var defaultValue any
					if err = rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil || at >= len(expected) || cid != at || notNull != 1 || defaultValue != nil || fmt.Sprintf("%s:%s:%d", name, kind, primary) != expected[at] {
						rows.Close()
						return -1, errors.New("统计请求或归档去重主键结构异常，未报告就绪")
					}
					at++
				}
				err = rows.Err()
				rows.Close()
				if err != nil || at != len(expected) {
					return -1, errors.New("统计去重结构不完整")
				}
			}
		}
	}
	visible, err := directory.Lstat("access.sqlite")
	if err != nil || !directory.current() || !os.SameFile(info, visible) || !moduleRecordInfo(visible, false, false) {
		return -1, errors.New("统计历史读取期间目录或文件身份改变")
	}
	return version, nil
}

func (s *Service) statisticsInstalledReady(ctx context.Context) error {
	reader, err := s.statisticsLogReadLock()
	if err != nil {
		return err
	}
	defer reader.Close()
	before, err := s.statisticsLogTransactionService().statisticsLogStableBackup(s.Config.NginxConf)
	if err != nil || !before.existed {
		return errors.New("统计受管日志配置无法核对")
	}
	if _, changed, err := statisticsRequestIDNginxConfig(before.data); err != nil || changed {
		return errors.New("统计请求标识格式尚未生效或配置被改写")
	}
	nonce, err := statisticsHealthConfigNonce(before.data, s.statisticsHealthSocket())
	if err != nil || nonce == "" {
		return errors.New("统计配置缺少已核对的本机生效身份")
	}
	if err = s.statisticsHealthLoaded(ctx, nonce); err != nil {
		return err
	}
	schema, err := s.statisticsHistorySchemaReadOnly(ctx)
	if err != nil || schema != 2 {
		return errors.Join(errors.New("统计日志已启用，但历史库尚未就绪；原数据保留，后台会重试初始化"), err)
	}
	return nil
}

// Normal fixed-handler install/update entry. The signed package version reaches
// this method through the existing registry/job binding, not a runtime override.
// Never hold the legacy SH lifecycle lock while acquiring this EX migration lock.
func (s *Service) statisticsIdentityLifecycle(ctx context.Context, action string, settings map[string]any, add func(string)) error {
	return s.statisticsVersionLifecycle(ctx, statisticsIdentityVersion, action, settings, add)
}
func (s *Service) statisticsVersionLifecycle(ctx context.Context, desiredVersion, action string, settings map[string]any, add func(string)) error {
	if desiredVersion == statisticsGeographyVersion {
		lease, err := statisticsGeoInstanceLease(true)
		if err != nil {
			return err
		}
		defer lease.Close()
	}
	if desiredVersion != statisticsIdentityVersion && desiredVersion != statisticsGeographyVersion {
		return errors.New("统计安装或更新不是已实现的固定版本")
	}
	tx := s.statisticsLogTransactionService()
	lock, err := tx.lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = tx.recoverStatisticsLogBeforeMutation(ctx); err != nil {
		return err
	}
	previous, err := s.moduleInstalledRecord("website-statistics-v2")
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if action == "install" && exists {
		return errors.New("统计应用已安装，安装不能覆盖原记录；请使用签名更新")
	}
	if action == "update" && !exists {
		return errors.New("统计应用未安装，不能发布更新记录")
	}
	if action != "install" && action != "update" {
		return errors.New("统计格式迁移动作无效")
	}
	if err = s.prepareStatisticsPrivateDirectory(); err != nil {
		return err
	}
	if _, err = s.statisticsHistorySchemaReadOnly(ctx); err != nil {
		return err
	}
	next := map[string]any{"id": "website-statistics-v2", "version": desiredVersion, "settings": settings, "installed_at": core.Now()}
	if exists {
		version, _ := previous["version"].(string)
		if version == "" {
			version = "1.0"
		}
		comparison, valid := appcatalog.CompareVersions(desiredVersion, version)
		if !valid || comparison < 0 {
			return errors.New("统计更新拒绝降级或未知原版本")
		}
		next = previous
		next["version"] = desiredVersion
		if comparison > 0 {
			next["updated_at"] = core.Now()
		}
		if comparison == 0 {
			// A retry after committed files / interrupted schema initialization
			// keeps the exact installed record and probe. No new nonce/revision.
			data, err := tx.statisticsLogStableBackup(s.Config.NginxConf)
			if err != nil {
				return err
			}
			if _, changed, err := statisticsRequestIDNginxConfig(data.data); err != nil || changed {
				return errors.New("已安装统计格式发生外部变化，未覆盖")
			}
			nonce, err := statisticsHealthConfigNonce(data.data, s.statisticsHealthSocket())
			if err != nil || nonce == "" {
				return errors.New("已安装统计探针无法核对，未覆盖")
			}
			if err = s.statisticsHealthLoaded(ctx, nonce); err != nil {
				return err
			}
			return s.initializeStatisticsIdentityHistory(ctx, add)
		}
	}
	if desiredVersion == statisticsGeographyVersion {
		if _, exists := next["installation_id"]; !exists {
			next["installation_id"] = core.ID()
		}
		id, ok := next["installation_id"].(string)
		if !ok || !core.ValidID(id) {
			return errors.New("统计地域应用实例身份损坏，未修复或接管")
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	plan, err := tx.statisticsLogPlan(raw)
	if err != nil {
		return err
	}
	if err = tx.applyStatisticsLogPlan(ctx, plan); err != nil {
		return err
	}
	// SQLite schema publication follows the committed native/installed identity.
	// A crash or initialization failure leaves a known2.5 record with explicitly
	// UNHEALTHY history, never an old manifest pointing at a migrated schema.
	return s.initializeStatisticsIdentityHistory(ctx, add)
}

func (s *Service) initializeStatisticsIdentityHistory(ctx context.Context, add func(string)) error {
	db, err := s.openStatisticsHistorySchema(ctx, 2)
	if err != nil {
		return fmt.Errorf("统计日志迁移已确认，但历史初始化未完成；原数据保留，应用未就绪：%w", err)
	}
	if err = db.Close(); err != nil {
		return err
	}
	version, err := s.statisticsHistorySchemaReadOnly(ctx)
	if err != nil || version != 2 {
		return errors.Join(errors.New("统计历史初始化后的结构未确认，应用未就绪，原数据保留"), err)
	}
	add("固定日志配置及本机已加载身份已确认；历史库已就绪，原设置、安装时间、访问数据及游标保留")
	return nil
}
