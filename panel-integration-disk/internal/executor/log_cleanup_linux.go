//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"math"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const siteLogDirectoryLimit = 100000
const siteLogExpiredLimit = 1000

func siteLogExpiredBytes(items []plannedSiteLog) (int64, error) {
	var total int64
	for _, item := range items {
		if item.info == nil || item.info.Size() < 0 || item.info.Size() > math.MaxInt64-total {
			return 0, errors.New("过期日志大小无法安全累计；未开始变更")
		}
		total += item.info.Size()
	}
	return total, nil
}

func siteLogArchiveName(id, name string) bool {
	return core.ValidSiteLogArchiveName(id, name)
}

type plannedSiteLog struct {
	name, target string
	info         os.FileInfo
}

// Validate every affected file before the first rename or deletion. Another
// site's files and ambiguous timestamps are never inferred to be ours.
func planSiteLogCleanup(ctx context.Context, root *os.Root, id string, days int, now time.Time) ([]plannedSiteLog, []plannedSiteLog, error) {
	active, expired := []plannedSiteLog{}, []plannedSiteLog{}
	stamp := now.UTC().Format("20060102-150405")
	for _, kind := range []string{"access", "error"} {
		name := "panel-" + id + "." + kind + ".log"
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || privateLogEntry(info) != nil {
			return nil, nil, errors.New("站点日志类型、归属、权限或链接数异常；未开始轮转")
		}
		if info.Size() == 0 {
			continue
		}
		target := name + "." + stamp
		if _, err = root.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("同一时间的归档已存在或无法核实；不覆盖已有日志")
		}
		active = append(active, plannedSiteLog{name, target, info})
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, nil, err
	}
	entries, err := dir.ReadDir(siteLogDirectoryLimit + 1)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, err
	}
	if len(entries) > siteLogDirectoryLimit {
		return nil, nil, errors.New("日志目录超过 100000 项；未开始变更，请先人工核对")
	}
	pattern := regexp.MustCompile(`^panel-` + regexp.QuoteMeta(id) + `\.(access|error)\.log\.([0-9]{8}-[0-9]{6})(\.gz)?$`)
	cutoff := now.UTC().Add(-time.Duration(days) * 24 * time.Hour)
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return nil, nil, err
		}
		match := pattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		created, parseErr := time.Parse("20060102-150405", match[2])
		if parseErr != nil || created.Format("20060102-150405") != match[2] || !created.Before(cutoff) {
			continue
		}
		info, statErr := root.Lstat(entry.Name())
		if statErr != nil || privateLogEntry(info) != nil {
			return nil, nil, errors.New("轮转日志类型、归属、权限或链接数异常；未开始清理")
		}
		expired = append(expired, plannedSiteLog{name: entry.Name(), info: info})
		if len(expired) > siteLogExpiredLimit {
			return nil, nil, errors.New("单次过期日志超过 1000 项；未开始变更，请先人工核对")
		}
	}
	sort.Slice(expired, func(i, j int) bool { return expired[i].name < expired[j].name })
	if _, err = siteLogExpiredBytes(expired); err != nil {
		return nil, nil, err
	}
	return active, expired, ctx.Err()
}

func samePlannedSiteLog(root *os.Root, item plannedSiteLog) error {
	info, err := root.Lstat(item.name)
	if err != nil || privateLogEntry(info) != nil || !os.SameFile(info, item.info) {
		return errors.New("日志路径身份已经变化；停止操作并保留现有日志")
	}
	return nil
}

func cleanupSiteLogs(ctx context.Context, id string, days int, now time.Time, reopen func(context.Context) error) (core.LogCleanupResult, error) {
	return cleanupSiteLogsAt(ctx, "/var/log/nginx", id, days, now, reopen)
}

func cleanupSiteLogsAt(ctx context.Context, base, id string, days int, now time.Time, reopen func(context.Context) error) (core.LogCleanupResult, error) {
	return cleanupSiteLogsAtGuarded(ctx, base, id, days, now, reopen, nil, nil)
}

func cleanupSiteLogsAtGuarded(ctx context.Context, base, id string, days int, now time.Time, reopen func(context.Context) error, beforeMutation func([]plannedSiteLog, []plannedSiteLog) error, beforeRetire func() error) (core.LogCleanupResult, error) {
	result := core.LogCleanupResult{Files: []string{}}
	if !core.ValidID(id) || days < 1 || days > 100 || !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return result, errors.New("日志清理参数无效")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := ownedRuntimePath(base, true); err != nil {
		return result, errors.New("日志目录类型、归属或权限异常；不接管外部目录")
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return result, err
	}
	defer root.Close()
	anchor, err := root.Stat(".")
	if err != nil {
		return result, err
	}
	checkRoot := func() error {
		info, e := os.Lstat(base)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || !os.SameFile(anchor, info) || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("日志目录身份已变化；停止并保留日志")
		}
		return nil
	}
	active, expired, err := planSiteLogCleanup(ctx, root, id, days, now)
	if err != nil {
		return result, err
	}
	if len(active) > 0 && reopen == nil {
		return result, errors.New("缺少 Nginx 重新打开日志处理器；未开始变更")
	}
	if beforeMutation != nil {
		if err = beforeMutation(active, expired); err != nil {
			return result, err
		}
	}
	moved := []plannedSiteLog{}
	rollback := func(cause error) error {
		conflict := false
		for i := len(moved) - 1; i >= 0; i-- {
			item := moved[i]
			if checkRoot() != nil || samePlannedSiteLog(root, plannedSiteLog{name: item.target, info: item.info}) != nil || renameNoReplace(root, item.target, item.name) != nil {
				conflict = true
			}
		}
		if conflict {
			return fmt.Errorf("日志操作未完成，原归档及新的活动日志均保留；无法安全回滚，需人工核对: %w", cause)
		}
		return fmt.Errorf("日志操作未完成，已无覆盖恢复原日志；尚未删除过期日志: %w", cause)
	}
	for _, item := range active {
		if err = ctx.Err(); err != nil {
			return result, rollback(err)
		}
		if err = checkRoot(); err != nil {
			return result, rollback(err)
		}
		if err = samePlannedSiteLog(root, item); err != nil {
			return result, rollback(err)
		}
		if err = renameNoReplace(root, item.name, item.target); err != nil {
			return result, rollback(err)
		}
		moved = append(moved, item)
		result.Rotated++
	}
	if len(moved) > 0 {
		if err = reopen(ctx); err != nil {
			return result, rollback(err)
		}
	}
	if len(expired) > 0 && beforeRetire != nil {
		if err = beforeRetire(); err != nil {
			return result, err
		}
	}
	for _, item := range expired {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		if err = checkRoot(); err != nil {
			return result, err
		}
		if err = samePlannedSiteLog(root, item); err != nil {
			return result, err
		}
		info, e := root.Lstat(item.name)
		if e != nil {
			return result, e
		}
		// A timestamped archive which grew since planning is not an immutable
		// retirement candidate. Never remove a newly appended active inode.
		if info.Size() != item.info.Size() || !info.ModTime().Equal(item.info.ModTime()) {
			return result, errors.New("过期日志在核对后发生写入；保留数据且停止清理")
		}
		if err = root.Remove(item.name); err != nil {
			return result, err
		}
		result.Deleted++
		result.DeletedBytes += info.Size()
		result.Files = append(result.Files, item.name)
	}
	return result, nil
}

func privateLogEntry(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || info.Size() < 0 {
		return errors.New("日志不是受管普通文件")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("日志链接数或身份异常")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		if os.Geteuid() != 0 {
			return errors.New("日志所有者不匹配")
		}
		account, err := user.Lookup("www-data")
		if err != nil {
			return errors.New("Nginx 日志账户不可核实")
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil || uid < 1 || uint32(uid) != stat.Uid {
			return errors.New("日志所有者不属于面板或固定 Nginx 账户")
		}
	}
	return nil
}

func (s *Service) logCleanupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/{id}/logs/operations/{request}/continue", func(w http.ResponseWriter, r *http.Request) {
		var in core.LogCleanupContinueRequest
		if !readJSON(w, r, &in) {
			return
		}
		if in.SiteID != r.PathValue("id") || in.RequestID != r.PathValue("request") {
			respond(w, 400, map[string]string{"error": "日志核实对象不匹配"})
			return
		}
		out, e := s.continueSiteLogCleanup(r.Context(), in, nil)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("GET /v1/sites/{id}/logs/operations/{request}", func(w http.ResponseWriter, r *http.Request) {
		out, e := s.inspectSiteLogCleanup(r.Context(), r.PathValue("id"), r.PathValue("request"))
		if e != nil {
			respond(w, 409, map[string]string{"error": "日志操作身份或记录不可核实；保留文件和记录，未执行修改"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/sites/{id}/logs/cleanup", func(w http.ResponseWriter, r *http.Request) {
		var in core.LogCleanupRequest
		if !readJSON(w, r, &in) {
			return
		}
		if in.SiteID != r.PathValue("id") || strings.TrimSpace(in.SiteID) == "" {
			respond(w, 400, map[string]string{"error": "日志清理站点不匹配"})
			return
		}
		result, e := s.guardedSiteLogCleanup(r.Context(), in, time.Now(), nil)
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, result)
	})
}
