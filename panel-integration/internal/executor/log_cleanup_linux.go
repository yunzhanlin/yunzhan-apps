//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

func cleanupSiteLogs(ctx context.Context, id string, days int, now time.Time, reopen func(context.Context) error) (core.LogCleanupResult, error) {
	return cleanupSiteLogsAt(ctx, "/var/log/nginx", id, days, now, reopen)
}

func cleanupSiteLogsAt(ctx context.Context, base, id string, days int, now time.Time, reopen func(context.Context) error) (core.LogCleanupResult, error) {
	result := core.LogCleanupResult{Files: []string{}}
	if !core.ValidID(id) || days < 1 || days > 100 {
		return result, errors.New("日志清理参数无效")
	}
	root, e := os.OpenRoot(base)
	if e != nil {
		return result, e
	}
	defer root.Close()
	stamp := now.UTC().Format("20060102-150405")
	type movedLog struct{ old, rotated string }
	moved := []movedLog{}
	for _, kind := range []string{"access", "error"} {
		name := "panel-" + id + "." + kind + ".log"
		info, statErr := root.Lstat(name)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil || privateLogEntry(info) != nil {
			return result, errors.New("站点日志类型或归属异常")
		}
		if info.Size() == 0 {
			continue
		}
		rotated := name + "." + stamp
		if e = root.Rename(name, rotated); e != nil {
			return result, e
		}
		moved = append(moved, movedLog{name, rotated})
		result.Rotated++
	}
	if result.Rotated > 0 {
		if e = reopen(ctx); e != nil {
			for index := len(moved) - 1; index >= 0; index-- {
				_ = root.Rename(moved[index].rotated, moved[index].old)
			}
			return result, fmt.Errorf("Nginx 重新打开日志失败，已恢复原日志: %w", e)
		}
	}
	dir, e := root.Open(".")
	if e != nil && !errors.Is(e, io.EOF) {
		return result, e
	}
	entries, e := dir.ReadDir(100001)
	dir.Close()
	if e != nil {
		return result, e
	}
	pattern := regexp.MustCompile(`^panel-` + regexp.QuoteMeta(id) + `\.(access|error)\.log\.([0-9]{8}-[0-9]{6})(\.gz)?$`)
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	for _, entry := range entries {
		match := pattern.FindStringSubmatch(entry.Name())
		if match == nil {
			continue
		}
		created, parseErr := time.Parse("20060102-150405", match[2])
		if parseErr != nil || !created.Before(cutoff.UTC()) {
			continue
		}
		info, statErr := root.Lstat(entry.Name())
		if statErr != nil || privateLogEntry(info) != nil {
			return result, errors.New("轮转日志类型或归属异常")
		}
		if e = root.Remove(entry.Name()); e != nil {
			return result, e
		}
		result.Deleted++
		result.DeletedBytes += info.Size()
		result.Files = append(result.Files, entry.Name())
	}
	return result, nil
}

func privateLogEntry(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0002 != 0 {
		return errors.New("日志不是受管普通文件")
	}
	return nil
}

func (s *Service) logCleanupRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/sites/{id}/logs/cleanup", func(w http.ResponseWriter, r *http.Request) {
		var in core.LogCleanupRequest
		if !readJSON(w, r, &in) {
			return
		}
		if in.SiteID != r.PathValue("id") || strings.TrimSpace(in.SiteID) == "" {
			respond(w, 400, map[string]string{"error": "日志清理站点不匹配"})
			return
		}
		lock := fileMutex(in.SiteID)
		lock.Lock()
		defer lock.Unlock()
		result, e := cleanupSiteLogs(r.Context(), in.SiteID, in.RetentionDays, time.Now(), func(ctx context.Context) error {
			_, e := s.Config.Run(ctx, "systemctl", "kill", "-s", "USR1", "nginx")
			return e
		})
		if e != nil {
			respond(w, 409, map[string]string{"error": e.Error()})
			return
		}
		respond(w, 200, result)
	})
}
