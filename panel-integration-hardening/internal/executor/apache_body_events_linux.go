//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http"
	"os"
	"syscall"
	"time"
)

const apacheBodyEventsLimit int64 = 32 << 20

func emptyApacheBodyEvents() core.ApacheBodyEventsPage {
	return core.ApacheBodyEventsPage{Events: []core.ApacheBodyEvent{}, BestEffort: true, MaxBytes: apacheBodyEventsLimit}
}

// No creation, ownership repair, engine loading or log fallback is performed
// by this read. Missing is checked through the fixed root-owned ancestors;
// a link, FIFO, foreign directory or unreadable file is never an empty report.
func readApacheBodyEvents(ctx context.Context) (core.ApacheBodyEventsPage, error) {
	page := emptyApacheBodyEvents()
	if err := ctx.Err(); err != nil {
		return page, err
	}
	f, err := openApacheBodyMetadataLog()
	if errors.Is(err, os.ErrNotExist) {
		return page, nil
	}
	if err != nil {
		return page, err
	}
	defer f.Close()
	return readApacheBodyEventsFile(ctx, f)
}

func readApacheBodyEventsFile(ctx context.Context, f *os.File) (core.ApacheBodyEventsPage, error) {
	page := emptyApacheBodyEvents()
	if err := ctx.Err(); err != nil {
		return page, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return page, errors.New("Apache 数值日志正在写入或轮转，未当成零匹配，请稍后读取")
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > apacheBodyEventsLimit {
		return page, errors.New("Apache 数值日志快照类型或容量异常")
	}
	const budget = 4 << 20
	start := max(int64(0), before.Size()-budget)
	data := make([]byte, before.Size()-start)
	if len(data) > 0 {
		if _, err := f.ReadAt(data, start); err != nil {
			return page, err
		}
	}
	after, err := f.Stat()
	current, currentErr := os.Lstat(f.Name())
	if err != nil || currentErr != nil || !apacheBodyEventsSameFile(before, after) || !apacheBodyEventsSameFile(after, current) {
		return page, errors.New("Apache 数值日志在读取期间发生变化，未返回旧快照冒充当前结果")
	}
	page.Available = true
	page.LogBytes = before.Size()
	page.CapacityNearLimit = before.Size() > apacheBodyEventsLimit-256
	page.Partial = page.CapacityNearLimit || start > 0
	lines := bytes.Split(data, []byte{'\n'})
	if start > 0 {
		lines = lines[1:]
	}
	if len(lines) > 0 && len(lines[len(lines)-1]) > 0 {
		// A partial final record is not a completed event, even if its JSON
		// happens to be parseable. Never expose its raw bytes on failure.
		page.Rejected++
		page.Partial = true
		lines = lines[:len(lines)-1]
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if err := ctx.Err(); err != nil {
			return emptyApacheBodyEvents(), err
		}
		line := lines[i]
		if len(line) == 0 {
			continue
		}
		if len(page.Events) == 5000 {
			page.Partial = true
			break
		}
		if event, ok := parseApacheBodyEvent(line); ok {
			page.Events = append(page.Events, event)
		} else {
			page.Rejected++
			page.Partial = true
		}
	}
	return page, ctx.Err()
}

func apacheBodyEventsSameFile(a, b os.FileInfo) bool {
	if a == nil || b == nil || !a.Mode().IsRegular() || !b.Mode().IsRegular() {
		return false
	}
	x, ok := a.Sys().(*syscall.Stat_t)
	y, otherOK := b.Sys().(*syscall.Stat_t)
	return ok && otherOK && x.Dev == y.Dev && x.Ino == y.Ino && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Nlink == 1 && x.Size == y.Size && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func (s *Service) apacheBodyReportRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/software/apache-waf/body-report", func(w http.ResponseWriter, r *http.Request) {
		query, err := core.ApacheBodyReportQuery(r.URL.Query(), time.Now())
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if s.Config.SystemRoot != "/" || os.Geteuid() != 0 {
			respond(w, 503, map[string]string{"error": "Apache 数值日志仅从实际固定目录读取，不接受自定义日志路径或模拟运行环境"})
			return
		}
		page, err := readApacheBodyEvents(r.Context())
		if err != nil {
			respond(w, 503, map[string]string{"error": err.Error()})
			return
		}
		report, err := core.BuildApacheBodyReport(page, query, time.Now())
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, report)
	})
}
