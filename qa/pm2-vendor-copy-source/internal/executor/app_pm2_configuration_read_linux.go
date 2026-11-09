//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

// A terminal file can become visible just before its fsync. The original
// writer holds the project lock until its intent/result and parent have been
// synced. Read-only callers must obtain a shared lease before treating that
// terminal publication as settled; they never create or repair a lock.
func (s *Service) pm2ConfigurationTerminalReadLease(id string) (*os.File, error) {
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	if err = pm2ConfigChild(d, "locks", false); err != nil {
		return nil, err
	}
	name := id + ".lock"
	info, err := d.Lstat(name)
	if err != nil || !moduleRecordInfo(info, false, false) {
		return nil, errors.New("PM2 原配置操作锁无法核对")
	}
	f, err := d.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !programQueueSame(info, opened) || !d.current() {
		f.Close()
		return nil, errors.New("PM2 原操作锁身份发生变化")
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("PM2 原操作仍在处理，尚未返回持久完成证明；请稍后只读核对")
	}
	visible, err := d.Lstat(name)
	if err != nil || !programQueueSame(info, visible) || !d.current() {
		f.Close()
		return nil, errors.New("PM2 原操作锁在读取期间变化")
	}
	return f, nil
}
func (s *Service) pm2ConfigurationReadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/pm2-manager/configuration", func(w http.ResponseWriter, r *http.Request) {
		in, err := core.ParsePM2ConfigurationQuery(r.URL.RawQuery)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		guard, installed, err := s.beginModuleAlertRead("pm2-manager")
		if err != nil || !installed {
			respond(w, 409, map[string]string{"error": "PM2 安装身份无法核对，未读取配置事务"})
			return
		}
		defer guard.dir.Close()
		records, err := s.pm2ConfigRecords()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		page, err := publicPM2ConfigPage(records, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		originalPage, _ := json.Marshal(page)
		leases := []*os.File{}
		defer func() {
			for _, f := range leases {
				f.Close()
			}
		}()
		seen := map[string]bool{}
		for _, v := range page["configuration_transactions"].([]any) {
			row := v.(map[string]any)
			if row["state"] == "needs_attention" {
				continue
			}
			id := row["resource_id"].(string)
			if seen[id] {
				continue
			}
			seen[id] = true
			f, e := s.pm2ConfigurationTerminalReadLease(id)
			if e != nil {
				respond(w, 409, map[string]string{"error": e.Error()})
				return
			}
			leases = append(leases, f)
		}
		// An operation might finish between the inventory and lease acquisition.
		// Re-read under all selected terminal leases; no old file earns authority.
		current, err := s.pm2ConfigRecords()
		if err == nil {
			page, err = publicPM2ConfigPage(current, in)
		}
		if err == nil {
			next, _ := json.Marshal(page)
			if !bytes.Equal(originalPage, next) {
				err = errors.New("PM2 configuration publication changed during read")
			}
		}
		if err == nil {
			err = guard.check(r.Context())
		}
		if err != nil {
			respond(w, 409, map[string]string{"error": "PM2 原配置事务读取期间变化，请重新只读核对"})
			return
		}
		respond(w, 200, page)
	})
}
