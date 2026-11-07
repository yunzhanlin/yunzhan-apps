//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"local/panel/internal/core"
)

// This bounded view does not open configuration transactions or old reports,
// create a lock, repair a record, or wait on the executor's mutation mutex.
// It observes only private known projects and their fixed systemd units.
func pm2ProjectNames(d *modulePrivateDirectory) ([]string, error) {
	f, err := d.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := f.ReadDir(513)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) > 512 || !d.current() {
		return nil, errors.New("PM2 项目清单超过512项或原目录无法完整核对")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !strings.HasSuffix(entry.Name(), ".json") || !moduleResourceID.MatchString(id) {
			return nil, errors.New("PM2 原项目目录含无法核对的记录，未忽略或改动原文件")
		}
		names = append(names, id)
	}
	sort.Strings(names)
	return names, nil
}

func (s *Service) readPM2Projects(ctx context.Context, in core.AppModuleInput) (any, error) {
	guard, installed, err := s.beginModuleAlertRead("pm2-manager")
	if err != nil || !installed {
		return nil, errors.New("PM2 原安装身份无法核对，未读取或启动任何项目")
	}
	defer guard.dir.Close()
	d, err := s.moduleRecordDirectory("pm2-manager")
	if err != nil {
		return nil, err
	}
	defer d.Close()
	err = pm2ConfigChild(d, "apps", false)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return nil, err
	}
	all := []string{}
	if !missing {
		all, err = pm2ProjectNames(d)
		if err != nil {
			return nil, err
		}
	}
	selected := make([]string, 0, len(all))
	for _, id := range all {
		if in.ResourceID == "" || in.ResourceID == id {
			selected = append(selected, id)
		}
	}
	start := min(in.Offset, len(selected))
	end := min(start+in.Limit, len(selected))
	apps, failures := []any{}, []any{}
	pageComplete := true
	for _, id := range selected[start:end] {
		app, digest, err := s.pm2StopApp(id)
		if err != nil {
			pageComplete = false
			failures = append(failures, map[string]any{"resource_id": id, "state": "unknown", "error": "原项目身份或内容无法核对，未读取其他服务"})
			continue
		}
		state, stateErr := s.readPM2UnitState(ctx, "panel-pm2@"+id+".service")
		current, nextDigest, readErr := s.pm2StopApp(id)
		if readErr != nil || current.ID != app.ID || nextDigest != digest || !d.current() {
			pageComplete = false
			failures = append(failures, map[string]any{"resource_id": id, "state": "unknown", "error": "项目在服务读取期间变化，请重新只读核对"})
			continue
		}
		row := map[string]any{"app": publicPM2App(app), "original_project_sha256": digest, "state": state.ActiveState, "state_known": stateErr == nil, "boot_enabled": state.UnitFileState == "enabled"}
		if stateErr != nil {
			pageComplete = false
			row["state"], row["boot_enabled"], row["error"] = "unknown", nil, stateErr.Error()
		}
		apps = append(apps, row)
	}
	if missing {
		if _, err = d.Lstat("apps"); !errors.Is(err, os.ErrNotExist) || !d.current() {
			return nil, errors.New("PM2 原项目目录在读取期间出现或变化，请重新只读核对")
		}
	} else {
		now, err := pm2ProjectNames(d)
		if err != nil || !reflect.DeepEqual(all, now) {
			return nil, errors.New("PM2 原项目清单在读取期间变化，请重新只读核对")
		}
	}
	if err := guard.check(ctx); err != nil {
		return nil, err
	}
	return map[string]any{"apps": apps, "unreadable_projects": failures, "total": len(selected), "limit": in.Limit, "offset": start, "project_page_complete": pageComplete, "projects_readonly": true, "configuration_not_inspected": true, "configuration_or_deployment_replayed": false, "history_or_report_written": false, "observed_at": core.Now()}, nil
}

func (s *Service) pm2ProjectsReadRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/app-modules/pm2-manager/projects", func(w http.ResponseWriter, r *http.Request) {
		in, err := core.ParsePM2ProjectsQuery(r.URL.RawQuery)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		out, err := s.readPM2Projects(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
}
