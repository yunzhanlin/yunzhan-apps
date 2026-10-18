//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/diskjob"
)

func (s *Service) diskHostObservationRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/disk-host-jobs/observe", func(w http.ResponseWriter, r *http.Request) {
		var raw json.RawMessage
		if !readJSON(w, r, &raw) {
			return
		}
		in, err := diskjob.DecodeRequest(raw)
		if err != nil || s.Config.SystemRoot != "/" {
			respond(w, 400, map[string]string{"error": "原全盘任务选择无效；未读取替代根目录"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		reader, err := openDiskHostCoreReader()
		if err != nil {
			respond(w, 409, map[string]string{"error": "原全盘任务授权不能核对"})
			return
		}
		defer reader.db.Close()
		guard := func() bool {
			return reader.current() && (&core.Store{DB: reader.db}).ValidateHostDiskObservation(ctx, in) == nil && reader.current()
		}
		if !guard() {
			respond(w, 403, map[string]string{"error": "仅原完整管理员可核对全盘任务"})
			return
		}
		journal, err := diskjob.OpenRootJob(in.JobID)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原全盘任务暂不可读取；未认定结束或重发"})
			return
		}
		defer journal.Close()
		observation, err := journal.Observe(in)
		if err != nil || ctx.Err() != nil || !guard() {
			respond(w, 409, map[string]string{"error": "原全盘记录、权限或实际退出状态无法核对"})
			return
		}
		respond(w, 200, observation)
	})
}
