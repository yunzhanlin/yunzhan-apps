package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func decodeHardeningRecoveryBody(raw []byte) (map[string]any, error) {
	if len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"settings"}) {
		return nil, errors.New("加固恢复请求必须是唯一、完整且有界的 settings 对象")
	}
	var outer struct {
		Settings json.RawMessage `json:"settings"`
	}
	if json.Unmarshal(raw, &outer) != nil || !wafInventoryJSONShape(outer.Settings, []string{"transaction_id", "sha256", "confirm"}) {
		return nil, errors.New("加固恢复字段缺失、重复、未知或非规范")
	}
	var input HardeningRecoveryRequest
	if json.Unmarshal(outer.Settings, &input) != nil {
		return nil, errors.New("加固恢复字段类型无效")
	}
	return NormalizeHardeningRecovery(map[string]any{"transaction_id": input.TransactionID, "sha256": input.SHA256, "confirm": input.Confirm})
}

func (a *Server) hardeningRecoveryRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/software/system-hardening/jobs/{job}", a.authorize(func(w http.ResponseWriter, r *http.Request, _ identity) {
		w.Header().Set("Cache-Control", "no-store")
		id := r.PathValue("job")
		if !ValidID(id) || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "系统加固原任务标识或查询字段无效")
			return
		}
		var out struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			State string `json:"state"`
			Error string `json:"error"`
		}
		err := a.Store.DB.QueryRowContext(r.Context(), `SELECT id,kind,state,error FROM runtime_jobs
			WHERE id=? AND target_id='system-hardening'
			AND kind IN ('software_install','software_configure','software_uninstall','software_recover')`, id).
			Scan(&out.ID, &out.Kind, &out.State, &out.Error)
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "未找到系统加固原任务")
			return
		}
		if err != nil {
			fail(w, 503, "系统加固原任务暂时无法读取")
			return
		}
		if !containsString([]string{"queued", "running", "succeeded", "failed", "needs_attention", "cancelled"}, out.State) || len(out.Error) > 32768 {
			fail(w, 409, "系统加固原任务状态无法核对")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/system-hardening/inspection", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		var out any
		if err := a.Executor.Call(r.Context(), http.MethodGet, "/v1/software/system-hardening/inspection", nil, &out); err != nil {
			fail(w, 503, err.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/software/system-hardening/recover", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			fail(w, 400, "加固恢复请求过大或不完整")
			return
		}
		settings, err := decodeHardeningRecoveryBody(raw)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		job, err := a.Store.QueueSoftwareAction("system-hardening", "recover", settings, r.Header.Get("Idempotency-Key"), u.Username)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 202, map[string]string{"job_id": job})
	}))
}
