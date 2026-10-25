package core

import (
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
