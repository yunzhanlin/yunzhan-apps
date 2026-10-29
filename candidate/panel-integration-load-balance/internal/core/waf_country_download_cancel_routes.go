package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// Always observe the fixed Root original independently of browser input.
// This method has no Root POST, source download, signal or request creation.
func (a *Server) observeCountryDownloadCancellation(ctx context.Context, actor, id string) (wafCountryRequestDetail, WAFCountryDataOperation, error) {
	var empty wafCountryRequestDetail
	var none WAFCountryDataOperation
	if a.Executor == nil {
		return empty, none, errors.New("原国家下载固定执行服务不可核对")
	}
	original, err := a.Store.readWAFCountryRequest(ctx, actor, id)
	if err != nil || original.Request.State != "running" || original.Result != nil {
		return empty, none, errors.New("原国家下载尚未开始或已结束，只核对原结果")
	}
	query := WAFCountryObservationQuery(actor, original.Request.PayloadSHA)
	var raw json.RawMessage
	if err := a.Executor.Call(ctx, "GET", "/v1/waf/country/jobs/"+id+"?"+query.Encode(), nil, &raw); err != nil {
		return empty, none, errors.New("原国家下载执行状态尚未完整确认")
	}
	observed, err := DecodeWAFCountryDataOperation(raw, id, actor, original.Selection)
	if err != nil || observed.PayloadSHA != original.Request.PayloadSHA {
		return empty, none, errors.New("原国家下载的完整执行绑定不同")
	}
	return original, observed, nil
}

func (a *Server) wafCountryDownloadCancelRoutes(m *http.ServeMux, allowed func(http.ResponseWriter, *http.Request, identity) bool) {
	const base = "/api/software/nginx-waf/country-data/jobs/{id}/download-cancellation"
	m.HandleFunc("GET "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || !ValidID(r.PathValue("id")) {
			fail(w, 400, "原国家下载取消条件编号无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		original, native, err := a.observeCountryDownloadCancellation(ctx, actor.ID, r.PathValue("id"))
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		send(w, 200, map[string]any{"actor_id": actor.ID, "job_id": original.Request.ID, "payload_sha256": original.Request.PayloadSHA, "request_sha256": native.RequestSHA, "selection": original.Selection, "root_state": native.State, "can_request": native.State == "running" && original.DownloadCancellation == nil, "read_only": true, "automatic_replay_allowed": false})
	}))
	m.HandleFunc("POST "+base, a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if !allowed(w, r, actor) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || !ValidID(r.PathValue("id")) {
			fail(w, 400, "原国家下载取消必须绑定同一原编号")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		var in struct {
			Actor      string          `json:"actor_id"`
			PayloadSHA string          `json:"payload_sha256"`
			RequestSHA string          `json:"request_sha256"`
			Selection  json.RawMessage `json:"selection"`
		}
		if err != nil || !wafInventoryJSONShape(raw, []string{"actor_id", "payload_sha256", "request_sha256", "selection"}) || json.Unmarshal(raw, &in) != nil || in.Actor != actor.ID || !validLowerSHA256(in.PayloadSHA) || !validLowerSHA256(in.RequestSHA) {
			fail(w, 400, "原国家下载取消账户或完整请求无效")
			return
		}
		selection, err := DecodeWAFCountryDataSelection(in.Selection)
		if err != nil {
			fail(w, 400, "原国家下载取消选项无法完整核对")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		original, native, err := a.observeCountryDownloadCancellation(ctx, actor.ID, r.PathValue("id"))
		if err != nil || original.Request.PayloadSHA != in.PayloadSHA || !SameWAFCountryDataSelection(original.Selection, selection) || native.State != "running" || native.RequestSHA != in.RequestSHA {
			fail(w, 409, "原国家下载尚未开始、已结束或完整绑定不同，只核对原结果")
			return
		}
		proof, err := a.Store.requestWAFCountryDownloadCancellation(ctx, actor.ID, r.PathValue("id"), in.PayloadSHA, in.RequestSHA, selection)
		if err != nil {
			fail(w, 409, err.Error())
			return
		}
		// Only the original worker observes this durable stop request. The
		// acknowledgement does not claim a signal, a stopped job or no commit.
		send(w, 202, proof)
	}))
}
