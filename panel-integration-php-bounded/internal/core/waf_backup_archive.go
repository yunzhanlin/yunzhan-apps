package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type WAFBackupArchiveInput struct {
	ID      string `json:"resource_id"`
	SHA     string `json:"expected_sha"`
	Confirm string `json:"confirm"`
}

func ValidateWAFBackupArchive(in WAFBackupArchiveInput) error {
	if !ValidID(in.ID) || len(in.SHA) != 64 || strings.Trim(in.SHA, "0123456789abcdef") != "" || in.Confirm != "ARCHIVE NGINX CONFIG "+in.ID {
		return errors.New("归档须核对原快照标识、完整 SHA-256 和精确确认；不接受路径、内容或删除动作")
	}
	return nil
}

func DecodeWAFBackupArchive(raw []byte) (WAFBackupArchiveInput, error) {
	var in WAFBackupArchiveInput
	if len(raw) > 4096 || !wafInventoryJSONShape(raw, []string{"resource_id", "expected_sha", "confirm"}) {
		return in, errors.New("原快照归档字段重复、缺失、未知或超过 4 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
		return WAFBackupArchiveInput{}, errors.New("原快照归档字段类型或对象格式无效")
	}
	return in, ValidateWAFBackupArchive(in)
}

type WAFBackupArchiveResult struct {
	Snapshot             WAFBackupInventoryRow `json:"snapshot"`
	Archived             bool                  `json:"archived"`
	Replayed             bool                  `json:"replayed"`
	RecordsRetained      bool                  `json:"records_retained"`
	ConfigurationChanged bool                  `json:"configuration_changed"`
}

func DecodeWAFBackupArchiveResult(raw []byte, in WAFBackupArchiveInput) (WAFBackupArchiveResult, error) {
	var out WAFBackupArchiveResult
	bad := errors.New("原标识和摘要的归档回执不可核对；不能宣称未移动或重新生成标识")
	if ValidateWAFBackupArchive(in) != nil || len(raw) > 8192 || !wafInventoryJSONShape(raw, []string{"snapshot", "archived", "replayed", "records_retained", "configuration_changed"}) {
		return out, bad
	}
	var shape struct {
		Snapshot json.RawMessage `json:"snapshot"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || json.Unmarshal(raw, &shape) != nil {
		return WAFBackupArchiveResult{}, bad
	}
	row, err := DecodeWAFBackupSnapshot(shape.Snapshot)
	if err != nil || row.ID != in.ID || row.SHA != in.SHA || !out.Archived || !out.RecordsRetained || out.ConfigurationChanged {
		return WAFBackupArchiveResult{}, bad
	}
	out.Snapshot = row
	return out, nil
}

func (a *Server) wafBackupArchiveRoutes(m *http.ServeMux) {
	admin := func(u identity, w http.ResponseWriter) bool {
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可核对和归档原防火墙配置备份")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/nginx-waf/config-backup-archive-request", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(u, w) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "原归档请求核对不接受账户、路径或查询字段")
			return
		}
		pending, err := readWAFBackupArchivePending(r.Context(), a.Store.DB, u.ID)
		if err != nil {
			fail(w, 503, "当前账户的原归档请求不可核对；未执行或重试归档")
			return
		}
		send(w, 200, WAFBackupArchiveRecovery{Pending: pending, ReadOnly: true})
	}))
	for _, selected := range []bool{false, true} {
		path := "/api/software/nginx-waf/config-backup-archive"
		if selected {
			path += "/{id}"
		}
		m.HandleFunc("GET "+path, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			w.Header().Set("Cache-Control", "no-store")
			if !admin(u, w) {
				return
			}
			id := r.PathValue("id")
			if r.URL.RawQuery != "" || r.URL.ForceQuery || selected && !ValidID(id) {
				fail(w, 400, "原归档标识或查询字段无效")
				return
			}
			target := "/v1/software/nginx-waf/config-backup-archive"
			if selected {
				target += "/" + id
			}
			var raw json.RawMessage
			if err := a.Executor.Call(r.Context(), "GET", target, nil, &raw); err != nil {
				fail(w, 503, "原归档尚未完整核验；未执行维护或返回配置正文")
				return
			}
			if selected {
				row, err := DecodeWAFBackupSnapshot(raw)
				if err != nil || row.ID != id {
					fail(w, 503, "所选原归档身份或完整元数据不可核对")
					return
				}
				send(w, 200, row)
				return
			}
			out, err := DecodeWAFBackupInventory(raw)
			if err != nil {
				fail(w, 503, "原归档库存不可完整核对；未返回部分列表")
				return
			}
			if out.Available {
				out.Message = "完整核验归档索引及内容；只返回元数据。归档保留全部原配置字节，不代表已恢复旧配置或具备磁盘硬配额。"
			}
			send(w, 200, out)
		}))
	}
	m.HandleFunc("POST /api/software/nginx-waf/archive-config-backup", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		w.Header().Set("Cache-Control", "no-store")
		if !admin(u, w) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "原快照归档不接受查询字段")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			fail(w, 400, "原快照归档请求超过 4 KiB 或不可读取")
			return
		}
		in, err := DecodeWAFBackupArchive(raw)
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if err = a.Store.beginWAFBackupArchive(r.Context(), u, in); err != nil {
			if errors.Is(err, errWAFBackupArchivePendingConflict) {
				fail(w, 409, err.Error())
				return
			}
			fail(w, 500, "请求审计未保存；未发送归档操作")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		var response json.RawMessage
		if err = a.Executor.Call(ctx, "POST", "/v1/software/nginx-waf/archive-config-backup", in, &response); err != nil {
			fail(w, 503, "原归档结果尚未确认；保留原标识和摘要核对，不自动重试，不宣称未移动")
			return
		}
		out, err := DecodeWAFBackupArchiveResult(response, in)
		if err != nil {
			fail(w, 503, err.Error())
			return
		}
		if err = a.Store.finishWAFBackupArchive(ctx, u, in, out); err != nil {
			fail(w, 503, "执行器已核对原归档，但结果审计未保存；保留同一标识和摘要核对，不能宣称整条操作通过")
			return
		}
		send(w, 200, out)
	}))
}
