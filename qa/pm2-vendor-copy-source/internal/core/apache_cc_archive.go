package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ApacheCCArchiveRequest struct {
	RequestID        string `json:"request_id"`
	ExpectedRevision int64  `json:"expected_revision"`
	AllowIncomplete  bool   `json:"allow_incomplete"`
}

const ApacheCCArchiveChunkBytes = 256 << 10
const ApacheCCArchiveParts = 128

type ApacheCCArchiveRetainRequest struct {
	SHA            string `json:"sha256"`
	ConfirmUnknown bool   `json:"confirm_unknown"`
}

func DecodeApacheCCArchiveRetention(raw []byte) (ApacheCCArchiveRetainRequest, error) {
	var out ApacheCCArchiveRetainRequest
	if len(raw) > 1024 || bytes.ContainsRune(raw, '\\') {
		return out, errors.New("CC 原证据保留请求超过 1 KiB")
	}
	values, err := DecodeApacheNumericLogMaintenance(raw, "retain-stage")
	if err != nil {
		return out, err
	}
	out.SHA, out.ConfirmUnknown = values["sha256"].(string), values["confirm_unknown"].(bool)
	return out, nil
}

type ApacheCCArchiveHistoryRequest struct {
	SHA             string `json:"sha256"`
	ConfirmPreserve bool   `json:"confirm_preserve"`
}

func DecodeApacheCCArchiveHistory(raw []byte) (ApacheCCArchiveHistoryRequest, error) {
	var out ApacheCCArchiveHistoryRequest
	if len(raw) > 1024 || bytes.ContainsRune(raw, '\\') {
		return out, errors.New("CC 原历史转存请求无效")
	}
	values, err := DecodeApacheNumericLogMaintenance(raw, "cc-history")
	if err != nil {
		return out, err
	}
	out.SHA, out.ConfirmPreserve = values["sha256"].(string), values["confirm_preserve"].(bool)
	return out, nil
}

// Exact scalars at both trust boundaries. IDs and revisions are identities,
// never file paths; null, duplicates, aliases and coerced numbers are refused.
func DecodeApacheCCArchiveRequest(raw []byte) (ApacheCCArchiveRequest, error) {
	var out ApacheCCArchiveRequest
	if len(raw) == 0 || len(raw) > 1024 || bytes.ContainsRune(raw, '\\') {
		return out, errors.New("CC 归档请求格式无效或超过 1 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return out, errors.New("CC 归档需要完整独立对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return out, errors.New("CC 归档字段重复或无效")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return out, errors.New("CC 归档不接受缺失或 null 字段")
		}
		switch key {
		case "request_id":
			if json.Unmarshal(value, &out.RequestID) != nil || !ValidID(out.RequestID) {
				return out, errors.New("CC 原请求标识无效")
			}
		case "expected_revision":
			if json.Unmarshal(value, &out.ExpectedRevision) != nil || out.ExpectedRevision < 1 || out.ExpectedRevision > 1000000000 {
				return out, errors.New("CC 原配置修订无效")
			}
		case "allow_incomplete":
			if json.Unmarshal(value, &out.AllowIncomplete) != nil {
				return out, errors.New("CC 残缺末行选项必须为明确布尔值")
			}
		default:
			return out, errors.New("CC 归档字段未知")
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 || d.Decode(&struct{}{}) != io.EOF {
		return out, errors.New("CC 归档字段不完整或包含额外内容")
	}
	return out, nil
}

func ApacheCCArchivePart(value string) (int, error) {
	part, err := strconv.Atoi(value)
	if err != nil || part < 0 || part >= ApacheCCArchiveParts || strconv.Itoa(part) != value {
		return 0, errors.New("CC 归档下载分段标识无效")
	}
	return part, nil
}

func (a *Server) apacheCCArchiveRoutes(m *http.ServeMux) {
	for _, op := range []struct{ method, suffix, kind string }{
		{"GET", "archives", "inventory"}, {"GET", "archives/{id}", "receipt"}, {"GET", "archives/{id}/chunks/{part}", "download"}, {"POST", "archive", "archive"},
		{"GET", "requests/{id}", "observe"}, {"POST", "requests/{id}/close", "close-unstarted"},
		{"GET", "archives/{id}/recovery", "recovery"}, {"POST", "archives/{id}/retain", "retain-unknown"},
		{"GET", "archives/{id}/history", "history-snapshot"}, {"POST", "archives/{id}/history", "preserve-history"},
	} {
		m.HandleFunc(op.method+" /api/software/apache-waf/cc-log/"+op.suffix, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			role, _, err := a.Store.appUserRole(u.ID)
			if err != nil || role != "admin" {
				fail(w, 403, "CC 日志归档仅管理员可访问")
				return
			}
			if len(r.URL.Query()) != 0 {
				fail(w, 400, "CC 日志归档不接受查询参数或文件路径")
				return
			}
			suffix, target := op.suffix, "apache-waf"
			if id := r.PathValue("id"); id != "" {
				if !ValidID(id) {
					fail(w, 400, "CC 归档标识无效")
					return
				}
				suffix, target = strings.ReplaceAll(suffix, "{id}", id), id
			}
			if part := r.PathValue("part"); part != "" {
				if _, err := ApacheCCArchivePart(part); err != nil {
					fail(w, 400, err.Error())
					return
				}
				suffix = strings.ReplaceAll(suffix, "{part}", part)
			}
			var payload any
			if op.method == "POST" {
				raw, err := io.ReadAll(io.LimitReader(r.Body, 1025))
				if err != nil {
					fail(w, 400, "无法读取 CC 归档请求")
					return
				}
				if op.kind == "retain-unknown" {
					in, err := DecodeApacheCCArchiveRetention(raw)
					if err != nil {
						fail(w, 400, err.Error())
						return
					}
					payload = in
				} else if op.kind == "preserve-history" {
					in, err := DecodeApacheCCArchiveHistory(raw)
					if err != nil {
						fail(w, 400, err.Error())
						return
					}
					payload = in
				} else {
					in, err := DecodeApacheCCArchiveRequest(raw)
					if err != nil {
						fail(w, 400, err.Error())
						return
					}
					if id := r.PathValue("id"); id != "" && id != in.RequestID {
						fail(w, 400, "CC 原请求路径与对象标识不一致")
						return
					}
					payload, target = in, in.RequestID
				}
				if err := a.Store.Audit(u.Username, "apache.cc-log."+op.kind+".requested", target, "Explicit original request ID; unknown archive outcomes are observed and never replayed; closing a proven-unstarted request must prevent delayed dispatch"); err != nil {
					fail(w, 503, "CC 归档请求审计未保存，未提交")
					return
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			var out json.RawMessage // Retain exact inode/device integers.
			if err := a.Executor.Call(ctx, op.method, "/v1/software/apache-waf/cc-log/"+suffix, payload, &out); err != nil {
				fail(w, 409, err.Error())
				return
			}
			if op.method == "POST" {
				if err := a.Store.Audit(u.Username, "apache.cc-log."+op.kind+".confirmed", target, "Executor returned the original fixed-ID receipt; original website settings, CC counters and Apache lifetime were not changed"); err != nil {
					fail(w, 503, "执行器已返回原回执，完成审计未保存；请按原标识核对，不要重新归档")
					return
				}
			}
			send(w, 200, out)
		}))
	}
}
