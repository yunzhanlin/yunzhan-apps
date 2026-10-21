package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ApacheWAFHistoryInput struct {
	Limit   int    `json:"limit,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	ID      string `json:"resource_id,omitempty"`
	SHA     string `json:"expected_sha,omitempty"`
	Confirm string `json:"confirm,omitempty"`
}

func ApacheWAFHistoryVersion(version string) bool {
	return version == "2.0.0" || version == "2.1.0" || version == "2.2.0" || version == ApacheWAFVersion
}

func ApacheWAFHistoryQuery(raw string) (ApacheWAFHistoryInput, error) {
	in := ApacheWAFHistoryInput{Limit: 16}
	if len(raw) > 256 {
		return in, errors.New("事务查询超过容量")
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return in, errors.New("事务查询格式无效")
	}
	for key, values := range q {
		if (key != "limit" && key != "offset") || len(values) != 1 {
			return in, errors.New("事务查询字段未知或重复")
		}
		value, err := strconv.Atoi(values[0])
		if err != nil || strconv.Itoa(value) != values[0] {
			return in, errors.New("事务查询须为规范整数")
		}
		if key == "limit" {
			in.Limit = value
		} else {
			in.Offset = value
		}
	}
	return in, ValidateApacheWAFHistoryInput("transactions", in)
}

func DecodeApacheWAFHistoryArchive(raw []byte) (ApacheWAFHistoryInput, error) {
	var in ApacheWAFHistoryInput
	if len(raw) > 4096 {
		return in, errors.New("归档请求超过 4 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return in, errors.New("归档请求须为独立对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "resource_id" && key != "expected_sha" && key != "confirm") || seen[key] {
			return in, errors.New("归档字段未知或重复")
		}
		seen[key] = true
		var value string
		var rawValue json.RawMessage
		if d.Decode(&rawValue) != nil || bytes.Equal(bytes.TrimSpace(rawValue), []byte("null")) || json.Unmarshal(rawValue, &value) != nil {
			return in, errors.New("归档字段须为非空字符串")
		}
		switch key {
		case "resource_id":
			in.ID = value
		case "expected_sha":
			in.SHA = value
		case "confirm":
			in.Confirm = value
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF {
		return in, errors.New("归档请求不完整或含额外数据")
	}
	return in, ValidateApacheWAFHistoryInput("archive-transaction", in)
}

func ValidateApacheWAFHistoryInput(action string, in ApacheWAFHistoryInput) error {
	if action == "transactions" {
		if in.Limit < 1 || in.Limit > 32 || in.Offset < 0 || in.Offset > 612 || in.ID != "" || in.SHA != "" || in.Confirm != "" {
			return errors.New("事务清单每页 1–32 条，起点最多 612；不接受其他业务字段")
		}
		return nil
	}
	if action != "archive-transaction" || in.Limit != 0 || in.Offset != 0 || !ValidID(in.ID) || len(in.SHA) != 64 || strings.Trim(in.SHA, "0123456789abcdef") != "" || in.Confirm != "ARCHIVE APACHE TRANSACTION "+in.ID {
		return errors.New("归档须核对原事务标识、SHA-256 并精确确认 ARCHIVE APACHE TRANSACTION 原标识")
	}
	return nil
}

func (a *Server) apacheWAFHistoryRoutes(m *http.ServeMux) {
	for _, action := range []string{"transactions", "archive-transaction"} {
		method := "GET"
		if action == "archive-transaction" {
			method = "POST"
		}
		m.HandleFunc(method+" /api/software/apache-waf/"+action, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			role, _, err := a.Store.appUserRole(u.ID)
			if err != nil || role != "admin" {
				fail(w, 403, "仅管理员可核对私有配置事务")
				return
			}
			var in ApacheWAFHistoryInput
			if action == "transactions" {
				in, err = ApacheWAFHistoryQuery(r.URL.RawQuery)
			} else {
				if r.URL.RawQuery != "" {
					fail(w, 400, "归档不接受查询参数")
					return
				}
				var raw []byte
				raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
				if err == nil {
					in, err = DecodeApacheWAFHistoryArchive(raw)
				}
			}
			if err != nil {
				fail(w, 400, err.Error())
				return
			}
			path := "/v1/software/apache-waf/" + action
			var body any
			if action == "transactions" {
				path += "?limit=" + strconv.Itoa(in.Limit) + "&offset=" + strconv.Itoa(in.Offset)
			} else {
				body = in
				if err = a.Store.Audit(u.Username, "apache-waf.transaction.archive-requested", in.ID, "digest="+in.SHA+"; no configuration change or backup deletion"); err != nil {
					fail(w, 500, "请求审计未保存；尚未归档")
					return
				}
			}
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			var out json.RawMessage
			if err = a.Executor.Call(ctx, method, path, body, &out); err != nil {
				fail(w, 409, err.Error())
				return
			}
			if action == "archive-transaction" {
				if err = a.Store.Audit(u.Username, "apache-waf.transaction.archive-confirmed", in.ID, "digest="+in.SHA+"; retained original private bytes; may be same-identity replay"); err != nil {
					fail(w, 503, "执行器已核对归档，但结果审计未保存；请用同一标识和摘要核对，不换标识重复操作")
					return
				}
			}
			w.Header().Set("Cache-Control", "no-store, private")
			send(w, 200, out)
		}))
	}
}
