package core

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxTextFile = 32 * 1024
const MaxFileUpload = 512 * 1024 * 1024

// File paths are always relative to the selected site's public directory.
// The executor additionally uses directory descriptors to enforce that boundary.
func ValidFilePath(value string, allowRoot bool) bool {
	if allowRoot && (value == "" || value == ".") {
		return true
	}
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." || part == "." || part == "" || strings.HasPrefix(part, ".panel-") {
			return false
		}
		for _, c := range part {
			if c < 32 || c == 127 {
				return false
			}
		}
	}
	return true
}

type FileEntry struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	ModifiedAt string `json:"modified_at"`
}
type FileAction struct {
	Action         string `json:"action"`
	Path           string `json:"path"`
	Destination    string `json:"destination"`
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Mode           string `json:"mode"`
	TrashID        string `json:"trash_id"`
}
type FileText struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
	Mode    string `json:"mode"`
}
type TrashEntry struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Reason    string `json:"reason"`
	DeletedAt string `json:"deleted_at"`
	Mode      string `json:"mode"`
}

func decodeFileAction(w http.ResponseWriter, r *http.Request, in *FileAction) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	d.DisallowUnknownFields()
	if e := d.Decode(in); e != nil {
		fail(w, 400, "文件操作参数格式错误")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "请求必须是单个对象")
		return false
	}
	return true
}
func (a *Server) fileRoutes(m *http.ServeMux) {
	for _, suffix := range []string{"", "/text", "/trash"} {
		suffix := suffix
		m.HandleFunc("GET /api/sites/{id}/files"+suffix, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			if _, e := a.Store.Site(r.PathValue("id")); e != nil {
				fail(w, 404, "站点不存在")
				return
			}
			q := url.Values{"path": {r.URL.Query().Get("path")}, "search": {r.URL.Query().Get("search")}, "page": {r.URL.Query().Get("page")}, "limit": {r.URL.Query().Get("limit")}}
			var out any
			if e := a.Executor.Call(r.Context(), "GET", "/v1/sites/"+r.PathValue("id")+"/files"+suffix+"?"+q.Encode(), nil, &out); e != nil {
				fail(w, 409, e.Error())
				return
			}
			send(w, 200, out)
		}))
	}
	m.HandleFunc("POST /api/sites/{id}/files/action", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		var in FileAction
		if !decodeFileAction(w, r, &in) {
			return
		}
		var out any
		e := a.Executor.Call(r.Context(), "POST", "/v1/sites/"+r.PathValue("id")+"/files/action", in, &out)
		result := "success"
		if e != nil {
			result = "failed"
		}
		_ = a.Store.Audit(u.Username, "file."+in.Action, r.PathValue("id")+":"+in.Path, result)
		if e != nil {
			fail(w, 409, e.Error())
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST /api/sites/{id}/files/upload", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		filename := r.URL.Query().Get("path")
		if !ValidFilePath(filename, false) || r.ContentLength < 0 || r.ContentLength > MaxFileUpload {
			fail(w, 400, "请提供有效文件路径和文件长度，最大 512 MiB")
			return
		}
		ctrl := http.NewResponseController(w)
		_ = ctrl.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_ = ctrl.SetWriteDeadline(time.Now().Add(5 * time.Minute))
		r.Body = http.MaxBytesReader(w, r.Body, MaxFileUpload)
		q := url.Values{"path": {filename}, "sha256": {r.Header.Get("X-File-SHA256")}}
		sent, e := a.proxyFile(w, r, "/v1/sites/"+r.PathValue("id")+"/files/upload?"+q.Encode())
		result := "success"
		if e != nil {
			result = "failed"
			if !sent {
				fail(w, 502, e.Error())
			}
		}
		_ = a.Store.Audit(u.Username, "file.upload", r.PathValue("id")+":"+filename, result)
	}))
	m.HandleFunc("GET /api/sites/{id}/files/download", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, e := a.Store.Site(r.PathValue("id")); e != nil {
			fail(w, 404, "站点不存在")
			return
		}
		filename := r.URL.Query().Get("path")
		if !ValidFilePath(filename, false) {
			fail(w, 400, "无效文件路径")
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
		sent, e := a.proxyFile(w, r, "/v1/sites/"+r.PathValue("id")+"/files/download?"+url.Values{"path": {filename}}.Encode())
		if e != nil {
			if !sent {
				fail(w, 502, e.Error())
			}
			_ = a.Store.Audit(u.Username, "file.download", r.PathValue("id")+":"+filename, "failed")
			return
		}
		_ = a.Store.Audit(u.Username, "file.download", r.PathValue("id")+":"+filename, "success")
	}))
}

// Stream file bodies over the private Unix socket. The API process never receives
// host filesystem paths and never buffers the complete upload/download in memory.
func (a *Server) proxyFile(w http.ResponseWriter, r *http.Request, endpoint string) (bool, error) {
	return a.proxyStream(w, r, endpoint, 5*time.Minute)
}
func (a *Server) proxyStream(w http.ResponseWriter, r *http.Request, endpoint string, timeout time.Duration) (bool, error) {
	var body io.Reader
	if r.Method == "POST" {
		body = r.Body
	}
	req, e := http.NewRequestWithContext(r.Context(), r.Method, "http://executor"+endpoint, body)
	if e != nil {
		return false, e
	}
	req.ContentLength = r.ContentLength
	req.Header.Set("Content-Type", "application/octet-stream")
	client := &http.Client{Transport: a.Executor.Client.Transport, Timeout: timeout}
	resp, e := client.Do(req)
	if e != nil {
		return false, errors.New("文件传输服务连接失败")
	}
	defer resp.Body.Close()
	for _, name := range []string{"Content-Type", "Content-Length", "Content-Disposition", "X-Content-SHA256"} {
		if v := resp.Header.Get(name); v != "" {
			w.Header().Set(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, e = io.Copy(w, resp.Body)
	if e != nil {
		return true, errors.New("文件传输中断")
	}
	if resp.StatusCode >= 400 {
		return true, errors.New("执行器拒绝了文件操作")
	}
	return true, nil
}
