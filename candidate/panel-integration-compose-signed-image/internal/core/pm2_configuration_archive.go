package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"net/http"
	"net/url"
	"regexp"
)

// This exact new revision owns the API. Older signed installations retain
// their previous operations and cannot acquire archive authority by alias.
const PM2ConfigurationArchiveAppVersion = appcatalog.PM2ConfigurationArchiveVersion

var pm2ConfigurationArchiveDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func PM2ConfigurationArchiveAction(action string) bool {
	return action == "archive-configurations" || action == "recover-configuration-archive" || action == "restore-configuration-archive"
}
func ParsePM2ConfigurationArchiveRecordsQuery(raw string) (AppModuleInput, error) {
	if len(raw) > 640 {
		return AppModuleInput{}, errors.New("配置封存读取查询过长")
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return AppModuleInput{}, errors.New("配置封存查询格式无效")
	}
	values := q["pm2_installation_id"]
	if len(values) != 1 || !ValidID(values[0]) {
		return AppModuleInput{}, errors.New("请选择当前已安装的 PM2 实例")
	}
	instance := values[0]
	delete(q, "pm2_installation_id")
	in, err := ParsePM2ConfigurationQuery(q.Encode())
	if err != nil {
		return AppModuleInput{}, err
	}
	in.PM2InstallationID = instance
	return in, nil
}
func ParsePM2ConfigurationArchiveQuery(raw string) (AppModuleInput, error) {
	in, err := ParsePM2ConfigurationArchiveRecordsQuery(raw)
	if err != nil || in.ResourceID != "" || in.Limit > 32 {
		return AppModuleInput{}, errors.New("配置归档只读查询仅接受当前实例、原请求标识、最多32项及有界分页")
	}
	return in, nil
}

// A dedicated wire object prevents zero-valued unrelated project, secret,
// path or deployment fields from entering a whole-journal maintenance action.
func DecodePM2ConfigurationArchiveInput(action string, raw []byte) (AppModuleInput, error) {
	var in AppModuleInput
	if !PM2ConfigurationArchiveAction(action) || len(raw) == 0 || len(raw) > 4096 {
		return in, errors.New("配置归档请求不是固定有界对象")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return in, errors.New("配置归档请求须为独立对象")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (key != "pm2_operation_id" && key != "pm2_installation_id" && key != "expected_sha" && key != "confirm") {
			return in, errors.New("配置归档字段重复或不被支持")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return in, errors.New("配置归档字段须为有效值")
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || d.Decode(&struct{}{}) != io.EOF || json.Unmarshal(raw, &in) != nil {
		return in, errors.New("配置归档对象不完整或格式无效")
	}
	confirmation := "ARCHIVE PM2 CONFIGURATIONS " + in.ExpectedSHA
	if action == "recover-configuration-archive" {
		confirmation = "RECOVER PM2 CONFIG ARCHIVE " + in.PM2OperationID
	}
	if action == "restore-configuration-archive" {
		confirmation = "RESTORE PM2 CONFIG ARCHIVE " + in.PM2OperationID
	}
	if len(seen) != 4 || !ValidID(in.PM2InstallationID) || !ValidID(in.PM2OperationID) || !pm2ConfigurationArchiveDigest.MatchString(in.ExpectedSHA) || in.Confirm != confirmation {
		return AppModuleInput{}, errors.New("请选择原完整清单或归档请求、摘要并填写精确确认")
	}
	return in, nil
}
func (a *Server) pm2ConfigurationArchiveRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-modules/pm2-manager/configuration-archives/{id}/records", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !ValidID(id) {
			fail(w, 400, "原配置归档标识无效")
			return
		}
		if _, err := ParsePM2ConfigurationArchiveRecordsQuery(r.URL.RawQuery); err != nil {
			fail(w, 400, err.Error())
			return
		}
		access, err := a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "完整配置归档仅完整管理员可读取")
			return
		}
		var out any
		if err := a.Executor.Call(r.Context(), "GET", "/v1/app-modules/pm2-manager/configuration-archives/"+id+"/records?"+r.URL.RawQuery, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		access, err = a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "授权已改变，请由完整管理员重新核对原配置归档")
			return
		}
		send(w, 200, out)
	}))

	m.HandleFunc("GET /api/app-modules/pm2-manager/configuration-archives", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if _, err := ParsePM2ConfigurationArchiveQuery(r.URL.RawQuery); err != nil {
			fail(w, 400, err.Error())
			return
		}
		access, err := a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "完整配置归档仅完整管理员可读取")
			return
		}
		var out any
		if err := a.Executor.Call(r.Context(), "GET", "/v1/app-modules/pm2-manager/configuration-archives?"+r.URL.RawQuery, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		access, err = a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "授权已改变，请由完整管理员重新核对原配置归档")
			return
		}
		send(w, 200, out)
	}))
}
