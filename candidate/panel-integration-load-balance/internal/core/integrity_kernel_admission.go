package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

type IntegrityKernelClosure struct {
	Format             int                    `json:"format"`
	ID                 string                 `json:"id"`
	Request            IntegrityKernelRequest `json:"request"`
	OriginalRequestSHA string                 `json:"original_request_sha256"`
	SealedAt           string                 `json:"sealed_at"`
}
type IntegrityKernelAdmission struct {
	ID        string                    `json:"id"`
	State     string                    `json:"state"`
	Operation *IntegrityKernelOperation `json:"operation,omitempty"`
	Closure   *IntegrityKernelClosure   `json:"closure,omitempty"`
}
type IntegrityKernelCloseRequest struct {
	ID      string                 `json:"id"`
	Request IntegrityKernelRequest `json:"request"`
}

func ValidIntegrityKernelClosure(v IntegrityKernelClosure) bool {
	_, err := time.Parse(time.RFC3339Nano, v.SealedAt)
	return v.Format == 1 && ValidID(v.ID) && ValidateIntegrityKernelRequest(v.Request) == nil && (v.OriginalRequestSHA == "" || integrityKernelSHA(v.OriginalRequestSHA)) && err == nil
}
func ValidIntegrityKernelAdmission(v IntegrityKernelAdmission) bool {
	if !ValidID(v.ID) {
		return false
	}
	switch v.State {
	case "absent":
		return v.Operation == nil && v.Closure == nil
	case "original":
		return v.Closure == nil && v.Operation != nil && v.Operation.Request.ID == v.ID && ValidIntegrityKernelOperation(*v.Operation)
	case "sealed":
		return v.Closure != nil && v.Closure.Request.ID == v.ID && ValidIntegrityKernelClosure(*v.Closure) && (v.Operation == nil || v.Operation.Request.ID == v.ID && v.Operation.State == "cancelled" && ValidIntegrityKernelOperation(*v.Operation))
	}
	return false
}

func (a *Server) integrityKernelAdmissionRoutes(m *http.ServeMux) {
	for _, route := range IntegrityKernelApplicationRoutes() {
		a.integrityKernelApplicationAdmissionRoutes(m, route)
	}
}

func (a *Server) integrityKernelApplicationAdmissionRoutes(m *http.ServeMux, route IntegrityKernelApplicationRoute) {
	api := route.API
	m.HandleFunc("GET "+api+"/admissions/{id}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		id := r.PathValue("id")
		if !ValidID(id) || len(r.URL.Query()) != 0 {
			fail(w, 400, "原提交核对标识或查询无效")
			return
		}
		var out IntegrityKernelAdmission
		if err := a.Executor.Call(r.Context(), "GET", route.Executor+"/admissions/"+id, nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if !ValidIntegrityKernelAdmission(out) || out.ID != id || !IntegrityKernelAdmissionApplicationMatches(out, route.Application) {
			fail(w, 502, "原提交核对回执身份无效")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST "+api+"/close-admission", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		var in struct {
			OriginalKey string          `json:"original_key"`
			Action      string          `json:"action"`
			Input       json.RawMessage `json:"input"`
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		if err != nil {
			fail(w, 400, "封存输入容量无效")
			return
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		token, err := d.Token()
		if err != nil || token != json.Delim('{') {
			fail(w, 400, "封存输入须为对象")
			return
		}
		seen := map[string]bool{}
		for d.More() {
			token, e := d.Token()
			key, ok := token.(string)
			if e != nil || !ok || seen[key] || key != "original_key" && key != "action" && key != "input" {
				fail(w, 400, "封存输入重复或未知")
				return
			}
			seen[key] = true
			var value json.RawMessage
			if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				fail(w, 400, "封存输入无效")
				return
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 {
			fail(w, 400, "封存输入不完整")
			return
		}
		if _, err = d.Token(); !errors.Is(err, io.EOF) {
			fail(w, 400, "封存输入包含尾随内容")
			return
		}
		if json.Unmarshal(raw, &in) != nil {
			fail(w, 400, "封存输入类型无效")
			return
		}
		input, err := DecodeIntegrityKernelInput(in.Action, in.Input)
		key := r.Header.Get("Idempotency-Key")
		validKey := func(v string) bool { return len(v) > 0 && len(v) <= 128 && strings.TrimSpace(v) == v }
		if err != nil || !validKey(key) || !validKey(in.OriginalKey) {
			fail(w, 400, "请选择原提交键、动作和完整原输入，并使用独立封存标识")
			return
		}
		access, err := a.Store.UserAccess(u.ID)
		if err != nil || !fullAdministrator(access) {
			fail(w, 403, "原提交封存需要当前完整管理员权限")
			return
		}
		var appSHA string
		if a.Store.DB.QueryRowContext(r.Context(), "SELECT sha256 FROM app_registry_receipts WHERE app_id=? AND scope=? AND version=? AND target=?", route.Application, route.Application, IntegrityKernelAppVersion, route.Application).Scan(&appSHA) != nil || !integrityKernelSHA(appSHA) {
			fail(w, 409, "原签名应用收据不能核对，未封存")
			return
		}
		request := NewIntegrityKernelApplicationRequest(route.Application, IntegrityKernelRequest{ID: IntegrityKernelSubmissionID(u.ID, in.OriginalKey, route.Application, false), ActorID: u.ID, AccessRevision: access.Revision, AppSHA: appSHA, Action: in.Action, Input: input, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		if err = a.Store.ValidateIntegrityKernelAuthority(r.Context(), request); err != nil {
			fail(w, 409, err.Error())
			return
		}
		closeRequest := IntegrityKernelCloseRequest{ID: IntegrityKernelSubmissionID(u.ID, key, route.Application, true), Request: request}
		var out IntegrityKernelAdmission
		if err = a.Executor.Call(r.Context(), "POST", route.Executor+"/close-admission", closeRequest, &out); err != nil {
			fail(w, 409, "封存结果仍待核对；保留原提交标识，只读核对："+err.Error())
			return
		}
		if !ValidIntegrityKernelAdmission(out) || out.ID != request.ID || out.State == "absent" || !IntegrityKernelAdmissionApplicationMatches(out, route.Application) {
			fail(w, 502, "原提交封存回执无效，未宣称已封存")
			return
		}
		original := request
		if out.Closure != nil {
			original = out.Closure.Request
		} else if out.Operation != nil {
			original = out.Operation.Request
		}
		if original.ActorID != u.ID || original.Action != in.Action || !reflect.DeepEqual(original.Input, input) {
			fail(w, 502, "原提交封存回执绑定不同输入或操作者")
			return
		}
		if err = a.Store.Audit(u.Username, "integrity.kernel.admission.observe", out.ID, out.State); err != nil {
			fail(w, 503, "原封存可能已保存，但审计未完成；只读核对原标识")
			return
		}
		send(w, 200, out)
	}))
}
