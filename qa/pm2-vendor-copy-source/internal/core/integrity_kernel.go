package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

const IntegrityKernelAppVersion = "1.5.0"

type IntegrityKernelInput struct {
	SiteID             string `json:"site_id"`
	ExpectedRevision   int64  `json:"expected_revision"`
	ExpectedAppVersion string `json:"expected_app_version"`
	BaselineSHA        string `json:"baseline_sha"`
	SourceOperation    string `json:"source_operation"`
	SourceSHA          string `json:"source_sha"`
	Confirm            string `json:"confirm"`
}

type IntegrityKernelRequest struct {
	Format         int                  `json:"format"`
	AppID          string               `json:"app_id,omitempty"`
	ID             string               `json:"id"`
	ActorID        string               `json:"actor_id"`
	AccessRevision int64                `json:"access_revision"`
	AppSHA         string               `json:"app_sha"`
	Action         string               `json:"action"`
	Input          IntegrityKernelInput `json:"input"`
	CreatedAt      string               `json:"created_at"`
}

type IntegrityKernelOperation struct {
	Request         IntegrityKernelRequest `json:"request"`
	RequestSHA      string                 `json:"request_sha256"`
	State           string                 `json:"state"`
	Revision        int64                  `json:"revision"`
	PlanSHA         string                 `json:"plan_sha"`
	EnableOperation string                 `json:"enable_operation"`
	Files           int                    `json:"files"`
	Directories     int                    `json:"directories"`
	Completed       int                    `json:"completed"`
	Error           string                 `json:"error"`
	FinishedAt      string                 `json:"finished_at"`
}

type IntegrityKernelStatus struct {
	AppID         string                     `json:"app_id,omitempty"`
	SiteID        string                     `json:"site_id"`
	AppVersion    string                     `json:"app_version"`
	AppSHA        string                     `json:"app_sha"`
	Revision      int64                      `json:"revision"`
	State         string                     `json:"state"`
	BaselineSHA   string                     `json:"baseline_sha"`
	BaselineFiles int                        `json:"baseline_files"`
	Capability    bool                       `json:"cap_linux_immutable"`
	VerifiedAt    string                     `json:"verified_at"`
	Error         string                     `json:"error"`
	Latest        *IntegrityKernelOperation  `json:"latest,omitempty"`
	Operations    []IntegrityKernelOperation `json:"operations"`
	Scope         string                     `json:"scope"`
}

func integrityKernelSHA(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && strings.ToLower(value) == value
}

func ValidateIntegrityKernelInput(action string, in IntegrityKernelInput) error {
	if !ValidID(in.SiteID) || in.ExpectedRevision < 0 || in.ExpectedRevision >= 1<<60 || in.ExpectedAppVersion != IntegrityKernelAppVersion {
		return errors.New("内核保护网站、版本或修订身份无效")
	}
	switch action {
	case "enable":
		if !integrityKernelSHA(in.BaselineSHA) || in.SourceOperation != "" || in.SourceSHA != "" || in.Confirm != "PROTECT SITE "+in.SiteID {
			return errors.New("启用须明确选择当前签名基线和网站；不能混入解除记录")
		}
	case "release":
		if in.BaselineSHA != "" || !ValidID(in.SourceOperation) || !integrityKernelSHA(in.SourceSHA) || in.Confirm != "RELEASE SITE "+in.SiteID {
			return errors.New("解除须选择原任务及其完整摘要；不会重新建立基线或重放原操作")
		}
	default:
		return errors.New("内核保护操作无效")
	}
	return nil
}

func ValidateIntegrityKernelRequest(in IntegrityKernelRequest) error {
	if IntegrityKernelRequestApplication(in) == "" || !ValidID(in.ID) || !ValidID(in.ActorID) || in.AccessRevision < 1 || !integrityKernelSHA(in.AppSHA) || ValidateIntegrityKernelInput(in.Action, in.Input) != nil {
		return errors.New("内核保护原请求身份无效")
	}
	t, err := time.Parse(time.RFC3339Nano, in.CreatedAt)
	if err != nil || t.Year() < 2026 {
		return errors.New("内核保护原请求时间无效")
	}
	return nil
}

// The durable worker repeats this read against the original actor and signed
// app receipt immediately before dispatch. Revocation/regrant changes the
// revision; neither a queued request nor Root UID upgrades old authority.
func (s *Store) ValidateIntegrityKernelAuthority(ctx context.Context, request IntegrityKernelRequest) error {
	if ValidateIntegrityKernelRequest(request) != nil {
		return errors.New("内核保护请求身份无效")
	}
	access, err := readUserAccessContext(ctx, s.DB, request.ActorID)
	if err != nil || !fullAdministrator(access) || access.Revision != request.AccessRevision {
		return errors.New("原操作者完整管理权限已变化，未执行内核保护")
	}
	var version, sha, target string
	application := IntegrityKernelRequestApplication(request)
	if err = s.DB.QueryRowContext(ctx, "SELECT version,sha256,target FROM app_registry_receipts WHERE app_id=? AND scope=?", application, application).Scan(&version, &sha, &target); err != nil || version != IntegrityKernelAppVersion || sha != request.AppSHA || target != application {
		return errors.New("原签名应用收据已变化或不能核对，未执行内核保护")
	}
	return nil
}

// All seven scalar fields are explicit, even when intentionally empty. Do
// not let null, duplicate/case-equivalent names or unrelated module inputs
// become a Root operation through Go's permissive struct matching.
func DecodeIntegrityKernelInput(action string, raw []byte) (IntegrityKernelInput, error) {
	var in IntegrityKernelInput
	if len(raw) < 1 || len(raw) > 4096 {
		return in, errors.New("内核保护输入容量无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return in, errors.New("内核保护输入须为对象")
	}
	allowed := map[string]bool{"site_id": true, "expected_revision": true, "expected_app_version": true, "baseline_sha": true, "source_operation": true, "source_sha": true, "confirm": true}
	seen := map[string]bool{}
	for d.More() {
		t, e := d.Token()
		key, ok := t.(string)
		if e != nil || !ok || !allowed[key] || seen[key] {
			return in, errors.New("内核保护输入包含重复、别名或未知字段")
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return in, errors.New("内核保护输入不能为 null")
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || len(seen) != len(allowed) {
		return in, errors.New("内核保护输入字段缺失")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return in, errors.New("内核保护输入包含尾随内容")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&in); err != nil {
		return in, err
	}
	return in, ValidateIntegrityKernelInput(action, in)
}

func IntegrityKernelRequestSHA(request IntegrityKernelRequest) string {
	b, _ := json.Marshal(request)
	return Hash(string(b))
}

func ValidIntegrityKernelOperation(out IntegrityKernelOperation) bool {
	if ValidateIntegrityKernelRequest(out.Request) != nil || out.Revision != out.Request.Input.ExpectedRevision+1 || out.Completed < 0 || out.Files < 0 || out.Files > 10000 || out.Directories < 0 || out.Directories > 4097 || out.Completed > out.Files+out.Directories || len(out.Error) > 2048 {
		return false
	}
	if out.RequestSHA != IntegrityKernelRequestSHA(out.Request) {
		return false
	}
	if out.PlanSHA != "" && !integrityKernelSHA(out.PlanSHA) || out.EnableOperation != "" && !ValidID(out.EnableOperation) {
		return false
	}
	switch out.State {
	case "queued", "running":
		return out.Error == "" && out.FinishedAt == ""
	case "needs-attention":
		return out.Error != ""
	case "cancelled":
		_, err := time.Parse(time.RFC3339Nano, out.FinishedAt)
		return err == nil && out.Error != "" && out.PlanSHA == "" && out.EnableOperation == "" && out.Completed == 0 && out.Files == 0 && out.Directories == 0
	case "succeeded", "declined":
		if out.State == "declined" && out.Request.Action != "enable" {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, out.FinishedAt)
		return err == nil && (out.State == "succeeded" && out.Error == "" || out.State == "declined" && out.Error != "")
	}
	return false
}

func ValidIntegrityKernelStatus(out IntegrityKernelStatus) bool {
	application := IntegrityKernelStatusApplication(out)
	if application == "" {
		return false
	}
	if out.AppSHA != "" && !integrityKernelSHA(out.AppSHA) {
		return false
	}
	if !ValidID(out.SiteID) || out.Revision < 0 || out.Revision >= 1<<60 || out.AppVersion != "" && out.AppVersion != IntegrityKernelAppVersion || out.BaselineFiles < 0 || out.BaselineFiles > 10000 || out.BaselineSHA != "" && !integrityKernelSHA(out.BaselineSHA) || len(out.Error) > 2048 || len(out.Scope) > 8192 || len(out.Operations) > 512 {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, out.VerifiedAt); err != nil {
		return false
	}
	switch out.State {
	case "needs-baseline", "ready", "upgrade-required", "unsupported", "queued", "running", "enabled", "released", "needs-attention", "other-application":
	default:
		return false
	}
	for i, op := range out.Operations {
		if !ValidIntegrityKernelOperation(op) || op.Request.Input.SiteID != out.SiteID || op.Revision != int64(i+1) {
			return false
		}
		if op.Request.Action == "release" && (i == 0 || op.Request.Input.SourceOperation != out.Operations[i-1].Request.ID || op.Request.Input.SourceSHA != out.Operations[i-1].RequestSHA || IntegrityKernelRequestApplication(op.Request) != IntegrityKernelRequestApplication(out.Operations[i-1].Request)) {
			return false
		}
	}
	if out.Revision != int64(len(out.Operations)) || (out.Latest == nil) != (len(out.Operations) == 0) {
		return false
	}
	if out.Latest != nil && !reflect.DeepEqual(*out.Latest, out.Operations[len(out.Operations)-1]) {
		return false
	}
	if out.State == "enabled" && (out.AppVersion != IntegrityKernelAppVersion || !integrityKernelSHA(out.AppSHA) || out.Latest == nil || out.Latest.State != "succeeded" || out.Latest.Request.Action != "enable" || IntegrityKernelRequestApplication(out.Latest.Request) != application) {
		return false
	}
	if out.State == "released" && (out.Latest == nil || out.Latest.State != "succeeded" || out.Latest.Request.Action != "release" || IntegrityKernelRequestApplication(out.Latest.Request) != application) {
		return false
	}
	if out.State == "other-application" && (out.Latest == nil || IntegrityKernelOperationReleased(*out.Latest) || IntegrityKernelRequestApplication(out.Latest.Request) == application) {
		return false
	}
	return true
}

func (a *Server) integrityKernelRoutes(m *http.ServeMux) {
	a.integrityKernelAdmissionRoutes(m)
	for _, route := range IntegrityKernelApplicationRoutes() {
		a.integrityKernelApplicationRoutes(m, route)
	}
}

func (a *Server) integrityKernelApplicationRoutes(m *http.ServeMux, route IntegrityKernelApplicationRoute) {
	api := route.API
	m.HandleFunc("GET "+api, a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		query := r.URL.Query()
		if len(query) != 1 || len(query["site_id"]) != 1 || !ValidID(query.Get("site_id")) {
			fail(w, 400, "请选择唯一网站；不接受路径或其他查询字段")
			return
		}
		var out IntegrityKernelStatus
		if err := a.Executor.Call(r.Context(), "GET", route.Executor+"?site_id="+query.Get("site_id"), nil, &out); err != nil {
			fail(w, 409, err.Error())
			return
		}
		if out.SiteID != query.Get("site_id") || !ValidIntegrityKernelStatus(out) || IntegrityKernelStatusApplication(out) != route.Application {
			fail(w, 502, "内核保护状态身份不能核对")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("POST "+api+"/{action}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		action, key := r.PathValue("action"), r.Header.Get("Idempotency-Key")
		if len(key) < 1 || len(key) > 128 || strings.TrimSpace(key) != key {
			fail(w, 400, "内核保护任务需要稳定提交键；回执未知时保留原键核对")
			return
		}
		raw, readErr := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		in, err := DecodeIntegrityKernelInput(action, raw)
		if readErr != nil || err != nil {
			fail(w, 400, "内核保护输入缺失、重复、未知或身份无效")
			return
		}
		id := IntegrityKernelSubmissionID(u.ID, key, route.Application, false)
		access, accessErr := a.Store.UserAccess(u.ID)
		if accessErr != nil || !fullAdministrator(access) {
			fail(w, 403, "内核写保护需要当前完整管理员权限")
			return
		}
		var appSHA string
		if err = a.Store.DB.QueryRowContext(r.Context(), "SELECT sha256 FROM app_registry_receipts WHERE app_id=? AND scope=? AND version=? AND target=?", route.Application, route.Application, IntegrityKernelAppVersion, route.Application).Scan(&appSHA); err != nil || !integrityKernelSHA(appSHA) {
			fail(w, 409, "请先通过签名商店安装支持内核写保护的应用")
			return
		}
		request := NewIntegrityKernelApplicationRequest(route.Application, IntegrityKernelRequest{ID: id, ActorID: u.ID, AccessRevision: access.Revision, AppSHA: appSHA, Action: action, Input: in, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		if err = a.Store.ValidateIntegrityKernelAuthority(r.Context(), request); err != nil {
			fail(w, 409, err.Error())
			return
		}
		var out IntegrityKernelOperation
		if err = a.Executor.Call(r.Context(), "POST", route.Executor+"/operations/"+id, request, &out); err != nil {
			fail(w, 409, "提交结果待核对，请保留原键和原请求："+err.Error())
			return
		}
		// CreatedAt belongs to the first accepted request; a retry returns it
		// unchanged, with exactly the original actor/action/input identity.
		if !ValidIntegrityKernelOperation(out) || IntegrityKernelRequestApplication(out.Request) != route.Application || out.Request.ID != id || out.Request.ActorID != u.ID || out.Request.AccessRevision != access.Revision || out.Request.AppSHA != appSHA || out.Request.Action != action || !reflect.DeepEqual(out.Request.Input, in) {
			fail(w, 502, "内核保护提交回执身份无效，未宣称完成")
			return
		}
		if err = a.Store.Audit(u.Username, "integrity.kernel.observe", id, out.State); err != nil {
			fail(w, 503, "任务可能已接收，但审计未保存；保留原提交键核对")
			return
		}
		send(w, 202, out)
	}))
}
