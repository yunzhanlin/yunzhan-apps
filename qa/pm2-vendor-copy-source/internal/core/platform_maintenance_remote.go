package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type platformMaintenancePeer struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}
type platformMaintenanceRemoteInput struct {
	URL       string                   `json:"url"`
	Token     string                   `json:"token"`
	ActorID   string                   `json:"actor_id"`
	Operation PlatformMaintenanceInput `json:"operation"`
}
type PlatformMaintenanceRemotePlan struct {
	Plan            PlatformMaintenancePlan `json:"plan"`
	GrantID         string                  `json:"grant_id"`
	ActorID         string                  `json:"actor_id"`
	AllowedCommands []string                `json:"allowed_commands"`
	Expires         int64                   `json:"expires_at"`
}

func validatePlatformMaintenancePeer(address, token string) error {
	u, e := url.Parse(address)
	if e != nil || len(address) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Path != "" && u.Path != "/" && path.Clean(u.Path) != strings.TrimRight(u.Path, "/") || !platformMaintenanceSHA.MatchString(token) {
		return errors.New("远端维护只接受明确 HTTPS 地址和独立维护秘密；不接受账号、查询、片段、跳转或旧摘要")
	}
	return nil
}
func platformMaintenancePeerCall(ctx context.Context, client *http.Client, address, token, method, endpoint string, body []byte) ([]byte, int, error) {
	if validatePlatformMaintenancePeer(address, token) != nil {
		return nil, 0, errors.New("远端维护地址或授权无效")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(address, "/")+endpoint, bytes.NewReader(body))
	if e != nil {
		return nil, 0, errors.New("无法构造固定维护请求")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	r, e := client.Do(req)
	if e != nil {
		return nil, 0, errors.New("远端 HTTPS、证书或响应未核对；不自动重发")
	}
	defer r.Body.Close()
	media, _, me := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if me != nil || media != "application/json" || r.StatusCode != 200 && r.StatusCode != 202 {
		return nil, r.StatusCode, errors.New("远端维护状态或 JSON 协议不符合要求；没有使用错误页")
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 8193))
	if e != nil || len(raw) > 8192 {
		return nil, r.StatusCode, errors.New("远端维护回执不完整或超限；不使用部分成功")
	}
	return raw, r.StatusCode, nil
}
func decodePlatformMaintenanceRemotePlan(raw []byte, token string) (PlatformMaintenanceRemotePlan, error) {
	var out PlatformMaintenanceRemotePlan
	var shape struct{ Plan json.RawMessage }
	if len(raw) > 2048 || !wafInventoryJSONShape(raw, []string{"plan", "grant_id", "actor_id", "allowed_commands", "expires_at"}) || json.Unmarshal(raw, &out) != nil || json.Unmarshal(raw, &shape) != nil || out.GrantID != Hash(token) || !ValidID(out.ActorID) || !validatePlatformMaintenanceCommands(out.AllowedCommands) || out.Expires <= time.Now().Unix() || out.Expires > time.Now().Unix()+86400+120 {
		return out, errors.New("远端维护计划授权身份或有效期不可核对")
	}
	if _, e := DecodePlatformMaintenancePlan(shape.Plan); e != nil {
		return out, e
	}
	return out, nil
}
func platformMaintenancePending(raw []byte, id string) bool {
	var out struct {
		ID    string `json:"request_id"`
		State string `json:"state"`
		Retry *bool  `json:"retry_allowed"`
	}
	return len(raw) <= 512 && wafInventoryJSONShape(raw, []string{"request_id", "state", "retry_allowed"}) && json.Unmarshal(raw, &out) == nil && out.ID == id && out.State == "needs_attention" && out.Retry != nil && !*out.Retry
}
func (a *Server) platformMaintenanceRemoteRoutes(m *http.ServeMux) {
	base := "/api/app-modules/platform-ops/maintenance/remote"
	allowed := func(w http.ResponseWriter, r *http.Request, u identity) bool {
		w.Header().Set("Cache-Control", "no-store")
		if platformMaintenanceAdmin(r.Context(), a.Store.DB, u.ID) != nil {
			fail(w, 403, "需要当前维护管理员权限")
			return false
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(w, 400, "维护桥接不接受查询字段")
			return false
		}
		if a.platformMaintenanceInstalled(r.Context()) != nil {
			fail(w, 409, "本机维护应用身份未核对")
			return false
		}
		return true
	}
	m.HandleFunc("POST "+base+"/plan", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !allowed(w, r, u) {
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 3072))
		var peer platformMaintenancePeer
		if e != nil || !wafInventoryJSONShape(raw, []string{"url", "token"}) || json.Unmarshal(raw, &peer) != nil || validatePlatformMaintenancePeer(peer.URL, peer.Token) != nil {
			fail(w, 400, "远端维护地址或独立授权无效")
			return
		}
		client := platformMaintenanceClient()
		defer client.CloseIdleConnections()
		wire, status, e := platformMaintenancePeerCall(r.Context(), client, peer.URL, peer.Token, "GET", "/api/platform-maintenance/plan", nil)
		if e != nil || status != 200 {
			fail(w, 503, "远端维护计划未核对；未执行命令")
			return
		}
		out, e := decodePlatformMaintenanceRemotePlan(wire, peer.Token)
		if e != nil {
			fail(w, 503, e.Error())
			return
		}
		send(w, 200, out)
	}))
	command := func(statusOnly bool) http.HandlerFunc {
		return a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
			if !allowed(w, r, u) {
				return
			}
			raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
			var in platformMaintenanceRemoteInput
			var shape struct{ Operation json.RawMessage }
			if e != nil || !wafInventoryJSONShape(raw, []string{"url", "token", "actor_id", "operation"}) || json.Unmarshal(raw, &in) != nil || json.Unmarshal(raw, &shape) != nil || validatePlatformMaintenancePeer(in.URL, in.Token) != nil || !ValidID(in.ActorID) {
				fail(w, 400, "原远端维护请求字段无效")
				return
			}
			op, e := DecodePlatformMaintenanceInput(shape.Operation)
			if e != nil {
				fail(w, 400, e.Error())
				return
			}
			if !statusOnly && platformMaintenanceCommandAllowed(r.Context(), a.Store.DB, u.ID, op.Command) != nil {
				fail(w, 403, "协调面板当前账号无权派发此主机级命令")
				return
			}
			req := PlatformMaintenanceNativeRequest{Format: 1, GrantID: Hash(in.Token), ActorID: in.ActorID, Input: op}
			// Audit only a digest of endpoint/grant/original request, never a token.
			binding := Hash(strings.TrimRight(in.URL, "/") + "\x00" + PlatformMaintenanceRequestSHA(req))
			action := "platform.maintenance.remote.submit"
			if statusOnly {
				action = "platform.maintenance.remote.inspect"
			}
			if _, e = a.Store.DB.ExecContext(r.Context(), "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,?,?,?,?)", u.ID, action, op.RequestID, binding, Now()); e != nil {
				fail(w, 503, "维护请求审计未保存，未发出请求")
				return
			}
			client := platformMaintenanceClient()
			defer client.CloseIdleConnections()
			method, endpoint := "POST", "/api/platform-maintenance/commands"
			body, _ := json.Marshal(op)
			if statusOnly {
				method = "GET"
				endpoint += "/" + op.RequestID
				body = nil
			}
			if !statusOnly {
				planWire, planStatus, pe := platformMaintenancePeerCall(r.Context(), client, in.URL, in.Token, "GET", "/api/platform-maintenance/plan", nil)
				if pe != nil || planStatus != 200 {
					fail(w, 503, "远端原计划未核对，未派发")
					return
				}
				plan, pe := decodePlatformMaintenanceRemotePlan(planWire, in.Token)
				if pe != nil || plan.ActorID != in.ActorID || plan.GrantID != req.GrantID || plan.Plan.SHA != op.ExpectedPlanSHA || !containsString(plan.AllowedCommands, op.Command) {
					fail(w, 409, "远端主体、计划或命令权限已变化；未派发")
					return
				}
			}
			wire, status, e := platformMaintenancePeerCall(r.Context(), client, in.URL, in.Token, method, endpoint, body)
			if e != nil {
				fail(w, 503, "远端原结果未确认；保留原ID及请求，只读核对，不自动重发")
				return
			}
			if status == 202 {
				if !platformMaintenancePending(wire, op.RequestID) {
					fail(w, 503, "远端待核对回执身份不同")
					return
				}
				send(w, 202, json.RawMessage(wire))
				return
			}
			out, e := DecodePlatformMaintenanceRecord(wire, req)
			if e != nil || out.State == "started" {
				fail(w, 503, "远端原终态或主体不可核对，未宣称成功")
				return
			}
			if _, e = a.Store.DB.ExecContext(r.Context(), "INSERT INTO audit_logs(actor,action,target,result,created_at) VALUES(?,'platform.maintenance.remote.observed',?,?,?)", u.ID, op.RequestID, Hash(string(wire)), Now()); e != nil {
				fail(w, 503, "远端回执已观察但本机审计失败；使用原ID只读核对")
				return
			}
			send(w, 200, out)
		})
	}
	m.HandleFunc("POST "+base+"/commands", command(false))
	m.HandleFunc("POST "+base+"/commands/status", command(true))
}
func platformMaintenanceClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxResponseHeaderBytes = 16 << 10
	t.TLSHandshakeTimeout = 3 * time.Second
	t.ResponseHeaderTimeout = 25 * time.Second
	return &http.Client{Transport: t, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
