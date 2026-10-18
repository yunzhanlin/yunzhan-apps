package core

import (
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"
)

type wafApplyRequestSummary struct {
	ID            string `json:"id"`
	TargetID      string `json:"target_id"`
	Kind          string `json:"kind"`
	State         string `json:"state"`
	CreatedAt     string `json:"created_at"`
	PayloadSHA    string `json:"request_sha256"`
	SignedInstall bool   `json:"signed_install_binding"`
}
type wafApplyOriginalRequest struct {
	Request  wafApplyRequestSummary `json:"request"`
	Error    string                 `json:"error"`
	Settings map[string]any         `json:"settings"`
	ReadOnly bool                   `json:"read_only"`
}
type wafApplyRequestPage struct {
	Entries    []wafApplyRequestSummary `json:"entries"`
	NextCursor string                   `json:"next_cursor"`
	ReadOnly   bool                     `json:"read_only"`
}

// A request binding is NOT an installed package receipt. Read only the exact
// current actor's retained identity, including legacy signed-store bindings;
// never infer ownership from a username, global job access, or a guessed key.
func (s *Store) readWAFApplyOriginal(app, actor, job string) (wafApplyOriginalRequest, error) {
	var out wafApplyOriginalRequest
	bad := errors.New("原防火墙请求身份或配置不可完整核对；未返回部分记录、修复或重新提交")
	if !wafApplyApp(app) || !ValidID(actor) || !ValidID(job) {
		return out, bad
	}
	var owner, storedApp, storedKind, key, digest, storedCreated string
	err := s.DB.QueryRow(`SELECT actor_id,app_id,kind,idempotency_key,payload_sha256,created_at FROM waf_apply_requests WHERE job_id=?`, job).Scan(&owner, &storedApp, &storedKind, &key, &digest, &storedCreated)
	if errors.Is(err, sql.ErrNoRows) {
		// Do not backfill or adopt old unbound configuration/direct-install jobs.
		if err = s.DB.QueryRow(`SELECT idempotency_key FROM app_registry_install_requests WHERE actor_id=? AND app_id=? AND job_id=?`, actor, app, job).Scan(&key); err != nil {
			return out, err
		}
		binding, found, e := s.registryInstallBinding(app, actor, key)
		if e != nil || !found || binding.JobID != job || binding.Provider != "panel-module" || binding.Scope != app || binding.Target != app {
			return out, bad
		}
		out.Request.SignedInstall = true
		owner, storedApp, storedKind = actor, app, "software_install"
		if err = s.DB.QueryRow(`SELECT job_payload_sha256 FROM app_registry_install_requests WHERE job_id=?`, job).Scan(&digest); err != nil {
			return out, bad
		}
	} else if err != nil {
		return out, err
	}
	if owner != actor || storedApp != app {
		return out, sql.ErrNoRows
	}
	// A signed legacy binding has no new request-table row; its original
	// created_at remains checked on the retained job below. New rows must bind
	// the exact creation time too. Ownership is checked before corruption.
	if storedCreated == "" && !out.Request.SignedInstall {
		return out, bad
	}
	if key == "" || len(key) > 128 || !registryDigestValid(digest) {
		return out, bad
	}
	var payload, jobKey string
	out.Request.ID = job
	if err = s.DB.QueryRow(`SELECT target_id,kind,state,payload,idempotency_key,created_at,error FROM runtime_jobs WHERE id=?`, job).Scan(&out.Request.TargetID, &out.Request.Kind, &out.Request.State, &payload, &jobKey, &out.Request.CreatedAt, &out.Error); err != nil {
		return out, bad
	}
	stamp, stampErr := time.Parse(time.RFC3339, out.Request.CreatedAt)
	if storedCreated != "" && out.Request.CreatedAt != storedCreated {
		return out, bad
	}
	if out.Request.TargetID != app || out.Request.Kind != storedKind || (storedKind != "software_install" && storedKind != "software_configure") || jobKey != key || registryInstallDigest([]byte(payload)) != digest || stampErr != nil || stamp.UTC().Format(time.RFC3339) != out.Request.CreatedAt || !containsString([]string{"queued", "running", "succeeded", "failed", "needs_attention", "cancelled"}, out.Request.State) || len(out.Error) > 32768 || !utf8.ValidString(out.Error) {
		return out, bad
	}
	if storedKind == "software_install" && !out.Request.SignedInstall {
		var signedCount int
		if err = s.DB.QueryRow(`SELECT count(*) FROM app_registry_install_requests WHERE job_id=?`, job).Scan(&signedCount); err != nil || signedCount > 1 {
			return out, bad
		}
		if signedCount == 1 {
			binding, found, e := s.registryInstallBinding(app, actor, key)
			if e != nil || !found || binding.JobID != job || binding.Provider != "panel-module" || binding.Scope != app || binding.Target != app {
				return out, bad
			}
			out.Request.SignedInstall = true
		}
	}
	out.Settings, err = wafApplyOriginalSettings(app, payload)
	if err != nil {
		return wafApplyOriginalRequest{}, bad
	}
	out.Request.PayloadSHA = digest
	out.ReadOnly = true
	return out, nil
}

func (a *Server) wafApplyRecoveryRoutes(m *http.ServeMux) {
	allowed := func(w http.ResponseWriter, r *http.Request, u identity) bool {
		w.Header().Set("Cache-Control", "no-store")
		role, _, err := a.Store.appUserRole(u.ID)
		if err != nil || role != "admin" {
			fail(w, 403, "仅管理员可核对原防火墙请求")
			return false
		}
		if !wafApplyApp(r.PathValue("id")) {
			fail(w, 400, "防火墙请求标识无效")
			return false
		}
		return true
	}
	m.HandleFunc("GET /api/software/{id}/requests/{job}", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !allowed(w, r, u) {
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || !ValidID(r.PathValue("job")) {
			fail(w, 400, "原请求读取不接受账户、路径或查询字段")
			return
		}
		out, err := a.Store.readWAFApplyOriginal(r.PathValue("id"), u.ID, r.PathValue("job"))
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "未找到当前账户的原请求记录；不能据此认定没有提交")
			return
		}
		if err != nil {
			fail(w, 503, "原请求身份或配置不可完整核对；未返回部分记录或重新提交")
			return
		}
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/software/{id}/requests", a.authorize(func(w http.ResponseWriter, r *http.Request, u identity) {
		if !allowed(w, r, u) {
			return
		}
		q, err := url.ParseQuery(r.URL.RawQuery)
		cursor := ""
		if err != nil || len(r.URL.RawQuery) > 128 || r.URL.ForceQuery || len(q) > 1 || len(q) == 1 && (len(q["cursor"]) != 1 || !ValidID(q.Get("cursor"))) {
			fail(w, 400, "原防火墙请求分页字段无效")
			return
		}
		if len(q) == 1 {
			cursor = q.Get("cursor")
		}
		app := r.PathValue("id")
		// Exactly 20 ID-keyset results per read; collect and CLOSE the cursor before
		// further queries because the Store intentionally has a single connection.
		rows, err := a.Store.DB.QueryContext(r.Context(), `SELECT job_id FROM waf_apply_requests WHERE actor_id=? AND app_id=? AND job_id>? UNION SELECT job_id FROM app_registry_install_requests WHERE actor_id=? AND app_id=? AND job_id>? AND provider='panel-module' ORDER BY job_id LIMIT 21`, u.ID, app, cursor, u.ID, app, cursor)
		if err != nil {
			fail(w, 503, "当前账户的原请求目录暂不可读取；未返回空目录结论")
			return
		}
		ids := []string{}
		previous := cursor
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil || !ValidID(id) || id <= previous {
				rows.Close()
				fail(w, 503, "原请求目录身份不可完整核对；未返回部分列表")
				return
			}
			ids = append(ids, id)
			previous = id
		}
		readErr := rows.Err()
		closeErr := rows.Close()
		if readErr != nil || closeErr != nil {
			fail(w, 503, "原请求目录读取中断；未返回部分列表")
			return
		}
		out := wafApplyRequestPage{Entries: []wafApplyRequestSummary{}, ReadOnly: true}
		for _, job := range ids {
			original, e := a.Store.readWAFApplyOriginal(app, u.ID, job)
			if e != nil {
				fail(w, 503, "原请求身份或配置不可完整核对；未返回部分列表")
				return
			}
			if len(out.Entries) == 20 {
				out.NextCursor = out.Entries[19].ID
				break
			}
			out.Entries = append(out.Entries, original.Request)
		}
		send(w, 200, out)
	}))
}
