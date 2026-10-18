package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const MaxMemcachedUpdateSnapshotBytes = MaxMemcachedUpdateChainBytes + 2048

var ErrMemcachedUpdateSnapshotIdentity = errors.New("Memcached 原事务快照身份或上下文变化")

type MemcachedUpdateSnapshot struct {
	Format  int                     `json:"format"`
	Records []MemcachedUpdateRecord `json:"records"`
}

// Strict per-response decoding; this neither expands the general executor
// response budget nor interprets an unknown/missing job as non-submission.
func DecodeMemcachedUpdateSnapshot(raw []byte) (MemcachedUpdateSnapshot, error) {
	var out MemcachedUpdateSnapshot
	bad := errors.New("Memcached 原生完整事务回复结构或容量无效")
	if len(raw) == 0 || len(raw) > MaxMemcachedUpdateSnapshotBytes {
		return out, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return out, bad
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return MemcachedUpdateSnapshot{}, bad
		}
		seen[name] = true
		switch name {
		case "format":
			if d.Decode(&out.Format) != nil || out.Format != 1 {
				return MemcachedUpdateSnapshot{}, bad
			}
		case "records":
			token, err := d.Token()
			if err != nil || token != json.Delim('[') {
				return MemcachedUpdateSnapshot{}, bad
			}
			for d.More() {
				if len(out.Records) >= MemcachedUpdateJournalEvents {
					return MemcachedUpdateSnapshot{}, bad
				}
				var rawRecord json.RawMessage
				if d.Decode(&rawRecord) != nil {
					return MemcachedUpdateSnapshot{}, bad
				}
				record, err := DecodeMemcachedUpdateRecord(rawRecord)
				if err != nil {
					return MemcachedUpdateSnapshot{}, bad
				}
				out.Records = append(out.Records, record)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return MemcachedUpdateSnapshot{}, bad
			}
		default:
			return MemcachedUpdateSnapshot{}, bad
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 2 || len(out.Records) == 0 {
		return MemcachedUpdateSnapshot{}, bad
	}
	if _, err := d.Token(); err != io.EOF {
		return MemcachedUpdateSnapshot{}, bad
	}
	if _, err := MemcachedUpdateChainHead(out.Records[0], out.Records); err != nil {
		return MemcachedUpdateSnapshot{}, bad
	}
	return out, nil
}

func (e *ExecutorClient) readMemcachedUpdateSnapshot(ctx context.Context, project, job string) (MemcachedUpdateSnapshot, error) {
	var empty MemcachedUpdateSnapshot
	if e == nil || e.Client == nil || !ValidID(project) || !ValidID(job) {
		return empty, errMemcachedUpdateStore
	}
	var raw json.RawMessage
	transport := *e.Client
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &ExecutorClient{Client: &transport}
	if err := guarded.Call(ctx, http.MethodGet, "/v1/docker/projects/"+project+"/app-updates/"+job, nil, &raw); err != nil {
		return empty, err
	}
	return DecodeMemcachedUpdateSnapshot(raw)
}

type memcachedUpdateStatus struct {
	AppID           string `json:"app_id"`
	ProjectID       string `json:"project_id"`
	RequestID       string `json:"request_id"`
	JobID           string `json:"job_id"`
	State           string `json:"state"`
	StateKnown      bool   `json:"state_known"`
	ExpectedVersion string `json:"expected_version"`
	ExpectedSHA256  string `json:"expected_sha256"`
	LastRecordSHA   string `json:"last_record_sha256,omitempty"`
	VersionRecorded bool   `json:"version_recorded"`
	Detail          string `json:"detail"`
}

// GET is deliberately read-only: it queries only the reserved job, not a
// catalog/POST/retry and not even an audit/receipt reconciliation. The background
// original-result reconciler has its own explicit transaction boundary.
func (a *Server) memcachedUpdateStatusRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /api/app-registry/memcached/updates", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		if r.URL.RawQuery != "" {
			fail(w, 400, "原更新清单不接受查询参数")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		tx, err := a.Store.DB.BeginTx(ctx, nil)
		if err != nil {
			fail(w, 503, "原更新清单暂不可读")
			return
		}
		defer tx.Rollback()
		if memcachedUpdateAuthority(ctx, tx, actor.ID, "") != nil {
			fail(w, 403, "当前账户不能核对主机更新")
			return
		}
		rows, err := memcachedUpdateInventory(ctx, tx)
		if err != nil {
			fail(w, 409, "原更新清单或审计不能核对")
			return
		}
		out := []memcachedUpdateStatus{}
		for _, row := range rows {
			if row.Seed.Dispatch.ActorID == actor.ID {
				out = append(out, memcachedOriginalUpdateStatus(row))
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		send(w, 200, out)
	}))
	m.HandleFunc("GET /api/app-registry/{id}/instances/{project}/updates/{key}", a.authorize(func(w http.ResponseWriter, r *http.Request, actor identity) {
		project, key := r.PathValue("project"), r.PathValue("key")
		if r.PathValue("id") != "memcached" || !ValidID(project) || !ValidID(key) || r.URL.RawQuery != "" {
			fail(w, 404, "原应用、项目或更新请求标识无效")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		row, found, err := a.Store.memcachedUpdateForActor(ctx, actor.ID, key)
		if err != nil {
			fail(w, 403, "当前账户不能核对该原更新请求；未重新提交")
			return
		}
		if !found || row.Seed.Dispatch.ProjectID != project {
			fail(w, 404, "尚未找到对应原更新请求；不能据此认定未提交")
			return
		}
		out := memcachedUpdateStatus{AppID: "memcached", ProjectID: project, RequestID: key, JobID: row.Seed.Dispatch.JobID, State: row.State, ExpectedVersion: row.Seed.Dispatch.Input.ExpectedVersion, ExpectedSHA256: row.Seed.Dispatch.Input.ExpectedSHA256, Detail: "本次原生状态尚不能确认；保留原任务和上次记录，不重发、不换编号更新"}
		if len(row.Chain) > 0 {
			out.LastRecordSHA = row.Chain[len(row.Chain)-1].RecordSHA256
		}
		snapshot, nativeErr := a.Executor.readMemcachedUpdateSnapshot(ctx, project, row.Seed.Dispatch.JobID)
		if nativeErr == nil {
			head, err := MemcachedUpdateChainHead(row.Seed, snapshot.Records)
			if err != nil {
				fail(w, 409, "原生回复不属于该完整原事务；保留原证据")
				return
			}
			for i := 0; i < len(row.Chain) && i < len(snapshot.Records); i++ {
				if row.Chain[i] != snapshot.Records[i] {
					fail(w, 409, "原事务事件出现分歧；保留原证据，不重发")
					return
				}
			}
			if len(snapshot.Records) >= len(row.Chain) {
				out.State, out.StateKnown, out.LastRecordSHA = head.Phase, true, head.RecordSHA256
				out.Detail = "已只读核对完整原生事件链；不会重新提交命令"
			}
		}
		if row.State == "committed" {
			var version, digest, target string
			if a.Store.DB.QueryRowContext(ctx, `SELECT version,sha256,target FROM app_registry_receipts WHERE app_id='memcached' AND scope=?`, project).Scan(&version, &digest, &target) == nil {
				out.VersionRecorded = version == out.ExpectedVersion && digest == out.ExpectedSHA256 && target == "memcached-cache"
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		send(w, 200, out)
	}))
}
