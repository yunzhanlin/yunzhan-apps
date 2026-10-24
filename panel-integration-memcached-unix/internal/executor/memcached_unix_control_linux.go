//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

func (r *memcachedUpdateCoreAuthority) unixControl(ctx context.Context, op core.MemcachedUnixControlOperation, others bool) error {
	if r == nil {
		return errMemcachedCoreAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.db == nil || r.blocked == nil || r.blocked() || !r.current() {
		return errMemcachedCoreAuthority
	}
	store := &core.Store{DB: r.db}
	err := store.CheckMemcachedUnixControl(ctx, op)
	if err == nil && others {
		err = store.CheckMemcachedUnixOtherControls(ctx, op)
	}
	if err != nil || !r.current() || r.blocked() || ctx.Err() != nil {
		return errMemcachedCoreAuthority
	}
	return nil
}
func memcachedUnixControlStateIdentity(raw json.RawMessage) (int, string, error) {
	var value struct {
		State struct {
			Pid       int
			StartedAt string
		}
	}
	if memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, &value) != nil || value.State.Pid < 0 || value.State.StartedAt == "" || len(value.State.StartedAt) > 64 {
		return 0, "", core.ErrMemcachedUnixControl
	}
	if _, err := time.Parse(time.RFC3339Nano, value.State.StartedAt); err != nil {
		return 0, "", core.ErrMemcachedUnixControl
	}
	return value.State.Pid, value.State.StartedAt, nil
}
func memcachedUnixControlBaseResult(op core.MemcachedUnixControlOperation, state string) core.MemcachedUnixControlResult {
	return core.MemcachedUnixControlResult{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: core.MemcachedUnixControlSHA(op), State: state}
}

// One exact daemon action. Inspection may repeat; this POST never does. The
// unchanged CID/image/contract, real kernel and same-connection readiness are
// required afterwards. No Compose pull/up, recreate, network or image removal.
func runMemcachedUnixControl(ctx context.Context, op core.MemcachedUnixControlOperation) (core.MemcachedUnixControlResult, error) {
	var empty core.MemcachedUnixControlResult
	if ctx == nil || ctx.Err() != nil || core.ValidateMemcachedUnixControlOperation(op) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	p, err := openMemcachedUnixProjectOriginal(ctx, op.ProjectID)
	if err != nil {
		return empty, err
	}
	defer p.Close()
	if p.head.Phase != "committed" {
		return empty, core.ErrMemcachedUnixControl
	}
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return empty, err
	}
	defer reader.Close()
	permission := op.Input.Action
	check := func(c context.Context) error {
		if p.current(c) != nil || reader.unixOperation(c, op.ActorID, p.head.Operation, permission, p.head.Binding) != nil || reader.unixControl(c, op, false) != nil {
			return core.ErrMemcachedUnixControl
		}
		_, err := readMemcachedUnixProject(p.project, p.head)
		return err
	}
	if check(ctx) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(bound)
	cancel()
	if err != nil {
		return empty, err
	}
	defer lifetime.Close()
	if !lifetime.current() || check(ctx) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	seed := memcachedUnixControlSeed{Format: 1, Operation: op, InstalledRecordSHA256: memcachedUnixControlInstalledSHA(p.head)}
	store := memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}
	j, fresh, err := store.prepare(seed)
	if err != nil {
		return empty, err
	}
	defer j.Close()
	if !fresh {
		value, err := j.read()
		if err != nil || value.Seed != seed {
			return empty, core.ErrMemcachedUnixControl
		}
		if value.Result != nil {
			return *value.Result, nil
		}
		return memcachedUnixControlBaseResult(op, "unknown"), nil
	}
	lease, err := j.lease()
	if err != nil {
		return empty, err
	}
	defer lease.Close()
	own := &memcachedUnixControlRun{lease: lease, original: p}
	completed := false
	defer func() {
		if !completed && lease.current() {
			// Evidence only, not recovery: never turn a partial/issued operation
			// into a new daemon call or remove its original files/container.
			value, readErr := j.read()
			if readErr == nil && value.Result == nil && value.Issued != nil {
				_ = lease.finish(memcachedUnixControlBaseResult(op, "unknown"))
			}
		}
	}()
	pending := func(c context.Context) error {
		if own.current(c) != nil || reader.unixControl(c, op, true) != nil {
			return core.ErrMemcachedUnixControl
		}
		if (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(c) != nil || (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).checkProgramUpgrade(c) != nil || store.checkTransactions(c, own) != nil {
			return core.ErrMemcachedUnixControl
		}
		return own.current(c)
	}
	engineStore := productionDockerMutationStore()
	engineStore.pending = pending
	bound, cancel = context.WithTimeout(ctx, 3*time.Second)
	engine, err := engineStore.begin(bound)
	cancel()
	if err != nil {
		return empty, err
	}
	defer engine.Close()
	var result core.MemcachedUnixControlResult
	err = engine.use(ctx, func(active context.Context) error {
		if pending(active) != nil || check(active) != nil {
			return core.ErrMemcachedUnixControl
		}
		account, err := memcachedUnixOriginalAccount(active, p)
		if err != nil {
			return err
		}
		refresh := func(c context.Context) error {
			if own.current(c) != nil || check(c) != nil {
				return core.ErrMemcachedUnixControl
			}
			actual, err := memcachedUnixOriginalAccount(c, p)
			if err != nil || actual != account {
				return errMemcachedUnixNSS
			}
			if op.Input.Action != "stop" && p.head.Operation.SiteID != "" {
				owned, err := memcachedUnixOwnedSiteAccount(c, p.head.Operation.SiteID)
				if err != nil || owned != account {
					return errMemcachedUnixNSS
				}
			}
			return nil
		}
		if refresh(active) != nil {
			return core.ErrMemcachedUnixControl
		}
		_, raw, pid, state, err := memcachedUnixWorkspaceState(active, p, account)
		if err != nil {
			return err
		}
		required := "running"
		if op.Input.Action == "start" {
			required = "stopped"
		}
		fingerprint, fingerprintErr := memcachedUnixRuntimeFingerprint(raw)
		if fingerprintErr != nil {
			return fingerprintErr
		}
		if fingerprint != op.Input.ExpectedRuntimeSHA256 || state != required {
			result = memcachedUnixControlBaseResult(op, "refused")
			if lease.finish(result) != nil {
				return core.ErrMemcachedUnixControl
			}
			completed = true
			return nil
		}
		directory, err := core.MemcachedUnixDirectory(op.ProjectID, p.head.Operation.SiteID)
		if err != nil {
			return err
		}
		if state == "running" && memcachedUnixReadyAt(active, filepath.Join(directory, "cache.sock"), pid, account) != nil {
			return errMemcachedUnix
		}
		initialPID, started, err := memcachedUnixControlStateIdentity(raw)
		if err != nil {
			return err
		}
		seedRaw, _ := json.Marshal(seed)
		issued := memcachedUnixControlIssued{Format: 1, SeedSHA256: core.Hash(string(seedRaw)), ContainerID: p.head.ContainerID, InitialPID: initialPID, InitialStartedAt: started}
		if refresh(active) != nil || lease.issued(issued) != nil || refresh(active) != nil {
			return core.ErrMemcachedUnixControl
		}
		path := "/containers/" + p.head.ContainerID + "/" + op.Input.Action
		if op.Input.Action != "start" {
			path += "?t=10"
		}
		status, _, callErr := memcachedRetentionDaemon(active, http.MethodPost, path, nil) // Exactly once.
		if callErr != nil || status != 204 {
			return core.ErrMemcachedUnixControl
		}
		target := "running"
		if op.Input.Action == "stop" {
			target = "stopped"
		}
		ready, cancel := context.WithTimeout(active, 20*time.Second)
		defer cancel()
		for attempt := 0; attempt < 21; attempt++ {
			if refresh(ready) != nil {
				return core.ErrMemcachedUnixControl
			}
			_, current, currentPID, currentState, observeErr := memcachedUnixWorkspaceState(ready, p, account)
			if observeErr == nil && currentState == target {
				afterPID, afterStart, idErr := memcachedUnixControlStateIdentity(current)
				verified := idErr == nil
				if target == "running" {
					verified = verified && currentPID == afterPID && memcachedUnixReadyAt(ready, filepath.Join(directory, "cache.sock"), currentPID, account) == nil
				}
				if op.Input.Action == "restart" {
					verified = verified && afterStart != issued.InitialStartedAt
				}
				if verified && refresh(ready) == nil {
					result = memcachedUnixControlBaseResult(op, "completed")
					result.FinalState = target
					result.RuntimeSHA256, err = memcachedUnixRuntimeFingerprint(current)
					if err != nil {
						return err
					}
					if lease.finish(result) != nil {
						return core.ErrMemcachedUnixControl
					}
					completed = true
					return nil
				}
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-ready.Done():
				timer.Stop()
				return core.ErrMemcachedUnixControl
			case <-timer.C:
			}
		}
		return core.ErrMemcachedUnixControl
	})
	if err != nil {
		return empty, err
	}
	return result, nil
}

func (s *Service) memcachedUnixControlRoutes(m *http.ServeMux) {
	s.memcachedUnixControlClosureRoutes(m)
	m.HandleFunc("GET /v1/memcached-unix/projects/{id}/controls/{request}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		actor := r.URL.Query().Get("actor_id")
		if !core.ValidID(actor) || r.URL.RawQuery != "actor_id="+actor || !core.ValidID(r.PathValue("id")) || !core.ValidID(r.PathValue("request")) {
			respond(w, 400, map[string]string{"error": "原启停查询身份无效"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		reader, err := openMemcachedUpdateCoreAuthority(ctx)
		if err != nil {
			respond(w, 409, map[string]string{"error": core.ErrMemcachedUnixControl.Error()})
			return
		}
		defer reader.Close()
		op, err := (&core.Store{DB: reader.db}).MemcachedUnixControlStatusBinding(ctx, actor, r.PathValue("request"))
		if err != nil || op.ProjectID != r.PathValue("id") || !reader.current() {
			respond(w, 403, map[string]string{"error": "当前原账户授权不能核对"})
			return
		}
		p, err := openMemcachedUnixProjectOriginal(ctx, op.ProjectID)
		if err != nil {
			respond(w, 409, map[string]string{"error": core.ErrMemcachedUnixControl.Error()})
			return
		}
		defer p.Close()
		j, err := (memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}).open(op.RequestID)
		if err != nil {
			respond(w, 409, map[string]string{"error": "没有可核对的原生回执；未重新提交"})
			return
		}
		defer j.Close()
		value, err := j.read()
		if err != nil || value.Seed.Operation != op || !memcachedUnixControlMatchesOriginal(value, p) || p.current(ctx) != nil || reader.unixOperation(ctx, actor, p.head.Operation, "stop", p.head.Binding) != nil {
			respond(w, 409, map[string]string{"error": core.ErrMemcachedUnixControl.Error()})
			return
		}
		result := memcachedUnixControlBaseResult(op, "unknown")
		if value.Result != nil {
			result = *value.Result
		}
		respond(w, 200, result)
	})
	m.HandleFunc("POST /v1/memcached-unix/projects/{id}/controls/{request}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(r.PathValue("id")) || !core.ValidID(r.PathValue("request")) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原启停请求身份无效"})
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUnixControlBytes+1))
		op, decodeErr := core.DecodeMemcachedUnixControlOperation(raw)
		if err != nil || decodeErr != nil || op.ProjectID != r.PathValue("id") || op.RequestID != r.PathValue("request") {
			respond(w, 400, map[string]string{"error": "启停传输必须绑定原请求和固定动作"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		defer cancel()
		result, err := runMemcachedUnixControl(ctx, op)
		if err != nil {
			respond(w, 409, map[string]string{"error": core.ErrMemcachedUnixControl.Error()})
			return
		}
		respond(w, 200, result)
	})
}
