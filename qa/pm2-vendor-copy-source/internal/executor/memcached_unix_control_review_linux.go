//go:build linux

package executor

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"local/panel/internal/core"
)

func (r *memcachedUpdateCoreAuthority) unixControlReview(ctx context.Context, in core.MemcachedUnixControlReviewRequest, others bool) error {
	if r == nil {
		return errMemcachedCoreAuthority
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.db == nil || r.blocked == nil || r.blocked() || !r.current() {
		return errMemcachedCoreAuthority
	}
	if (&core.Store{DB: r.db}).CheckMemcachedUnixControlReview(ctx, in, others) != nil || !r.current() || r.blocked() || ctx.Err() != nil {
		return errMemcachedCoreAuthority
	}
	return nil
}
func memcachedUnixReviewView(op core.MemcachedUnixControlOperation) core.MemcachedUnixControlReviewView {
	return core.MemcachedUnixControlReviewView{Format: 1, RequestID: op.RequestID, ProjectID: op.ProjectID, OperationSHA256: core.MemcachedUnixControlSHA(op), OriginalOutcome: "unknown"}
}

// The only native calls here are READS and a verified VERSION exchange.
// There is no daemon POST, Compose command, pull, signal, cleanup or account
// creation. A separately acknowledged append can settle an issued unknown,
// while its original result (including absence) stays byte-for-byte retained.
func runMemcachedUnixControlReview(ctx context.Context, in core.MemcachedUnixControlReviewRequest) (core.MemcachedUnixControlReviewView, error) {
	var empty core.MemcachedUnixControlReviewView
	if ctx == nil || ctx.Err() != nil || core.ValidateMemcachedUnixControlReviewRequest(in) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	op := in.Operation
	p, err := openMemcachedUnixProjectOriginal(ctx, op.ProjectID)
	if err != nil {
		return empty, err
	}
	defer p.Close()
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return empty, err
	}
	defer reader.Close()
	check := func(c context.Context) error {
		if p.current(c) != nil || p.head.Phase != "committed" || reader.unixControlReview(c, in, false) != nil || reader.unixOperation(c, in.ReviewerID, p.head.Operation, "stop", p.head.Binding) != nil {
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
	// Never prepare or repair a missing/partial original transaction.
	store := memcachedUnixControlJournalStore{base: memcachedUnixControlsRoot}
	j, err := store.open(op.RequestID)
	if err != nil {
		return empty, err
	}
	defer j.Close()
	lease, err := j.lease()
	if err != nil {
		return empty, err
	}
	defer lease.Close()
	original, err := j.read()
	if err != nil || original.Seed.Operation != op || !memcachedUnixControlMatchesOriginal(original, p) || check(ctx) != nil {
		return empty, core.ErrMemcachedUnixControl
	}
	out := memcachedUnixReviewView(op)
	if original.Observation != nil {
		result := original.Observation.Result
		out.Observation = &result
		return out, core.ValidateMemcachedUnixControlReviewView(op, out)
	}
	if original.Issued == nil || original.Result != nil && original.Result.State != "unknown" {
		return empty, core.ErrMemcachedUnixControl
	}
	own := &memcachedUnixControlRun{lease: lease, original: p, review: &in}
	pending := func(c context.Context) error {
		if own.current(c) != nil || reader.unixControlReview(c, in, true) != nil || check(c) != nil {
			return core.ErrMemcachedUnixControl
		}
		if (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).checkProgramUpgrade(c) != nil || (memcachedUnixJournalStore{base: memcachedUnixInstallJobsRoot}).checkProgramUpgrade(c) != nil || store.checkTransactions(c, own) != nil {
			return core.ErrMemcachedUnixControl
		}
		return own.current(c)
	}
	engineStore := productionDockerMutationStore()
	engineStore.pending = pending
	engineStore.existingOnly = true
	bound, cancel = context.WithTimeout(ctx, 3*time.Second)
	engine, err := engineStore.begin(bound)
	cancel()
	if err != nil {
		return empty, err
	}
	defer engine.Close()
	err = engine.use(ctx, func(active context.Context) error {
		if pending(active) != nil || !lifetime.current() {
			return core.ErrMemcachedUnixControl
		}
		account, err := memcachedUnixOriginalAccount(active, p)
		if err != nil {
			return err
		}
		observe := func() (string, string, error) {
			if check(active) != nil || own.current(active) != nil {
				return "", "", core.ErrMemcachedUnixControl
			}
			actual, e := memcachedUnixOriginalAccount(active, p)
			if e != nil || actual != account {
				return "", "", errMemcachedUnixNSS
			}
			if op.Input.Action == "retire" {
				if validateMemcachedUnixDirectory(op.ProjectID, p.head.Operation.SiteID, account) != nil {
					return "", "", errMemcachedUnixNSS
				}
				// Absence is authoritative only for this original issued retirement.
				// Other commands and missing/foreign CIDs can never borrow it.
				fingerprint, absentErr := memcachedUnixRetirementAbsence(active, original.Seed, *original.Issued, memcachedRetentionDaemon)
				if absentErr == nil && check(active) == nil && own.current(active) == nil {
					return "retired", fingerprint, nil
				}
			}
			_, raw, pid, state, e := memcachedUnixWorkspaceState(active, p, account)
			if e != nil {
				return "", "", e
			}
			if state == "running" {
				dir, e := core.MemcachedUnixDirectory(op.ProjectID, p.head.Operation.SiteID)
				if e != nil || memcachedUnixReadyAt(active, filepath.Join(dir, "cache.sock"), pid, account) != nil {
					return "", "", errMemcachedUnix
				}
			}
			fingerprint, e := memcachedUnixRuntimeFingerprint(raw)
			if e != nil || check(active) != nil || own.current(active) != nil {
				return "", "", core.ErrMemcachedUnixControl
			}
			return state, fingerprint, nil
		}
		state, fingerprint, err := observe()
		if err != nil {
			return err
		}
		if in.Input == nil {
			out.CurrentState = state
			out.RuntimeSHA256 = fingerprint
			return core.ValidateMemcachedUnixControlReviewView(op, out)
		}
		if fingerprint != in.Input.ExpectedRuntimeSHA256 {
			return core.ErrMemcachedUnixControl
		}
		// A second independent complete inspection prevents the confirmation from
		// adopting a moving process/state or an external Docker CLI change.
		again, digest, err := observe()
		if err != nil || again != state || digest != fingerprint || pending(active) != nil || !lifetime.current() {
			return core.ErrMemcachedUnixControl
		}
		result := memcachedUnixControlBaseResult(op, "observed")
		result.FinalState = state
		result.RuntimeSHA256 = fingerprint
		result.ReviewerID = in.ReviewerID
		result.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if core.ValidateMemcachedUnixControlResult(op, result) != nil || lease.observe(result) != nil {
			return core.ErrMemcachedUnixControl
		}
		// No own.current call after appending: that command capability is now
		// permanently invalid. Current reviewer authorization is still mandatory.
		if check(active) != nil || !lifetime.current() {
			return core.ErrMemcachedUnixControl
		}
		out.Observation = &result
		return core.ValidateMemcachedUnixControlReviewView(op, out)
	})
	if err != nil {
		return empty, err
	}
	return out, nil
}
func (s *Service) memcachedUnixControlReviewRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/memcached-unix/projects/{id}/controls/{request}/review", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !core.ValidID(r.PathValue("id")) || !core.ValidID(r.PathValue("request")) || r.URL.RawQuery != "" {
			respond(w, 404, map[string]string{"error": "原启停复核身份无效"})
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, core.MaxMemcachedUnixControlReviewBytes+1))
		in, decodeErr := core.DecodeMemcachedUnixControlReviewRequest(raw)
		if err != nil || decodeErr != nil || in.Operation.ProjectID != r.PathValue("id") || in.Operation.RequestID != r.PathValue("request") {
			respond(w, 400, map[string]string{"error": "复核不能替换原请求、当前审核人或携带原生命令"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		out, err := runMemcachedUnixControlReview(ctx, in)
		if err != nil {
			respond(w, 409, map[string]string{"error": "原请求、权限或真实当前状态不能核对；保留原结果，不重发启停命令"})
			return
		}
		respond(w, 200, out)
	})
}
