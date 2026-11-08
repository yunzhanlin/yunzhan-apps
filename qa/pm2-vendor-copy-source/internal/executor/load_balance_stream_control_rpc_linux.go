//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamLiveControl struct {
	mu         sync.RWMutex
	controller *loadBalanceStreamTrafficController
	ctx        context.Context
	done       chan struct{}
}

var loadBalanceStreamLiveControls sync.Map

func streamControlResult(op loadbalancestream.Operation, state string) core.LoadBalanceStreamNativeResult {
	return core.LoadBalanceStreamNativeResult{Format: 1, RequestID: op.RequestID, Version: loadbalancestream.AppVersion,
		OperationSHA256: loadbalancestream.OperationSHA256(op), State: state}
}

func (v *loadBalanceStreamLiveControl) live() bool {
	if v == nil {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.ctx == nil || v.ctx.Err() != nil || v.controller == nil || v.controller.owner == nil ||
		v.controller.journal == nil || !v.controller.journal.creator ||
		v.controller.owner.process == nil || v.controller.owner.process.PID != os.Getpid() ||
		!v.controller.lifetime.current() || !v.controller.mutation.current() ||
		!streamControlHeldLease(v.controller.lifetime.file.file, false) ||
		!streamControlHeldLease(v.controller.mutation.file, true) || !streamControlHeldLease(v.controller.journal.lock, true) {
		return false
	}
	select {
	case <-v.done:
		return false
	default:
		return true
	}
}

// The ONE POST only prepares a fresh original creator and schedules its body.
// A long graceful drain does not depend on the generic 90s HTTP client limit.
// Browser disconnects never create another dispatch; server/process death
// leaves the original unknown journal and no restart/resume worker is emitted.
func (s *Service) submitLoadBalanceStreamControl(ctx context.Context, op loadbalancestream.Operation) (core.LoadBalanceStreamNativeResult, error) {
	unknown := streamControlResult(op, "unknown")
	if ctx == nil || ctx.Err() != nil || s == nil || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return unknown, errLoadBalanceStreamInstallationGate
	}
	if _, err := loadbalancestream.OperationBytes(op); err != nil {
		return unknown, err
	}
	if _, exists := loadBalanceStreamLiveControls.Load(op.RequestID); exists {
		return observeLoadBalanceStreamControl(ctx, op.RequestID)
	}
	if _, err := os.Lstat(filepath.Join(loadBalanceStreamJobsRoot, op.RequestID)); err == nil {
		return observeLoadBalanceStreamControl(ctx, op.RequestID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return unknown, errLoadBalanceStreamJournal
	}
	c, err := prepareLoadBalanceStreamTrafficController(ctx, s, op)
	if err != nil {
		if refusal, ok := err.(*loadBalanceStreamPreflightRefusalError); ok && refusal.result.State == "refused-before-effects" && core.ValidateLoadBalanceStreamNativeResult(refusal.result, op) == nil {
			return refusal.result, nil
		}
		return unknown, err
	}
	// Fixed total bound for this new protocol only, shorter than the Core
	// original observer's bound. No global client/policy timeout is increased.
	runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(loadbalancestream.RuntimeDrainSeconds+120)*time.Second)
	live := &loadBalanceStreamLiveControl{controller: c, ctx: runCtx, done: make(chan struct{})}
	if _, loaded := loadBalanceStreamLiveControls.LoadOrStore(op.RequestID, live); loaded {
		cancel()
		c.close()
		return unknown, errLoadBalanceStreamJournal
	}
	go func() {
		defer func() {
			if recover() != nil {
				log.Print("TCP/UDP original controller panicked; original outcome remains unknown; no replay")
			}
			live.mu.Lock()
			defer live.mu.Unlock()
			close(live.done)
			loadBalanceStreamLiveControls.CompareAndDelete(op.RequestID, live)
			cancel()
			c.close()
		}()
		// An error never writes a successful seal, deletes partial state,
		// sends another signal/start or repairs a prior directory.
		if _, err := c.execute(runCtx); err != nil {
			// Fixed protocol stages and validated request ID only; no credentials,
			// browser policy, configuration bytes or automatic replay are logged.
			log.Printf("TCP/UDP original control %s failed: %v; original outcome remains unknown; no replay", op.RequestID, err)
		}
	}()
	return streamControlResult(op, "running"), nil
}

// GET is a historical original transaction observation, NOT today's health
// and never a recovery/start operation. No reader creates a seal, fills in a
// missing phase, replays an intent or adopts a live/unknown old controller.
func observeLoadBalanceStreamControl(ctx context.Context, request string) (core.LoadBalanceStreamNativeResult, error) {
	empty := core.LoadBalanceStreamNativeResult{Format: 1, RequestID: request, Version: loadbalancestream.AppVersion, State: "unknown"}
	if ctx == nil || ctx.Err() != nil || !core.ValidID(request) || os.Geteuid() != 0 ||
		!loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return empty, errLoadBalanceStreamInstallationGate
	}
	if actual, ok := loadBalanceStreamLiveControls.Load(request); ok {
		live, ok := actual.(*loadBalanceStreamLiveControl)
		if ok && live.live() && live.controller.store.original.RequestID == request {
			return streamControlResult(live.controller.store.operation, "running"), nil
		}
		return empty, errLoadBalanceStreamJournal
	}
	j, err := openLoadBalanceStreamJournalReadOnlyAt(loadBalanceStreamJobsRoot, request)
	if err != nil {
		return empty, err
	}
	defer j.close()
	run, err := j.read("run.lock", 0)
	if err != nil {
		return empty, err
	}
	defer run.close()
	if syscall.Flock(int(run.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return empty, errLoadBalanceStreamJournal
	}
	raw, records, chain, err := j.original(ctx)
	if err != nil || !chain.Complete || chain.OriginalUnknown {
		return empty, errLoadBalanceStreamJournal
	}
	seed, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		return empty, err
	}
	empty = streamControlResult(seed.Operation, "unknown")
	installed, err := holdLoadBalanceStreamInstalledContext(ctx)
	if err != nil {
		return empty, err
	}
	defer installed.close()
	pool, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamConfigurationPublicationsRoot, false)
	if err != nil {
		return empty, err
	}
	defer pool.Close()
	pub, err := pool.OpenRoot(request)
	if err != nil {
		return empty, err
	}
	defer pub.Close()
	before, e1 := pub.Stat(".")
	named, e2 := pool.Lstat(request)
	if e1 != nil || e2 != nil || !memcachedUnixAdminDirectoryInfo(before) || !geoStoreStableInfo(before, named) {
		return empty, errLoadBalanceStreamJournal
	}
	seal, err := readStreamControlCompletion(pub)
	if err != nil {
		return empty, err
	}
	result, err := decodeStreamControlCompletion(seal, raw)
	if err != nil {
		return empty, err
	}
	cfg, err := os.OpenRoot(loadBalanceStreamConfigurationRoot)
	if err != nil {
		return empty, err
	}
	defer cfg.Close()
	history, err := checkStreamConfigurationPublication(pub, cfg, raw, installed.identity.GID, false)
	if err != nil || !bytes.Equal(history.CompletionReceipt, seal) || len(history.ServiceReceipt) == 0 ||
		core.Hash(string(history.ServiceReceipt)) != result.ServiceReceiptSHA256 {
		return empty, errLoadBalanceStreamJournal
	}
	serviceReceipt, err := decodeStreamServiceReceipt(history.ServiceReceipt, raw)
	if err != nil || serviceReceipt.InstallationID != installed.receipt.InstallationID {
		return empty, errLoadBalanceStreamJournal
	}
	generations, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamGenerationPublicationsRoot, false)
	if err != nil {
		return empty, err
	}
	defer generations.Close()
	gp, err := generations.OpenRoot(request)
	if err != nil {
		return empty, err
	}
	defer gp.Close()
	generation, err := streamInstallationPrivateRead(gp, "proposal.json", loadbalancestream.MaxGenerationRecordBytes)
	if err != nil || core.Hash(string(generation)) != result.GenerationSHA256 ||
		!loadbalancestream.GenerationRecordBindsOriginal(generation, installed.receipt.InstallationID, result.Generation, raw, records) {
		return empty, errLoadBalanceStreamJournal
	}
	if _, err := checkStreamGenerationPublication(gp, raw, generation); err != nil {
		return empty, errLoadBalanceStreamJournal
	}
	for i, record := range records {
		if i >= len(result.Records) || result.Records[i] != string(record) {
			return empty, errLoadBalanceStreamJournal
		}
	}
	after, e1 := pub.Stat(".")
	named, e2 = pool.Lstat(request)
	if e1 != nil || e2 != nil || !geoStoreStableInfo(before, after) || !geoStoreStableInfo(after, named) ||
		!j.current() || !run.current() || !streamControlCompletionMatches(pub, seal) ||
		installed.current(ctx) != nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamJournal
	}
	return result, nil
}

func (s *Service) loadBalanceStreamControlRoutes(m *http.ServeMux) {
	m.HandleFunc("GET /v1/load-balance-stream/workspace", func(w http.ResponseWriter, r *http.Request) {
		if s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" {
			respond(w, 409, map[string]string{"error": "实际固定主机布局不可核对"})
			return
		}
		out, err := observeLoadBalanceStreamWorkspace(r.Context())
		if err != nil {
			respond(w, 409, map[string]string{"error": "当前原生状态无法核对；未执行变更"})
			return
		}
		respond(w, 200, out)
	})
	m.HandleFunc("POST /v1/load-balance-stream/controls", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, loadbalancestream.MaxEntryBytes+1024))
		if err != nil {
			respond(w, 400, map[string]string{"error": "TCP/UDP 控制请求超出固定容量"})
			return
		}
		op, err := loadbalancestream.DecodeOperation(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		result, err := s.submitLoadBalanceStreamControl(r.Context(), op)
		if err != nil {
			respond(w, 409, map[string]any{"result": result, "error": err.Error()})
			return
		}
		respond(w, 202, result)
	})
	m.HandleFunc("GET /v1/load-balance-stream/controls/{request}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("request")
		if !core.ValidID(id) {
			respond(w, 400, map[string]string{"error": "原始请求编号无效"})
			return
		}
		if s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" {
			respond(w, 409, map[string]string{"error": "TCP/UDP 观察仅支持实际固定主机布局"})
			return
		}
		result, err := observeLoadBalanceStreamControl(r.Context(), id)
		if err != nil {
			respond(w, 409, map[string]any{"result": result, "error": err.Error()})
			return
		}
		respond(w, 200, result)
	})
}
