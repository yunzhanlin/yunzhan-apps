//go:build linux

package executor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"local/panel/internal/core"
)

var errMemcachedWorker = errors.New("Memcached 原更新的官方交付、当前授权或服务身份不能核对；保留原任务，不重放")

func memcachedUpdateDockerRead(ctx context.Context, path string, out any) error {
	status, raw, err := memcachedRetentionDaemon(ctx, http.MethodGet, path, nil)
	if err != nil || status != 200 || memcachedDaemonJSON(raw) != nil || json.Unmarshal(raw, out) != nil {
		return errMemcachedWorker
	}
	return nil
}

func memcachedUpdateImageRead(ctx context.Context, ref string) ([]byte, error) {
	var raw json.RawMessage
	if err := memcachedUpdateDockerRead(ctx, "/images/"+url.PathEscape(ref)+"/json", &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Independent loopback protocol observation. No cache mutation, authentication
// or caller-provided destination; Docker's health flag alone is not acceptance.
func memcachedUpdateProtocol(ctx context.Context, port int) error {
	if ctx == nil || ctx.Err() != nil || port < 1024 || port > 65535 {
		return errMemcachedWorker
	}
	bound, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(bound, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return errMemcachedWorker
	}
	defer c.Close()
	deadline, _ := bound.Deadline()
	if c.SetDeadline(deadline) != nil {
		return errMemcachedWorker
	}
	if n, err := c.Write([]byte("version\r\n")); err != nil || n != 9 {
		return errMemcachedWorker
	}
	line, err := bufio.NewReaderSize(c, 128).ReadSlice('\n')
	if err != nil || string(line) != "VERSION 1.6.45\r\n" || bound.Err() != nil {
		return errMemcachedWorker
	}
	return nil
}

func memcachedUpdateService(ctx context.Context, seed core.MemcachedUpdateRecord, refs map[string]string, healthy bool) (core.MemcachedUpdateObservation, error) {
	var empty core.MemcachedUpdateObservation
	m := composeMetadata{ID: seed.Dispatch.ProjectID, Engine: memcachedProjectEngine(seed.Dispatch.ProjectID), HostPort: seed.Plan.HostPort}
	filters, _ := json.Marshal(map[string][]string{"label": {"com.docker.compose.project=" + m.Engine}})
	var rows []struct {
		ID string `json:"Id"`
	}
	if memcachedUpdateDockerRead(ctx, "/containers/json?all=1&filters="+url.QueryEscape(string(filters)), &rows) != nil || len(rows) != 1 || !dockerPullDigestPattern.MatchString("sha256:"+rows[0].ID) {
		return empty, errMemcachedWorker
	}
	var raw json.RawMessage
	if memcachedUpdateDockerRead(ctx, "/containers/"+rows[0].ID+"/json", &raw) != nil {
		return empty, errMemcachedWorker
	}
	v, identity, err := memcachedUpdateRuntimeState(raw, m, func(ref string, out any) error {
		return memcachedUpdateDockerRead(ctx, "/images/"+url.PathEscape(ref)+"/json", out)
	}, healthy)
	if err != nil || v.ID != rows[0].ID || refs[v.Config.Image] == "" || refs[v.Config.Image] != v.Image {
		return empty, errMemcachedWorker
	}
	if healthy && memcachedUpdateProtocol(ctx, seed.Plan.HostPort) != nil {
		return empty, errMemcachedWorker
	}
	observation := core.MemcachedUpdateObservation{ContainerID: v.ID, ImageID: v.Image, RuntimeConfigSHA256: identity}
	if healthy {
		observation.Health = "healthy"
	}
	return observation, nil
}

// Constructed inside native admission only. A flock, unsigned journal or
// configurable callback alone never grants this worker execution authority.
type memcachedUpdateWorker struct {
	seed             core.MemcachedUpdateRecord
	run              *memcachedUpdateJournalLease
	engine           *dockerMutationLease
	core             *memcachedUpdateCoreAuthority
	project          *composeUpdateDirectory
	source, metadata os.FileInfo
}

func (w *memcachedUpdateWorker) authority(ctx context.Context, restoration bool) error {
	if ctx == nil || ctx.Err() != nil || w == nil || w.run == nil || w.engine == nil || w.core == nil || w.project == nil || !w.run.current() || !w.project.current() {
		return errMemcachedWorker
	}
	head, err := w.run.j.read()
	if err != nil || head.Dispatch != w.seed.Dispatch || restoration && head.Phase != "rollback_started" {
		return errMemcachedWorker
	}
	a, err := w.run.j.officialAuthority(ctx)
	if err != nil || !a.Matches(w.seed.Dispatch.Input.ExpectedVersion, w.seed.Dispatch.Input.ExpectedSHA256) || a.CatalogSHA256() != w.seed.CatalogSHA256 {
		return errMemcachedWorker
	}
	if restoration {
		err = w.core.restoration(ctx, w.seed)
	} else {
		err = w.core.check(ctx, w.seed)
	}
	if err != nil {
		return errMemcachedWorker
	}
	return w.engine.use(ctx, func(context.Context) error { return nil })
}

func (w *memcachedUpdateWorker) transition(phase, reason, target string, observation core.MemcachedUpdateObservation) error {
	before, err := w.run.j.read()
	if err != nil {
		return err
	}
	after := before
	after.Sequence++
	after.PreviousSHA256 = before.RecordSHA256
	after.Phase = phase
	after.Reason = reason
	if target != "" {
		after.TargetImageID = target
	}
	if observation != (core.MemcachedUpdateObservation{}) {
		after.Observation = observation
	}
	after, err = core.SealMemcachedUpdateRecord(after)
	if err != nil {
		return err
	}
	return w.run.append(after)
}

func (w *memcachedUpdateWorker) old(ctx context.Context, sourceRef bool) error {
	if w.authority(ctx, false) != nil {
		return errMemcachedWorker
	}
	plan, err := memcachedAppUpdatePlanBound(ctx, dockerProjects, w.seed.Dispatch.ProjectID, memcachedUpdateDockerRead, sourceRef)
	_, si, se := w.project.read("compose.yaml", 48<<10)
	_, mi, me := w.project.read("metadata.json", 16<<10)
	if err != nil || plan != w.seed.Plan || se != nil || me != nil || !sameComposeUpdateFile(w.source, si) || !sameComposeUpdateFile(w.metadata, mi) {
		return errMemcachedWorker
	}
	return nil
}

// A failed pull can still move a mutable source tag. Only fresh observation of
// the ENTIRE original service/source reference can release the project fence.
// Never label that situation safe merely because Compose up was not invoked.
func (w *memcachedUpdateWorker) failSafe(ctx context.Context, reason string) error {
	empty := core.MemcachedUpdateObservation{}
	if ctx == nil || ctx.Err() != nil {
		return w.transition("needs_attention", "interrupted", "", empty)
	}
	a, err := w.run.j.officialAuthority(ctx)
	if err != nil || !a.Matches(w.seed.Dispatch.Input.ExpectedVersion, w.seed.Dispatch.Input.ExpectedSHA256) {
		return errMemcachedWorker
	}
	plan, err := memcachedAppUpdatePlanAt(ctx, dockerProjects, w.seed.Dispatch.ProjectID, memcachedUpdateDockerRead)
	_, si, se := w.project.read("compose.yaml", 48<<10)
	_, mi, me := w.project.read("metadata.json", 16<<10)
	if err != nil || plan != w.seed.Plan || se != nil || me != nil || !sameComposeUpdateFile(w.source, si) || !sameComposeUpdateFile(w.metadata, mi) {
		return w.transition("needs_attention", "source_drift", "", empty)
	}
	return w.transition("failed_safe", reason, "", empty)
}

func (w *memcachedUpdateWorker) anchor(ctx context.Context) error {
	in, raw, err := memcachedRetentionOriginal(w.seed)
	if err != nil {
		return err
	}
	receipt, err := w.run.j.retentionEvidence(w.seed)
	if err != nil || receipt == nil {
		return errMemcachedWorker
	}
	status, actual, err := memcachedRetentionDaemon(ctx, http.MethodGet, "/containers/"+in.Name+"/json", nil)
	if err != nil || status != 200 {
		return errMemcachedWorker
	}
	_, err = memcachedRetentionInspect(actual, in, raw, receipt.ContainerID)
	return err
}

func (w *memcachedUpdateWorker) rollback(ctx context.Context, target string) error {
	// Only this already-running original worker restores. No restart scan,
	// request flag, alternate job/key or GET can enter a failed update again.
	if w.authority(ctx, true) != nil || w.anchor(ctx) != nil {
		return errMemcachedWorker
	}
	refs := map[string]string{w.seed.Plan.TargetImage: target, w.seed.Plan.CurrentImage: w.seed.Plan.RuntimeImageID, w.seed.Plan.RuntimeImageID: w.seed.Plan.RuntimeImageID}
	observed, err := memcachedUpdateService(ctx, w.seed, refs, false)
	if err != nil {
		return errMemcachedWorker
	}
	unchanged := observed.ContainerID == w.seed.Plan.ContainerID && observed.ImageID == w.seed.Plan.RuntimeImageID && observed.RuntimeConfigSHA256 == w.seed.Plan.RuntimeConfigSHA256
	if !unchanged {
		if w.authority(ctx, true) != nil || memcachedComposeApply(ctx, w.seed, true) != nil {
			return errMemcachedWorker
		}
	}
	refs = map[string]string{w.seed.Plan.RuntimeImageID: w.seed.Plan.RuntimeImageID}
	if unchanged {
		refs[w.seed.Plan.CurrentImage] = w.seed.Plan.RuntimeImageID
	}
	observed, err = memcachedUpdateService(ctx, w.seed, refs, true)
	if err != nil {
		return err
	}
	if w.authority(ctx, true) != nil || w.anchor(ctx) != nil || w.project.publishMemcachedCompose(ctx, w.seed, true, w.source, w.metadata) != nil {
		return errMemcachedWorker
	}
	observed.ComposeSHA256 = w.seed.Plan.RollbackComposeSHA256
	head, err := w.run.j.read()
	if err != nil {
		return err
	}
	return w.transition("rolled_back", head.Reason, "", observed)
}

func (w *memcachedUpdateWorker) execute(ctx context.Context) error {
	empty := core.MemcachedUpdateObservation{}
	if w.old(ctx, true) != nil {
		return w.failSafe(ctx, "precondition_changed")
	}
	if _, err := w.run.retainOriginalImage(ctx, memcachedRetentionDaemon, func(c context.Context) error { return w.old(c, true) }); err != nil {
		return w.transition("needs_attention", "journal_uncertain", "", empty)
	}
	if w.old(ctx, true) != nil || w.anchor(ctx) != nil {
		return w.failSafe(ctx, "precondition_changed")
	}
	if err := w.transition("pull_started", "", "", empty); err != nil {
		return err
	}
	if w.authority(ctx, false) != nil {
		return w.failSafe(ctx, "precondition_changed")
	}
	if err := dockerPullFromDaemon(ctx, w.seed.Plan.TargetImage, dockerClient(0), memcachedUpdateImageRead); err != nil {
		return w.failSafe(ctx, "pull_failed")
	}
	_, digest, _ := strings.Cut(w.seed.Plan.TargetImage, "@")
	target, err := verifyDockerPulledImage(ctx, dockerPullReceipt{Image: w.seed.Plan.TargetImage, Digest: digest}, memcachedUpdateImageRead)
	if err != nil {
		return w.failSafe(ctx, "target_image_rejected")
	}
	if err = w.transition("image_verified", "", target, empty); err != nil {
		return err
	}
	if w.old(ctx, false) != nil || w.anchor(ctx) != nil {
		return w.failSafe(ctx, "precondition_changed")
	}
	if err = w.transition("apply_started", "", "", empty); err != nil {
		return err
	}
	if w.authority(ctx, false) != nil {
		return w.transition("needs_attention", "source_drift", "", empty)
	}
	applyErr := memcachedComposeApply(ctx, w.seed, false)
	if ctx.Err() != nil {
		return w.transition("needs_attention", "apply_unknown", "", empty)
	}
	observed, healthErr := memcachedUpdateService(ctx, w.seed, map[string]string{w.seed.Plan.TargetImage: target}, true)
	if applyErr != nil || healthErr != nil || w.authority(ctx, false) != nil {
		reason := "target_unhealthy"
		if applyErr != nil {
			reason = "apply_failed"
		}
		if err = w.transition("rollback_started", reason, "", empty); err != nil {
			return err
		}
		if err = w.rollback(ctx, target); err != nil {
			return w.transition("needs_attention", "rollback_failed", "", empty)
		}
		return nil
	}
	// Source is untouched until target health; any uncertain exchange or fsync
	// retains both inodes and the original nonterminal transaction fence.
	if w.anchor(ctx) != nil || w.project.publishMemcachedCompose(ctx, w.seed, false, w.source, w.metadata) != nil {
		return w.transition("needs_attention", "journal_uncertain", "", empty)
	}
	observed.ComposeSHA256 = w.seed.TargetComposeSHA256
	if err = w.transition("applied", "", "", observed); err != nil {
		return err
	}
	current, err := memcachedUpdateService(ctx, w.seed, map[string]string{w.seed.Plan.TargetImage: target}, true)
	source, _, se := w.project.read("compose.yaml", 48<<10)
	if err != nil || se != nil || core.Hash(string(source)) != w.seed.TargetComposeSHA256 || current.ContainerID != observed.ContainerID || current.RuntimeConfigSHA256 != observed.RuntimeConfigSHA256 || w.authority(ctx, false) != nil {
		return w.transition("needs_attention", "health_unknown", "", empty)
	}
	return w.transition("committed", "", "", empty)
}

// Fresh native admission dispatches once. Repeated POST, observer, startup,
// timeout and reopened prepared records never requeue this original operation.
func runMemcachedAppUpdate(job string) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	j, err := (memcachedUpdateJournalStore{base: memcachedUpdateJobsRoot}).open(job)
	if err != nil {
		return
	}
	defer j.Close()
	run, err := j.lease()
	if err != nil {
		return
	}
	defer run.Close()
	defer func() {
		head, err := j.read()
		if err != nil || memcachedUpdateSafeTerminal(head.Phase) || head.Phase == "needs_attention" {
			return
		}
		bound, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if _, err := j.officialAuthority(bound); err == nil {
			_ = (&memcachedUpdateWorker{run: run}).transition("needs_attention", "interrupted", "", core.MemcachedUpdateObservation{})
		}
	}()
	chain, err := j.readChain()
	if err != nil || len(chain) != 1 || chain[0].Phase != "prepared" {
		return
	}
	seed := chain[0]
	engine, err := productionDockerMutationStore().acquire(ctx)
	if err != nil {
		return
	}
	defer engine.Close()
	reader, err := openMemcachedUpdateCoreAuthority(ctx)
	if err != nil {
		return
	}
	defer reader.Close()
	project, err := openComposeUpdateDirectory(dockerProjects, seed.Dispatch.ProjectID)
	if err != nil {
		return
	}
	defer project.Close()
	_, source, se := project.read("compose.yaml", 48<<10)
	_, metadata, me := project.read("metadata.json", 16<<10)
	if se != nil || me != nil {
		return
	}
	w := &memcachedUpdateWorker{seed: seed, run: run, engine: engine, core: reader, project: project, source: source, metadata: metadata}
	_ = engine.use(ctx, w.execute)
}
