//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamInstallObservationsRoot = "/var/lib/panel-executor/load-balance-stream-install-observations"

type loadBalanceStreamObservedInstallExit struct {
	Format                    int                                 `json:"format"`
	Unit                      string                              `json:"unit"`
	SubmissionSHA256          string                              `json:"submission_sha256"`
	OriginalStartWaitExitZero bool                                `json:"original_start_wait_exit_zero"`
	Result                    core.LoadBalanceStreamInstallResult `json:"result"`
}

func streamInstallResult(job, state string) core.LoadBalanceStreamInstallResult {
	return core.LoadBalanceStreamInstallResult{Format: 1, JobID: job, Version: loadbalancestream.AppVersion, State: state}
}

// Only the original submitter invokes this after its ONE real --wait start
// returned exit zero AND the complete current original installation was read.
// A claimed RPC result, an old opener, or a journal alone cannot write it.
func retainLoadBalanceStreamOriginalExit(ctx context.Context, submission *loadBalanceStreamHeldSubmission, result core.LoadBalanceStreamInstallResult) error {
	if ctx == nil || ctx.Err() != nil || submission == nil || !submission.creator || !submission.nativeParentExitObserved || !submission.current() || result.State != "committed" || core.ValidateLoadBalanceStreamInstallResult(result, submission.value.JobID) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	unit, err := loadbalancestream.AccountParentUnit(result.JobID)
	if err != nil || unit != submission.nativeParentUnit {
		return errLoadBalanceStreamInstallationJournal
	}
	observed := loadBalanceStreamObservedInstallExit{1, unit, core.Hash(string(submission.raw)), true, result}
	raw, err := json.Marshal(observed)
	if err != nil || len(raw) > 2047 {
		return errLoadBalanceStreamInstallationJournal
	}
	raw = append(raw, '\n')
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallObservationsRoot, true)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := dir.ReadDir(129)
	dir.Close()
	if readErr != nil && readErr != io.EOF || len(entries) >= 128 {
		return errLoadBalanceStreamInstallationJournal
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if !strings.HasSuffix(entry.Name(), ".json") || !core.ValidID(strings.TrimSuffix(entry.Name(), ".json")) || err != nil || !streamJournalFileInfo(info, 2048) {
			return errLoadBalanceStreamInstallationJournal
		}
	}
	if !submission.current() || ctx.Err() != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	f, err := root.OpenFile(result.JobID+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil || !streamModulePublicationMatches(root, result.JobID+".json", raw) {
		return errLoadBalanceStreamInstallationJournal
	}
	return nil
}

func loadBalanceStreamOriginalJobEvidence(job string) (bool, error) {
	if !core.ValidID(job) {
		return true, errLoadBalanceStreamInstallationJournal
	}
	for _, location := range []struct{ root, leaf string }{
		{loadBalanceStreamInstallationJobsRoot, job}, {loadBalanceStreamModulePublicationsRoot, job}, {loadBalanceStreamAccountPermitsRoot, job + ".json"}, {loadBalanceStreamInstallObservationsRoot, job + ".json"},
	} {
		if _, err := os.Lstat(location.root); errors.Is(err, os.ErrNotExist) {
			if threatIDSTrustedParents(filepath.Dir(location.root), false) != nil {
				return true, errLoadBalanceStreamInstallationJournal
			}
			continue
		} else if err != nil {
			return true, errLoadBalanceStreamInstallationJournal
		}
		root, err := streamJournalAnchor(location.root)
		if err != nil {
			return true, err
		}
		_, err = root.Lstat(location.leaf)
		root.Close()
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return true, errLoadBalanceStreamInstallationJournal
		}
	}
	if _, err := os.Lstat(loadBalanceStreamAccountStorePath); err == nil {
		store, err := openLoadBalanceStreamAccountStoreAt(loadBalanceStreamAccountStorePath)
		if err != nil {
			return true, err
		}
		defer store.root.Close()
		record, err := store.read("account-intent.json")
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return true, err
		}
		defer record.close()
		intent, err := decodeLoadBalanceStreamAccountIntent(record.bytes())
		if err != nil || !record.current() {
			return true, errLoadBalanceStreamAccount
		}
		if intent.JobID == job {
			return true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return true, errLoadBalanceStreamAccount
	}
	return false, nil
}

func observeLoadBalanceStreamInstall(ctx context.Context, job string) (core.LoadBalanceStreamInstallResult, error) {
	unknown := streamInstallResult(job, "unknown")
	if ctx == nil || ctx.Err() != nil || !core.ValidID(job) || os.Geteuid() != 0 {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	unit, _ := loadbalancestream.AccountParentUnit(job)
	state, unitErr := streamInstallUnitProperties(ctx, unit)
	if unitErr == nil && state["LoadState"] == "loaded" && (state["ActiveState"] == "activating" || state["ActiveState"] == "active" && state["SubState"] == "running") {
		// Do not race a live creator's exclusive file append or mistake a
		// transient incomplete prefix for completed native installation.
		return streamInstallResult(job, "running"), nil
	}
	for _, path := range []string{loadBalanceStreamSubmissionsRoot, loadBalanceStreamInstallObservationsRoot} {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			if threatIDSTrustedParents(filepath.Dir(path), false) != nil {
				return unknown, errLoadBalanceStreamInstallationJournal
			}
			// Absence after any original evidence is not a fresh empty job.
			if _, e := os.Lstat(filepath.Join(loadBalanceStreamInstallationJobsRoot, job)); !errors.Is(e, os.ErrNotExist) {
				return unknown, errLoadBalanceStreamInstallationJournal
			}
			if path == loadBalanceStreamSubmissionsRoot {
				if exists, err := loadBalanceStreamOriginalJobEvidence(job); err != nil || exists {
					return unknown, errLoadBalanceStreamInstallationJournal
				}
				return streamInstallResult(job, "not-found"), nil
			}
			return unknown, nil
		} else if err != nil {
			return unknown, errLoadBalanceStreamInstallationJournal
		}
	}
	submission, err := holdLoadBalanceStreamSubmission(job)
	if err != nil {
		if _, e := os.Lstat(filepath.Join(loadBalanceStreamSubmissionsRoot, job+".json")); errors.Is(e, os.ErrNotExist) && unitErr == nil && state["MainPID"] == "0" && state["ControlPID"] == "0" && state["InvocationID"] == "" {
			return streamInstallResult(job, "not-found"), nil
		}
		return unknown, err
	}
	defer submission.close()
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallObservationsRoot, false)
	if err != nil {
		return unknown, err
	}
	defer root.Close()
	raw, err := streamInstallationPrivateRead(root, job+".json", 2048)
	if err != nil {
		return unknown, err
	}
	var observed loadBalanceStreamObservedInstallExit
	if decodeProgramQueueJSON(raw, &observed) != nil || observed.Format != 1 || observed.Unit != unit || observed.SubmissionSHA256 != core.Hash(string(submission.raw)) || !observed.OriginalStartWaitExitZero || observed.Result.State != "committed" || core.ValidateLoadBalanceStreamInstallResult(observed.Result, job) != nil {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	canonical, _ := json.Marshal(observed)
	if !bytes.Equal(append(canonical, '\n'), raw) {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	actual, err := readLoadBalanceStreamCommittedInstallation(ctx, job)
	if err != nil || actual != observed.Result || !submission.current() {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	return actual, nil
}

// Synchronous once-only dispatch. The --wait caller itself retains the actual
// native exit observation before returning, so unit garbage collection does
// not turn a prior expected result into claimed success on a later GET.
// It releases the L4 mutation lease BEFORE starting the parent, and never owns
// the Compose capability while that parent waits for its independent child.
func (s *Service) submitLoadBalanceStreamInstall(ctx context.Context, in core.LoadBalanceStreamInstallSubmission) (core.LoadBalanceStreamInstallResult, error) {
	unknown := streamInstallResult(in.JobID, "unknown")
	if ctx == nil || ctx.Err() != nil || s == nil || s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" || !loadBalanceStreamAccountHash(loadBalanceStreamCompiledProgrammeInputsSHA256) {
		return unknown, errLoadBalanceStreamInstallationGate
	}
	if _, err := core.LoadBalanceStreamInstallSubmissionBytes(in); err != nil {
		return unknown, err
	}
	source, err := openLoadBalanceStreamCoreAuthority(ctx)
	if err != nil {
		return unknown, err
	}
	defer source.close()
	grant, err := source.installAuthority(ctx, in.JobID)
	if err != nil {
		return unknown, err
	}
	authority, err := appcatalog.VerifyLoadBalanceStreamReleaseEnvelope(ctx, in.Release, grant.AppVersion, grant.ManifestSHA256)
	if err != nil || !authority.Matches(grant.AppVersion, grant.ManifestSHA256) {
		return unknown, errLoadBalanceStreamInstallationGate
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	lifetime, err := acquireMemcachedUnixRuntime(bounded)
	cancel()
	if err != nil {
		return unknown, err
	}
	defer lifetime.Close()
	bounded, cancel = context.WithTimeout(ctx, 3*time.Second)
	mutation, err := acquireLoadBalanceStreamMutation(bounded)
	cancel()
	if err != nil {
		return unknown, err
	}
	defer mutation.close()
	authorize := func(c context.Context) error {
		if c == nil || c.Err() != nil || !lifetime.current() || !mutation.current() || source.checkInstall(c, grant) != nil {
			return errLoadBalanceStreamInstallationGate
		}
		return nil
	}
	// A prior handoff is observation only; never dispatch it a second time,
	// including when its first start reply or complete result was lost.
	if _, err := os.Lstat(filepath.Join(loadBalanceStreamSubmissionsRoot, in.JobID+".json")); err == nil {
		return observeLoadBalanceStreamInstall(ctx, in.JobID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	if exists, err := loadBalanceStreamOriginalJobEvidence(in.JobID); err != nil || exists {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	owner := &loadBalanceStreamUpgradeOwner{source: source, original: grant, lifetime: lifetime, mutation: mutation}
	if authorize(ctx) != nil || checkLegacyProgramUpgradeQueues() != nil || checkLoadBalanceStreamUpgrade(ctx, owner) != nil {
		return unknown, errLoadBalanceStreamInstallationGate
	}
	unit, err := loadbalancestream.AccountParentUnit(in.JobID)
	if err != nil {
		return unknown, err
	}
	prior, err := streamInstallUnitProperties(ctx, unit)
	if err != nil || prior["LoadState"] != "loaded" || prior["ActiveState"] != "inactive" || prior["SubState"] != "dead" || prior["MainPID"] != "0" || prior["ControlPID"] != "0" || prior["InvocationID"] != "" {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	if err := preflightLoadBalanceStreamInstall(ctx, owner); err != nil {
		return unknown, err
	}
	submission, err := writeLoadBalanceStreamSubmission(ctx, in, authorize)
	if err != nil {
		return unknown, err
	}
	defer submission.close()
	owner.submission = submission
	if authorize(ctx) != nil || !submission.current() || checkLoadBalanceStreamUpgrade(ctx, owner) != nil {
		return unknown, errLoadBalanceStreamInstallationGate
	}
	mutation.close()
	// No mutation-lease callback is used after release; the independently
	// verified original parent becomes the sole new journal creator.
	bounded, cancel = context.WithTimeout(ctx, 90*time.Second)
	_, err = programQueueCommand(bounded, "/usr/bin/systemctl", "--wait", "start", unit)
	cancel()
	if err != nil || ctx.Err() != nil || !lifetime.current() || !submission.current() {
		return unknown, errLoadBalanceStreamInstallationJournal
	}
	submission.nativeParentUnit = unit
	submission.nativeParentExitObserved = true
	result, err := readLoadBalanceStreamCommittedInstallation(ctx, in.JobID)
	if err != nil {
		return unknown, err
	}
	if err = retainLoadBalanceStreamOriginalExit(ctx, submission, result); err != nil {
		return unknown, err
	}
	return observeLoadBalanceStreamInstall(ctx, in.JobID)
}

func (s *Service) loadBalanceStreamInstallRoutes(m *http.ServeMux) {
	m.HandleFunc("POST /v1/load-balance-stream/install-jobs", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, core.LoadBalanceStreamInstallSubmissionMaxBytes))
		if err != nil {
			respond(w, 400, map[string]string{"error": "TCP/UDP 原始签名交接超过固定容量或不可读取"})
			return
		}
		in, err := core.DecodeLoadBalanceStreamInstallSubmission(raw)
		if err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		result, err := s.submitLoadBalanceStreamInstall(r.Context(), in)
		if err != nil {
			respond(w, 409, struct {
				core.LoadBalanceStreamInstallResult
				Error string `json:"error"`
			}{result, err.Error()})
			return
		}
		respond(w, 200, result)
	})
	m.HandleFunc("GET /v1/load-balance-stream/install-jobs/{job}", func(w http.ResponseWriter, r *http.Request) {
		job := r.PathValue("job")
		if !core.ValidID(job) {
			respond(w, 400, map[string]string{"error": "TCP/UDP 原任务编号无效"})
			return
		}
		if s.Config.SystemRoot != "/" || s.Config.SecurityDir != "/etc/panel/security-apps" {
			respond(w, 409, map[string]string{"error": "TCP/UDP 原生任务观察仅支持固定实际主机布局；未从测试根读取宿主"})
			return
		}
		result, err := observeLoadBalanceStreamInstall(r.Context(), job)
		if err != nil {
			respond(w, 409, struct {
				core.LoadBalanceStreamInstallResult
				Error string `json:"error"`
			}{result, err.Error()})
			return
		}
		respond(w, 200, result)
	})
}
