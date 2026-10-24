//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// A service that has not yet been dispatched has no list-units/list-jobs row.
// Retained controls therefore need independent matching terminal evidence.
// These checks prove an operation is not pending, never engine ABI, activation
// or threat-data trust. Existing activation paths retain their own verifiers.
func (r *programQueueReader) nativeBuilds() error {
	families := []struct {
		requests, cancellations, builds string
		validate                        func(string, []byte) error
	}{
		{"waf-engine-requests", "waf-engine-cancellations", "waf-engine-builds", programQueueWAFBuild},
		{"apache-body-requests", "apache-body-cancellations", "apache-body-builds", programQueueApacheBuild},
		{"analytics-html-requests", "analytics-html-cancellations", "analytics-html-builds", programQueueHTMLBuild},
	}
	for _, family := range families {
		requests := map[string]bool{}
		cancellations := map[string]bool{}
		terminal := map[string]bool{}
		controls := func(target map[string]bool) func(string, []byte) error {
			return func(id string, raw []byte) error {
				var v wafEngineRequest
				if decodeProgramQueueJSON(raw, &v) != nil || v.Format != 1 || !core.ValidID(id) || v.JobID != id {
					return errors.New("native build control binding cannot be verified")
				}
				if _, err := time.Parse(time.RFC3339, v.CreatedAt); err != nil {
					return errors.New("native build control time cannot be verified")
				}
				target[id] = true
				return nil
			}
		}
		for _, check := range []struct {
			name     string
			maximum  int
			limit    int64
			validate func(string, []byte) error
		}{
			{family.requests, 64, 1024, controls(requests)},
			{family.cancellations, 64, 1024, controls(cancellations)},
			{family.builds, 64, 128 << 10, func(id string, raw []byte) error {
				if err := family.validate(id, raw); err != nil {
					return err
				}
				terminal[id] = true
				return nil
			}},
		} {
			if err := r.records("var/lib/panel-executor/"+check.name, check.maximum, check.limit, check.validate); err != nil {
				return err
			}
		}
		for id := range requests {
			if !terminal[id] && !cancellations[id] {
				return errors.New("native build request has no terminal or explicit cancellation evidence; upgrade refused")
			}
		}
	}
	return nil
}
func programQueueBuildTerminal(format int, id, job, state, arch, prefix, wantPrefix, started, finished string) error {
	if format != 1 || !core.ValidID(id) || job != id || arch != runtime.GOARCH || prefix != filepath.Join(wantPrefix, id) {
		return errors.New("native build record binding cannot be verified")
	}
	if _, err := time.Parse(time.RFC3339, started); err != nil {
		return errors.New("native build start time cannot be verified")
	}
	if state == "building" {
		return errors.New("native build record remains pending; upgrade refused")
	}
	if state != "ready" && state != "failed" {
		return errors.New("unknown native build record state")
	}
	start, _ := time.Parse(time.RFC3339, started)
	finish, err := time.Parse(time.RFC3339, finished)
	if err != nil || finish.Before(start) {
		return errors.New("native build terminal completion time cannot be verified")
	}
	return nil
}
func programQueueWAFBuild(id string, raw []byte) error {
	var v wafEngineBuildRecord
	if decodeProgramQueueJSON(raw, &v) != nil {
		return errors.New("native WAF build record cannot be decoded")
	}
	return programQueueBuildTerminal(v.Format, id, v.JobID, v.State, v.Architecture, v.Prefix, wafNativeEngines, v.StartedAt, v.FinishedAt)
}
func programQueueApacheBuild(id string, raw []byte) error {
	var v apacheBodyBuildRecord
	if decodeProgramQueueJSON(raw, &v) != nil {
		return errors.New("native Apache build record cannot be decoded")
	}
	return programQueueBuildTerminal(v.Format, id, v.JobID, v.State, v.Architecture, v.Prefix, apacheBodyEngines, v.StartedAt, v.FinishedAt)
}
func programQueueHTMLBuild(id string, raw []byte) error {
	var v analyticsHTMLBuildRecord
	if decodeProgramQueueJSON(raw, &v) != nil {
		return errors.New("native HTML build record cannot be decoded")
	}
	return programQueueBuildTerminal(v.Format, id, v.JobID, v.State, v.Architecture, v.Prefix, analyticsHTMLNativeRoot, v.StartedAt, v.FinishedAt)
}

func (r *programQueueReader) ruleFeedJobs() error {
	relative := "var/lib/panel-executor/network-rule-feed-jobs"
	root, err := r.directory(relative)
	if err != nil || root == nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(17)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 16 {
		return errors.New("native rule feed complete job inventory exceeds budget")
	}
	for _, entry := range entries {
		id := entry.Name()
		if !core.ValidID(id) || !entry.IsDir() {
			return errors.New("native rule feed job has unknown or unpublished stage; upgrade refused")
		}
		childRelative := relative + "/" + id
		child, err := r.directory(childRelative)
		if err != nil || child == nil {
			if err != nil {
				return err
			}
			return errors.New("native rule feed job disappeared")
		}
		err = r.ruleFeedJob(childRelative, id, child)
		child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *programQueueReader) ruleFeedJob(relative, id string, root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(5)
	dir.Close()
	if err != nil && !errors.Is(err, io.EOF) || len(entries) > 4 {
		return errors.New("native rule feed job contains unknown or unpublished files")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		switch entry.Name() {
		case "request.json", "envelope.json", "result.json", "install.lock":
		default:
			return errors.New("native rule feed job contains unknown or unpublished files")
		}
		seen[entry.Name()] = true
	}
	if !seen["request.json"] || !seen["envelope.json"] || !seen["result.json"] {
		return errors.New("native rule feed request lacks terminal evidence; upgrade refused")
	}
	if seen["install.lock"] {
		lock, err := root.OpenFile("install.lock", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer lock.Close()
		before, err := lock.Stat()
		if err != nil || !runtimeInstallPrivateFile(before) || before.Size() != 0 {
			return errors.New("native rule feed lock identity cannot be verified")
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			return errors.New("native rule feed installation still holds its lock; upgrade refused")
		}
		after, err := root.Lstat("install.lock")
		if err != nil || !programQueueSame(before, after) {
			return errors.New("native rule feed lock changed during preflight")
		}
		r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, "install.lock"), after})
	}
	data, err := r.record(root, relative, "request.json", 8192)
	if err != nil {
		return err
	}
	var request threatIDSRuleFeedRequest
	if decodeProgramQueueJSON(data, &request) != nil || request.Format != 1 || request.JobID != id || core.ValidateNetworkIDSRuleFeedSelection(request.Selection) != nil || !networkIDSRootSHA.MatchString(request.EnvelopeSHA) {
		return errors.New("native rule feed request binding cannot be verified")
	}
	envelopeSHA, err := r.ruleFeedEnvelope(root, relative)
	if err != nil {
		return err
	}
	if envelopeSHA != request.EnvelopeSHA {
		return errors.New("native rule feed retained delivery differs from original request")
	}
	data, err = r.record(root, relative, "result.json", 16<<10)
	if err != nil {
		return err
	}
	var result core.NetworkIDSRuleFeedStatus
	if decodeProgramQueueJSON(data, &result) != nil || result.JobID != id || result.Selection != request.Selection || !result.DataOnly || result.CaptureStarted || result.NativeSyntaxVerified || len(result.Steps) > 16 || len(result.Error) > 1024 {
		return errors.New("native rule feed result binding cannot be verified")
	}
	if result.State == "failed" && result.Error != "" || result.State == "ready-data" && result.Error == "" {
		return nil
	}
	return errors.New("native rule feed result is pending, unknown or uncertain; upgrade refused")
}

// The legitimate envelope contract is 16 MiB per job. Hash at most16 jobs
// through a fixed32 KiB buffer; do not materialize256 MiB of retained feeds.
func (r *programQueueReader) ruleFeedEnvelope(root *os.Root, relative string) (string, error) {
	f, err := root.OpenFile("envelope.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !runtimeInstallPrivateFile(before) || before.Size() < 1 || before.Size() > appcatalog.MaxRuleFeedEnvelopeBytes {
		return "", errors.New("native rule feed envelope identity or size cannot be verified")
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	var size int64
	for {
		if err := r.ctx.Err(); err != nil {
			return "", err
		}
		n, err := f.Read(buffer)
		size += int64(n)
		r.deliveryBytes += int64(n)
		if size > appcatalog.MaxRuleFeedEnvelopeBytes || r.deliveryBytes > 16*appcatalog.MaxRuleFeedEnvelopeBytes {
			return "", errors.New("native rule feed complete streaming budget exceeded")
		}
		if n > 0 {
			h.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	after, err := f.Stat()
	current, currentErr := root.Lstat("envelope.json")
	if err != nil || currentErr != nil || size != before.Size() || !programQueueSame(before, after) || !programQueueSame(after, current) {
		return "", errors.New("native rule feed envelope changed while streaming")
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, "envelope.json"), after})
	return hex.EncodeToString(h.Sum(nil)), nil
}
