//go:build linux

package executor

import (
	"context"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProgramUpgradeQueuesUnstartedNativeBuildRequestsNeedTerminalOrCancellation(t *testing.T) {
	for _, family := range []string{"waf-engine", "apache-body", "analytics-html"} {
		for _, state := range []string{"unstarted", "building", "ready", "failed", "cancelled", "unknown", "missing-finish", "foreign-identity"} {
			t.Run(family+"-"+state, func(t *testing.T) {
				root := programQueueFixture(t)
				id := core.ID()
				base := "var/lib/panel-executor/" + family
				control := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
				writeProgramQueueFixture(t, root, base+"-requests", id, control)
				if state == "cancelled" {
					writeProgramQueueFixture(t, root, base+"-cancellations", id, control)
				}
				if state != "unstarted" && state != "cancelled" {
					job := id
					const started = "2026-10-12T00:00:00Z"
					finish := "2026-10-12T00:01:00Z"
					if state == "foreign-identity" {
						job = core.ID()
					}
					if state == "missing-finish" {
						finish = ""
					}
					actualState := state
					if state == "foreign-identity" || state == "missing-finish" {
						actualState = "ready"
					}
					switch family {
					case "waf-engine":
						writeProgramQueueFixture(t, root, base+"-builds", id, wafEngineBuildRecord{Format: 1, JobID: job, State: actualState, Architecture: runtime.GOARCH, Prefix: filepath.Join(wafNativeEngines, id), StartedAt: started, FinishedAt: finish})
					case "apache-body":
						writeProgramQueueFixture(t, root, base+"-builds", id, apacheBodyBuildRecord{Format: 1, JobID: job, State: actualState, Architecture: runtime.GOARCH, Prefix: filepath.Join(apacheBodyEngines, id), StartedAt: started, FinishedAt: finish})
					case "analytics-html":
						writeProgramQueueFixture(t, root, base+"-builds", id, analyticsHTMLBuildRecord{analyticsHTMLEngineIdentity: analyticsHTMLEngineIdentity{Format: 1, JobID: job, State: actualState, Architecture: runtime.GOARCH, Prefix: filepath.Join(analyticsHTMLNativeRoot, id)}, StartedAt: started, FinishedAt: finish})
					}
				}
				before := programQueueTree(t, root)
				err := checkProgramUpgradeQueues(context.Background(), root)
				if (err != nil) != (state != "ready" && state != "failed" && state != "cancelled") {
					t.Fatal(family, state, err)
				}
				if !reflect.DeepEqual(before, programQueueTree(t, root)) {
					t.Fatal("native build preflight changed original controls")
				}
			})
		}
	}
}

func TestProgramUpgradeQueuesNativeControlsNeverTruncateCompleteInventory(t *testing.T) {
	root := programQueueFixture(t)
	for i := 0; i < 65; i++ {
		id := core.ID()
		control := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
		writeProgramQueueFixture(t, root, "var/lib/panel-executor/waf-engine-requests", id, control)
		writeProgramQueueFixture(t, root, "var/lib/panel-executor/waf-engine-cancellations", id, control)
		if i == 63 {
			if err := checkProgramUpgradeQueues(context.Background(), root); err != nil {
				t.Fatal("all 64 legitimate cancelled requests must be read", err)
			}
		}
	}
	before := programQueueTree(t, root)
	if checkProgramUpgradeQueues(context.Background(), root) == nil {
		t.Fatal("65th request silently omitted")
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("excess inventory changed retained controls")
	}
}

func TestProgramUpgradeQueuesRuleFeedStreamingHonorsOriginalEnvelopeLimitAndDeadline(t *testing.T) {
	root := programQueueFixture(t)
	id := core.ID()
	relative := "var/lib/panel-executor/network-rule-feed-jobs/" + id
	selection := programQueueRuleFeedSelection()
	// The opaque fixture exercises the original full-size delivery contract,
	// not cryptographic threat-data verification or feed activation.
	envelope := []byte(strings.Repeat("x", 16<<20))
	request := threatIDSRuleFeedRequest{Format: 1, JobID: id, Selection: selection, EnvelopeSHA: core.Hash(string(envelope))}
	writeProgramQueueFixture(t, root, relative, "request", request)
	file := filepath.Join(root, relative, "envelope.json")
	if err := os.WriteFile(file, envelope, 0600); err != nil {
		t.Fatal(err)
	}
	writeProgramQueueFixture(t, root, relative, "result", core.NetworkIDSRuleFeedStatus{JobID: id, State: "ready-data", Selection: selection, DataOnly: true})
	before := programQueueTree(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := checkProgramUpgradeQueues(ctx, root); err != nil {
		t.Fatal("full original envelope delivery must not be truncated", err)
	}
	t.Logf("complete original 16 MiB envelope streaming: %s (5s original preflight deadline)", time.Since(start))
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("streaming edited original request or delivery")
	}
	expired, expire := context.WithCancel(context.Background())
	expire()
	if checkProgramUpgradeQueues(expired, root) == nil {
		t.Fatal("cancelled deadline ignored")
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := f.Write([]byte("x"))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(writeErr, closeErr)
	}
	if checkProgramUpgradeQueues(context.Background(), root) == nil {
		t.Fatal("oversized envelope accepted")
	}
}
func TestProgramUpgradeQueuesCancellationDoesNotHideStillBuildingRecord(t *testing.T) {
	root := programQueueFixture(t)
	id := core.ID()
	base := "var/lib/panel-executor/apache-body"
	control := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
	writeProgramQueueFixture(t, root, base+"-requests", id, control)
	writeProgramQueueFixture(t, root, base+"-cancellations", id, control)
	writeProgramQueueFixture(t, root, base+"-builds", id, apacheBodyBuildRecord{Format: 1, JobID: id, State: "building", Architecture: runtime.GOARCH, Prefix: filepath.Join(apacheBodyEngines, id), StartedAt: core.Now()})
	if checkProgramUpgradeQueues(context.Background(), root) == nil {
		t.Fatal("cancellation incorrectly proved actual build stop")
	}
}
func TestProgramUpgradeQueuesBuildControlCorruptionIsNeverIgnored(t *testing.T) {
	for _, kind := range []string{"duplicate", "unknown", "wrong-id", "invalid-time", "public", "linked", "unfinished-stage"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			id := core.ID()
			relative := "var/lib/panel-executor/waf-engine-requests"
			v := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
			if kind == "wrong-id" {
				v.JobID = core.ID()
			}
			if kind == "invalid-time" {
				v.CreatedAt = "unknown"
			}
			p := writeProgramQueueFixture(t, root, relative, id, v)
			raw, _ := os.ReadFile(p)
			switch kind {
			case "duplicate":
				if err := os.WriteFile(p, bytesAppendObject(raw, `"format":1`), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(p, bytesAppendObject(raw, `"unknown":true`), 0600); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(p, 0644); err != nil {
					t.Fatal(err)
				}
			case "linked":
				if err := os.Link(p, filepath.Join(root, "own-alias")); err != nil {
					t.Fatal(err)
				}
			case "unfinished-stage":
				if err := os.Rename(p, filepath.Join(filepath.Dir(p), ".panel-write-own-stage")); err != nil {
					t.Fatal(err)
				}
			}
			if checkProgramUpgradeQueues(context.Background(), root) == nil {
				t.Fatal("unsafe control ignored")
			}
		})
	}
}
func programQueueRuleFeedSelection() core.NetworkIDSRuleFeedSelection {
	return core.NetworkIDSRuleFeedSelection{FeedID: "et-open-web-20260929", AppVersion: "1.0.0", AppManifestSHA: strings.Repeat("a", 64), RuleManifestSHA: strings.Repeat("b", 64)}
}
func TestProgramUpgradeQueuesRuleFeedIncompleteRequestsNeverLookTerminal(t *testing.T) {
	root := programQueueFixture(t)
	id := core.ID()
	relative := "var/lib/panel-executor/network-rule-feed-jobs/" + id
	if err := os.MkdirAll(filepath.Join(root, relative), 0700); err != nil {
		t.Fatal(err)
	}
	if checkProgramUpgradeQueues(context.Background(), root) == nil {
		t.Fatal("empty published rule feed job treated as complete")
	}
	if err := os.Rename(filepath.Join(root, relative), filepath.Join(root, "var/lib/panel-executor/network-rule-feed-jobs/.request-"+id)); err != nil {
		t.Fatal(err)
	}
	if checkProgramUpgradeQueues(context.Background(), root) == nil {
		t.Fatal("unpublished rule feed stage ignored")
	}
}

func TestProgramUpgradeQueuesRuleFeedTerminalBindingsAndHeldLockAreIndependent(t *testing.T) {
	for _, kind := range []string{"ready-data", "failed", "queued", "running", "needs-attention", "missing-result", "changed-envelope", "changed-selection", "capture-claimed", "held-lock", "nonempty-lock", "unknown-file"} {
		t.Run(kind, func(t *testing.T) {
			root := programQueueFixture(t)
			id := core.ID()
			relative := "var/lib/panel-executor/network-rule-feed-jobs/" + id
			selection := programQueueRuleFeedSelection()
			envelope := []byte("own opaque fixture envelope: drain test only, not signed threat data")
			request := threatIDSRuleFeedRequest{Format: 1, JobID: id, Selection: selection, EnvelopeSHA: core.Hash(string(envelope))}
			writeProgramQueueFixture(t, root, relative, "request", request)
			base := filepath.Join(root, relative)
			if err := os.WriteFile(filepath.Join(base, "envelope.json"), envelope, 0600); err != nil {
				t.Fatal(err)
			}
			status := core.NetworkIDSRuleFeedStatus{JobID: id, State: "ready-data", Selection: selection, DataOnly: true}
			if kind == "failed" {
				status.State = "failed"
				status.Error = "own retained error"
			}
			if kind == "queued" || kind == "running" || kind == "needs-attention" {
				status.State = kind
			}
			if kind == "changed-selection" {
				status.Selection.AppManifestSHA = strings.Repeat("c", 64)
			}
			if kind == "capture-claimed" {
				status.CaptureStarted = true
			}
			if kind != "missing-result" {
				writeProgramQueueFixture(t, root, relative, "result", status)
			}
			if kind == "changed-envelope" {
				if err := os.WriteFile(filepath.Join(base, "envelope.json"), []byte("changed own data"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "unknown-file" {
				if err := os.WriteFile(filepath.Join(base, "unknown.txt"), []byte("own"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(base, "install.lock"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "nonempty-lock" {
				if err := os.WriteFile(filepath.Join(base, "install.lock"), []byte("own"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "held-lock" {
				lock, err := os.OpenFile(filepath.Join(base, "install.lock"), os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, root)
			err := checkProgramUpgradeQueues(context.Background(), root)
			if (err != nil) != (kind != "ready-data" && kind != "failed") {
				t.Fatal(kind, err)
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("rule feed preflight edited lock, request or terminal data")
			}
		})
	}
}
