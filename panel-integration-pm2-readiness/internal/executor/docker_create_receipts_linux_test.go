//go:build linux

package executor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"local/panel/internal/core"
)

func composeReceiptFixture(t *testing.T) (string, composeProjectRequest) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root, composeProjectRequest{JobID: core.ID(), ProjectID: core.ID(), Action: "create", Name: "receipt-fixture", TemplateID: "nginx-static", Compose: "services:\n  web:\n    image: nginx:1.30.6-alpine\n", RequestSHA: strings.Repeat("a", 64)}
}
func TestComposeCreateReceiptConcurrentClaimsNeverEnqueueTwice(t *testing.T) {
	root, op := composeReceiptFixture(t)
	var created atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := claimComposeCreate(root, op)
			if ok {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatal("exclusive receipt did not have exactly one creator", created.Load())
	}
	original, err := os.ReadFile(filepath.Join(root, op.JobID+".compose.intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := claimComposeCreate(root, op); ok || err != nil {
		t.Fatal("original replay did not return only original", ok, err)
	}
	for _, change := range []func(*composeProjectRequest){func(v *composeProjectRequest) { v.RequestSHA = strings.Repeat("b", 64) }, func(v *composeProjectRequest) { v.ProjectID = core.ID() }, func(v *composeProjectRequest) { v.Name = "changed" }} {
		v := op
		change(&v)
		if ok, err := claimComposeCreate(root, v); ok || err == nil {
			t.Fatal("changed original request accepted")
		}
	}
	after, _ := os.ReadFile(filepath.Join(root, op.JobID+".compose.intent.json"))
	if string(original) != string(after) {
		t.Fatal("immutable original receipt changed")
	}
}
func TestComposeCreateReceiptLookupIsReadOnlyAndNeverInventsQueueSuccess(t *testing.T) {
	root, op := composeReceiptFixture(t)
	if out, err := composeCreateStatus(root, op.JobID, func(string) (core.DockerJobResult, error) {
		t.Fatal("missing receipt reached result")
		return core.DockerJobResult{}, nil
	}); err != nil || out.Found {
		t.Fatal(out, err)
	}
	if ok, err := claimComposeCreate(root, op); !ok || err != nil {
		t.Fatal(ok, err)
	}
	name := filepath.Join(root, op.JobID+".compose.intent.json")
	original, _ := os.ReadFile(name)
	out, err := composeCreateStatus(root, op.JobID, func(string) (core.DockerJobResult, error) { return core.DockerJobResult{}, os.ErrNotExist })
	if err != nil || !out.Found || !out.Pending || out.Job != nil || out.JobID != op.JobID || out.Error == "" {
		t.Fatal("missing queue fabricated a result", out, err)
	}
	result := core.DockerJobResult{JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "succeeded"}
	out, err = composeCreateStatus(root, op.JobID, func(string) (core.DockerJobResult, error) { return result, nil })
	if err != nil || out.Job == nil || out.Job.State != "succeeded" || out.Pending {
		t.Fatal(out, err)
	}
	for _, v := range []core.DockerJobResult{{JobID: core.ID(), ProjectID: op.ProjectID, Kind: "compose", State: "succeeded"}, {JobID: op.JobID, ProjectID: core.ID(), Kind: "compose", State: "succeeded"}, {JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "unknown"}, {JobID: op.JobID, ProjectID: op.ProjectID, Kind: "compose", State: "succeeded", Error: "failure"}} {
		if _, err := composeCreateStatus(root, op.JobID, func(string) (core.DockerJobResult, error) { return v, nil }); err == nil {
			t.Fatal("foreign or impossible original result accepted")
		}
	}
	after, _ := os.ReadFile(name)
	if string(original) != string(after) {
		t.Fatal("GET rewrote original intent")
	}
}
func TestComposeCreateReceiptRefusesUnsafeOriginalsWithoutRepair(t *testing.T) {
	for _, kind := range []string{"partial", "duplicate-key", "unknown-field", "linked", "hardlinked", "writable", "directory", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			root, op := composeReceiptFixture(t)
			name := filepath.Join(root, op.JobID+".compose.intent.json")
			raw, _ := json.Marshal(composeCreateReceipt{1, op.JobID, op.ProjectID, op.RequestSHA, op.Name, op.TemplateID})
			switch kind {
			case "partial":
				raw = []byte("{")
			case "duplicate-key":
				raw = append([]byte(`{"format":1,`), raw[1:]...)
			case "unknown-field":
				raw = append([]byte(`{"foreign":1,`), raw[1:]...)
			case "oversized":
				raw = []byte(strings.Repeat("x", 4097))
			}
			switch kind {
			case "linked":
				target := filepath.Join(root, "original")
				if os.WriteFile(target, raw, 0600) != nil || os.Symlink(target, name) != nil {
					t.Fatal("fixture link")
				}
			case "directory":
				if os.Mkdir(name, 0700) != nil {
					t.Fatal("fixture directory")
				}
			default:
				if os.WriteFile(name, raw, 0600) != nil {
					t.Fatal("fixture file")
				}
				if kind == "hardlinked" {
					if os.Link(name, filepath.Join(root, "original")) != nil {
						t.Fatal("fixture hardlink")
					}
				}
				if kind == "writable" {
					if os.Chmod(name, 0660) != nil {
						t.Fatal("fixture mode")
					}
				}
			}
			before, err := os.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readComposeCreateReceipt(root, op.JobID); err == nil {
				t.Fatal("unsafe original read")
			}
			if ok, err := claimComposeCreate(root, op); ok || err == nil || errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe receipt repaired/replaced", ok, err)
			}
			after, _ := os.Lstat(name)
			if !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatal("original changed")
			}
		})
	}
}
