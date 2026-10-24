//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func memcachedUnixControlJournalFixture(t *testing.T) (memcachedUnixControlJournalStore, memcachedUnixControlSeed) {
	t.Helper()
	old, _, first := memcachedUnixJournalFixture(t)
	op := core.MemcachedUnixControlOperation{Format: 1, RequestID: first.Operation.JobID, ProjectID: first.Operation.ProjectID, ActorID: first.Operation.ActorID, Input: core.MemcachedUnixControlInput{Action: "stop", ExpectedRuntimeSHA256: strings.Repeat("a", 64), AcknowledgeCacheLoss: true}}
	return memcachedUnixControlJournalStore{base: filepath.Join(filepath.Dir(old.base), "controls")}, memcachedUnixControlSeed{Format: 1, Operation: op, InstalledRecordSHA256: strings.Repeat("b", 64)}
}
func TestMemcachedUnixControlJournalOriginalLeaseAndImmutableOutcomeNeverReplay(t *testing.T) {
	store, seed := memcachedUnixControlJournalFixture(t)
	j, fresh, err := store.prepare(seed)
	if err != nil || !fresh {
		t.Fatal("new private control", err)
	}
	defer j.Close()
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := j.lease(); err == nil {
		t.Fatal("second worker acquired original run")
	}
	seedRaw, _ := json.Marshal(seed)
	issued := memcachedUnixControlIssued{Format: 1, SeedSHA256: core.Hash(string(seedRaw)), ContainerID: strings.Repeat("c", 64), InitialPID: 789, InitialStartedAt: "2026-10-24T00:00:00Z"}
	if err := lease.issued(issued); err != nil {
		t.Fatal(err)
	}
	if lease.issued(issued) == nil {
		t.Fatal("daemon intent reissued")
	}
	unknown := memcachedUnixControlBaseResult(seed.Operation, "unknown")
	if err := lease.finish(unknown); err != nil {
		t.Fatal(err)
	}
	if lease.finish(unknown) == nil {
		t.Fatal("terminal evidence overwritten")
	}
	before, err := j.inventory()
	if err != nil {
		t.Fatal(err)
	}
	replay, again, err := store.prepare(seed)
	if err != nil || again {
		t.Fatal("original unknown replayed", err)
	}
	replay.Close()
	changed := seed
	changed.Operation.Input.Action = "restart"
	if _, _, err := store.prepare(changed); err == nil {
		t.Fatal("original request rebound")
	}
	another := seed
	another.Operation.RequestID = strings.Repeat("d", 32)
	if _, _, err := store.prepare(another); err == nil {
		t.Fatal("new ID bypassed original unknown")
	}
	after, err := j.inventory()
	if err != nil || len(after) != len(before) {
		t.Fatal(err)
	}
	for n, info := range before {
		if !geoStoreStableInfo(info, after[n]) {
			t.Fatal("old transaction changed", n)
		}
	}
	if store.checkTransactions(context.Background(), nil) == nil {
		t.Fatal("unsigned/unknown transaction inferred quiescent")
	}
}
func TestMemcachedUnixControlJournalPartialForeignOrPublicEvidenceIsNotRepaired(t *testing.T) {
	for _, kind := range []string{"partial", "extra", "hardlink", "public", "run-replaced", "result-before-intent", "unsigned-terminal"} {
		t.Run(kind, func(t *testing.T) {
			store, seed := memcachedUnixControlJournalFixture(t)
			j, fresh, err := store.prepare(seed)
			if err != nil || !fresh {
				t.Fatal(err)
			}
			defer j.Close()
			dir := filepath.Join(store.base, seed.Operation.RequestID)
			switch kind {
			case "partial":
				os.Remove(filepath.Join(dir, "run.lock"))
			case "extra":
				os.WriteFile(filepath.Join(dir, "recovery.json"), []byte("{}"), 0600)
			case "hardlink":
				os.Link(filepath.Join(dir, "operation.json"), filepath.Join(filepath.Dir(store.base), "foreign-record"))
			case "public":
				os.Chmod(filepath.Join(dir, "operation.json"), 0640)
			case "run-replaced":
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				os.Rename(filepath.Join(dir, "run.lock"), filepath.Join(dir, "old-run"))
				os.WriteFile(filepath.Join(dir, "run.lock"), nil, 0600)
				if lease.current() {
					t.Fatal("replacement run adopted")
				}
			case "result-before-intent":
				raw, _ := json.Marshal(core.MemcachedUnixControlResult{Format: 1, RequestID: seed.Operation.RequestID, ProjectID: seed.Operation.ProjectID, OperationSHA256: core.MemcachedUnixControlSHA(seed.Operation), State: "completed", FinalState: "stopped", RuntimeSHA256: strings.Repeat("f", 64)})
				os.WriteFile(filepath.Join(dir, "result.json"), raw, 0600)
			case "unsigned-terminal":
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				if lease.finish(memcachedUnixControlBaseResult(seed.Operation, "refused")) != nil {
					t.Fatal("refused framing")
				}
				lease.Close()
				if store.checkTransactions(context.Background(), nil) == nil {
					t.Fatal("terminal-looking record borrowed signing authority")
				}
				return
			}
			if _, err := j.read(); err == nil {
				t.Fatal("foreign partial file accepted", kind)
			}
			if _, _, err := store.prepare(seed); err == nil {
				t.Fatal("foreign/partial original adopted", kind)
			}
		})
	}
	if (&memcachedUnixControlRun{}).current(context.Background()) == nil {
		t.Fatal("empty run capability skipped native census")
	}
}
func TestMemcachedUnixControlAdmissionCannotBorrowActorOrNativeFields(t *testing.T) {
	project, request, actor := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	op := core.MemcachedUnixControlOperation{Format: 1, RequestID: request, ProjectID: project, ActorID: actor, Input: core.MemcachedUnixControlInput{Action: "stop", ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeCacheLoss: true}}
	raw, _ := json.Marshal(op)
	for _, kind := range []string{"unsigned", "query", "foreign-project", "foreign-request"} {
		t.Run(kind, func(t *testing.T) {
			path := "/v1/memcached-unix/projects/" + project + "/controls/" + request
			want := 400
			body := append([]byte(nil), raw...)
			switch kind {
			case "unsigned":
				want = 409
			case "query":
				path += "?retry=true"
				want = 404
			case "foreign-project":
				op2 := op
				op2.ProjectID = strings.Repeat("e", 32)
				body, _ = json.Marshal(op2)
			case "foreign-request":
				op2 := op
				op2.RequestID = strings.Repeat("e", 32)
				body, _ = json.Marshal(op2)
			}
			before, be := os.Lstat(memcachedUnixControlsRoot)
			mux := http.NewServeMux()
			New(Config{}).memcachedUnixControlRoutes(mux)
			out := httptest.NewRecorder()
			mux.ServeHTTP(out, httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(body))))
			after, ae := os.Lstat(memcachedUnixControlsRoot)
			if out.Code != want || os.IsNotExist(be) != os.IsNotExist(ae) || be == nil && (ae != nil || !geoStoreStableInfo(before, after)) {
				t.Fatal("unbound control changed original namespace", kind, out.Code, out.Body.String())
			}
		})
	}
	if _, err := runMemcachedUnixControl(nil, op); err == nil {
		t.Fatal("nil context")
	}
}
