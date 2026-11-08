//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func memcachedJournalFixture(t *testing.T) (memcachedUpdateJournalStore, memcachedUpdateJournalSeed) {
	t.Helper()
	base, id := memcachedPlanFileFixture(t)
	m, _, _ := memcachedInspectionFixture(t)
	if m.ID != id {
		t.Fatal("owned synthetic fixture identity changed")
	}
	metadata, _ := json.Marshal(m)
	source := []byte("services:\n  memcached:\n    image: memcached:1.6.45-alpine\n    restart: unless-stopped\n    command: [\"memcached\", \"-m\", \"128\", \"-I\", \"4m\"]\n    ports:\n      - \"127.0.0.1:21212:11211\"\n    healthcheck:\n      test: [\"CMD-SHELL\", " + strconv.Quote(core.MemcachedHealthCommand) + "]\n      interval: 10s\n      timeout: 3s\n      retries: 12\n")
	if core.Hash(string(source)) != "297589552b027e123ab1c309c89fa9a53e37ca0446c509ca344171563e4abb6d" {
		t.Fatal("synthetic backup diverged from original reviewed old template")
	}
	plan, err := core.MemcachedComposeUpdatePlan(id, core.Hash(string(metadata)), source, m.HostPort, strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	target, err := core.MemcachedComposeUpdateTarget(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately unsigned material. Journal framing MUST NOT turn it into
	// signing authority, and the independent public verifier must refuse it.
	envelope := appcatalog.MemcachedReleaseEnvelope{Catalog: []byte("{}"), Signature: []byte("not-an-official-signature"), AppManifest: []byte("{}")}
	raw, _ := json.Marshal(envelope)
	dispatch := core.MemcachedUpdateDispatch{Format: 1, JobID: strings.Repeat("1", 32), RequestID: strings.Repeat("2", 32), ActorID: strings.Repeat("3", 32), AccessRevision: "1", ProjectID: id, Input: core.MemcachedUpdateInput{ExpectedVersion: appcatalog.MemcachedDigestVersion, ExpectedSHA256: core.Hash("{}"), ExpectedProjectSHA256: plan.ProjectSHA256, AcknowledgeCacheLoss: true}}
	record, err := core.SealMemcachedUpdateRecord(core.MemcachedUpdateRecord{Format: 1, Dispatch: dispatch, DispatchSHA256: core.MemcachedUpdateDispatchSHA(dispatch), Plan: plan, EnvelopeSHA256: core.Hash(string(raw)), CatalogSHA256: core.Hash("{}"), TargetComposeSHA256: core.Hash(string(target)), Phase: "prepared"})
	if err != nil {
		t.Fatal(err)
	}
	return memcachedUpdateJournalStore{base: filepath.Join(filepath.Dir(base), "journals")}, memcachedUpdateJournalSeed{record, raw, source, metadata}
}

func memcachedJournalPrepare(t *testing.T, store memcachedUpdateJournalStore, seed memcachedUpdateJournalSeed) *memcachedUpdateJournal {
	t.Helper()
	first, fresh, err := store.prepare(seed)
	if err != nil || !fresh || first != seed.Record {
		t.Fatal("evidence-only fixture prepare", err)
	}
	j, err := store.open(seed.Record.Dispatch.JobID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	return j
}

func memcachedJournalNext(t *testing.T, before core.MemcachedUpdateRecord, phase string) core.MemcachedUpdateRecord {
	t.Helper()
	after := before
	after.Sequence++
	after.PreviousSHA256 = before.RecordSHA256
	after.Phase = phase
	if phase == "image_verified" {
		after.TargetImageID = "sha256:" + strings.Repeat("7", 64)
	}
	if phase == "applied" {
		after.Observation = core.MemcachedUpdateObservation{ContainerID: strings.Repeat("8", 64), ImageID: after.TargetImageID, ComposeSHA256: after.TargetComposeSHA256, RuntimeConfigSHA256: strings.Repeat("9", 64), Health: "healthy"}
	}
	if phase == "failed_safe" {
		after.Reason = "precondition_changed"
	}
	sealed, err := core.SealMemcachedUpdateRecord(after)
	if err != nil {
		t.Fatal("synthetic transition fixture", err)
	}
	return sealed
}

func TestMemcachedJournalPrivateDurableOriginalAndAuthorityNeverConflated(t *testing.T) {
	store, seed := memcachedJournalFixture(t)
	j := memcachedJournalPrepare(t, store, seed)
	before, err := j.inventory()
	if err != nil {
		t.Fatal(err)
	}
	if a, err := j.officialAuthority(context.Background()); err == nil || a.Matches(seed.Record.Dispatch.Input.ExpectedVersion, seed.Record.Dispatch.Input.ExpectedSHA256) {
		t.Fatal("private journal hash framing forged official signing authority")
	}
	chain, err := j.readChain()
	if err != nil || len(chain) != 1 || chain[0] != seed.Record {
		t.Fatal("read-only complete original chain", err)
	}
	if _, err := j.snapshot(context.Background()); err == nil {
		t.Fatal("snapshot exposed unsigned framed data as official original progress")
	}
	prior, fresh, err := store.prepare(seed)
	if err != nil || fresh || prior != seed.Record {
		t.Fatal("exact evidence replay overwrote or recreated original", err)
	}
	after, err := j.inventory()
	if err != nil || len(before) != len(after) {
		t.Fatal(err)
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			t.Fatal("readonly authority refusal or replay changed original evidence", name)
		}
	}
	changed := seed
	changed.Record.Dispatch.ActorID = strings.Repeat("f", 32)
	changed.Record.DispatchSHA256 = core.MemcachedUpdateDispatchSHA(changed.Record.Dispatch)
	changed.Record, err = core.SealMemcachedUpdateRecord(changed.Record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.prepare(changed); err == nil {
		t.Fatal("original job adopted another actor")
	}
}

func TestMemcachedJournalOriginalLeaseContiguousEventsAndTerminalNoReplay(t *testing.T) {
	store, seed := memcachedJournalFixture(t)
	j := memcachedJournalPrepare(t, store, seed)
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if other, err := j.lease(); err == nil {
		other.Close()
		t.Fatal("same original transaction acquired two execution leases")
	}
	current := seed.Record
	for _, phase := range []string{"pull_started", "image_verified", "apply_started", "applied", "committed"} {
		next := memcachedJournalNext(t, current, phase)
		if err := lease.append(next); err != nil {
			t.Fatal(phase, err)
		}
		current = next
	}
	prior, fresh, err := store.prepare(seed)
	if err != nil || fresh || prior != current || prior.Phase != "committed" {
		t.Fatal("evidence replay concealed original completed chain", err)
	}
	next := current
	if err := lease.append(next); err == nil {
		t.Fatal("terminal journal extended or rewritten")
	}
	lease.Close()
	if err := lease.append(next); err == nil {
		t.Fatal("closed original lease adopted")
	}
}

func TestMemcachedJournalUnknownAppendObservesSameEventWithoutRetry(t *testing.T) {
	store, seed := memcachedJournalFixture(t)
	j := memcachedJournalPrepare(t, store, seed)
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	j.fault = func(point string) error { return errors.New("synthetic lost response after event file sync") }
	next := memcachedJournalNext(t, seed.Record, "pull_started")
	if err := lease.append(next); err == nil {
		t.Fatal("injected uncertainty not preserved")
	}
	actual, err := j.read()
	if err != nil || actual != next {
		t.Fatal("same original fully-written event was not observable", err)
	}
	j.fault = nil
	if err := lease.append(next); err == nil {
		t.Fatal("unknown append replayed as a new event")
	}
	prior, fresh, err := store.prepare(seed)
	if err != nil || fresh || prior != next {
		t.Fatal("unknown result replaced by fresh request", err)
	}
	changed := seed
	changed.Record.Dispatch.JobID, changed.Record.Dispatch.RequestID = strings.Repeat("a", 32), strings.Repeat("b", 32)
	changed.Record.DispatchSHA256 = core.MemcachedUpdateDispatchSHA(changed.Record.Dispatch)
	changed.Record, err = core.SealMemcachedUpdateRecord(changed.Record)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.prepare(changed); err == nil {
		t.Fatal("uncertain same project retried by switching job/key")
	}
}

func TestMemcachedJournalUnsafeMembersAndDetachedAncestryNeverRepaired(t *testing.T) {
	for _, scenario := range []string{"public-job", "public-file", "foreign-owner", "file-symlink", "hardlink", "fifo", "detached-base", "detached-job", "empty-event", "truncated-event", "event-gap", "event-hash", "extra-member", "changed-compose", "changed-metadata", "changed-envelope", "replaced-lock"} {
		t.Run(scenario, func(t *testing.T) {
			store, seed := memcachedJournalFixture(t)
			j := memcachedJournalPrepare(t, store, seed)
			job := filepath.Join(store.base, seed.Record.Dispatch.JobID)
			file := filepath.Join(job, "event-0000.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch scenario {
			case "public-job":
				must(os.Chmod(job, 0755))
			case "public-file":
				must(os.Chmod(file, 0644))
			case "foreign-owner":
				must(os.Chown(file, 65534, 65534))
			case "file-symlink":
				must(os.Rename(file, file+".original"))
				must(os.Symlink("event-0000.json.original", file))
			case "hardlink":
				must(os.Link(file, file+".other"))
			case "fifo":
				must(os.Remove(file))
				must(unix.Mkfifo(file, 0600))
			case "detached-base":
				must(os.Rename(store.base, store.base+".old"))
				must(os.Mkdir(store.base, 0700))
			case "detached-job":
				must(os.Rename(job, job+".old"))
				must(os.Mkdir(job, 0700))
			case "empty-event":
				must(os.Truncate(file, 0))
			case "truncated-event":
				must(os.Truncate(file, 100))
			case "event-gap":
				must(os.Rename(file, filepath.Join(job, "event-0001.json")))
			case "event-hash":
				bad := seed.Record
				bad.RecordSHA256 = strings.Repeat("0", 64)
				raw, _ := json.Marshal(bad)
				must(os.WriteFile(file, raw, 0600))
			case "extra-member":
				must(os.WriteFile(filepath.Join(job, "verified.json"), []byte(`{"verified":true}`), 0600))
			case "changed-compose":
				must(os.WriteFile(filepath.Join(job, "compose.original.yaml"), append(seed.OriginalCompose, ' '), 0600))
			case "changed-metadata":
				must(os.WriteFile(filepath.Join(job, "metadata.original.json"), append(seed.OriginalMetadata, ' '), 0600))
			case "changed-envelope":
				must(os.WriteFile(filepath.Join(job, "envelope.json"), append(seed.Envelope, ' '), 0600))
			case "replaced-lock":
				lease, err := j.lease()
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				p := filepath.Join(job, "run.lock")
				must(os.Rename(p, p+".old"))
				must(os.WriteFile(p, nil, 0600))
				if lease.current() || lease.append(memcachedJournalNext(t, seed.Record, "pull_started")) == nil {
					t.Fatal("detached original lease was adopted")
				}
			}
			if _, err := j.read(); err == nil {
				t.Fatal("unsafe or detached evidence adopted", scenario)
			}
			if scenario == "public-file" {
				info, _ := os.Stat(file)
				if info.Mode().Perm() != 0644 {
					t.Fatal("unsafe original permissions silently repaired")
				}
			}
		})
	}
}

func TestMemcachedJournalPartialPrepareNeverOverwritesOriginalEvidence(t *testing.T) {
	for _, point := range []string{"prepared-envelope.json", "prepared-compose.original.yaml", "prepared-metadata.original.json", "prepared-run.lock", "prepared-event-0000.json"} {
		t.Run(point, func(t *testing.T) {
			store, seed := memcachedJournalFixture(t)
			store.fault = func(name string) error {
				if name == point {
					return errors.New("synthetic preparation interruption")
				}
				return nil
			}
			if _, _, err := store.prepare(seed); err == nil {
				t.Fatal("prepare fault not injected")
			}
			store.fault = nil
			prior, fresh, err := store.prepare(seed)
			if point == "prepared-event-0000.json" {
				if err != nil || fresh || prior != seed.Record {
					t.Fatal("same complete original preparation not observed", err)
				}
			} else if err == nil || fresh {
				t.Fatal("incomplete original preparation was repaired, overwritten or retried")
			}
		})
	}
}
