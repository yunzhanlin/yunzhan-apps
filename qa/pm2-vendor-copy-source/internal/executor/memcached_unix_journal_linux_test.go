//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func memcachedUnixJournalFixture(t *testing.T) (memcachedUnixJournalStore, []byte, core.MemcachedUnixInstallRecord) {
	t.Helper()
	anchor := os.Getenv("PANEL_MEMCACHED_UNIX_ACCOUNT_QA_ROOT")
	if os.Geteuid() != 0 || anchor == "" {
		t.Skip("explicit own Root filesystem QA anchor required")
	}
	if filepath.Clean(anchor) != anchor || !strings.HasPrefix(anchor, "/var/lib/panel-executor/memcached-unix-account-models") ||
		threatIDSTrustedParents(anchor, false) != nil || !strings.HasPrefix(os.TempDir(), anchor+"/") {
		t.Fatal("fixture may not leave its owned Root case")
	}
	project, job, actor := strings.Repeat("b", 32), strings.Repeat("a", 32), strings.Repeat("c", 32)
	compose, err := core.MemcachedUnixRequestCompose(project, "")
	if err != nil {
		t.Fatal(err)
	}
	op := core.DockerProjectRequest{JobID: job, ProjectID: project, Action: "create", Name: "own-unix-cache", Compose: compose, TemplateID: "memcached-cache", TemplateProfile: core.MemcachedUnixProfile, ActorID: actor}
	envelope := appcatalog.MemcachedUnixReleaseEnvelope{Catalog: []byte("own unsigned catalog"), Signature: []byte("own unsigned signature"), AppManifest: []byte("own unsigned manifest")}
	in, err := core.NewMemcachedUnixInstallSubmission(op, core.MemcachedUnixBinding{Version: appcatalog.MemcachedUnixVersion, ManifestSHA256: core.Hash(string(envelope.AppManifest))}, envelope)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	record, err := core.NewMemcachedUnixInstallRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	return memcachedUnixJournalStore{base: filepath.Join(t.TempDir(), "journals")}, raw, record
}
func memcachedUnixJournalPrepared(t *testing.T, store memcachedUnixJournalStore, raw []byte, first core.MemcachedUnixInstallRecord) *memcachedUnixJournal {
	t.Helper()
	actual, fresh, err := store.prepare(raw)
	if err != nil || !fresh || actual != first {
		t.Fatal("new private evidence persistence", err)
	}
	j, err := store.open(first.Operation.JobID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(j.Close)
	return j
}
func TestMemcachedUnixJournalInterruptedIntentStaysTerminalAndNeverReplays(t *testing.T) {
	store, raw, first := memcachedUnixJournalFixture(t)
	j := memcachedUnixJournalPrepared(t, store, raw, first)
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	intent := first
	intent.Sequence = 1
	intent.Phase = "account-intent"
	if err = lease.append(intent); err != nil {
		t.Fatal(err)
	}
	failed := intent
	failed.Sequence = 2
	failed.Phase = "needs-attention"
	failed.Fault = "interrupted"
	if err = lease.append(failed); err != nil {
		t.Fatal(err)
	}
	before, err := j.inventory()
	if err != nil {
		t.Fatal(err)
	}
	got, fresh, err := store.prepare(raw)
	if err != nil || fresh || got != failed {
		t.Fatal("interrupted intent became a new worker", err)
	}
	next := failed
	next.Sequence++
	if lease.append(next) == nil {
		t.Fatal("uncertain account intent resumed without separate authorized recovery")
	}
	after, err := j.inventory()
	if err != nil || len(before) != len(after) {
		t.Fatal(err)
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			t.Fatal("interrupted evidence overwritten", name)
		}
	}
}

func TestMemcachedUnixJournalMetadataAndSeparateCapacityAreClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Root private metadata model")
	}
	v := memcachedUnixNSSInfoFixture{mode: 0600, size: 128}
	v.stat.Nlink = 1
	if !memcachedUnixJournalFileInfo(v, 128, false) || memcachedUnixJournalFileInfo(v, 127, false) || memcachedUnixJournalFileInfo(nil, 128, false) {
		t.Fatal("file byte/type boundary lost")
	}
	for _, change := range []func(*memcachedUnixNSSInfoFixture){
		func(v *memcachedUnixNSSInfoFixture) { v.stat.Uid = 1 }, func(v *memcachedUnixNSSInfoFixture) { v.stat.Gid = 1 },
		func(v *memcachedUnixNSSInfoFixture) { v.stat.Nlink = 2 }, func(v *memcachedUnixNSSInfoFixture) { v.mode = 0640 },
		func(v *memcachedUnixNSSInfoFixture) { v.mode = os.ModeSymlink | 0600 }, func(v *memcachedUnixNSSInfoFixture) { v.size = -1 },
	} {
		got := v
		change(&got)
		if memcachedUnixJournalFileInfo(got, 128, false) {
			t.Fatal("foreign/public/linked/invalid record adopted")
		}
	}
	dir := v
	dir.mode = os.ModeDir | 0700
	if !memcachedUnixJournalRootInfo(dir) || memcachedUnixJournalRootInfo(v) || memcachedUnixJournalRootInfo(nil) {
		t.Fatal("private Root directory lost")
	}
	for _, name := range []string{"../event-0000.json", "event-0000.JSON", "event-0012.json", "event-0000.json.tmp", "store.lock", "auth.json", "envelope.json", "compose.original.yaml"} {
		if _, ok := memcachedUnixJournalLimit(name); ok {
			t.Fatal("foreign namespace/member admitted", name)
		}
	}
	if limit, ok := memcachedUnixJournalLimit("submission.json"); !ok || limit != core.MaxMemcachedUnixInstallSubmissionBytes {
		t.Fatal("independent closed capacity lost")
	}
}
func TestMemcachedUnixJournalOriginalReadAndExactReplayNeverForgeSigningAuthority(t *testing.T) {
	store, raw, first := memcachedUnixJournalFixture(t)
	j := memcachedUnixJournalPrepared(t, store, raw, first)
	before, err := j.inventory()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := j.readChain()
	if err != nil || len(chain) != 1 || chain[0] != first {
		t.Fatal("first original event", err)
	}
	if a, err := j.officialAuthority(context.Background()); err == nil || a.Matches(first.Binding.Version, first.Binding.ManifestSHA256) {
		t.Fatal("hash framing became official authority")
	}
	got, fresh, err := store.prepare(raw)
	if err != nil || fresh || got != first {
		t.Fatal("exact readback replay changed original evidence", err)
	}
	after, err := j.inventory()
	if err != nil || len(after) != len(before) {
		t.Fatal(err)
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			t.Fatal("read/replay changed original inode", name)
		}
	}
	in, err := core.DecodeMemcachedUnixInstallSubmission(raw)
	if err != nil {
		t.Fatal(err)
	}
	in.Operation.ActorID = strings.Repeat("d", 32)
	changed, _ := json.Marshal(in)
	if _, _, err := store.prepare(changed); err == nil {
		t.Fatal("same job borrowed a changed actor")
	}
	in.Operation.JobID = strings.Repeat("e", 32)
	changed, _ = json.Marshal(in)
	if _, _, err := store.prepare(changed); err == nil {
		t.Fatal("new job adopted the original project")
	}
	got, err = j.read()
	if err != nil || got != first {
		t.Fatal("rejected writes modified original", err)
	}
}
func TestMemcachedUnixJournalLeaseAppendsOnlyContiguousOriginalEventsAndNoRestart(t *testing.T) {
	store, raw, first := memcachedUnixJournalFixture(t)
	j := memcachedUnixJournalPrepared(t, store, raw, first)
	lease, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if second, err := j.lease(); err == nil {
		second.Close()
		t.Fatal("two workers acquired same run identity")
	}
	current := first
	for _, phase := range []string{"account-intent", "account-verified", "pull-intent", "image-verified", "project-intent", "project-written", "start-intent", "runtime-verified", "committed"} {
		next := current
		next.Sequence++
		next.Phase = phase
		switch phase {
		case "account-verified":
			next.UID, next.GID = 999, 998
		case "image-verified":
			next.ImageID = "sha256:" + strings.Repeat("d", 64)
		case "project-intent":
			next.ComposeSHA256 = strings.Repeat("e", 64)
		case "runtime-verified":
			next.ContainerID = strings.Repeat("f", 64)
		}
		if err := lease.append(next); err != nil {
			t.Fatal(phase, err)
		}
		current = next
	}
	got, err := j.read()
	if err != nil || got != current {
		t.Fatal(err)
	}
	replayed := current
	replayed.Sequence++
	if lease.append(replayed) == nil {
		t.Fatal("committed job was restarted")
	}
	got, fresh, err := store.prepare(raw)
	if err != nil || fresh || got != current {
		t.Fatal("committed replay lost original terminal state", err)
	}
	lease.Close()
	if lease.append(current) == nil {
		t.Fatal("closed original lease retained writer authority")
	}
}
func TestMemcachedUnixJournalRetainsPartialGapsUnknownFilesAndReplacedLocks(t *testing.T) {
	for _, scenario := range []string{"partial", "gap", "unknown", "public-file", "foreign-group", "hardlink", "fifo", "missing-submission", "replaced-lock", "detached-parent"} {
		t.Run(scenario, func(t *testing.T) {
			store, raw, first := memcachedUnixJournalFixture(t)
			j := memcachedUnixJournalPrepared(t, store, raw, first)
			path := filepath.Join(store.base, first.Operation.JobID)
			var lease *memcachedUnixJournalLease
			if scenario == "replaced-lock" {
				var err error
				lease, err = j.lease()
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
			}
			switch scenario {
			case "partial":
				os.WriteFile(filepath.Join(path, "event-0001.json"), []byte("{"), 0600)
			case "gap":
				next := first
				next.Sequence = 1
				next.Phase = "account-intent"
				body, _ := coreEncodeMemcachedUnixInstallRecord(next)
				os.WriteFile(filepath.Join(path, "event-0002.json"), body, 0600)
			case "unknown":
				os.WriteFile(filepath.Join(path, "unknown.json"), []byte("{}"), 0600)
			case "public-file":
				os.Chmod(filepath.Join(path, "submission.json"), 0644)
			case "foreign-group":
				os.Chown(filepath.Join(path, "submission.json"), 0, 65534)
			case "hardlink":
				if err := os.Link(filepath.Join(path, "submission.json"), filepath.Join(t.TempDir(), "linked")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(filepath.Join(path, "submission.json")); err != nil {
					t.Fatal(err)
				}
				if err := syscall.Mkfifo(filepath.Join(path, "submission.json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-submission":
				os.Remove(filepath.Join(path, "submission.json"))
			case "replaced-lock":
				if err := os.Rename(filepath.Join(path, "run.lock"), filepath.Join(t.TempDir(), "original.lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "run.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "detached-parent":
				retained := store.base + ".retained"
				if err := os.Rename(store.base, retained); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.RemoveAll(retained) })
				if err := os.Mkdir(store.base, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "replaced-lock" {
				if lease.current() {
					t.Fatal("replacement borrowed original held lock")
				}
				next := first
				next.Sequence = 1
				next.Phase = "account-intent"
				if lease.append(next) == nil {
					t.Fatal("detached writer acquired a replacement")
				}
			} else {
				if _, err := j.read(); err == nil {
					t.Fatal("partial/foreign evidence accepted", scenario)
				}
			}
			if scenario != "replaced-lock" && scenario != "detached-parent" {
				if _, _, err := store.prepare(raw); err == nil {
					t.Fatal("unknown original was recreated/repaired", scenario)
				}
			}
		})
	}
}
