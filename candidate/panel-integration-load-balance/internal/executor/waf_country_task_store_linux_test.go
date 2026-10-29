//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

// Metadata models only. Deliberately NOT trusted application/data signatures.
// A valid seal is never software, admission, download or execution authority.
func countryTaskFixture(t *testing.T) (countryTaskStore, countryTaskRequest, []byte) {
	t.Helper()
	f := newCountryCacheFixture(t)
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	in := core.WAFCountryDataSelection{Action: "download", AppVersion: core.WAFCountryDataVersion, AppManifestSHA: core.Hash("test app"), InstallationSHA: core.Hash("test instance"), Release: "2026-10", Revision: 1, DataManifestSHA: core.Hash("test data"), Countries: []string{"CN", "US"}}
	raw, _ := json.Marshal(appcatalog.GeoDataEnvelope{AppCatalog: []byte("test-only catalog"), AppSignature: []byte("not an original signature"), AppManifest: []byte("test-only app"), DataManifest: []byte("test-only data"), DataSignature: []byte("not a data signature")})
	payload, _ := json.Marshal(in)
	request := countryTaskRequest{1, core.ID(), core.ID(), in, core.Hash(string(payload)), core.Hash(string(raw)), now.Format(time.RFC3339)}
	return countryTaskStore{base: filepath.Join(filepath.Dir(f.store.base), "tasks"), now: func() time.Time { return now }}, request, raw
}

func TestCountryTaskSealCompleteOriginalObservedWithoutRestartOrReplacement(t *testing.T) {
	s, request, raw := countryTaskFixture(t)
	ctx := context.Background()
	prepared, sha, fresh, err := s.prepare(ctx, request, raw)
	if err != nil || !fresh || !countryTaskSameBinding(prepared, request) || !wafLogDigestValid(sha) {
		t.Fatal(prepared, sha, fresh, err)
	}
	base, err := s.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	got, envelope, dir, err := s.read(base, request.JobID)
	if err != nil || !countryTaskSameBinding(got, request) || !bytes.Equal(raw, envelope) {
		t.Fatal(got, err)
	}
	defer dir.Close()
	before, err := dir.Lstat("request.json")
	if err != nil {
		t.Fatal(err)
	}
	request.PreparedAt = "2026-10-20T01:00:00Z"
	again, digest, fresh, err := s.prepare(ctx, request, raw)
	if err != nil || fresh || digest != sha || again.PreparedAt != prepared.PreparedAt {
		t.Fatal("observation overwrote original creation time or replayed", again, digest, fresh, err)
	}
	after, err := dir.Lstat("request.json")
	if err != nil || !geoStoreStableInfo(before, after) {
		t.Fatal("read-only original observation changed seal", err)
	}
	for _, name := range []string{"dispatch.json", "started.json", "result.json", "task.lock"} {
		if _, err := dir.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("metadata prepare granted dispatch/execution authority", name, err)
		}
	}
}

func TestCountryTaskSealEveryIncompleteOriginalRetainedWithoutPrepareReplay(t *testing.T) {
	for _, point := range []string{"before-prepare-request.json", "after-prepare-request.json", "after-prepare-envelope.json", "before-prepare-publish", "after-prepare-publish"} {
		t.Run(point, func(t *testing.T) {
			s, request, raw := countryTaskFixture(t)
			s.fault = func(p string) error {
				if p == point {
					return errors.New("synthetic metadata crash")
				}
				return nil
			}
			if _, _, _, err := s.prepare(context.Background(), request, raw); err == nil {
				t.Fatal("injected failure lost")
			}
			s.fault = nil
			_, _, fresh, err := s.prepare(context.Background(), request, raw)
			if point == "after-prepare-publish" {
				if err != nil || fresh {
					t.Fatal("complete original replayed", fresh, err)
				}
			} else {
				if err == nil || fresh {
					t.Fatal("partial metadata implicitly repaired/published", fresh, err)
				}
				if _, err := os.Lstat(filepath.Join(s.base, ".prepare-"+request.JobID)); err != nil {
					t.Fatal("original partial evidence removed", err)
				}
			}
		})
	}
}

func TestCountryTaskSealCannotAdoptAnotherActorPayloadEnvelopeOrDirectory(t *testing.T) {
	for _, kind := range []string{"actor", "selection", "envelope", "metadata", "linked"} {
		t.Run(kind, func(t *testing.T) {
			s, request, raw := countryTaskFixture(t)
			if _, _, _, err := s.prepare(context.Background(), request, raw); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "actor":
				request.ActorID = core.ID()
			case "selection":
				request.Selection.Countries = []string{"US"}
				p, _ := json.Marshal(request.Selection)
				request.PayloadSHA = core.Hash(string(p))
			case "envelope":
				var env appcatalog.GeoDataEnvelope
				json.Unmarshal(raw, &env)
				env.AppManifest = []byte("different test app bytes")
				raw, _ = json.Marshal(env)
				request.EnvelopeSHA = core.Hash(string(raw))
			case "metadata":
				file := filepath.Join(s.base, request.JobID, "request.json")
				original, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, bytes.Replace(original, []byte(`"job_id"`), []byte(`"Job_id"`), 1), 0600); err != nil {
					t.Fatal(err)
				}
			case "linked":
				path := filepath.Join(s.base, request.JobID)
				if err := os.Rename(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".retained", path); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, fresh, err := s.prepare(context.Background(), request, raw); err == nil || fresh {
				t.Fatal("foreign original adopted or replaced", fresh, err)
			}
		})
	}
}

func TestCountryTaskSealRejectsUnsafeQuotaAndCancelledContextWithoutRepair(t *testing.T) {
	for _, kind := range []string{"unknown-member", "quota", "public-root", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			s, request, raw := countryTaskFixture(t)
			base, err := s.open(true)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unknown-member":
				if err := base.Mkdir("unknown-task", 0700); err != nil {
					t.Fatal(err)
				}
			case "quota":
				for i := 0; i < countryTasksMax; i++ {
					if err := base.Mkdir(".prepare-"+core.ID(), 0700); err != nil {
						t.Fatal(err)
					}
				}
			case "public-root":
				if err := os.Chmod(s.base, 0755); err != nil {
					t.Fatal(err)
				}
			}
			base.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if _, _, fresh, err := s.prepare(ctx, request, raw); err == nil || fresh {
				t.Fatal("unsafe or cancelled metadata admitted", fresh, err)
			}
			if _, err := os.Lstat(filepath.Join(s.base, request.JobID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed preparation published original")
			}
			if kind == "public-root" {
				info, err := os.Lstat(s.base)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatal("unsafe permissions repaired", err)
				}
			}
		})
	}
}

func TestCountryTaskMetadataCannotBypassProductionFullAdmission(t *testing.T) {
	s, request, raw := countryTaskFixture(t)
	fixtureService := New(Config{SystemRoot: filepath.Dir(s.base), SecurityDir: filepath.Join(filepath.Dir(s.base), "security")})
	if _, _, fresh, err := fixtureService.prepareWAFCountryTask(context.Background(), request.JobID, request.ActorID, request.Selection, raw); err == nil || fresh {
		t.Fatal("metadata-only fixture became production admission", fresh, err)
	}
	for _, bad := range []countryTaskRequest{{}, {Format: 1, JobID: request.JobID, ActorID: request.ActorID, Selection: request.Selection, PayloadSHA: strings.Repeat("a", 64), EnvelopeSHA: request.EnvelopeSHA, PreparedAt: request.PreparedAt}} {
		if _, _, fresh, err := s.prepare(context.Background(), bad, raw); err == nil || fresh {
			t.Fatal("incomplete original task admitted", fresh, err)
		}
	}
}
