//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Synthetic, throwaway signed filesystem models. These do not claim provider
// publication, a production worker lifetime, or actual installed WAF traffic.
func countryCompletionFixture(t *testing.T, point string) (*countryCacheFixture, countryTaskRequest, *statisticsGeoDirectory, *statisticsGeoDirectory, *os.File) {
	t.Helper()
	f := newCountryCacheFixture(t)
	s, request, envelope := countryTaskFixture(t)
	f.plan.JobID = request.JobID
	request.Selection.DataManifestSHA = f.plan.DataManifestSHA
	payload, _ := json.Marshal(request.Selection)
	request.PayloadSHA = core.Hash(string(payload))
	if _, _, _, err := s.prepare(context.Background(), request, envelope); err != nil {
		t.Fatal(err)
	}
	base, err := s.open(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { base.Close() })
	_, _, dir, err := s.read(base, request.JobID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	if _, fresh, err := s.markDispatch(context.Background(), request, countryFixtureBoot); err != nil || !fresh {
		t.Fatal(fresh, err)
	}
	lock, err := countryTaskWorkerLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	if err := countryTaskPublishStarted(context.Background(), dir, lock, request, countryTaskSyntheticStarted(request)); err != nil {
		t.Fatal(err)
	}
	f.store.fault = func(where string) error {
		if where == point {
			return errors.New("original transfer interrupted")
		}
		return nil
	}
	if _, err := f.publish(); err == nil {
		t.Fatal("original interruption not reached")
	}
	return f, request, base, dir, lock
}

func TestCountryTaskCompletionAfterCancelledDownloadRetainsOriginalBytesAndAppendsTerminal(t *testing.T) {
	for _, kind := range []string{"cancelled", "expired", "already-committed", "owner-cancelled", "owner-cancelled-commit-won"} {
		t.Run(kind, func(t *testing.T) {
			point := "after-file:CN"
			if kind == "already-committed" || kind == "owner-cancelled-commit-won" {
				point = "after-publish"
			}
			f, request, base, dir, lock := countryCompletionFixture(t, point)
			before := map[string][]byte{}
			entries, _ := os.ReadDir(f.stage())
			for _, e := range entries {
				raw, err := os.ReadFile(filepath.Join(f.stage(), e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				before[e.Name()] = raw
			}
			original, stop := context.WithCancel(context.Background())
			if kind == "expired" {
				stop()
				original, stop = context.WithDeadline(context.Background(), time.Unix(1, 0))
			}
			stop()
			if original.Err() == nil {
				t.Fatal("download context remains live")
			}
			calls, checks := f.downloads, 0
			current := func(final context.Context) error {
				checks++
				deadline, ok := final.Deadline()
				if final.Err() != nil || !ok || time.Until(deadline) <= 0 || time.Until(deadline) > countryTaskCompletionTimeout {
					return errors.New("finalization is unbounded or inherits the cancelled context")
				}
				return nil
			}
			out := countryTaskOperation(request, "needs_attention", "original transfer interrupted")
			if kind == "owner-cancelled" || kind == "owner-cancelled-commit-won" {
				out.Error = core.WAFCountryDownloadCancelledMessage
			}
			result, err := completeCountryTask(original, base, dir, lock, request, out, &f.store, &f.plan, current)
			if err != nil || checks != 2 || f.downloads != calls || original.Err() == nil {
				t.Fatal("original finalization failed or fetched again", result, err, checks)
			}
			if kind == "already-committed" || kind == "owner-cancelled-commit-won" {
				if result.State != "succeeded" || result.Cache == nil || result.Cache.OriginalJobID != request.JobID || result.Error != "" {
					t.Fatal("lost original commit was not independently proved", result)
				}
			} else {
				if kind == "owner-cancelled" && result.Error != core.WAFCountryDownloadCancelledMessage {
					t.Fatal("complete cancelled transfer lost its original stop reason", result)
				}
				if result.State != "failed" || result.Cache != nil || result.Error == "" {
					t.Fatal("partial bytes became committed", result)
				}
				for name, raw := range before {
					after, err := os.ReadFile(filepath.Join(f.stage(), name))
					if err != nil || !bytes.Equal(raw, after) {
						t.Fatal("original evidence changed", name, err)
					}
				}
				if _, err := f.store.finalize(context.Background(), request.JobID, f.digest()); err == nil {
					t.Fatal("aborted original can publish")
				}
			}
			raw, err := geoStoreRead(dir.Root, "result.json", 32<<10)
			parsed, decodeErr := core.DecodeWAFCountryDataOperation(raw, request.JobID, request.ActorID, request.Selection)
			if err != nil || decodeErr != nil || parsed.State != result.State || parsed.RequestSHA != countryTaskRequestDigest(request) {
				t.Fatal("complete original terminal not durable", err, decodeErr)
			}
			if _, err := completeCountryTask(original, base, dir, lock, request, out, &f.store, &f.plan, current); err == nil {
				t.Fatal("original terminal was overwritten")
			}
		})
	}
}

func TestCountryTaskCompletionCannotUseNewContextToBypassRevocationOrAnotherRequest(t *testing.T) {
	for _, kind := range []string{"revoked-before-settlement", "revoked-before-result", "wrong-result-request", "wrong-plan", "missing-authority"} {
		t.Run(kind, func(t *testing.T) {
			f, request, base, dir, lock := countryCompletionFixture(t, "after-file:CN")
			original, cancel := context.WithCancel(context.Background())
			cancel()
			out := countryTaskOperation(request, "needs_attention", "original interrupted")
			plan := f.plan
			checks := 0
			guard := func(context.Context) error {
				checks++
				if kind == "revoked-before-settlement" || kind == "revoked-before-result" && checks == 2 {
					return errors.New("current authority revoked")
				}
				return nil
			}
			if kind == "wrong-result-request" {
				out.RequestSHA = core.Hash("foreign")
			}
			if kind == "wrong-plan" {
				plan.JobID = core.ID()
			}
			if kind == "missing-authority" {
				guard = nil
			}
			calls := f.downloads
			if _, err := completeCountryTask(original, base, dir, lock, request, out, &f.store, &plan, guard); err == nil {
				t.Fatal("revoked or foreign original was finalized")
			}
			if f.downloads != calls {
				t.Fatal("finalization performed a new download")
			}
			if _, err := dir.Lstat("result.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("uncertainty became a terminal", err)
			}
			if kind != "revoked-before-result" {
				if _, err := os.Lstat(filepath.Join(f.stage(), "abort.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused work mutated original staging", err)
				}
			}
		})
	}
}
