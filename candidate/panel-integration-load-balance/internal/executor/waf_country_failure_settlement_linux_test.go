//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/panel/internal/core"
)

func TestCountryCachePublicationFailureSettlesWithoutFetchOrNewCommit(t *testing.T) {
	for _, point := range []string{"before-stage", "after-request.json", "before-file:CN", "after-file:CN", "before-publish", "after-publish"} {
		t.Run(point, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			f.store.fault = func(where string) error {
				if where == point {
					return errors.New("original interrupted outcome")
				}
				return nil
			}
			if _, err := f.publish(); err == nil {
				t.Fatal("fault was not reached")
			}
			calls := f.downloads
			original := map[string][]byte{}
			entries, _ := os.ReadDir(f.stage())
			for _, entry := range entries {
				b, err := os.ReadFile(filepath.Join(f.stage(), entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				original[entry.Name()] = b
			}
			state, committed, err := f.store.settlePublicationError(context.Background(), f.plan)
			if err != nil || f.downloads != calls {
				t.Fatal("settlement failed or fetched again", state, err, f.downloads, calls)
			}
			if point == "after-publish" {
				if state != "succeeded" || committed == nil || !committed.Published || committed.OriginalJobID != f.plan.JobID || committed.PlanSHA != f.digest() {
					t.Fatal("actual original commit not proved", state, committed)
				}
			} else {
				if state != "failed" || committed != nil {
					t.Fatal("uncommitted data was promoted", state, committed)
				}
				requireCountryCacheAbsent(t, f)
				for name, before := range original {
					after, err := os.ReadFile(filepath.Join(f.stage(), name))
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("settlement replaced partial evidence", name, err)
					}
				}
				if point != "before-stage" {
					raw, err := os.ReadFile(filepath.Join(f.stage(), "abort.json"))
					var stop countryCacheAborted
					if err != nil || countryCacheDecode(raw, &stop) != nil || stop.OriginalJobID != f.plan.JobID || stop.PlanSHA != f.digest() {
						t.Fatal("failed outcome lacks exact original abort", err)
					}
					if _, err := f.store.finalize(context.Background(), f.plan.JobID, f.digest()); err == nil {
						t.Fatal("aborted original was promoted")
					}
				}
			}
		})
	}
}

func TestCountryCacheFailureSettlementPreservesUncertaintyAndForeignOwnership(t *testing.T) {
	for _, kind := range []string{"canceled", "guard-revoked", "changed-plan", "foreign-published"} {
		t.Run(kind, func(t *testing.T) {
			f := newCountryCacheFixture(t)
			point := "after-file:CN"
			if kind == "foreign-published" {
				point = "after-publish"
			}
			f.store.fault = func(where string) error {
				if where == point {
					return errors.New("interrupted original")
				}
				return nil
			}
			if _, err := f.publish(); err == nil {
				t.Fatal("fault was not reached")
			}
			calls := f.downloads
			ctx := context.Background()
			plan := f.plan
			switch kind {
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "guard-revoked":
				f.store.guard = func() error { return errors.New("original current permission revoked") }
			case "changed-plan":
				plan.Countries = []string{"US"}
			case "foreign-published":
				plan.JobID = core.ID()
			}
			state, entry, err := f.store.settlePublicationError(ctx, plan)
			if err == nil || state != "needs_attention" || entry != nil || f.downloads != calls {
				t.Fatal("uncertainty/foreign work became success or replay", kind, state, entry, err)
			}
			if _, err := os.Lstat(filepath.Join(f.stage(), "abort.json")); !os.IsNotExist(err) {
				t.Fatal("uncertain operation changed original data", err)
			}
		})
	}
}
