//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFBodySelectedExportIndependentOfOtherUnknownSnapshots(t *testing.T) {
	s, current, data := wafBodyLogFixture(t)
	complete, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, data, 0640); err != nil {
		t.Fatal(err)
	}
	pending, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(stage string) error {
		if stage == "snapshot-created" {
			return errors.New("owned incomplete snapshot")
		}
		return nil
	})
	if err == nil {
		t.Fatal("private cut not reached")
	}
	before, _ := os.ReadFile(current)
	request := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives/"+id, nil))
		return w
	}
	w := request(complete.ID)
	var out struct {
		Archive  wafBodyLogArchive `json:"archive"`
		Verified bool              `json:"selected_snapshot_digest_verified"`
		Complete bool              `json:"inventory_not_claimed_complete"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Archive != complete || !out.Verified || !out.Complete {
		t.Fatal("individually verified snapshot blocked by another pending copy", w.Code, w.Body.String())
	}
	if w := request(pending.ID); w.Code != 503 || !strings.Contains(w.Body.String(), "复制未确认") {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(current)
	if string(before) != string(after) {
		t.Fatal("read-only export changed live data")
	}
	index, _, _ := s.readWAFBodyLogIndex(pending.ID)
	if index.State != "copying" {
		t.Fatal("export resolved unknown copying outcome")
	}
	path := filepath.Join(s.wafBodyLogArchiveDirectory(), complete.ID+".log")
	if err := os.WriteFile(path, []byte("corrupted snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request(complete.ID); w.Code != 503 {
		t.Fatal("wrong digest exported", w.Code)
	}
}

func TestWAFBodySelectedRemovingExportPreservesUncertainState(t *testing.T) {
	s, current, _ := wafBodyLogFixture(t)
	entry, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.removeWAFBodyLogArchiveAt(context.Background(), entry.ID, entry.SHA256, func(stage string) error {
		if stage == "remove-intent-durable" {
			return errors.New("owned uncertain deletion")
		}
		return nil
	}); err == nil {
		t.Fatal("private delete cut not reached")
	}
	index, indexSHA, err := s.readWAFBodyLogIndex(entry.ID)
	if err != nil || index.State != "removing" {
		t.Fatal(index, err)
	}
	before, _ := os.ReadFile(current)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives/"+entry.ID, nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"removing"`) || !strings.Contains(w.Body.String(), `"selected_snapshot_digest_verified":true`) {
		t.Fatal("uncertain copy not exportable without mutation", w.Code, w.Body.String())
	}
	actual, sha, err := s.readWAFBodyLogIndex(entry.ID)
	after, _ := os.ReadFile(current)
	if err != nil || actual != index || sha != indexSHA || string(before) != string(after) {
		t.Fatal("export changed uncertain state or live log")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.exportWAFBodyLogArchive(ctx, index, indexSHA); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
