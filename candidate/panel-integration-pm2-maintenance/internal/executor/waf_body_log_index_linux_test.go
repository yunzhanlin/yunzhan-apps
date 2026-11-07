//go:build linux

package executor

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFBodyLogIndexNineInterruptedWritesPreserveOriginalInodeWithoutAdoption(t *testing.T) {
	for _, phase := range []string{"intent", "prepared", "completed"} {
		for _, at := range []string{"index-stage-created", "index-stage-written", "index-stage-durable"} {
			cut := phase + "-" + at
			t.Run(cut, func(t *testing.T) {
				s, path, data := wafBodyLogFixture(t)
				_, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(stage string) error {
					if stage == cut {
						return errors.New("interrupted index write")
					}
					return nil
				})
				if err == nil {
					t.Fatal("cutpoint not reached")
				}
				fresh := New(s.Config)
				stages, err := fresh.wafBodyLogIndexStages(context.Background())
				if err != nil || len(stages) != 1 {
					t.Fatal(stages, err)
				}
				selected := stages[0]
				before, _ := os.ReadFile(path)
				if phase == "completed" {
					if len(before) != 0 {
						t.Fatal("expected prior durable truncate")
					}
				} else if string(before) != string(data) {
					t.Fatal("index failure discarded live data")
				}
				if _, err := fresh.snapshotAndTruncateWAFBodyLog(context.Background()); err == nil {
					t.Fatal("uncommitted index did not block another rotation")
				}
				if _, err := fresh.retainWAFBodyLogIndexStage(context.Background(), selected.ID, strings.Repeat("0", 64)); err == nil {
					t.Fatal("stale index digest accepted")
				}
				stagePath := filepath.Join(fresh.wafBodyLogIndexDirectory(), selected.ID+".json")
				original, err := os.Stat(stagePath)
				if err != nil {
					t.Fatal(err)
				}
				retained, err := fresh.retainWAFBodyLogIndexStage(context.Background(), selected.ID, selected.SHA256)
				if err != nil {
					t.Fatal(err)
				}
				moved := fresh.systemPath("/var/lib/panel-waf/retained-index-staging/" + retained + ".json")
				st, err := os.Stat(moved)
				if err != nil || !os.SameFile(original, st) {
					t.Fatal("original pending inode not preserved", err)
				}
				if _, err := os.Lstat(stagePath); !os.IsNotExist(err) {
					t.Fatal("pending index not moved", err)
				}
				stages, err = fresh.wafBodyLogIndexStages(context.Background())
				if err != nil || len(stages) != 0 {
					t.Fatal(stages, err)
				}
				if _, err := fresh.retainWAFBodyLogIndexStage(context.Background(), selected.ID, selected.SHA256); err == nil {
					t.Fatal("stale pending index action accepted")
				}
				pending, err := fresh.wafBodyLogRecoveryEntries(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if phase == "intent" {
					if len(pending) != 0 {
						t.Fatal("uncommitted first index adopted", pending)
					}
				} else {
					if len(pending) != 1 || pending[0].Archive.State == "completed" {
						t.Fatal("uncommitted index interpreted as successful", pending)
					}
					if err := fresh.retainWAFBodyLogSnapshot(context.Background(), pending[0]); err != nil {
						t.Fatal(err)
					}
				}
				after, _ := os.ReadFile(path)
				if string(after) != string(before) {
					t.Fatal("pending index recovery changed current log")
				}
			})
		}
	}
}

func TestWAFBodyLogIndexStagingPrivateClosedHTTPAndNoRepair(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	_, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(at string) error {
		if at == "intent-index-stage-created" {
			return errors.New("stop")
		}
		return nil
	})
	if err == nil {
		t.Fatal("no interruption")
	}
	stages, err := s.wafBodyLogIndexStages(context.Background())
	if err != nil || len(stages) != 1 {
		t.Fatal(stages, err)
	}
	x := stages[0]
	valid := `{"sha256":"` + x.SHA256 + `","acknowledge_uncommitted_index_not_applied":true}`
	request := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/software/nginx-waf/body-log/index-stages/"+x.ID+"/retain", strings.NewReader(body)))
		return w
	}
	for _, body := range []string{`{}`, strings.Replace(valid, "true", "false", 1), valid + ` {}`, strings.TrimSuffix(valid, "}") + `,"path":"/etc/passwd"}`} {
		if w := request(body); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"index_stages"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(valid); w.Code != 200 || !strings.Contains(w.Body.String(), `"never_applied_as_index":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("HTTP recovery changed current log")
	}
	os.Chmod(s.wafBodyLogIndexDirectory(), 0750)
	if _, err := s.wafBodyLogIndexStages(context.Background()); err == nil {
		t.Fatal("foreign private-directory permissions silently accepted")
	}
	if err := s.wafBodyLogPrivateDirectory(s.wafBodyLogIndexDirectory(), true); err == nil {
		t.Fatal("foreign private-directory permissions repaired")
	}
}

func TestWAFBodyLogRecoveryNeverMasksUnrelatedSnapshotCorruption(t *testing.T) {
	for _, kind := range []string{"missing", "digest", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			s, path, data := wafBodyLogFixture(t)
			good, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			os.WriteFile(path, data, 0640)
			_, err = s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(at string) error {
				if at == "snapshot-created" {
					return errors.New("copy interrupted")
				}
				return nil
			})
			if err == nil {
				t.Fatal("no interruption")
			}
			target := filepath.Join(s.wafBodyLogArchiveDirectory(), good.ID+".log")
			switch kind {
			case "missing":
				os.Remove(target)
			case "digest":
				os.WriteFile(target, []byte(strings.Repeat("x", len(data))), 0600)
			case "permissions":
				os.Chmod(target, 0644)
			}
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/software/nginx-waf/body-log/archives", nil))
			if w.Code != 503 {
				t.Fatal("unrelated abnormal archive hidden by recovery", w.Code, w.Body.String())
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(data) {
				t.Fatal("read changed live log")
			}
		})
	}
}
