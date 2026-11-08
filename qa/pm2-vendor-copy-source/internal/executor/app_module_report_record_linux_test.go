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
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func retrospectiveFixture(t *testing.T, name string) (*Service, string) {
	t.Helper()
	s, _ := moduleRecordFixture(t)
	path := filepath.Join(s.moduleDir("task-manager"), name)
	var value any = map[string]any{"time": core.Now(), "action": "run", "result": map[string]any{"private": "trusted-retrospective-sentinel"}}
	if name == "history.json" {
		value = []moduleEvent{{ID: core.ID(), Time: core.Now(), Action: "run", Trigger: "manual", Outcome: "succeeded"}}
	}
	if err := moduleWrite(path, value); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestModuleRetrospectiveKnownRecordsAndMissingDoNotRewrite(t *testing.T) {
	for _, name := range []string{"history.json", "last-report.json"} {
		s, path := retrospectiveFixture(t, name)
		before, _ := os.Lstat(path)
		raw, _ := os.ReadFile(path)
		var out any
		if err := s.moduleRetrospectiveRecord("task-manager", name, &out); err != nil || out == nil {
			t.Fatal(name, err)
		}
		after, _ := os.Lstat(path)
		current, _ := os.ReadFile(path)
		if !os.SameFile(before, after) || before.ModTime() != after.ModTime() || string(raw) != string(current) {
			t.Fatal("read rewrote evidence")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := s.moduleRetrospectiveRecord("task-manager", name, &out); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("known missing record is not absence", err)
		}
		if name == "history.json" {
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/app-modules/task-manager/history", nil))
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"read_only":true`) {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		if _, err := os.Lstat(filepath.Join(s.moduleDir("task-manager"), "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("read created ledger", err)
		}
	}
	// Scheduled failure reports legitimately include a bounded error field.
	s, path := retrospectiveFixture(t, "last-report.json")
	if err := moduleWrite(path, map[string]any{"time": core.Now(), "action": "scheduled-check", "result": nil, "error": "original bounded failure"}); err != nil {
		t.Fatal(err)
	}
	var out any
	if err := s.moduleRetrospectiveRecord("task-manager", "last-report.json", &out); err != nil {
		t.Fatal(err)
	}
}

func TestModuleRetrospectiveUntrustedReadKeepsEvidence(t *testing.T) {
	for _, name := range []string{"history.json", "last-report.json"} {
		for _, kind := range []string{"public-file", "group-write", "public-module", "writable-modules", "writable-anchor", "foreign-owner", "symlink-file", "symlink-module", "hardlink", "fifo", "directory", "oversize", "malformed", "duplicate", "escaped-duplicate", "case-duplicate", "nested-duplicate", "trailing", "wrong-root", "unknown-field", "missing-field", "deep"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				s, path := retrospectiveFixture(t, name)
				outside := filepath.Join(t.TempDir(), "own-sentinel.json")
				sentinel := []byte(`{"keep":"owned-original-not-a-report"}`)
				if err := os.WriteFile(outside, sentinel, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "foreign-owner" && os.Geteuid() != 0 {
					t.Skip("actual root foreign UID fixture required")
				}
				switch kind {
				case "public-file":
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				case "group-write":
					if err := os.Chmod(path, 0620); err != nil {
						t.Fatal(err)
					}
				case "public-module":
					if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
						t.Fatal(err)
					}
				case "writable-modules":
					if err := os.Chmod(filepath.Dir(filepath.Dir(path)), 0777); err != nil {
						t.Fatal(err)
					}
				case "writable-anchor":
					if err := os.Chmod(s.Config.SecurityDir, 0777); err != nil {
						t.Fatal(err)
					}
				case "foreign-owner":
					if err := os.Chown(path, 1, -1); err != nil {
						t.Fatal(err)
					}
				case "symlink-file":
					os.Remove(path)
					if err := os.Symlink(outside, path); err != nil {
						t.Fatal(err)
					}
				case "symlink-module":
					owned := filepath.Dir(path) + "-own-retained"
					if err := os.Rename(filepath.Dir(path), owned); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(owned, filepath.Dir(path)); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					if err := os.Link(path, filepath.Join(filepath.Dir(path), "own-second-link")); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					os.Remove(path)
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					os.Remove(path)
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "oversize":
					f, err := os.OpenFile(path, os.O_WRONLY, 0)
					if err != nil {
						t.Fatal(err)
					}
					err = f.Truncate((4 << 20) + 1)
					f.Close()
					if err != nil {
						t.Fatal(err)
					}
				default:
					valid := `{"time":"` + core.Now() + `","action":"run","result":{}}`
					if name == "history.json" {
						valid = `[{"id":"` + core.ID() + `","time":"` + core.Now() + `","action":"run","trigger":"manual","outcome":"succeeded"}]`
					}
					raw := valid
					switch kind {
					case "malformed":
						raw = "{"
					case "duplicate":
						raw = strings.Replace(valid, `"action":"run"`, `"action":"run","action":"run"`, 1)
					case "escaped-duplicate":
						raw = strings.Replace(valid, `"action":"run"`, `"action":"run","\u0061ction":"run"`, 1)
					case "case-duplicate":
						raw = strings.Replace(valid, `"action":"run"`, `"action":"run","Action":"run"`, 1)
					case "nested-duplicate":
						if name == "history.json" {
							raw = `[{"id":"` + core.ID() + `","time":"` + core.Now() + `","action":"run","trigger":"manual","outcome":{"x":1,"x":2}}]`
						} else {
							raw = strings.Replace(valid, `"result":{}`, `"result":{"x":1,"x":2}`, 1)
						}
					case "trailing":
						raw = valid + ` {}`
					case "wrong-root":
						if name == "history.json" {
							raw = `{"time":"` + core.Now() + `","action":"run","result":{}}`
						} else {
							raw = `[]`
						}
					case "unknown-field":
						raw = strings.Replace(valid, `"action":"run"`, `"action":"run","token":"untrusted-hidden-value"`, 1)
					case "missing-field":
						raw = strings.Replace(valid, `"action":"run",`, "", 1)
					case "deep":
						if name == "history.json" {
							raw = `[` + strings.Repeat(`{"x":`, 18) + `0` + strings.Repeat(`}`, 18) + `]`
						} else {
							raw = `{"time":"` + core.Now() + `","action":"run","result":` + strings.Repeat(`{"x":`, 18) + `0` + strings.Repeat(`}`, 18) + `}`
						}
					}
					if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				var out any
				if err := s.moduleRetrospectiveRecord("task-manager", name, &out); err == nil || errors.Is(err, os.ErrNotExist) || out != nil {
					t.Fatal("untrusted record returned or treated as absence", kind, err)
				}
				var replacement any = map[string]any{"time": core.Now(), "action": "run", "result": map[string]any{"replacement": true}}
				if name == "history.json" {
					replacement = []moduleEvent{{ID: core.ID(), Time: core.Now(), Action: "run", Trigger: "manual", Outcome: "succeeded"}}
				}
				if err := s.writeModuleRetrospectiveRecord("task-manager", name, replacement); err == nil {
					t.Fatal("writer adopted or replaced untrusted evidence")
				}
				if err := s.moduleRetrospectivePreflight("task-manager"); err == nil {
					t.Fatal("business preflight ignored bad retrospective evidence")
				}
				post := httptest.NewRecorder()
				s.Handler().ServeHTTP(post, httptest.NewRequest("POST", "/v1/app-modules/task-manager/run", strings.NewReader(`{}`)))
				if post.Code != 409 {
					t.Fatal("bad evidence dispatched automatic business refresh", post.Code, post.Body.String())
				}
				url := "/v1/app-modules/task-manager"
				if name == "history.json" {
					url += "/history"
				}
				w := httptest.NewRecorder()
				s.Handler().ServeHTTP(w, httptest.NewRequest("GET", url, nil))
				if name == "history.json" {
					if w.Code != 409 {
						t.Fatal("unsafe history accepted", w.Code, w.Body.String())
					}
				} else {
					var page struct {
						Report  any  `json:"report"`
						Unknown bool `json:"report_state_unknown"`
					}
					if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Report != nil || !page.Unknown {
						t.Fatal("unsafe last report returned", w.Code, w.Body.String())
					}
				}
				if strings.Contains(w.Body.String(), "trusted-retrospective-sentinel") || strings.Contains(w.Body.String(), "untrusted-hidden-value") {
					t.Fatal("untrusted report leaked")
				}
				after, err := os.Lstat(path)
				raw, readErr := os.ReadFile(outside)
				if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || before.ModTime() != after.ModTime() || string(raw) != string(sentinel) {
					t.Fatal("refusal changed original evidence")
				}
				if _, err := os.Lstat(filepath.Join(s.moduleDir("task-manager"), "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("unsafe read created ledger", err)
				}
			})
		}
	}
}

func TestModulePrivateDirectoryRejectsDetachedNamedAncestry(t *testing.T) {
	for _, parent := range []string{"anchor", "modules", "module"} {
		t.Run(parent, func(t *testing.T) {
			s, _ := moduleRecordFixture(t)
			d, err := s.moduleRecordDirectory("task-manager")
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if !d.current() {
				t.Fatal("fresh identity unavailable")
			}
			path := s.Config.SecurityDir
			if parent == "modules" {
				path = filepath.Join(path, "modules")
			}
			if parent == "module" {
				path = s.moduleDir("task-manager")
			}
			if err := os.Rename(path, path+"-own-retained"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if d.current() {
				t.Fatal("detached old tree treated as current")
			}
			if _, err := d.Lstat("installed.json"); err != nil {
				t.Fatal("fixture did not retain original pinned tree", err)
			}
		})
	}
}

func TestModuleLedgerReadOnlyLegacyAndDatabasePreserveBytes(t *testing.T) {
	s, path := retrospectiveFixture(t, "history.json")
	before, _ := os.Lstat(path)
	raw, _ := os.ReadFile(path)
	for _, filter := range []core.AppModuleInput{{}, {Search: "run", Limit: 1}, {Offset: 100}} {
		out, err := s.moduleHistory("task-manager", filter)
		if err != nil || out.(map[string]any)["read_only"] != true || out.(map[string]any)["source"] != "legacy-json" {
			t.Fatal(out, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(s.moduleDir("task-manager"), "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy query migrated database", err)
	}
	after, _ := os.Lstat(path)
	current, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() || string(raw) != string(current) {
		t.Fatal("legacy query modified file")
	}
	if err := s.appendModuleEvent("task-manager", "run", "manual", core.AppModuleInput{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(s.moduleDir("task-manager"), "history.sqlite")
	dbBefore, _ := os.Lstat(database)
	dbRaw, _ := os.ReadFile(database)
	for i := 0; i < 3; i++ {
		out, err := s.moduleHistory("task-manager", core.AppModuleInput{Limit: 1})
		if err != nil || out.(map[string]any)["read_only"] != true || out.(map[string]any)["source"] != "private-sqlite" || out.(map[string]any)["total"] != 2 {
			t.Fatal(out, err)
		}
	}
	dbAfter, _ := os.Lstat(database)
	dbCurrent, _ := os.ReadFile(database)
	if !os.SameFile(dbBefore, dbAfter) || dbBefore.Mode() != dbAfter.Mode() || dbBefore.ModTime() != dbAfter.ModTime() || string(dbRaw) != string(dbCurrent) {
		t.Fatal("read-only database query wrote or pruned")
	}
	db, dir, pinned, _, err := s.openModuleLedgerReadOnly(context.Background(), "task-manager")
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	defer pinned.Close()
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM module_events`); err == nil {
		t.Fatal("readonly SQLite allowed write")
	}
}

func TestModuleLedgerHardlinksAndSidecarsAreNotRecoveredByRead(t *testing.T) {
	for _, kind := range []string{"database-hardlink", "journal-hardlink", "wal-hardlink", "shm-hardlink", "database-public", "journal", "wal", "shm", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := retrospectiveFixture(t, "history.json")
			if err := s.appendModuleEvent("task-manager", "run", "manual", core.AppModuleInput{}, nil, nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.moduleDir("task-manager"), "history.sqlite")
			outside := filepath.Join(t.TempDir(), "own-keep")
			if strings.Contains(kind, "hardlink") {
				if kind != "database-hardlink" {
					path += map[string]string{"journal-hardlink": "-journal", "wal-hardlink": "-wal", "shm-hardlink": "-shm"}[kind]
					if err := os.WriteFile(path, []byte("own-sidecar-evidence"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Link(path, outside); err != nil {
					t.Fatal(err)
				}
			} else if kind == "database-public" {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			} else if kind == "corrupt" {
				if err := os.WriteFile(path, []byte("original-corrupt-evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				path += "-" + kind
				if err := os.WriteFile(path, []byte("own-sidecar-evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.Lstat(path)
			raw, _ := os.ReadFile(path)
			if _, err := s.moduleHistory("task-manager", core.AppModuleInput{}); err == nil {
				t.Fatal("unsafe or pending database accepted")
			}
			if strings.Contains(kind, "hardlink") || kind == "database-public" {
				if err := s.appendModuleEvent("task-manager", "run", "manual", core.AppModuleInput{}, nil, nil); err == nil {
					t.Fatal("writer accepted unsafe hardlink or permissions")
				}
			}
			after, err := os.Lstat(path)
			current, readErr := os.ReadFile(path)
			if err != nil || readErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() || string(raw) != string(current) {
				t.Fatal("read or refused write changed evidence")
			}
		})
	}
}

func TestModuleRetrospectivePublicationAndPostHistoryStayScoped(t *testing.T) {
	s, _, _ := appReliabilityFixture(t)
	for _, definition := range core.AppModules() {
		id := definition.ID
		if err := moduleWrite(filepath.Join(s.moduleDir(id), "installed.json"), map[string]any{"id": id}); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"history.json", "last-report.json"} {
			var value any = map[string]any{"time": core.Now(), "action": "scheduled-check", "result": map[string]any{"business_result": id}, "error": "bounded original failure"}
			if name == "history.json" {
				value = []moduleEvent{{ID: core.ID(), Time: core.Now(), Action: "run", Trigger: "manual", Outcome: "succeeded"}}
			}
			for i := 0; i < 2; i++ {
				if err := s.writeModuleRetrospectiveRecord(id, name, value); err != nil {
					t.Fatal(id, name, err)
				}
			}
			st, err := os.Lstat(filepath.Join(s.moduleDir(id), name))
			if err != nil || !moduleRecordInfo(st, false, false) {
				t.Fatal("published record identity is not private single-link", id, err)
			}
			var out any
			if err := s.moduleRetrospectiveRecord(id, name, &out); err != nil {
				t.Fatal(id, name, err)
			}
		}
		matches, err := filepath.Glob(filepath.Join(s.moduleDir(id), ".panel-retrospective-*"))
		if err != nil || len(matches) != 0 {
			t.Fatal("private temporary files retained", id, matches, err)
		}
	}
	last := filepath.Join(s.moduleDir("file-monitor"), "last-report.json")
	before, _ := os.Lstat(last)
	raw, _ := os.ReadFile(last)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/app-modules/file-monitor/history", strings.NewReader(`{}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"read_only":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	after, _ := os.Lstat(last)
	current, _ := os.ReadFile(last)
	if !os.SameFile(before, after) || before.ModTime() != after.ModTime() || string(raw) != string(current) {
		t.Fatal("POST history rewrote last business report")
	}
	if _, err := os.Lstat(filepath.Join(s.moduleDir("file-monitor"), "history.sqlite")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("POST query created database", err)
	}
}

func TestModuleAutomationRefusesBeforeBusinessWhenReportsUntrusted(t *testing.T) {
	s, source, target := appReliabilityFixture(t)
	fixtureWrite(t, s, source, "own-copy.txt", "new-source")
	fixtureWrite(t, s, target, "own-copy.txt", "keep-existing-target")
	path := filepath.Join(s.moduleDir("files-sync"), "last-report.json")
	if err := os.WriteFile(path, []byte(`{"damaged":"original-evidence"}`), 0600); err != nil {
		t.Fatal(err)
	}
	plan := moduleSyncPlan{ID: "own-plan", SiteID: source, TargetSiteID: target, Interval: 60, Enabled: true, Revision: 1, LastState: "pending"}
	if _, err := s.executeSyncPlan(context.Background(), &plan, "scheduled", time.Now().UTC()); err == nil || !s.moduleAutoBlocked["files-sync/own-plan"] {
		t.Fatal("unsafe report did not block automatic sync", err)
	}
	if fixtureRead(t, s, target, "own-copy.txt") != "keep-existing-target" || plan.LastState != "pending" {
		t.Fatal("guard ran business or changed original plan")
	}
	if _, err := os.Lstat(s.syncPlanPath(plan.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guard created plan state", err)
	}
	id := "website-tamper-proof"
	report := filepath.Join(s.moduleDir(id), "last-report.json")
	if err := os.WriteFile(report, []byte(`{"damaged":"original-integrity-evidence"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.runIntegrityPolicy(id, source, moduleIntegrityPolicy{SiteID: source, Enabled: true, Interval: 60}, "scheduled")
	if !s.moduleAutoBlocked[id+"/"+source] || fixtureRead(t, s, source, "own-copy.txt") != "new-source" {
		t.Fatal("unsafe report did not block integrity automation")
	}
	if _, err := os.Lstat(s.integrityControlPath(id, source)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("guard rewrote policy state", err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != `{"damaged":"original-evidence"}` {
		t.Fatal("original sync report repaired or overwritten")
	}
	if raw, _ := os.ReadFile(report); string(raw) != `{"damaged":"original-integrity-evidence"}` {
		t.Fatal("original integrity report overwritten")
	}
}
