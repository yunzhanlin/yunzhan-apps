//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

// Private filesystem contracts, not native Nginx or normal API acceptance.
func lbHistoryFixture(t *testing.T, withTLS ...bool) (*Service, loadBalanceTransaction, string, []byte) {
	t.Helper()
	s, tx, _ := lbRoutingTransactionFixture(t, withTLS...)
	lbRoutingInstalled(t, s, "1.8.0")
	tx.State = "committed"
	path := filepath.Join(filepath.Dir(s.loadBalancePendingPath()), tx.ID+".json")
	if err := s.writeLoadBalanceTransaction(path, tx); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Whitespace is part of the selected whole-file identity, not discarded by
	// decoding and re-encoding the private record during archival.
	b = append(b, ' ', '\n')
	if err = atomicWrite(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Error("history unexpectedly executed a system command")
		return "", fmt.Errorf("no command allowed")
	}
	return s, tx, path, b
}
func lbHistoryInput(tx loadBalanceTransaction, b []byte) core.AppModuleInput {
	return core.AppModuleInput{ResourceID: tx.ID, ExpectedSHA: core.Hash(string(b)), Confirm: "ARCHIVE LOAD TRANSACTION " + tx.ID}
}
func lbHistoryReport(t *testing.T, s *Service, in core.AppModuleInput) map[string]any {
	t.Helper()
	out, err := s.moduleLoadBalance(context.Background(), "transactions", in)
	if err != nil {
		t.Fatal(err)
	}
	return out.(map[string]any)
}

func TestLoadBalanceHistoryEmptyReadNeverCreatesArchiveOrRewritesInstallation(t *testing.T) {
	s := wafPolicyFixture(t)
	lbRoutingInstalled(t, s, "1.7.1")
	p := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	before, _ := os.ReadFile(p)
	out := lbHistoryReport(t, s, core.AppModuleInput{})
	if out["total"] != 0 || len(out["load_transactions"].([]loadBalanceHistoryRow)) != 0 {
		t.Fatal(out)
	}
	if _, err := os.Lstat(s.loadBalanceArchiveDir()); !os.IsNotExist(err) {
		t.Fatal("read created archive", err)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("read rewrote installed identity")
	}
}

func TestLoadBalanceHistoryReviewedPatchVersionsOnly(t *testing.T) {
	for _, version := range []string{"1.8.0", "1.8.1", "1.8.2", "1.9.0"} {
		t.Run(version, func(t *testing.T) {
			s, tx, path, b := lbHistoryFixture(t)
			lbRoutingInstalled(t, s, version)
			out := lbHistoryReport(t, s, core.AppModuleInput{})
			want := version == "1.8.0" || version == "1.8.1"
			if out["transaction_archive_ready"] != want {
				t.Fatal("archive eligibility differs from version contract", out)
			}
			_, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b))
			if (err == nil) != want {
				t.Fatal("archive write differs from reviewed version contract", err)
			}
			if want {
				path = filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json")
			}
			got, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(got, b) {
				t.Fatal("version check changed original bytes", e)
			}
		})
	}
}

func TestLoadBalanceHistoryExactBytesReplayAndPermanentIDReservation(t *testing.T) {
	for _, tls := range []bool{false, true} {
		t.Run(fmt.Sprint(tls), func(t *testing.T) {
			s, tx, path, b := lbHistoryFixture(t, tls)
			before := map[string][]byte{}
			for _, c := range tx.Changes {
				before[c.Path], _ = os.ReadFile(c.Path)
			}
			in := lbHistoryInput(tx, b)
			bad := in
			bad.ExpectedSHA = strings.Repeat("0", 64)
			if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", bad); err == nil {
				t.Fatal("stale whole-file identity accepted")
			}
			if _, err := os.Lstat(s.loadBalanceArchiveDir()); !os.IsNotExist(err) {
				t.Fatal("rejected archive changed namespace")
			}
			out, err := s.moduleLoadBalance(context.Background(), "archive-transaction", in)
			if err != nil {
				t.Fatal(err)
			}
			if out.(map[string]any)["replayed"] != false || out.(map[string]any)["configuration_changed"] != false {
				t.Fatal(out)
			}
			archive := filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json")
			actual, err := loadBalancePrivateRead(archive, 256<<10)
			if err != nil || !bytes.Equal(actual, b) {
				t.Fatal("original bytes changed", err)
			}
			if _, err = os.Lstat(path); !os.IsNotExist(err) {
				t.Fatal("active record not moved", err)
			}
			st, _ := os.Stat(s.loadBalanceArchiveDir())
			if st.Mode().Perm() != 0700 {
				t.Fatal("archive is not private")
			}
			fresh := New(s.Config)
			again, err := fresh.moduleLoadBalance(context.Background(), "archive-transaction", in)
			if err != nil || again.(map[string]any)["replayed"] != true {
				t.Fatal("lost reply replay not resolved", again, err)
			}
			for _, p := range []string{path, s.loadBalancePendingPath()} {
				if err = fresh.writeLoadBalanceTransaction(p, tx); err == nil {
					t.Fatal("archived identity reused", p)
				}
			}
			for p, want := range before {
				got, _ := os.ReadFile(p)
				if !bytes.Equal(got, want) {
					t.Fatal("history altered active set", p)
				}
			}
			report := lbHistoryReport(t, fresh, core.AppModuleInput{})
			raw, _ := json.Marshal(report)
			if report["transaction_active_count"] != 0 || report["transaction_archive_count"] != 1 || bytes.Contains(raw, []byte("old_data")) || bytes.Contains(raw, []byte("BEGIN CERTIFICATE")) || bytes.Contains(raw, []byte(s.Config.SystemRoot)) {
				t.Fatal("incorrect or private public report", string(raw))
			}
		})
	}
}

func TestLoadBalanceHistoryUnfinishedPendingAndOldVersionRefuseMove(t *testing.T) {
	for _, state := range []string{"applying", "restored"} {
		t.Run(state, func(t *testing.T) {
			s, tx, path, _ := lbHistoryFixture(t)
			tx.State = state
			if err := moduleWrite(path, tx); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(path)
			if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err == nil {
				t.Fatal("unfinished record archived")
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, b) {
				t.Fatal("unfinished evidence changed")
			}
		})
	}
	for _, kind := range []string{"load-pending", "waf-pending", "old-version"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := lbHistoryFixture(t)
			if kind == "load-pending" {
				p := tx
				p.State = "applying"
				if err := s.writeLoadBalanceTransaction(s.loadBalancePendingPath(), p); err != nil {
					t.Fatal(err)
				}
				out := lbHistoryReport(t, s, core.AppModuleInput{})
				if !out["pending"].(bool) || out["load_transactions"].([]loadBalanceHistoryRow)[0].Archivable {
					t.Fatal("pending inventory grants archive", out)
				}
			} else if kind == "waf-pending" {
				if err := moduleWrite(s.wafPendingPath(), map[string]any{"unknown": true}); err != nil {
					t.Fatal(err)
				}
			} else {
				lbRoutingInstalled(t, s, "1.7.1")
			}
			if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err == nil {
				t.Fatal("unsafe maintenance accepted", kind)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, b) {
				t.Fatal("rejected request changed record")
			}
		})
	}
}

func TestLoadBalanceHistoryHTMLPendingRefusesArchiveAndReplay(t *testing.T) {
	for _, replay := range []bool{false, true} {
		for _, kind := range []string{"file", "symlink", "fifo", "directory"} {
			t.Run(fmt.Sprintf("replay=%t/%s", replay, kind), func(t *testing.T) {
				s, tx, path, b := lbHistoryFixture(t)
				in := lbHistoryInput(tx, b)
				if replay {
					if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", in); err != nil {
						t.Fatal(err)
					}
					path = filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json")
				}
				pending := s.analyticsHTMLTransactionService().wafPendingPath()
				if err := os.MkdirAll(filepath.Dir(pending), 0750); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "file":
					if err := atomicWrite(pending, []byte(`{"unrecognized":true}`), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(path, pending); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := syscall.Mkfifo(pending, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(pending, 0700); err != nil {
						t.Fatal(err)
					}
				}
				pendingBefore, err := os.Lstat(pending)
				if err != nil {
					t.Fatal(err)
				}
				out := lbHistoryReport(t, s, core.AppModuleInput{})
				if out["transaction_archive_ready"] != false || out["load_transactions"].([]loadBalanceHistoryRow)[0].Archivable {
					t.Fatal("HTML pending inventory grants archive", out)
				}
				if _, err = s.moduleLoadBalance(context.Background(), "archive-transaction", in); err == nil {
					t.Fatal("HTML transaction barrier bypassed", kind, replay)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, b) {
					t.Fatal("pending HTML changed original transaction", err)
				}
				pendingAfter, err := os.Lstat(pending)
				if err != nil || !os.SameFile(pendingBefore, pendingAfter) || pendingBefore.Mode() != pendingAfter.Mode() || pendingBefore.Size() != pendingAfter.Size() {
					t.Fatal("HTML pending evidence changed", err)
				}
				if !replay {
					if _, err = os.Lstat(s.loadBalanceArchiveDir()); !os.IsNotExist(err) {
						t.Fatal("blocked request created archive", err)
					}
				}
			})
		}
	}
}

func TestLoadBalanceHistoryUnsafeFilesRefuseCompleteInventory(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "hardlink", "fifo", "unknown", "bad-digest", "bad-format", "foreign-path"} {
		t.Run(kind, func(t *testing.T) {
			s, tx, path, b := lbHistoryFixture(t)
			switch kind {
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".retained"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".retained"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(filepath.Join(filepath.Dir(path), core.ID()+".json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := atomicWrite(filepath.Join(filepath.Dir(path), "unrecognized"), b, 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-digest":
				tx.Digests[tx.Changes[0].Path+":old"] = strings.Repeat("0", 64)
				if err := moduleWrite(path, tx); err != nil {
					t.Fatal(err)
				}
			case "bad-format":
				tx.Format = 99
				if err := moduleWrite(path, tx); err != nil {
					t.Fatal(err)
				}
			case "foreign-path":
				tx.Changes[0].Path = filepath.Join(s.Config.SystemRoot, "foreign.conf")
				if err := moduleWrite(path, tx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.moduleLoadBalance(context.Background(), "transactions", core.AppModuleInput{}); err == nil {
				t.Fatal("returned partial/untrusted inventory", kind)
			}
			if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err == nil {
				t.Fatal("untrusted record archived", kind)
			}
			if _, err := os.Lstat(s.loadBalanceArchiveDir()); !os.IsNotExist(err) {
				t.Fatal("rejection created archive", kind)
			}
		})
	}
}

func TestLoadBalanceHistoryNoOverwriteCollisionAndUnsafeArchiveNamespace(t *testing.T) {
	s, tx, path, b := lbHistoryFixture(t)
	row, err := s.loadBalanceHistoryRecord(path, tx.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(s.loadBalanceArchiveDir(), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json")
	other := append(append([]byte{}, b...), '\n')
	if err = atomicWrite(target, other, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err == nil {
		t.Fatal("duplicate identity inventory accepted")
	}
	// Exercise the kernel no-overwrite leaf independently from the public
	// complete inventory guard. Both original files must remain byte-identical.
	if _, err = s.archiveLoadBalanceHistory(context.Background(), row); err == nil {
		t.Fatal("native no-overwrite collision accepted")
	}
	for p, want := range map[string][]byte{path: b, target: other} {
		got, _ := os.ReadFile(p)
		if !bytes.Equal(got, want) {
			t.Fatal("collision overwrote evidence", p)
		}
	}
	if err = os.Chmod(s.loadBalanceArchiveDir(), 0750); err != nil {
		t.Fatal(err)
	}
	if _, err = s.moduleLoadBalance(context.Background(), "transactions", core.AppModuleInput{}); err == nil {
		t.Fatal("public archive accepted")
	}
	copy := tx
	copy.ID = core.ID()
	if err = s.writeLoadBalanceTransaction(filepath.Join(filepath.Dir(path), copy.ID+".json"), copy); err == nil {
		t.Fatal("unsafe archive namespace authorized a new write")
	}
}

func TestLoadBalanceHistoryPrivateFIFOReaderCannotBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "record.json")
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBalancePrivateRead(p, 256<<10); err == nil {
		t.Fatal("special file accepted as a private transaction")
	}
}

func TestLoadBalanceHistoryCanceledAndCompetingWriterPreserveRecords(t *testing.T) {
	s, tx, path, b := lbHistoryFixture(t)
	in := lbHistoryInput(tx, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.moduleLoadBalance(ctx, "archive-transaction", in); err == nil {
		t.Fatal("cancelled operation moved evidence")
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	fresh := New(s.Config)
	for _, action := range []string{"transactions", "archive-transaction"} {
		body := core.AppModuleInput{}
		if action == "archive-transaction" {
			body = in
		}
		if _, err = fresh.moduleLoadBalance(context.Background(), action, body); err == nil {
			t.Fatal("competing writer accepted", action)
		}
	}
	lock.Close()
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, b) {
		t.Fatal("cancelled/locked operation altered evidence")
	}
}

func TestLoadBalanceHistory512RecordsCanBeMaintainedWithoutDroppingEvidence(t *testing.T) {
	s, tx, path, b := lbHistoryFixture(t)
	dir := filepath.Dir(path)
	for i := 1; i < 512; i++ {
		copy := tx
		copy.ID = core.ID()
		if err := moduleWrite(filepath.Join(dir, copy.ID+".json"), copy); err != nil {
			t.Fatal(err)
		}
	}
	out := lbHistoryReport(t, s, core.AppModuleInput{Limit: 32, Offset: 500})
	if out["total"] != 512 || len(out["load_transactions"].([]loadBalanceHistoryRow)) != 12 {
		t.Fatal("boundary inventory incomplete", out["total"])
	}
	if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err != nil {
		t.Fatal(err)
	}
	out = lbHistoryReport(t, s, core.AppModuleInput{})
	if out["total"] != 512 || out["transaction_active_count"] != 511 || out["transaction_archive_count"] != 1 {
		t.Fatal("maintenance lost records", out["total"])
	}
	if actual, err := loadBalancePrivateRead(filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json"), 256<<10); err != nil || !bytes.Equal(actual, b) {
		t.Fatal("maintained record corrupted", err)
	}
}

func TestLoadBalanceHistory2048ArchiveCapacityAndOverflowAreExplicit(t *testing.T) {
	s, tx, path, b := lbHistoryFixture(t)
	if err := os.Mkdir(s.loadBalanceArchiveDir(), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2048; i++ {
		copy := tx
		copy.ID = core.ID()
		if err := moduleWrite(filepath.Join(s.loadBalanceArchiveDir(), copy.ID+".json"), copy); err != nil {
			t.Fatal(err)
		}
	}
	out := lbHistoryReport(t, s, core.AppModuleInput{Limit: 32, Offset: 2040})
	if out["total"] != 2049 || out["transaction_archive_count"] != 2048 || len(out["load_transactions"].([]loadBalanceHistoryRow)) != 9 {
		t.Fatal("exactly full archive unreadable", out["total"])
	}
	if out["transaction_archive_ready"] != false {
		t.Fatal("full archive claims new admission")
	}
	for _, row := range out["load_transactions"].([]loadBalanceHistoryRow) {
		if row.Archivable {
			t.Fatal("full archive claims selectable new admission")
		}
	}
	if _, err := s.moduleLoadBalance(context.Background(), "archive-transaction", lbHistoryInput(tx, b)); err == nil {
		t.Fatal("full archive accepted another record")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, b) {
		t.Fatal("full archive deleted active record")
	}
	copy := tx
	copy.ID = core.ID()
	if err := moduleWrite(filepath.Join(s.loadBalanceArchiveDir(), copy.ID+".json"), copy); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleLoadBalance(context.Background(), "transactions", core.AppModuleInput{}); err == nil {
		t.Fatal("overflow returned truncated inventory")
	}
}

func TestLoadBalanceHistoryExecutorHTTPRejectsGenericFieldsAndReplaysOriginalArchive(t *testing.T) {
	s, tx, path, b := lbHistoryFixture(t)
	mux := http.NewServeMux()
	s.appModuleRoutes(mux)
	request := func(action, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/app-modules/load-balance/"+action, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, body := range []string{`{"limit":16,"enabled":false}`, `{"offset":0,"offset":1}`, `{"health_check":null}`, `null`, `{} {}`} {
		w := request("transactions", body)
		if w.Code != 400 {
			t.Fatal("unclosed request reached executor", body, w.Code, w.Body.String())
		}
	}
	before, _ := os.ReadFile(path)
	if !bytes.Equal(before, b) {
		t.Fatal("invalid body altered private record")
	}
	w := request("transactions", `{"limit":16,"offset":0}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var report struct {
		Rows []loadBalanceHistoryRow `json:"load_transactions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || len(report.Rows) != 1 || report.Rows[0].SHA != core.Hash(string(b)) {
		t.Fatal("actual handler report mismatch", err)
	}
	body := `{"resource_id":"` + tx.ID + `","expected_sha":"` + core.Hash(string(b)) + `","confirm":"ARCHIVE LOAD TRANSACTION ` + tx.ID + `"}`
	for _, replayed := range []bool{false, true} {
		w = request("archive-transaction", body)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		var result struct {
			Replayed             bool `json:"replayed"`
			ConfigurationChanged bool `json:"configuration_changed"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Replayed != replayed || result.ConfigurationChanged {
			t.Fatal("actual archive/replay handler did not preserve original identity", err)
		}
	}
	actual, err := loadBalancePrivateRead(filepath.Join(s.loadBalanceArchiveDir(), tx.ID+".json"), 256<<10)
	if err != nil || !bytes.Equal(actual, b) {
		t.Fatal("handler archive changed original bytes", err)
	}
}
