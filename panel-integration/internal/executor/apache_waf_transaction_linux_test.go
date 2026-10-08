//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"local/panel/internal/core"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type apacheCrashDescriptor struct {
	Root, Sites, Conf, State, Security, Apache, Nginx string
	Cut                                               int
	Plan                                              []wafConfigChange
}

func TestApacheWAFTransactionCrashChild(t *testing.T) {
	path := os.Getenv("PANEL_QA_APACHE_CRASH_DESCRIPTOR")
	if path == "" {
		t.Skip("only the private subprocess crash fixture may select this test")
	}
	rel, e := filepath.Rel(os.TempDir(), path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.Clean(path) != path {
		t.Fatal("descriptor outside private temp fixture")
	}
	data, e := apacheWAFReadStableFile(path, 64<<10)
	if e != nil {
		t.Fatal(e)
	}
	var d apacheCrashDescriptor
	if e = json.Unmarshal(data, &d); e != nil {
		t.Fatal(e)
	}
	if d.Cut < 0 || d.Cut > 3 || d.Root != filepath.Dir(path) {
		t.Fatal("invalid private crash root or cut")
	}
	s := New(Config{SystemRoot: d.Root, SitesDir: d.Sites, ConfDir: d.Conf, StateDir: d.State, SecurityDir: d.Security, ApacheSiteConfig: d.Apache, NginxConf: d.Nginx}).apacheWAFTransactionService()
	if _, e = s.startWAFTransaction(d.Plan); e != nil {
		t.Fatal(e)
	}
	for _, change := range d.Plan[:d.Cut] {
		if e = wafApplyChange(change, true); e != nil {
			t.Fatal(e)
		}
	}
	// No defers, Go cleanup, or in-memory rollback may run after this boundary.
	if e = syscall.Kill(os.Getpid(), syscall.SIGKILL); e != nil {
		t.Fatal(e)
	}
	t.Fatal("SIGKILL returned without killing child")
}

func TestApacheWAFTransactionActualSIGKILLRequiresDurableRecovery(t *testing.T) {
	for cut := 0; cut <= 3; cut++ {
		t.Run(string(rune('A'+cut)), func(t *testing.T) {
			s, plan := apacheTransactionFixture(t, true, false)
			d := apacheCrashDescriptor{Root: s.Config.SystemRoot, Sites: s.Config.SitesDir, Conf: s.Config.ConfDir, State: s.Config.StateDir, Security: s.Config.SecurityDir, Apache: s.Config.ApacheSiteConfig, Nginx: s.Config.NginxConf, Cut: cut, Plan: plan}
			path := filepath.Join(d.Root, "crash-descriptor.json")
			data, e := json.Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			child := exec.Command(os.Args[0], "-test.run", "^TestApacheWAFTransactionCrashChild$", "-test.timeout", "10s")
			child.Env = append(os.Environ(), "PANEL_QA_APACHE_CRASH_DESCRIPTOR="+path)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatal("child did not crash", e, string(output))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not an actual SIGKILL", e, string(output))
			}
			fresh := New(s.Config).apacheWAFTransactionService()
			if changed, e := fresh.recoverWAFTransaction(); e != nil || !changed {
				t.Fatal("fresh process state failed durable recovery", e)
			}
			for _, c := range plan {
				match, e := fresh.wafCurrentMatches(c, false)
				if e != nil || !match {
					t.Fatal("SIGKILL lost original content/owner/mode", c.Path, e)
				}
			}
			tx, e := fresh.readWAFTransaction()
			if e != nil || tx.State != "recovered" {
				t.Fatal("lost pending native confirmation", e)
			}
		})
	}
}

func apacheTransactionFixture(t *testing.T, original bool, removing bool) (*Service, []wafConfigChange) {
	t.Helper()
	s := wafPolicyFixture(t)
	s.Config.ApacheSiteConfig = filepath.Join(s.Config.SystemRoot, "apache", "httpd.conf")
	txs := s.apacheWAFTransactionService()
	paths := txs.apacheWAFConfigurationPaths()
	backups := []fileBackup{}
	for i, path := range paths {
		if err := txs.wafOwnedDirectory(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		if i == 0 || original {
			mode := os.FileMode(0640)
			if i == 2 {
				mode = 0600
			}
			if err := os.WriteFile(path, []byte("original-"+string(rune('0'+i))+"\n"), mode); err != nil {
				t.Fatal(err)
			}
		}
		b, err := txs.apacheWAFStableBackup(path)
		if err != nil {
			t.Fatal(err)
		}
		backups = append(backups, b)
	}
	plan, err := txs.planApacheWAFTransaction(backups, "next source\n", "next rules\n", map[string]any{"id": "apache-waf", "version": core.ApacheWAFVersion}, removing)
	if err != nil {
		t.Fatal(err)
	}
	return txs, plan
}

func TestApacheWAFTransactionEveryInterruptionPreservesTripletAndOwners(t *testing.T) {
	for _, original := range []bool{false, true} {
		for _, removing := range []bool{false, true} {
			for cut := 0; cut <= 3; cut++ {
				t.Run(strings.Join([]string{map[bool]string{true: "existing", false: "absent"}[original], map[bool]string{true: "remove", false: "apply"}[removing], string(rune('A' + cut))}, "-"), func(t *testing.T) {
					s, plan := apacheTransactionFixture(t, original, removing)
					tx, err := s.startWAFTransaction(plan)
					if err != nil {
						t.Fatal(err)
					}
					for _, c := range plan[:cut] {
						if err = wafApplyChange(c, true); err != nil {
							t.Fatal(err)
						}
					}
					fresh := New(s.Config).apacheWAFTransactionService()
					changed, err := fresh.recoverWAFTransaction()
					if err != nil || !changed {
						t.Fatal("fresh durable recovery failed", err)
					}
					for _, c := range plan {
						match, err := fresh.wafCurrentMatches(c, false)
						if err != nil || !match {
							t.Fatal("original bytes/mode/owner/existence changed", c.Path, err)
						}
					}
					pending, err := fresh.readWAFTransaction()
					if err != nil || pending.State != "recovered" || pending.ID != tx.ID {
						t.Fatal("evidence removed before native verification", err)
					}
					if changed, err = fresh.recoverWAFTransaction(); err != nil || changed {
						t.Fatal("restoration not idempotent", err)
					}
					if err = fresh.finishWAFTransaction(pending); err != nil {
						t.Fatal(err)
					}
					if _, err = os.Lstat(fresh.wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("acknowledged journal remains", err)
					}
				})
			}
		}
	}
}

func TestApacheWAFTransactionForeignEditRefusesBeforeAnyRestore(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "applying", true: "committed"}[committed], func(t *testing.T) {
			s, plan := apacheTransactionFixture(t, true, false)
			tx, err := s.startWAFTransaction(plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range plan[:2] {
				if err = wafApplyChange(c, true); err != nil {
					t.Fatal(err)
				}
			}
			if committed {
				if err = wafApplyChange(plan[2], true); err != nil {
					t.Fatal(err)
				}
				tx.State = "committed"
				if err = wafWriteTransaction(s.wafPendingPath(), tx); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(plan[1].Path, []byte("foreign edit\n"), 0644); err != nil {
				t.Fatal(err)
			}
			before := map[string]string{}
			for _, c := range plan {
				b, err := s.apacheWAFStableBackup(c.Path)
				if err != nil {
					t.Fatal(err)
				}
				before[c.Path] = string(b.data)
			}
			if _, err = New(s.Config).apacheWAFTransactionService().recoverWAFTransaction(); err == nil {
				t.Fatal("external edit overwritten")
			}
			for _, c := range plan {
				b, err := s.apacheWAFStableBackup(c.Path)
				if err != nil || string(b.data) != before[c.Path] {
					t.Fatal("partial restore occurred before full validation", c.Path, err)
				}
			}
			if _, err = s.readWAFTransaction(); err != nil {
				t.Fatal("refusal lost recovery evidence", err)
			}
		})
	}
}

func TestApacheWAFTransactionNamespaceDigestAndPathRestrictions(t *testing.T) {
	s, plan := apacheTransactionFixture(t, true, false)
	if s.wafPendingPath() == New(s.Config).wafPendingPath() {
		t.Fatal("Apache journal aliases Nginx journal")
	}
	if s.wafChangePathAllowed(s.Config.NginxConf) || New(s.Config).wafChangePathAllowed(plan[0].Path) {
		t.Fatal("cross-engine path accepted")
	}
	tx, err := s.startWAFTransaction(plan)
	if err != nil {
		t.Fatal(err)
	}
	changed := tx
	changed.Digests = map[string]string{}
	for k, v := range tx.Digests {
		changed.Digests[k] = v
	}
	changed.Digests[plan[1].Path+":old"] = strings.Repeat("0", 64)
	if s.wafTransactionContract(changed) == nil {
		t.Fatal("corrupted backup digest accepted")
	}
	changed = tx
	changed.Changes = append([]wafConfigChange{}, tx.Changes...)
	changed.Changes[1].Path = s.Config.NginxConf
	if s.wafTransactionContract(changed) == nil {
		t.Fatal("Nginx mutation in Apache journal accepted")
	}
	if err = os.Chmod(s.wafPendingPath(), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = s.readWAFTransaction(); err == nil {
		t.Fatal("nonprivate recovery journal accepted")
	}
}

func TestApacheWAFTransactionPendingAndBusyBlockSiteBeforeWrites(t *testing.T) {
	s, plan := apacheTransactionFixture(t, true, false)
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	other := New(s.Config).apacheWAFTransactionService()
	if _, err = other.lockWAFConfiguration(); !errors.Is(err, errWAFConfigurationBusy) {
		t.Fatal("busy transaction lock accepted", err)
	}
	lock.Close()
	if _, err = s.startWAFTransaction(plan); err != nil {
		t.Fatal(err)
	}
	site := core.Site{ID: core.ID(), Name: "not-created", Slug: "not-created", Domain: "apache-pending.localhost"}
	service := New(s.Config)
	if _, err = service.Apply(context.Background(), core.ApplyRequest{Site: site, JobID: core.ID(), Enabled: true}); err == nil || !strings.Contains(err.Error(), "Apache") {
		t.Fatal("pending Apache mutation not rejected", err)
	}
	if _, err = os.Stat(filepath.Join(s.Config.SitesDir, site.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created site before pending guard", err)
	}
}

func TestApacheWAFTransactionFIFOAndSymlinkCannotBlockOrSubstitute(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s, plan := apacheTransactionFixture(t, true, false)
			path := plan[1].Path
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "fifo" {
				err = syscall.Mkfifo(path, 0600)
			} else {
				err = os.Symlink(plan[0].Path, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.apacheWAFStableBackup(path); err == nil {
				t.Fatal("nonordinary backup accepted")
			}
		})
	}
}
