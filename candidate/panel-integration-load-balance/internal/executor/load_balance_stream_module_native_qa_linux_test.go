//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type streamModuleNativeModel struct {
	modulePath, publicationPath string
	module, publication         *os.Root
	held                        *loadBalanceStreamHeldModule
	seed, proposal, original    []byte
	current                     func() bool
}

func streamModuleNativeFixture(t *testing.T, update bool) *streamModuleNativeModel {
	t.Helper()
	if os.Getenv("PANEL_NATIVE_QA") != "1" {
		t.Skip("explicit isolated Root filesystem models only; not original Core/account/application acceptance")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("Root-only private filesystem fixture required")
	}
	return streamModuleNativeFixtureChecked(t, update)
}

func streamModuleNativeFixtureChecked(t *testing.T, update bool) *streamModuleNativeModel {
	t.Helper()
	base := t.TempDir()
	m := &streamModuleNativeModel{modulePath: filepath.Join(base, "module"), publicationPath: filepath.Join(base, "publication")}
	for _, name := range []string{m.modulePath, m.publicationPath} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Only this new PRIVATE fixture publication changes ownership. Old module
	// bytes, group and directory keep the real caller's original identity.
	if err := os.Chown(m.publicationPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if update {
		m.original = []byte("{\n  \"id\": \"load-balance\", \"version\": \"1.8.5\", \"settings\": {\"legacy\": {\"domain\": \"原有.example\", \"n\": 9007199254740993}}, \"installed_at\": \"2026-10-24T00:00:00Z\"\n}\n")
		if err := os.WriteFile(filepath.Join(m.modulePath, "installed.json"), m.original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Existing HTTP state is an adjacent business file, never a stream input.
	if err := os.WriteFile(filepath.Join(m.modulePath, "entries.json"), []byte("unchanged old HTTP entries\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	m.module, err = os.OpenRoot(m.modulePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.module.Close() })
	m.publication, err = os.OpenRoot(m.publicationPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.publication.Close() })
	moduleInfo, _ := m.module.Stat(".")
	pubInfo, _ := m.publication.Stat(".")
	m.current = func() bool {
		a, e1 := m.publication.Stat(".")
		b, e2 := os.Lstat(m.publicationPath)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(a) && os.SameFile(pubInfo, a) && os.SameFile(a, b)
	}
	m.held, err = holdLoadBalanceStreamModuleAt(m.module, func() bool {
		a, e1 := m.module.Stat(".")
		b, e2 := os.Lstat(m.modulePath)
		return e1 == nil && e2 == nil && moduleRecordInfo(a, true, false) && os.SameFile(moduleInfo, a) && os.SameFile(a, b)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.held.close)
	seed, now := streamModuleProposalFixture(t, m.original)
	m.seed = seed
	m.proposal, err = loadBalanceStreamModuleProposal(seed, m.original, now)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func streamModuleModelAuthorize(context.Context) error { return nil }

func TestLoadBalanceStreamModuleNativeExclusiveOriginalPublication(t *testing.T) {
	for _, update := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "legacy-update"}[update], func(t *testing.T) {
			m := streamModuleNativeFixture(t, update)
			httpInfo, _ := os.Lstat(filepath.Join(m.modulePath, "entries.json"))
			p, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal("private original preparation refused", err)
			}
			defer p.close()
			if update {
				backup, err := os.ReadFile(filepath.Join(m.publicationPath, "original.json"))
				if err != nil || !bytes.Equal(backup, m.original) {
					t.Fatal("incomplete original backup", err)
				}
			}
			if q, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize); err == nil || q != nil {
				t.Fatal("old publication adopted")
			}
			digest, err := p.publish(context.Background(), streamModuleModelAuthorize)
			if err != nil || digest != core.Hash(string(m.proposal)) || !p.done || !p.unknown {
				t.Fatal("actual isolated atomic publication failed", err)
			}
			installed, err := os.ReadFile(filepath.Join(m.modulePath, "installed.json"))
			if err != nil || !bytes.Equal(installed, m.proposal) {
				t.Fatal("actual published bytes differ", err)
			}
			if err := checkStreamModulePublicationIntent(m.publication, m.module, m.seed, m.proposal); err != nil {
				t.Fatal("complete original publication intent, closed inventory or retained inode refused", err)
			}
			if _, err := p.publish(context.Background(), streamModuleModelAuthorize); err == nil {
				t.Fatal("original publication replayed")
			}
			if update {
				old, err := os.Lstat(filepath.Join(m.modulePath, ".lbstream-publication-"+p.job+".json"))
				if err != nil || !os.SameFile(old, m.held.before) {
					t.Fatal("original old inode was not retained", err)
				}
				body, err := os.ReadFile(filepath.Join(m.modulePath, ".lbstream-publication-"+p.job+".json"))
				if err != nil || !bytes.Equal(body, m.original) {
					t.Fatal("old inode bytes lost", err)
				}
			}
			afterHTTP, err := os.Lstat(filepath.Join(m.modulePath, "entries.json"))
			body, err2 := os.ReadFile(filepath.Join(m.modulePath, "entries.json"))
			if err != nil || err2 != nil || !geoStoreStableInfo(httpInfo, afterHTTP) || string(body) != "unchanged old HTTP entries\n" {
				t.Fatal("adjacent HTTP state changed")
			}
		})
	}
}

func TestLoadBalanceStreamModuleNativeCompletionCannotAdoptCopiedOldInode(t *testing.T) {
	for _, fault := range []string{"old-inode-replaced", "old-mode", "old-mtime", "intent-missing", "intent-unknown", "extra-file"} {
		t.Run(fault, func(t *testing.T) {
			m := streamModuleNativeFixture(t, true)
			p, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			if _, err = p.publish(context.Background(), streamModuleModelAuthorize); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(m.modulePath, ".lbstream-publication-"+p.job+".json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "old-inode-replaced":
				must(os.Rename(old, filepath.Join(m.modulePath, "retained-original")))
				must(os.WriteFile(old, m.original, 0600))
			case "old-mode":
				must(os.Chmod(old, 0640))
			case "old-mtime":
				info, err := os.Lstat(old)
				must(err)
				must(os.Chtimes(old, info.ModTime(), info.ModTime().Add(time.Second)))
			case "intent-missing":
				must(os.Rename(filepath.Join(m.publicationPath, "intent.json"), filepath.Join(m.modulePath, "retained-intent")))
			case "intent-unknown":
				raw, err := os.ReadFile(filepath.Join(m.publicationPath, "intent.json"))
				must(err)
				must(os.WriteFile(filepath.Join(m.publicationPath, "intent.json"), bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"claimed_complete":true`), 1), 0600))
			case "extra-file":
				must(os.WriteFile(filepath.Join(m.publicationPath, "unknown.json"), []byte("{}"), 0600))
			}
			if checkStreamModulePublicationIntent(m.publication, m.module, m.seed, m.proposal) == nil {
				t.Fatal("completion adopted corrupt/copied original evidence", fault)
			}
		})
	}
}

func TestLoadBalanceStreamModuleNativeDriftNeverOverwritesOriginal(t *testing.T) {
	for _, fault := range []string{"cancelled", "nil-authority", "revoked", "missing-original-copy", "changed-original-copy", "backup-mode", "proposal-copy", "intent-copy", "unexpected-publication-leaf", "publication-root-mode", "original-content", "original-mode", "original-inode", "original-symlink", "existing-candidate", "new-target-appears"} {
		t.Run(fault, func(t *testing.T) {
			m := streamModuleNativeFixture(t, fault != "new-target-appears")
			p, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize)
			if err != nil {
				t.Fatal(err)
			}
			defer p.close()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, auth := context.Background(), streamModuleModelAuthorize
			switch fault {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil-authority":
				auth = nil
			case "revoked":
				auth = func(context.Context) error { return errors.New("fixture revoked") }
			case "missing-original-copy":
				must(os.Rename(filepath.Join(m.publicationPath, "original.json"), filepath.Join(filepath.Dir(m.publicationPath), "retained-original")))
			case "changed-original-copy":
				must(os.WriteFile(filepath.Join(m.publicationPath, "original.json"), []byte("changed backup"), 0600))
			case "backup-mode":
				must(os.Chmod(filepath.Join(m.publicationPath, "original.json"), 0644))
			case "proposal-copy":
				must(os.WriteFile(filepath.Join(m.publicationPath, "proposal.json"), []byte("changed proposal"), 0600))
			case "intent-copy":
				must(os.WriteFile(filepath.Join(m.publicationPath, "intent.json"), []byte("changed intent"), 0600))
			case "unexpected-publication-leaf":
				must(os.WriteFile(filepath.Join(m.publicationPath, "extra.json"), []byte("unknown"), 0600))
			case "publication-root-mode":
				must(os.Chmod(m.publicationPath, 0755))
			case "original-content":
				must(os.WriteFile(filepath.Join(m.modulePath, "installed.json"), []byte("changed original"), 0600))
			case "original-mode":
				must(os.Chmod(filepath.Join(m.modulePath, "installed.json"), 0644))
			case "original-inode", "original-symlink":
				retained := filepath.Join(m.modulePath, "retained-original")
				must(os.Rename(filepath.Join(m.modulePath, "installed.json"), retained))
				if fault == "original-symlink" {
					must(os.Symlink(retained, filepath.Join(m.modulePath, "installed.json")))
				} else {
					must(os.WriteFile(filepath.Join(m.modulePath, "installed.json"), m.original, 0600))
				}
			case "existing-candidate":
				must(os.WriteFile(filepath.Join(m.modulePath, ".lbstream-publication-"+p.job+".json"), []byte("unknown candidate"), 0600))
			case "new-target-appears":
				must(os.WriteFile(filepath.Join(m.modulePath, "installed.json"), []byte("foreign new installation"), 0600))
			}
			before, _ := os.ReadFile(filepath.Join(m.modulePath, "installed.json"))
			beforeInfo, _ := os.Lstat(filepath.Join(m.modulePath, "installed.json"))
			if _, err := p.publish(ctx, auth); err == nil || p.done {
				t.Fatal("drift/unknown state became successful publication")
			}
			after, _ := os.ReadFile(filepath.Join(m.modulePath, "installed.json"))
			afterInfo, _ := os.Lstat(filepath.Join(m.modulePath, "installed.json"))
			if !bytes.Equal(before, after) || !geoStoreStableInfo(beforeInfo, afterInfo) {
				t.Fatal("refusal modified or replaced current original")
			}
		})
	}
}

func TestLoadBalanceStreamModuleNativePostEffectRevokeRetainsUnknown(t *testing.T) {
	m := streamModuleNativeFixture(t, true)
	p, err := prepareLoadBalanceStreamModulePublicationAt(context.Background(), m.publication, m.current, m.held, m.seed, m.proposal, streamModuleModelAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	auth := func(context.Context) error {
		raw, err := os.ReadFile(filepath.Join(m.modulePath, "installed.json"))
		if err != nil || bytes.Equal(raw, m.proposal) {
			return errors.New("fixture revoke after atomic publication")
		}
		return nil
	}
	if _, err := p.publish(context.Background(), auth); err == nil || p.done || !p.unknown {
		t.Fatal("post-effect uncertainty became success")
	}
	installed, err := os.ReadFile(filepath.Join(m.modulePath, "installed.json"))
	if err != nil || !bytes.Equal(installed, m.proposal) {
		t.Fatal("uncertain effect was silently reverted")
	}
	if _, err := os.Lstat(filepath.Join(m.publicationPath, "published.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncertain publication invented a completion receipt")
	}
	if _, err := p.publish(context.Background(), streamModuleModelAuthorize); err == nil {
		t.Fatal("unknown original publication replayed")
	}
	seed, _ := loadbalancestream.DecodeInstallationSeed(m.seed)
	old, err := os.ReadFile(filepath.Join(m.modulePath, ".lbstream-publication-"+seed.JobID+".json"))
	if err != nil || !bytes.Equal(old, m.original) {
		t.Fatal("unknown publication discarded exact original inode")
	}
}
