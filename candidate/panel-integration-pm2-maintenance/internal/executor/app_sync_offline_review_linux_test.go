//go:build linux

package executor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func offlineUnpublishedFixture(t *testing.T, version string) (*Service, remoteSyncConfig, core.AppModuleInput, string) {
	t.Helper()
	s, cfg, in, base := unpublishedFixture(t, []byte(`{"source":"opaque, not an archive identity",`))
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Target = core.RemoteSyncTarget{Address: "127.0.0.1", Port: 1, Username: "owned_sftp", Root: "/srv/owned/public", BackupRoot: "/srv/owned/backup", HostKey: string(ssh.MarshalAuthorizedKey(key))}
	cfg.SpecSHA, cfg.AuthKind, cfg.Cipher = remoteSpecSHA(cfg.Target), "private-key", []byte("opaque-credential-must-never-be-returned")
	if err := moduleWrite(s.remoteConfigPath(cfg.ID), cfg); err != nil {
		t.Fatal(err)
	}
	if err := moduleWrite(filepath.Join(s.moduleDir("files-sync"), "installed.json"), map[string]any{"id": "files-sync", "version": version, "settings": map[string]any{"enabled": false}, "installed_at": "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	in.Confirm = ""
	return s, cfg, in, base
}

func TestRemoteUnpublishedOfflineReviewReadsOld200WithoutGrantingWrites(t *testing.T) {
	s, cfg, in, base := offlineUnpublishedFixture(t, "2.0.0")
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	part := filepath.Join(base, entries[0].Name())
	before, _ := os.Lstat(part)
	data, _ := os.ReadFile(part)
	installedPath := filepath.Join(s.moduleDir("files-sync"), "installed.json")
	installedBefore, _ := os.Lstat(installedPath)
	installedBytes, _ := os.ReadFile(installedPath)
	view, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil {
		t.Fatal(err)
	}
	if view.InstalledVersion != "2.0.0" || view.Target != cfg.ID || view.Transaction != in.ResourceID || view.Revision != cfg.Revision || view.ConfigSpecSHA != cfg.SpecSHA || !view.ReadOnly || !view.NeedsWriterBarrier || view.BackupComplete || view.SourceAuthority || view.Downloadable || !coreSHA.MatchString(view.CensusSHA) || !coreSHA.MatchString(view.InstalledRecordSHA) {
		t.Fatal("read-only old installation review became a mutation permit", view)
	}
	again, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil || !reflect.DeepEqual(view, again) {
		t.Fatal("read-only review was unstable without any source change", err)
	}
	raw, _ := json.Marshal(view)
	if bytes.Contains(raw, cfg.Cipher) || bytes.Contains(raw, data) {
		t.Fatal("review disclosed a credential or interpreted original fragment content")
	}
	after, _ := os.Lstat(part)
	actual, _ := os.ReadFile(part)
	installedAfter, _ := os.Lstat(installedPath)
	installedActual, _ := os.ReadFile(installedPath)
	entries, _ = os.ReadDir(base)
	if !os.SameFile(before, after) || !bytes.Equal(data, actual) || !os.SameFile(installedBefore, installedAfter) || !bytes.Equal(installedBytes, installedActual) || len(entries) != 1 {
		t.Fatal("offline review changed original bytes, installation or namespace")
	}
	if _, err := s.remoteCopyPending("", ""); err == nil {
		t.Fatal("read-only review weakened the ordinary pending-copy guard")
	}
}

func TestRemoteUnpublishedOfflineReviewBindsWholeCensusAndReceiptState(t *testing.T) {
	s, cfg, in, _ := offlineUnpublishedFixture(t, "2.0.1")
	first, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil {
		t.Fatal(err)
	}
	other := core.ID()
	d, err := s.remoteCopyDirectory(cfg.ID, other, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteCopySync(d); err != nil {
		t.Fatal(err)
	}
	d.Close()
	second, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil || second.SnapshotSHA != first.SnapshotSHA || second.CensusSHA == first.CensusSHA || second.GlobalCopies != first.GlobalCopies+1 {
		t.Fatal("unrelated original namespace omitted from full census", second, err)
	}
	retain := in
	retain.ExpectedSHA, retain.Confirm = second.SnapshotSHA, "RETAIN FRAGMENTS "+in.ResourceID
	if _, err := s.retainUnpublishedRemoteCopy(cfg, retain); err != nil {
		t.Fatal(err)
	}
	third, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil || third.SnapshotSHA != second.SnapshotSHA || third.CensusSHA == second.CensusSHA || third.UnpublishedRecord["fragment_state"] != "unpublished-retained" || third.MetadataBytes <= second.MetadataBytes || !third.NeedsWriterBarrier {
		t.Fatal("retention state omitted from census or treated as a fresh write permit", third, err)
	}
}

func TestRemoteUnpublishedOfflineReviewRejectsStaleScopeAndUnsafeInventory(t *testing.T) {
	for _, kind := range []string{"old-version", "future-version", "stale-revision", "wrong-transaction", "unknown-entry", "symbolic-link", "hard-link", "malformed-master"} {
		t.Run(kind, func(t *testing.T) {
			version := "2.0.0"
			if kind == "old-version" {
				version = "1.9.0"
			} else if kind == "future-version" {
				version = "2.0.2"
			}
			s, _, in, base := offlineUnpublishedFixture(t, version)
			switch kind {
			case "stale-revision":
				in.ExpectedRevision++
			case "wrong-transaction":
				in.ResourceID = core.ID()
			case "unknown-entry":
				if err := os.WriteFile(filepath.Join(base, "unknown"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symbolic-link", "hard-link":
				outside := filepath.Join(t.TempDir(), "keep")
				if err := os.WriteFile(outside, []byte("original outside"), 0600); err != nil {
					t.Fatal(err)
				}
				name := filepath.Join(base, "record-"+core.ID()+".part")
				var err error
				if kind == "symbolic-link" {
					err = os.Symlink(outside, name)
				} else {
					err = os.Link(outside, name)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "malformed-master":
				if err := os.WriteFile(filepath.Join(base, "intent.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.reviewUnpublishedRemoteCopyOffline(in); err == nil {
				t.Fatal("unsafe or stale original state admitted")
			}
			if _, err := os.Lstat(filepath.Join(base, remoteUnpublishedReceipt)); !os.IsNotExist(err) {
				t.Fatal("read-only refusal created a receipt", err)
			}
		})
	}
}
