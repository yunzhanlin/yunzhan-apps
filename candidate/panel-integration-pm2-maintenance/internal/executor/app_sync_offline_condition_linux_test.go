//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func offlineConditionFixture(t *testing.T) (*Service, remoteSyncConfig, core.AppModuleInput, string, remoteUnpublishedOfflineCondition) {
	t.Helper()
	s, cfg, in, base := offlineUnpublishedFixture(t, "2.0.0")
	view, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil {
		t.Fatal(err)
	}
	c := remoteUnpublishedOfflineCondition{Format: 1, Target: view.Target, Transaction: view.Transaction, Revision: view.Revision, InstalledRecordSHA: view.InstalledRecordSHA, ConfigSpecSHA: view.ConfigSpecSHA, SnapshotSHA: view.SnapshotSHA, CensusSHA: view.CensusSHA, Confirm: "RETAIN FRAGMENTS " + view.Transaction}
	return s, cfg, in, base, c
}

func TestRemoteUnpublishedOfflineConditionRejectsNonCanonicalInput(t *testing.T) {
	c := remoteUnpublishedOfflineCondition{Format: 1, Target: "owned-target", Transaction: strings.Repeat("a", 32), Revision: 7, InstalledRecordSHA: core.Hash("installed"), ConfigSpecSHA: core.Hash("config"), SnapshotSHA: core.Hash("snapshot"), CensusSHA: core.Hash("census"), Confirm: "RETAIN FRAGMENTS " + strings.Repeat("a", 32)}
	raw, _ := json.Marshal(c)
	decoded, err := decodeUnpublishedOfflineCondition(raw)
	if err != nil || decoded != c {
		t.Fatal("exact complete condition refused", err)
	}
	for name, body := range map[string][]byte{
		"duplicate":       bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1),
		"case-alias":      bytes.Replace(raw, []byte(`"format"`), []byte(`"Format"`), 1),
		"extra-root":      bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"root":"/"`), 1),
		"escaped-key":     bytes.Replace(raw, []byte(`"format"`), []byte(`"\u0066ormat"`), 1),
		"null":            bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":null`), 1),
		"missing":         bytes.Replace(raw, []byte(`"format":1,`), nil, 1),
		"exponent":        bytes.Replace(raw, []byte(`"revision":7`), []byte(`"revision":7e0`), 1),
		"fraction":        bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1.0`), 1),
		"trailing-object": append(append([]byte(nil), raw...), []byte(`{}`)...),
		"oversized":       bytes.Repeat([]byte(" "), 2049),
		"empty-object":    []byte(`{}`),
		"array":           []byte(`[]`),
		"unknown-version": bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":2`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeUnpublishedOfflineCondition(body); err == nil {
				t.Fatal("noncanonical condition was accepted")
			}
		})
	}
}

func TestRemoteUnpublishedOfflineConditionRejectsStaleFieldsWithoutWrites(t *testing.T) {
	for _, kind := range []string{"installation", "config", "snapshot", "census", "revision", "transaction", "confirmation"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _, base, c := offlineConditionFixture(t)
			switch kind {
			case "installation":
				c.InstalledRecordSHA = core.Hash("other installation")
			case "config":
				c.ConfigSpecSHA = core.Hash("other config")
			case "snapshot":
				c.SnapshotSHA = core.Hash("other snapshot")
			case "census":
				c.CensusSHA = core.Hash("other census")
			case "revision":
				c.Revision++
			case "transaction":
				c.Transaction = core.ID()
				c.Confirm = "RETAIN FRAGMENTS " + c.Transaction
			case "confirmation":
				c.Confirm = "COPY BACKUP " + c.Transaction
			}
			if _, err := s.matchUnpublishedOfflineCondition(c); err == nil {
				t.Fatal("changed condition received a recovery observation")
			}
			entries, err := os.ReadDir(base)
			if err != nil || len(entries) != 1 {
				t.Fatal("refusal changed original private namespace", err)
			}
		})
	}
}

func TestRemoteUnpublishedOfflineConditionObservesLostReplyWithoutRewriting(t *testing.T) {
	s, cfg, in, base, c := offlineConditionFixture(t)
	before, err := s.matchUnpublishedOfflineCondition(c)
	if err != nil || before.State != "original-unpublished" || !before.ReadOnly || before.WriterPermitted {
		t.Fatal(before, err)
	}
	in.ExpectedSHA, in.Confirm = c.SnapshotSHA, c.Confirm
	if _, err := s.retainUnpublishedRemoteCopy(cfg, in); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(base, remoteUnpublishedReceipt)
	original, _ := os.Lstat(receipt)
	data, _ := os.ReadFile(receipt)
	for i := 0; i < 2; i++ {
		observed, err := s.matchUnpublishedOfflineCondition(c)
		if err != nil || observed.State != "observed-original-retained-receipt" || observed.OriginalCensus != c.CensusSHA || observed.ObservedCensus == c.CensusSHA || observed.WriterPermitted || !observed.ReadOnly || observed.Review.BackupComplete || observed.Review.Downloadable || observed.Review.SourceAuthority {
			t.Fatal("matched original receipt was rewritten or turned into backup/write authority", observed, err)
		}
	}
	after, _ := os.Lstat(receipt)
	actual, _ := os.ReadFile(receipt)
	if !os.SameFile(original, after) || !bytes.Equal(data, actual) {
		t.Fatal("read-only parent census reconstruction changed on-disk receipt")
	}
	cfg.Revision++
	if err := moduleWrite(s.remoteConfigPath(cfg.ID), cfg); err != nil {
		t.Fatal(err)
	}
	c.Revision++
	if _, err := s.matchUnpublishedOfflineCondition(c); err == nil {
		t.Fatal("receipt from another config revision was adopted")
	}
}

func TestRemoteUnpublishedOfflineConditionRefusesUnselectedOrphan(t *testing.T) {
	s, cfg, in, _, c := offlineConditionFixture(t)
	d, err := s.remoteCopyDirectory(cfg.ID, core.ID(), "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := remoteCopySync(d); err != nil {
		t.Fatal(err)
	}
	d.Close()
	current, err := s.reviewUnpublishedRemoteCopyOffline(in)
	if err != nil {
		t.Fatal(err)
	}
	// Even a newly supplied complete census cannot make one confirmation
	// authorize another original transaction.
	c.CensusSHA = current.CensusSHA
	if _, err := s.matchUnpublishedOfflineCondition(c); err == nil {
		t.Fatal("single-transaction recovery silently admitted another orphan")
	}
	if _, err := s.remoteCopyPending("", ""); err == nil {
		t.Fatal("ordinary complete guard was weakened for a multi-orphan state")
	}
}
