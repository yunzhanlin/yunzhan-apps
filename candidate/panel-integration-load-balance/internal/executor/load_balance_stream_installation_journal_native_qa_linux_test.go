//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamInstallationJournalNativeFixture(t *testing.T) string {
	t.Helper()
	anchor := os.Getenv("PANEL_LBSTREAM_INSTALL_JOURNAL_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit isolated Root installation-journal models only; not actual installation or service acceptance")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 ||
		!regexp.MustCompile(`^/var/lib/panel-executor/lbstream-install-journal-native24bmeg-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) ||
		threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("closed trusted isolated Root fixture required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

// These three bounded fake buffers are deliberately NOT signed authority.
// Filesystem serialization may retain them, but the compiled-key authority
// verifier must refuse them. No existing module or account is touched.
func streamInstallationJournalNativeSeed(t *testing.T, action string) ([]byte, []byte) {
	t.Helper()
	envelope := appcatalog.LoadBalanceStreamReleaseEnvelope{Catalog: []byte(`{"fixture_only":true}`), Signature: []byte("not-a-signature"), AppManifest: []byte(`{"fixture_only":true}`)}
	submission, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := loadbalancestream.RenderRuntime([]loadbalancestream.Entry{}, loadbalancestream.ServiceRuntimePrefix,
		loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil {
		t.Fatal(err)
	}
	seed := loadbalancestream.InstallationSeed{Format: 1, Nonce: core.ID(), JobID: core.ID(), ActorID: core.ID(), Action: action,
		AppVersion: loadbalancestream.AppVersion, AccessRevision: 1, ActorObservationSHA256: strings.Repeat("1", 64),
		ManifestSHA256: core.Hash(string(envelope.AppManifest)), OriginalRequestSHA256: strings.Repeat("2", 64), KeySHA256: strings.Repeat("3", 64),
		JobCreatedAt: "2026-10-25T00:00:00Z", CatalogSHA256: core.Hash(string(envelope.Catalog)), SubmissionSHA256: core.Hash(string(submission)),
		ProgrammeInputsSHA256: strings.Repeat("4", 64), EmptyConfigurationSHA: empty.SHA256}
	payload := `{"settings":{},"version":"` + loadbalancestream.AppVersion + `"}`
	if action == "update" {
		seed.OriginalModuleVersion, seed.OriginalModuleSHA256 = "1.8.5", strings.Repeat("5", 64)
		payload = `{"settings":null,"version":"` + loadbalancestream.AppVersion + `"}`
	}
	seed.PayloadSHA256 = core.Hash(payload)
	raw, err := loadbalancestream.InstallationSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	return raw, submission
}

func streamInstallationJournalNativeFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = raw
	}
	return files
}

func TestLoadBalanceStreamInstallationJournalNativeOriginalLeaseAndDurablePhases(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			parent := streamInstallationJournalNativeFixture(t)
			raw, submission := streamInstallationJournalNativeSeed(t, action)
			j, err := createLoadBalanceStreamInstallationJournalAt(context.Background(), parent, raw, submission)
			if err != nil {
				t.Fatal("new exclusive installation journal refused", err)
			}
			defer j.close()
			seed, records, chain, err := j.original(context.Background())
			if err != nil || !bytes.Equal(seed, raw) || len(records) != 1 || chain.Complete || !chain.OriginalUnknown {
				t.Fatal("prepared original installation not unknown", chain, err)
			}
			decoded, _ := loadbalancestream.DecodeInstallationSeed(raw)
			reader, err := openLoadBalanceStreamInstallationJournalReadOnlyAt(parent, decoded.JobID)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.close()
			before := streamInstallationJournalNativeFiles(t, j.path)
			if reader.appendOriginal(context.Background(), loadbalancestream.InstallationEvidence{}) == nil {
				t.Fatal("existing incomplete installation gained mutation/recovery authority")
			}
			if duplicate, err := createLoadBalanceStreamInstallationJournalAt(context.Background(), parent, raw, submission); err == nil || duplicate != nil {
				t.Fatal("old original installation adopted or replayed")
			}
			if authority, err := j.officialAuthority(context.Background()); err == nil || authority.Matches(decoded.AppVersion, decoded.ManifestSHA256) {
				t.Fatal("fake serialization fixture became official signed authority")
			}
			for name, original := range before {
				current, err := os.ReadFile(filepath.Join(j.path, name))
				if err != nil || !bytes.Equal(current, original) {
					t.Fatal("read-only/duplicate/invalid-signature check changed original", name, err)
				}
			}
			lease, err := os.OpenFile(filepath.Join(j.path, "run.lock"), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := syscall.Flock(int(lease.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
				lease.Close()
				t.Fatal("original installation run lease not held")
			}
			lease.Close()
			for sequence := 1; sequence < loadbalancestream.InstallationPhaseCount; sequence++ {
				evidence := loadbalancestream.InstallationEvidence{}
				if sequence == 2 {
					evidence.AccountReceiptSHA256 = strings.Repeat("6", 64)
				}
				if sequence == 4 {
					evidence.PublishedModuleSHA256 = strings.Repeat("7", 64)
				}
				if err := j.appendOriginal(context.Background(), evidence); err != nil {
					t.Fatal("new creator could not durably append exact installation phase", sequence, err)
				}
			}
			_, records, chain, err = j.original(context.Background())
			if err != nil || len(records) != loadbalancestream.InstallationPhaseCount || !chain.Complete || chain.OriginalUnknown || j.unknown {
				t.Fatal("terminal original installation history not complete", chain, err)
			}
			if j.appendOriginal(context.Background(), loadbalancestream.InstallationEvidence{}) == nil || len(streamInstallationJournalNativeFiles(t, j.path)) != 9 {
				t.Fatal("terminal installation accepted another event or lost original files")
			}
			if _, _, _, err := reader.original(context.Background()); err == nil {
				t.Fatal("old held directory silently adopted later file identity")
			}
		})
	}
}

func TestLoadBalanceStreamInstallationJournalNativeOriginalIdentityAndShapeRefuse(t *testing.T) {
	for _, fault := range []string{"directory-mode", "unknown-entry", "missing-event", "event-gap", "event-mode", "event-directory", "event-fifo", "event-symlink", "event-hardlink", "event-oversize", "event-replacement", "seed-replacement", "submission-replacement", "submission-mode", "submission-bytes", "lock-replacement", "cancelled", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			parent := streamInstallationJournalNativeFixture(t)
			raw, submission := streamInstallationJournalNativeSeed(t, "install")
			j, err := createLoadBalanceStreamInstallationJournalAt(context.Background(), parent, raw, submission)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			event := filepath.Join(j.path, "event-0000.json")
			ctx := context.Background()
			switch fault {
			case "directory-mode":
				must(os.Chmod(j.path, 0755))
			case "unknown-entry":
				must(os.WriteFile(filepath.Join(j.path, "unknown.json"), []byte("unknown"), 0600))
			case "missing-event":
				must(os.Rename(event, filepath.Join(parent, "retained-event")))
			case "event-gap":
				must(os.Rename(event, filepath.Join(j.path, "event-0001.json")))
			case "event-mode":
				must(os.Chmod(event, 0644))
			case "event-directory", "event-fifo", "event-symlink", "event-hardlink":
				retained := filepath.Join(parent, "retained-event")
				must(os.Rename(event, retained))
				switch fault {
				case "event-directory":
					must(os.Mkdir(event, 0700))
				case "event-fifo":
					must(syscall.Mkfifo(event, 0600))
				case "event-symlink":
					must(os.Symlink(retained, event))
				case "event-hardlink":
					must(os.Link(retained, event))
				}
			case "event-oversize":
				must(os.WriteFile(event, bytes.Repeat([]byte("x"), 2049), 0600))
			case "event-replacement", "seed-replacement", "submission-replacement", "lock-replacement":
				target := event
				if fault == "seed-replacement" {
					target = filepath.Join(j.path, "seed.json")
				}
				if fault == "submission-replacement" {
					target = filepath.Join(j.path, "submission.json")
				}
				if fault == "lock-replacement" {
					target = filepath.Join(j.path, "run.lock")
				}
				original, err := os.ReadFile(target)
				must(err)
				must(os.WriteFile(filepath.Join(parent, "replacement"), original, 0600))
				must(os.Rename(filepath.Join(parent, "replacement"), target))
			case "submission-mode":
				must(os.Chmod(filepath.Join(j.path, "submission.json"), 0644))
			case "submission-bytes":
				must(os.WriteFile(filepath.Join(j.path, "submission.json"), []byte(`{}`), 0600))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unknown":
				j.unknown = true
			}
			if j.appendOriginal(ctx, loadbalancestream.InstallationEvidence{}) == nil {
				t.Fatal("changed or unknown original installation gained append authority", fault)
			}
			if _, err := os.Lstat(filepath.Join(j.path, "event-0001.json")); fault != "event-gap" && !os.IsNotExist(err) {
				t.Fatal("refusal created another installation phase", fault, err)
			}
		})
	}
}

func TestLoadBalanceStreamInstallationJournalNativeInvalidCreationRetainsAnchor(t *testing.T) {
	for _, fault := range []string{"cancelled", "submission-hash", "submission-type", "unsafe-anchor", "retained-limit"} {
		t.Run(fault, func(t *testing.T) {
			parent := streamInstallationJournalNativeFixture(t)
			raw, submission := streamInstallationJournalNativeSeed(t, "install")
			ctx := context.Background()
			switch fault {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "submission-hash":
				submission = append(bytes.Clone(submission), ' ')
			case "submission-type":
				submission = []byte(`{}`)
				seed, _ := loadbalancestream.DecodeInstallationSeed(raw)
				seed.SubmissionSHA256 = core.Hash(string(submission))
				raw, _ = loadbalancestream.InstallationSeedBytes(seed)
			case "unsafe-anchor":
				if err := os.Chmod(parent, 0755); err != nil {
					t.Fatal(err)
				}
			case "retained-limit":
				for i := 0; i < 128; i++ {
					if err := os.Mkdir(filepath.Join(parent, core.ID()), 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if j, err := createLoadBalanceStreamInstallationJournalAt(ctx, parent, raw, submission); err == nil || j != nil {
				t.Fatal("invalid creation gained a new original case", fault)
			}
			after, err := os.ReadDir(parent)
			if err != nil || len(before) != len(after) {
				t.Fatal("refused creation modified anchor", fault, err)
			}
			for i := range before {
				if before[i].Name() != after[i].Name() {
					t.Fatal("original retained case removed or replaced")
				}
			}
		})
	}
}
