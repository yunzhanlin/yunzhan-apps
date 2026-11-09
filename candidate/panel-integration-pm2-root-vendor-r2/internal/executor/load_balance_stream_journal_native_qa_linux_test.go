//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamJournalNativeFixture(t *testing.T) string {
	t.Helper()
	anchor := os.Getenv("PANEL_LBSTREAM_JOURNAL_QA_ROOT")
	if anchor == "" {
		t.Skip("explicit isolated Root journal filesystem models only; no controller or service acceptance")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/lbstream-journal-native24bmax-(amd64|arm64)\.[a-f0-9]{32}$`).MatchString(anchor) ||
		threatIDSTrustedParents(anchor, false) != nil || os.TempDir() != anchor+"/tmp" {
		t.Fatal("actual closed isolated Root journal fixture required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func streamJournalNativeSeed(t *testing.T) []byte {
	t.Helper()
	facts := loadbalancestream.ServiceFacts{
		Validation:           loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: 64 << 20},
		AvailableMemoryBytes: 4 << 30, HardOpenFiles: loadbalancestream.RuntimeOpenFiles,
		UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: 991, AccountGID: 991,
		AccountRecordSHA256: strings.Repeat("a", 64), NginxVersion: "1.30.6", NginxSHA256: strings.Repeat("b", 64),
	}
	op := loadbalancestream.Operation{Format: 1, Kind: loadbalancestream.OperationKind, RequestID: core.ID(), ActorID: core.ID(),
		Mutation: loadbalancestream.Mutation{Format: 1, Action: "create", Name: "db.lb.invalid", Policy: &loadbalancestream.Policy{
			Protocol: "tcp", Port: 42000, Nodes: []loadbalancestream.Node{{Address: "192.0.2.10:41001", Weight: 1}, {Address: "192.0.2.11:41002", Weight: 3}},
			Method: "round-robin", ConnectMilliseconds: 2000, SessionSeconds: 30, MaxSessions: 64,
		}}}
	prior, err := loadbalancestream.RenderRuntime([]loadbalancestream.Entry{}, loadbalancestream.ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		t.Fatal(err)
	}
	binding := loadbalancestream.OperationBinding{Format: 1, AppID: "load-balance", AppVersion: loadbalancestream.AppVersion, OperationSHA256: loadbalancestream.OperationSHA256(op),
		ManifestSHA256: strings.Repeat("1", 64), InstalledSHA256: strings.Repeat("2", 64), ProgrammeInputs: strings.Repeat("3", 64), ActorObservationSHA: strings.Repeat("4", 64), OriginalConfigSHA256: prior.SHA256}
	binding.OriginalRequestSHA256 = strings.Repeat("9", 64)
	seed, _, err := loadbalancestream.PrepareControlSeed(op, binding, []loadbalancestream.Entry{}, 43000, strings.Repeat("6", 64), facts)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := loadbalancestream.ControlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func streamJournalNativeReadFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		b, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = b
	}
	return out
}

func TestLoadBalanceStreamJournalNativeOriginalDurableChainAndReadOnlyExisting(t *testing.T) {
	parent, raw := streamJournalNativeFixture(t), streamJournalNativeSeed(t)
	j, err := createLoadBalanceStreamJournalAt(context.Background(), parent, raw)
	if err != nil {
		t.Fatal("new exclusive journal refused", err)
	}
	defer j.close()
	seed, records, chain, err := j.original(context.Background())
	if err != nil || !bytes.Equal(raw, seed) || len(records) != 1 || !chain.OriginalUnknown || chain.Complete {
		t.Fatal("original prepared history not unknown", chain, err)
	}
	decoded, _ := loadbalancestream.DecodeControlSeed(raw)
	reader, err := openLoadBalanceStreamJournalReadOnlyAt(parent, decoded.Operation.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.close()
	before := streamJournalNativeReadFiles(t, j.path)
	if reader.appendOriginal(context.Background(), loadbalancestream.ControlAdvanceEvidence{}) == nil {
		t.Fatal("existing partial journal gained mutation/recovery authority")
	}
	if other, err := createLoadBalanceStreamJournalAt(context.Background(), parent, raw); err == nil || other != nil {
		t.Fatal("duplicate original request adopted or restarted")
	}
	for name, b := range before {
		current, err := os.ReadFile(filepath.Join(j.path, name))
		if err != nil || !bytes.Equal(b, current) {
			t.Fatal("read-only/duplicate attempt changed original", name, err)
		}
	}
	lock, err := os.OpenFile(filepath.Join(j.path, "run.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		lock.Close()
		t.Fatal("original exclusive lease was not held")
	}
	lock.Close()
	for sequence := 1; sequence < 12; sequence++ {
		evidence := loadbalancestream.ControlAdvanceEvidence{}
		if sequence == 2 {
			evidence.AccountReceiptSHA256 = strings.Repeat("7", 64)
		}
		if sequence == 10 {
			evidence.ServiceObservationSHA = strings.Repeat("8", 64)
		}
		if err := j.appendOriginal(context.Background(), evidence); err != nil {
			t.Fatal("new creator could not durably append original exact phase", sequence, err)
		}
	}
	_, records, chain, err = j.original(context.Background())
	if err != nil || len(records) != 12 || !chain.Complete || chain.OriginalUnknown || j.unknown {
		t.Fatal("complete original chain not confirmed", chain, err)
	}
	if j.appendOriginal(context.Background(), loadbalancestream.ControlAdvanceEvidence{}) == nil {
		t.Fatal("completed operation appended a new operation")
	}
	if got := len(streamJournalNativeReadFiles(t, j.path)); got != 14 {
		t.Fatal("unexpected completed journal member count", got)
	}
}

func TestLoadBalanceStreamJournalNativeOriginalInodesAndShapeFailClosed(t *testing.T) {
	for _, fault := range []string{"directory-mode", "unknown-entry", "missing-event", "event-gap", "event-mode", "event-directory", "event-fifo", "event-symlink", "event-hardlink", "event-oversize", "same-byte-replacement", "same-byte-seed-replacement", "lock-replacement", "cancelled", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			parent, raw := streamJournalNativeFixture(t), streamJournalNativeSeed(t)
			j, err := createLoadBalanceStreamJournalAt(context.Background(), parent, raw)
			if err != nil {
				t.Fatal(err)
			}
			defer j.close()
			event := filepath.Join(j.path, "event-0000.json")
			ctx := context.Background()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "directory-mode":
				must(os.Chmod(j.path, 0755))
			case "unknown-entry":
				must(os.WriteFile(filepath.Join(j.path, "foreign.json"), []byte("foreign"), 0600))
			case "missing-event":
				must(os.Rename(event, filepath.Join(parent, "retained-event.json")))
			case "event-gap":
				must(os.Rename(event, filepath.Join(j.path, "event-0001.json")))
			case "event-mode":
				must(os.Chmod(event, 0644))
			case "event-directory", "event-fifo", "event-symlink", "event-hardlink":
				retained := filepath.Join(parent, "retained-event.json")
				must(os.Rename(event, retained))
				if fault == "event-directory" {
					must(os.Mkdir(event, 0700))
				}
				if fault == "event-fifo" {
					must(syscall.Mkfifo(event, 0600))
				}
				if fault == "event-symlink" {
					must(os.Symlink(retained, event))
				}
				if fault == "event-hardlink" {
					must(os.Link(retained, event))
				}
			case "event-oversize":
				must(os.WriteFile(event, bytes.Repeat([]byte("x"), 2049), 0600))
			case "same-byte-replacement", "same-byte-seed-replacement", "lock-replacement":
				target := event
				if fault == "same-byte-seed-replacement" {
					target = filepath.Join(j.path, "seed.json")
				}
				if fault == "lock-replacement" {
					target = filepath.Join(j.path, "run.lock")
				}
				b, err := os.ReadFile(target)
				must(err)
				must(os.WriteFile(filepath.Join(parent, "replacement"), b, 0600))
				must(os.Rename(filepath.Join(parent, "replacement"), target))
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "unknown":
				j.unknown = true
			}
			if err := j.appendOriginal(ctx, loadbalancestream.ControlAdvanceEvidence{}); err == nil {
				t.Fatal("unverified original journal gained append authority", fault)
			}
			if _, err := os.Lstat(filepath.Join(j.path, "event-0001.json")); fault != "event-gap" && !os.IsNotExist(err) {
				t.Fatal("refused append created another event", fault, err)
			}
		})
	}
}

func TestLoadBalanceStreamJournalNativeCancelledCreationDoesNotStage(t *testing.T) {
	parent, raw := streamJournalNativeFixture(t), streamJournalNativeSeed(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if j, err := createLoadBalanceStreamJournalAt(ctx, parent, raw); err == nil || j != nil {
		t.Fatal("cancelled creation staged a request")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled creation changed fixture anchor", entries, err)
	}
}
