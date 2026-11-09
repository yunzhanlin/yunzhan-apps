//go:build linux

package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamGenerationNativeRoot(t *testing.T) (*os.Root, string, func() bool) {
	t.Helper()
	if os.Getenv("PANEL_NATIVE_QA") != "1" {
		t.Skip("explicit private Root filesystem models only; not original control/service/traffic acceptance")
	}
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		t.Fatal("original Root-only isolated model required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	before, _ := root.Stat(".")
	return root, path, func() bool {
		held, e1 := root.Stat(".")
		visible, e2 := os.Lstat(path)
		return e1 == nil && e2 == nil && memcachedUnixAdminDirectoryInfo(held) && os.SameFile(before, held) && os.SameFile(held, visible)
	}
}

func streamGenerationNativePrefix(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var records [][]byte
	for i := 0; i < 11; i++ {
		evidence := loadbalancestream.ControlAdvanceEvidence{}
		if i == 2 {
			evidence.AccountReceiptSHA256 = strings.Repeat("a", 64)
		}
		if i == 10 {
			evidence.ServiceObservationSHA = strings.Repeat("b", 64)
		}
		value, err := loadbalancestream.NextControlEvent(raw, records, evidence)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, value)
	}
	return records
}

func streamGenerationNativeNext(t *testing.T, raw []byte) []byte {
	t.Helper()
	old, err := loadbalancestream.DecodeControlSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	op := old.Operation
	op.RequestID = core.ID()
	op.Mutation.Action = "replace"
	op.Mutation.ExpectedRevision = old.After[0].Revision
	op.Mutation.ExpectedFingerprint = loadbalancestream.Fingerprint(old.After[0])
	policy := *old.Operation.Mutation.Policy
	policy.MaxSessions++
	op.Mutation.Policy = &policy
	binding := old.Binding
	binding.OperationSHA256 = loadbalancestream.OperationSHA256(op)
	binding.OriginalConfigSHA256 = old.AfterRuntimeSHA256
	facts := loadbalancestream.ServiceFacts{Validation: loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: 64 << 20}, AvailableMemoryBytes: 4 << 30, HardOpenFiles: loadbalancestream.RuntimeOpenFiles, UnifiedMemoryAvailable: true, IPFilterAvailable: true, AccountUID: 991, AccountGID: 991, AccountRecordSHA256: strings.Repeat("a", 64), NginxVersion: "1.30.6", NginxSHA256: strings.Repeat("b", 64)}
	seed, _, err := loadbalancestream.PrepareControlSeed(op, binding, old.After, 0, strings.Repeat("6", 64), facts)
	if err != nil {
		t.Fatal(err)
	}
	next, err := loadbalancestream.ControlSeedBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestLoadBalanceStreamGenerationNativeAtomicOriginalInodeAndClosedLineage(t *testing.T) {
	state, _, stateCurrent := streamGenerationNativeRoot(t)
	seed := streamJournalNativeSeed(t)
	instance := core.ID()
	var previous []byte
	for generation := int64(1); generation <= 3; generation++ {
		pub, pubPath, pubCurrent := streamGenerationNativeRoot(t)
		original, err := holdStreamGenerationFileAt(state, stateCurrent)
		if err != nil || original.missing != (generation == 1) {
			t.Fatal("actual held predecessor refused", err)
		}
		p, err := prepareStreamGenerationPublicationAt(context.Background(), pub, pubCurrent, original, instance, seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize)
		if err != nil {
			t.Fatal("original private generation preparation refused", err)
		}
		if duplicate, err := prepareStreamGenerationPublicationAt(context.Background(), pub, pubCurrent, original, instance, seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize); err == nil || duplicate != nil {
			t.Fatal("publication adopted an existing intent")
		}
		if err := p.publish(context.Background(), streamModuleModelAuthorize); err != nil || !p.done || !p.unknown {
			t.Fatal("original actual atomic generation failed", err)
		}
		if p.publish(context.Background(), streamModuleModelAuthorize) == nil {
			t.Fatal("published original generation replayed")
		}
		current, err := holdStreamGenerationFileAt(state, stateCurrent)
		if err != nil || current.missing {
			t.Fatal("actual current generation missing", err)
		}
		v, err := loadbalancestream.DecodeGenerationRecord(current.raw)
		if err != nil || v.Generation != generation || v.InstallationID != instance {
			t.Fatal("counter or installed instance changed", err)
		}
		actualPrevious, err := checkStreamGenerationPublication(pub, seed, current.raw)
		if err != nil || !bytes.Equal(actualPrevious, previous) {
			t.Fatal("actual original publication lineage refused", err)
		}
		if generation > 1 {
			old, err := pub.Lstat("candidate.json")
			if err != nil || !os.SameFile(original.before, old) {
				t.Fatal("old generation inode lost", err)
			}
			body, err := os.ReadFile(filepath.Join(pubPath, "original.json"))
			if err != nil || !bytes.Equal(body, previous) {
				t.Fatal("complete original backup changed", err)
			}
		}
		if err := os.WriteFile(filepath.Join(pubPath, "unknown.json"), []byte("unknown\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := checkStreamGenerationPublication(pub, seed, current.raw); err == nil {
			t.Fatal("extra unrecorded publication input accepted")
		}
		previous = bytes.Clone(current.raw)
		current.close()
		original.close()
		seed = streamGenerationNativeNext(t, seed)
	}
}

func TestLoadBalanceStreamGenerationNativeUnknownRefusalCannotRestoreAdoptOrRetry(t *testing.T) {
	state, _, stateCurrent := streamGenerationNativeRoot(t)
	pub, pubPath, pubCurrent := streamGenerationNativeRoot(t)
	seed := streamJournalNativeSeed(t)
	original, err := holdStreamGenerationFileAt(state, stateCurrent)
	if err != nil {
		t.Fatal(err)
	}
	defer original.close()
	p, err := prepareStreamGenerationPublicationAt(context.Background(), pub, pubCurrent, original, core.ID(), seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("revoked after actual candidate write")
	denyAfterCandidate := func(context.Context) error {
		if _, err := os.Lstat(filepath.Join(pubPath, "candidate.json")); err == nil {
			return refused
		}
		return nil
	}
	if err := p.publish(context.Background(), denyAfterCandidate); err == nil || !p.unknown || p.done {
		t.Fatal("uncertain original was relabelled complete", err)
	}
	before, err := os.ReadFile(filepath.Join(pubPath, "candidate.json"))
	if err != nil {
		t.Fatal("original uncertain candidate lost", err)
	}
	if p.publish(context.Background(), streamModuleModelAuthorize) == nil {
		t.Fatal("unknown original replayed")
	}
	if q, err := prepareStreamGenerationPublicationAt(context.Background(), pub, pubCurrent, original, core.ID(), seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize); err == nil || q != nil {
		t.Fatal("old uncertain publication adopted")
	}
	after, err := os.ReadFile(filepath.Join(pubPath, "candidate.json"))
	if err != nil || !bytes.Equal(before, after) || !original.current() {
		t.Fatal("refusal retried, restored or removed original files", err)
	}
}

func TestLoadBalanceStreamGenerationNativeCopiedOldInodeAndWrongInstanceRefuse(t *testing.T) {
	state, _, stateCurrent := streamGenerationNativeRoot(t)
	seed := streamJournalNativeSeed(t)
	instance := core.ID()
	firstPub, _, firstCurrent := streamGenerationNativeRoot(t)
	missing, err := holdStreamGenerationFileAt(state, stateCurrent)
	if err != nil {
		t.Fatal(err)
	}
	defer missing.close()
	p, err := prepareStreamGenerationPublicationAt(context.Background(), firstPub, firstCurrent, missing, instance, seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize)
	if err != nil || p.publish(context.Background(), streamModuleModelAuthorize) != nil {
		t.Fatal("fresh isolated original refused", err)
	}
	seed = streamGenerationNativeNext(t, seed)
	old, err := holdStreamGenerationFileAt(state, stateCurrent)
	if err != nil {
		t.Fatal(err)
	}
	defer old.close()
	pub, path, current := streamGenerationNativeRoot(t)
	if wrong, err := prepareStreamGenerationPublicationAt(context.Background(), pub, current, old, core.ID(), seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize); err == nil || wrong != nil {
		t.Fatal("foreign installation adopted current generation")
	}
	p, err = prepareStreamGenerationPublicationAt(context.Background(), pub, current, old, instance, seed, streamGenerationNativePrefix(t, seed), streamModuleModelAuthorize)
	if err != nil || p.publish(context.Background(), streamModuleModelAuthorize) != nil {
		t.Fatal("second original generation refused", err)
	}
	retained, err := pub.Lstat("candidate.json")
	if err != nil {
		t.Fatal(err)
	}
	// Replace ONLY this new private fixture's retained inode with identical
	// bytes/mode/mtime. The historical checker must not accept that copy.
	copyPath := filepath.Join(path, "copy.json")
	if err := os.WriteFile(copyPath, old.raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(copyPath, retained.ModTime(), retained.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(copyPath, filepath.Join(path, "candidate.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := checkStreamGenerationPublication(pub, seed, p.proposal); err == nil {
		t.Fatal("new inode with identical bytes/mtime adopted as original predecessor")
	}
}
