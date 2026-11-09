//go:build linux

package executor

import (
	"bytes"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
)

// A successful recovery remains a mandatory historical anchor. Later normal
// configuration/rule saves must prove every committed +1 transition, its exact
// action/input/time binding, and the final two live files. A higher number or a
// successful start/stop alone is never new recovery or drain authority.
type programQueueIDSLineageTip struct {
	revision int64
	yaml     []byte
	config   []byte
}

func programQueueIDSRecoveryLineage(records []threatIDSOperationRecord, transactions []wafTransaction, now time.Time) (*programQueueIDSLineageTip, error) {
	base, err := programQueueIDSRecoveryRevision(records, now)
	if err != nil || base == 0 {
		return nil, err
	}
	var lastDecline, anchor time.Time
	identities := map[string]bool{}
	for _, record := range records {
		o := record.Operation
		if identities[o.ID] {
			return nil, errors.New("IDS recovery lineage has duplicate operation identities; upgrade refused")
		}
		identities[o.ID] = true
		if o.State == "needs-attention" {
			at, _ := time.Parse(time.RFC3339Nano, o.UpdatedAt)
			if at.After(lastDecline) {
				lastDecline = at
			}
		}
	}
	for _, record := range records {
		o := record.Operation
		created, _ := time.Parse(time.RFC3339Nano, o.CreatedAt)
		updated, _ := time.Parse(time.RFC3339Nano, o.UpdatedAt)
		if o.Action == "ids-recover" && o.State == "succeeded" && o.Input.ExpectedRevision == base && created.After(lastDecline) && updated.After(anchor) {
			anchor = updated
		}
	}
	if anchor.IsZero() {
		return nil, errors.New("IDS recovery lineage lacks the original explicit anchor; upgrade refused")
	}
	operations := map[string]core.NetworkIDSOperation{}
	for _, record := range records {
		o := record.Operation
		created, _ := time.Parse(time.RFC3339Nano, o.CreatedAt)
		if o.State == "succeeded" && (o.Action == "ids-config" || o.Action == "ids-rules") && !created.Before(anchor) && o.Input.ExpectedRevision >= base {
			operations[o.ID] = o
		}
	}
	type edge struct {
		old, next threatIDSConfig
		tx        wafTransaction
		created   time.Time
		finished  time.Time
	}
	edges := map[int64]edge{}
	used := map[string]bool{}
	for _, tx := range transactions {
		at, timeErr := time.Parse(time.RFC3339Nano, tx.CreatedAt)
		if tx.Format != 2 || !core.ValidID(tx.ID) || (tx.State != "committed" && tx.State != "recovered") || timeErr != nil || at.Year() < 2000 || at.After(now) || validateThreatIDSJournal(tx) != nil {
			return nil, errors.New("IDS recovery lineage has invalid retained configuration history; upgrade refused")
		}
		var old, next threatIDSConfig
		if !tx.Changes[1].OldExists {
			continue
		}
		if decodeThreatIDSPrivateJSON(tx.Changes[1].OldData, &old) != nil || decodeThreatIDSPrivateJSON(tx.Changes[1].NextData, &next) != nil {
			return nil, errors.New("IDS recovery lineage configuration bytes cannot be decoded; upgrade refused")
		}
		if tx.State != "committed" || old.Revision < base || at.Before(anchor) {
			continue
		}
		matched := ""
		for id, o := range operations {
			created, _ := time.Parse(time.RFC3339Nano, o.CreatedAt)
			updated, _ := time.Parse(time.RFC3339Nano, o.UpdatedAt)
			if o.Input.ExpectedRevision != old.Revision || at.Before(created) || at.After(updated) || !programQueueIDSLineageAction(o, old, next) {
				continue
			}
			if matched != "" {
				return nil, errors.New("IDS recovery lineage action binding is ambiguous; upgrade refused")
			}
			matched = id
		}
		if matched == "" || used[matched] {
			return nil, errors.New("IDS recovery lineage lacks a unique successful configuration action; upgrade refused")
		}
		if _, duplicate := edges[old.Revision]; duplicate {
			return nil, errors.New("IDS recovery lineage has conflicting committed branches; upgrade refused")
		}
		used[matched] = true
		created, _ := time.Parse(time.RFC3339Nano, operations[matched].CreatedAt)
		finished, _ := time.Parse(time.RFC3339Nano, operations[matched].UpdatedAt)
		edges[old.Revision] = edge{old: old, next: next, tx: tx, created: created, finished: finished}
	}
	if len(used) != len(operations) {
		return nil, errors.New("IDS recovery lineage has a successful action without its committed transaction; upgrade refused")
	}
	var previous *wafTransaction
	var tip *programQueueIDSLineageTip
	revision, visited := base, 0
	finished := anchor
	for {
		e, exists := edges[revision]
		if !exists {
			break
		}
		if e.created.Before(finished) {
			return nil, errors.New("IDS recovery lineage operation order is inconsistent; upgrade refused")
		}
		if previous != nil {
			for i := 0; i < 2; i++ {
				if !bytes.Equal(previous.Changes[i].NextData, e.tx.Changes[i].OldData) || previous.Changes[i].NextMode != e.tx.Changes[i].OldMode || !reflect.DeepEqual(previous.Changes[i].NextOwner, e.tx.Changes[i].OldOwner) {
					return nil, errors.New("IDS recovery lineage has changed intermediate configuration identity; upgrade refused")
				}
			}
		}
		if e.next.Revision != revision+1 {
			return nil, errors.New("IDS recovery lineage skips a configuration revision; upgrade refused")
		}
		revision, visited = e.next.Revision, visited+1
		finished = e.finished
		copy := e.tx
		previous = &copy
		tip = &programQueueIDSLineageTip{revision: revision, yaml: copy.Changes[0].NextData, config: copy.Changes[1].NextData}
	}
	if visited != len(edges) {
		return nil, errors.New("IDS recovery lineage is incomplete; upgrade refused")
	}
	return tip, nil
}

func programQueueIDSLineageAction(o core.NetworkIDSOperation, old, next threatIDSConfig) bool {
	want := old
	want.Revision++
	switch o.Action {
	case "ids-config":
		want.Interface = o.Input.Interface
		want.HomeNetworks = append([]string{}, o.Input.HomeNetworks...)
		want.CaptureFormat, want.CaptureMTU = 1, next.CaptureMTU
	case "ids-rules":
		if o.Input.RuleProfile == nil || core.ValidateNetworkIDSRuleProfile(*o.Input.RuleProfile) != nil {
			return false
		}
		want.RuleFeed = nil
		if o.Input.RuleProfile.Selection != nil {
			selection := *o.Input.RuleProfile.Selection
			want.RuleFeed = &selection
		}
	default:
		return false
	}
	return validateThreatIDSConfig(next) == nil && reflect.DeepEqual(want, next)
}

func (r *programQueueReader) idsRecoveryCurrentConfiguration(tip programQueueIDSLineageTip) error {
	relative := "etc/panel/security-apps/modules/network-threat-detection"
	root, err := r.queueDirectory(relative, false)
	if err != nil || root == nil {
		return errors.New("IDS recovery lineage current configuration directory is unavailable; upgrade refused")
	}
	raw, err := r.record(root, relative, "ids-config.json", 16<<10)
	root.Close()
	if err != nil || !bytes.Equal(raw, tip.config) {
		return errors.New("IDS recovery lineage differs from current configuration bytes; upgrade refused")
	}
	relative = "etc/panel/network-ids"
	root, err = r.queueDirectory(relative, false)
	if err != nil || root == nil {
		return errors.New("IDS recovery lineage current native directory is unavailable; upgrade refused")
	}
	defer root.Close()
	const name = "suricata.yaml"
	before, err := root.Lstat(name)
	if err != nil || before.Mode() != 0644 {
		return errors.New("IDS recovery lineage native file mode cannot be verified; upgrade refused")
	}
	identity, ok := before.Sys().(*syscall.Stat_t)
	if !ok || identity.Uid != 0 || identity.Nlink != 1 || before.Size() < 1 || before.Size() > 128<<10 {
		return errors.New("IDS recovery lineage native file identity cannot be verified; upgrade refused")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !programQueueSame(before, opened) {
		return errors.New("IDS recovery lineage native file changed before read; upgrade refused")
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	after, statErr := f.Stat()
	visible, pathErr := root.Lstat(name)
	if readErr != nil || statErr != nil || pathErr != nil || !programQueueSame(before, after) || !programQueueSame(after, visible) || !bytes.Equal(data, tip.yaml) {
		return errors.New("IDS recovery lineage native file changed or differs from committed bytes; upgrade refused")
	}
	r.bytes += len(data)
	if r.bytes > 16<<20 {
		return errors.New("program queue complete read exceeds byte budget")
	}
	r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, name), after})
	return r.ctx.Err()
}
