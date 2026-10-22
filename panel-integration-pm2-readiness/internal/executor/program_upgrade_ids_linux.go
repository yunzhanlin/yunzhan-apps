//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// An old pre-mutation decline stays needs-attention forever in its original
// receipt. This reader proves only present upgrade quiescence, NOT that the
// declined operation succeeded. Unknown/partially executed failures still
// block; there is no force/ack flag or writable acknowledgement record.
func (r *programQueueReader) idsOperations(scope func(context.Context, string, int64) (io.Closer, error)) error {
	var records []threatIDSOperationRecord
	err := r.records("var/lib/panel-executor/network-ids-operations", 128, 48<<10, func(id string, data []byte) error {
		var v threatIDSOperationRecord
		if decodeProgramQueueJSON(data, &v) != nil || v.Operation.ID != id || validateThreatIDSOperation(v) != nil {
			return errors.New("IDS operation record cannot be verified")
		}
		records = append(records, v)
		return nil
	})
	if err != nil {
		return err
	}
	revision, err := programQueueIDSRecoveryRevision(records, time.Now())
	if err != nil || revision == 0 {
		return err
	}
	lease, err := scope(r.ctx, r.root, revision)
	if err != nil {
		return err
	}
	if lease == nil {
		return errors.New("IDS recovered scope lacks existing serialization; upgrade refused")
	}
	r.readLeases = append(r.readLeases, lease)
	if err := r.idsTransactionHistory(); err != nil {
		return err
	}
	return r.unchanged()
}

// Existing IDS transaction directories may be0750, unlike private operation
// queues. Parents and every retained file still retain the original root-only
// mutation contract. A missing leaf never hides a linked/foreign ancestor.
func (r *programQueueReader) idsTransactionHistory() error {
	s := &Service{Config: Config{SystemRoot: r.root, SecurityDir: filepath.Join(r.root, "etc/panel/security-apps")}, fileTransactionApplication: "network-ids"}
	for _, family := range []string{"config-transactions", "runtime-transactions"} {
		relative := "etc/panel/security-apps/modules/network-threat-detection/" + family
		root, err := r.queueDirectory(relative, false)
		if err != nil {
			return err
		}
		if root == nil {
			continue
		}
		err = func() error {
			defer root.Close()
			dir, err := root.Open(".")
			if err != nil {
				return err
			}
			entries, err := dir.ReadDir(129)
			dir.Close()
			if err != nil && !errors.Is(err, io.EOF) || len(entries) > 128 {
				return errors.New("IDS transaction inventory exceeds complete read budget")
			}
			for _, entry := range entries {
				name := entry.Name()
				if entry.IsDir() || name == "pending.json" {
					return errors.New("IDS transaction is pending or unknown; upgrade refused")
				}
				id := strings.TrimSuffix(name, ".json")
				if family == "runtime-transactions" {
					id = strings.TrimSuffix(strings.TrimSuffix(id, "-committed"), "-rolled-back")
				}
				if !core.ValidID(id) {
					return errors.New("IDS transaction retains an unknown or unfinished record")
				}
				data, err := r.record(root, relative, name, 1<<20)
				if err != nil {
					return err
				}
				if family == "config-transactions" {
					var tx wafTransaction
					if name != id+".json" || decodeProgramQueueJSON(data, &tx) != nil || tx.ID != id || (tx.State != "committed" && tx.State != "recovered") || s.wafTransactionContract(tx) != nil {
						return errors.New("IDS configuration history lacks a complete closed transaction")
					}
				} else {
					var tx threatIDSRuntimeUpgrade
					if decodeProgramQueueJSON(data, &tx) != nil || tx.ID != id || (tx.State != "committed" && tx.State != "rolled-back") || name != id+"-"+tx.State+".json" {
						return errors.New("IDS runtime history lacks a complete closed transaction")
					}
					if _, _, err := s.threatIDSRuntimeUpgradeContract(tx); err != nil {
						return err
					}
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func programQueueIDSRecoveryRevision(records []threatIDSOperationRecord, now time.Time) (int64, error) {
	var declined []core.NetworkIDSOperation
	var recovered []core.NetworkIDSOperation
	for _, v := range records {
		if err := validateThreatIDSOperation(v); err != nil {
			return 0, err
		}
		o := v.Operation
		created, _ := time.Parse(time.RFC3339Nano, o.CreatedAt)
		updated, _ := time.Parse(time.RFC3339Nano, o.UpdatedAt)
		if created.After(now) || updated.After(now) {
			return 0, errors.New("IDS operation time is in the future; upgrade refused")
		}
		switch o.State {
		case "queued", "running":
			return 0, errors.New("IDS operation is pending; upgrade refused")
		case "needs-attention":
			// Only this exact known historical gate was before native dispatch.
			// String matching alone is not authority: a newer explicit recovery,
			// higher configuration revision AND complete native scope are needed.
			if o.Error != errThreatIDSLegacyCapture.Error() || o.Input.ExpectedRevision < 1 || !(o.Action == "ids-start" || o.Action == "ids-boot" && o.Input.Enabled != nil && *o.Input.Enabled) {
				return 0, errors.New("IDS operation needs attention; upgrade refused")
			}
			declined = append(declined, o)
		case "succeeded":
			if o.Action == "ids-recover" {
				recovered = append(recovered, o)
			}
		}
	}
	if len(declined) == 0 {
		return 0, nil
	}
	var latest *core.NetworkIDSOperation
	for i := range recovered {
		o := &recovered[i]
		created, _ := time.Parse(time.RFC3339Nano, o.CreatedAt)
		qualifies := true
		for _, old := range declined {
			finished, _ := time.Parse(time.RFC3339Nano, old.UpdatedAt)
			if !created.After(finished) || o.Input.ExpectedRevision <= old.Input.ExpectedRevision {
				qualifies = false
			}
		}
		if qualifies {
			updated, _ := time.Parse(time.RFC3339Nano, o.UpdatedAt)
			if latest != nil {
				prior, _ := time.Parse(time.RFC3339Nano, latest.UpdatedAt)
				if updated.Equal(prior) && o.Input.ExpectedRevision != latest.Input.ExpectedRevision {
					return 0, errors.New("IDS recovery order is ambiguous; upgrade refused")
				}
				if !updated.After(prior) {
					continue
				}
			}
			latest = o
		}
	}
	if latest == nil {
		return 0, errors.New("IDS legacy decline has no later explicit recovery; upgrade refused")
	}
	return latest.Input.ExpectedRevision, nil
}

// No constructor, startup, syntax execution, preparation or recovery is used.
// Only an EXISTING shared lock is held until all queue snapshots are rechecked.
func programQueueIDSRecoveredScope(ctx context.Context, root string, revision int64) (io.Closer, error) {
	s := &Service{Config: Config{SystemRoot: root, StateDir: filepath.Join(root, "var/lib/panel-executor"), SecurityDir: filepath.Join(root, "etc/panel/security-apps"), Run: programQueueIDSReadCommand}}
	lock, err := s.threatIDSReadLock()
	if err != nil || lock == nil {
		return nil, errors.New("IDS recovery read lock cannot be verified; upgrade refused")
	}
	ok := false
	defer func() {
		if !ok {
			lock.Close()
		}
	}()
	if _, err := s.moduleInstalledRecord("network-threat-detection"); err != nil {
		return nil, err
	}
	if err := s.threatIDSUpgradeNoPending(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(s.threatIDSTransactionService().wafPendingPath()); !os.IsNotExist(err) {
		return nil, errors.New("IDS configuration transaction is pending or unknown; upgrade refused")
	}
	in, err := s.threatIDSConfig()
	if err != nil || in.Revision != revision {
		return nil, errors.New("IDS recovery receipt differs from current configuration; upgrade refused")
	}
	_, account, _, err := s.threatIDSImmutable(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.threatIDSNativeConfig(in); err != nil {
		return nil, err
	}
	// Verify all three loaded units, including pending jobs and source reload
	// state. An inactive MainPID alone cannot attest an unknown unit policy.
	for _, unit := range []string{threatIDSService, "panel-network-ids-check.service", "panel-network-ids-recover.service"} {
		raw, err := s.Config.Run(ctx, "/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus")
		if err != nil || !programQueueIDSIdleUnit(unit, raw) {
			return nil, errors.New("IDS recovered native unit is not trusted and idle; upgrade refused")
		}
	}
	if _, _, err := s.threatIDSHistorySources(ctx); err != nil {
		return nil, err
	}
	f, _, err := s.openThreatIDSLiveFile(account)
	if err != nil {
		return nil, err
	}
	if f != nil {
		defer f.Close()
		before, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if err := s.threatIDSArchiveDetached(ctx, before, account); err != nil {
			return nil, err
		}
		after, err := f.Stat()
		visible, pathErr := os.Lstat(s.systemPath("/var/lib/panel-network-ids/logs/eve.json"))
		if err != nil || pathErr != nil || !programQueueSame(before, after) || !programQueueSame(before, visible) {
			return nil, errors.New("IDS retained output changed during recovery observation; upgrade refused")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ok = true
	return lock, nil
}

func programQueueIDSReadCommand(ctx context.Context, name string, args ...string) (string, error) {
	if name != "/usr/bin/systemctl" || len(args) != 3 || args[0] != "show" || (args[1] != threatIDSService && args[1] != "panel-network-ids-check.service" && args[1] != "panel-network-ids-recover.service") || args[2] != "--property=Id,LoadState,ActiveState,SubState,MainPID,Job,FragmentPath,DropInPaths,Transient,NeedDaemonReload,UnitFileState,ExecMainCode,ExecMainStatus" {
		return "", errors.New("IDS upgrade reader refuses non-fixed observation command")
	}
	return programQueueCommand(ctx, name, args...)
}

func programQueueIDSIdleUnit(unit, raw string) bool {
	if len(raw) > 4096 || (unit != threatIDSService && unit != "panel-network-ids-check.service" && unit != "panel-network-ids-recover.service") {
		return false
	}
	v := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return false
		}
		if _, duplicate := v[key]; duplicate {
			return false
		}
		switch key {
		case "Id", "LoadState", "ActiveState", "SubState", "MainPID", "Job", "FragmentPath", "DropInPaths", "Transient", "NeedDaemonReload", "UnitFileState", "ExecMainCode", "ExecMainStatus":
		default:
			return false
		}
		v[key] = value
	}
	wanted := map[string]string{"Id": unit, "LoadState": "loaded", "MainPID": "0", "Job": "", "FragmentPath": "/etc/systemd/system/" + unit, "DropInPaths": "", "Transient": "no", "NeedDaemonReload": "no", "ExecMainStatus": "0"}
	for key, value := range wanted {
		if v[key] != value {
			return false
		}
	}
	if len(v) != 13 {
		return false
	}
	if unit == threatIDSService {
		return v["ActiveState"] == "inactive" && v["SubState"] == "dead" && v["UnitFileState"] == "disabled" && (v["ExecMainCode"] == "0" || v["ExecMainCode"] == "1")
	}
	return v["UnitFileState"] == "static" && (v["ActiveState"] == "inactive" && v["SubState"] == "dead" && v["ExecMainCode"] == "0" || v["ActiveState"] == "active" && v["SubState"] == "exited" && v["ExecMainCode"] == "1")
}
