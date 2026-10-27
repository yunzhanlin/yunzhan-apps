package executor

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const streamServiceReceiptMaxBytes = 64 << 10

type streamServiceReceiptProcess struct {
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid"`
	StartTime uint64 `json:"start_time"`
}

type streamServiceRecordedRunning struct {
	Format          int                           `json:"format"`
	InvocationID    string                        `json:"invocation_id"`
	MainPID         int                           `json:"main_pid"`
	AccountUID      uint32                        `json:"account_uid"`
	AccountGID      uint32                        `json:"account_gid"`
	EngineSHA256    string                        `json:"engine_sha256"`
	UnitSHA256      string                        `json:"unit_sha256"`
	MemoryHigh      int64                         `json:"memory_high"`
	MemoryMax       int64                         `json:"memory_max"`
	MemoryEvents    loadBalanceStreamMemoryEvents `json:"memory_events"`
	IngressPrograms []uint32                      `json:"ingress_programs"`
	EgressPrograms  []uint32                      `json:"egress_programs"`
	Processes       []streamServiceReceiptProcess `json:"processes"`
}

type streamServiceRecordedStopped struct {
	Format                   int                           `json:"format"`
	InvocationID             string                        `json:"invocation_id"`
	AccountUID               uint32                        `json:"account_uid"`
	AccountGID               uint32                        `json:"account_gid"`
	EngineSHA256             string                        `json:"engine_sha256"`
	FinalExitSHA256          string                        `json:"final_exit_sha256"`
	FinalExitProperties      string                        `json:"final_exit_properties"`
	OriginalProcesses        []streamServiceReceiptProcess `json:"original_processes"`
	MemoryEvents             loadBalanceStreamMemoryEvents `json:"memory_events"`
	OriginalQUITObserved     bool                          `json:"original_quit_observed"`
	EmptyCgroupBeforeCleanup bool                          `json:"empty_cgroup_before_cleanup"`
	ManagerCleanupObserved   bool                          `json:"manager_cleanup_observed"`
}

// Immutable historical DATA, not a live grant, kernel witness or health flag.
// The complete body is retained, not just an uncheckable hash. Root separately
// joins its actual protected inode, full journal, Core completion, installation
// and lineage before using it as the BEFORE identity of a fresh operation.
type streamServiceReceipt struct {
	Format              int                         `json:"format"`
	Version             string                      `json:"version"`
	RequestID           string                      `json:"request_id"`
	InstallationID      string                      `json:"installation_id"`
	SeedSHA256          string                      `json:"seed_sha256"`
	ConfigurationSHA256 string                      `json:"configuration_sha256"`
	ServiceUnitSHA256   string                      `json:"service_unit_sha256"`
	State               string                      `json:"state"`
	CurrentWorker       streamServiceReceiptProcess `json:"current_worker"`
	Native              json.RawMessage             `json:"native"`
	Egress              streamEgressReceipt         `json:"egress"`
}

func streamServiceCanonicalCompact(raw []byte, v any) bool {
	if len(raw) == 0 || json.Unmarshal(raw, v) != nil {
		return false
	}
	canonical, err := json.Marshal(v)
	return err == nil && bytes.Equal(raw, canonical)
}

func streamServiceProcessSet(processes []streamServiceReceiptProcess, master int) bool {
	if master < 2 || master > 1<<30 || len(processes) < 2 || len(processes) > 3 {
		return false
	}
	seen := map[int]bool{}
	masters := 0
	for _, p := range processes {
		if p.PID < 2 || p.PID > 1<<30 || p.StartTime == 0 || seen[p.PID] {
			return false
		}
		seen[p.PID] = true
		if p.PID == master {
			if p.ParentPID != 1 {
				return false
			}
			masters++
		} else if p.ParentPID != master {
			return false
		}
	}
	return masters == 1
}

func streamServiceNativeIdentity(invocation string, uid, gid uint32, engine string) bool {
	return core.ValidID(invocation) && invocation != strings.Repeat("0", 32) &&
		uid >= 100 && uid < 1000 && gid >= 100 && gid < 1000 && loadBalanceStreamAccountHash(engine)
}

func streamServiceBPFIDs(ids []uint32) bool {
	if len(ids) == 0 || len(ids) > 64 {
		return false
	}
	seen := map[uint32]bool{}
	for _, id := range ids {
		if id == 0 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func decodeStreamServiceReceipt(raw, seedRaw []byte) (streamServiceReceipt, error) {
	var r streamServiceReceipt
	if len(raw) == 0 || len(raw) > streamServiceReceiptMaxBytes || !bytes.HasSuffix(raw, []byte("\n")) ||
		!streamServiceCanonicalCompact(bytes.TrimSuffix(raw, []byte("\n")), &r) {
		return r, loadbalancestream.ErrService
	}
	seed, err := loadbalancestream.DecodeControlSeed(seedRaw)
	if err != nil || r.Format != 1 || r.Version != loadbalancestream.AppVersion || r.RequestID != seed.Operation.RequestID ||
		!core.ValidID(r.InstallationID) || r.InstallationID == strings.Repeat("0", 32) ||
		r.SeedSHA256 != core.Hash(string(seedRaw)) || r.ConfigurationSHA256 != seed.AfterRuntimeSHA256 ||
		r.ServiceUnitSHA256 != seed.ServiceUnitSHA256 || len(r.Native) == 0 || len(r.Native) > 16384 {
		return streamServiceReceipt{}, loadbalancestream.ErrService
	}
	runtime, err := loadbalancestream.RenderRuntime(seed.After, loadbalancestream.ServiceRuntimePrefix,
		loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget})
	if err != nil {
		return streamServiceReceipt{}, loadbalancestream.ErrService
	}
	var uid uint32
	switch r.State {
	case "running":
		var n streamServiceRecordedRunning
		if !streamServiceCanonicalCompact(r.Native, &n) || runtime.ActiveEntries == 0 || n.Format != 1 ||
			!streamServiceNativeIdentity(n.InvocationID, n.AccountUID, n.AccountGID, n.EngineSHA256) ||
			n.UnitSHA256 != seed.ServiceUnitSHA256 || n.MemoryHigh < loadbalancestream.ServiceBaseMemory ||
			n.MemoryMax < n.MemoryHigh || n.MemoryMax > loadbalancestream.ServiceBaseMemory+loadbalancestream.MaxMemoryBudget+loadbalancestream.MaxMemoryBudget/4 ||
			!streamServiceProcessSet(n.Processes, n.MainPID) || !streamServiceBPFIDs(n.IngressPrograms) || !streamServiceBPFIDs(n.EgressPrograms) ||
			r.CurrentWorker.PID == n.MainPID || r.CurrentWorker.ParentPID != n.MainPID || !slices.Contains(n.Processes, r.CurrentWorker) {
			return streamServiceReceipt{}, loadbalancestream.ErrService
		}
		uid = n.AccountUID
	case "stopped":
		var n streamServiceRecordedStopped
		if !streamServiceCanonicalCompact(r.Native, &n) || runtime.ActiveEntries != 0 || n.Format != 1 ||
			!streamServiceNativeIdentity(n.InvocationID, n.AccountUID, n.AccountGID, n.EngineSHA256) ||
			!loadBalanceStreamAccountHash(n.FinalExitSHA256) || core.Hash(n.FinalExitProperties) != n.FinalExitSHA256 ||
			!streamStoppedExitMatches([]byte(n.FinalExitProperties), n.InvocationID) ||
			!n.OriginalQUITObserved || !n.EmptyCgroupBeforeCleanup || !n.ManagerCleanupObserved ||
			len(n.OriginalProcesses) != 2 || r.CurrentWorker != (streamServiceReceiptProcess{}) {
			return streamServiceReceipt{}, loadbalancestream.ErrService
		}
		master := 0
		for _, p := range n.OriginalProcesses {
			if p.ParentPID == 1 {
				if master != 0 {
					return streamServiceReceipt{}, loadbalancestream.ErrService
				}
				master = p.PID
			}
		}
		if !streamServiceProcessSet(n.OriginalProcesses, master) {
			return streamServiceReceipt{}, loadbalancestream.ErrService
		}
		uid = n.AccountUID
	default:
		return streamServiceReceipt{}, loadbalancestream.ErrService
	}
	policy, err := streamReceiptEgressPolicy(seed, r.State, uid)
	if err != nil || !r.Egress.valid(policy) {
		return streamServiceReceipt{}, loadbalancestream.ErrService
	}
	return r, nil
}
