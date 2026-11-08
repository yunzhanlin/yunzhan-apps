package executor

import (
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Retained only inside the immutable service receipt and its journal digest.
// These fields are DATA, not a substitute for a live original owner, held
// executable/netns descriptors and complete fresh kernel-table inspection.
type streamEgressReceipt struct {
	Format      int                                      `json:"format"`
	BootID      string                                   `json:"boot_id"`
	NetnsDevice uint64                                   `json:"netns_device"`
	NetnsInode  uint64                                   `json:"netns_inode"`
	NftSHA256   string                                   `json:"nft_sha256"`
	Observation loadbalancestream.EgressGuardObservation `json:"observation"`
}

func streamEgressBootID(id string) bool {
	return len(id) == 36 && id[8] == '-' && id[13] == '-' && id[18] == '-' && id[23] == '-' &&
		core.ValidID(strings.ReplaceAll(id, "-", "")) && strings.ReplaceAll(id, "-", "") != strings.Repeat("0", 32)
}

func streamReceiptEgressPolicy(seed loadbalancestream.ControlSeed, state string, uid uint32) (loadbalancestream.EgressGuard, error) {
	retiring := loadbalancestream.ControlRetiringEntries(seed)
	if state == "stopped" {
		retiring = []loadbalancestream.Entry{}
	} else if state != "running" {
		return loadbalancestream.EgressGuard{}, loadbalancestream.ErrEgressGuard
	}
	return loadbalancestream.PlanEgressGuard(seed.After, retiring, loadbalancestream.ValidationContext{
		PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}, uid)
}

func (r streamEgressReceipt) valid(policy loadbalancestream.EgressGuard) bool {
	return r.Format == 1 && streamEgressBootID(r.BootID) && r.NetnsDevice != 0 && r.NetnsInode != 0 &&
		loadBalanceStreamAccountHash(r.NftSHA256) && policy.ValidateObservation(r.Observation) == nil
}
