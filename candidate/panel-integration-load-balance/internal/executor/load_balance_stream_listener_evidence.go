package executor

import (
	"net/netip"
	"strconv"
	"strings"

	"local/panel/internal/loadbalancestream"
)

func streamSocketIsListener(row loadBalanceStreamHostSocket) bool {
	return strings.HasPrefix(row.Protocol, "tcp") && row.State == 10 || strings.HasPrefix(row.Protocol, "udp") && row.State == 7 && row.Remote.Port() == 0 && row.Remote.Addr().IsUnspecified()
}

// Pure evidence join only. Production obtains rows and BOTH descriptor sets
// from actual held original processes in the same kernel namespace. UID alone,
// a saved inode, a claimed PID or a successful fingerprint is never ownership.
func matchStreamOwnedListeners(rows []loadBalanceStreamHostSocket, master map[string]bool, workers []map[string]bool, entries []loadbalancestream.Entry, uid uint32) (map[string]string, error) {
	if uid < 100 || uid >= 1000 || len(master) == 0 || len(master) > loadbalancestream.RuntimeOpenFiles || len(workers) < 1 || len(workers) > 2 || loadbalancestream.ValidateSet(entries, loadbalancestream.ValidationContext{PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}) != nil {
		return nil, loadbalancestream.ErrService
	}
	expected := map[string]bool{}
	for _, entry := range entries {
		if entry.Removed {
			continue
		}
		expected[entry.Protocol+"|127.0.0.1:"+strconv.Itoa(entry.Port)] = true
		expected["tcp|127.0.0.1:"+strconv.Itoa(entry.ProbePort)] = true
	}
	if len(expected) == 0 {
		return nil, loadbalancestream.ErrService
	}
	for _, worker := range workers {
		if len(worker) > loadbalancestream.RuntimeOpenFiles {
			return nil, loadbalancestream.ErrService
		}
	}
	found := map[string]string{}
	for _, row := range rows {
		if !streamSocketIsListener(row) {
			continue
		}
		inode := strconv.FormatUint(row.Inode, 10)
		ownedWorker := false
		for _, worker := range workers {
			ownedWorker = ownedWorker || worker[inode]
		}
		ownedMaster := master[inode]
		key := strings.TrimSuffix(row.Protocol, "6") + "|" + row.Local.String()
		if !ownedMaster && !ownedWorker {
			// An additional foreign listener, including a wildcard/v6 listener
			// on the same port, cannot be hidden by an otherwise owned probe.
			for endpoint := range expected {
				_, address, _ := strings.Cut(endpoint, "|")
				want, err := netip.ParseAddrPort(address)
				if err != nil {
					return nil, loadbalancestream.ErrService
				}
				if want.Port() == row.Local.Port() && strings.HasPrefix(endpoint, strings.TrimSuffix(row.Protocol, "6")+"|") {
					return nil, loadbalancestream.ErrService
				}
			}
			continue
		}
		if !expected[key] || !ownedMaster || !ownedWorker || row.UID != uid || row.Inode == 0 || row.Local.Addr() != netip.MustParseAddr("127.0.0.1") {
			return nil, loadbalancestream.ErrService
		}
		if _, duplicate := found[key]; duplicate {
			return nil, loadbalancestream.ErrService
		}
		found[key] = inode
	}
	if len(found) != len(expected) {
		return nil, loadbalancestream.ErrService
	}
	return found, nil
}
