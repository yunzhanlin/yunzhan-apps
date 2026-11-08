//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"strconv"

	"local/panel/internal/loadbalancestream"
)

// Read-only listener evidence for the independently measured actual service.
// It starts/stops nothing, changes no capabilities/ports/namespaces and makes
// no backend-health or forwarding claim. The old-worker listener-close reload
// barrier and actual traffic probes remain independent mandatory checks.
func observeLoadBalanceStreamOwnedListeners(ctx context.Context, service *loadBalanceStreamServiceObservation, entries []loadbalancestream.Entry) (map[string]string, error) {
	if service == nil || service.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	census, err := observeLoadBalanceStreamHostSockets(ctx)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	defer census.close()
	var master map[string]bool
	var workers []map[string]bool
	for _, process := range service.Processes {
		// Explicit fixed procfs namespace link, guarded by the already held
		// actual pidfd/proc directory/start-time/UID/ELF/cgroup witness.
		info, err := os.Stat(filepath.Join("/proc", strconv.Itoa(process.PID), "ns/net"))
		if err != nil || !os.SameFile(census.before, info) || !process.current(service.installed.engine, service.AccountUID, service.AccountGID) {
			return nil, loadbalancestream.ErrService
		}
		fds, err := wafProcessSockets(ctx, "/proc", process.PID)
		if err != nil || len(fds) > loadbalancestream.RuntimeOpenFiles {
			return nil, loadbalancestream.ErrService
		}
		if process.PID == service.MainPID {
			master = fds
		} else {
			workers = append(workers, fds)
		}
	}
	owned, err := matchStreamOwnedListeners(census.sockets, master, workers, entries, service.AccountUID)
	if err != nil || !census.current() || service.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	return owned, nil
}
