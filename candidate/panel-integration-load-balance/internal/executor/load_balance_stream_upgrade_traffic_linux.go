//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Held historical evidence, never a control owner. In particular it has no
// grant, runtime/configuration writer lease, journal creator or recovery path.
// Programme replacement already serializes with the real global EX lease;
// acquiring a new SH lease here would deadlock that production upgrade path.
type loadBalanceStreamTrafficUpgrade struct {
	source     *loadBalanceStreamCoreAuthority
	history    []byte
	closed     map[string]bool
	namespaces *programQueueReader
	installed  *loadBalanceStreamInstalledContext
	store      *loadBalanceStreamConfigurationStore
	seed       loadbalancestream.ControlSeed
	receipt    streamServiceReceipt
	live       *loadBalanceStreamServiceObservation
	egress     *loadBalanceStreamHeldEgress
}

func (w *loadBalanceStreamTrafficUpgrade) close() {
	if w == nil {
		return
	}
	if w.egress != nil {
		w.egress.close()
		w.egress = nil
	}
	if w.live != nil {
		w.live.close()
		w.live = nil
	}
	if w.store != nil {
		w.store.close()
		w.store = nil
	}
	if w.installed != nil {
		w.installed.close()
		w.installed = nil
	}
	clear(w.history)
	w.history = nil
	w.namespaces = nil
	w.source = nil
}

// Called only on the complete SELECT-only canonical Core history. Native
// artifacts are allowed ONLY for committed originals; a pre-effect refusal
// must have no Root journal. No prefix, supplied ID or revoked actor is a skip.
func streamUpgradeClosedControls(history []core.LoadBalanceStreamControlUpgradeRecord) (map[string]bool, error) {
	closed, seen := map[string]bool{}, map[string]bool{}
	if len(history) > 4096 {
		return nil, loadbalancestream.ErrJournal
	}
	for _, row := range history {
		id := row.Operation.RequestID
		if !core.ValidID(id) || loadbalancestream.OperationSHA256(row.Operation) == "" || seen[id] || row.State != "completed" {
			return nil, loadbalancestream.ErrJournal
		}
		seen[id] = true
		switch row.ResultState {
		case "committed":
			closed[id] = true
		case "refused-before-issue", "refused-before-effects":
		default:
			return nil, loadbalancestream.ErrJournal
		}
	}
	if len(closed) > 128 {
		return nil, loadbalancestream.ErrJournal
	}
	return closed, nil
}

// Private reader seam matches the installation census tests. Production always
// supplies the fixed '/' root; neither the exported fence nor CLI accepts paths.
// Keep the first inode/absence observations until admission finishes: a second
// census must not silently adopt a replaced empty directory or unknown journal.
func streamUpgradeControlNamespaces(r *programQueueReader, closed map[string]bool) error {
	if r == nil || r.ctx == nil || r.ctx.Err() != nil || len(closed) > 128 {
		return loadbalancestream.ErrJournal
	}
	for id, committed := range closed {
		if !core.ValidID(id) || !committed {
			return loadbalancestream.ErrJournal
		}
	}
	relative := strings.TrimPrefix(loadBalanceStreamJobsRoot, "/")
	root, err := r.directory(relative)
	if err != nil || root == nil && len(closed) != 0 {
		return loadbalancestream.ErrJournal
	}
	if root != nil {
		defer root.Close()
		if streamConfigurationExactDirectories(root, closed) != nil {
			return loadbalancestream.ErrJournal
		}
		for id := range closed {
			info, err := root.Lstat(id)
			if err != nil || !memcachedUnixAdminDirectoryInfo(info) {
				return loadbalancestream.ErrJournal
			}
			r.snapshots = append(r.snapshots, programQueueSnapshot{filepath.Join(r.root, relative, id), info})
		}
	}
	if len(closed) == 0 {
		for _, path := range []string{loadBalanceStreamStateRoot, loadBalanceStreamGenerationPublicationsRoot,
			loadBalanceStreamConfigurationRoot, loadBalanceStreamConfigurationPublicationsRoot} {
			observed, err := r.queueDirectory(strings.TrimPrefix(path, "/"), false)
			if observed != nil {
				observed.Close()
			}
			if err != nil || observed != nil {
				return loadbalancestream.ErrGeneration
			}
		}
	}
	return r.unchanged()
}

func holdLoadBalanceStreamTrafficUpgrade(ctx context.Context, source *loadBalanceStreamCoreAuthority) (*loadBalanceStreamTrafficUpgrade, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || source == nil {
		return nil, loadbalancestream.ErrJournal
	}
	history, err := source.controlUpgradeHistory(ctx, nil)
	if err != nil {
		return nil, err
	}
	closed, err := streamUpgradeClosedControls(history)
	namespaces := &programQueueReader{ctx: ctx, root: "/"}
	if err != nil || streamUpgradeControlNamespaces(namespaces, closed) != nil {
		return nil, loadbalancestream.ErrJournal
	}
	raw, err := json.Marshal(history)
	if err != nil {
		return nil, loadbalancestream.ErrJournal
	}
	w := &loadBalanceStreamTrafficUpgrade{source: source, history: raw, closed: closed, namespaces: namespaces}
	fail := func() (*loadBalanceStreamTrafficUpgrade, error) {
		w.close()
		return nil, loadbalancestream.ErrJournal
	}
	if len(closed) != 0 {
		w.installed, err = holdLoadBalanceStreamInstalledContext(ctx)
		if err != nil {
			return fail()
		}
		w.store = &loadBalanceStreamConfigurationStore{installed: w.installed, source: source, closed: closed}
		if w.store.holdCompletedConfiguration(ctx) != nil {
			return fail()
		}
		seedRaw, _, _, err := w.store.generation.journal.original(ctx)
		if err != nil {
			return fail()
		}
		w.seed, err = loadbalancestream.DecodeControlSeed(seedRaw)
		if err != nil {
			return fail()
		}
		w.receipt, err = w.store.recordedServiceReceipt(ctx)
		if err != nil {
			return fail()
		}
	}
	if w.current(ctx) != nil {
		return fail()
	}
	return w, nil
}

func (w *loadBalanceStreamTrafficUpgrade) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || w.source == nil || w.namespaces == nil || len(w.history) == 0 || w.namespaces.unchanged() != nil {
		return loadbalancestream.ErrJournal
	}
	history, err := w.source.controlUpgradeHistory(ctx, nil)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(history)
	current := &programQueueReader{ctx: ctx, root: "/"}
	if err != nil || !bytes.Equal(raw, w.history) || streamUpgradeControlNamespaces(current, w.closed) != nil {
		return loadbalancestream.ErrJournal
	}
	if len(w.closed) == 0 {
		properties, err := streamInstallUnitProperties(ctx, loadbalancestream.ServiceUnitName)
		if err != nil || properties["LoadState"] != "not-found" || properties["ActiveState"] != "inactive" ||
			properties["SubState"] != "dead" || properties["InvocationID"] != "" ||
			properties["MainPID"] != "0" || properties["ControlPID"] != "0" {
			return loadbalancestream.ErrService
		}
		return w.namespaces.unchanged()
	}
	if w.installed == nil || w.store == nil || w.store.released || w.store.generation == nil || w.store.file == nil ||
		w.installed.current(ctx) != nil || w.store.generation.current(ctx) != nil || !w.store.file.current() ||
		!streamConfigurationNamedRootCurrent(w.store.root, w.installed.identity.GID) || w.store.checkPublicationLineage(ctx, w.closed) != nil {
		return loadbalancestream.ErrGeneration
	}
	facts, err := measureLoadBalanceStreamServiceFacts(ctx, w.installed)
	if err != nil {
		return err
	}
	ports, err := observeLoadBalanceStreamControlPorts(ctx)
	if err != nil {
		return err
	}
	facts.Validation.PanelControlPorts = ports
	plan, err := loadbalancestream.RecordedControlServicePlan(w.seed, facts)
	if err != nil || plan.SHA256 != w.store.generation.value.ServiceUnitSHA256 {
		return loadbalancestream.ErrService
	}
	if w.egress == nil {
		w.egress, err = holdLoadBalanceStreamRecordedEgress(ctx, w.seed, w.receipt.State, w.installed.identity.UID, w.receipt.Egress)
		if err != nil {
			return err
		}
	}
	if w.egress.current(ctx) != nil {
		return loadbalancestream.ErrEgressGuard
	}
	if w.receipt.State == "stopped" {
		var stopped streamServiceRecordedStopped
		if json.Unmarshal(w.receipt.Native, &stopped) != nil || plan.ShouldRun ||
			stopped.AccountUID != w.installed.identity.UID || stopped.AccountGID != w.installed.identity.GID ||
			stopped.EngineSHA256 != w.installed.engine.binary.sha || !streamManagedServiceInactive(ctx, stopped.InvocationID) {
			return loadbalancestream.ErrService
		}
		// A historical quit receipt alone cannot hide a live orphan cgroup.
		if _, err := os.Lstat("/sys/fs/cgroup/system.slice/" + loadbalancestream.ServiceUnitName); !errors.Is(err, os.ErrNotExist) {
			return loadbalancestream.ErrService
		}
		census, err := observeLoadBalanceStreamHostSockets(ctx)
		if err != nil {
			return err
		}
		defer census.close()
		for _, socket := range census.sockets {
			if socket.UID == w.installed.identity.UID {
				return loadbalancestream.ErrService
			}
		}
		if !census.current() {
			return loadbalancestream.ErrService
		}
	} else {
		if !plan.ShouldRun {
			return loadbalancestream.ErrService
		}
		if w.live == nil {
			w.live, err = observeLoadBalanceStreamService(ctx, w.installed, plan, true)
			if err != nil {
				return err
			}
		}
		// Keep the original pidfds/cgroup/configuration handles until the final
		// recheck, rather than adopting a restarted/reused PID on a second read.
		if w.live.current(ctx) != nil || !streamServiceMatchesRecorded(w.live, w.receipt) ||
			verifyLoadBalanceStreamConfigurationMarkers(ctx, w.live, w.seed.After) != nil {
			return loadbalancestream.ErrService
		}
	}
	if w.egress.current(ctx) != nil {
		return loadbalancestream.ErrEgressGuard
	}
	return w.namespaces.unchanged()
}
