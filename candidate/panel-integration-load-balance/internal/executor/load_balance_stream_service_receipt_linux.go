//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func writeStreamServiceReceipt(root *os.Root, raw []byte) error {
	if root == nil || len(raw) == 0 || len(raw) > streamServiceReceiptMaxBytes {
		return loadbalancestream.ErrService
	}
	f, err := root.OpenFile("service.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return loadbalancestream.ErrService
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return loadbalancestream.ErrService
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil ||
		!streamModulePublicationMatches(root, "service.json", raw) {
		return loadbalancestream.ErrService
	}
	return nil
}

func (s *loadBalanceStreamConfigurationStore) recordedServiceReceipt(ctx context.Context) (streamServiceReceipt, error) {
	var empty streamServiceReceipt
	if s == nil || s.first || s.generation == nil || s.publications == nil || s.generation.current(ctx) != nil {
		return empty, loadbalancestream.ErrService
	}
	seed, _, chain, err := s.generation.journal.original(ctx)
	if err != nil || !chain.Complete {
		return empty, loadbalancestream.ErrService
	}
	pub, err := s.publications.OpenRoot(s.generation.value.RequestID)
	if err != nil {
		return empty, loadbalancestream.ErrService
	}
	defer pub.Close()
	raw, err := streamInstallationPrivateRead(pub, "service.json", streamServiceReceiptMaxBytes)
	if err != nil || core.Hash(string(raw)) != s.generation.value.ServiceObservationSHA256 {
		return empty, loadbalancestream.ErrService
	}
	r, err := decodeStreamServiceReceipt(raw, seed)
	if err != nil || r.InstallationID != s.installed.receipt.InstallationID || s.generation.current(ctx) != nil {
		return empty, loadbalancestream.ErrService
	}
	return r, nil
}

// Compare today's actual original identity with the complete protected previous
// observation. A daemon/worker restarted after an OOM cannot silently become
// the unchanged prior generation merely because its UID/ELF/unit name match.
func streamServiceMatchesRecorded(current *loadBalanceStreamServiceObservation, receipt streamServiceReceipt) bool {
	var old streamServiceRecordedRunning
	if current == nil || receipt.State != "running" || json.Unmarshal(receipt.Native, &old) != nil ||
		current.InvocationID != old.InvocationID || current.MainPID != old.MainPID ||
		current.AccountUID != old.AccountUID || current.AccountGID != old.AccountGID ||
		current.EngineSHA256 != old.EngineSHA256 || current.UnitSHA256 != old.UnitSHA256 ||
		current.MemoryHigh != old.MemoryHigh || current.MemoryMax != old.MemoryMax || current.MemoryEvents != old.MemoryEvents ||
		len(current.Processes) < 2 || len(current.Processes) > 3 || len(old.Processes) < 2 || len(old.Processes) > 3 {
		return false
	}
	var oldMaster streamServiceReceiptProcess
	for _, p := range old.Processes {
		if p.PID == old.MainPID {
			oldMaster = p
		}
	}
	seenCurrent := false
	for _, p := range current.Processes {
		if p == nil {
			return false
		}
		actual := streamServiceReceiptProcess{p.PID, p.ParentPID, p.StartTime}
		if p.PID == current.MainPID {
			if actual != oldMaster {
				return false
			}
		} else {
			if !slices.Contains(old.Processes, actual) {
				return false
			}
			seenCurrent = seenCurrent || actual == receipt.CurrentWorker
		}
	}
	// Attachments are checked live independently. Their IDs may legitimately
	// change only in a new original policy operation, not between two controls.
	return seenCurrent && slices.Equal(current.IngressPrograms, old.IngressPrograms) && slices.Equal(current.EgressPrograms, old.EgressPrograms)
}

func (p *loadBalanceStreamConfigurationPublication) retainServiceOwned(ctx context.Context, w *loadBalanceStreamControlOwner, running *loadBalanceStreamServiceObservation, stopped *loadBalanceStreamStoppedObservation) (string, error) {
	if p == nil || !p.serviceIssued || p.serviceReceiptIssued || (running == nil) == (stopped == nil) {
		return "", loadbalancestream.ErrService
	}
	seed, plan, err := p.servicePlanOwned(ctx, w)
	if err != nil {
		return "", loadbalancestream.ErrService
	}
	r := streamServiceReceipt{Format: 1, Version: loadbalancestream.AppVersion, RequestID: p.request,
		InstallationID: w.gate.installed.receipt.InstallationID, SeedSHA256: core.Hash(string(p.seed)),
		ConfigurationSHA256: seed.AfterRuntimeSHA256, ServiceUnitSHA256: seed.ServiceUnitSHA256}
	var native []byte
	if running != nil {
		if !plan.Service.ShouldRun || running.installed != w.gate.installed || running.UnitSHA256 != plan.Service.SHA256 ||
			verifyLoadBalanceStreamConfigurationMarkers(ctx, running, seed.After) != nil {
			return "", loadbalancestream.ErrService
		}
		native, err = running.bytes(ctx)
		r.State = "running"
		var oldWorker *loadBalanceStreamProcessWitness
		if prior := p.store.priorService; prior != nil {
			if !streamReloadSameOriginalService(prior, running) || !streamReloadHasOneNewWorker(prior, running) {
				return "", loadbalancestream.ErrService
			}
			for _, process := range prior.Processes {
				if process.PID != prior.MainPID {
					oldWorker = process
				}
			}
		}
		for _, process := range running.Processes {
			if process.PID == running.MainPID || oldWorker != nil && process.PID == oldWorker.PID && process.StartTime == oldWorker.StartTime {
				continue
			}
			if r.CurrentWorker != (streamServiceReceiptProcess{}) {
				return "", loadbalancestream.ErrService
			}
			r.CurrentWorker = streamServiceReceiptProcess{process.PID, process.ParentPID, process.StartTime}
		}
	} else {
		if plan.Service.ShouldRun || stopped.publication != p || stopped.owner != w {
			return "", loadbalancestream.ErrService
		}
		native, err = stopped.bytes(ctx)
		r.State = "stopped"
	}
	if err != nil || len(native) == 0 || !p.receiptEgressCurrent(ctx, r.State) {
		return "", loadbalancestream.ErrService
	}
	r.Native = bytes.TrimSpace(native)
	r.Egress = p.store.egress.receipt
	raw, err := json.Marshal(r)
	if err != nil {
		return "", loadbalancestream.ErrService
	}
	raw = append(raw, '\n')
	if _, err := decodeStreamServiceReceipt(raw, p.seed); err != nil || !p.metadataCurrent() {
		return "", loadbalancestream.ErrService
	}
	if _, _, err := p.servicePlanOwned(ctx, w); err != nil || !p.receiptEgressCurrent(ctx, r.State) {
		return "", loadbalancestream.ErrService
	}
	p.serviceReceiptIssued = true
	p.serviceReceipt = bytes.Clone(raw)
	if writeStreamServiceReceipt(p.publication, raw) != nil || !p.metadataCurrent() {
		return "", loadbalancestream.ErrService
	}
	if running != nil && running.current(ctx) != nil || stopped != nil && stopped.current(ctx) != nil {
		return "", loadbalancestream.ErrService
	}
	if _, _, err := p.servicePlanOwned(ctx, w); err != nil || !p.receiptEgressCurrent(ctx, r.State) {
		return "", loadbalancestream.ErrService
	}
	return core.Hash(string(raw)), nil
}
