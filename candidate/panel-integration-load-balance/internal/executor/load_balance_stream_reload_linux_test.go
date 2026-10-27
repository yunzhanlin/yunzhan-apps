//go:build linux

package executor

import (
	"context"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamReloadAndStopMissingOriginalCannotSignalOrChangePolicy(t *testing.T) {
	for _, p := range []*loadBalanceStreamConfigurationPublication{nil, {}, {serviceIssued: true}, {stopCleanupIssued: true}, {promoted: true}, {syntaxIssued: true, syntaxVerified: true}} {
		if service, err := p.reloadOwned(context.Background(), nil); err != loadbalancestream.ErrService || service != nil {
			t.Fatal("missing/old original selected reload effect", err)
		}
		if stopped, err := p.stopOwned(context.Background(), nil); err != loadbalancestream.ErrService || stopped != nil {
			t.Fatal("missing/old original selected stop effect", err)
		}
	}
	for _, s := range []*loadBalanceStreamConfigurationStore{nil, {}, {released: true}, {first: true}} {
		if s.capturePriorService(context.Background(), nil, loadbalancestream.ControlSeed{}) != loadbalancestream.ErrService {
			t.Fatal("unbound store adopted an existing service")
		}
	}
	for _, p := range []*loadBalanceStreamProcessWitness{nil, {}, {pidfd: -1}, {PID: 219, StartTime: 1, pidfd: -1}} {
		if exited, err := streamOriginalProcessExited(p); err != loadbalancestream.ErrService || exited {
			t.Fatal("missing original pidfd became process exit")
		}
	}
	for _, s := range []*loadBalanceStreamStoppedObservation{nil, {}, {Format: 1, OriginalQUITObserved: true, EmptyCgroupBeforeCleanup: true, ManagerCleanupObserved: true}} {
		if s.current(context.Background()) != loadbalancestream.ErrService {
			t.Fatal("claimed stop became original completion")
		}
		if raw, err := s.bytes(context.Background()); err == nil || raw != nil {
			t.Fatal("unbound stopped observer returned completion bytes")
		}
	}
}

func TestLoadBalanceStreamReloadWorkerJoinRefusesOldOnlyOrThirdGeneration(t *testing.T) {
	process := func(pid, parent int, start uint64) *loadBalanceStreamProcessWitness {
		return &loadBalanceStreamProcessWitness{PID: pid, ParentPID: parent, StartTime: start}
	}
	prior := &loadBalanceStreamServiceObservation{MainPID: 219, Processes: []*loadBalanceStreamProcessWitness{process(219, 1, 100), process(222, 219, 101)}}
	for _, workers := range [][]*loadBalanceStreamProcessWitness{
		{process(219, 1, 100), process(223, 219, 102)},
		{process(219, 1, 100), process(222, 219, 101), process(223, 219, 102)},
	} {
		if !streamReloadHasOneNewWorker(prior, &loadBalanceStreamServiceObservation{MainPID: 219, Processes: workers}) {
			t.Fatal("original master, one new worker and optional retiring old worker refused")
		}
	}
	for _, workers := range [][]*loadBalanceStreamProcessWitness{
		{process(219, 1, 100), process(222, 219, 101)},
		{process(219, 1, 100), process(223, 219, 102), process(224, 219, 103)},
		{process(219, 1, 100), process(222, 219, 101), process(223, 219, 102), process(224, 219, 103)},
		{process(219, 1, 999), process(223, 219, 102)},
		{process(219, 2, 100), process(223, 219, 102)},
		{process(219, 1, 100), process(223, 1, 102)},
		{process(219, 1, 100), process(223, 219, 0)},
		{process(219, 1, 100), nil},
		{process(223, 219, 102), process(223, 219, 102)},
	} {
		if streamReloadHasOneNewWorker(prior, &loadBalanceStreamServiceObservation{MainPID: 219, Processes: workers}) {
			t.Fatal("old-only, substituted master or unknown third generation accepted")
		}
	}
}
