//go:build linux

package executor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"local/panel/internal/loadbalancestream"
)

const streamEgressNFT = "/usr/sbin/nft"

// Held read-only BEFORE witness. Mutation additionally requires the original
// controller, SH/EX leases, promoted configuration and service-intent phase.
// A saved successful flag, table comment or replacement netns grants nothing.
type loadBalanceStreamHeldEgress struct {
	nft       *loadBalanceStreamEngineFile
	namespace *os.File
	nsBefore  os.FileInfo
	bootID    string
	policy    loadbalancestream.EgressGuard
	receipt   streamEgressReceipt
	missing   bool
	issued    bool
	retired   bool
	unknown   bool
	readOnly  bool
}

func (g *loadBalanceStreamHeldEgress) close() {
	if g != nil {
		if g.nft != nil {
			g.nft.file.Close()
			g.nft = nil
		}
		if g.namespace != nil {
			g.namespace.Close()
			g.namespace = nil
		}
	}
}

func (g *loadBalanceStreamHeldEgress) identityCurrent(ctx context.Context) bool {
	if g == nil || ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || g.unknown || g.nft == nil ||
		!g.nft.current() || g.nft.path != streamEgressNFT || g.namespace == nil || !streamEgressBootID(g.bootID) {
		return false
	}
	boot, e1 := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	held, e2 := g.namespace.Stat()
	named, e3 := os.Stat("/proc/self/ns/net")
	if e2 != nil {
		return false
	}
	st, ok := held.Sys().(*syscall.Stat_t)
	var fs unix.Statfs_t
	return e1 == nil && e3 == nil && ok && st.Dev != 0 && st.Ino != 0 && string(boot) == g.bootID+"\n" &&
		g.receipt.Format == 1 && g.receipt.BootID == g.bootID && g.receipt.NftSHA256 == g.nft.sha &&
		g.receipt.NetnsDevice == uint64(st.Dev) && g.receipt.NetnsInode == st.Ino &&
		os.SameFile(g.nsBefore, held) && os.SameFile(held, named) &&
		unix.Fstatfs(int(g.namespace.Fd()), &fs) == nil && fs.Type == unix.NSFS_MAGIC
}

// Only two fixed read forms and the private pure-policy batch below execute.
// argv, tool, stdin and output bounds cannot be supplied by Core or browser.
func (g *loadBalanceStreamHeldEgress) command(ctx context.Context, batch []byte, tables bool) ([]byte, error) {
	if !g.identityCurrent(ctx) || batch != nil && (g.readOnly || len(batch) == 0 || len(batch) > loadbalancestream.MaxEgressObservationBytes || tables) {
		return nil, loadbalancestream.ErrEgressGuard
	}
	args := []string{"-s", "-a", "-j", "list", "table", "inet", loadbalancestream.EgressTableName}
	if tables {
		args = []string{"-s", "-a", "-j", "list", "tables"}
	} else if batch != nil {
		args = []string{"-f", "-"}
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/proc/self/fd/3", args...)
	cmd.Args[0] = streamEgressNFT
	cmd.ExtraFiles = []*os.File{g.nft.file}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	output, diagnostics := &boundedBuffer{max: loadbalancestream.MaxEgressObservationBytes}, &boundedBuffer{max: 16384}
	cmd.Stdout, cmd.Stderr = output, diagnostics
	if batch != nil {
		cmd.Stdin = bytes.NewReader(batch)
	}
	if err := cmd.Run(); err != nil || output.truncated || diagnostics.truncated || diagnostics.String() != "" ||
		batch != nil && output.String() != "" || !g.identityCurrent(ctx) {
		return nil, loadbalancestream.ErrEgressGuard
	}
	return []byte(output.String()), nil
}

func (g *loadBalanceStreamHeldEgress) current(ctx context.Context) error {
	if !g.identityCurrent(ctx) {
		return loadbalancestream.ErrEgressGuard
	}
	if g.missing {
		raw, err := g.command(ctx, nil, true)
		if err != nil || !loadbalancestream.EgressTableAbsent(raw) {
			return loadbalancestream.ErrEgressGuard
		}
		return nil
	}
	raw, err := g.command(ctx, nil, false)
	actual, e2 := g.policy.Inspect(raw)
	if err != nil || e2 != nil || !g.receipt.valid(g.policy) || !reflect.DeepEqual(actual, g.receipt.Observation) {
		return loadbalancestream.ErrEgressGuard
	}
	return nil
}

// Observation only: original verified receipt bytes never authorize a write.
// Hold the actual current tool/netns descriptors and compare the complete live
// table including handles. A new boot, replaced tool or missing policy fails.
func holdLoadBalanceStreamRecordedEgress(ctx context.Context, seed loadbalancestream.ControlSeed, state string, uid uint32, receipt streamEgressReceipt) (*loadBalanceStreamHeldEgress, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return nil, loadbalancestream.ErrEgressGuard
	}
	policy, err := streamReceiptEgressPolicy(seed, state, uid)
	if err != nil || !receipt.valid(policy) {
		return nil, loadbalancestream.ErrEgressGuard
	}
	receipt.Observation.RuleHandles = append([]uint64(nil), receipt.Observation.RuleHandles...)
	g := &loadBalanceStreamHeldEgress{policy: policy, receipt: receipt, readOnly: true}
	fail := func() (*loadBalanceStreamHeldEgress, error) { g.close(); return nil, loadbalancestream.ErrEgressGuard }
	g.nft, _, err = holdLoadBalanceStreamEngineFile(streamEgressNFT, true)
	if err != nil {
		return fail()
	}
	g.namespace, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return fail()
	}
	g.nsBefore, err = g.namespace.Stat()
	if err != nil {
		return fail()
	}
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	g.bootID = strings.TrimSuffix(string(boot), "\n")
	if err != nil || g.current(ctx) != nil {
		return fail()
	}
	return g, nil
}

// Hold the current fixed tool and network namespace only to read table
// absence. In particular readOnly forbids even a caller with this pointer
// from issuing a batch. This observation is never a publication receipt.
func holdLoadBalanceStreamAbsentEgressReadOnly(ctx context.Context) (*loadBalanceStreamHeldEgress, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 {
		return nil, loadbalancestream.ErrEgressGuard
	}
	g := &loadBalanceStreamHeldEgress{missing: true, readOnly: true}
	fail := func() (*loadBalanceStreamHeldEgress, error) { g.close(); return nil, loadbalancestream.ErrEgressGuard }
	var err error
	g.nft, _, err = holdLoadBalanceStreamEngineFile(streamEgressNFT, true)
	if err != nil {
		return fail()
	}
	g.namespace, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return fail()
	}
	g.nsBefore, err = g.namespace.Stat()
	if err != nil {
		return fail()
	}
	st, ok := g.nsBefore.Sys().(*syscall.Stat_t)
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	g.bootID = strings.TrimSuffix(string(boot), "\n")
	if !ok || st.Dev == 0 || st.Ino == 0 || err != nil || !streamEgressBootID(g.bootID) {
		return fail()
	}
	g.receipt = streamEgressReceipt{Format: 1, BootID: g.bootID, NetnsDevice: uint64(st.Dev), NetnsInode: st.Ino, NftSHA256: g.nft.sha}
	if g.current(ctx) != nil {
		return fail()
	}
	return g, nil
}

func (s *loadBalanceStreamConfigurationStore) holdEgress(ctx context.Context, facts loadbalancestream.ServiceFacts) error {
	if s == nil || s.egress != nil || !s.priorCaptured || s.beforeCurrent(ctx) != nil || facts.AccountUID != s.installed.identity.UID {
		return loadbalancestream.ErrEgressGuard
	}
	g := &loadBalanceStreamHeldEgress{missing: s.first || s.priorColdBoot != nil}
	fail := func() error { g.close(); return loadbalancestream.ErrEgressGuard }
	var err error
	g.nft, _, err = holdLoadBalanceStreamEngineFile(streamEgressNFT, true)
	if err != nil {
		return fail()
	}
	g.namespace, err = os.Open("/proc/self/ns/net")
	if err != nil {
		return fail()
	}
	g.nsBefore, err = g.namespace.Stat()
	if err != nil {
		return fail()
	}
	st, ok := g.nsBefore.Sys().(*syscall.Stat_t)
	boot, err := streamAccountParentProc("/proc/sys/kernel/random/boot_id", 128)
	g.bootID = strings.TrimSuffix(string(boot), "\n")
	if !ok || st.Dev == 0 || st.Ino == 0 || err != nil {
		return fail()
	}
	g.receipt = streamEgressReceipt{Format: 1, BootID: g.bootID, NetnsDevice: uint64(st.Dev), NetnsInode: st.Ino, NftSHA256: g.nft.sha}
	if !g.identityCurrent(ctx) {
		return fail()
	}
	if !s.first {
		prior, err := s.recordedServiceReceipt(ctx)
		if err != nil {
			return fail()
		}
		raw, _, chain, err := s.generation.journal.original(ctx)
		seed, e2 := loadbalancestream.DecodeControlSeed(raw)
		if err != nil || e2 != nil || !chain.Complete {
			return fail()
		}
		priorPolicy, err := streamReceiptEgressPolicy(seed, prior.State, facts.AccountUID)
		if err != nil || !prior.Egress.valid(priorPolicy) {
			return fail()
		}
		if s.priorColdBoot != nil {
			if s.priorColdBoot.current(ctx, s) != nil || prior.Egress.BootID != s.priorColdBoot.record.PreviousBootID ||
				g.bootID != s.priorColdBoot.record.BootID || prior.Egress.BootID == g.bootID {
				return fail()
			}
			// Keep the NEW held namespace/tool identity and require actual table
			// absence below. The old table/handles are immutable lineage only.
		} else {
			if prior.Egress.BootID != g.bootID || prior.Egress.NetnsDevice != uint64(st.Dev) ||
				prior.Egress.NetnsInode != st.Ino || prior.Egress.NftSHA256 != g.nft.sha {
				return fail()
			}
			g.policy, g.receipt = priorPolicy, prior.Egress
		}
	}
	if g.current(ctx) != nil || s.beforeCurrent(ctx) != nil {
		return fail()
	}
	s.egress = g
	return nil
}

// ONE atomic batch. Failure preserves uncertainty; no fallback flush,
// recreate, adopt, automatic rollback or replay of a saved job is allowed.
func (g *loadBalanceStreamHeldEgress) replaceOriginal(ctx context.Context, next loadbalancestream.EgressGuard) error {
	if g.current(ctx) != nil || next.SHA256() == "" {
		return loadbalancestream.ErrEgressGuard
	}
	previous, wasMissing := g.receipt.Observation, g.missing
	batch, err := next.ReplacementRules()
	if wasMissing {
		batch, err = next.CreateRules()
	}
	if err != nil {
		return loadbalancestream.ErrEgressGuard
	}
	if _, err := g.command(ctx, batch, false); err != nil {
		g.unknown = true
		return loadbalancestream.ErrEgressGuard
	}
	raw, err := g.command(ctx, nil, false)
	observed, e2 := next.Inspect(raw)
	if err != nil || e2 != nil || !wasMissing && (observed.TableHandle != previous.TableHandle || observed.ChainHandle != previous.ChainHandle) {
		g.unknown = true
		return loadbalancestream.ErrEgressGuard
	}
	g.policy, g.receipt.Observation, g.missing = next, observed, false
	if g.current(ctx) != nil {
		g.unknown = true
		return loadbalancestream.ErrEgressGuard
	}
	return nil
}

func (p *loadBalanceStreamConfigurationPublication) applyEgressOwned(ctx context.Context, w *loadBalanceStreamControlOwner) error {
	seed, _, err := p.servicePlanOwned(ctx, w)
	if err != nil || p.serviceIssued || p.store.egress == nil || p.store.egress.issued || p.store.egress.retired || p.store.egress.current(ctx) != nil {
		return loadbalancestream.ErrEgressGuard
	}
	policy, err := loadbalancestream.PlanEgressGuard(seed.After, loadbalancestream.ControlRetiringEntries(seed), loadbalancestream.ValidationContext{
		PanelControlPorts: []int{19100, 19102, 19080}, MemoryBudgetBytes: loadbalancestream.MaxMemoryBudget}, w.gate.installed.identity.UID)
	if err != nil || w.current(ctx) != nil || !p.metadataCurrent() {
		return loadbalancestream.ErrEgressGuard
	}
	p.store.egress.issued = true
	return p.store.egress.replaceOriginal(ctx, policy)
}

func (p *loadBalanceStreamConfigurationPublication) serviceEgressCurrent(ctx context.Context) bool {
	return p != nil && p.store != nil && !p.store.released && p.store.egress != nil &&
		p.store.egress.issued && !p.store.egress.retired && p.egressPolicyCurrent(ctx, "running")
}

func (p *loadBalanceStreamConfigurationPublication) egressPolicyCurrent(ctx context.Context, state string) bool {
	if p == nil || p.store == nil || p.store.released || p.store.installed == nil || p.store.egress == nil || p.store.egress.missing {
		return false
	}
	seed, err := loadbalancestream.DecodeControlSeed(p.seed)
	policy, e2 := streamReceiptEgressPolicy(seed, state, p.store.installed.identity.UID)
	g := p.store.egress
	return err == nil && e2 == nil && policy.SHA256() == g.policy.SHA256() && g.receipt.valid(policy) && g.current(ctx) == nil
}

// The retained bytes describe this same original operation, not a successful
// command from another boot, namespace or previous generation. Recheck the
// complete live table even after the service observation has been written.
func (p *loadBalanceStreamConfigurationPublication) receiptEgressCurrent(ctx context.Context, state string) bool {
	if p == nil || p.store == nil || p.store.egress == nil || !p.store.egress.issued {
		return false
	}
	g := p.store.egress
	return (state == "running" && !g.retired || state == "stopped" && g.retired) && p.egressPolicyCurrent(ctx, state)
}

// Retire old destinations AFTER original QUIT/empty-cgroup/manager-cleanup.
// Reloads retain both generations while the witnessed old worker drains.
func (p *loadBalanceStreamConfigurationPublication) retireStoppedEgressOwned(ctx context.Context, w *loadBalanceStreamControlOwner, stopped *loadBalanceStreamStoppedObservation) error {
	seed, plan, err := p.servicePlanOwned(ctx, w)
	if err != nil || plan.Service.ShouldRun || !p.serviceIssued || !p.serviceEgressCurrent(ctx) || stopped == nil ||
		stopped.publication != p || stopped.owner != w || !stopped.ManagerCleanupObserved || !stopped.originalProcessesExited() ||
		!streamManagedServiceInactive(ctx, stopped.InvocationID) {
		return loadbalancestream.ErrEgressGuard
	}
	policy, err := streamReceiptEgressPolicy(seed, "stopped", w.gate.installed.identity.UID)
	if err != nil || w.current(ctx) != nil || !p.metadataCurrent() {
		return loadbalancestream.ErrEgressGuard
	}
	p.store.egress.retired = true
	return p.store.egress.replaceOriginal(ctx, policy)
}
