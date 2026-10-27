//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

type loadBalanceStreamProcessWitness struct {
	PID       int    `json:"pid"`
	ParentPID int    `json:"parent_pid"`
	StartTime uint64 `json:"start_time"`
	pidfd     int
	proc      *os.Root
	before    os.FileInfo
}

func (p *loadBalanceStreamProcessWitness) close() {
	if p == nil {
		return
	}
	if p.pidfd >= 0 {
		unix.Close(p.pidfd)
		p.pidfd = -1
	}
	if p.proc != nil {
		p.proc.Close()
		p.proc = nil
	}
}

func (p *loadBalanceStreamProcessWitness) read(name string) ([]byte, error) {
	if p == nil || p.proc == nil || p.pidfd < 0 || name != "stat" && name != "status" && name != "cgroup" && name != "limits" {
		return nil, loadbalancestream.ErrService
	}
	f, err := p.proc.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, loadbalancestream.ErrService
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, loadbalancestream.ErrService
	}
	return raw, nil
}

func (p *loadBalanceStreamProcessWitness) current(engine *loadBalanceStreamHeldEngine, uid, gid uint32) bool {
	if p == nil || p.proc == nil || p.pidfd < 0 || engine == nil || !engine.current() || p.PID < 2 {
		return false
	}
	poll := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	held, e1 := p.proc.Stat(".")
	visible, e2 := os.Lstat("/proc/" + strconv.Itoa(p.PID))
	if err != nil || n != 0 || poll[0].Revents != 0 || e1 != nil || e2 != nil || !os.SameFile(p.before, held) || !os.SameFile(held, visible) {
		return false
	}
	// Deliberate procfs magic-link dereference ONLY after the actual pidfd and
	// original proc-directory identity are held. No request selects a path.
	exe, err := os.Open("/proc/" + strconv.Itoa(p.PID) + "/exe")
	if err != nil {
		return false
	}
	exeInfo, err := exe.Stat()
	exe.Close()
	if err != nil || !geoStoreStableInfo(engine.binary.before, exeInfo) {
		return false
	}
	status, e1 := p.read("status")
	limits, e2 := p.read("limits")
	cgroup, e3 := p.read("cgroup")
	stat, e4 := p.read("stat")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !streamServiceProcessStatus(status, uid, gid) || !streamServiceOpenFiles(limits) || string(cgroup) != "0::/system.slice/"+loadbalancestream.ServiceUnitName+"\n" {
		return false
	}
	parsed, err := parseProcStat(p.PID, string(stat), uint64(os.Getpagesize()))
	end := strings.LastIndex(string(stat), ")")
	if err != nil || end < 0 || parsed.State == "Z" || parsed.State == "X" || parsed.StartTime == 0 || p.StartTime != 0 && parsed.StartTime != p.StartTime {
		return false
	}
	fields := strings.Fields(string(stat[end+1:]))
	parent, err := strconv.Atoi(fields[1])
	if err != nil || parent < 1 || strconv.Itoa(parent) != fields[1] || p.ParentPID != 0 && parent != p.ParentPID {
		return false
	}
	p.StartTime, p.ParentPID = parsed.StartTime, parent
	return true
}

// This is measured process/resource metadata, NOT forwarding health and NOT a
// new grant. Attached BPF IDs (even effective ones) do not by themselves prove
// that a destination is allowed/denied; real positive/negative traffic tests
// remain a separate prerequisite before the control can append its observation.
type loadBalanceStreamServiceObservation struct {
	Format          int                                `json:"format"`
	InvocationID    string                             `json:"invocation_id"`
	MainPID         int                                `json:"main_pid"`
	AccountUID      uint32                             `json:"account_uid"`
	AccountGID      uint32                             `json:"account_gid"`
	EngineSHA256    string                             `json:"engine_sha256"`
	UnitSHA256      string                             `json:"unit_sha256"`
	MemoryHigh      int64                              `json:"memory_high"`
	MemoryMax       int64                              `json:"memory_max"`
	MemoryEvents    loadBalanceStreamMemoryEvents      `json:"memory_events"`
	IngressPrograms []uint32                           `json:"ingress_programs"`
	EgressPrograms  []uint32                           `json:"egress_programs"`
	Processes       []*loadBalanceStreamProcessWitness `json:"processes"`
	installed       *loadBalanceStreamInstalledContext
	cgroup          *os.File
	cgroupBefore    os.FileInfo
	plan            loadbalancestream.ServicePlan
	permitsRetiring bool
}

func (w *loadBalanceStreamServiceObservation) close() {
	if w == nil {
		return
	}
	for _, p := range w.Processes {
		p.close()
	}
	w.Processes = nil
	if w.cgroup != nil {
		w.cgroup.Close()
		w.cgroup = nil
	}
}

func streamServiceManagerFacts(ctx context.Context) (int, string, error) {
	raw, err := programQueueCommand(ctx, "/usr/bin/systemctl", "show", loadbalancestream.ServiceUnitName, "--property="+strings.Join(streamServicePropertyNames, ","))
	if err != nil {
		return 0, "", loadbalancestream.ErrService
	}
	return decodeStreamServiceProperties([]byte(raw))
}

func (w *loadBalanceStreamServiceObservation) limitsCurrent() bool {
	if w == nil || w.cgroup == nil || w.plan.MemoryHighBytes < loadbalancestream.ServiceBaseMemory || w.plan.MemoryMaxBytes < w.plan.MemoryHighBytes || w.plan.MemoryMaxBytes > loadbalancestream.ServiceBaseMemory+loadbalancestream.MaxMemoryBudget+loadbalancestream.MaxMemoryBudget/4 {
		return false
	}
	for name, want := range map[string]string{"memory.high": strconv.FormatInt(w.plan.MemoryHighBytes, 10) + "\n", "memory.max": strconv.FormatInt(w.plan.MemoryMaxBytes, 10) + "\n", "memory.swap.max": "0\n", "pids.max": "32\n"} {
		value, err := readLoadBalanceStreamCgroupFile(w.cgroup, name, 128)
		if err != nil || string(value) != want {
			return false
		}
	}
	cpu, err := readLoadBalanceStreamCgroupFile(w.cgroup, "cpu.max", 128)
	if err != nil || !streamServiceCPU100(cpu) {
		return false
	}
	return true
}

func (w *loadBalanceStreamServiceObservation) current(ctx context.Context) error {
	if w == nil || ctx == nil || ctx.Err() != nil || w.installed == nil || w.installed.current(ctx) != nil || w.cgroup == nil || w.Format != 1 || !w.plan.ShouldRun || w.plan.SHA256 != core.Hash(string(w.plan.Unit)) || w.UnitSHA256 != w.plan.SHA256 || w.MemoryHigh != w.plan.MemoryHighBytes || w.MemoryMax != w.plan.MemoryMaxBytes || !w.limitsCurrent() {
		return loadbalancestream.ErrService
	}
	main, invocation, err := streamServiceManagerFacts(ctx)
	if err != nil || main != w.MainPID || invocation != w.InvocationID {
		return loadbalancestream.ErrService
	}
	held, e1 := w.cgroup.Stat()
	visible, e2 := os.Lstat("/sys/fs/cgroup/system.slice/" + loadbalancestream.ServiceUnitName)
	if e1 != nil || e2 != nil || !os.SameFile(w.cgroupBefore, held) || !os.SameFile(held, visible) {
		return loadbalancestream.ErrService
	}
	eventsRaw, err := readLoadBalanceStreamCgroupFile(w.cgroup, "memory.events", 4096)
	events, eventErr := decodeStreamMemoryEvents(eventsRaw)
	if err != nil || eventErr != nil || events != w.MemoryEvents {
		return loadbalancestream.ErrService
	}
	rawPIDs, err := readLoadBalanceStreamCgroupFile(w.cgroup, "cgroup.procs", 512)
	pids, ok := streamServicePIDs(rawPIDs)
	if err != nil || !ok || len(pids) != len(w.Processes) || len(pids) < 2 || len(pids) > 3 || !slices.Contains(pids, main) || !w.permitsRetiring && len(pids) != 2 {
		return loadbalancestream.ErrService
	}
	slices.Sort(pids)
	for i, p := range w.Processes {
		if p.PID != pids[i] || !p.current(w.installed.engine, w.AccountUID, w.AccountGID) || p.PID == main && p.ParentPID != 1 || p.PID != main && p.ParentPID != main {
			return loadbalancestream.ErrService
		}
	}
	for attach, wanted := range map[uint32][]uint32{unix.BPF_CGROUP_INET_INGRESS: w.IngressPrograms, unix.BPF_CGROUP_INET_EGRESS: w.EgressPrograms} {
		// Direct attachments are required. An inherited unrelated filter alone
		// cannot make an unfiltered unit look isolated.
		actual, err := loadBalanceStreamCgroupBPFProgramsWithFlags(w.cgroup, attach, 0)
		effective, e2 := loadBalanceStreamCgroupBPFPrograms(w.cgroup, attach)
		if err != nil || e2 != nil || len(actual) == 0 || !slices.Equal(actual, wanted) {
			return loadbalancestream.ErrService
		}
		for _, id := range actual {
			if !slices.Contains(effective, id) {
				return loadbalancestream.ErrService
			}
		}
	}
	if w.AccountUID != w.installed.identity.UID || w.AccountGID != w.installed.identity.GID || w.EngineSHA256 != w.installed.engine.binary.sha || observeStreamServiceIPPolicy(ctx, w.plan) != nil || ctx.Err() != nil {
		return loadbalancestream.ErrService
	}
	return nil
}

// Read-only actual instance observation. It starts/stops/signals nothing and
// makes no path or identity repairs. Missing permissions, unavailable kernel
// facts and a changed/dead process fail closed without adding capabilities.
func observeLoadBalanceStreamService(ctx context.Context, installed *loadBalanceStreamInstalledContext, plan loadbalancestream.ServicePlan, permitsRetiring bool) (*loadBalanceStreamServiceObservation, error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || installed == nil || installed.current(ctx) != nil || !plan.ShouldRun || plan.SHA256 != core.Hash(string(plan.Unit)) {
		return nil, loadbalancestream.ErrService
	}
	main, invocation, err := streamServiceManagerFacts(ctx)
	if err != nil || threatIDSTrustedParents("/sys/fs/cgroup/system.slice", false) != nil {
		return nil, loadbalancestream.ErrService
	}
	w := &loadBalanceStreamServiceObservation{Format: 1, InvocationID: invocation, MainPID: main, AccountUID: installed.identity.UID, AccountGID: installed.identity.GID, EngineSHA256: installed.engine.binary.sha, UnitSHA256: plan.SHA256, MemoryHigh: plan.MemoryHighBytes, MemoryMax: plan.MemoryMaxBytes, installed: installed, plan: plan, permitsRetiring: permitsRetiring}
	fail := func() (*loadBalanceStreamServiceObservation, error) {
		w.close()
		return nil, loadbalancestream.ErrService
	}
	w.cgroup, err = os.OpenFile("/sys/fs/cgroup/system.slice/"+loadbalancestream.ServiceUnitName, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail()
	}
	w.cgroupBefore, err = w.cgroup.Stat()
	if err != nil {
		return fail()
	}
	eventsRaw, err := readLoadBalanceStreamCgroupFile(w.cgroup, "memory.events", 4096)
	if err != nil {
		return fail()
	}
	w.MemoryEvents, err = decodeStreamMemoryEvents(eventsRaw)
	if err != nil {
		return fail()
	}
	raw, err := readLoadBalanceStreamCgroupFile(w.cgroup, "cgroup.procs", 512)
	pids, ok := streamServicePIDs(raw)
	if err != nil || !ok || len(pids) < 2 || len(pids) > 3 || !permitsRetiring && len(pids) != 2 || !slices.Contains(pids, main) {
		return fail()
	}
	slices.Sort(pids)
	for _, pid := range pids {
		p := &loadBalanceStreamProcessWitness{PID: pid, pidfd: -1}
		w.Processes = append(w.Processes, p)
		p.pidfd, err = unix.PidfdOpen(pid, 0)
		if err != nil {
			return fail()
		}
		p.proc, err = os.OpenRoot(filepath.Join("/proc", strconv.Itoa(pid)))
		if err != nil {
			return fail()
		}
		p.before, err = p.proc.Stat(".")
		if err != nil || !p.current(installed.engine, w.AccountUID, w.AccountGID) {
			return fail()
		}
	}
	w.IngressPrograms, err = loadBalanceStreamCgroupBPFProgramsWithFlags(w.cgroup, unix.BPF_CGROUP_INET_INGRESS, 0)
	if err != nil {
		return fail()
	}
	w.EgressPrograms, err = loadBalanceStreamCgroupBPFProgramsWithFlags(w.cgroup, unix.BPF_CGROUP_INET_EGRESS, 0)
	if err != nil || w.current(ctx) != nil {
		return fail()
	}
	return w, nil
}

func (w *loadBalanceStreamServiceObservation) bytes(ctx context.Context) ([]byte, error) {
	if w.current(ctx) != nil {
		return nil, loadbalancestream.ErrService
	}
	raw, err := json.Marshal(w)
	if err != nil || len(raw) == 0 || len(raw) > 16384 {
		return nil, loadbalancestream.ErrService
	}
	if ctx.Err() != nil {
		return nil, loadbalancestream.ErrService
	}
	return append(raw, '\n'), nil
}
