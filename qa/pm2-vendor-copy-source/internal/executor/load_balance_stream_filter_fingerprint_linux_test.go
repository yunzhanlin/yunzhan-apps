//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func TestStreamFilterKernelUAPIHasExactDualArchitectureOffsets(t *testing.T) {
	if !streamFilterNativeABI() {
		t.Fatal("unsupported or changed BPF UAPI prefix")
	}
}

func TestStreamFilterInfoReplyRetainsRequiredOldKernelPrefix(t *testing.T) {
	before := streamFilterInfoRequest{FD: 8, Bytes: 88, Info: 4096}
	for _, size := range []uint32{80, 88} {
		after := before
		after.Bytes = size
		if !streamFilterInfoReply(before, after, 80) || streamFilterInfoReply(before, after, 88) != (size == 88) {
			t.Fatal("map optional suffix confused with required program identity", size)
		}
	}
	for _, change := range []func(*streamFilterInfoRequest){
		func(v *streamFilterInfoRequest) { v.FD++ },
		func(v *streamFilterInfoRequest) { v.Info++ },
		func(v *streamFilterInfoRequest) { v.Bytes = 72 },
		func(v *streamFilterInfoRequest) { v.Bytes = 79 },
		func(v *streamFilterInfoRequest) { v.Bytes = 84 },
		func(v *streamFilterInfoRequest) { v.Bytes = 96 },
	} {
		after := before
		change(&after)
		if streamFilterInfoReply(before, after, 80) {
			t.Fatal("truncated, enlarged or redirected kernel info accepted", after)
		}
	}
}

func streamFilterOwnObjectFDs(t *testing.T) []string {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	result := []string{}
	for _, f := range files {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", f.Name()))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(target, "bpf-prog") || strings.Contains(target, "bpf-map") {
			result = append(result, f.Name()+"="+target)
		}
	}
	slices.Sort(result)
	return result
}

// Explicit native component reader only, not programme/application install
// acceptance. The controlled native harness requires this case to run with no
// SKIP against its already-installed isolated service, with complete outside
// process/NSS/files/NFT preservation observations.
func TestStreamFilterNativeExistingUnitKernelPolicyReadOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Root native read-only component harness")
	}
	group := "/sys/fs/cgroup/system.slice/" + loadbalancestream.ServiceUnitName
	if _, err := os.Lstat(group); os.IsNotExist(err) {
		t.Skip("requires already-installed isolated native service")
	} else if err != nil {
		t.Fatal(err)
	}
	beforeFDs := streamFilterOwnObjectFDs(t)
	func() {
		directory, err := os.Open(group)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ingress, e1 := loadBalanceStreamCgroupBPFProgramsWithFlags(directory, 0, 0)
		egress, e2 := loadBalanceStreamCgroupBPFProgramsWithFlags(directory, 1, 0)
		if e1 != nil || e2 != nil || !streamServiceBPFIDs(ingress) || !streamServiceBPFIDs(egress) {
			t.Fatal("actual direct kernel filters absent", e1, e2)
		}
		first, err := observeStreamFilterPolicySHA256(ctx, directory, ingress, egress)
		if err != nil || !streamFilterReceiptFormat(2, first) {
			t.Fatal("actual kernel instruction/map observation failed", err)
		}
		second, err := observeStreamFilterPolicySHA256(ctx, directory, ingress, egress)
		if err != nil || first != second {
			t.Fatal("identical actual policy not stable on independent kernel reads", err)
		}
		t.Logf("actual native filter fingerprint %s; direct ingress=%v egress=%v; no kernel or service mutations", first, ingress, egress)
	}()
	if after := streamFilterOwnObjectFDs(t); !slices.Equal(beforeFDs, after) {
		t.Fatal("read-only observer leaked a kernel object descriptor", beforeFDs, after)
	}
}

func streamFilterRecordedFixture(t *testing.T, format int) (*loadBalanceStreamServiceObservation, streamServiceReceipt, []byte) {
	t.Helper()
	_, seed, r := streamServiceReceiptFixture(t, "running")
	var n streamServiceRecordedRunning
	if err := json.Unmarshal(r.Native, &n); err != nil {
		t.Fatal(err)
	}
	n.Format = format
	if format == 2 {
		n.FilterSHA256 = strings.Repeat("a", 64)
	}
	r.Native, _ = json.Marshal(n)
	w := &loadBalanceStreamServiceObservation{Format: 2, InvocationID: n.InvocationID, MainPID: n.MainPID,
		AccountUID: n.AccountUID, AccountGID: n.AccountGID, EngineSHA256: n.EngineSHA256, UnitSHA256: n.UnitSHA256,
		MemoryHigh: n.MemoryHigh, MemoryMax: n.MemoryMax, MemoryEvents: n.MemoryEvents,
		IngressPrograms: slices.Clone(n.IngressPrograms), EgressPrograms: slices.Clone(n.EgressPrograms),
		FilterSHA256: strings.Repeat("a", 64)}
	for _, p := range n.Processes {
		w.Processes = append(w.Processes, &loadBalanceStreamProcessWitness{PID: p.PID, ParentPID: p.ParentPID, StartTime: p.StartTime})
	}
	return w, r, seed
}

func TestStreamFilterNewReceiptAcceptsOnlyEquivalentPolicyForOriginalProcesses(t *testing.T) {
	for _, format := range []int{1, 2} {
		w, r, seed := streamFilterRecordedFixture(t, format)
		raw, _ := json.Marshal(r)
		raw = append(raw, '\n')
		before := core.Hash(string(raw))
		if _, err := decodeStreamServiceReceipt(raw, seed); err != nil || !streamServiceMatchesRecorded(w, r) {
			t.Fatal("valid exact native body rejected", format, err)
		}
		w.IngressPrograms[0] += 1000
		w.EgressPrograms[0] += 1000
		if streamServiceMatchesRecorded(w, r) != (format == 2) {
			t.Fatal("legacy ID rule and new exact-policy rule confused", format)
		}
		after, _ := json.Marshal(r)
		if core.Hash(string(append(after, '\n'))) != before {
			t.Fatal("immutable original native body changed")
		}
	}
	cases := map[string]func(*loadBalanceStreamServiceObservation){
		"policy":                func(w *loadBalanceStreamServiceObservation) { w.FilterSHA256 = strings.Repeat("b", 64) },
		"missing-policy":        func(w *loadBalanceStreamServiceObservation) { w.FilterSHA256 = "" },
		"missing-direct-filter": func(w *loadBalanceStreamServiceObservation) { w.IngressPrograms = nil },
		"legacy-current-format": func(w *loadBalanceStreamServiceObservation) { w.Format = 1 },
		"invocation":            func(w *loadBalanceStreamServiceObservation) { w.InvocationID = core.ID() },
		"master":                func(w *loadBalanceStreamServiceObservation) { w.MainPID++ },
		"worker":                func(w *loadBalanceStreamServiceObservation) { w.Processes[1].StartTime++ },
		"UID":                   func(w *loadBalanceStreamServiceObservation) { w.AccountUID++ },
		"GID":                   func(w *loadBalanceStreamServiceObservation) { w.AccountGID++ },
		"ELF":                   func(w *loadBalanceStreamServiceObservation) { w.EngineSHA256 = strings.Repeat("c", 64) },
		"unit":                  func(w *loadBalanceStreamServiceObservation) { w.UnitSHA256 = strings.Repeat("b", 64) },
		"memory":                func(w *loadBalanceStreamServiceObservation) { w.MemoryMax++ },
		"OOM":                   func(w *loadBalanceStreamServiceObservation) { w.MemoryEvents.OOM++ },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			w, r, _ := streamFilterRecordedFixture(t, 2)
			change(w)
			if streamServiceMatchesRecorded(w, r) {
				t.Fatal("changed policy, resource or original process identity accepted")
			}
		})
	}
}

func TestStreamFilterReceiptFormatsRemainCanonicalAndSeparate(t *testing.T) {
	for _, format := range []int{1, 2} {
		_, r, seed := streamFilterRecordedFixture(t, format)
		raw, _ := json.Marshal(r)
		got, err := decodeStreamServiceReceipt(append(raw, '\n'), seed)
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatal("canonical native receipt changed", format, err)
		}
	}
	for _, test := range []struct {
		format int
		digest string
	}{
		{1, strings.Repeat("a", 64)}, {2, ""}, {2, strings.Repeat("0", 64)}, {3, strings.Repeat("a", 64)},
	} {
		_, r, seed := streamFilterRecordedFixture(t, 1)
		var n streamServiceRecordedRunning
		json.Unmarshal(r.Native, &n)
		n.Format, n.FilterSHA256 = test.format, test.digest
		r.Native, _ = json.Marshal(n)
		raw, _ := json.Marshal(r)
		if _, err := decodeStreamServiceReceipt(append(raw, '\n'), seed); err == nil {
			t.Fatal("contradictory native format accepted", test)
		}
	}
}
