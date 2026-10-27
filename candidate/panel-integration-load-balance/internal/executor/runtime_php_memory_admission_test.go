package executor

import (
	"bytes"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/runtimecatalog"
)

// Test-only kernel counters, never a caller budget, controller write or
// production fallback. memory.peak includes reclaimable filesystem cache;
// a max-boundary reclaim is not an OOM event (kernel cgroup-v2 interface).
func runtimePHPCompilerEventsForNativeTest(raw []byte) (map[string]uint64, error) {
	if len(raw) == 0 || len(raw) > 16384 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return nil, errors.New("invalid kernel event record")
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) == 0 || len(fields[0]) > 32 || len(values) >= 64 {
			return nil, errors.New("invalid kernel event field")
		}
		for _, c := range fields[0] {
			if c != '_' && (c < 'a' || c > 'z') {
				return nil, errors.New("invalid kernel event name")
			}
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return nil, errors.New("duplicate kernel event")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != fields[1] {
			return nil, errors.New("invalid kernel event counter")
		}
		values[fields[0]] = value
	}
	for _, key := range []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} {
		if _, found := values[key]; !found {
			return nil, errors.New("missing kernel memory event")
		}
	}
	return values, nil
}

func runtimePHPCompilerNoOOMForNativeTest(before, after map[string]uint64) error {
	if len(before) < 6 || len(before) > 64 || len(before) != len(after) {
		return errors.New("kernel event set changed")
	}
	for key, initial := range before {
		final, found := after[key]
		if !found || final < initial {
			return errors.New("kernel event reset or identity changed")
		}
	}
	for _, key := range []string{"oom", "oom_kill", "oom_group_kill"} {
		initial, found := before[key]
		if !found || initial != 0 || after[key] != 0 {
			return errors.New("actual OOM or incomplete memory evidence")
		}
	}
	return nil
}

func TestRuntimePHPCompilerMemoryEventsDifferentiateReclaimFromActualOOM(t *testing.T) {
	fixture := "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"
	before, err := runtimePHPCompilerEventsForNativeTest([]byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	after, err := runtimePHPCompilerEventsForNativeTest([]byte(strings.Replace(fixture, "max 0", "max 123", 1)))
	if err != nil || runtimePHPCompilerNoOOMForNativeTest(before, after) != nil {
		t.Fatal("successful bounded cache reclaim was relabelled OOM", err)
	}
	for _, key := range []string{"oom", "oom_kill", "oom_group_kill"} {
		changed := map[string]uint64{}
		for k, v := range after {
			changed[k] = v
		}
		changed[key] = 1
		if runtimePHPCompilerNoOOMForNativeTest(before, changed) == nil || runtimePHPCompilerNoOOMForNativeTest(changed, changed) == nil {
			t.Fatal("actual current or earlier OOM admitted", key)
		}
	}
	for _, raw := range []string{"", fixture + "oom 0\n", strings.Replace(fixture, "oom 0\n", "", 1), strings.TrimSuffix(fixture, "\n"), fixture + "unknown -1\n", fixture + "unknown 18446744073709551616\n", fixture + "unknown 01\n", fixture + "unknown +1\n", fixture + "bad-name 0\n", fixture + "bad 0 extra\n", fixture + "\x00\n", fixture + "\r\n"} {
		if _, err := runtimePHPCompilerEventsForNativeTest([]byte(raw)); err == nil {
			t.Fatal("unknown/partial/malformed event set admitted", strconv.Quote(raw[:min(len(raw), 80)]))
		}
	}
	if runtimePHPCompilerNoOOMForNativeTest(after, before) == nil || runtimePHPCompilerNoOOMForNativeTest(nil, nil) == nil {
		t.Fatal("reset/absent counters admitted")
	}
}

func TestRuntimePHPCompilerMemoryExactHostReserveAndSelectedReleases(t *testing.T) {
	for _, id := range []string{"php-8.2.35", "php-8.3.36"} {
		r, _ := runtimecatalog.Find(id)
		for _, kb := range []uint64{1572864, 1572865, 2097152} {
			raw := []byte("MemTotal: 3145728 kB\nMemAvailable: " + strconv.FormatUint(kb, 10) + " kB\nSwapTotal: 0 kB\n")
			if err := runtimePHPCompilerMemoryAdmission(r, raw); err != nil {
				t.Fatal(id, kb, err)
			}
		}
		for _, kb := range []uint64{0, 524288, 1048576, 1572863} {
			raw := []byte("MemTotal: 3145728 kB\nMemAvailable: " + strconv.FormatUint(kb, 10) + " kB\n")
			if err := runtimePHPCompilerMemoryAdmission(r, raw); err == nil || !strings.Contains(err.Error(), "未启动编译") || !strings.Contains(err.Error(), "512 MiB") {
				t.Fatal("insufficient headroom did not refuse without spawning", id, kb, err)
			}
		}
		if err := runtimePHPCompilerMemoryAdmission(r, nil); !errors.Is(err, errRuntimePHPCompilerMemoryInventory) {
			t.Fatal("unknown memory was guessed sufficient", err)
		}
	}
}

func TestRuntimePHPCompilerMemoryOwnedBudgetNeverCreditsHostCacheOrLowersReserve(t *testing.T) {
	r, _ := runtimecatalog.Find("php-8.3.36")
	info := func(mib uint64) []byte {
		return []byte("MemTotal: 3145728 kB\nMemAvailable: " + strconv.FormatUint(mib*1024, 10) + " kB\n")
	}
	if runtimePHPCompilerMemoryAdmission(r, info(1476)) == nil {
		t.Fatal("outside-worker admission lost original1536MiB minimum")
	}
	if err := runtimePHPCompilerMemoryAdmissionOwned(r, info(1476), 60<<20); err != nil {
		t.Fatal("same actual unit charge was budgeted twice", err)
	}
	if runtimePHPCompilerMemoryAdmissionOwned(r, info(1475), 60<<20) == nil {
		t.Fatal("remaining1GiB budget plus512MiB reserve was not retained")
	}
	if runtimePHPCompilerMemoryAdmissionOwned(r, info(1400), 60<<20) == nil {
		t.Fatal("host file cache was incorrectly credited as owned non-reclaimable memory")
	}
	for _, owned := range []uint64{(1 << 30) + 1, ^uint64(0)} {
		if runtimePHPCompilerMemoryAdmissionOwned(r, info(2048), owned) == nil || runtimePHPCompilerMemoryAncestorOwned([]byte("max\n"), []byte("0\n"), owned) == nil {
			t.Fatal("unbounded/impossible unit charge admitted", owned)
		}
	}
	if err := runtimePHPCompilerMemoryAncestorOwned([]byte("2147483648\n"), []byte(strconv.FormatUint(712<<20, 10)+"\n"), 200<<20); err != nil {
		t.Fatal("parent's charged child memory was budgeted twice", err)
	}
	if runtimePHPCompilerMemoryAncestorOwned([]byte("2147483648\n"), []byte(strconv.FormatUint(713<<20, 10)+"\n"), 200<<20) == nil {
		t.Fatal("parent remaining charge budget or512MiB reserve weakened")
	}
}

func TestRuntimePHPCompilerMemoryFootprintCreditsOnlyConfirmedAnonAndSharedBytes(t *testing.T) {
	current := []byte(strconv.FormatUint(200<<20, 10) + "\n")
	fixture := "anon 20971520\nshmem 36700160\nfile 152043520\nkernel 83886080\nslab_reclaimable 73400320\n"
	for _, raw := range []string{fixture, "anon 20971520\nshmem 36700160\n", strings.Replace(fixture, "file 152043520", "file 0", 1), strings.Replace(fixture, "slab_reclaimable 73400320", "slab_reclaimable 0", 1)} {
		owned, err := runtimePHPCompilerMemoryFootprint(current, []byte(raw))
		if err != nil || owned.Charged != 200<<20 || owned.NonReclaimable != 55<<20 {
			t.Fatal("file cache/slab/optional fields changed confirmed host credit", owned, err)
		}
	}
	for _, row := range [][2]string{
		{"", fixture}, {"0\n", fixture}, {"209715200", fixture}, {"0209715200\n", fixture}, {"+209715200\n", fixture}, {"1073741825\n", fixture},
		{string(current), "shmem 0\n"}, {string(current), "anon 0\n"}, {string(current), fixture + "anon 0\n"},
		{string(current), strings.TrimSuffix(fixture, "\n")}, {string(current), fixture + "\x00\n"}, {string(current), fixture + "\r\n"},
		{string(current), strings.Replace(fixture, "anon 20971520", "anon -1", 1)}, {string(current), strings.Replace(fixture, "anon 20971520", "anon 021", 1)},
		{string(current), strings.Replace(fixture, "anon 20971520", "anon 1073741825", 1)}, {string(current), strings.Replace(fixture, "anon 20971520", "anon 209715201", 1)},
		{string(current), fixture + "unknown 18446744073709551616\n"}, {string(current), fixture + "bad-name 0\n"}, {string(current), fixture + strings.Repeat("x", 65536) + "\n"},
	} {
		if _, err := runtimePHPCompilerMemoryFootprint([]byte(row[0]), []byte(row[1])); err == nil {
			t.Fatal("partial/malformed/contradictory owned kernel footprint admitted", strconv.Quote(row[0]))
		}
	}
}

func TestRuntimePHPCompilerMemoryInventoryRejectsMalformedMissingDuplicateOverflow(t *testing.T) {
	valid := "MemTotal: 3145728 kB\nMemAvailable: 1572864 kB\n"
	for _, raw := range []string{
		"", "MemTotal: 1 kB\n", "MemAvailable: 1 kB\n", valid + "MemAvailable: 1572864 kB\n",
		valid + "MemTotal: 3145728 kB\n", strings.TrimSuffix(valid, "\n"), valid + "\x00\n", valid + "\r\n",
		strings.Replace(valid, "1572864", "+1572864", 1), strings.Replace(valid, "1572864", "-1", 1),
		strings.Replace(valid, "1572864", "01572864", 1), strings.Replace(valid, "1572864", "1e6", 1),
		strings.Replace(valid, "1572864", "18446744073709551616", 1), strings.Replace(valid, "1572864", "18014398509481984", 1),
		strings.Replace(valid, "1572864", "3145729", 1), strings.Replace(valid, "3145728", "0", 1),
		strings.ReplaceAll(valid, "kB", "MB"), strings.ReplaceAll(valid, "kB", "KB"),
		"MemTotal: 3145728 kB extra\nMemAvailable: 1572864 kB\n",
		valid + strings.Repeat("x", 64<<10) + "\n",
	} {
		if _, _, err := runtimePHPCompilerHostMemory([]byte(raw)); !errors.Is(err, errRuntimePHPCompilerMemoryInventory) {
			t.Fatal("malformed inventory admitted", strconv.Quote(raw[:min(len(raw), 100)]), err)
		}
	}
	for _, raw := range []string{valid, "MemTotal:\t3145728 kB\nMemAvailable:       1572864 kB\nSwapFree: 0 kB\n"} {
		total, available, err := runtimePHPCompilerHostMemory([]byte(raw))
		if err != nil || total != 3<<30 || available != runtimePHPCompilerMemoryBytes+runtimePHPCompilerServiceReserve {
			t.Fatal("actual canonical procfs inventory lost", total, available, err)
		}
	}
}

func TestRuntimePHPCompilerMemoryBindingNeverAcceptsForeignSelectedReleaseFields(t *testing.T) {
	r, _ := runtimecatalog.Find("php-8.2.35")
	value := reflect.ValueOf(r)
	for i := range value.NumField() {
		t.Run(value.Type().Field(i).Name, func(t *testing.T) {
			forged := r
			field := reflect.ValueOf(&forged).Elem().Field(i)
			if value.Type().Field(i).Name == "ID" {
				field.SetString("php-8.3.36")
			} else {
				field.SetString("foreign")
			}
			if _, err := runtimePHPCompilerNeedsMemoryAdmission(forged); !errors.Is(err, errRuntimePHPCompilerMemoryIdentity) {
				t.Fatal("foreign source selected larger resource policy", err)
			}
		})
	}
	for _, id := range []string{"php-8.2.33", "php-8.3.33", "php-8.4.27", "php-8.5.12", "nginx-1.30.6", "apache-2.4.68", "mysql-8.4.11", "redis-8.2.10"} {
		r, found := runtimecatalog.Find(id)
		selected, err := runtimePHPCompilerNeedsMemoryAdmission(r)
		if !found || err != nil || selected || runtimePHPCompilerMemoryAdmission(r, nil) != nil {
			t.Fatal("unselected runtime gained a memory requirement", id, err)
		}
	}
}

func TestRuntimePHPCompilerMemoryKernelPolicyIsOneFiniteExactBudget(t *testing.T) {
	valid := map[string]string{"memory.max": "1073741824\n", "memory.high": "1073741824\n", "memory.swap.max": "0\n", "pids.max": "512\n"}
	if err := runtimePHPCompilerMemoryKernelPolicy(valid); err != nil {
		t.Fatal(err)
	}
	copyPolicy := func() map[string]string {
		copy := map[string]string{}
		for k, v := range valid {
			copy[k] = v
		}
		return copy
	}
	for key := range valid {
		for _, bad := range []string{"", "max\n", "infinity\n", "768M\n", "805306368\n", "0\n", "1G\n", "1073741824", "01073741824\n", "1073741824\r\n", "1073741824\n1073741824\n"} {
			if bad == valid[key] {
				continue
			}
			changed := copyPolicy()
			changed[key] = bad
			if err := runtimePHPCompilerMemoryKernelPolicy(changed); !errors.Is(err, errRuntimePHPCompilerMemoryKernel) {
				t.Fatal("non-exact policy admitted", key, strconv.Quote(bad), err)
			}
		}
		missing := copyPolicy()
		delete(missing, key)
		if runtimePHPCompilerMemoryKernelPolicy(missing) == nil {
			t.Fatal("missing real kernel bound admitted", key)
		}
	}
	extra := copyPolicy()
	extra["caller.memory.max"] = "1073741824\n"
	if runtimePHPCompilerMemoryKernelPolicy(extra) == nil || runtimePHPCompilerMemoryKernelPolicy(nil) == nil {
		t.Fatal("unknown or absent kernel policy admitted")
	}
}

func TestRuntimePHPCompilerMemoryAncestorReservesCapacityWithoutOverrides(t *testing.T) {
	for _, row := range [][2]string{{"max\n", "99999999999\n"}, {"1610612736\n", "0\n"}, {"2147483648\n", "536870912\n"}} {
		if err := runtimePHPCompilerMemoryAncestor([]byte(row[0]), []byte(row[1])); err != nil {
			t.Fatal("valid parent capacity rejected", row, err)
		}
	}
	for _, row := range [][2]string{{"", "0\n"}, {"max\n", ""}, {"max\n", "unknown\n"}, {"max\r\n", "0\n"}, {"max\n", "00\n"}, {"1610612736\n", "1\n"}, {"1073741824\n", "0\n"}, {"2147483648\n", "536870913\n"}, {"1\n", "2\n"}, {"0\n", "0\n"}} {
		if err := runtimePHPCompilerMemoryAncestor([]byte(row[0]), []byte(row[1])); err == nil {
			t.Fatal("unknown/insufficient parent capacity admitted", row)
		}
	}
}

func TestRuntimePHPCompilerMemoryTrueRootExceptionIsNotUnknownAncestorFallback(t *testing.T) {
	controllers := []byte("cpuset cpu io memory hugetlb pids rdma misc\n")
	if err := runtimePHPCompilerMemoryUncontrolledRoot(1, controllers, true, true, true); err != nil {
		t.Fatal("actual kernel root semantics rejected", err)
	}
	for _, inode := range []uint64{0, 2, 67, 12345} {
		if runtimePHPCompilerMemoryUncontrolledRoot(inode, controllers, true, true, true) == nil {
			t.Fatal("delegated/non-root/unknown inode admitted as uncontrolled root", inode)
		}
	}
	for _, flags := range [][3]bool{{false, true, true}, {true, false, true}, {true, true, false}, {false, false, false}} {
		if runtimePHPCompilerMemoryUncontrolledRoot(1, controllers, flags[0], flags[1], flags[2]) == nil {
			t.Fatal("partial absence or non-ENOENT read error admitted", flags)
		}
	}
	for _, raw := range []string{"", "cpu io pids\n", "memory memory\n", "Memory\n", "memory", "memory\r\n", "memory\x00\n", "memory invalid-controller\n", strings.Repeat("memory ", 1000) + "\n"} {
		if runtimePHPCompilerMemoryUncontrolledRoot(1, []byte(raw), true, true, true) == nil {
			t.Fatal("unknown/disabled/malformed kernel controller admitted", strconv.Quote(raw[:min(len(raw), 60)]))
		}
	}
}
