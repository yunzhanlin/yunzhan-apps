package executor

import (
	"fmt"
	"math"
	"strconv"
	"testing"

	"local/panel/internal/geodata"
)

func TestWAFCountryMemoryBudgetUsesCompleteGeometryWithTwoCyclesAndUncreditedReserve(t *testing.T) {
	metadata := geodata.CountrySelectionMetadata{Networks: 2, Bytes: 64, RadixNodes: 8}
	budget, err := wafCountryReloadMemoryBudget(metadata)
	if err != nil || budget.Parser != 64<<20+8*64+64*16 || budget.Reload != 2*budget.Parser || budget.Host != budget.Reload+512<<20 {
		t.Fatal(budget, err)
	}
	if budget.Host%1024 != 0 {
		t.Fatal("boundary fixture is not representable in kernel kB")
	}
	for _, delta := range []int64{-1024, 0, 1024} {
		available := uint64(int64(budget.Host) + delta)
		raw := []byte(fmt.Sprintf("MemTotal: 4194304 kB\nMemAvailable: %d kB\n", available/1024))
		err := wafCountryHostMemoryAdmission(raw, budget)
		if (err == nil) != (delta >= 0) {
			t.Fatal("host reserve boundary relaxed", delta, err)
		}
	}
	for _, bad := range []geodata.CountrySelectionMetadata{{}, {Networks: 1, Bytes: 1, RadixNodes: 2}, {Networks: 1, Bytes: 1, RadixNodes: 131}, {Networks: 1<<20 + 1, Bytes: 1, RadixNodes: 1<<20 + 3}, {Networks: 1, Bytes: -1, RadixNodes: 3}, {Networks: 1, Bytes: geodata.MaxCountryCIDRBytes + 1, RadixNodes: 3}} {
		if got, err := wafCountryReloadMemoryBudget(bad); err == nil || got != (wafCountryMemoryBudget{}) {
			t.Fatal("partial/overflow metadata became usable budget", bad, got, err)
		}
	}
	overflowParser := uint64(math.MaxUint64)
	overflowReload := overflowParser * 2
	for _, bad := range []wafCountryMemoryBudget{{}, {Parser: overflowParser, Reload: overflowReload, Host: overflowReload + wafCountryMemoryHostReserve}, {Parser: budget.Parser, Reload: budget.Reload, Host: budget.Host - 1}} {
		if wafCountryHostMemoryAdmission([]byte("MemTotal: 4194304 kB\nMemAvailable: 4194304 kB\n"), bad) == nil {
			t.Fatal("forged budget accepted", bad)
		}
	}
}

func TestWAFCountryMemoryCgroupExactByteHighLimitAndCurrentMustAllBeKnown(t *testing.T) {
	const additional = 128 << 20
	used := uint64(17 << 20)
	decimal := func(n uint64) []byte { return []byte(strconv.FormatUint(n, 10) + "\n") }
	for _, delta := range []int64{-1, 0, 1} {
		limit := uint64(int64(used+additional) + delta)
		for _, high := range []bool{false, true} {
			maximum, threshold := []byte("max\n"), []byte("max\n")
			if high {
				threshold = decimal(limit)
			} else {
				maximum = decimal(limit)
			}
			if err := wafCountryGroupMemoryAdmission(maximum, threshold, decimal(used), additional); (err == nil) != (delta >= 0) {
				t.Fatal("one-byte parent/high boundary ignored", delta, high, err)
			}
		}
	}
	if wafCountryGroupMemoryAdmission(decimal(math.MaxUint64), []byte("max\n"), decimal(math.MaxUint64-additional+1), additional) == nil {
		t.Fatal("unsigned subtraction wrapped")
	}
	for _, raw := range []string{"", "max", "max\nmax\n", "-1\n", "+1\n", "01\n", "1 \n", " 1\n", "1\r\n", "1\x00\n", "18446744073709551616\n", "infinity\n"} {
		if wafCountryGroupMemoryAdmission([]byte(raw), []byte("max\n"), decimal(used), additional) == nil {
			t.Fatal("unknown maximum accepted", raw)
		}
		if wafCountryGroupMemoryAdmission([]byte("max\n"), []byte(raw), decimal(used), additional) == nil {
			t.Fatal("unknown high accepted", raw)
		}
		if wafCountryGroupMemoryAdmission([]byte("max\n"), []byte("max\n"), []byte(raw), additional) == nil {
			t.Fatal("unknown current accepted", raw)
		}
	}
	if wafCountryGroupMemoryAdmission([]byte("max\n"), []byte("max\n"), []byte("max\n"), additional) == nil {
		t.Fatal("unlimited current invented")
	}
}

func TestWAFCountryMemoryIncludesExistingMasterHighWaterWithoutReuseCredit(t *testing.T) {
	base, err := wafCountryReloadMemoryBudget(geodata.CountrySelectionMetadata{Networks: 2, Bytes: 64, RadixNodes: 8})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Name:\tnginx\nVmPeak:\t9999999999999999999 kB\nVmHWM:\t524288 kB\nVmRSS:\t131072 kB\n")
	got, err := wafCountryMemoryWithMaster(base, raw)
	if err != nil || got.Parser != base.Parser+512<<20 || got.Reload != base.Reload+1<<30 || got.Host != base.Host+1<<30 {
		t.Fatal("existing full configuration, retained peak or two-cycle reserve omitted", got, err)
	}
	for _, bad := range []string{"", "VmHWM: 1 kB\n", "VmRSS: 1 kB\n", "VmHWM: 0 kB\nVmRSS: 0 kB\n", "VmHWM: 1 kB\nVmRSS: 2 kB\n", "VmHWM: 2 kB\nVmHWM: 2 kB\nVmRSS: 1 kB\n", "VmHWM: 02 kB\nVmRSS: 1 kB\n", "VmHWM: 2 MB\nVmRSS: 1 kB\n", "VmHWM: 2 kB\nVmRSS: 1 kB", "VmHWM: 18446744073709551615 kB\nVmRSS: 1 kB\n", "VmHWM: 2 kB\nVmRSS: 1 kB\r\n"} {
		if value, err := wafCountryMemoryWithMaster(base, []byte(bad)); err == nil || value != (wafCountryMemoryBudget{}) {
			t.Fatal("missing/partial/malformed master became zero memory", bad, value, err)
		}
	}
}
