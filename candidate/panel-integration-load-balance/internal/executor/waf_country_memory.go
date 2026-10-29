package executor

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"local/panel/internal/geodata"
)

const wafCountryMemoryHostReserve uint64 = 512 << 20
const wafCountryMemoryUnitReserve uint64 = 64 << 20
const wafCountryMemoryParserMax uint64 = wafCountryMemoryUnitReserve + ((1<<20)*128+2)*64 + uint64(geodata.MaxCountryCIDRBytes)*16
const wafCountryMemoryMasterMax uint64 = 1 << 40

var errWAFCountryMemoryInventory = errors.New("无法完整核实国家规则的内存预算或内核余量，未允许新的国家规则解析或重载")

type wafCountryMemoryBudget struct {
	Parser, Reload, Host uint64
}

// This is a conservative admission estimate, NOT a reservation or an OOM
// guarantee. A 64-bit Nginx geo radix node has three pointers and uintptr_t
// (32 bytes); charge twice that, sixteen times the complete input bytes and
// 64MiB for allocator/preallocated trees, labels and parser overhead. Reserve
// two new cycles for reload and leave 512MiB for existing host services. Never
// credit existing/reclaimable cache or alter a kernel/service limit.
// https://github.com/nginx/nginx/blob/release-1.24.0/src/core/ngx_radix_tree.h
func wafCountryReloadMemoryBudget(metadata geodata.CountrySelectionMetadata) (wafCountryMemoryBudget, error) {
	var empty wafCountryMemoryBudget
	if metadata.Networks < 1 || metadata.Networks > 1<<20 || metadata.Bytes < 1 || metadata.Bytes > geodata.MaxCountryCIDRBytes || metadata.RadixNodes < uint64(metadata.Networks)+2 || metadata.RadixNodes > uint64(metadata.Networks)*128+2 {
		return empty, errWAFCountryMemoryInventory
	}
	parser := wafCountryMemoryUnitReserve + metadata.RadixNodes*64 + uint64(metadata.Bytes)*16
	return wafCountryMemoryBudget{Parser: parser, Reload: parser * 2, Host: parser*2 + wafCountryMemoryHostReserve}, nil
}

func wafCountryHostMemoryAdmission(raw []byte, budget wafCountryMemoryBudget) error {
	_, available, err := runtimePHPCompilerHostMemory(raw)
	if err != nil || budget.Parser < wafCountryMemoryUnitReserve || budget.Parser > wafCountryMemoryParserMax+wafCountryMemoryMasterMax || budget.Reload != budget.Parser*2 || budget.Host != budget.Reload+wafCountryMemoryHostReserve {
		return errWAFCountryMemoryInventory
	}
	if available < budget.Host {
		return fmt.Errorf("国家规则解析及双代重载的保守预算需 %d MiB，并为已有服务预留 512 MiB；当前可用 %d MiB，未允许新的国家规则解析或重载。请减少所选地区或释放容量；停用国家规则不受此预算限制", (budget.Reload+(1<<20)-1)>>20, available>>20)
	}
	return nil
}

// The full syntax check and new cycle parse existing sites and modules too.
// Add the actual selected master's resident high-water mark to EACH proposed
// cycle; never subtract an allegedly reusable old country allocation. HWM is
// conservative after earlier reloads. Missing/hidden/malformed status is not
// a zero-footprint Nginx. VmPeak is virtual address space and is not used.
func wafCountryMemoryWithMaster(base wafCountryMemoryBudget, raw []byte) (wafCountryMemoryBudget, error) {
	var empty wafCountryMemoryBudget
	if base.Parser < wafCountryMemoryUnitReserve || base.Parser > wafCountryMemoryParserMax || base.Reload != base.Parser*2 || base.Host != base.Reload+wafCountryMemoryHostReserve || len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return empty, errWAFCountryMemoryInventory
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "VmHWM:" && fields[0] != "VmRSS:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return empty, errWAFCountryMemoryInventory
		}
		if _, exists := values[fields[0]]; exists {
			return empty, errWAFCountryMemoryInventory
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != fields[1] || n == 0 || n > wafCountryMemoryMasterMax/1024 {
			return empty, errWAFCountryMemoryInventory
		}
		values[fields[0]] = n * 1024
	}
	high, current := values["VmHWM:"], values["VmRSS:"]
	if high == 0 || current == 0 || high < current {
		return empty, errWAFCountryMemoryInventory
	}
	parser := base.Parser + high
	return wafCountryMemoryBudget{Parser: parser, Reload: parser * 2, Host: parser*2 + wafCountryMemoryHostReserve}, nil
}

func wafCountryMemoryNumber(raw []byte, unlimited bool) (uint64, bool, error) {
	if len(raw) == 0 || len(raw) > 32 || raw[len(raw)-1] != '\n' || bytes.ContainsAny(raw, "\x00\r") {
		return 0, false, errWAFCountryMemoryInventory
	}
	value := string(raw[:len(raw)-1])
	if unlimited && value == "max" {
		return 0, true, nil
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, false, errWAFCountryMemoryInventory
	}
	return n, false, nil
}

func wafCountryGroupMemoryAdmission(maximum, high, current []byte, additional uint64) error {
	if additional < wafCountryMemoryUnitReserve {
		return errWAFCountryMemoryInventory
	}
	used, _, err := wafCountryMemoryNumber(current, false)
	if err != nil {
		return err
	}
	for _, raw := range [][]byte{maximum, high} {
		limit, unlimited, err := wafCountryMemoryNumber(raw, true)
		if err != nil {
			return err
		}
		if !unlimited && (used > limit || limit-used < additional) {
			return errors.New("国家规则的语法检查、Nginx 或其父 cgroup 内存余量不足；没有提高限额、使用交换或忽略 memory.high，未允许新的解析或重载")
		}
	}
	return nil
}
