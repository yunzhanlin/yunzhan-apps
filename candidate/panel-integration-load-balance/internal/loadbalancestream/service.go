package loadbalancestream

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const (
	ServiceAccount       = "panel-lbstream"
	ServiceRuntimePrefix = "/run/panel-load-balance-stream"
	ServiceConfigPath    = "/etc/panel/load-balance-stream/nginx.conf"
	ServiceHostReserve   = int64(512 << 20)
	ServiceBaseMemory    = int64(128 << 20)
	MaxServiceUnitBytes  = 128 << 10
)

var ErrService = errors.New("TCP/UDP 独立服务的完整两代配置、专用身份、内核隔离或可用资源无法核对；未启动或重载服务")

// ServiceFacts are independently measured Root facts, NEVER browser fields or
// an authority grant. Root must bind the actual dedicated locked NSS account,
// complete native installation ledger/ELF and live cgroup/kernel support. It
// must verify the resulting process UID, all capability sets, NNP, limits and
// IP filter after start. A caller-provided digest or bool proves none of that.
type ServiceFacts struct {
	Validation             ValidationContext
	AvailableMemoryBytes   int64
	HardOpenFiles          uint64
	UnifiedMemoryAvailable bool
	IPFilterAvailable      bool
	AccountUID             uint32
	AccountGID             uint32
	AccountRecordSHA256    string
	NginxVersion           string
	NginxSHA256            string
}

// ServicePlan contains bytes only. It creates no account/file/unit, performs no
// command/reload and makes no health or enforcement claim. No automatic restart
// or boot enablement is emitted: committed-generation startup/recovery authority
// must be implemented and verified by the Root controller before exposure.
type ServicePlan struct {
	Current                       RuntimeConfiguration
	Retiring                      RuntimeConfiguration
	Unit                          []byte
	SHA256                        string
	AllowedIPs                    []string
	AggregatePlannedBytes         int64
	MemoryHighBytes               int64
	MemoryMaxBytes                int64
	RequiredAvailableMemoryBytes  int64
	ShouldRun                     bool
	RequiresOriginalKernelWitness bool
}

func serviceDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func serviceHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) || value == strings.Repeat("0", 64) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func serviceNginx(version string) string {
	// A syntax-safe path is not an installation/ELF/stream-module proof.
	switch version {
	case "1.30.6", "1.31.5":
		return "/opt/panel/runtimes/nginx/" + version + "/sbin/nginx"
	}
	return ""
}

// Generations can overlap while old workers drain. Check the union graph, not
// just each individually acyclic configuration. An endpoint may retain its
// original same-name role but cannot be silently re-used by another identity
// or become a probe until its old generation has actually disappeared.
func serviceOverlap(current, retiring []Entry) bool {
	type owner struct{ name, role string }
	owners, probes, graph := map[string]owner{}, map[int]bool{}, map[string][]string{}
	for _, generation := range [][]Entry{retiring, current} {
		for _, entry := range generation {
			if entry.Removed {
				continue
			}
			for _, endpoint := range []struct{ key, role string }{{entry.Protocol + ":" + strconv.Itoa(entry.Port), "data"}, {"tcp:" + strconv.Itoa(entry.ProbePort), "probe"}} {
				identity := owner{entry.Name, endpoint.role}
				if prior, found := owners[endpoint.key]; found && prior != identity {
					return false
				}
				owners[endpoint.key] = identity
			}
			probes[entry.ProbePort] = true
			graph[entry.Protocol+":"+strconv.Itoa(entry.Port)] = nil
		}
	}
	for _, generation := range [][]Entry{retiring, current} {
		for _, entry := range generation {
			if entry.Removed {
				continue
			}
			from := entry.Protocol + ":" + strconv.Itoa(entry.Port)
			for _, node := range entry.Nodes {
				ip, port, err := nodeAddress(node.Address)
				if err != nil {
					return false
				}
				if ip.IsLoopback() {
					if probes[port] {
						return false
					}
					to := entry.Protocol + ":" + strconv.Itoa(port)
					if _, exists := graph[to]; exists {
						graph[from] = append(graph[from], to)
					}
				}
			}
		}
	}
	colors := map[string]uint8{}
	var visit func(string) bool
	visit = func(key string) bool {
		if colors[key] == 1 {
			return false
		}
		if colors[key] == 2 {
			return true
		}
		colors[key] = 1
		for _, next := range graph[key] {
			if !visit(next) {
				return false
			}
		}
		colors[key] = 2
		return true
	}
	for key := range graph {
		if !visit(key) {
			return false
		}
	}
	return true
}

// PlanService admits at most one current and one retiring generation under the
// UNCHANGED <=1GiB aggregate buffer/zone budget. Root must first census all real
// owned workers; a third/unknown generation refuses another reload. Passing nil
// retiring is legitimate only after that original generation is proven gone.
// Removing the last active entry only drains the already owned generation; it
// does not admit another daemon/worker allocation. It must remain possible when
// free memory falls below the start reserve. All identities, kernel capability,
// configuration and aggregate-budget checks still apply to that stop policy.
func PlanService(current, retiring []Entry, facts ServiceFacts) (ServicePlan, error) {
	return renderServicePolicy(current, retiring, facts, true)
}

// RecordedServicePlan reconstructs the original policy for READ-ONLY runtime
// inspection. Current free memory is still measured/returned by the caller;
// it is not fabricated, and an already resident daemon is not reported dead
// merely because a second full allocation could not be admitted now. This
// result NEVER authorizes a start/reload; those paths use PlanService above.
func RecordedServicePlan(current, retiring []Entry, facts ServiceFacts) (ServicePlan, error) {
	return renderServicePolicy(current, retiring, facts, false)
}

// Called only after both complete generations have passed RenderRuntime. The
// allocation exception is exactly ONE last-entry removal: no dropped/rewritten
// tombstone, changed endpoint/policy, bulk removal or invented revision. This is
// not authority; the original control seed and owned native drain remain required.
func serviceLastRemoval(current, retiring []Entry) bool {
	if len(current) == 0 || len(current) != len(retiring) {
		return false
	}
	next := make(map[string]Entry, len(current))
	for _, entry := range current {
		if !entry.Removed {
			return false
		}
		next[entry.Name] = entry
	}
	removed := 0
	for _, prior := range retiring {
		if !prior.Removed {
			removed++
			prior.Revision++
			prior.Removed = true
		}
		after, exists := next[prior.Name]
		want, e1 := json.Marshal(prior)
		got, e2 := json.Marshal(after)
		if !exists || e1 != nil || e2 != nil || !bytes.Equal(want, got) {
			return false
		}
	}
	return removed == 1
}

func renderServicePolicy(current, retiring []Entry, facts ServiceFacts, admit bool) (ServicePlan, error) {
	nginx := serviceNginx(facts.NginxVersion)
	if nginx == "" || !serviceHash(facts.NginxSHA256) || !serviceHash(facts.AccountRecordSHA256) ||
		facts.AccountUID < 100 || facts.AccountUID >= 1000 || facts.AccountGID < 100 || facts.AccountGID >= 1000 ||
		!facts.UnifiedMemoryAvailable || !facts.IPFilterAvailable || facts.HardOpenFiles < RuntimeOpenFiles ||
		facts.AvailableMemoryBytes < 0 || facts.AvailableMemoryBytes > 1<<60 {
		return ServicePlan{}, ErrService
	}
	next, err := RenderRuntime(current, ServiceRuntimePrefix, facts.Validation)
	if err != nil {
		return ServicePlan{}, ErrService
	}
	prior, err := RenderRuntime(retiring, ServiceRuntimePrefix, facts.Validation)
	if err != nil || !serviceOverlap(current, retiring) {
		return ServicePlan{}, ErrService
	}
	planned := next.PlannedBufferAndZoneBytes + prior.PlannedBufferAndZoneBytes
	if planned > facts.Validation.MemoryBudgetBytes || planned > MaxMemoryBudget {
		return ServicePlan{}, ErrService
	}
	align := func(value, size int64) int64 { return ((value + size - 1) / size) * size }
	high := align(ServiceBaseMemory+planned+(planned+7)/8, 8<<20)
	maximum := align(ServiceBaseMemory+planned+(planned+3)/4, 16<<20)
	drainingLast := next.ActiveEntries == 0 && prior.ActiveEntries == 1 && serviceLastRemoval(current, retiring)
	if high > maximum || maximum > ServiceBaseMemory+MaxMemoryBudget+MaxMemoryBudget/4 || admit && !drainingLast && facts.AvailableMemoryBytes < maximum+ServiceHostReserve {
		return ServicePlan{}, ErrService
	}
	allowed := map[string]bool{"127.0.0.0/8": true, "::1/128": true}
	for _, generation := range [][]Entry{retiring, current} {
		for _, entry := range generation {
			if entry.Removed {
				continue
			}
			for _, node := range entry.Nodes {
				ip, _, e := nodeAddress(node.Address)
				if e != nil {
					return ServicePlan{}, ErrService
				}
				if !ip.IsLoopback() {
					allowed[netip.PrefixFrom(ip, ip.BitLen()).String()] = true
				}
			}
		}
	}
	ips := make([]string, 0, len(allowed))
	for ip := range allowed {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	unit := renderServiceUnit(nginx, high, maximum, ips)
	if len(unit) > MaxServiceUnitBytes {
		return ServicePlan{}, ErrService
	}
	return ServicePlan{Current: next, Retiring: prior, Unit: []byte(unit), SHA256: serviceDigest([]byte(unit)), AllowedIPs: append([]string(nil), ips...), AggregatePlannedBytes: planned, MemoryHighBytes: high, MemoryMaxBytes: maximum, RequiredAvailableMemoryBytes: maximum + ServiceHostReserve, ShouldRun: next.ActiveEntries != 0, RequiresOriginalKernelWitness: true}, nil
}
