package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

const (
	EgressTableName           = "panel_lbstream"
	EgressChainName           = "output"
	MaxEgressObservationBytes = 4 << 20
)

var ErrEgressGuard = errors.New("TCP/UDP 出站防护的专用身份、完整两代节点或实际内核规则无法核对")

type egressListener struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type egressBackend struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type egressDocument struct {
	Format    int              `json:"format"`
	UID       uint32           `json:"uid"`
	Listeners []egressListener `json:"listeners"`
	Backends  []egressBackend  `json:"backends"`
}

// EgressGuard is a pure, closed policy, not creation or activation authority.
// Only the Root controller holding the original operation and installation may
// create a MISSING table, or replace its exact, previously witnessed chain in
// one nft transaction. A matching comment/digest alone never proves ownership.
// No method touches the kernel, opens a port, grants a capability or changes
// the service's existing cgroup policy. Public exposure remains gated on the
// original controller's complete kernel/lifecycle and forwarding acceptance.
type EgressGuard struct {
	document egressDocument
	raw      []byte
	sha256   string
}

// EgressGuardObservation describes one complete actual kernel table read. It
// is NOT a service/NSS/ownership/forwarding witness; callers must also retain
// original table and chain handles and verify the service's dedicated UID.
type EgressGuardObservation struct {
	PolicySHA256 string   `json:"policy_sha256"`
	TableHandle  uint64   `json:"table_handle"`
	ChainHandle  uint64   `json:"chain_handle"`
	RuleHandles  []uint64 `json:"rule_handles"`
}

// PlanEgressGuard checks the COMPLETE current+retiring generations, including
// backups. Destination protocol AND IP AND port must match. The only other
// permitted service traffic is an ESTABLISHED conntrack REPLY from an exact
// frontend/probe port. In particular a generic established/related accept or
// source-port-only accept would permit unrelated outbound traffic and is never
// emitted. Other UIDs and packets without a readable socket UID follow the
// host's existing policy without alteration. UID predicates cannot identify
// orphaned packets after their socket file closes; the separately verified
// service cgroup IP policy remains required, not replaced by this guard.
func PlanEgressGuard(current, retiring []Entry, facts ValidationContext, uid uint32) (EgressGuard, error) {
	if uid < 100 || uid >= 1000 || ValidateSet(current, facts) != nil || ValidateSet(retiring, facts) != nil || !serviceOverlap(current, retiring) {
		return EgressGuard{}, ErrEgressGuard
	}
	d := egressDocument{Format: 1, UID: uid, Listeners: []egressListener{}, Backends: []egressBackend{}}
	listeners, backends := map[egressListener]bool{}, map[egressBackend]bool{}
	var memory int64
	for _, generation := range [][]Entry{current, retiring} {
		for _, entry := range generation {
			if entry.Removed {
				continue
			}
			memory += FixedBytesPerEntry + int64(entry.MaxSessions)*BytesPerSession
			if memory > facts.MemoryBudgetBytes || memory > MaxMemoryBudget {
				return EgressGuard{}, ErrEgressGuard
			}
			listeners[egressListener{entry.Protocol, entry.Port}] = true
			listeners[egressListener{"tcp", entry.ProbePort}] = true
			for _, node := range entry.Nodes {
				ip, port, err := nodeAddress(node.Address)
				if err != nil {
					return EgressGuard{}, ErrEgressGuard
				}
				backends[egressBackend{entry.Protocol, ip.String(), port}] = true
			}
		}
	}
	for listener := range listeners {
		d.Listeners = append(d.Listeners, listener)
	}
	for backend := range backends {
		d.Backends = append(d.Backends, backend)
	}
	slices.SortFunc(d.Listeners, func(a, b egressListener) int {
		if order := strings.Compare(a.Protocol, b.Protocol); order != 0 {
			return order
		}
		return a.Port - b.Port
	})
	slices.SortFunc(d.Backends, func(a, b egressBackend) int {
		if order := strings.Compare(a.Protocol, b.Protocol); order != 0 {
			return order
		}
		if order := netip.MustParseAddr(a.Address).Compare(netip.MustParseAddr(b.Address)); order != 0 {
			return order
		}
		return a.Port - b.Port
	})
	raw, err := json.Marshal(d)
	if err != nil {
		return EgressGuard{}, ErrEgressGuard
	}
	return EgressGuard{document: d, raw: raw, sha256: serviceDigest(raw)}, nil
}

func (g EgressGuard) valid() bool {
	if g.document.Format != 1 || g.document.UID < 100 || g.document.UID >= 1000 || len(g.raw) == 0 || !serviceHash(g.sha256) {
		return false
	}
	raw, err := json.Marshal(g.document)
	return err == nil && bytes.Equal(raw, g.raw) && serviceDigest(raw) == g.sha256
}

func (g EgressGuard) SHA256() string {
	if !g.valid() {
		return ""
	}
	return g.sha256
}

func (g EgressGuard) tableComment() string {
	return "panel-lbstream-v1 uid=" + strconv.FormatUint(uint64(g.document.UID), 10)
}

func (g EgressGuard) policyComment() string {
	return "panel-lbstream-policy-v1 sha256=" + g.sha256
}

// CreateRules must be used only after an original authorized absence witness.
// 'create table' fails rather than merging into an existing/foreign table.
func (g EgressGuard) CreateRules() ([]byte, error) {
	if !g.valid() {
		return nil, ErrEgressGuard
	}
	var out strings.Builder
	fmt.Fprintf(&out, "create table inet %s { comment %q; }\n", EgressTableName, g.tableComment())
	fmt.Fprintf(&out, "add chain inet %s %s { type filter hook output priority 10; policy accept; }\n", EgressTableName, EgressChainName)
	g.writeRules(&out)
	return []byte(out.String()), nil
}

// ReplacementRules is an atomic nft batch for an already-owned, fully checked
// table. It retains the base-chain and table identities, replaces the COMPLETE
// chain including its final policy marker, and never creates a missing table
// or chain, flushes a ruleset or changes another table. It is
// not safe to submit from a retry, a read, an old receipt or a digest claim.
func (g EgressGuard) ReplacementRules() ([]byte, error) {
	if !g.valid() {
		return nil, ErrEgressGuard
	}
	var out strings.Builder
	fmt.Fprintf(&out, "flush chain inet %s %s\n", EgressTableName, EgressChainName)
	g.writeRules(&out)
	return []byte(out.String()), nil
}

func (g EgressGuard) writeRules(out *strings.Builder) {
	prefix := "add rule inet " + EgressTableName + " " + EgressChainName + " "
	fmt.Fprintf(out, "%smeta skuid != %d return\n", prefix, g.document.UID)
	for _, listener := range g.document.Listeners {
		fmt.Fprintf(out, "%sct state established ct direction reply %s sport %d accept\n", prefix, listener.Protocol, listener.Port)
	}
	for _, backend := range g.document.Backends {
		family := "ip6"
		if netip.MustParseAddr(backend.Address).Is4() {
			family = "ip"
		}
		fmt.Fprintf(out, "%s%s daddr %s %s dport %d accept\n", prefix, family, backend.Address, backend.Protocol, backend.Port)
	}
	// A failed skuid lookup breaks evaluation of the current rule; it does NOT
	// make `skuid != UID` true. An unconditional final drop would therefore
	// discard unrelated, already-closed sockets' queued TCP data and FINs. Keep
	// the deny positively scoped to the same dedicated service identity.
	fmt.Fprintf(out, "%smeta skuid %d drop comment %q\n", prefix, g.document.UID, g.policyComment())
}

func egressMatch(op string, left, right any) map[string]any {
	return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
}
func egressPayload(protocol, field string) map[string]any {
	return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
}
func (g EgressGuard) expressions() [][]any {
	rules := [][]any{{egressMatch("!=", map[string]any{"meta": map[string]any{"key": "skuid"}}, json.Number(strconv.FormatUint(uint64(g.document.UID), 10))), map[string]any{"return": nil}}}
	for _, l := range g.document.Listeners {
		rules = append(rules, []any{
			egressMatch("in", map[string]any{"ct": map[string]any{"key": "state"}}, "established"),
			egressMatch("==", map[string]any{"ct": map[string]any{"key": "direction"}}, "reply"),
			egressMatch("==", egressPayload(l.Protocol, "sport"), json.Number(strconv.Itoa(l.Port))), map[string]any{"accept": nil},
		})
	}
	for _, b := range g.document.Backends {
		family := "ip6"
		if netip.MustParseAddr(b.Address).Is4() {
			family = "ip"
		}
		rules = append(rules, []any{egressMatch("==", egressPayload(family, "daddr"), b.Address), egressMatch("==", egressPayload(b.Protocol, "dport"), json.Number(strconv.Itoa(b.Port))), map[string]any{"accept": nil}})
	}
	return append(rules, []any{egressMatch("==", map[string]any{"meta": map[string]any{"key": "skuid"}}, json.Number(strconv.FormatUint(uint64(g.document.UID), 10))), map[string]any{"drop": nil}})
}

// Parse the entire bounded JSON, rejecting duplicate keys at EVERY depth,
// excessive nesting, noncanonical numbers, unknown objects and trailing data.
// json.Unmarshal alone would silently accept a duplicate verdict or match.
func egressJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxEgressObservationBytes {
		return nil, ErrEgressGuard
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	remaining := 400000
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		remaining--
		if depth > 16 || remaining < 0 {
			return nil, ErrEgressGuard
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, ErrEgressGuard
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				object := map[string]any{}
				for decoder.More() {
					key, err := decoder.Token()
					text, ok := key.(string)
					if err != nil || !ok || len(text) > 128 {
						return nil, ErrEgressGuard
					}
					if _, duplicate := object[text]; duplicate {
						return nil, ErrEgressGuard
					}
					object[text], err = value(depth + 1)
					if err != nil {
						return nil, err
					}
				}
				if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
					return nil, ErrEgressGuard
				}
				return object, nil
			case '[':
				list := []any{}
				for decoder.More() {
					item, err := value(depth + 1)
					if err != nil {
						return nil, err
					}
					list = append(list, item)
				}
				if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
					return nil, ErrEgressGuard
				}
				return list, nil
			}
			return nil, ErrEgressGuard
		}
		if text, ok := token.(string); ok && (len(text) > 256 || strings.ContainsAny(text, "\x00\r\n")) {
			return nil, ErrEgressGuard
		}
		if number, ok := token.(json.Number); ok {
			n, err := strconv.ParseUint(string(number), 10, 64)
			if err != nil || strconv.FormatUint(n, 10) != string(number) || n > 1<<63-1 {
				return nil, ErrEgressGuard
			}
		}
		return token, nil
	}
	out, err := value(0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrEgressGuard
	}
	return out, nil
}

func egressObject(value any, keys ...string) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return nil, false
		}
	}
	return object, true
}
func egressHandle(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(string(number), 10, 64)
	return n, err == nil && n > 0 && n <= 1<<63-1 && strconv.FormatUint(n, 10) == string(number)
}

// EgressTableAbsent accepts a COMPLETE successful `nft -s -a -j list tables`
// response. An error from `list table` is not evidence of absence: permission,
// namespace and parser failures must not authorize a create. This is only a
// read-only admission fact, never ownership or mutation authority.
func EgressTableAbsent(raw []byte) bool {
	document, err := egressJSON(raw)
	root, ok := egressObject(document, "nftables")
	if err != nil || !ok {
		return false
	}
	list, ok := root["nftables"].([]any)
	if !ok || len(list) < 1 || len(list) > 4097 || !egressMetainfo(list[0]) {
		return false
	}
	seen := map[string]bool{}
	for _, item := range list[1:] {
		outer, ok := egressObject(item, "table")
		table, valid := outer["table"].(map[string]any)
		// Foreign tables may carry the documented comment/flags metadata.
		// Inspect those fields but never read, change or adopt their contents.
		// Our OWN table remains forbidden even when it is dormant or owned.
		for key, value := range table {
			switch key {
			case "family", "name", "handle":
			case "comment":
				if _, text := value.(string); !text {
					return false
				}
			case "flags":
				if text, single := value.(string); single {
					// Older libnftables can emit a stale allocation (for
					// example its version or a table name) for a single flag.
					// This FOREIGN metadata is not interpreted as authority:
					// only the complete family/name inventory proves absence.
					// Own-table presence below is always refused, whatever
					// this field contains. Never relax Inspect's own-table AST.
					if text == "" || len(text) > 128 {
						return false
					}
					continue
				}
				flags, array := value.([]any)
				if !array || len(flags) > 3 {
					return false
				}
				seenFlags := map[string]bool{}
				for _, flag := range flags {
					text, known := flag.(string)
					if !known || !slices.Contains([]string{"dormant", "owner", "persist"}, text) || seenFlags[text] {
						return false
					}
					seenFlags[text] = true
				}
			default:
				return false
			}
		}
		_, handleOK := egressHandle(table["handle"])
		family, familyOK := table["family"].(string)
		name, nameOK := table["name"].(string)
		key := family + ":" + name
		if !ok || !valid || !handleOK || !familyOK || !nameOK || name == "" ||
			!slices.Contains([]string{"inet", "ip", "ip6", "arp", "bridge", "netdev"}, family) || seen[key] ||
			family == "inet" && name == EgressTableName {
			return false
		}
		seen[key] = true
	}
	return true
}

func egressMetainfo(value any) bool {
	outer, ok := egressObject(value, "metainfo")
	meta, valid := egressObject(outer["metainfo"], "version", "release_name", "json_schema_version")
	version, versionOK := meta["version"].(string)
	release, releaseOK := meta["release_name"].(string)
	return ok && valid && meta["json_schema_version"] == json.Number("1") && versionOK && releaseOK &&
		version != "" && len(version) <= 32 && release != "" && len(release) <= 128
}

// ValidateObservation checks a historical typed value's exact policy and
// complete handle set. It does not read the kernel or prove table ownership.
func (g EgressGuard) ValidateObservation(o EgressGuardObservation) error {
	if !g.valid() || o.PolicySHA256 != g.sha256 || o.TableHandle == 0 || o.TableHandle > 1<<63-1 ||
		o.ChainHandle == 0 || o.ChainHandle > 1<<63-1 || len(o.RuleHandles) != len(g.expressions()) {
		return ErrEgressGuard
	}
	seen := map[uint64]bool{o.ChainHandle: true}
	for _, handle := range o.RuleHandles {
		if handle == 0 || handle > 1<<63-1 || seen[handle] {
			return ErrEgressGuard
		}
		seen[handle] = true
	}
	return nil
}

// Inspect requires nft -s -j list table inet panel_lbstream, not a filtered
// rule/chain read. Handles, order, every predicate, comment, verdict, hook,
// priority and policy must match. No unknown set/map/chain/rule is ignored.
func (g EgressGuard) Inspect(raw []byte) (EgressGuardObservation, error) {
	var empty EgressGuardObservation
	if !g.valid() {
		return empty, ErrEgressGuard
	}
	document, err := egressJSON(raw)
	root, ok := egressObject(document, "nftables")
	if err != nil || !ok {
		return empty, ErrEgressGuard
	}
	list, ok := root["nftables"].([]any)
	expressions := g.expressions()
	if !ok || len(list) != len(expressions)+3 {
		return empty, ErrEgressGuard
	}
	if !egressMetainfo(list[0]) {
		return empty, ErrEgressGuard
	}
	outer, ok := egressObject(list[1], "table")
	table, tableOK := egressObject(outer["table"], "family", "name", "handle", "comment")
	tableHandle, handleOK := egressHandle(table["handle"])
	if !ok || !tableOK || !handleOK || table["family"] != "inet" || table["name"] != EgressTableName || table["comment"] != g.tableComment() {
		return empty, ErrEgressGuard
	}
	outer, ok = egressObject(list[2], "chain")
	chain, chainOK := egressObject(outer["chain"], "family", "table", "name", "handle", "type", "hook", "prio", "policy")
	chainHandle, handleOK := egressHandle(chain["handle"])
	if !ok || !chainOK || !handleOK || chain["family"] != "inet" || chain["table"] != EgressTableName || chain["name"] != EgressChainName || chain["type"] != "filter" || chain["hook"] != "output" || chain["prio"] != json.Number("10") || chain["policy"] != "accept" {
		return empty, ErrEgressGuard
	}
	out := EgressGuardObservation{PolicySHA256: g.sha256, TableHandle: tableHandle, ChainHandle: chainHandle, RuleHandles: make([]uint64, 0, len(expressions))}
	seen := map[uint64]bool{chainHandle: true}
	for index, want := range expressions {
		outer, ok := egressObject(list[index+3], "rule")
		keys := []string{"family", "table", "chain", "handle", "expr"}
		last := index == len(expressions)-1
		if last {
			keys = append(keys, "comment")
		}
		rule, ruleOK := egressObject(outer["rule"], keys...)
		handle, handleOK := egressHandle(rule["handle"])
		if !ok || !ruleOK || !handleOK || seen[handle] || rule["family"] != "inet" || rule["table"] != EgressTableName || rule["chain"] != EgressChainName || !reflect.DeepEqual(rule["expr"], want) || (last && rule["comment"] != g.policyComment()) {
			return empty, ErrEgressGuard
		}
		seen[handle] = true
		out.RuleHandles = append(out.RuleHandles, handle)
	}
	return out, nil
}
