package executor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

// Only the Linux observer constructs these snapshots from held kernel FDs.
// They are neither HTTP inputs nor saved evidence that grants live authority.
type streamFilterEntry struct {
	Key   []byte
	Value []byte
}
type streamFilterMap struct {
	ID, Type, KeyBytes, ValueBytes, MaxEntries, Flags uint32
	Name                                              string
	Entries                                           []streamFilterEntry
}
type streamFilterProgram struct {
	ID, Type, UID, Flags uint32
	Name                 string
	Tag                  [8]byte
	Instructions         []byte
	Maps                 []streamFilterMap
}
type streamFilterCanonicalEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type streamFilterCanonicalMap struct {
	Type        uint32                       `json:"type"`
	Name        string                       `json:"name"`
	KeyBytes    uint32                       `json:"key_bytes"`
	ValueBytes  uint32                       `json:"value_bytes"`
	MaxEntries  uint32                       `json:"max_entries"`
	Flags       uint32                       `json:"flags"`
	CounterOnly bool                         `json:"counter_only"`
	Entries     []streamFilterCanonicalEntry `json:"entries"`
}
type streamFilterReference struct {
	Instruction int    `json:"instruction"`
	MapSHA256   string `json:"map_sha256"`
}

const streamFilterMaxMapEntries = 4096
const streamFilterMaxInstructions = 32 << 10
const streamFilterMaxMaps = 8

func streamFilterMapName(prefix string) string {
	// systemd's BPF object-name conversion, restricted to this fixed unit.
	name := prefix + strings.ReplaceAll(strings.ReplaceAll(loadbalancestream.ServiceUnitName, "-", "_"), ".", "_")
	return name[:15]
}

// systemd's IP accounting arrays contain only packet/byte counters. Their exact
// definition, directional name and every instruction using them remain in the
// fingerprint; only those two live counter values are excluded. ACL map keys
// AND values are always included. See systemd v255 src/core/bpf-firewall.c.
func streamFilterMapCanonical(m streamFilterMap, ingress bool) (streamFilterCanonicalMap, error) {
	out := streamFilterCanonicalMap{Type: m.Type, Name: m.Name, KeyBytes: m.KeyBytes,
		ValueBytes: m.ValueBytes, MaxEntries: m.MaxEntries, Flags: m.Flags,
		Entries: []streamFilterCanonicalEntry{}}
	if m.ID == 0 || m.MaxEntries == 0 || m.MaxEntries > streamFilterMaxMapEntries {
		return out, loadbalancestream.ErrService
	}
	if m.Type == 2 { // BPF_MAP_TYPE_ARRAY; exactly systemd IP accounting.
		prefix := "E_"
		if ingress {
			prefix = "I_"
		}
		if m.Name != streamFilterMapName(prefix) || m.KeyBytes != 4 || m.ValueBytes != 8 ||
			m.MaxEntries != 2 || m.Flags != 0 || len(m.Entries) != 0 {
			return out, loadbalancestream.ErrService
		}
		out.CounterOnly = true
		return out, nil
	}
	if m.Type != 11 || m.Flags != 1 || m.ValueBytes != 8 ||
		len(m.Entries) == 0 || len(m.Entries) > int(m.MaxEntries) ||
		!(m.KeyBytes == 8 && m.Name == streamFilterMapName("4_") ||
			m.KeyBytes == 20 && m.Name == streamFilterMapName("6_")) {
		return out, loadbalancestream.ErrService
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if len(e.Key) != int(m.KeyBytes) || len(e.Value) != 8 {
			return out, loadbalancestream.ErrService
		}
		bits := binary.LittleEndian.Uint32(e.Key[:4])
		ip, valid := netip.AddrFromSlice(e.Key[4:])
		value := binary.LittleEndian.Uint64(e.Value)
		if !valid || ip.Is4In6() || bits > uint32(ip.BitLen()) ||
			netip.PrefixFrom(ip, int(bits)).Masked().Addr() != ip || (value != 1 && value != 2) {
			return out, loadbalancestream.ErrService
		}
		key := hex.EncodeToString(e.Key)
		if seen[key] {
			return out, loadbalancestream.ErrService
		}
		seen[key] = true
		out.Entries = append(out.Entries, streamFilterCanonicalEntry{key, hex.EncodeToString(e.Value)})
	}
	sort.Slice(out.Entries, func(i, j int) bool { return out.Entries[i].Key < out.Entries[j].Key })
	return out, nil
}

// Numeric program/map IDs are allocations, not policy. Preserve every actual
// translated instruction and exact ACL map content, replacing ONLY a verified
// BPF_PSEUDO_MAP_FD's numeric map reference with that complete map's digest.
// No program tag alone, manager property, UID or successful GET establishes
// equivalence. A changed opcode, immediate, map definition or prefix differs.
func streamFilterProgramSHA256(p streamFilterProgram, ingress bool) (string, error) {
	name := "sd_fw_egress"
	if ingress {
		name = "sd_fw_ingress"
	}
	if p.ID == 0 || p.Type != 8 || p.UID != 0 || p.Flags != 1 || p.Name != name ||
		p.Tag == ([8]byte{}) || len(p.Instructions) < 8 || len(p.Instructions) > streamFilterMaxInstructions ||
		len(p.Instructions)%8 != 0 || len(p.Maps) < 1 || len(p.Maps) > streamFilterMaxMaps {
		return "", loadbalancestream.ErrService
	}
	mapHashes := map[uint32]string{}
	for _, m := range p.Maps {
		if _, exists := mapHashes[m.ID]; exists {
			return "", loadbalancestream.ErrService
		}
		v, err := streamFilterMapCanonical(m, ingress)
		if err != nil {
			return "", err
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return "", loadbalancestream.ErrService
		}
		mapHashes[m.ID] = core.Hash(string(raw))
	}
	code := bytes.Clone(p.Instructions)
	references := []streamFilterReference{}
	used := map[uint32]bool{}
	for at := 0; at < len(code); at += 8 {
		if code[at] != 0x18 { // BPF_LD | BPF_DW | BPF_IMM
			continue
		}
		if at+16 > len(code) || !bytes.Equal(code[at+8:at+12], make([]byte, 4)) {
			return "", loadbalancestream.ErrService
		}
		source := code[at+1] >> 4
		if source == 1 { // kernel-returned BPF_PSEUDO_MAP_FD -> actual map ID.
			id := binary.LittleEndian.Uint32(code[at+4 : at+8])
			digest, exists := mapHashes[id]
			if !exists || !bytes.Equal(code[at+8:at+16], make([]byte, 8)) {
				return "", loadbalancestream.ErrService
			}
			binary.LittleEndian.PutUint32(code[at+4:at+8], 0)
			references = append(references, streamFilterReference{at / 8, digest})
			used[id] = true
		} else if source != 0 {
			return "", loadbalancestream.ErrService // No unimplemented pseudo-value or kernel pointer inference.
		}
		at += 8
	}
	if len(used) != len(mapHashes) || len(references) == 0 {
		return "", loadbalancestream.ErrService
	}
	canonical := struct {
		Format       int                     `json:"format"`
		Direction    string                  `json:"direction"`
		Type         uint32                  `json:"type"`
		Name         string                  `json:"name"`
		Tag          string                  `json:"tag"`
		Flags        uint32                  `json:"flags"`
		Instructions []byte                  `json:"instructions"`
		Maps         []streamFilterReference `json:"map_references"`
	}{1, name, p.Type, p.Name, hex.EncodeToString(p.Tag[:]), p.Flags, code, references}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", loadbalancestream.ErrService
	}
	return core.Hash(string(raw)), nil
}

func streamFilterPolicySHA256(ingress, egress []string) (string, error) {
	if len(ingress) < 1 || len(ingress) > 64 || len(egress) < 1 || len(egress) > 64 {
		return "", loadbalancestream.ErrService
	}
	for _, set := range [][]string{ingress, egress} {
		for _, digest := range set {
			if !loadBalanceStreamAccountHash(digest) || digest == strings.Repeat("0", 64) {
				return "", loadbalancestream.ErrService
			}
		}
	}
	// Attachment ordering is retained; no sorting-away of a policy change.
	raw, err := json.Marshal(struct {
		Format  int      `json:"format"`
		Ingress []string `json:"ingress"`
		Egress  []string `json:"egress"`
	}{1, ingress, egress})
	if err != nil {
		return "", loadbalancestream.ErrService
	}
	return core.Hash(string(raw)), nil
}

// Legacy native bodies retain exact program-ID semantics. Only a newly
// recorded format2 body, after actual kernel instruction/map observation, can
// establish a policy fingerprint for later read-side equivalence checks.
func streamFilterReceiptFormat(format int, digest string) bool {
	return format == 1 && digest == "" || format == 2 && loadBalanceStreamAccountHash(digest) && digest != strings.Repeat("0", 64)
}
