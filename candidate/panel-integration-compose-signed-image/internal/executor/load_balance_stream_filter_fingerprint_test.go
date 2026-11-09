package executor

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func streamFilterFixture(ingress bool) streamFilterProgram {
	p := streamFilterProgram{ID: 70, Type: 8, UID: 0, Flags: 1, Name: "sd_fw_egress", Tag: [8]byte{1, 2, 3}}
	prefix := "E_"
	if ingress {
		prefix, p.Name = "I_", "sd_fw_ingress"
	}
	v4 := make([]byte, 8)
	binary.LittleEndian.PutUint32(v4, 8)
	v4[4] = 127
	v6 := make([]byte, 20)
	binary.LittleEndian.PutUint32(v6, 128)
	v6[19] = 1
	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, 1)
	p.Maps = []streamFilterMap{
		{ID: 101, Type: 11, Name: streamFilterMapName("4_"), KeyBytes: 8, ValueBytes: 8, MaxEntries: 1, Flags: 1, Entries: []streamFilterEntry{{v4, bytes.Clone(value)}}},
		{ID: 102, Type: 11, Name: streamFilterMapName("6_"), KeyBytes: 20, ValueBytes: 8, MaxEntries: 1, Flags: 1, Entries: []streamFilterEntry{{v6, bytes.Clone(value)}}},
		{ID: 103, Type: 2, Name: streamFilterMapName(prefix), KeyBytes: 4, ValueBytes: 8, MaxEntries: 2},
	}
	for _, m := range p.Maps {
		code := make([]byte, 16)
		code[0], code[1] = 0x18, 0x11
		binary.LittleEndian.PutUint32(code[4:8], m.ID)
		p.Instructions = append(p.Instructions, code...)
	}
	p.Instructions = append(p.Instructions, 0x95, 0, 0, 0, 0, 0, 0, 0)
	return p
}

func TestStreamFilterFingerprintExcludesOnlyVerifiedAllocationIDs(t *testing.T) {
	for _, ingress := range []bool{false, true} {
		old := streamFilterFixture(ingress)
		wanted, err := streamFilterProgramSHA256(old, ingress)
		if err != nil {
			t.Fatal(err)
		}
		fresh := streamFilterFixture(ingress)
		fresh.ID = 800
		for i := range fresh.Maps {
			fresh.Maps[i].ID += 5000
			binary.LittleEndian.PutUint32(fresh.Instructions[i*16+4:i*16+8], fresh.Maps[i].ID)
		}
		fresh.Maps[0], fresh.Maps[2] = fresh.Maps[2], fresh.Maps[0]
		got, err := streamFilterProgramSHA256(fresh, ingress)
		if err != nil || got != wanted {
			t.Fatal("same actual instructions and ACL data changed solely with kernel allocation/map enumeration", ingress, err)
		}
	}
}

func TestStreamFilterFingerprintKeepsEveryPolicyAndInstructionField(t *testing.T) {
	base, err := streamFilterProgramSHA256(streamFilterFixture(true), true)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*streamFilterProgram){
		"opcode":       func(p *streamFilterProgram) { p.Instructions[len(p.Instructions)-8] = 0xb7 },
		"immediate":    func(p *streamFilterProgram) { p.Instructions[len(p.Instructions)-4] = 1 },
		"tag":          func(p *streamFilterProgram) { p.Tag[7] = 1 },
		"ACL-address":  func(p *streamFilterProgram) { p.Maps[0].Entries[0].Key[4] = 126 },
		"ACL-prefix":   func(p *streamFilterProgram) { binary.LittleEndian.PutUint32(p.Maps[0].Entries[0].Key, 9) },
		"ACL-value":    func(p *streamFilterProgram) { binary.LittleEndian.PutUint64(p.Maps[0].Entries[0].Value, 2) },
		"ACL-capacity": func(p *streamFilterProgram) { p.Maps[0].MaxEntries = 2 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := streamFilterFixture(true)
			change(&p)
			got, err := streamFilterProgramSHA256(p, true)
			if err == nil && got == base {
				t.Fatal("changed kernel policy data had the same fingerprint")
			}
		})
	}
}

func TestStreamFilterFingerprintRefusesAmbiguousOrUnimplementedKernelShapes(t *testing.T) {
	cases := map[string]func(*streamFilterProgram){
		"program-type":           func(p *streamFilterProgram) { p.Type = 1 },
		"creator":                func(p *streamFilterProgram) { p.UID = 1000 },
		"flags":                  func(p *streamFilterProgram) { p.Flags = 3 },
		"direction":              func(p *streamFilterProgram) { p.Name = "sd_fw_egress" },
		"empty-tag":              func(p *streamFilterProgram) { p.Tag = [8]byte{} },
		"truncated-instruction":  func(p *streamFilterProgram) { p.Instructions = p.Instructions[:len(p.Instructions)-1] },
		"unknown-map-reference":  func(p *streamFilterProgram) { binary.LittleEndian.PutUint32(p.Instructions[4:8], 9000) },
		"high-map-pointer":       func(p *streamFilterProgram) { p.Instructions[12] = 1 },
		"pseudo-map-value":       func(p *streamFilterProgram) { p.Instructions[1] = 0x21 },
		"duplicate-map":          func(p *streamFilterProgram) { p.Maps[1].ID = p.Maps[0].ID },
		"unreferenced-map":       func(p *streamFilterProgram) { p.Maps[0].ID = 99 },
		"unknown-map-type":       func(p *streamFilterProgram) { p.Maps[0].Type = 1 },
		"ACL-map-name":           func(p *streamFilterProgram) { p.Maps[0].Name = "unrelated" },
		"ACL-key-size":           func(p *streamFilterProgram) { p.Maps[0].KeyBytes = 9 },
		"ACL-host-bits":          func(p *streamFilterProgram) { p.Maps[0].Entries[0].Key[7] = 1 },
		"ACL-value-size":         func(p *streamFilterProgram) { p.Maps[0].Entries[0].Value = []byte{1} },
		"ACL-unknown-verdict":    func(p *streamFilterProgram) { binary.LittleEndian.PutUint64(p.Maps[0].Entries[0].Value, 3) },
		"ACL-extra-entry":        func(p *streamFilterProgram) { p.Maps[0].Entries = append(p.Maps[0].Entries, p.Maps[0].Entries[0]) },
		"ACL-oversize":           func(p *streamFilterProgram) { p.Maps[0].MaxEntries = streamFilterMaxMapEntries + 1 },
		"counter-direction":      func(p *streamFilterProgram) { p.Maps[2].Name = streamFilterMapName("E_") },
		"counter-shape":          func(p *streamFilterProgram) { p.Maps[2].ValueBytes = 16 },
		"counter-flags":          func(p *streamFilterProgram) { p.Maps[2].Flags = 1 },
		"claimed-counter-values": func(p *streamFilterProgram) { p.Maps[2].Entries = []streamFilterEntry{{[]byte{0}, []byte{0}}} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := streamFilterFixture(true)
			change(&p)
			if _, err := streamFilterProgramSHA256(p, true); err == nil {
				t.Fatal("ambiguous kernel observation accepted")
			}
		})
	}
}

func TestStreamFilterPolicyPreservesDirectionAndAttachmentOrder(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	base, err := streamFilterPolicySHA256([]string{a, b}, []string{a})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := streamFilterPolicySHA256([]string{b, a}, []string{a})
	if err != nil || changed == base {
		t.Fatal("attachment ordering lost")
	}
	for _, body := range [][]string{nil, {""}, {strings.Repeat("G", 64)}} {
		if _, err := streamFilterPolicySHA256(body, []string{a}); err == nil {
			t.Fatal("missing or malformed fingerprint accepted")
		}
	}
	if streamFilterReceiptFormat(1, a) || streamFilterReceiptFormat(2, "") ||
		streamFilterReceiptFormat(2, strings.Repeat("0", 64)) || streamFilterReceiptFormat(3, a) ||
		!streamFilterReceiptFormat(1, "") || !streamFilterReceiptFormat(2, a) {
		t.Fatal("legacy and new-format identity rules overlap")
	}
}
