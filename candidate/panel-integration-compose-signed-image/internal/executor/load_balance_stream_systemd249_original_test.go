package executor

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type original249Fields struct {
	ID         uint32 `json:"id"`
	Type       uint32 `json:"type"`
	UID        uint32 `json:"uid"`
	Flags      uint32 `json:"flags"`
	KeyBytes   uint32 `json:"key_bytes"`
	ValueBytes uint32 `json:"value_bytes"`
	MaxEntries uint32 `json:"max_entries"`
	Name       string `json:"name"`
	Tag        string `json:"tag"`
}
type original249Program struct {
	Fields original249Fields `json:"fields"`
	Code   string            `json:"translated_instructions"`
	Maps   []struct {
		Fields  original249Fields `json:"fields"`
		Entries []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"entries"`
	} `json:"maps"`
}

func original249Fixture(t *testing.T, index int) (streamFilterProgram, bool) {
	t.Helper()
	raw, err := os.ReadFile("testdata/stream-systemd249-original-kernel-arm64.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Format   int `json:"format"`
		Programs []struct {
			Ingress  bool               `json:"ingress"`
			Original original249Program `json:"original"`
		} `json:"programs"`
	}
	if json.Unmarshal(raw, &f) != nil || f.Format != 1 || len(f.Programs) != 2 {
		t.Fatal("captured original kernel fixture malformed")
	}
	original := f.Programs[index]
	o := original.Original
	decode := func(s string) []byte {
		v, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	p := streamFilterProgram{ID: o.Fields.ID, Type: o.Fields.Type, UID: o.Fields.UID, Flags: o.Fields.Flags, Name: string(decode(o.Fields.Name)), Instructions: decode(o.Code)}
	tag := decode(o.Fields.Tag)
	if len(tag) != 8 {
		t.Fatal("original tag malformed")
	}
	copy(p.Tag[:], tag)
	for _, m := range o.Maps {
		v := streamFilterMap{ID: m.Fields.ID, Type: m.Fields.Type, KeyBytes: m.Fields.KeyBytes, ValueBytes: m.Fields.ValueBytes, MaxEntries: m.Fields.MaxEntries, Flags: m.Fields.Flags, Name: string(decode(m.Fields.Name))}
		for _, entry := range m.Entries {
			v.Entries = append(v.Entries, streamFilterEntry{decode(entry.Key), decode(entry.Value)})
		}
		p.Maps = append(p.Maps, v)
	}
	return p, original.Ingress
}
func TestLoadBalanceStreamOriginalSystemd249AnonymousProgramsKeepCompletePolicy(t *testing.T) {
	for index := 0; index < 2; index++ {
		p, ingress := original249Fixture(t, index)
		before, _ := json.Marshal(p)
		if p.Name != "" || !streamFilterAnonymousPolicyMatches(p, []string{"127.0.0.0/8", "::1/128"}) {
			t.Fatal("actual original complete anonymous policy differs")
		}
		first, err := streamFilterProgramSHA256(p, ingress)
		if err != nil || !loadBalanceStreamAccountHash(first) {
			t.Fatal("actual original systemd249 programme rejected", err)
		}
		again, err := streamFilterProgramSHA256(p, ingress)
		after, _ := json.Marshal(p)
		if err != nil || again != first || !bytes.Equal(before, after) {
			t.Fatal("original kernel observation mutated or fingerprint unstable")
		}
	}
}
func TestLoadBalanceStreamOriginalSystemd249CannotBorrowNamesMapsOrInstructions(t *testing.T) {
	for index := 0; index < 2; index++ {
		for _, change := range []string{"named-profile", "mixed-map-name", "missing-map", "counter-size", "missing-code", "missing-tag", "foreign-type", "foreign-uid", "foreign-flags", "foreign-name", "foreign-ACL-value", "duplicate-map-id", "missing-ACL-entry"} {
			t.Run(string(rune('0'+index))+"/"+change, func(t *testing.T) {
				p, ingress := original249Fixture(t, index)
				switch change {
				case "named-profile":
					for i := range p.Maps {
						m := &p.Maps[i]
						if m.Type == 2 {
							prefix := "E_"
							if ingress {
								prefix = "I_"
							}
							m.Name = streamFilterMapName(prefix)
						} else if m.KeyBytes == 8 {
							m.Name = streamFilterMapName("4_")
						} else {
							m.Name = streamFilterMapName("6_")
						}
					}
				case "mixed-map-name":
					p.Maps[0].Name = streamFilterMapName("4_")
				case "missing-map":
					p.Maps = p.Maps[:2]
				case "counter-size":
					p.Maps[2].MaxEntries = 3
				case "missing-code":
					p.Instructions = nil
				case "missing-tag":
					p.Tag = [8]byte{}
				case "foreign-type":
					p.Type = 1
				case "foreign-uid":
					p.UID = 1
				case "foreign-flags":
					p.Flags = 0
				case "foreign-name":
					p.Name = "foreign"
				case "foreign-ACL-value":
					p.Maps[0].Entries[0].Value[0] = 2
				case "duplicate-map-id":
					p.Maps[1].ID = p.Maps[0].ID
				case "missing-ACL-entry":
					p.Maps[0].Entries = nil
				}
				if _, err := streamFilterProgramSHA256(p, ingress); err == nil {
					t.Fatal("unreviewed anonymous profile admitted")
				}
			})
		}
		p, ingress := original249Fixture(t, index)
		original, err := streamFilterProgramSHA256(p, ingress)
		if err != nil {
			t.Fatal(err)
		}
		p.Maps[0].Entries[0].Key[4] ^= 1
		if streamFilterAnonymousPolicyMatches(p, []string{"127.0.0.0/8", "::1/128"}) {
			t.Fatal("changed ACL prefix matched held service plan")
		}
		changed, err := streamFilterProgramSHA256(p, ingress)
		if err == nil && changed == original {
			t.Fatal("changed original ACL bytes lost in fingerprint")
		}
		p, ingress = original249Fixture(t, index)
		p.Instructions[0] ^= 1
		changed, err = streamFilterProgramSHA256(p, ingress)
		if err == nil && changed == original {
			t.Fatal("changed original opcode lost in fingerprint")
		}
	}
}
