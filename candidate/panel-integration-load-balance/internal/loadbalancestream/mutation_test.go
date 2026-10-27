package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func policy(entry Entry) *Policy {
	return &Policy{Protocol: entry.Protocol, Port: entry.Port, Nodes: append([]Node(nil), entry.Nodes...), Method: entry.Method, ConnectMilliseconds: entry.ConnectMilliseconds, SessionSeconds: entry.SessionSeconds, MaxSessions: entry.MaxSessions, UDPRequests: entry.UDPRequests, UDPResponses: entry.UDPResponses}
}
func replacement(entry Entry) Mutation {
	return Mutation{Format: 1, Action: "replace", Name: entry.Name, ExpectedRevision: entry.Revision, ExpectedFingerprint: Fingerprint(entry), Policy: policy(entry)}
}
func TestMutationPlansOriginalCASCreateReplaceRemoveAndExplicitRevival(t *testing.T) {
	initial := fixture()
	create := Mutation{Format: 1, Action: "create", Name: initial.Name, Policy: policy(initial)}
	a, err := PlanMutation(nil, create, initial.ProbePort, facts())
	if err != nil || a.Before != nil || a.After.Revision != 1 || a.AfterConfig.Fingerprint != Fingerprint(a.After) || len(a.BeforeConfig.Stream) != 0 {
		t.Fatal(a, err)
	}
	current := a.After
	change := replacement(current)
	change.Policy.Method = "least-connections"
	before, _ := json.Marshal(a.Entries)
	b, err := PlanMutation(a.Entries, change, 0, facts())
	if err != nil || b.After.Revision != 2 || b.After.ProbePort != current.ProbePort || b.Before == nil || Fingerprint(*b.Before) != Fingerprint(current) || b.BeforeConfig.Fingerprint != a.AfterConfig.Fingerprint || bytes.Equal(b.BeforeConfig.Stream, b.AfterConfig.Stream) {
		t.Fatal(b, err)
	}
	after, _ := json.Marshal(a.Entries)
	if !bytes.Equal(before, after) {
		t.Fatal("input state mutated")
	}
	if _, err = PlanMutation(b.Entries, change, 0, facts()); err == nil {
		t.Fatal("stale replay became original success")
	}
	remove := Mutation{Format: 1, Action: "remove", Name: current.Name, ExpectedRevision: b.After.Revision, ExpectedFingerprint: Fingerprint(b.After)}
	c, err := PlanMutation(b.Entries, remove, 0, facts())
	if err != nil || !c.After.Removed || c.After.Revision != 3 || len(c.AfterConfig.Stream) != 0 || len(c.AfterConfig.HTTP) != 0 || len(c.Entries) != 1 {
		t.Fatal(c, err)
	}
	if _, err = PlanMutation(c.Entries, create, initial.ProbePort, facts()); err == nil {
		t.Fatal("tombstone overwritten as a new name")
	}
	revival := replacement(c.After)
	d, err := PlanMutation(c.Entries, revival, 0, facts())
	if err != nil || d.After.Removed || d.After.Revision != 4 || len(d.AfterConfig.Stream) == 0 {
		t.Fatal(d, err)
	}
	remove.ExpectedRevision = c.After.Revision
	remove.ExpectedFingerprint = Fingerprint(c.After)
	if _, err = PlanMutation(c.Entries, remove, 0, facts()); err == nil {
		t.Fatal("already removed entry produced a new removal effect")
	}
	// Mutation input, returned before, returned after and complete-set copies do
	// not share a node slice with the original current state or with one another.
	d.After.Nodes[0].Weight = 9
	d.Entries[0].Nodes[0].Weight = 8
	d.Before.Nodes[0].Weight = 7
	revival.Policy.Nodes[0].Weight = 6
	if c.After.Nodes[0].Weight != 1 || c.Entries[0].Nodes[0].Weight != 1 || d.After.Nodes[0].Weight != 9 {
		t.Fatal("alias changed original or independent plan")
	}
}
func TestMutationRejectsForeignRevisionIdentityPolicyAndServerAllocation(t *testing.T) {
	original := fixture()
	changes := map[string]func(*Mutation, *int){
		"format": func(m *Mutation, p *int) { m.Format = 2 }, "action": func(m *Mutation, p *int) { m.Action = "reload" }, "different-name": func(m *Mutation, p *int) { m.Name = "foreign.invalid" },
		"zero-revision": func(m *Mutation, p *int) { m.ExpectedRevision = 0 }, "future-revision": func(m *Mutation, p *int) { m.ExpectedRevision++ },
		"different-fingerprint": func(m *Mutation, p *int) { m.ExpectedFingerprint += "x" }, "fingerprint-case": func(m *Mutation, p *int) { m.ExpectedFingerprint = strings.ToUpper(m.ExpectedFingerprint) },
		"different-original": func(m *Mutation, p *int) {
			m.ExpectedFingerprint = Fingerprint(Entry{Name: original.Name, Revision: original.Revision})
		},
		"nil-policy": func(m *Mutation, p *int) { m.Policy = nil }, "caller-probe": func(m *Mutation, p *int) { *p = original.ProbePort + 1 },
		"policy-injection": func(m *Mutation, p *int) { m.Policy.Nodes[0].Address = "127.0.0.1:19100" },
		"unbounded-memory": func(m *Mutation, p *int) { m.Policy.MaxSessions = 513 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			m := replacement(original)
			probe := 0
			change(&m, &probe)
			if _, err := PlanMutation([]Entry{original}, m, probe, facts()); err == nil {
				t.Fatal("unsafe mutation accepted")
			}
		})
	}
	create := Mutation{Format: 1, Action: "create", Name: original.Name, Policy: policy(original)}
	if _, err := PlanMutation([]Entry{original}, create, original.ProbePort, facts()); err == nil {
		t.Fatal("existing original adopted as fresh")
	}
	if _, err := PlanMutation(nil, create, 0, facts()); err == nil {
		t.Fatal("caller omitted server allocation")
	}
	exhausted := clone(original)
	exhausted.Revision = (1 << 60) - 1
	if _, err := PlanMutation([]Entry{exhausted}, replacement(exhausted), 0, facts()); err == nil {
		t.Fatal("revision overflow")
	}
}
func TestMutationCanonicalWireCannotCarryMetadataOrUnknownAuthority(t *testing.T) {
	m := replacement(fixture())
	raw, _ := json.Marshal(m)
	got, err := DecodeMutation(raw)
	if err != nil || got.Name != m.Name {
		t.Fatal(got, err)
	}
	cases := [][]byte{
		append(append([]byte(nil), raw...), '\n'), append(append([]byte(nil), raw...), []byte("{}")...),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"format\":1"), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"probe_port\":43000"), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"actor_id\":\"root\""), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"required_panel_features\":[]"), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1,\"removed\":false"), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"Format\":1"), 1),
		bytes.Replace(raw, []byte("\"format\":1"), []byte("\"format\":1e0"), 1),
		bytes.Replace(raw, []byte("\"max_sessions\":64"), []byte("\"max_sessions\":64,\"revision\":5"), 1),
	}
	for i, value := range cases {
		if _, err = DecodeMutation(value); err == nil {
			t.Fatalf("wire authority case %d accepted", i)
		}
	}
	remove := Mutation{Format: 1, Action: "remove", Name: m.Name, ExpectedRevision: 1, ExpectedFingerprint: m.ExpectedFingerprint}
	canonical, _ := json.Marshal(remove)
	if _, err = DecodeMutation(canonical); err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeMutation(bytes.Replace(canonical, []byte(",\"policy\":null"), nil, 1)); err == nil {
		t.Fatal("omitted private field accepted")
	}
}
func TestMutationValidatesCompleteCurrentSetAndNewCrossEntryGraph(t *testing.T) {
	original := fixture()
	foreign := clone(original)
	foreign.Name = "other.invalid"
	foreign.Port = original.Port + 1
	foreign.ProbePort = original.ProbePort + 1
	m := replacement(original)
	m.Policy.Nodes[0].Address = "127.0.0.1:42001"
	foreign.Nodes[0].Address = "127.0.0.1:42000"
	if _, err := PlanMutation([]Entry{original, foreign}, m, 0, facts()); err == nil {
		t.Fatal("new complete-set cycle accepted")
	}
	f := facts()
	f.OccupiedTCPPorts = []int{original.ProbePort}
	if _, err := PlanMutation([]Entry{original}, replacement(original), 0, f); err == nil {
		t.Fatal("foreign listener repaired or adopted")
	}
	bad := clone(foreign)
	bad.Name = original.Name
	if _, err := PlanMutation([]Entry{original, bad}, replacement(original), 0, facts()); err == nil {
		t.Fatal("ambiguous current metadata adopted")
	}
	if _, err := PlanMutation([]Entry{original}, replacement(original), 0, ValidationContext{}); err == nil {
		t.Fatal("missing server facts accepted")
	}
}
