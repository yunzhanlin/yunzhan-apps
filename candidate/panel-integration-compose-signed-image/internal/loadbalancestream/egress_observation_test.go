package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEgressAbsenceRequiresCompleteSuccessfulTableInventory(t *testing.T) {
	meta := `{"metainfo":{"version":"1.0.9","release_name":"Old Doc Yak #3","json_schema_version":1}}`
	inventory := func(tables ...string) []byte {
		return []byte(`{"nftables":[` + strings.Join(append([]string{meta}, tables...), ",") + `]}`)
	}
	table := `{"table":{"family":"inet","name":"foreign","handle":7}}`
	for _, raw := range [][]byte{inventory(), inventory(table), inventory(
		`{"table":{"family":"ip","name":"panel_lbstream","handle":7}}`,
		`{"table":{"family":"ip6","name":"filter","handle":7,"comment":"existing host filter","flags":["dormant"]}}`,
		`{"table":{"family":"bridge","name":"filter","handle":9,"flags":"owner"}}`,
		`{"table":{"family":"netdev","name":"filter","handle":11,"flags":["owner","persist"]}}`,
		`{"table":{"family":"arp","name":"filter","handle":13,"flags":[]}}`,
		// Captured on the ARM64 Ubuntu 24.04 native fixture: a valid
		// complete inventory, but old libnftables emitted its version for
		// the unrelated table's single dormant flag. Do not adopt that
		// metadata, or mistake an existing own table for an absent one.
		`{"table":{"family":"inet","name":"qa_l4_egress_foreign","handle":1,"flags":"1.0.9","comment":"unrelated private QA"}}`,
		`{"table":{"family":"ip","name":"foreign_stale_allocation","handle":15,"flags":"foreign_stale_allocation"}}`,
	)} {
		before := bytes.Clone(raw)
		if !EgressTableAbsent(raw) || !bytes.Equal(before, raw) {
			t.Fatalf("complete foreign-table metadata refused or mutated: %s", raw)
		}
	}
	for _, raw := range [][]byte{
		nil, []byte(`{"nftables":[]}`), []byte(`{"nftables":[` + table + `]}`),
		inventory(table, table), inventory(`{"table":{"family":"inet","name":"panel_lbstream","handle":7,"flags":"dormant"}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":0}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":9223372036854775808}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7e0}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":"7"}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"verified":true}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"comment":null}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":null}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":""}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":"` + strings.Repeat("f", 129) + `"}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":1}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":["future"]}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":["owner","owner"]}}`),
		inventory(`{"table":{"family":"ip","name":"x","handle":7,"flags":[1]}}`),
		inventory(`{"table":{"family":"inet","name":"x","name":"panel_lbstream","handle":7}}`),
		inventory(`{"table":{"family":"unknown","name":"x","handle":7}}`),
		inventory(`{"table":{"family":"ip","name":"","handle":7}}`),
		inventory(`{"table":{"family":"ip","name":"x"}}`),
		inventory(`{"chain":{"family":"inet","table":"panel_lbstream","name":"output","handle":1}}`),
		[]byte(`{"nftables":[` + meta + `],"nftables":[]}`),
		append(inventory(), []byte(`{}`)...), inventory(strings.Repeat(table+",", 4096) + table),
	} {
		if EgressTableAbsent(raw) {
			t.Fatalf("error, own-table or incomplete/ambiguous inventory accepted: %.200s", raw)
		}
	}
	for _, flags := range []string{`"dormant"`, `"1.0.9"`, `"qa_l4_egress_foreign"`, `""`, `[]`, `["owner","persist"]`} {
		if EgressTableAbsent(inventory(`{"table":{"family":"inet","name":"panel_lbstream","handle":1,"flags":` + flags + `}}`)) {
			t.Fatalf("own table was mistaken for absent with flags %s", flags)
		}
	}
}

func TestEgressHistoricalObservationRequiresShapeAndFreshLiveHandleComparison(t *testing.T) {
	policy := mustEgress(t, []Entry{fixture()}, nil)
	raw := egressFixtureJSON(t, policy)
	observation, err := policy.Inspect(raw)
	if err != nil || policy.ValidateObservation(observation) != nil {
		t.Fatal("complete observation rejected", err)
	}
	for name, mutate := range map[string]func(*EgressGuardObservation){
		"policy":         func(o *EgressGuardObservation) { o.PolicySHA256 = strings.Repeat("f", 64) },
		"table-zero":     func(o *EgressGuardObservation) { o.TableHandle = 0 },
		"table-overflow": func(o *EgressGuardObservation) { o.TableHandle = 1 << 63 },
		"chain-zero":     func(o *EgressGuardObservation) { o.ChainHandle = 0 },
		"chain-overflow": func(o *EgressGuardObservation) { o.ChainHandle = 1 << 63 },
		"missing":        func(o *EgressGuardObservation) { o.RuleHandles = o.RuleHandles[1:] },
		"extra":          func(o *EgressGuardObservation) { o.RuleHandles = append(o.RuleHandles, 123) },
		"rule-zero":      func(o *EgressGuardObservation) { o.RuleHandles[0] = 0 },
		"rule-overflow":  func(o *EgressGuardObservation) { o.RuleHandles[0] = 1 << 63 },
		"duplicate":      func(o *EgressGuardObservation) { o.RuleHandles[1] = o.RuleHandles[0] },
		"chain-as-rule":  func(o *EgressGuardObservation) { o.RuleHandles[0] = o.ChainHandle },
	} {
		t.Run(name, func(t *testing.T) {
			copy := observation
			copy.RuleHandles = append([]uint64{}, observation.RuleHandles...)
			mutate(&copy)
			if policy.ValidateObservation(copy) != ErrEgressGuard {
				t.Fatal("partial/invalid historical observation accepted")
			}
		})
	}
	// Historical validation checks well-formed DATA, not live ownership. Even
	// reordered well-formed handles must be compared to a fresh full table.
	reordered := observation
	reordered.RuleHandles = append([]uint64{}, observation.RuleHandles...)
	reordered.RuleHandles[0], reordered.RuleHandles[1] = reordered.RuleHandles[1], reordered.RuleHandles[0]
	if policy.ValidateObservation(reordered) != nil || reflect.DeepEqual(reordered, observation) {
		t.Fatal("historical shape or live equality boundary changed")
	}
	encoded, _ := json.Marshal(reordered)
	if bytes.Equal(encoded, raw) {
		t.Fatal("historical fields were confused with a complete kernel inventory")
	}
	if (EgressGuard{}).ValidateObservation(observation) != ErrEgressGuard {
		t.Fatal("empty policy accepted typed historical data")
	}
}

func TestEgressNft106RequiresMatchingTextCommentAndHandles(t *testing.T) {
	guard := mustEgress(t, []Entry{fixture()}, nil)
	complete := string(egressFixtureJSON(t, guard))
	modern := strings.Replace(complete, `"comment":"panel-lbstream-v1 uid=991",`, "", 1)
	if modern == complete {
		t.Fatal("fixture table comment did not change")
	}
	old := strings.Replace(modern, `"version":"1.1.3"`, `"version":"1.0.6"`, 1)
	old = strings.Replace(old, `"family":"inet","handle":1,"name":"panel_lbstream"`, `"family":"inet","handle":9,"name":"panel_lbstream"`, 1)
	text := "table inet panel_lbstream { # handle 9\n" +
		"\tcomment \"panel-lbstream-v1 uid=991\"\n" +
		"\tchain output { # handle 1\n" +
		"\t\ttype filter hook output priority filter + 10; policy accept;\n" +
		"\t\tmeta skuid != 991 return # handle 2\n" +
		"\t\tct state established ct direction reply tcp sport 42000 accept # handle 3\n" +
		"\t\tct state established ct direction reply tcp sport 43000 accept # handle 4\n" +
		"\t\tip daddr 192.0.2.10 tcp dport 41001 accept # handle 5\n" +
		"\t\tip6 daddr 2001:db8::2 tcp dport 41002 accept # handle 6\n" +
		"\t\tmeta skuid 991 drop comment \"" + guard.policyComment() + "\" # handle 7\n" +
		"\t}\n}\n"
	if _, err := guard.Inspect([]byte(old)); err != ErrEgressTableCommentOmitted {
		t.Fatalf("old JSON must request independent table evidence: %v", err)
	}
	actual, err := guard.InspectWithTableComment([]byte(old), []byte(text))
	if err != nil || actual.TableHandle != 9 || actual.ChainHandle != 1 || len(actual.RuleHandles) != 6 {
		t.Fatalf("complete joined observation refused: %+v %v", actual, err)
	}
	for _, broken := range []string{
		strings.Replace(text, "# handle 9", "# handle 8", 1),
		strings.Replace(text, "uid=991", "uid=990", 1),
		strings.Replace(text, "# handle 7", "# handle 5", 1),
		strings.Replace(text, "priority filter + 10", "priority filter + 11", 1),
		strings.Replace(text, "\tcomment ", "\tflags dormant\n\tcomment ", 1),
		strings.Replace(text, "\tcomment \"panel-lbstream-v1 uid=991\"\n", "", 1),
		text + "\n",
	} {
		if _, err := guard.InspectWithTableComment([]byte(old), []byte(broken)); err != ErrEgressGuard {
			t.Fatalf("changed text became ownership: %v", err)
		}
	}
	for _, broken := range []string{
		modern,
		strings.Replace(old, `"right":"reply"`, `"right":"original"`, 1),
		strings.Replace(old, `"family":"inet","handle":9,"name":"panel_lbstream"`, `"family":"inet","handle":9,"name":"panel_lbstream","comment":"wrong owner"`, 1),
		strings.Replace(old, `"family":"inet","handle":9,"name":"panel_lbstream"`, `"family":"inet","handle":9,"name":"panel_lbstream","flags":["dormant"]`, 1),
	} {
		if _, err := guard.InspectWithTableComment([]byte(broken), []byte(text)); err != ErrEgressGuard {
			t.Fatalf("changed JSON became ownership: %v", err)
		}
	}
}
