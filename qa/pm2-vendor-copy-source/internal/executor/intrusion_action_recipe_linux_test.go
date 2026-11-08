//go:build linux

package executor

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

//go:embed testdata/intrusion-action-stock-arm64.json
var intrusionStockARMFixture []byte

//go:embed testdata/intrusion-action-stock-amd64.json
var intrusionStockAMDFixture []byte

func intrusionActionRecipeFixture(t *testing.T, policy intrusionManagedPolicy) string {
	t.Helper()
	values, err := intrusionStockActionValues(policy, "nft", "<known/chain>")
	if err != nil {
		t.Fatal(err)
	}
	values["banEpoch"] = "0"
	keys := []string{"ESCAPE_CRE", "ESCAPE_VN_CRE"}
	for name := range values {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	raw, err := json.Marshal(intrusionActionRecipe{Format: 1, Action: policy.Action, Properties: keys, Values: values})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func intrusionActionRecipePolicy() intrusionManagedPolicy {
	return intrusionManagedPolicy{Format: 1, Action: "nftables", Name: "sshd", Table: "f2b-table", Chain: "f2b-chain", IPv4Set: "addr-set-sshd", IPv6Set: "addr6-set-sshd", Ports: []int{22}, MaxMatches: 5}
}

func TestIntrusionActionRecipeChecksCompleteActualStockDumpWithoutExecution(t *testing.T) {
	// These small declarations contain no addresses, credentials or servers;
	// they preserve the actual 24-property upstream dump for two native OSes.
	for arch, raw := range map[string][]byte{"arm64": intrusionStockARMFixture, "amd64": intrusionStockAMDFixture} {
		var dump map[string]string
		if json.Unmarshal(raw, &dump) != nil {
			t.Fatal("invalid observed fixture")
		}
		policy := intrusionActionRecipePolicy()
		expected, err := intrusionStockActionValues(policy, "nft", "<known/chain>")
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range dump {
			if expected[name] != value {
				t.Fatalf("actual stock property %s disagrees on %s", name, arch)
			}
		}
		if len(dump) != 24 {
			t.Fatal("actual fixture incomplete")
		}
		if _, err := intrusionActionRecipeValidate(intrusionActionRecipeFixture(t, policy), policy); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntrusionActionRecipeRejectsEveryCustomOrMissingProperty(t *testing.T) {
	policy := intrusionActionRecipePolicy()
	fixture := intrusionActionRecipeFixture(t, policy)
	var base intrusionActionRecipe
	json.Unmarshal([]byte(fixture), &base)
	for name := range base.Values {
		t.Run(name, func(t *testing.T) {
			for _, missing := range []bool{false, true} {
				var changed intrusionActionRecipe
				json.Unmarshal([]byte(fixture), &changed)
				if missing {
					delete(changed.Values, name)
				} else {
					changed.Values[name] += "; echo private-backend-sentinel"
				}
				raw, _ := json.Marshal(changed)
				if _, err := intrusionActionRecipeValidate(string(raw), policy); err == nil || strings.Contains(err.Error(), "private-backend-sentinel") {
					t.Fatal("custom/missing live property accepted or leaked", err)
				}
			}
		})
	}
	for name, change := range map[string]func(*intrusionActionRecipe){
		"extra-property":     func(v *intrusionActionRecipe) { v.Properties = append(v.Properties, "actionprolong") },
		"duplicate-property": func(v *intrusionActionRecipe) { v.Properties = append(v.Properties, v.Properties[0]) },
		"missing-property":   func(v *intrusionActionRecipe) { v.Properties = v.Properties[1:] },
		"wrong-action":       func(v *intrusionActionRecipe) { v.Action = "mail" },
		"extra-getter":       func(v *intrusionActionRecipe) { v.Values["actionprolong"] = "" },
		"negative-epoch":     func(v *intrusionActionRecipe) { v.Values["banEpoch"] = "-1" },
		"noncanonical-epoch": func(v *intrusionActionRecipe) { v.Values["banEpoch"] = "00" },
	} {
		t.Run(name, func(t *testing.T) {
			var v intrusionActionRecipe
			json.Unmarshal([]byte(fixture), &v)
			change(&v)
			raw, _ := json.Marshal(v)
			if _, err := intrusionActionRecipeValidate(string(raw), policy); err == nil {
				t.Fatal("unknown action surface accepted")
			}
		})
	}
}

func TestIntrusionActionRecipeRejectsDuplicateUnknownAndTruncatedJSON(t *testing.T) {
	p := intrusionActionRecipePolicy()
	raw := intrusionActionRecipeFixture(t, p)
	for _, bad := range []string{strings.Replace(raw, `"format":1`, `"format":1,"FORMAT":1`, 1), strings.Replace(raw, `"format":1`, `"format":1,"command":"stop"`, 1), raw + `{}`, raw[:len(raw)/2]} {
		if _, err := intrusionActionRecipeValidate(bad, p); err == nil {
			t.Fatal("nonclosed recipe accepted")
		}
	}
}
