//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestIntrusionRemovalMemoBindsEverySemanticInputAndNeverCachesErrors(t *testing.T) {
	current, dump, identity := intrusionRemovalCandidateFixture(t, "arm64")
	raw, err := json.Marshal(dump)
	if err != nil {
		t.Fatal(err)
	}
	var memo intrusionRemovalMemo
	if _, err := memo.derive(raw, current, identity); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*[]byte, *intrusionRuntimeState, *string){
		"truncated-dump": func(v *[]byte, _ *intrusionRuntimeState, _ *string) { *v = (*v)[:len(*v)/2] },
		"different-filter": func(v *[]byte, _ *intrusionRuntimeState, _ *string) {
			var d intrusionEffectiveDump
			if json.Unmarshal(*v, &d) != nil {
				t.Fatal("fixture")
			}
			intrusionRemovalCandidateSet(t, &d, "prefregex", "^different$")
			*v, _ = json.Marshal(d)
		},
		"unknown-format": func(v *[]byte, _ *intrusionRuntimeState, _ *string) {
			var d intrusionEffectiveDump
			if json.Unmarshal(*v, &d) != nil {
				t.Fatal("fixture")
			}
			d.Format = 2
			*v, _ = json.Marshal(d)
		},
		"policy-name":     func(_ *[]byte, v *intrusionRuntimeState, _ *string) { v.Policy.Name = "another" },
		"policy-ports":    func(_ *[]byte, v *intrusionRuntimeState, _ *string) { v.Policy.Ports = []int{23} },
		"policy-capacity": func(_ *[]byte, v *intrusionRuntimeState, _ *string) { v.Policy.MaxMatches++ },
		"recipe-value":    func(_ *[]byte, v *intrusionRuntimeState, _ *string) { v.Recipe.Values["actionstop"] = "different" },
		"recipe-surface": func(_ *[]byte, v *intrusionRuntimeState, _ *string) {
			v.Recipe.Properties = append(v.Recipe.Properties, "different")
		},
		"journal-match":       func(_ *[]byte, v *intrusionRuntimeState, _ *string) { v.JournalMatch = "_COMM=another" },
		"comparison-identity": func(_ *[]byte, _ *intrusionRuntimeState, v *string) { *v = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			q := current
			q.Policy.Ports = slices.Clone(current.Policy.Ports)
			q.Recipe.Properties = slices.Clone(current.Recipe.Properties)
			q.Recipe.Values = maps.Clone(current.Recipe.Values)
			v, id := bytes.Clone(raw), identity
			change(&v, &q, &id)
			out, err := memo.derive(v, q, id)
			if err == nil || out.Settings != nil || out.Ports != nil || out.Identity != "" {
				t.Fatal("different semantic input reused valid proof", err)
			}
			if len(memo.entries) != 1 {
				t.Fatal("error or partial derivation was cached")
			}
		})
	}
}

func TestIntrusionRemovalMemoClonesInputsAndResults(t *testing.T) {
	current, dump, identity := intrusionRemovalCandidateFixture(t, "arm64")
	raw, _ := json.Marshal(dump)
	original := bytes.Clone(raw)
	var memo intrusionRemovalMemo
	out, err := memo.derive(raw, current, identity)
	if err != nil {
		t.Fatal(err)
	}
	out.Settings["max_retry"] = 9
	out.Ports[0] = 1234
	raw[0] = ' '
	again, err := memo.derive(original, current, identity)
	if err != nil || !maps.Equal(again.Settings, current.Settings) || !slices.Equal(again.Ports, current.Policy.Ports) || again.Identity != identity {
		t.Fatal("memo result or input aliased", err)
	}
	if len(memo.entries) != 1 {
		t.Fatal("same frozen input did not reuse pure summary")
	}
	again.Settings["max_retry"] = 19
	last, err := memo.derive(original, current, identity)
	if err != nil || last.Settings["max_retry"] != current.Settings["max_retry"] {
		t.Fatal("another reader changed stored summary", err)
	}
}

func TestIntrusionRemovalMemoBoundedEvictionAndConcurrentAccess(t *testing.T) {
	var memo intrusionRemovalMemo
	value := intrusionRemovalSummary{Settings: map[string]int{"max_retry": 5}, Ports: []int{22}, Identity: strings.Repeat("a", 64)}
	for i := 0; i < intrusionRemovalMemoEntries+7; i++ {
		memo.put(fmt.Sprintf("%064x", i), value)
	}
	value.Settings["max_retry"] = 9
	value.Ports[0] = 999
	if _, ok := memo.lookup(fmt.Sprintf("%064x", 0)); ok {
		t.Fatal("oldest pure derivation was not evicted")
	}
	v, ok := memo.lookup(fmt.Sprintf("%064x", intrusionRemovalMemoEntries+6))
	if !ok || v.Settings["max_retry"] != 5 || v.Ports[0] != 22 {
		t.Fatal("stored summary aliases input")
	}
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("%064x", 1000+worker*20+i)
				memo.put(key, value)
				copy, ok := memo.lookup(key)
				if ok {
					copy.Settings["max_retry"] = 20
					copy.Ports[0] = 20
				}
			}
		}(worker)
	}
	group.Wait()
	if len(memo.entries) != intrusionRemovalMemoEntries || len(memo.order) != intrusionRemovalMemoEntries {
		t.Fatal("pure derivation memory not bounded")
	}
}
