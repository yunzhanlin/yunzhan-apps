//go:build linux

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sync"
)

const intrusionRemovalMemoEntries = 256

type intrusionRemovalSummary struct {
	Settings map[string]int
	Ports    []int
	Identity string
}

func (v intrusionRemovalSummary) clone() intrusionRemovalSummary {
	v.Settings = maps.Clone(v.Settings)
	v.Ports = slices.Clone(v.Ports)
	return v
}

type intrusionRemovalMemo struct {
	mu      sync.Mutex
	entries map[string]intrusionRemovalSummary
	order   []string
}

var intrusionRemovalDerivations intrusionRemovalMemo

func (m *intrusionRemovalMemo) lookup(key string) (intrusionRemovalSummary, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[key]
	return v.clone(), ok
}

func (m *intrusionRemovalMemo) put(key string, value intrusionRemovalSummary) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[string]intrusionRemovalSummary)
	}
	if _, ok := m.entries[key]; ok {
		return
	}
	if len(m.order) == intrusionRemovalMemoEntries {
		delete(m.entries, m.order[0])
		m.order = m.order[1:]
	}
	m.entries[key] = value.clone()
	m.order = append(m.order, key)
}

// ONLY deterministic literal-proof decoding is memoized. The complete raw
// observation, policy, full action recipe, journal match and comparison
// identity select the key. Successful results contain only cloned limits,
// ports and a digest: no dump, file, PID, boot, lock, live runtime or write
// authority is stored. Every original target/file derivation and every fresh
// external write gate still runs independently, even on a memo hit.
func (m *intrusionRemovalMemo) derive(raw []byte, current intrusionRuntimeState, beforeIdentity string) (intrusionRemovalSummary, error) {
	if len(raw) < 1 || len(raw) > 32<<10 {
		return intrusionRemovalSummary{}, errors.New("底层卸载证据超过固定范围")
	}
	// Freeze precisely the semantic decoder's inputs before hashing/decoding;
	// callers never receive aliases to an original or another memo result.
	raw = slices.Clone(raw)
	current.Policy.Ports = slices.Clone(current.Policy.Ports)
	current.Recipe.Properties = slices.Clone(current.Recipe.Properties)
	current.Recipe.Values = maps.Clone(current.Recipe.Values)
	input := struct {
		Format         int
		Dump           []byte
		Policy         intrusionManagedPolicy
		Recipe         intrusionActionRecipe
		JournalMatch   string
		BeforeIdentity string
	}{1, raw, current.Policy, current.Recipe, current.JournalMatch, beforeIdentity}
	encoded, err := json.Marshal(input)
	if err != nil {
		return intrusionRemovalSummary{}, err
	}
	digest := sha256.Sum256(encoded)
	key := hex.EncodeToString(digest[:])
	if value, ok := m.lookup(key); ok {
		return value, nil
	}
	value, err := intrusionRemovalCandidateDecode(raw, current, beforeIdentity)
	if err != nil {
		return intrusionRemovalSummary{}, err
	}
	summary := intrusionRemovalSummary{Settings: value.Settings, Ports: value.Ports, Identity: value.EffectiveIdentity}
	m.put(key, summary)
	return summary.clone(), nil
}
