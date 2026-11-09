package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Mutation and Policy are the canonical internal Core-to-Root wire, not a
// browser form or an authority grant. ProbePort, Revision and Removed are
// deliberately absent from the caller's policy.
type Policy struct {
	Protocol            string `json:"protocol"`
	Port                int    `json:"port"`
	Nodes               []Node `json:"nodes"`
	Method              string `json:"method"`
	ConnectMilliseconds int    `json:"connect_milliseconds"`
	SessionSeconds      int    `json:"session_seconds"`
	MaxSessions         int    `json:"max_sessions"`
	UDPRequests         int    `json:"udp_requests"`
	UDPResponses        int    `json:"udp_responses"`
}
type Mutation struct {
	Format              int     `json:"format"`
	Action              string  `json:"action"`
	Name                string  `json:"name"`
	ExpectedRevision    int64   `json:"expected_revision"`
	ExpectedFingerprint string  `json:"expected_fingerprint"`
	Policy              *Policy `json:"policy"`
}
type Transition struct {
	Before       *Entry
	After        Entry
	Entries      []Entry
	BeforeConfig Configuration
	AfterConfig  Configuration
}

var ErrMutation = errors.New("TCP/UDP 变更类型、服务端分配或原始修订号与配置指纹不匹配；未修改配置")

func copyEntry(entry Entry) Entry {
	entry.Nodes = append([]Node(nil), entry.Nodes...)
	return entry
}
func mutationShape(m Mutation) bool {
	if m.Format != 1 || !validName(m.Name) || m.ExpectedRevision < 0 || m.ExpectedRevision >= 1<<60 {
		return false
	}
	switch m.Action {
	case "create":
		return m.ExpectedRevision == 0 && m.ExpectedFingerprint == "" && m.Policy != nil
	case "replace":
		return m.ExpectedRevision > 0 && len(m.ExpectedFingerprint) > 0 && len(m.ExpectedFingerprint) < 128 && m.Policy != nil
	case "remove":
		return m.ExpectedRevision > 0 && len(m.ExpectedFingerprint) > 0 && len(m.ExpectedFingerprint) < 128 && m.Policy == nil
	}
	return false
}

// DecodeMutation never normalizes private wire aliases, omitted/null fields,
// duplicate keys, unknown fields, alternate number forms or trailing documents.
func DecodeMutation(raw []byte) (Mutation, error) {
	var mutation Mutation
	if len(raw) == 0 || len(raw) > MaxEntryBytes || json.Unmarshal(raw, &mutation) != nil {
		return Mutation{}, ErrMutation
	}
	canonical, err := json.Marshal(mutation)
	if err != nil || !bytes.Equal(raw, canonical) || !mutationShape(mutation) {
		return Mutation{}, ErrMutation
	}
	return mutation, nil
}

// PlanMutation computes bytes and an optimistic-concurrency transition only.
// It cannot read files, allocate listeners, reload Nginx, resume unknown work,
// or authorize an actor. Root must bind this plan to the original installed
// module/actor/journal, hold its locks, measure external TCP AND UDP occupancy,
// enforce actual host/service budgets, backup/test/reload and verify the exact
// generation and owned listeners before committing. A replayed request is not
// original success; the controller must observe its own original journal.
func PlanMutation(current []Entry, m Mutation, freshProbePort int, facts ValidationContext) (Transition, error) {
	if !mutationShape(m) || ValidateSet(current, facts) != nil {
		return Transition{}, ErrMutation
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > MaxEntryBytes {
		return Transition{}, ErrMutation
	}
	index := -1
	for i, entry := range current {
		if entry.Name == m.Name {
			index = i
			break
		}
	}
	entries := make([]Entry, len(current))
	for i, entry := range current {
		entries[i] = copyEntry(entry)
	}
	var before *Entry
	var oldConfig Configuration
	revision := int64(1)
	probe := freshProbePort
	if m.Action == "create" {
		// A retained tombstone is still original identity, not a reusable fresh name.
		if index != -1 || probe == 0 {
			return Transition{}, ErrMutation
		}
	} else {
		if index < 0 || freshProbePort != 0 {
			return Transition{}, ErrMutation
		}
		old := current[index]
		if old.Revision != m.ExpectedRevision || Fingerprint(old) != m.ExpectedFingerprint || old.Revision+1 >= 1<<60 || m.Action == "remove" && old.Removed {
			return Transition{}, ErrMutation
		}
		held := copyEntry(old)
		before = &held
		oldConfig, err = Render(old)
		if err != nil {
			return Transition{}, ErrMutation
		}
		revision = old.Revision + 1
		probe = old.ProbePort
	}
	var next Entry
	if m.Action == "remove" {
		next = copyEntry(*before)
		next.Revision = revision
		next.Removed = true
	} else {
		policy := m.Policy
		next = Entry{Format: 1, Revision: revision, Name: m.Name, Protocol: policy.Protocol, Port: policy.Port, ProbePort: probe, Nodes: append([]Node(nil), policy.Nodes...), Method: policy.Method, ConnectMilliseconds: policy.ConnectMilliseconds, SessionSeconds: policy.SessionSeconds, MaxSessions: policy.MaxSessions, UDPRequests: policy.UDPRequests, UDPResponses: policy.UDPResponses}
	}
	if index < 0 {
		entries = append(entries, copyEntry(next))
	} else {
		entries[index] = copyEntry(next)
	}
	if ValidateSet(entries, facts) != nil {
		return Transition{}, ErrMutation
	}
	nextConfig, err := Render(next)
	if err != nil {
		return Transition{}, ErrMutation
	}
	return Transition{Before: before, After: copyEntry(next), Entries: entries, BeforeConfig: oldConfig, AfterConfig: nextConfig}, nil
}
