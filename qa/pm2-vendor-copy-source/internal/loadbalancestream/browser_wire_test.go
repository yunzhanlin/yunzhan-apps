package loadbalancestream

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Cross-language golden matches scripts/test-load-balance-stream.mjs, using
// Go's real canonical serializers and hashes, not a second JS approximation.
func TestBrowserStreamWireGolden(t *testing.T) {
	const raw = `{"format":1,"revision":7,"name":"fixture.lb.invalid","protocol":"tcp","port":42000,"probe_port":43000,"nodes":[{"address":"192.0.2.10:41001","weight":1,"backup":false},{"address":"[2001:db8::11]:41002","weight":3,"backup":false}],"method":"round-robin","connect_milliseconds":2000,"session_seconds":30,"max_sessions":64,"udp_requests":0,"udp_responses":0,"removed":false}`
	var entry Entry
	if json.Unmarshal([]byte(raw), &entry) != nil {
		t.Fatal("invalid browser golden")
	}
	canonical, err := json.Marshal(entry)
	if err != nil || string(canonical) != raw || Fingerprint(entry) != "e8e82a868215edb8995f:7:7c86557ebd9dd6b853e4f872" {
		t.Fatal("browser entry CAS wire mismatch", string(canonical), Fingerprint(entry), err)
	}
	policy := &Policy{Protocol: entry.Protocol, Port: entry.Port, Nodes: entry.Nodes, Method: entry.Method, ConnectMilliseconds: entry.ConnectMilliseconds, SessionSeconds: entry.SessionSeconds, MaxSessions: entry.MaxSessions}
	mutation := Mutation{Format: 1, Action: "create", Name: entry.Name, Policy: policy}
	mutationRaw, err := json.Marshal(mutation)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(mutationRaw)) != "a4c010f08043fdb667fa16dc3e90acd86567daf2cf04941ee53721e21b2a33e7" {
		t.Fatal("browser mutation hash mismatch", string(mutationRaw), err)
	}
	if _, err := DecodeMutation(mutationRaw); err != nil {
		t.Fatal("canonical browser mutation rejected", err)
	}
	op := Operation{Format: 1, Kind: OperationKind, RequestID: strings.Repeat("c", 32), ActorID: strings.Repeat("a", 32), Mutation: mutation}
	if _, err := OperationBytes(op); err != nil || OperationSHA256(op) != "576295f5cd04c8329450521ca59bc39f7011db185a0ffa1314ac205ecf381867" {
		t.Fatal("browser original operation binding mismatch", err)
	}
}
