package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func streamOperationFixture() (Operation, OperationBinding) {
	entry := fixture()
	policy := Policy{entry.Protocol, entry.Port, append([]Node(nil), entry.Nodes...), entry.Method, entry.ConnectMilliseconds, entry.SessionSeconds, entry.MaxSessions, entry.UDPRequests, entry.UDPResponses}
	op := Operation{1, OperationKind, strings.Repeat("a", 32), strings.Repeat("b", 32), Mutation{1, "create", entry.Name, 0, "", &policy}}
	binding := OperationBinding{1, "load-balance", AppVersion, OperationSHA256(op), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), strings.Repeat("4", 64), strings.Repeat("5", 64), strings.Repeat("6", 64)}
	return op, binding
}

func TestOperationClosedWireAndOriginalBindingDoNotMutateCaller(t *testing.T) {
	for _, action := range []string{"create", "replace", "remove"} {
		t.Run(action, func(t *testing.T) {
			op, binding := streamOperationFixture()
			if action != "create" {
				op.Mutation.Action, op.Mutation.ExpectedRevision, op.Mutation.ExpectedFingerprint = action, 1, Fingerprint(fixture())
				if action == "remove" {
					op.Mutation.Policy = nil
				}
			}
			binding.OperationSHA256 = OperationSHA256(op)
			raw, err := OperationBytes(op)
			if err != nil {
				t.Fatal(err)
			}
			before := bytes.Clone(raw)
			got, err := DecodeOperation(raw)
			if err != nil || !reflect.DeepEqual(got, op) || !bytes.Equal(before, raw) || OperationSHA256(got) != binding.OperationSHA256 {
				t.Fatal("original exact operation changed/refused", err)
			}
			bound, err := OperationBindingBytes(binding)
			if err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(bound)
			if got, err := DecodeOperationBinding(bound, op); err != nil || got != binding || !bytes.Equal(bound, original) {
				t.Fatal("original exact private binding changed/refused", err)
			}
			op.ActorID = strings.Repeat("c", 32)
			if _, err := DecodeOperationBinding(bound, op); err == nil {
				t.Fatal("old private binding adopted a different original actor")
			}
			op, _ = streamOperationFixture()
			op.RequestID = strings.Repeat("d", 32)
			if _, err := DecodeOperationBinding(bound, op); err == nil {
				t.Fatal("old private binding adopted a different original request")
			}
		})
	}
}

func TestOperationPrivateDecodersRefuseAliasesDuplicatesAndForeignRecords(t *testing.T) {
	op, binding := streamOperationFixture()
	raw, _ := OperationBytes(op)
	bound, _ := OperationBindingBytes(binding)
	for _, change := range []struct{ name, old, replacement string }{
		{"unknown", "\"format\":1", "\"foreign\":true,\"format\":1"},
		{"duplicate", "\"format\":1", "\"format\":1,\"format\":1"},
		{"case-alias", "\"format\":1", "\"Format\":1"},
		{"float-format", "\"format\":1", "\"format\":1.0"},
		{"another-format", "\"format\":1", "\"format\":2"},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := DecodeOperation(bytes.Replace(raw, []byte(change.old), []byte(change.replacement), 1)); err == nil {
				t.Fatal("noncanonical operation accepted")
			}
			if _, err := DecodeOperationBinding(bytes.Replace(bound, []byte(change.old), []byte(change.replacement), 1), op); err == nil {
				t.Fatal("noncanonical private binding accepted")
			}
		})
	}
	for _, value := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[]"), append([]byte(" "), raw...), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), []byte("{}")...), bytes.Repeat([]byte("x"), MaxEntryBytes+1025), bound} {
		if _, err := DecodeOperation(value); err == nil {
			t.Fatal("incomplete/oversize/multiple/private-binding-as-operation accepted")
		}
	}
	for _, value := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[]"), append([]byte(" "), bound...), append(bytes.Clone(bound), '\n'), bytes.TrimSuffix(bound, []byte("\n")), bytes.Repeat([]byte("x"), 2049), raw} {
		if _, err := DecodeOperationBinding(value, op); err == nil {
			t.Fatal("incomplete/oversize/multiple/operation-as-private-binding accepted")
		}
	}
	for _, change := range []struct{ name, old, replacement string }{
		{"nested-unknown", "\"action\":\"create\"", "\"foreign\":true,\"action\":\"create\""},
		{"nested-duplicate", "\"action\":\"create\"", "\"action\":\"create\",\"action\":\"create\""},
		{"nested-alias", "\"expected_revision\":0", "\"Expected_Revision\":0"},
	} {
		t.Run(change.name, func(t *testing.T) {
			if _, err := DecodeOperation(bytes.Replace(raw, []byte(change.old), []byte(change.replacement), 1)); err == nil {
				t.Fatal("noncanonical nested mutation accepted")
			}
		})
	}
}

func TestOperationIdentifiersAndEveryPrivateBindingHashRemainClosed(t *testing.T) {
	for _, field := range []string{"RequestID", "ActorID"} {
		for _, value := range []string{"", "../foreign", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
			t.Run(field+"-"+value, func(t *testing.T) {
				op, _ := streamOperationFixture()
				reflect.ValueOf(&op).Elem().FieldByName(field).SetString(value)
				if raw, err := OperationBytes(op); err == nil || raw != nil || OperationSHA256(op) != "" {
					t.Fatal("invalid original identity returned operation bytes or a digest")
				}
			})
		}
	}
	for _, value := range []string{"", "load-balance", "memcached-unix-control-v1", OperationKind + "\nUser=root"} {
		op, _ := streamOperationFixture()
		op.Kind = value
		if raw, err := OperationBytes(op); err == nil || raw != nil {
			t.Fatal("different operation domain accepted")
		}
	}
	for _, field := range []string{"OperationSHA256", "ManifestSHA256", "InstalledSHA256", "ProgrammeInputs", "ActorObservationSHA", "OriginalConfigSHA256"} {
		for _, value := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
			t.Run(field+"-"+value, func(t *testing.T) {
				_, binding := streamOperationFixture()
				reflect.ValueOf(&binding).Elem().FieldByName(field).SetString(value)
				if raw, err := OperationBindingBytes(binding); err == nil || raw != nil {
					t.Fatal("unknown or invalid original private proof returned bytes")
				}
			})
		}
	}
	for _, version := range []string{"", "1.8.4", "1.8.5", "1.9.1", "2.0.0", "../1.8.5", "1.8", "01.8.5", "1x8y5", "1/8/5", "1.8.5\nUser=root", "1.8.5-unknown", "1000000.0.0"} {
		t.Run("version-"+version, func(t *testing.T) {
			_, binding := streamOperationFixture()
			binding.AppVersion = version
			if raw, err := OperationBindingBytes(binding); err == nil || raw != nil {
				t.Fatal("noncanonical installed version returned bytes")
			}
		})
	}
	for _, name := range []string{"", "nginx-waf", "memcached", "load-balance\nUser=root"} {
		_, binding := streamOperationFixture()
		binding.AppID = name
		if raw, err := OperationBindingBytes(binding); err == nil || raw != nil {
			t.Fatal("foreign application identity returned private binding bytes")
		}
	}
}

func TestOperationSyntaxIsNotBackendOrListenerOrActorAdmission(t *testing.T) {
	op, _ := streamOperationFixture()
	op.Mutation.Policy.Port = 19100
	raw, err := OperationBytes(op)
	if err != nil {
		t.Fatal("this codec test requires a syntactic but non-admissible policy", err)
	}
	got, err := DecodeOperation(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PlanMutation(nil, got.Mutation, 43000, facts()); err == nil {
		t.Fatal("private request serialization was mistaken for listener admission")
	}
	// A caller cannot make a valid private record bind a different operation
	// just by preserving the app identity and an otherwise valid manifest.
	original, binding := streamOperationFixture()
	bound, _ := OperationBindingBytes(binding)
	value := original
	value.Mutation.Name = "other.lb.invalid"
	if _, err := DecodeOperationBinding(bound, value); err == nil {
		t.Fatal("private module fields masked a different original mutation")
	}
	bad, _ := json.Marshal(Operation{})
	if _, err := DecodeOperation(bad); err == nil {
		t.Fatal("zero operation acquired authority")
	}
}
