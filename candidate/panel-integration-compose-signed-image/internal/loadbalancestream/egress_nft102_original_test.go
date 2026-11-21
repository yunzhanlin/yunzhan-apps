package loadbalancestream

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestEgressNft102OriginalUbuntu22RequiresCompleteIndependentComment(t *testing.T) {
	raw, err := os.ReadFile("testdata/ubuntu22-nft-1.0.2-original-TCP.json")
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(raw)
	entry := fixture()
	entry.Name, entry.Port, entry.ProbePort = "tcp-c317.example.test", 41080, 60000
	entry.Nodes = []Node{{Address: "127.0.0.1:31081", Weight: 1}, {Address: "127.0.0.1:31082", Weight: 1}}
	guard := mustEgress(t, []Entry{entry}, nil)
	if guard.SHA256() != "bd0a57aaa86821504fb4c118d2c53f87e2792bde6329b0536e28c06d445563ee" {
		t.Fatal("original captured policy differs", guard.SHA256())
	}
	if _, err := guard.Inspect(raw); err != ErrEgressTableCommentOmitted {
		t.Fatal("complete original JSON must require independent text, never grant ownership alone", err)
	}
	// The captured original JSON is unchanged. This text is a model of the
	// fixed tool's complete handle-bearing listing, not a native receipt.
	text := "table inet panel_lbstream { # handle 4\n\tcomment \"panel-lbstream-v1 uid=991\"\n\tchain output { # handle 1\n\t\ttype filter hook output priority filter + 10; policy accept;\n\t\tmeta skuid != 991 return # handle 2\n\t\tct state established ct direction reply tcp sport 41080 accept # handle 3\n\t\tct state established ct direction reply tcp sport 60000 accept # handle 4\n\t\tip daddr 127.0.0.1 tcp dport 31081 accept # handle 5\n\t\tip daddr 127.0.0.1 tcp dport 31082 accept # handle 6\n\t\tmeta skuid 991 drop comment \"" + guard.policyComment() + "\" # handle 7\n\t}\n}\n"
	seen, err := guard.InspectWithTableComment(raw, []byte(text))
	if err != nil || seen.TableHandle != 4 || seen.ChainHandle != 1 || len(seen.RuleHandles) != 6 || guard.ValidateObservation(seen) != nil {
		t.Fatal("complete matching old-version observation", seen, err)
	}
	for _, invalid := range []string{strings.Replace(text, "# handle 4", "# handle 8", 1), strings.Replace(text, "uid=991", "uid=990", 1), strings.Replace(text, "\tcomment ", "\tflags dormant\n\tcomment ", 1), strings.Replace(text, "# handle 7", "# handle 6", 1), strings.Replace(text, "policy accept", "policy drop", 1), text + "\n"} {
		if _, err := guard.InspectWithTableComment(raw, []byte(invalid)); err != ErrEgressGuard {
			t.Fatal("changed independent listing accepted", err)
		}
	}
	for _, change := range []struct{ from, to string }{
		{`"right": 991`, `"right": 990`}, {`"right": 31081`, `"right": 31083`}, {`"protocol": "tcp"`, `"protocol": "udp"`}, {`"op": "!="`, `"op": "=="`}, {`"handle": 7`, `"handle": 6`}, {`"version": "1.0.2"`, `"version": "1.0.99"`}, {`"name": "panel_lbstream", "handle": 4`, `"name": "panel_lbstream", "handle": 4, "flags": ["dormant"]`}, {`"policy": "accept"`, `"policy": "drop"`},
	} {
		changed := bytes.Replace(raw, []byte(change.from), []byte(change.to), 1)
		if bytes.Equal(changed, raw) {
			t.Fatal("negative mutation did not touch captured fixture", change)
		}
		if _, err := guard.InspectWithTableComment(changed, []byte(text)); err != ErrEgressGuard {
			t.Fatal("changed original rule or unreviewed version accepted", change, err)
		}
	}
	if !bytes.Equal(raw, original) {
		t.Fatal("original raw observation modified")
	}
}
