//go:build linux

package executor

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestMemcachedUnixRetirementOnlyDeletesTheIssuedStoppedCIDOnce(t *testing.T) {
	seed, issued := retirementAbsenceFixture()
	deletes, reads, checks := 0, 0, 0
	check := func(context.Context) error { checks++; return nil }
	remove := func(_ context.Context, cid string) (int, []byte, error) {
		deletes++
		if cid != issued.ContainerID {
			t.Fatal("wrong CID")
		}
		return 204, nil, nil
	}
	read := func(_ context.Context, method, path string, body any) (int, []byte, error) {
		reads++
		if method != http.MethodGet || body != nil {
			t.Fatal("observation mutated")
		}
		if path == "/containers/"+issued.ContainerID+"/json" {
			return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\"}"), nil
		}
		if strings.HasPrefix(path, "/volumes?") {
			return 200, []byte("{\"Volumes\":null,\"Warnings\":null}"), nil
		}
		return 200, []byte("[]"), nil
	}
	out, e := completeMemcachedUnixRetirement(context.Background(), seed, issued, check, read, remove)
	if e != nil || out.State != "completed" || out.FinalState != "retired" || len(out.RuntimeSHA256) != 64 || deletes != 1 || reads != 8 || checks != 4 {
		t.Fatal("wrong one-shot lifecycle", out, e, deletes, reads, checks)
	}
}

func TestMemcachedUnixRetirementLostRefusedOrDriftedReplyNeverDeletesAgain(t *testing.T) {
	for _, kind := range []string{"lost-reply", "still-running-409", "already-missing-404", "unexpected-body", "revoked-before", "revoked-after", "daemon-inspection-lost", "container-reappeared", "foreign-engine-resource"} {
		t.Run(kind, func(t *testing.T) {
			seed, issued := retirementAbsenceFixture()
			deletes, reads, checks := 0, 0, 0
			check := func(context.Context) error {
				checks++
				if kind == "revoked-before" || kind == "revoked-after" && checks > 1 {
					return errors.New("fresh authorization revoked")
				}
				return nil
			}
			remove := func(context.Context, string) (int, []byte, error) {
				deletes++
				switch kind {
				case "lost-reply":
					return 0, nil, errors.New("lost reply")
				case "still-running-409":
					return 409, []byte("{}"), nil
				case "already-missing-404":
					return 404, []byte("{}"), nil
				case "unexpected-body":
					return 204, []byte("unexpected"), nil
				}
				return 204, nil, nil
			}
			read := func(_ context.Context, method, path string, body any) (int, []byte, error) {
				reads++
				if method != http.MethodGet || body != nil {
					t.Fatal("extra native mutation")
				}
				if kind == "daemon-inspection-lost" {
					return 0, nil, errors.New("unknown inspection")
				}
				if path == "/containers/"+issued.ContainerID+"/json" {
					if kind == "container-reappeared" && reads > 4 {
						return 200, []byte("{}"), nil
					}
					return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\"}"), nil
				}
				if kind == "foreign-engine-resource" {
					return 200, []byte("[{}]"), nil
				}
				if strings.HasPrefix(path, "/volumes?") {
					return 200, []byte("{\"Volumes\":[]}"), nil
				}
				return 200, []byte("[]"), nil
			}
			out, e := completeMemcachedUnixRetirement(context.Background(), seed, issued, check, read, remove)
			if e == nil || out.State != "" || deletes > 1 {
				t.Fatal("unknown/refused retirement became success or a retry", out, e, deletes)
			}
			if kind == "revoked-before" && deletes != 0 {
				t.Fatal("revoked actor reached removal")
			}
		})
	}
}

func TestMemcachedUnixRetirementInvalidFramingNeverTouchesRemovalOrDaemon(t *testing.T) {
	for _, kind := range []string{"nil-context", "canceled", "missing-check", "missing-read", "missing-remove", "bad-seed", "wrong-issued", "bad-time", "running", "bad-CID", "missing-confirmation"} {
		t.Run(kind, func(t *testing.T) {
			seed, issued := retirementAbsenceFixture()
			ctx := context.Background()
			calls := 0
			check := func(context.Context) error { calls++; return nil }
			read := memcachedRetentionCall(func(context.Context, string, string, any) (int, []byte, error) {
				calls++
				return 0, nil, errors.New("must not read")
			})
			remove := memcachedUnixRetirementRemove(func(context.Context, string) (int, []byte, error) {
				calls++
				return 0, nil, errors.New("must not delete")
			})
			switch kind {
			case "nil-context":
				ctx = nil
			case "canceled":
				next, cancel := context.WithCancel(ctx)
				cancel()
				ctx = next
			case "missing-check":
				check = nil
			case "missing-read":
				read = nil
			case "missing-remove":
				remove = nil
			case "bad-seed":
				seed.InstalledRecordSHA256 = ""
			case "wrong-issued":
				issued.SeedSHA256 = strings.Repeat("0", 64)
			case "bad-time":
				issued.InitialStartedAt = "invalid"
			case "running":
				issued.InitialPID = 123
			case "bad-CID":
				issued.ContainerID = "../other"
			case "missing-confirmation":
				seed.Operation.Input.AcknowledgeRemoval = false
			}
			out, e := completeMemcachedUnixRetirement(ctx, seed, issued, check, read, remove)
			if e == nil || out.State != "" || calls != 0 {
				t.Fatal("invalid framing reached a native capability", kind, e, calls)
			}
		})
	}
}
