//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func retirementAbsenceFixture() (memcachedUnixControlSeed, memcachedUnixControlIssued) {
	seed := memcachedUnixControlSeed{Format: 1, InstalledRecordSHA256: strings.Repeat("e", 64), Operation: core.MemcachedUnixControlOperation{Format: 1, RequestID: strings.Repeat("a", 32), ProjectID: strings.Repeat("b", 32), ActorID: strings.Repeat("c", 32), Input: core.MemcachedUnixControlInput{Action: "retire", ExpectedRuntimeSHA256: strings.Repeat("d", 64), AcknowledgeRemoval: true, ConfirmName: "own-cache"}}}
	raw, _ := json.Marshal(seed)
	return seed, memcachedUnixControlIssued{Format: 1, SeedSHA256: core.Hash(string(raw)), ContainerID: strings.Repeat("f", 64), InitialPID: 0, InitialStartedAt: "2026-10-25T00:00:00Z"}
}

func TestMemcachedUnixRetirementAbsenceUsesFourReadsNotADeleteAuthority(t *testing.T) {
	seed, issued := retirementAbsenceFixture()
	calls := []string{}
	read := func(_ context.Context, method, path string, input any) (int, []byte, error) {
		if method != http.MethodGet || input != nil {
			t.Fatal("absence observation attempted mutation", method, path)
		}
		calls = append(calls, path)
		if len(calls) == 1 {
			return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\"}"), nil
		}
		if strings.HasPrefix(path, "/volumes?") {
			return 200, []byte("{\"Volumes\":null,\"Warnings\":null}"), nil
		}
		return 200, []byte("[]"), nil
	}
	digest, e := memcachedUnixRetirementAbsence(context.Background(), seed, issued, read)
	if e != nil || len(digest) != 64 || len(calls) != 4 || calls[0] != "/containers/"+issued.ContainerID+"/json" {
		t.Fatal("complete absence evidence refused", digest, e, calls)
	}
	other := seed
	other.InstalledRecordSHA256 = strings.Repeat("9", 64)
	raw, _ := json.Marshal(other)
	next := issued
	next.SeedSHA256 = core.Hash(string(raw))
	calls = nil
	changed, e := memcachedUnixRetirementAbsence(context.Background(), other, next, read)
	if e != nil || changed == digest {
		t.Fatal("absence fingerprint borrowed another installation", e)
	}
}

func TestMemcachedUnixRetirementAbsenceRefusesPartialWrongOrStillReferencedEngine(t *testing.T) {
	for _, kind := range []string{"CID-present", "CID-denied", "CID-timeout", "bare-404", "wrong-CID", "extra-error-field", "duplicate-error-key", "containers-missing", "containers-null", "containers-still-present", "network-remaining", "volumes-field-missing", "volume-remaining", "volume-warning", "wrong-volume-type", "daemon-500", "trailing-document", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			seed, issued := retirementAbsenceFixture()
			calls := 0
			read := func(_ context.Context, method, path string, input any) (int, []byte, error) {
				calls++
				if method != http.MethodGet || input != nil {
					t.Fatal("mutation attempted")
				}
				if calls == 1 {
					if kind == "CID-present" {
						return 200, []byte("{}"), nil
					}
					if kind == "CID-denied" {
						return 403, []byte("{}"), nil
					}
					if kind == "CID-timeout" {
						return 0, nil, errors.New("lost read")
					}
					if kind == "bare-404" {
						return 404, []byte("{}"), nil
					}
					if kind == "wrong-CID" {
						return 404, []byte("{\"message\":\"No such container: other\"}"), nil
					}
					if kind == "extra-error-field" {
						return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\",\"other\":true}"), nil
					}
					if kind == "duplicate-error-key" {
						return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\",\"Message\":\"different\"}"), nil
					}
					return 404, []byte("{\"message\":\"No such container: " + issued.ContainerID + "\"}"), nil
				}
				if kind == "daemon-500" {
					return 500, []byte("[]"), nil
				}
				if kind == "trailing-document" {
					return 200, []byte("[] {}"), nil
				}
				if kind == "oversize" {
					return 200, []byte("[" + strings.Repeat(" ", 17<<10) + "]"), nil
				}
				if strings.HasPrefix(path, "/containers/json?") {
					if kind == "containers-missing" {
						return 404, []byte("{}"), nil
					}
					if kind == "containers-null" {
						return 200, []byte("null"), nil
					}
					if kind == "containers-still-present" {
						return 200, []byte("[{\"Id\":\"other\"}]"), nil
					}
				}
				if strings.HasPrefix(path, "/networks?") && kind == "network-remaining" {
					return 200, []byte("[{}]"), nil
				}
				if strings.HasPrefix(path, "/volumes?") {
					switch kind {
					case "volumes-field-missing":
						return 200, []byte("{}"), nil
					case "volume-remaining":
						return 200, []byte("{\"Volumes\":[{}]}"), nil
					case "volume-warning":
						return 200, []byte("{\"Volumes\":[],\"Warnings\":[\"incomplete plugin query\"]}"), nil
					case "wrong-volume-type":
						return 200, []byte("{\"Volumes\":{}}"), nil
					}
					return 200, []byte("{\"Volumes\":[],\"Warnings\":[]}"), nil
				}
				return 200, []byte("[]"), nil
			}
			if digest, e := memcachedUnixRetirementAbsence(context.Background(), seed, issued, read); e == nil || digest != "" {
				t.Fatal("unproved absence accepted", kind)
			}
			if calls > 4 {
				t.Fatal("read was retried", calls)
			}
		})
	}
}

func TestMemcachedUnixRetirementAbsenceRejectsUnboundFramingBeforeDaemon(t *testing.T) {
	for _, kind := range []string{"nil-context", "canceled", "nil-reader", "wrong-action", "bad-original", "unbound-issued", "running-original", "bad-start", "bad-CID"} {
		t.Run(kind, func(t *testing.T) {
			seed, issued := retirementAbsenceFixture()
			ctx := context.Background()
			calls := 0
			read := memcachedRetentionCall(func(context.Context, string, string, any) (int, []byte, error) {
				calls++
				return 0, nil, errors.New("must not read")
			})
			switch kind {
			case "nil-context":
				ctx = nil
			case "canceled":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "nil-reader":
				read = nil
			case "wrong-action":
				seed.Operation.Input.Action = "stop"
			case "bad-original":
				seed.InstalledRecordSHA256 = ""
			case "unbound-issued":
				issued.SeedSHA256 = strings.Repeat("0", 64)
			case "running-original":
				issued.InitialPID = 123
			case "bad-start":
				issued.InitialStartedAt = "not-a-time"
			case "bad-CID":
				issued.ContainerID = "../other"
			}
			if digest, e := memcachedUnixRetirementAbsence(ctx, seed, issued, read); e == nil || digest != "" || calls != 0 {
				t.Fatal("invalid framing reached daemon or returned proof", kind, calls, e)
			}
		})
	}
}
