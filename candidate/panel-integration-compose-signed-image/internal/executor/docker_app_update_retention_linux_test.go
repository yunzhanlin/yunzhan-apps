//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func memcachedRetentionFixture(t *testing.T, in memcachedRetentionIntent, raw []byte) map[string]any {
	t.Helper()
	value := memcachedRetentionPayload(in, raw)
	return map[string]any{
		"Id": strings.Repeat("b", 64), "Name": "/" + in.Name, "Image": in.ImageID, "RestartCount": 0,
		"Config":     map[string]any{"Image": in.ImageID, "User": value["User"], "Entrypoint": value["Entrypoint"], "Cmd": value["Cmd"], "NetworkDisabled": true, "Labels": value["Labels"], "Healthcheck": value["Healthcheck"]},
		"State":      map[string]any{"Status": "created", "StartedAt": "0001-01-01T00:00:00Z", "Pid": 0, "ExitCode": 0, "Running": false, "Paused": false, "Restarting": false, "OOMKilled": false, "Dead": false},
		"HostConfig": value["HostConfig"], "Mounts": []any{},
	}
}

func TestMemcachedRetentionRejectsUnsafeOrAmbiguousDaemonEvidence(t *testing.T) {
	_, seed := memcachedJournalFixture(t)
	in, raw, err := memcachedRetentionOriginal(seed.Record)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "missing-state", "wrong-id", "wrong-name", "wrong-image", "config-image", "owner", "extra-label", "started", "running", "pid", "restarted", "privileged", "writable", "network", "host-ipc", "restart-policy", "extra-cap", "bind", "mount", "port", "memory", "health-command", "missing-bool", "alias", "nested-alias", "duplicate", "case-duplicate", "nested-duplicate", "invalid-utf8", "trailing", "deep", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			v := memcachedRetentionFixture(t, in, raw)
			c, s, h := v["Config"].(map[string]any), v["State"].(map[string]any), v["HostConfig"].(map[string]any)
			switch scenario {
			case "missing-state":
				delete(v, "State")
			case "wrong-id":
				v["Id"] = "short"
			case "wrong-name":
				v["Name"] = "/foreign"
			case "wrong-image":
				v["Image"] = "sha256:" + strings.Repeat("f", 64)
			case "config-image":
				c["Image"] = "memcached:latest"
			case "owner":
				c["Labels"].(map[string]string)["io.yunzhan.owner"] = "foreign"
			case "extra-label":
				c["Labels"].(map[string]string)["unbound"] = "foreign"
			case "started":
				s["StartedAt"] = "2026-10-18T00:00:00Z"
			case "running":
				s["Running"] = true
			case "pid":
				s["Pid"] = 7
			case "restarted":
				v["RestartCount"] = 1
			case "privileged":
				h["Privileged"] = true
			case "writable":
				h["ReadonlyRootfs"] = false
			case "network":
				h["NetworkMode"] = "host"
			case "host-ipc":
				h["IpcMode"] = "host"
			case "restart-policy":
				h["RestartPolicy"].(map[string]any)["Name"] = "always"
			case "extra-cap":
				h["CapAdd"] = []string{"SYS_ADMIN"}
			case "bind":
				h["Binds"] = []string{"/:/host"}
			case "mount":
				v["Mounts"] = []any{map[string]any{"Type": "volume"}}
			case "port":
				h["PortBindings"] = map[string]any{"11211/tcp": []any{}}
			case "memory":
				h["Memory"] = 0
			case "health-command":
				c["Healthcheck"].(map[string]any)["Test"] = []string{"CMD", "anything"}
			case "missing-bool":
				delete(s, "Running")
			case "alias":
				v["id"] = v["Id"]
				delete(v, "Id")
			case "nested-alias":
				s["running"] = s["Running"]
				delete(s, "Running")
			}
			body, _ := json.Marshal(v)
			switch scenario {
			case "duplicate":
				body = append([]byte(`{"Id":"foreign",`), body[1:]...)
			case "case-duplicate":
				body = append([]byte(`{"id":"foreign",`), body[1:]...)
			case "nested-duplicate":
				body = bytes.Replace(body, []byte(`"Running":false`), []byte(`"Running":true,"Running":false`), 1)
			case "invalid-utf8":
				body = bytes.Replace(body, []byte(`"created"`), []byte{'"', 0xff, '"'}, 1)
			case "trailing":
				body = append(body, []byte(`{}`)...)
			case "deep":
				body = []byte(strings.Repeat("[", 22) + "0" + strings.Repeat("]", 22))
			case "oversize":
				body = bytes.Repeat([]byte(" "), (256<<10)+1)
			}
			id, err := memcachedRetentionInspect(body, in, raw, "")
			if scenario == "valid" {
				if err != nil || id != strings.Repeat("b", 64) {
					t.Fatal("closed synthetic evidence rejected", err)
				}
				if _, err := memcachedRetentionInspect(body, in, raw, strings.Repeat("a", 64)); err == nil {
					t.Fatal("changed original receipt identity accepted")
				}
			} else if err == nil {
				t.Fatal("unsafe daemon evidence accepted")
			}
		})
	}
}

func TestMemcachedRetentionWriteAheadSingleCreateAndOriginalInspectionOnly(t *testing.T) {
	for _, scenario := range []string{"created", "reply-lost-created", "reply-lost-absent", "foreign-name", "denied-before-intent", "denied-after-intent", "receipt-replaced", "intent-changed", "detached", "closed-lease", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			store, seed := memcachedJournalFixture(t)
			j := memcachedJournalPrepare(t, store, seed)
			lease, err := j.lease()
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			in, intent, _ := memcachedRetentionOriginal(seed.Record)
			v := memcachedRetentionFixture(t, in, intent)
			body, _ := json.Marshal(v)
			created, posts, reads, grants := false, 0, 0, 0
			call := func(ctx context.Context, method, path string, input any) (int, []byte, error) {
				if ctx.Err() != nil {
					return 0, nil, ctx.Err()
				}
				if method == http.MethodPost {
					posts++
					if path != "/containers/create?name="+in.Name || posts != 1 {
						t.Fatal("replayed or redirected create", path)
					}
					want, _ := json.Marshal(memcachedRetentionPayload(in, intent))
					got, _ := json.Marshal(input)
					if !bytes.Equal(want, got) {
						t.Fatal("mutable tag/unsafe create payload")
					}
					stored, e := geoStoreRead(j.d.root, "image-retention.intent.json", 4096)
					if e != nil || !bytes.Equal(stored, intent) {
						t.Fatal("effect without durable original intent", e)
					}
					created = scenario != "reply-lost-absent"
					if strings.HasPrefix(scenario, "reply-lost") {
						return 0, nil, errors.New("synthetic reply lost")
					}
					return 201, []byte(`{"Id":"ignored-response-not-authority"}`), nil
				}
				reads++
				if method != http.MethodGet || path != "/containers/"+in.Name+"/json" || input != nil {
					t.Fatal("unexpected operation")
				}
				if created || scenario == "foreign-name" {
					return 200, body, nil
				}
				return 404, []byte(`{"message":"not found"}`), nil
			}
			grant := func(context.Context) error {
				grants++
				if scenario == "denied-before-intent" || scenario == "denied-after-intent" && grants > 1 {
					return errors.New("synthetic current grant revoked")
				}
				return nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "closed-lease" {
				lease.Close()
			}
			if scenario == "canceled" {
				cancel()
			}
			id, err := lease.retainOriginalImage(ctx, call, grant)
			success := scenario == "created" || scenario == "reply-lost-created" || scenario == "receipt-replaced" || scenario == "intent-changed" || scenario == "detached"
			if success != (err == nil) {
				t.Fatal("wrong original outcome", id, err)
			}
			if !success && posts > 0 && scenario != "reply-lost-absent" {
				t.Fatal("unauthorized effect")
			}
			if !success && scenario != "reply-lost-absent" && scenario != "denied-after-intent" {
				return
			}
			if success && id != strings.Repeat("b", 64) {
				t.Fatal("wrong bound identity")
			}
			job := filepath.Join(store.base, seed.Record.Dispatch.JobID)
			switch scenario {
			case "receipt-replaced":
				v["Id"] = strings.Repeat("f", 64)
				body, _ = json.Marshal(v)
			case "intent-changed":
				if e := os.WriteFile(filepath.Join(job, "image-retention.intent.json"), append(intent, ' '), 0600); e != nil {
					t.Fatal(e)
				}
			case "detached":
				if e := os.Rename(job, job+".detached"); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(job, 0700); e != nil {
					t.Fatal(e)
				}
			}
			beforePosts, beforeReads := posts, reads
			_, again := lease.retainOriginalImage(ctx, call, grant)
			if posts != beforePosts {
				t.Fatal("reopened intent sent a second POST")
			}
			if scenario == "created" || scenario == "reply-lost-created" {
				if again != nil || reads != beforeReads+1 {
					t.Fatal("original receipt was not inspected readonly", again)
				}
			} else if again == nil {
				t.Fatal("unknown/drift adopted as success")
			}
		})
	}
}
