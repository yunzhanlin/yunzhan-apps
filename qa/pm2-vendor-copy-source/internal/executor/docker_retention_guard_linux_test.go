//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestDockerRetentionGuardCannotStartStopRestartOrDeleteNativeAnchor(t *testing.T) {
	for _, scenario := range []string{"reserved-name", "owner-label-renamed", "retention-label-renamed", "empty-retention-marker", "damaged-owner-but-original-name"} {
		t.Run(scenario, func(t *testing.T) {
			for _, action := range []string{"start", "stop", "restart", "delete"} {
				id := strings.Repeat("a", 64)
				name, labels := "/ordinary", map[string]string{}
				switch scenario {
				case "reserved-name":
					name = "/" + dockerRetentionPrefix + strings.Repeat("b", 32)
				case "owner-label-renamed":
					labels["io.yunzhan.owner"] = memcachedRetentionOwner
				case "retention-label-renamed":
					labels["io.yunzhan.retention-sha256"] = strings.Repeat("b", 64)
				case "empty-retention-marker":
					labels["io.yunzhan.retention-sha256"] = ""
				case "damaged-owner-but-original-name":
					name = "/" + dockerRetentionPrefix + "damaged"
					labels["io.yunzhan.owner"] = "damaged"
				}
				raw, _ := json.Marshal(map[string]any{"Id": id, "Name": name, "Config": map[string]any{"Labels": labels}})
				calls := 0
				call := func(ctx context.Context, method, path string, in, out any, max int64) ([]byte, error) {
					calls++
					if method != http.MethodGet || path != "/containers/"+id[:12]+"/json" || in != nil || out != nil || max != 256<<10 {
						t.Fatal("protected container reached daemon mutation", method, path)
					}
					return raw, nil
				}
				method, path := http.MethodPost, "/containers/"+id[:12]+"/"+action
				if action == "delete" {
					method, path = http.MethodDelete, "/containers/"+id[:12]+"?v=false"
				}
				if _, err := dockerOrdinaryRequest(t.Context(), method, path, nil, nil, 1024, call); !errors.Is(err, errDockerRetainedContainer) || calls != 1 {
					t.Fatal("native anchor mutation admitted", action, calls, err)
				}
			}
		})
	}
}

func TestDockerRetentionGuardOrdinaryOperationsBindFullActualIDAndPreserveRequest(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart", "delete"} {
		t.Run(action, func(t *testing.T) {
			id := strings.Repeat("c", 64)
			raw := []byte(`{"Id":"` + id + `","Name":"/ordinary","Config":{"Labels":null,"Env":["PRIVATE_DO_NOT_REFLECT=value"]}}`)
			method, suffix := http.MethodPost, "/"+action
			if action == "stop" || action == "restart" {
				suffix += "?t=10"
			}
			if action == "delete" {
				method, suffix = http.MethodDelete, "?v=false"
			}
			calls := 0
			input := &struct{ Value string }{"original"}
			output := &struct{}{}
			call := func(ctx context.Context, m, path string, in, out any, max int64) ([]byte, error) {
				calls++
				if calls == 1 {
					if m != http.MethodGet || path != "/containers/"+id[:12]+"/json" {
						t.Fatal("wrong inspection")
					}
					return raw, nil
				}
				if calls != 2 || m != method || path != "/containers/"+id+suffix || in != input || out != output || max != 8192 {
					t.Fatal("original operation changed or borrowed prefix", m, path)
				}
				return []byte("original-result"), nil
			}
			result, err := dockerOrdinaryRequest(t.Context(), method, "/containers/"+id[:12]+suffix, input, output, 8192, call)
			if err != nil || calls != 2 || string(result) != "original-result" {
				t.Fatal("ordinary operation blocked", calls, err)
			}
		})
	}
}

func TestDockerRetentionGuardUnknownOrAmbiguousEvidenceNeverBecomesAnEffect(t *testing.T) {
	for _, scenario := range []string{"missing", "invalid-json", "missing-config", "null-config", "missing-labels", "wrong-id", "short-id", "missing-name", "id-alias", "config-alias", "labels-alias", "duplicate", "nested-duplicate", "non-string-label", "trailing", "oversize", "canceled-during-inspection"} {
		t.Run(scenario, func(t *testing.T) {
			id := strings.Repeat("d", 64)
			v := map[string]any{"Id": id, "Name": "/ordinary", "Config": map[string]any{"Labels": map[string]string{}}}
			switch scenario {
			case "missing-config":
				delete(v, "Config")
			case "null-config":
				v["Config"] = nil
			case "missing-labels":
				v["Config"] = map[string]any{}
			case "wrong-id":
				v["Id"] = strings.Repeat("e", 64)
			case "short-id":
				v["Id"] = id[:12]
			case "missing-name":
				delete(v, "Name")
			case "id-alias":
				v["id"] = v["Id"]
				delete(v, "Id")
			case "config-alias":
				v["config"] = v["Config"]
				delete(v, "Config")
			case "labels-alias":
				v["Config"] = map[string]any{"labels": nil}
			case "non-string-label":
				v["Config"] = map[string]any{"Labels": map[string]int{"private": 1}}
			}
			raw, _ := json.Marshal(v)
			switch scenario {
			case "invalid-json":
				raw = []byte("{")
			case "duplicate":
				raw = append([]byte(`{"Id":"private-do-not-reflect",`), raw[1:]...)
			case "nested-duplicate":
				raw = bytes.Replace(raw, []byte(`"Labels":{}`), []byte(`"Labels":{},"labels":{}`), 1)
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), (256<<10)+1)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			call := func(_ context.Context, method, path string, in, out any, max int64) ([]byte, error) {
				calls++
				if method != http.MethodGet || calls != 1 {
					t.Fatal("uncertain evidence mutated daemon")
				}
				if scenario == "missing" {
					return nil, errors.New("private-do-not-reflect")
				}
				if scenario == "canceled-during-inspection" {
					cancel()
				}
				return raw, nil
			}
			_, err := dockerOrdinaryRequest(ctx, http.MethodPost, "/containers/"+id[:12]+"/start", nil, nil, 1024, call)
			if !errors.Is(err, errDockerRetainedContainer) || calls != 1 || strings.Contains(err.Error(), "private-do-not-reflect") {
				t.Fatal("ambiguous inspection adopted or reflected", calls, err)
			}
		})
	}
}

func TestDockerRetentionGuardReservedCreateAndUnreviewedContainerActionsNeverReachDaemon(t *testing.T) {
	for _, path := range []string{"/containers/create?name=yunzhan-retain-memcached-original", "/containers/prune", "/containers/" + strings.Repeat("a", 12) + "/kill", "/containers/" + strings.Repeat("a", 12) + "/rename?name=other", "http://foreign/containers/create", "/containers/%2f/start"} {
		if _, err := dockerOrdinaryRequest(t.Context(), http.MethodPost, path, nil, nil, 1024, func(context.Context, string, string, any, any, int64) ([]byte, error) {
			t.Fatal("unreviewed/reserved operation reached daemon", path)
			return nil, nil
		}); !errors.Is(err, errDockerRetainedContainer) {
			t.Fatal("unsafe operation accepted", path, err)
		}
	}
	for _, path := range []string{"/containers/create?name=ordinary", "/networks/create", "/volumes/create", "/images/" + strings.Repeat("a", 12) + "?force=false&noprune=true"} {
		calls := 0
		_, err := dockerOrdinaryRequest(t.Context(), http.MethodPost, path, nil, nil, 1024, func(_ context.Context, _ string, p string, _, _ any, _ int64) ([]byte, error) {
			calls++
			if p != path {
				t.Fatal("unrelated request changed")
			}
			return nil, nil
		})
		if err != nil || calls != 1 {
			t.Fatal("unrelated operation blocked", path, err)
		}
	}
}
