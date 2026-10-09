package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"local/panel/internal/appcatalog"
	"local/panel/internal/rulefeed"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func networkRuleFeedRepositoryFixture(t *testing.T) (*appcatalog.Client, NetworkIDSRuleFeedSelection, *atomic.Int64) {
	return networkRuleFeedRepositoryFixtureMode(t, false)
}

func networkRuleFeedRepositoryFixtureMode(t *testing.T, channel bool) (*appcatalog.Client, NetworkIDSRuleFeedSelection, *atomic.Int64) {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, name := range []string{"LICENSE", "BSD-License.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "rulefeed", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteHeader(&tar.Header{Name: "rules/" + name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	rules := []byte("alert http any any -> $HOME_NET any (msg:\"own worker fixture\";sid:2000001;rev:1;)\n")
	if err := writer.WriteHeader(&tar.Header{Name: "rules/emerging-fixture.rules", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(rules))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(rules); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := zip.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}
	source, err := rulefeed.ReadETOpen(context.Background(), bytes.NewReader(compressed.Bytes()), Hash(compressed.String()))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := rulefeed.Build(source, rulefeed.Profile{Categories: []string{"emerging-fixture"}, Variables: []string{"HOME_NET"}, MaxEnabled: 128})
	if err != nil {
		t.Fatal(err)
	}
	selection := networkRuleFeedSelectionFixture()
	if channel {
		selection.FeedID = "et-open-web-" + time.Now().UTC().Format("20060102")
	}
	selection.RuleManifestSHA = Hash(string(bundle.Files["manifest.json"]))
	feed := appcatalog.RuleFeed{ID: selection.FeedID, ManifestSHA256: selection.RuleManifestSHA}
	names := []string{}
	for name := range bundle.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		feed.Assets = append(feed.Assets, appcatalog.RuleFeedAsset{Name: name, SHA256: Hash(string(bundle.Files[name])), Bytes: len(bundle.Files[name])})
	}
	manifest := appcatalog.Manifest{SchemaVersion: 1, ID: "network-threat-detection", Name: "Own worker fixture", Category: "professional", Version: selection.AppVersion, Summary: "own offline worker fixture only", Stage: "ready", Risk: "maintained", Delivery: appcatalog.Delivery{Provider: "panel-module", Target: "network-threat-detection", ManageRoute: "app-modules"}, Capabilities: []string{"passive IDS"}, RuleFeeds: []appcatalog.RuleFeed{feed}}
	manifest.Compatibility = appcatalog.Compatibility{OS: []string{runtimecatalog.HostPlatform()}, Architectures: []string{runtime.GOARCH}}
	var dataCatalog []byte
	if channel {
		manifest.RuleFeeds = nil
		manifest.RuleDataChannel = &appcatalog.RuleDataChannel{ID: "et-open-web-bsd-v1", Format: 1, Engine: "suricata-8.0"}
		published := time.Now().UTC().Truncate(time.Minute)
		dataCatalog, _ = json.Marshal(appcatalog.RuleDataCatalog{SchemaVersion: 1, Channel: "et-open-web-bsd-v1", Sequence: 1, PublishedAt: published.Format(time.RFC3339), ExpiresAt: published.Add(24 * time.Hour).Format(time.RFC3339), Feed: feed})
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	selection.AppManifestSHA = Hash(string(manifestRaw))
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	requests := &atomic.Int64{}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		manifestPath := "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/manifest.json"
		switch r.URL.Path {
		case "/signatures/catalog-v1.bundle.json":
			item := appcatalog.CatalogItem{ID: manifest.ID, Name: manifest.Name, Category: manifest.Category, Version: manifest.Version, Summary: manifest.Summary, Stage: manifest.Stage, Risk: manifest.Risk, Provider: manifest.Delivery.Provider, Target: manifest.Delivery.Target, ManageRoute: manifest.Delivery.ManageRoute, Capabilities: manifest.Capabilities, PackageURL: server.URL + manifestPath, SHA256: selection.AppManifestSHA}
			catalog, _ := json.Marshal(appcatalog.Catalog{SchemaVersion: 1, GeneratedAt: "2026-10-09T00:00:00Z", Apps: []appcatalog.CatalogItem{item}})
			json.NewEncoder(w).Encode(map[string]string{"catalog": string(catalog), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, catalog))})
			return
		case manifestPath:
			w.Write(manifestRaw)
			return
		case "/dist/apps/network-threat-detection/rule-data/et-open-web-bsd-v1/catalog-v1.bundle.json":
			if channel {
				json.NewEncoder(w).Encode(map[string]string{"catalog": string(dataCatalog), "signature": base64.StdEncoding.EncodeToString(ed25519.Sign(private, append([]byte("yunzhan-rulefeed-channel-v1\n"), dataCatalog...)))})
				return
			}
		}
		prefix := "/dist/apps/" + manifest.ID + "/" + manifest.Version + "/rules/" + feed.ID + "/"
		if channel {
			prefix = "/dist/apps/network-threat-detection/rule-data/et-open-web-bsd-v1/feeds/" + feed.ID + "/" + feed.ManifestSHA256 + "/"
		}
		if strings.HasPrefix(r.URL.Path, prefix) {
			if data, ok := bundle.Files[strings.TrimPrefix(r.URL.Path, prefix)]; ok {
				w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := appcatalog.New(server.URL, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client, selection, requests
}

func TestNetworkIDSRuleFeedWorkerVerifiesBindingAndDataOnlyResult(t *testing.T) {
	for _, scenario := range []string{"ready", "bad-id", "bad-selection", "capture", "native-proof", "not-data-only", "failed", "ready-error", "unknown", "interrupted", "too-many-steps"} {
		t.Run(scenario, func(t *testing.T) {
			repository, selection, requests := networkRuleFeedRepositoryFixture(t)
			store := testStore(t)
			id, err := store.QueueNetworkIDSRuleFeed(selection, ID(), "admin")
			if err != nil {
				t.Fatal(err)
			}
			job, err := store.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			executor := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Path != "/v1/network-ids/rule-feeds/jobs/"+id || r.URL.Query().Get("app_version") != selection.AppVersion || r.URL.Query().Get("app_manifest_sha256") != selection.AppManifestSHA || r.URL.Query().Get("rule_manifest_sha256") != selection.RuleManifestSHA {
					t.Fatal("wrong data-only privileged dispatch", r.URL)
				}
				raw, err := io.ReadAll(io.LimitReader(r.Body, appcatalog.MaxRuleFeedEnvelopeBytes+1))
				if err != nil {
					t.Fatal(err)
				}
				in, err := appcatalog.DecodeRuleFeedEnvelope(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := repository.VerifyRuleFeedEnvelope(context.Background(), in, selection.AppVersion, selection.AppManifestSHA); err != nil {
					t.Fatal("wrong raw signing/data transfer", err)
				}
				result := NetworkIDSRuleFeedStatus{JobID: id, State: "ready-data", Selection: selection, DataOnly: true, Steps: []Step{{Time: Now(), Message: "own fake offline data result, not native proof"}}}
				switch scenario {
				case "bad-id":
					result.JobID = ID()
				case "bad-selection":
					result.Selection.RuleManifestSHA = strings.Repeat("c", 64)
				case "capture":
					result.CaptureStarted = true
				case "native-proof":
					result.NativeSyntaxVerified = true
				case "not-data-only":
					result.DataOnly = false
				case "failed":
					result.State = "failed"
					result.Error = "own retained failure"
				case "ready-error":
					result.Error = "unresolved"
				case "unknown":
					result.State = "invented"
				case "interrupted":
					result.State = "needs-attention"
					result.Error = "own missing result"
				case "too-many-steps":
					result.Steps = make([]Step, 17)
				}
				data, _ := json.Marshal(result)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}, nil
			})}}
			runNetworkIDSRuleFeedJob(context.Background(), store, executor, job, repository)
			var state string
			if err := store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state); err != nil {
				t.Fatal(err)
			}
			want := "needs_attention"
			if scenario == "ready" {
				want = "succeeded"
			}
			if scenario == "failed" {
				want = "failed"
			}
			if state != want || calls != 1 || requests.Load() != 8 {
				t.Fatal("false success, wrong closed download or privileged action", state, want, calls, requests.Load())
			}
		})
	}
}

func TestNetworkIDSRuleFeedHTTPAdministratorMenuCSRFAndSignedSelection(t *testing.T) {
	repository, selection, requests := networkRuleFeedRepositoryFixture(t)
	s := testStore(t)
	for _, user := range []struct {
		name, role string
		menus      []string
	}{{"admin", "admin", nil}, {"limited", "admin", []string{"runtimes"}}, {"viewer", "viewer", nil}} {
		accessUser(t, s, user.name, user.role, user.menus)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://127.0.0.1:19100", Socket: "/missing"})
	if err != nil {
		t.Fatal(err)
	}
	a.AppCatalog = repository
	executorCalls := 0
	a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		executorCalls++
		if r.Method != "GET" || r.URL.Path != "/v1/app-modules/network-threat-detection" {
			t.Fatal("queueing started privileged install or capture", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status":{"installed":true}}`))}, nil
	})}}
	endpoint := "/api/software/network-threat-detection/rule-feeds/install"
	request := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", a.Config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Idempotency-Key", "own-http-rule-job")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		return w
	}
	encoded, _ := json.Marshal(selection)
	if w := request(endpoint, string(encoded), "", nil); w.Code != 401 {
		t.Fatal("anonymous", w.Code)
	}
	for _, name := range []string{"viewer", "limited", "admin"} {
		login := request("/api/login", `{"username":"`+name+`","password":"access-test-password-long"}`, "", nil)
		if login.Code != 200 {
			t.Fatal("fixture login", login.Code)
		}
		var auth accountSession
		json.Unmarshal(login.Body.Bytes(), &auth)
		cookie := login.Result().Cookies()[0]
		beforeCalls, beforeRequests := executorCalls, requests.Load()
		if w := request(endpoint, string(encoded), "", cookie); w.Code != 403 {
			t.Fatal("CSRF bypass", name, w.Code)
		}
		if name != "admin" {
			if w := request(endpoint, string(encoded), auth.CSRF, cookie); w.Code != 403 || executorCalls != beforeCalls || requests.Load() != beforeRequests {
				t.Fatal("unauthorized request reached executor or repository", name, w.Code)
			}
			continue
		}
		for _, raw := range []string{`{}`, `{"verified":true}`, `{"repository":"https://foreign.invalid"}`, string(append([]byte(`{"feed_id":"other",`), encoded[1:]...)), string(encoded) + "{}"} {
			if w := request(endpoint, raw, auth.CSRF, cookie); w.Code != 400 || executorCalls != beforeCalls || requests.Load() != beforeRequests {
				t.Fatal("invalid input dispatched", w.Code)
			}
		}
		wrong := selection
		wrong.AppVersion = "99.0.0"
		wrongRaw, _ := json.Marshal(wrong)
		if w := request(endpoint, string(wrongRaw), auth.CSRF, cookie); w.Code != 409 || executorCalls != beforeCalls || requests.Load() != beforeRequests {
			t.Fatal("future handler dispatched or downloaded", w.Code)
		}
		wrong = selection
		wrong.RuleManifestSHA = strings.Repeat("c", 64)
		wrongRaw, _ = json.Marshal(wrong)
		if w := request(endpoint, string(wrongRaw), auth.CSRF, cookie); w.Code != 409 {
			t.Fatal("unlisted binding queued", w.Code)
		}
		w := request(endpoint, string(encoded), auth.CSRF, cookie)
		if w.Code != 202 || !strings.Contains(w.Body.String(), `"data_only":true`) || !strings.Contains(w.Body.String(), `"capture_started":false`) || !strings.Contains(w.Body.String(), `"native_syntax_verified":false`) {
			t.Fatal("queueing claimed readiness or capture", w.Code, w.Body.String())
		}
		// Each manifest check reads only the catalog and app manifest, never
		// the six rule assets; the background worker owns that explicit pull.
		if requests.Load() != 4 || executorCalls != 2 {
			t.Fatal("API pulled rule data or privileged install", requests.Load(), executorCalls)
		}
		var accepted struct {
			JobID string `json:"job_id"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil {
			t.Fatal(err)
		}
		for _, state := range []string{"queued", "failed"} {
			if state == "failed" {
				if _, err := s.DB.Exec(`UPDATE runtime_jobs SET state='failed',error='retained original failure' WHERE id=?`, accepted.JobID); err != nil {
					t.Fatal(err)
				}
			}
			w := request(endpoint, string(encoded), auth.CSRF, cookie)
			if w.Code != 202 || !strings.Contains(w.Body.String(), `"replayed":true`) || !strings.Contains(w.Body.String(), accepted.JobID) || executorCalls != 2 || requests.Load() != 4 {
				t.Fatal("lost reply or terminal failure pulled newer catalog/requeued", state, w.Code, w.Body.String())
			}
		}
		var jobs int
		s.DB.QueryRow(`SELECT count(*) FROM runtime_jobs WHERE kind='network_ids_rulefeed_install'`).Scan(&jobs)
		if jobs != 1 {
			t.Fatal("wrong task count", jobs)
		}
	}
}

func TestNetworkIDSRuleFeedWorkerRejectsChangedReleaseBeforeDispatch(t *testing.T) {
	repository, selection, requests := networkRuleFeedRepositoryFixture(t)
	s := testStore(t)
	selection.AppManifestSHA = strings.Repeat("c", 64)
	id, err := s.QueueNetworkIDSRuleFeed(selection, ID(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	job, err := s.nextRuntimeInstallJob()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		t.Fatal("changed signed release dispatched")
		return nil, nil
	})}}
	runNetworkIDSRuleFeedJob(context.Background(), s, e, job, repository)
	var state string
	s.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state)
	if state != "failed" || calls != 0 || requests.Load() != 1 {
		t.Fatal("changed release pulled data or falsely completed", state, calls, requests.Load())
	}
}

func TestNetworkIDSRuleFeedWorkerObservesOriginalAfterLostReply(t *testing.T) {
	for _, scenario := range []string{"lost-post", "temporary-poll", "mismatched-reply", "missing-original"} {
		t.Run(scenario, func(t *testing.T) {
			repository, selection, requests := networkRuleFeedRepositoryFixtureMode(t, true)
			store := testStore(t)
			id, err := store.QueueNetworkIDSRuleFeed(selection, ID(), "admin")
			if err != nil {
				t.Fatal(err)
			}
			job, err := store.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			posts, reads := 0, 0
			executor := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				result := NetworkIDSRuleFeedStatus{JobID: id, State: "ready-data", Selection: selection, DataOnly: true}
				if r.Method == "POST" {
					posts++
					if scenario != "temporary-poll" {
						return nil, io.EOF
					}
					result.State = "queued"
				} else {
					if r.Method != "GET" || r.URL.Path != "/v1/network-ids/rule-feeds/jobs/"+id {
						t.Fatal("observation changed original identity", r.URL)
					}
					reads++
					if scenario == "temporary-poll" && reads == 1 {
						return nil, context.DeadlineExceeded
					}
					if scenario == "mismatched-reply" {
						result.JobID = ID()
					}
					if scenario == "missing-original" {
						return &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"error":"own missing original request"}`))}, nil
					}
				}
				raw, _ := json.Marshal(result)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}}
			runNetworkIDSRuleFeedJob(context.Background(), store, executor, job, repository)
			var state string
			if err := store.DB.QueryRow(`SELECT state FROM runtime_jobs WHERE id=?`, id).Scan(&state); err != nil {
				t.Fatal(err)
			}
			want := "succeeded"
			if scenario == "mismatched-reply" || scenario == "missing-original" {
				want = "needs_attention"
			}
			if state != want || posts != 1 || reads < 1 || requests.Load() != 9 {
				t.Fatal("lost response repeated install/download or faked completion", state, posts, reads, requests.Load())
			}
		})
	}
}
