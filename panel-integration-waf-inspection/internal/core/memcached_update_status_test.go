package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type memcachedStatusTransport func(*http.Request) (*http.Response, error)

func (f memcachedStatusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMemcachedStatusSnapshotDecoderRequiresClosedCompleteOriginalChain(t *testing.T) {
	seed := memcachedTransactionFixture(t)
	chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
	wire, _ := json.Marshal(MemcachedUpdateSnapshot{1, chain})
	decoded, err := DecodeMemcachedUpdateSnapshot(append(wire, '\n'))
	if err != nil || !reflect.DeepEqual(decoded.Records, chain) {
		t.Fatal("complete canonical original snapshot", err)
	}
	for _, scenario := range []string{"duplicate", "escaped-duplicate", "alias", "extra", "missing-format", "null-records", "empty-records", "too-many", "noncanonical-record", "record-null", "record-extra", "gap", "fork", "trailing", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			raw := append([]byte(nil), wire...)
			switch scenario {
			case "duplicate":
				raw = append([]byte(`{"format":1,`), raw[1:]...)
			case "escaped-duplicate":
				raw = append([]byte(`{"for\u006dat":1,`), raw[1:]...)
			case "alias":
				raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"FORMAT":1`), 1)
			case "extra":
				raw = append([]byte(`{"verified":true,`), raw[1:]...)
			case "missing-format":
				raw = []byte(`{"records":[]}`)
			case "null-records":
				raw = []byte(`{"format":1,"records":null}`)
			case "empty-records":
				raw = []byte(`{"format":1,"records":[]}`)
			case "too-many":
				records := make([]MemcachedUpdateRecord, 17)
				for i := range records {
					records[i] = seed
				}
				raw, _ = json.Marshal(MemcachedUpdateSnapshot{1, records})
			case "noncanonical-record":
				raw = bytes.Replace(raw, []byte(`"records":[{`), []byte(`"records":[{ `), 1)
			case "record-null":
				raw = bytes.Replace(raw, []byte(`"reason":""`), []byte(`"reason":null`), 1)
			case "record-extra":
				raw = bytes.Replace(raw, []byte(`"records":[{`), []byte(`"records":[{"verified":true,`), 1)
			case "gap":
				raw, _ = json.Marshal(MemcachedUpdateSnapshot{1, []MemcachedUpdateRecord{seed, chain[5]}})
			case "fork":
				changed := append([]MemcachedUpdateRecord(nil), chain...)
				changed[5].PreviousSHA256 = strings.Repeat("e", 64)
				changed[5].RecordSHA256 = memcachedRecordSHA(changed[5])
				raw, _ = json.Marshal(MemcachedUpdateSnapshot{1, changed})
			case "trailing":
				raw = append(raw, []byte("{}")...)
			case "oversize":
				raw = bytes.Repeat([]byte(" "), MaxMemcachedUpdateSnapshotBytes+1)
			}
			if _, err := DecodeMemcachedUpdateSnapshot(raw); err == nil {
				t.Fatal("ambiguous/truncated/unbound snapshot accepted", scenario)
			}
		})
	}
}

func TestMemcachedStatusActualHTTPHandlerOnlyReadsOwnedOriginalWithoutReconciliation(t *testing.T) {
	for _, scenario := range []string{"complete-unreconciled", "reconciled", "native-missing", "native-error", "native-nil", "no-session", "revoked-role", "revoked-menu", "other-actor", "other-project", "other-app", "missing-request", "bad-key", "post-is-not-update", "wrong-original", "stale-native-chain", "fork-known-prefix"} {
		t.Run(scenario, func(t *testing.T) {
			s, actor, seed := memcachedStoreFixture(t)
			memcachedStoreReserve(t, s, actor, seed)
			chain := memcachedStoreChain(t, seed, "pull_started", "image_verified", "apply_started", "applied", "committed")
			if scenario == "reconciled" {
				if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "stale-native-chain" || scenario == "fork-known-prefix" {
				if _, err := s.reconcileMemcachedUpdate(context.Background(), seed.Dispatch.RequestID, chain[:5]); err != nil {
					t.Fatal(err)
				}
			}
			identity := actor
			if scenario == "other-actor" {
				identity = accessUser(t, s, "another-reader", "admin", nil)
			}
			token := Token()
			if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,expires_at,last_activity_at) VALUES(?,?,?,?,?)`, Hash(token), identity.ID, "status-csrf", time.Now().Add(time.Hour).Unix(), time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			calls := 0
			executor := registryTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/docker/projects/"+seed.Dispatch.ProjectID+"/app-updates/"+seed.Dispatch.JobID || r.URL.RawQuery != "" {
					t.Error("status query widened native command or identity")
				}
				if scenario == "native-missing" || scenario == "native-error" {
					w.WriteHeader(404)
					w.Write([]byte(`{"error":"private-executor-environment-do-not-reflect"}`))
					return
				}
				records := append([]MemcachedUpdateRecord(nil), chain...)
				if scenario == "wrong-original" {
					records[0].Dispatch.JobID = ID()
					records[0].DispatchSHA256 = MemcachedUpdateDispatchSHA(records[0].Dispatch)
					records[0], _ = SealMemcachedUpdateRecord(records[0])
					records = records[:1]
				}
				if scenario == "stale-native-chain" {
					records = records[:2]
				}
				if scenario == "fork-known-prefix" {
					records[4].Observation.ContainerID = strings.Repeat("f", 64)
					records[4], _ = SealMemcachedUpdateRecord(records[4])
					records[5] = memcachedTransactionNext(t, records[4], "committed")
				}
				json.NewEncoder(w).Encode(MemcachedUpdateSnapshot{1, records})
			})
			a := &Server{Store: s, Executor: executor}
			if scenario == "native-nil" {
				a.Executor = nil
			}
			mux := http.NewServeMux()
			a.memcachedUpdateStatusRoutes(mux)
			path := "/api/app-registry/memcached/instances/" + seed.Dispatch.ProjectID + "/updates/" + seed.Dispatch.RequestID
			method, want := "GET", 200
			switch scenario {
			case "no-session":
				want = 401
			case "revoked-role":
				s.DB.Exec(`UPDATE app_user_roles SET role='viewer' WHERE user_id=?`, actor.ID)
				want = 403
			case "revoked-menu":
				s.DB.Exec(`INSERT INTO app_user_menus VALUES(?,'[]',2)`, actor.ID)
				want = 403
			case "other-actor":
				want = 403
			case "other-project":
				path = strings.Replace(path, seed.Dispatch.ProjectID, ID(), 1)
				want = 404
			case "other-app":
				path = strings.Replace(path, "/memcached/", "/mongodb/", 1)
				want = 404
			case "missing-request":
				path = strings.Replace(path, seed.Dispatch.RequestID, ID(), 1)
				want = 404
			case "bad-key":
				path = strings.Replace(path, seed.Dispatch.RequestID, "unknown", 1)
				want = 404
			case "post-is-not-update":
				method = "POST"
				want = 405
			case "wrong-original", "fork-known-prefix":
				want = 409
			}
			counts := memcachedStoreCounts(t, s)
			oldReceipt := memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID)
			before, _, _ := s.memcachedUpdateForActor(context.Background(), actor.ID, seed.Dispatch.RequestID)
			r := httptest.NewRequest(method, path, nil)
			if scenario != "no-session" {
				r.AddCookie(&http.Cookie{Name: a.sessionCookieName(), Value: token})
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != want || strings.Contains(w.Body.String(), "do-not-reflect") || memcachedStoreCounts(t, s) != counts || memcachedStoreReceipt(t, s, seed.Dispatch.ProjectID) != oldReceipt {
				t.Fatal("actual readonly status/permission/privacy contract", w.Code, w.Body.String())
			}
			after, _, _ := s.memcachedUpdateForActor(context.Background(), actor.ID, seed.Dispatch.RequestID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("GET reconciled or rewrote original metadata")
			}
			if want == 200 {
				var status memcachedUpdateStatus
				if json.Unmarshal(w.Body.Bytes(), &status) != nil || status.JobID != seed.Dispatch.JobID || status.ProjectID != seed.Dispatch.ProjectID || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("status identity/cache contract")
				}
				unknown := scenario == "native-missing" || scenario == "native-error" || scenario == "native-nil" || scenario == "stale-native-chain"
				if status.StateKnown == unknown || status.VersionRecorded != (scenario == "reconciled") {
					t.Fatal("unknown outcome fabricated health or premature version", status)
				}
			}
			if (want == 200 && scenario != "native-nil" || want == 409) && calls != 1 {
				t.Fatal("original source not queried exactly once", calls)
			}
			if want != 200 && want != 409 && calls != 0 {
				t.Fatal("unauthorized/invalid status request touched native executor")
			}
		})
	}
}

func TestMemcachedStatusNativeReaderDoesNotFollowRedirectOrForwardSessionCookies(t *testing.T) {
	seed := memcachedTransactionFixture(t)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Cookie") != "" {
			t.Error("panel cookie forwarded to native status")
		}
		http.Redirect(w, r, "/forbidden", 302)
	}))
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	base, _ := url.Parse(server.URL)
	jar.SetCookies(base, []*http.Cookie{{Name: "session", Value: "private"}})
	client := server.Client()
	client.Jar = jar
	client.Transport = memcachedStatusTransport(func(r *http.Request) (*http.Response, error) {
		request := r.Clone(r.Context())
		u := *r.URL
		u.Scheme, u.Host = base.Scheme, base.Host
		request.URL = &u
		return http.DefaultTransport.RoundTrip(request)
	})
	e := &ExecutorClient{Client: client}
	if _, err := e.readMemcachedUpdateSnapshot(context.Background(), seed.Dispatch.ProjectID, seed.Dispatch.JobID); err == nil || calls != 1 {
		t.Fatal("native redirect followed or accepted", err, calls)
	}
}
