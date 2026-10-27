package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/loadbalancestream"
)

type streamInstallCoreRoundTrip func(*http.Request) (*http.Response, error)

func (f streamInstallCoreRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These are Core-only contract models. The mock metadata is NOT a signature,
// the mock Unix peer is NOT Root, and none is native/application acceptance.
func streamInstallCoreFixtureJob(t *testing.T, action string) (*Store, identity, Job) {
	t.Helper()
	s, u, id, _ := streamInstallFixture(t, action, true)
	var j Job
	j.ID = id
	if err := s.DB.QueryRow("SELECT target_id,kind,payload FROM runtime_jobs WHERE id=?", id).Scan(&j.TargetID, &j.Kind, &j.Payload); err != nil {
		t.Fatal(err)
	}
	return s, u, j
}

func streamInstallCoreModelMetadata(context.Context, string, string) (appcatalog.LoadBalanceStreamReleaseEnvelope, error) {
	return appcatalog.LoadBalanceStreamReleaseEnvelope{Catalog: []byte(`{"fixture_only":true}`), Signature: []byte("NOT-OFFICIAL-SIGNATURE"), AppManifest: []byte(`{"fixture_only":true}`)}, nil
}

func streamInstallCoreModelResult(j Job) LoadBalanceStreamInstallResult {
	return LoadBalanceStreamInstallResult{Format: 1, JobID: j.ID, Version: loadbalancestream.AppVersion, State: "committed", InstallationID: ID(), SeedSHA256: Hash("model-seed"), FinalEventSHA256: Hash("model-final"), PublishedModuleSHA256: Hash("model-module"), AccountReceiptSHA256: Hash("model-account")}
}

func streamInstallCoreResponse(status int, raw []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw))}
}

func streamInstallCoreState(t *testing.T, s *Store, j Job) string {
	t.Helper()
	var state string
	if err := s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", j.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestLoadBalanceStreamCoreContractModelDispatchesOneDedicatedPOSTNotNativeAcceptance(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			s, _, j := streamInstallCoreFixtureJob(t, action)
			calls := []string{}
			e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				in, err := DecodeLoadBalanceStreamInstallSubmission(raw)
				if err != nil || in.JobID != j.ID {
					t.Fatal("dedicated canonical original handoff lost", err)
				}
				out, _ := json.Marshal(streamInstallCoreModelResult(j))
				return streamInstallCoreResponse(200, append(out, '\n')), nil
			})}}
			runLoadBalanceStreamInstallJobWithMetadata(context.Background(), s, e, j, streamInstallCoreModelMetadata)
			if len(calls) != 1 || calls[0] != "POST /v1/load-balance-stream/install-jobs" || streamInstallCoreState(t, s, j) != "succeeded" {
				t.Fatal("one original dedicated dispatch contract failed", calls)
			}
		})
	}
}

func TestLoadBalanceStreamCoreContractModelNeverRetriesOrAcceptsPartialResult(t *testing.T) {
	for _, fault := range []string{"lost-reply", "http-error", "wrong-job", "wrong-version", "running", "unknown", "not-found", "healthy-shell", "missing-seed", "zero-digest", "claimed-traffic", "unknown-field", "duplicate-field", "alias-field", "trailing-object"} {
		t.Run(fault, func(t *testing.T) {
			s, _, j := streamInstallCoreFixtureJob(t, "update")
			calls := 0
			e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Path != "/v1/load-balance-stream/install-jobs" {
					t.Fatal("native request fell through to old route or observation replay")
				}
				if fault == "lost-reply" {
					return nil, errors.New("model lost original response")
				}
				v := streamInstallCoreModelResult(j)
				status := 200
				switch fault {
				case "http-error":
					status = 409
				case "wrong-job":
					v.JobID = ID()
				case "wrong-version":
					v.Version = "1.8.5"
				case "running", "unknown", "not-found":
					v = LoadBalanceStreamInstallResult{Format: 1, JobID: j.ID, Version: loadbalancestream.AppVersion, State: fault}
				case "healthy-shell":
					v.State = "healthy"
				case "missing-seed":
					v.SeedSHA256 = ""
				case "zero-digest":
					v.FinalEventSHA256 = strings.Repeat("0", 64)
				case "claimed-traffic":
					v.RuntimeProvisioned = true
				}
				raw, _ := json.Marshal(v)
				switch fault {
				case "unknown-field":
					raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"verified":true`), 1)
				case "duplicate-field":
					raw = bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1)
				case "alias-field":
					raw = bytes.Replace(raw, []byte(`"format"`), []byte(`"Format"`), 1)
				case "trailing-object":
					raw = append(raw, []byte(`{}`)...)
				}
				return streamInstallCoreResponse(status, raw), nil
			})}}
			runLoadBalanceStreamInstallJobWithMetadata(context.Background(), s, e, j, streamInstallCoreModelMetadata)
			if calls != 1 || streamInstallCoreState(t, s, j) != "needs_attention" {
				t.Fatal("partial/unknown original became success or was retried", calls)
			}
			var payload string
			if s.DB.QueryRow("SELECT payload FROM runtime_jobs WHERE id=?", j.ID).Scan(&payload) != nil || payload != j.Payload {
				t.Fatal("unknown result changed immutable original input")
			}
		})
	}
}

func TestLoadBalanceStreamCoreMetadataDriftNeverReachesExecutor(t *testing.T) {
	for _, fault := range []string{"metadata-error", "revoked-role", "changed-grant", "changed-payload", "missing-grant"} {
		t.Run(fault, func(t *testing.T) {
			s, u, j := streamInstallCoreFixtureJob(t, "install")
			calls := 0
			e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("must not be called") })}}
			fetch := func(ctx context.Context, v, h string) (appcatalog.LoadBalanceStreamReleaseEnvelope, error) {
				if fault == "metadata-error" {
					return appcatalog.LoadBalanceStreamReleaseEnvelope{}, errors.New("model metadata unavailable")
				}
				var err error
				switch fault {
				case "revoked-role":
					_, err = s.DB.Exec("UPDATE app_user_roles SET role='viewer'WHERE user_id=?", u.ID)
				case "changed-grant":
					_, err = s.DB.Exec("UPDATE load_balance_stream_install_requests SET access_revision=access_revision+1 WHERE job_id=?", j.ID)
				case "changed-payload":
					_, err = s.DB.Exec("UPDATE runtime_jobs SET payload='{}'WHERE id=?", j.ID)
				case "missing-grant":
					_, err = s.DB.Exec("DELETE FROM load_balance_stream_install_requests WHERE job_id=?", j.ID)
				}
				if err != nil {
					t.Fatal(err)
				}
				return streamInstallCoreModelMetadata(ctx, v, h)
			}
			runLoadBalanceStreamInstallJobWithMetadata(context.Background(), s, e, j, fetch)
			if calls != 0 {
				t.Fatal("metadata or original authority drift reached Root")
			}
			if fault == "metadata-error" && streamInstallCoreState(t, s, j) != "failed" {
				t.Fatal("pre-dispatch failure was marked installed")
			}
		})
	}
}

func TestLoadBalanceStreamCoreObserverOnlyReadsOriginalAndPreservesTerminalEvidence(t *testing.T) {
	for _, state := range []string{"running", "committed", "unknown", "not-found", "retained-failed", "retained-cancelled", "retained-needs_attention", "lost-history"} {
		t.Run(state, func(t *testing.T) {
			s, _, j := streamInstallCoreFixtureJob(t, "update")
			calls := []string{}
			if strings.HasPrefix(state, "retained-") {
				if _, err := s.DB.Exec("UPDATE runtime_jobs SET state=?,error='retained original result'WHERE id=?", strings.TrimPrefix(state, "retained-"), j.ID); err != nil {
					t.Fatal(err)
				}
			}
			if state == "lost-history" {
				if _, err := s.DB.Exec("DELETE FROM load_balance_stream_install_requests WHERE job_id=?", j.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := streamInstallSnapshot(t, s)
			e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.Method != "GET" || r.URL.Path != "/v1/load-balance-stream/install-jobs/"+j.ID {
					t.Fatal("restart observer dispatched an original operation")
				}
				v := streamInstallCoreModelResult(j)
				if state != "committed" {
					v = LoadBalanceStreamInstallResult{Format: 1, JobID: j.ID, Version: loadbalancestream.AppVersion, State: state}
				}
				raw, _ := json.Marshal(v)
				return streamInstallCoreResponse(200, raw), nil
			})}}
			keep, err := observeLoadBalanceStreamOriginalInstall(context.Background(), s, e, j)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasPrefix(state, "retained-"):
				if keep || len(calls) != 0 || streamInstallSnapshot(t, s) != before {
					t.Fatal("original terminal evidence was observed into new success or changed")
				}
			case state == "running":
				if !keep || len(calls) != 1 || streamInstallSnapshot(t, s) != before {
					t.Fatal("read-only ongoing observation changed or reissued original")
				}
			case state == "committed":
				if keep || len(calls) != 1 || streamInstallCoreState(t, s, j) != "succeeded" {
					t.Fatal("original completed model not accepted as bookkeeping")
				}
			case state == "lost-history":
				if keep || len(calls) != 0 || streamInstallCoreState(t, s, j) != "needs_attention" {
					t.Fatal("lost original grant/history adopted")
				}
			default:
				if keep || len(calls) != 1 || streamInstallCoreState(t, s, j) != "needs_attention" {
					t.Fatal("unverifiable original was restarted or marked installed")
				}
			}
		})
	}
}

func TestLoadBalanceStreamCoreLateOriginalSuccessNeverOverwritesCancellation(t *testing.T) {
	s, _, j := streamInstallCoreFixtureJob(t, "update")
	e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(*http.Request) (*http.Response, error) {
		if _, err := s.DB.Exec("UPDATE runtime_jobs SET state='cancelled',error='retained cancellation'WHERE id=?", j.ID); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(streamInstallCoreModelResult(j))
		return streamInstallCoreResponse(200, raw), nil
	})}}
	runLoadBalanceStreamInstallJobWithMetadata(context.Background(), s, e, j, streamInstallCoreModelMetadata)
	var detail string
	if s.DB.QueryRow("SELECT error FROM runtime_jobs WHERE id=?", j.ID).Scan(&detail) != nil || detail != "retained cancellation" || streamInstallCoreState(t, s, j) != "cancelled" {
		t.Fatal("late native model replaced explicit cancellation")
	}
}

func TestLoadBalanceStreamCoreStartupSnapshotNeverCapturesFreshQueuedDispatch(t *testing.T) {
	s, _, j := streamInstallCoreFixtureJob(t, "update")
	if _, err := s.DB.Exec("UPDATE runtime_jobs SET state='queued'WHERE id=?", j.ID); err != nil {
		t.Fatal(err)
	}
	calls := 0
	e := &ExecutorClient{Client: &http.Client{Transport: streamInstallCoreRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("queued original must not be observed or reissued")
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startLoadBalanceStreamInstallObserver(ctx, s, e)
	if calls != 0 || streamInstallCoreState(t, s, j) != "queued" {
		t.Fatal("startup observer raced a fresh unclaimed dispatch")
	}
}
