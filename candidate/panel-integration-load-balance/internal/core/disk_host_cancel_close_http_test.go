package core

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"local/panel/internal/diskjob"
)

// This covers the real HTTP cancellation boundary and the independently bound
// Root closure protocol. It never starts a host worker or changes a real job.
func TestHostDiskHTTPConfirmedUnstartedCancelUsesBoundClosure(t *testing.T) {
	for _, kind := range []string{"closed", "still-busy", "cancel-lost", "cancel-wrong-binding", "closure-lost", "closure-unsafe", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			owner := accessUser(t, s, "cancel-bound-owner", "admin", nil)
			j, _, err := s.QueueHostDisk(t.Context(), hostSelectionFixture(), ID(), owner.ID)
			if err != nil {
				t.Fatal(err)
			}
			j, _, err = s.HostDiskDispatchBoundary(t.Context(), j.ID, owner.ID)
			if err != nil {
				t.Fatal(err)
			}
			a, request, login := diskHostHTTPServer(t, s)
			calls := map[string]int{}
			a.Executor = &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls[r.URL.Path]++
				if r.Method != "POST" {
					t.Fatal("non-original native method")
				}
				var reply any
				switch r.URL.Path {
				case "/v1/disk-host-jobs/cancel":
					var in diskjob.Request
					if json.NewDecoder(r.Body).Decode(&in) != nil || in != j.Request {
						t.Fatal("original cancel request changed")
					}
					if kind == "cancel-lost" {
						return nil, errors.New("original cancel reply lost")
					}
					ack := diskjob.CancelAck{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request)}
					if kind == "cancel-wrong-binding" {
						ack.RequestSHA = strings.Repeat("f", 64)
					}
					if kind == "revoked" {
						if _, err := s.DB.Exec("INSERT INTO app_user_menus VALUES(?,'[]',2)", owner.ID); err != nil {
							t.Fatal(err)
						}
					}
					reply = ack
				case "/v1/disk-host-jobs/recover":
					var in diskjob.RecoveryRequest
					if json.NewDecoder(r.Body).Decode(&in) != nil || in.Request != j.Request || in.Operator.ActorID != owner.ID || in.Operator.AccessRevision != "1" {
						t.Fatal("closure adopted another actor, revision or original request")
					}
					if kind == "closure-lost" {
						return nil, errors.New("original closure reply lost")
					}
					closure := diskjob.Closure{Format: 1, JobID: j.ID, RequestSHA: diskjob.RequestSHA(j.Request), OwnerID: owner.ID, Kind: "admission_closed", State: "canceled", At: time.Now().UTC().Format(time.RFC3339Nano), ScopeEmpty: true, AdmissionSealed: true}
					ack := diskjob.RecoveryAck{Format: 1, JobID: j.ID, RequestSHA: closure.RequestSHA, State: closure.State, Closure: &closure}
					if kind == "still-busy" {
						ack.State, ack.Closure, ack.SignalRequested = "cancel_requested", nil, true
					}
					if kind == "closure-unsafe" {
						ack.Closure.ScopeEmpty = false
					}
					reply = ack
				default:
					t.Fatal("cancel launched or replayed another native action", r.URL.Path)
				}
				raw, _ := json.Marshal(reply)
				return &http.Response{StatusCode: 202, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			cookie, csrf := login(owner.Username)
			w := request("POST", "/api/software/disk-analysis/host/jobs/"+j.ID+"/cancel", `{"actor_id":"untrusted","state":"complete"}`, cookie, csrf)
			wantRecover := 1
			if kind == "cancel-lost" || kind == "cancel-wrong-binding" || kind == "revoked" {
				wantRecover = 0
			}
			if calls["/v1/disk-host-jobs/cancel"] != 1 || calls["/v1/disk-host-jobs/recover"] != wantRecover || len(calls) != 1+wantRecover {
				t.Fatal("original cancel or closure was replayed or inferred from an unconfirmed reply", calls)
			}
			if kind == "revoked" {
				if w.Code != 403 {
					t.Fatal("revoked original owner acquired closure authority", w.Code)
				}
			} else if w.Code != 202 {
				t.Fatal("cancel HTTP boundary", w.Code, w.Body.String())
			}
			var state string
			var closures, results, jobs int
			s.DB.QueryRow("SELECT state FROM disk_host_jobs WHERE id=?", j.ID).Scan(&state)
			s.DB.QueryRow("SELECT count(*) FROM disk_host_job_closures WHERE job_id=?", j.ID).Scan(&closures)
			s.DB.QueryRow("SELECT count(*) FROM disk_host_job_results WHERE job_id=?", j.ID).Scan(&results)
			s.DB.QueryRow("SELECT count(*) FROM disk_host_jobs").Scan(&jobs)
			if results != 0 || jobs != 1 {
				t.Fatal("cancel fabricated a scan result or another original task", results, jobs)
			}
			if kind == "closed" {
				if state != "canceled" || closures != 1 || !strings.Contains(w.Body.String(), `"terminal_verified":true`) {
					t.Fatal("confirmed empty admission remained active", state, closures, w.Body.String())
				}
				c, found, err := s.HostDiskClosureForActor(t.Context(), j.ID, owner.ID)
				if err != nil || !found || c.Kind != "admission_closed" || c.Started != nil || c.ResultSHA != "" {
					t.Fatal("canceled admission became an invented worker/report", found, err)
				}
			} else if state != "cancel_requested" || closures != 0 || strings.Contains(w.Body.String(), `"terminal_verified":true`) {
				t.Fatal("signal, uncertainty or unsafe closure became terminal", state, closures, w.Body.String())
			}
			if kind != "closed" && kind != "still-busy" && kind != "revoked" && !strings.Contains(w.Body.String(), `"cancel_uncertain":true`) {
				t.Fatal("lost or invalid original reply became certain", w.Body.String())
			}
		})
	}
}
