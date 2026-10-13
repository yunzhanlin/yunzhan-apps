package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
)

func TestStatisticsGeoWorkerOriginalIDNoLostReplyRedispatch(t *testing.T) {
	for _, kind := range []string{"succeeded", "lost-reply", "failed", "empty-failure", "success-with-error", "changed-instance", "changed-job", "unknown-state"} {
		t.Run(kind, func(t *testing.T) {
			s := testStore(t)
			in := statisticsGeoSelectionFixture()
			in.Action = "rollback" // No provider or repository network in this fixture.
			id, err := s.QueueStatisticsGeo(in, "original-worker", strings.Repeat("d", 32))
			if err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil || job.ID != id {
				t.Fatal(job, err)
			}
			posts, gets := 0, 0
			e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1/statistics/geodata/jobs/"+id {
					t.Fatal("worker changed original root job ID", r.URL)
				}
				switch r.Method {
				case "POST":
					posts++
					selected, err := ParseStatisticsGeoSelectionQuery(r.URL.Query())
					raw, readErr := io.ReadAll(r.Body)
					if err != nil || readErr != nil || selected != in || string(raw) != "{}" {
						t.Fatal("rollback delivery or original selection changed", string(raw), selected, err, readErr)
					}
					if kind == "lost-reply" {
						return nil, errors.New("owned lost POST response")
					}
				case "GET":
					gets++
					if kind != "lost-reply" || r.URL.RawQuery != "" {
						t.Fatal("unexpected redispatch or changed observation", r.URL)
					}
				default:
					t.Fatal("unexpected worker mutation", r.Method)
				}
				out := StatisticsGeoOperation{JobID: id, Selection: in, State: "succeeded", Steps: []Step{}}
				switch kind {
				case "failed":
					out.State, out.Error = "failed", "owned retained failure"
				case "empty-failure":
					out.State = "failed"
				case "success-with-error":
					out.Error = "unresolved failure"
				case "changed-instance":
					out.Selection.InstallationID = strings.Repeat("e", 32)
				case "changed-job":
					out.JobID = ID()
				case "unknown-state":
					out.State = "complete-but-unverified"
				}
				raw, _ := json.Marshal(out)
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
			})}}
			runStatisticsGeoJob(context.Background(), s, e, job, appcatalog.Default())
			var state, detail string
			if err := s.DB.QueryRow("SELECT state,error FROM runtime_jobs WHERE id=?", id).Scan(&state, &detail); err != nil {
				t.Fatal(err)
			}
			want := "needs_attention"
			if kind == "succeeded" || kind == "lost-reply" {
				want = "succeeded"
			} else if kind == "failed" {
				want = "failed"
			}
			if state != want || posts != 1 || gets != 0 && kind != "lost-reply" || kind == "lost-reply" && gets != 1 || want != "succeeded" && detail == "" {
				t.Fatal("unverified result or duplicate root operation accepted", state, want, posts, gets, detail)
			}
		})
	}
}
func TestStatisticsGeoMaintenanceWorkerSendsOnlyEmptyOriginalSelection(t *testing.T) {
	for _, action := range []string{"archive", "restore"} {
		t.Run(action, func(t *testing.T) {
			s := testStore(t)
			in := statisticsGeoSelectionFixture()
			in.Action = action
			id, err := s.QueueStatisticsGeo(in, "maintenance-original-"+action, strings.Repeat("d", 32))
			if err != nil {
				t.Fatal(err)
			}
			job, err := s.nextRuntimeInstallJob()
			if err != nil {
				t.Fatal(err)
			}
			posts := 0
			e := &ExecutorClient{Client: &http.Client{Transport: scheduleRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				posts++
				raw, err := io.ReadAll(r.Body)
				selection, parseErr := ParseStatisticsGeoSelectionQuery(r.URL.Query())
				if err != nil || parseErr != nil || r.Method != "POST" || string(raw) != "{}" || selection != in || r.URL.Path != "/v1/statistics/geodata/jobs/"+id {
					t.Fatal("maintenance mixed downloads, arbitrary fields or another identity", r.Method, r.URL, string(raw), err, parseErr)
				}
				out := StatisticsGeoOperation{JobID: id, Selection: in, State: "succeeded", Steps: []Step{}}
				body, _ := json.Marshal(out)
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
			})}}
			runStatisticsGeoJob(context.Background(), s, e, job, appcatalog.Default())
			var state string
			s.DB.QueryRow("SELECT state FROM runtime_jobs WHERE id=?", id).Scan(&state)
			if state != "succeeded" || posts != 1 {
				t.Fatal(state, posts)
			}
		})
	}
}
