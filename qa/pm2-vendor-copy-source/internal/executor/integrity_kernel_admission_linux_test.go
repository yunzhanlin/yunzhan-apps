//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"local/panel/internal/core"
)

func TestIntegrityKernelSealQueuedAdmissionPreservesOriginalAndStopsDispatch(t *testing.T) {
	s, request, _, d := integrityKernelFixture(t)
	before, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil {
		t.Fatal(err)
	}
	closeRequest := core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request}
	closeRequest.Request.AccessRevision++ // Current authority is distinct; original request remains unchanged.
	s.mu.Lock()
	out, err := s.integrityKernelSealAdmission(closeRequest)
	s.mu.Unlock()
	if err != nil || !core.ValidIntegrityKernelAdmission(out) || out.State != "sealed" || out.Operation == nil || out.Operation.State != "cancelled" || out.Closure.OriginalRequestSHA != core.IntegrityKernelRequestSHA(request) {
		t.Fatal(out, err)
	}
	after, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil || string(after) != string(before) {
		t.Fatal("original queued request was replaced", err)
	}
	s.integrityKernelExecute(context.Background(), request)
	for _, name := range []string{"started.json", "plan.json", "progress.jsonl", "result.json"} {
		if _, err = d.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("sealed task dispatched or invented a native outcome", name, err)
		}
	}
	if err = s.integrityKernelReference(request.Input.SiteID); err != nil {
		t.Fatal("cancelled, never-dispatched enable stranded the site", err)
	}
	observed, err := s.integrityKernelAdmission(request.ID)
	if err != nil || !reflect.DeepEqual(observed, out) {
		t.Fatal("original closure changed", observed, err)
	}
	late, err := s.integrityKernelSubmit(context.Background(), request)
	if err != nil || late.State != "cancelled" || late.Request != request {
		t.Fatal("late original request did not retain cancellation", late, err)
	}
	if fixtureRead(t, s, request.Input.SiteID, "data.txt") != "original website bytes" {
		t.Fatal("admission closure changed user bytes")
	}
}

func TestIntegrityKernelSealUnreceivedAdmissionCreatesNoFakeRevision(t *testing.T) {
	s, request, _, d := integrityKernelFixture(t)
	original := filepath.Join(d.paths[len(d.paths)-1], "request.json")
	retained := filepath.Join(t.TempDir(), "original-unreceived-request-fixture.json")
	if err := os.Rename(original, retained); err != nil {
		t.Fatal(err)
	} // Empty pre-request crash, not an original mutation.
	closeRequest := core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request}
	s.mu.Lock()
	out, err := s.integrityKernelSealAdmission(closeRequest)
	s.mu.Unlock()
	if err != nil || out.State != "sealed" || out.Operation != nil || out.Closure.OriginalRequestSHA != "" || !core.ValidIntegrityKernelAdmission(out) {
		t.Fatal(out, err)
	}
	rows, err := s.integrityKernelOperations()
	if err != nil || len(rows) != 0 {
		t.Fatal("unreceived closure invented an accepted operation or revision", rows, err)
	}
	if _, err = s.integrityKernelSubmit(context.Background(), request); !errors.Is(err, errIntegrityKernelSealed) {
		t.Fatal("late original submission was not fenced by permanent closure", err)
	}
	if _, err = d.Lstat("request.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closure replay created original request", err)
	}
	if err = s.integrityKernelReference(""); err != nil {
		t.Fatal("proven unreceived closure became an active protection", err)
	}
	first, err := integrityKernelRead(d, "closure.json", 16384)
	if err != nil {
		t.Fatal(err)
	}
	closeRequest.ID = core.ID()
	s.mu.Lock()
	again, err := s.integrityKernelSealAdmission(closeRequest)
	s.mu.Unlock()
	second, readErr := integrityKernelRead(d, "closure.json", 16384)
	if err != nil || readErr != nil || string(first) != string(second) || again.Closure.ID != out.Closure.ID {
		t.Fatal("a retry rewrote original closure", err, readErr)
	}
}

func TestIntegrityKernelClosureCannotRelabelStartedOrUnknownMutation(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-start-without-result", true: "original-needs-attention-result"}[terminal], func(t *testing.T) {
			s, request, plan, d := integrityKernelFixture(t)
			j := integrityKernelFixtureStart(t, d, request, plan)
			if err := j.append(0, "intent", 0); err != nil {
				t.Fatal(err)
			}
			if terminal {
				out := core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), Revision: 1, State: "needs-attention", PlanSHA: integrityKernelDigest(plan), EnableOperation: request.ID, Directories: 1, Files: 1, Error: "Original native result not verified", FinishedAt: core.Now()}
				if err := integrityKernelCreate(d, "result.json", out); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.integrityKernelReadOperation(request.ID)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
			if err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			out, err := s.integrityKernelSealAdmission(core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request})
			s.mu.Unlock()
			if err != nil || out.State != "original" || out.Operation == nil || !reflect.DeepEqual(*out.Operation, before) {
				t.Fatal("closure relabelled an original native outcome", out, err)
			}
			if _, err = d.Lstat("closure.json"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("started original mutation received a no-dispatch closure", err)
			}
			after, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
			if err != nil || string(after) != string(progress) {
				t.Fatal("original intent journal was changed", err)
			}
		})
	}
}

func TestIntegrityKernelClosureRefusesBorrowedInputAndChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"actor", "site", "action", "joined-name", "corrupt-request", "native-evidence-after-closure"} {
		t.Run(scenario, func(t *testing.T) {
			s, request, _, d := integrityKernelFixture(t)
			closeRequest := core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request}
			switch scenario {
			case "actor":
				closeRequest.Request.ActorID = core.ID()
			case "site":
				closeRequest.Request.Input.SiteID = core.ID()
				closeRequest.Request.Input.Confirm = "PROTECT SITE " + closeRequest.Request.Input.SiteID
			case "action":
				closeRequest.Request.Action = "release"
				closeRequest.Request.Input.BaselineSHA = ""
				closeRequest.Request.Input.SourceOperation = core.ID()
				closeRequest.Request.Input.SourceSHA = request.AppSHA
				closeRequest.Request.Input.Confirm = "RELEASE SITE " + request.Input.SiteID
			case "joined-name":
				if err := d.WriteFile("request.json|started.json", []byte("keep original unknown entry"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-request":
				if err := d.WriteFile("request.json", []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "native-evidence-after-closure":
				s.mu.Lock()
				_, err := s.integrityKernelSealAdmission(closeRequest)
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				if err = integrityKernelCreate(d, "started.json", map[string]string{"unknown": "preserve"}); err != nil {
					t.Fatal(err)
				}
			}
			s.mu.Lock()
			_, err := s.integrityKernelSealAdmission(closeRequest)
			s.mu.Unlock()
			if err == nil {
				t.Fatal("closure adopted borrowed or changed evidence", scenario)
			}
			if fixtureRead(t, s, request.Input.SiteID, "data.txt") != "original website bytes" {
				t.Fatal("rejected closure changed original file")
			}
		})
	}
}

func TestIntegrityKernelSealNeverReceivedIDDoesNotInventAcceptedRevision(t *testing.T) {
	s, request, _, _ := integrityKernelFixture(t)
	originalRows, err := s.integrityKernelOperations()
	if err != nil {
		t.Fatal(err)
	}
	request.ID = core.ID()
	s.mu.Lock()
	out, err := s.integrityKernelSealAdmission(core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request})
	s.mu.Unlock()
	if err != nil || out.State != "sealed" || out.Operation != nil || out.Closure.OriginalRequestSHA != "" {
		t.Fatal(out, err)
	}
	after, err := s.integrityKernelOperations()
	if err != nil || !reflect.DeepEqual(after, originalRows) {
		t.Fatal("never-received closure fabricated an accepted revision", after, err)
	}
	if _, err = s.integrityKernelSubmit(context.Background(), request); !errors.Is(err, errIntegrityKernelSealed) {
		t.Fatal("late request crossed sealed absent admission", err)
	}
}
