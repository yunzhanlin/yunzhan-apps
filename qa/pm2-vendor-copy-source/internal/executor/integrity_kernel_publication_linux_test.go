//go:build linux

package executor

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/panel/internal/core"
)

// Stop an actual private record writer after exclusive creation and before
// its first write. Both HTTP observers must wait for the existing publisher,
// rather than turn its known in-process publication into a corrupt original.
// This does not forgive an incomplete record left by a stopped process.
func runIntegrityKernelPublicationReader(t *testing.T, application, stage string, admission, completePublication bool) {
	t.Helper()
	s, request, plan, directory := integrityKernelFixture(t, application)
	if err := moduleWrite(filepath.Join(s.moduleDir(application), "installed.json"), map[string]any{"id": application, "version": "1.4.1", "installed_at": core.Now(), "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	var value any
	switch stage {
	case "request":
		request.ID = core.ID()
		request.Input.SiteID = core.ID()
		request.Input.Confirm = "PROTECT SITE " + request.Input.SiteID
		store, err := s.integrityKernelStore(false)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Mkdir(request.ID, 0700); err != nil {
			store.Close()
			t.Fatal(err)
		}
		directory, err = integrityKernelChild(store, request.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		value = request
	case "started":
		value = integrityKernelStarted{Format: 1, ID: request.ID, RequestSHA: core.IntegrityKernelRequestSHA(request), InstalledAt: core.Now(), StartedAt: core.Now()}
	case "plan", "result":
		if err := integrityKernelCreate(directory, "started.json", integrityKernelStarted{Format: 1, ID: request.ID, RequestSHA: core.IntegrityKernelRequestSHA(request), InstalledAt: core.Now(), StartedAt: core.Now()}); err != nil {
			t.Fatal(err)
		}
		if stage == "plan" {
			value = plan
		} else {
			value = core.IntegrityKernelOperation{Request: request, RequestSHA: core.IntegrityKernelRequestSHA(request), Revision: 1, State: "declined", Error: "synthetic original decline before any native mutation", FinishedAt: core.Now()}
		}
	case "closure":
		value = core.IntegrityKernelClosure{Format: 1, ID: core.ID(), Request: request, OriginalRequestSHA: core.IntegrityKernelRequestSHA(request), SealedAt: core.Now()}
	default:
		t.Fatal("unknown publication stage")
	}
	var route core.IntegrityKernelApplicationRoute
	for _, candidate := range core.IntegrityKernelApplicationRoutes() {
		if candidate.Application == application {
			route = candidate
		}
	}
	if route.Application != application {
		t.Fatal("missing exact application route")
	}
	mux := http.NewServeMux()
	path := route.Executor + "?site_id=" + request.Input.SiteID
	if admission {
		s.integrityKernelApplicationAdmissionRoutes(mux, route)
		path = route.Executor + "/admissions/" + request.ID
	} else {
		s.integrityKernelApplicationRoutes(mux, route)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	f, err := directory.OpenFile(stage+".json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	started := make(chan struct{})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		close(started)
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		done <- w
	}()
	<-started
	var early *httptest.ResponseRecorder
	select {
	case early = <-done:
	case <-time.After(100 * time.Millisecond):
	}
	if completePublication {
		if _, err = f.Write(append(raw, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	s.mu.Unlock()
	locked = false
	if early != nil {
		t.Fatalf("reader observed an unpublished private record: HTTP %d %s", early.Code, early.Body.String())
	}
	select {
	case response := <-done:
		expected := http.StatusOK
		if !completePublication {
			expected = http.StatusConflict
		}
		if response.Code != expected {
			t.Fatal("complete original publication was not readable", response.Code, response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not resume after the original publisher completed")
	}
	original, err := integrityKernelRead(directory, stage+".json", integrityKernelRecordBytes)
	if completePublication {
		if err != nil || string(original) != string(append(raw, '\n')) {
			t.Fatal("read-only HTTP observer changed the original record", err)
		}
	} else {
		info, statErr := directory.Lstat(stage + ".json")
		if err == nil || statErr != nil || info.Size() != 0 || !moduleRecordInfo(info, false, false) {
			t.Fatal("stopped incomplete original was ignored, deleted or normalized", err, statErr)
		}
	}
}

func TestIntegrityKernelConcurrentStatusWaitsForCompletePublication(t *testing.T) {
	for _, application := range []string{core.IntegrityKernelWebsiteApplication, core.IntegrityKernelEnterpriseApplication} {
		for _, stage := range []string{"request", "started", "plan", "result", "closure"} {
			t.Run(application+"/"+stage, func(t *testing.T) { runIntegrityKernelPublicationReader(t, application, stage, false, true) })
		}
	}
}

func TestIntegrityKernelConcurrentAdmissionWaitsForCompletePublication(t *testing.T) {
	for _, application := range []string{core.IntegrityKernelWebsiteApplication, core.IntegrityKernelEnterpriseApplication} {
		for _, stage := range []string{"request", "started", "result", "closure"} {
			t.Run(application+"/"+stage, func(t *testing.T) { runIntegrityKernelPublicationReader(t, application, stage, true, true) })
		}
	}
}

func TestIntegrityKernelStoppedIncompletePublicationStaysUnknown(t *testing.T) {
	for _, application := range []string{core.IntegrityKernelWebsiteApplication, core.IntegrityKernelEnterpriseApplication} {
		for _, stage := range []string{"request", "started", "plan", "result", "closure"} {
			t.Run(application+"/"+stage, func(t *testing.T) { runIntegrityKernelPublicationReader(t, application, stage, false, false) })
		}
	}
}
