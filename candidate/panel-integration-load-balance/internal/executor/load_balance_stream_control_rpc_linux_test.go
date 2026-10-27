//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamTrafficRPCUnboundFixtureCannotTouchHostOrDispatch(t *testing.T) {
	s := New(Config{SystemRoot: t.TempDir()})
	m := http.NewServeMux()
	s.loadBalanceStreamControlRoutes(m)
	seed, err := loadbalancestream.DecodeControlSeed(streamJournalNativeSeed(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(seed.Operation)
	recorder := httptest.NewRecorder()
	m.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/load-balance-stream/controls", strings.NewReader(string(raw))))
	if recorder.Code != http.StatusConflict {
		t.Fatal("fixture dispatched a host control", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/load-balance-stream/controls/"+seed.Operation.RequestID, nil))
	if recorder.Code != http.StatusConflict {
		t.Fatal("fixture inferred host completion", recorder.Code)
	}
	if c, err := prepareLoadBalanceStreamTrafficController(context.Background(), s, seed.Operation); err == nil || c != nil {
		t.Fatal("unbound layout selected host state")
	}
	recorder = httptest.NewRecorder()
	m.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/load-balance-stream/controls", strings.NewReader("{}")))
	if recorder.Code != http.StatusBadRequest {
		t.Fatal("malformed browser fields accepted")
	}
}

func TestLoadBalanceStreamTrafficCreatorMissingOriginalCannotPublishOrSeal(t *testing.T) {
	for _, c := range []*loadBalanceStreamTrafficController{nil, {}, {owner: &loadBalanceStreamControlOwner{}}, {journal: &loadBalanceStreamJournal{}}} {
		if c.completedCreatorCurrent(context.Background()) == nil {
			t.Fatal("old or missing creator became metadata publication authority")
		}
		if raw, err := c.publishGeneration(context.Background()); err == nil || raw != nil {
			t.Fatal("missing original selected generation publication")
		}
		if _, err := c.execute(context.Background()); err == nil {
			t.Fatal("missing original selected any native effect")
		}
		c.close()
	}
	for _, live := range []*loadBalanceStreamLiveControl{nil, {}, {controller: &loadBalanceStreamTrafficController{}}, {ctx: context.Background()}} {
		if live.live() {
			t.Fatal("claimed task handle became live")
		}
	}
}

func TestLoadBalanceStreamNativeHTTPVersionNeverTrustsOnlyCopiedVersionOrInstallationID(t *testing.T) {
	s, _, _, _ := lbHistoryFixture(t)
	lbRoutingInstalled(t, s, "1.9.0")
	if s.loadBalanceHealthVersion() != "" {
		t.Fatal("version-only native claim expanded legacy HTTP/archive authority")
	}
	path := filepath.Join(s.moduleDir("load-balance"), "installed.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("fixture invalid")
	}
	record["installation_id"] = strings.Repeat("a", 32)
	raw, _ = json.Marshal(record)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("fixture write failed")
	}
	if s.loadBalanceHealthVersion() != "" {
		t.Fatal("copied installation identifier adopted a native installation")
	}
}
