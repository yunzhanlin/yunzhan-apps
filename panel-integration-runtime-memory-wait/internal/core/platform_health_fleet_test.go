package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fleetTestResult struct {
	rows []map[string]any
	err  error
}

func fleetTestHosts() []platformHealthHost {
	hosts := make([]platformHealthHost, 12)
	for i := range hosts {
		hosts[i] = platformHealthHost{id: fmt.Sprintf("host%02d", i), url: fmt.Sprintf("https://owned-%02d.invalid", i), token: []byte("encrypted-only-fixture"), created: "2026-10-15T00:00:00Z"}
	}
	return hosts
}

func fleetPeak(peak *atomic.Int64, value int64) {
	for old := peak.Load(); value > old; old = peak.Load() {
		if peak.CompareAndSwap(old, value) {
			return
		}
	}
}

func TestPlatformHealthFleetBoundedOverlapAndStableCompleteOrder(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hosts := fleetTestHosts()
	started := make(chan int, 12)
	releases := make([]chan struct{}, 12)
	for i := range releases {
		releases[i] = make(chan struct{})
	}
	var active, peak, calls atomic.Int64
	var mu sync.Mutex
	completed := []int{}
	done := make(chan fleetTestResult, 1)
	go func() {
		rows, err := readPlatformHealthFleet(ctx, hosts, func(ctx context.Context, h platformHealthHost) map[string]any {
			i, err := strconv.Atoi(strings.TrimPrefix(h.id, "host"))
			if err != nil {
				return nil
			}
			calls.Add(1)
			fleetPeak(&peak, active.Add(1))
			defer active.Add(-1)
			started <- i
			select {
			case <-releases[i]:
			case <-ctx.Done():
				return nil
			}
			mu.Lock()
			completed = append(completed, i)
			mu.Unlock()
			return map[string]any{"id": h.id, "url": h.url, "healthy": i%4 != 0, "telemetry_complete": false}
		})
		done <- fleetTestResult{rows, err}
	}()
	receive := func() int {
		t.Helper()
		select {
		case i := <-started:
			return i
		case <-ctx.Done():
			t.Fatal("three bounded readers did not overlap")
			return -1
		}
	}
	initial := map[int]bool{}
	for range 3 {
		initial[receive()] = true
	}
	if !reflect.DeepEqual(initial, map[int]bool{0: true, 1: true, 2: true}) || peak.Load() != 3 || active.Load() != 3 || calls.Load() != 3 {
		t.Fatal("initial read concurrency is not exactly three", initial, peak.Load(), calls.Load())
	}
	// Keep the first two requests blocked while the third reader completes
	// every later host. Completion order must not replace inventory order.
	for i := 2; i < 12; i++ {
		close(releases[i])
		if i < 11 && receive() != i+1 {
			t.Fatal("bounded queue skipped or repeated a registered host")
		}
	}
	close(releases[1])
	close(releases[0])
	select {
	case result := <-done:
		if result.err != nil || len(result.rows) != 12 || peak.Load() != 3 || active.Load() != 0 || calls.Load() != 12 {
			t.Fatal("incomplete bounded fleet", result.err, peak.Load(), active.Load(), calls.Load())
		}
		for i, h := range hosts {
			if result.rows[i]["id"] != h.id || result.rows[i]["url"] != h.url || result.rows[i]["healthy"] != (i%4 != 0) || result.rows[i]["telemetry_complete"] != false || len(result.rows[i]) != 4 {
				t.Fatal("reordered, omitted, invented or leaked host result", i)
			}
		}
		if completed[0] != 2 {
			t.Fatal("test did not exercise out-of-order completion")
		}
	case <-ctx.Done():
		t.Fatal("bounded readers were not joined")
	}
}

func TestPlatformHealthFleetCancellationJoinsReadersAndDoesNotStartQueuedHosts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 12)
	var active, calls atomic.Int64
	done := make(chan fleetTestResult, 1)
	go func() {
		rows, err := readPlatformHealthFleet(ctx, fleetTestHosts(), func(ctx context.Context, _ platformHealthHost) map[string]any {
			calls.Add(1)
			active.Add(1)
			defer active.Add(-1)
			started <- struct{}{}
			<-ctx.Done()
			return map[string]any{"healthy": false}
		})
		done <- fleetTestResult{rows, err}
	}()
	for range 3 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("bounded readers did not enter")
		}
	}
	cancel()
	select {
	case result := <-done:
		if result.rows != nil || !errors.Is(result.err, context.Canceled) || active.Load() != 0 || calls.Load() != 3 {
			t.Fatal("canceled fleet leaked a partial inventory or started queued hosts", result.err, active.Load(), calls.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not join in-flight readers")
	}
}

func TestPlatformHealthFleetAdmissionEmptyAndUnavailableReader(t *testing.T) {
	var calls atomic.Int64
	read := func(context.Context, platformHealthHost) map[string]any {
		calls.Add(1)
		return map[string]any{"healthy": false}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := readPlatformHealthFleet(canceled, fleetTestHosts(), read); rows != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled fleet accepted", rows, err)
	}
	oversized := append(fleetTestHosts(), platformHealthHost{id: "extra"})
	if rows, err := readPlatformHealthFleet(context.Background(), oversized, read); rows != nil || err == nil {
		t.Fatal("capacity was relaxed or partial hosts scanned")
	}
	if rows, err := readPlatformHealthFleet(context.Background(), nil, nil); rows != nil || err == nil {
		t.Fatal("unavailable reader accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("rejected fleet issued reads")
	}
	rows, err := readPlatformHealthFleet(context.Background(), nil, read)
	if err != nil || rows == nil || len(rows) != 0 || calls.Load() != 0 {
		t.Fatal("empty inventory became null or issued requests")
	}
	raw, _ := json.Marshal(rows)
	if string(raw) != "[]" {
		t.Fatal("empty inventory contract changed")
	}
	if rows, err := readPlatformHealthFleet(context.Background(), fleetTestHosts(), func(context.Context, platformHealthHost) map[string]any { return nil }); rows != nil || err == nil {
		t.Fatal("missing per-host status became a complete report")
	}
}

func TestPlatformHealthFleetUsesActualHTTPSProtocolWithoutInventingCompleteTelemetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	started := make(chan struct{}, 12)
	release := make(chan struct{})
	var active, peak, requests, malformed atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		fleetPeak(&peak, active.Add(1))
		defer active.Add(-1)
		if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/api/platform/agent") || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("1", 64) || r.Header.Get("Accept") != "application/json" {
			malformed.Add(1)
			http.Error(w, "invalid fixture request", http.StatusBadRequest)
			return
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(platformHealthFixture(time.Now()))
	}))
	defer server.Close()
	defer cancel()
	hosts := fleetTestHosts()
	for i := range hosts {
		hosts[i].url = server.URL + "/" + hosts[i].id
	}
	// Test-only TLS trust in this httptest certificate. Production still uses
	// platformHealthClient and the unchanged system roots/no-redirect/5s policy.
	client := server.Client()
	done := make(chan fleetTestResult, 1)
	go func() {
		rows, err := readPlatformHealthFleet(ctx, hosts, func(ctx context.Context, h platformHealthHost) map[string]any {
			return readPlatformHealth(ctx, client, h.id, h.url, strings.Repeat("1", 64))
		})
		done <- fleetTestResult{rows, err}
	}()
	for range 3 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal("actual HTTPS requests did not overlap")
		}
	}
	if active.Load() != 3 || peak.Load() != 3 || requests.Load() != 3 {
		t.Fatal("actual HTTPS concurrency unbounded or serial")
	}
	close(release)
	select {
	case result := <-done:
		if result.err != nil || len(result.rows) != 12 || requests.Load() != 12 || malformed.Load() != 0 || peak.Load() != 3 || active.Load() != 0 {
			t.Fatal("actual HTTPS fleet incomplete", result.err, requests.Load(), peak.Load())
		}
		for i, row := range result.rows {
			if row["id"] != hosts[i].id || row["healthy"] != true || row["telemetry_complete"] != false || row["report"] == nil || row["token"] != nil {
				t.Fatal("protocol-only health became complete telemetry or leaked a token", i)
			}
		}
	case <-ctx.Done():
		t.Fatal("actual HTTPS fleet did not settle")
	}
}

func TestPlatformHealthFleetActualOperationKeepsEveryUndecryptableHostAndOriginalIdentity(t *testing.T) {
	a, actor := platformTransactionFixture(t)
	if _, err := a.Store.DB.Exec(`DELETE FROM app_platform_hosts`); err != nil {
		t.Fatal(err)
	}
	hosts := fleetTestHosts()
	for i := range hosts {
		// Deliberately invalid authenticated ciphertext in this independent
		// SQLite fixture: production must report each unavailable host without
		// trying its .invalid URL, echoing a token or rewriting registration.
		hosts[i].token = []byte{1, 2, 3}
		if _, err := a.Store.DB.Exec(`INSERT INTO app_platform_hosts VALUES(?,?,?,?)`, hosts[i].id, hosts[i].url, hosts[i].token, hosts[i].created); err != nil {
			t.Fatal(err)
		}
	}
	before := platformTables(t, a.Store)
	raw, err := a.platformOperation(context.Background(), actor, "run", AppModuleInput{})
	if err != nil || raw == nil {
		t.Fatal("actual operation omitted unavailable hosts", err)
	}
	out, ok := raw.(map[string]any)
	if !ok {
		t.Fatal("actual operation changed its envelope")
	}
	rows, ok := out["hosts"].([]map[string]any)
	if !ok || len(rows) != len(hosts) {
		t.Fatal("actual operation returned a partial or null inventory")
	}
	for i, h := range hosts {
		row := rows[i]
		if row["id"] != h.id || row["url"] != h.url || row["expected_sha"] != platformHostIdentity(h.id, h.url, h.token, h.created) || row["healthy"] != false || row["telemetry_complete"] != false || row["error"] != "登记令牌无法解密；保留原记录，未发出请求" || len(row) != 6 {
			t.Fatal("actual operation omitted, reordered, reidentified or leaked an unavailable host", i)
		}
	}
	if !bytes.Equal(before, platformTables(t, a.Store)) {
		t.Fatal("readonly fleet changed host ciphertext, tokens, events or audit")
	}
}
