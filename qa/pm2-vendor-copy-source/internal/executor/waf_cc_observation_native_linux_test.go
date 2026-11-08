//go:build linux

package executor

import (
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"strings"
	"testing"
	"time"
)

func TestWAFRealNginxCCObservationCountsWithoutBlockingOtherSites(t *testing.T) {
	for _, scope := range []string{"per-ip", "url"} {
		t.Run(scope, func(t *testing.T) {
			cfg := core.DefaultWAFConfig()
			cfg.Rate, cfg.Policy.Burst = 5, 1
			path := "/observe-rate"
			if scope == "url" {
				cfg.Rate = 200
				cfg.Policy.CCRules = []core.WAFCCRule{{ID: strings.Repeat("c", 32), Path: path, Rate: 1, Burst: 1, Enabled: true}}
			}
			cfg.Policy.Sites = []core.WAFSitePolicy{{SiteID: strings.Repeat("a", 32), Mode: "observe"}}
			fixture := wafTestNginxFixture(t, cfg)
			blocked := 0
			for i := 0; i < 16; i++ {
				if status, _ := fixture.request(t, "a.localhost", path, "", nil); status != 200 {
					t.Fatal("observation blocked request", scope, status)
				}
				if status, _ := fixture.request(t, "b.localhost", path, "", nil); status == 429 {
					blocked++
				} else if status != 200 {
					t.Fatal("unexpected blocking-site response", status)
				}
			}
			if blocked == 0 {
				t.Fatal("neighboring blocking policy silently turned into dry-run")
			}
			// Receiving the final HTTP body is not synchronization with Nginx's
			// subsequent log phase. Wait boundedly for every actual blocked reply
			// to have its corresponding event, without relaxing event counts.
			deadline := time.Now().Add(2 * time.Second)
			var data []byte
			for {
				var err error
				data, err = os.ReadFile(fixture.logPath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(string(data), `"action":"block"`) >= blocked || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			observed, actualBlocked := 0, 0
			for _, line := range strings.Split(string(data), "\n") {
				if line == "" {
					continue
				}
				var event core.WAFEvent
				if err := json.Unmarshal([]byte(line), &event); err != nil {
					t.Fatal(err, line)
				}
				if event.Site == "a.localhost" {
					if event.Status != 200 || event.Action != "observe" || core.WAFEventReason(event) != "cc" || event.Rate != "REJECTED_DRY_RUN" && event.Rate != "DELAYED_DRY_RUN" {
						t.Fatal("incorrect dry-run event", event)
					}
					observed++
				}
				if event.Site == "b.localhost" && event.Rate == "REJECTED" && event.Action == "block" {
					actualBlocked++
				}
			}
			if observed == 0 || actualBlocked != blocked {
				t.Fatal("actual excess events missing", observed, actualBlocked, blocked)
			}
		})
	}
}
