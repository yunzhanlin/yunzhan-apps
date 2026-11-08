package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit loopback-only source companion. The production collector and SQLite
// report are real; this is not an installed release, Nginx or management UI test.
// No executor, original panel database, browser clock or storage is replaced.
func TestAnalyticsRouteBrowserSourceQA(t *testing.T) {
	stage := os.Getenv("PANEL_ANALYTICS_ROUTE_BROWSER_QA")
	if stage == "" {
		t.Skip("explicit owned loopback browser source companion only")
	}
	info, err := os.Lstat(stage)
	actual, pathErr := filepath.EvalSymlinks(stage)
	if err != nil || pathErr != nil || actual != stage || !info.IsDir() || info.Mode().Perm() != 0700 || !strings.HasPrefix(filepath.Base(stage), "qa-analytics-route-c59-") {
		t.Fatal("exclusive private QA stage required", err, pathErr)
	}
	database := filepath.Join(stage, "source-browser-only.db")
	if _, err := os.Lstat(database); !os.IsNotExist(err) {
		t.Fatal("never reopen original browser evidence")
	}
	s, err := OpenStore(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if _, err := s.CreateSiteAtDomain("SPA route source browser only", "route-browser-only", "qa-analytics-route.localhost", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := s.Sites()
	if err != nil || len(sites) != 1 {
		t.Fatal(sites, err)
	}
	cfg, err := s.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: sites[0].ID, Enabled: true, Retention: 1})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	origin := fmt.Sprintf("http://qa-analytics-route.localhost:%d", port)
	for _, child := range []string{"qa-state", "qa-web"} {
		if err := os.Mkdir(filepath.Join(stage, child), 0700); err != nil {
			t.Fatal("private source-only QA directory", err)
		}
	}
	a, err := NewServer(s, Config{DataDir: filepath.Join(stage, "qa-state"), WebDir: filepath.Join(stage, "qa-web"), Origin: origin, Listen: listener.Addr().String(), Socket: filepath.Join(stage, "missing-executor.sock")})
	if err != nil {
		t.Fatal(err)
	}
	result := func() map[string]any {
		report, err := s.analyticsReport(context.Background(), cfg.SiteID, "", "", time.Now())
		if err != nil {
			return map[string]any{"ok": false, "failure": "source report failed"}
		}
		var leaks, total int
		if err = s.DB.QueryRow(`SELECT count(*),coalesce(sum(CASE WHEN data LIKE '%private-never-collect%' OR data LIKE '%route-ticket-never-send%' THEN 1 ELSE 0 END),0) FROM analytics_events`).Scan(&total, &leaks); err != nil {
			return map[string]any{"ok": false, "failure": "source privacy inventory failed"}
		}
		rows := report["performance_pages"].(analyticsPerformancePages)
		ready, current, document := false, false, false
		for _, row := range rows.Rows {
			if row.Kind == "document" {
				document = row.Path == "/qa/start"
				continue
			}
			metric := row.Metrics["route_ready_ms"]
			value, measured := metric["p75"].(float64)
			if measured && row.Navigations == 1 && metric["samples"] == 1 {
				ready = ready || row.Path == "/route/ready" && value >= 150
				current = current || row.Path == "/route/current" && value >= 90
			}
		}
		counts := report["overview"].(map[string]any)
		ok := ready && current && document && len(rows.Rows) == 3 && leaks == 0 && total < 100 && counts["pv"] == 4 && counts["uv"] == 1 && counts["sessions"] == 1
		return map[string]any{"ok": ok, "source_companion_NOT_installed_release": true, "browser_clocks_and_storage_unmodified": true, "original_panel_sites_or_executor_mutated": false, "report": report, "privacy_leaks": leaks, "stored_events": total}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /qa/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>SPA 实际浏览器源码验收</title><style>body{max-width:880px;margin:32px auto;padding:16px;font:17px system-ui;color:#203047}button,a{display:inline-block;padding:14px;margin:8px 8px 8px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}textarea{display:block;width:90%%}</style><h1>SPA 实际浏览器源码验收</h1><p>独立 SQLite 和回环服务，不是已安装版本或应用管理界面。</p><button id="ready">实际等待路由就绪</button><button id="rapid">快速跳转和旧标识拒绝</button><button id="interaction">实际 220 ms 文档交互</button><textarea data-analytics-ignore>private-never-collect</textarea><p id="state">等待实际点击</p><a href="/qa/summary">离开采集文档并核对原始报告</a><pre id="report"></pre><script defer src="/collect/analytics/tracker.js?site=%s&amp;key=%s"></script><script>
const state=document.querySelector('#state');
const delay=ms=>fetch('/qa/delay?ms='+ms,{cache:'no-store'}).then(r=>{if(!r.ok)throw Error('delay failed')});
document.querySelector('#ready').onclick=async()=>{history.pushState(null,'','/route/ready?token=private-never-collect#private-never-collect');const route=window.yunzhanAnalytics.currentRoute();state.textContent='加载真实路由内容';await delay(180);await new Promise(requestAnimationFrame);state.textContent='网站已就绪';await new Promise(requestAnimationFrame);state.textContent='本次就绪尝试='+window.yunzhanAnalytics.routeReady(route.id)+'，重复='+window.yunzhanAnalytics.routeReady(route.id)};
document.querySelector('#rapid').onclick=async()=>{history.pushState(null,'','/route/stale');const old=window.yunzhanAnalytics.currentRoute();history.pushState(null,'','/route/current');const current=window.yunzhanAnalytics.currentRoute();await delay(110);state.textContent='旧标识='+window.yunzhanAnalytics.routeReady(old.id)+'，当前标识='+window.yunzhanAnalytics.routeReady(current.id)+'，重复='+window.yunzhanAnalytics.routeReady(current.id)};
document.querySelector('#interaction').onclick=()=>{const until=performance.now()+220;while(performance.now()<until){};state.textContent='220 ms 实际交互已完成；性能仍属于原始文档'};
setInterval(async()=>{try{document.querySelector('#report').textContent=JSON.stringify(await(await fetch('/qa/report',{cache:'no-store'})).json(),null,2)}catch{}},1000);
</script></html>`, cfg.SiteID, cfg.Key)
	})
	mux.HandleFunc("GET /qa/delay", func(w http.ResponseWriter, r *http.Request) {
		delay := 180 * time.Millisecond
		if r.URL.Query().Get("ms") == "110" {
			delay = 110 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("GET /qa/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result())
	})
	mux.HandleFunc("GET /qa/summary", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>SPA 原始报告核对</title><h1>离开采集文档后的原始报告</h1><p>本页没有采集器，不生成新访问。</p><pre id="result" style="white-space:pre-wrap;overflow-wrap:anywhere"></pre><script>setInterval(async()=>{document.querySelector('#result').textContent=JSON.stringify(await(await fetch('/qa/report',{cache:'no-store'})).json(),null,2)},700)</script>`)
	})
	mux.Handle("/", a)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	defer server.Close()
	go server.Serve(listener)
	readyFile, err := os.OpenFile(filepath.Join(stage, "ready.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	err = json.NewEncoder(readyFile).Encode(map[string]any{"url": origin + "/qa/start", "report": origin + "/qa/report", "source_only": true})
	closeErr := readyFile.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(8 * time.Minute)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := os.Lstat(filepath.Join(stage, "stop")); os.IsNotExist(err) {
				continue
			}
		case <-timeout.C:
		}
		final := result()
		file, err := os.OpenFile(filepath.Join(stage, "original-result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewEncoder(file).Encode(final)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err != nil || syncErr != nil || closeErr != nil || final["ok"] != true {
			t.Fatal("original browser source result", err, syncErr, closeErr, final)
		}
		return
	}
}
