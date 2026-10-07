package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Interactive actual-browser harness with its own temporary database. It does
// not connect to the host executor, alter installed apps, or touch real sites.
func TestAnalyticsLiveINPBrowserQA(t *testing.T) {
	if os.Getenv("PANEL_INP_BROWSER_QA") != "1" {
		t.Skip("explicit isolated browser harness required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("isolated QA host required")
	}
	s := testStore(t)
	if _, err = s.CreateSiteAtDomain("Own INP browser fixture", "inp-browser-qa", "analytics-inp.localhost", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := s.Sites()
	if err != nil || len(sites) != 1 {
		t.Fatal(sites, err)
	}
	a, err := NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: "http://analytics-inp.localhost:19223", Listen: "127.0.0.1:19103", Socket: "/missing-qa-only.sock"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: sites[0].ID, Enabled: true, Retention: 1})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:19103")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finish := make(chan struct{}, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /qa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>云栈 INP 实际浏览器验收</title><style>body{max-width:850px;margin:60px auto;padding:24px;font:18px system-ui;color:#203047}button{padding:18px;border:0;border-radius:8px;background:#0aab66;color:white;font-size:18px}pre{white-space:pre-wrap;padding:20px;background:#f1f5f9}textarea{display:block;margin:25px 0;width:90%%}</style><h1>INP 实际浏览器验收</h1><p>独立 QA 数据库与回环服务；不修改主面板或网站。</p><button id="interaction">执行一次 250 ms 测试交互</button><textarea data-analytics-ignore>never-collected-private-text</textarea><p>只发送性能数值，不发送输入内容、DOM 或事件目标。</p><pre id="result">等待真实交互性能样本</pre><script defer src="/collect/analytics/tracker.js?site=%s&amp;key=%s"></script><script>document.querySelector('#interaction').addEventListener('click',()=>{const end=performance.now()+250;while(performance.now()<end){};document.querySelector('#interaction').textContent='交互已执行，等待 PerformanceObserver';});setInterval(async()=>{try{const r=await fetch('/qa/result');document.querySelector('#result').textContent=JSON.stringify(await r.json(),null,2);}catch{}},1000);</script></html>`, cfg.SiteID, cfg.Key)
	})
	result := func() (map[string]any, error) {
		report, err := s.analyticsReport(context.Background(), cfg.SiteID, "", "", time.Now())
		if err != nil {
			return nil, err
		}
		metric := report["performance"].(map[string]any)["inp"].(map[string]any)
		var leaked int
		if err = s.DB.QueryRow(`SELECT count(*) FROM analytics_events WHERE data LIKE '%never-collected-private-text%' OR data LIKE '%interactionId%' OR data LIKE '%navigationURL%' OR data LIKE '%target%'`).Scan(&leaked); err != nil {
			return nil, err
		}
		passed := metric["samples"].(int) > 0 && metric["p75"] != nil && metric["p75"].(float64) >= 40 && leaked == 0
		return map[string]any{"passed": passed, "inp": metric, "sampled_events": report["sampled_events"], "source": "actual browser -> same-origin collector -> independent SQLite report", "private_content_or_target_leaks": leaked, "main_panel_changed": false}, nil
	}
	mux.HandleFunc("GET /qa/result", func(w http.ResponseWriter, r *http.Request) {
		out, err := result()
		if err != nil {
			http.Error(w, "QA report failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /qa/finish", func(w http.ResponseWriter, r *http.Request) {
		out, err := result()
		if err != nil || out["passed"] != true {
			http.Error(w, "actual INP proof not yet valid", 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		select {
		case finish <- struct{}{}:
		default:
		}
	})
	mux.Handle("/", a)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	defer server.Close()
	go server.Serve(listener)
	t.Log("isolated real browser harness listening on loopback 19103; no host executor or real-site writes")
	select {
	case <-finish:
	case <-time.After(10 * time.Minute):
		t.Fatal("actual browser QA timeout")
	}
	out, err := result()
	if err != nil || out["passed"] != true {
		t.Fatal(out, err)
	}
	data, _ := json.Marshal(out)
	t.Log(string(data))
}
