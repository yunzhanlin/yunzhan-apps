package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// An opt-in source companion on owned QA only. Real wall time and actual
// browser navigation are required. It never touches the installed panel DB,
// host executor, existing websites, sessionStorage or browser clocks itself.
func TestAnalyticsSessionLiveBrowserSourceQA(t *testing.T) {
	if os.Getenv("PANEL_SESSION_BROWSER_QA") != "1" {
		t.Skip("explicit isolated real-time browser source companion required")
	}
	stage := os.Getenv("PANEL_SESSION_BROWSER_QA_STAGE")
	if os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/analytics-session-browser24bgnp\.[a-f0-9]{32}$`).MatchString(stage) {
		t.Fatal("fixed owned QA stage required")
	}
	for parent := stage; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			t.Fatal("unsafe QA parent", parent, err)
		}
		identity, ok := info.Sys().(*syscall.Stat_t)
		if !ok || identity.Uid != 0 {
			t.Fatal("QA parent is not owned by root", parent)
		}
		if parent == "/" {
			break
		}
	}
	info, err := os.Stat(stage)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("private QA stage required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" {
		t.Fatal("owned ARM QA host required")
	}
	database := filepath.Join(stage, "browser-only.db")
	if _, err := os.Lstat(database); !os.IsNotExist(err) {
		t.Fatal("retained browser evidence must never be reopened or overwritten")
	}
	s, err := OpenStore(database)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if _, err = s.CreateSiteAtDomain("Isolated browser session source QA", "session-browser-only", "analytics-session.localhost", "", "admin"); err != nil {
		t.Fatal(err)
	}
	sites, err := s.Sites()
	if err != nil || len(sites) != 1 {
		t.Fatal("private fixture site", err)
	}
	cfg, err := s.saveAnalyticsConfig(context.Background(), AnalyticsConfig{SiteID: sites[0].ID, Enabled: true, Retention: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service-state", "private-web"} {
		if err := os.Mkdir(filepath.Join(stage, name), 0700); err != nil {
			t.Fatal("exclusive private QA child", err)
		}
	}
	a, err := NewServer(s, Config{DataDir: filepath.Join(stage, "service-state"), WebDir: filepath.Join(stage, "private-web"), Origin: "http://analytics-session.localhost:19224", Listen: "127.0.0.1:19104", Socket: "/missing-session-qa-only.sock"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:19104")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var idleAt time.Time
	result := func() (map[string]any, error) {
		mu.Lock()
		when := idleAt
		mu.Unlock()
		rows, err := s.DB.Query(`SELECT data FROM analytics_events WHERE site_id=? ORDER BY received,id LIMIT 1001`, cfg.SiteID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		visits := []map[string]any{}
		var original, returned *AnalyticsEvent
		count := 0
		for rows.Next() {
			count++
			if count > 1000 {
				return nil, fmt.Errorf("complete private QA inventory exceeds bound")
			}
			var raw string
			var event AnalyticsEvent
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			if err := json.Unmarshal([]byte(raw), &event); err != nil {
				return nil, err
			}
			if event.Kind == "pageview" {
				visits = append(visits, map[string]any{"path": event.Path, "session_sha256": Hash(event.Session), "page_sha256": Hash(event.PageID), "received_at": event.Received})
				if event.Path == "/qa/start" && original == nil {
					copy := event
					original = &copy
				}
				if event.Path == "/qa/returned" {
					copy := event
					returned = &copy
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		elapsed := float64(0)
		if !when.IsZero() {
			elapsed = time.Since(when).Seconds()
		}
		passed := elapsed >= 1805 && original != nil && returned != nil && original.Visitor == returned.Visitor && original.Session != returned.Session && original.PageID != returned.PageID && returned.Received-original.Received >= 1800
		return map[string]any{"passed": passed, "source_companion_NOT_installed_release": true, "actual_wall_seconds_since_idle": elapsed, "required_seconds": 1805, "pageviews": visits, "sampled_events": count, "browser_clock_or_storage_overridden": false, "installed_panel_or_sites_mutated": false}, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /qa/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>真实会话时钟验收</title><style>body{max-width:900px;margin:48px auto;font:18px system-ui}a{display:inline-block;padding:16px;background:#087e4b;color:white}pre{white-space:pre-wrap}</style><h1>实际浏览器会话验收</h1><p>独立 QA SQLite；不修改真实面板、站点、浏览器时间或存储。先看到真实 pageview，再离开此页至少30分5秒。</p><a href="/qa/idle">开始真实30分钟离开</a><pre id="report">读取真实记录...</pre><script defer src="/collect/analytics/tracker.js?site=%s&amp;key=%s"></script><script>setInterval(async()=>{try{document.querySelector('#report').textContent=JSON.stringify(await(await fetch('/qa/result',{cache:'no-store'})).json(),null,2)}catch{}},1000)</script>`, cfg.SiteID, cfg.Key)
	})
	mux.HandleFunc("GET /qa/idle", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if idleAt.IsZero() {
			idleAt = time.Now()
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>真实会话等待中</title><h1>本页没有采集器</h1><p>保留同一浏览器标签页；真实等待至少30分5秒，不调整任何时钟或存储。</p><a href="/qa/returned">到时间后返回采集页</a><p><a href="/qa/result">只读服务器进度</a></p>`)
	})
	mux.HandleFunc("GET /qa/returned", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		when := idleAt
		mu.Unlock()
		if when.IsZero() || time.Since(when) < 1805*time.Second {
			http.Error(w, "真实等待尚未满30分5秒；未加载采集器", http.StatusTooEarly)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>真实会话返回验收</title><h1>返回后的真实新会话</h1><pre id="report">等待真实 pageview...</pre><script defer src="/collect/analytics/tracker.js?site=%s&amp;key=%s"></script><script>setInterval(async()=>{document.querySelector('#report').textContent=JSON.stringify(await(await fetch('/qa/result',{cache:'no-store'})).json(),null,2)},1000)</script>`, cfg.SiteID, cfg.Key)
	})
	mux.HandleFunc("GET /qa/result", func(w http.ResponseWriter, r *http.Request) {
		value, err := result()
		if err != nil {
			http.Error(w, "private QA inventory failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(value)
	})
	mux.Handle("/", a)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	defer server.Close()
	go server.Serve(listener)
	t.Log("owned source companion ready on loopback19104; real same-tab browser idle test required; no host executor")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(45 * time.Minute)
	defer timeout.Stop()
	var final map[string]any
	for final == nil {
		select {
		case <-ticker.C:
			value, err := result()
			if err != nil {
				t.Fatal(err)
			}
			if value["passed"] == true {
				final = value
			}
		case <-timeout.C:
			final, _ = result()
			if final == nil {
				final = map[string]any{"passed": false, "failure": "real browser source QA timeout"}
			}
		}
	}
	output, err := os.OpenFile(filepath.Join(stage, "result.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.NewEncoder(output).Encode(final); err == nil {
		err = output.Sync()
	}
	closeErr := output.Close()
	if err != nil || closeErr != nil || final["passed"] != true {
		t.Fatal("retained real-time browser source result", err, closeErr, final)
	}
}
