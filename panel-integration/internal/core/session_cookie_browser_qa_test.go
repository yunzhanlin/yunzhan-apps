package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type cookieQAResponse struct {
	http.ResponseWriter
	status int
}

func (w *cookieQAResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *cookieQAResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(data)
}

// Two independent databases on one browser host reproduce real cross-port
// cookie sharing. No host executor, installation state or user accounts change.
func TestSessionCookieLiveBrowserQA(t *testing.T) {
	if os.Getenv("PANEL_COOKIE_BROWSER_QA") != "1" {
		t.Skip("isolated actual browser fixture required")
	}
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || (strings.TrimSpace(string(host)) != "lima-panel-compat-ubuntu24" && strings.TrimSpace(string(host)) != "lima-panel-store-apps-debian13") {
		t.Fatal("isolated QA host required")
	}
	firstPort := 19225
	if strings.HasSuffix(strings.TrimSpace(string(host)), "debian13") {
		firstPort = 19227
	}
	servers := make([]*Server, 2)
	for i := range servers {
		s := testStore(t)
		accessUser(t, s, fmt.Sprintf("cookie-browser-%d", i), "admin", nil)
		servers[i], err = NewServer(s, Config{DataDir: t.TempDir(), WebDir: t.TempDir(), Origin: fmt.Sprintf("http://127.0.0.1:%d", firstPort+i), Listen: fmt.Sprintf("127.0.0.1:%d", 19104+i), Socket: "/missing-cookie-qa-only.sock"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if servers[0].sessionCookieName() == servers[1].sessionCookieName() {
		t.Fatal("not independent cookie namespaces")
	}
	var mu sync.Mutex
	proof := map[string]bool{}
	finish := make(chan struct{}, 1)
	active := func(i int) int {
		var n int
		_ = servers[i].Store.DB.QueryRow(`SELECT count(*) FROM sessions WHERE expires_at>?`, time.Now().Unix()).Scan(&n)
		return n
	}
	for i := range servers {
		i := i
		listener, err := net.Listen("tcp", servers[i].Config.Listen)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		mux := http.NewServeMux()
		mux.HandleFunc("GET /qa", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprintf(w, `<!doctype html><html lang="zh"><meta charset="utf-8"><title>云栈 Cookie 实例隔离验收 %d</title><style>body{max-width:800px;margin:70px auto;font:18px system-ui;color:#203047}button{padding:16px;margin:8px;border:0;border-radius:6px;background:#0aab66;color:white;font-size:18px}pre{padding:20px;background:#f1f5f9;white-space:pre-wrap}</style><h1>独立面板 %d · 会话隔离验收</h1><p>两个临时数据库，共用同一个浏览器主机的不同端口；不读取或修改主面板账户。</p><button id="login">登录此验收实例</button><button id="inspect">核对登录状态</button><button id="logout">退出此验收实例</button><pre id="result">等待真实浏览器操作</pre><script>let csrf='';async function call(path,body){const r=await fetch('/api'+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:body?JSON.stringify(body):undefined});const d=await r.json();if(d.csrf)csrf=d.csrf;document.querySelector('#result').textContent=JSON.stringify({instance:%d,request:path,http_status:r.status,authenticated:r.status===200&&path!=='/logout',main_panel_changed:false},null,2);}document.querySelector('#login').onclick=()=>call('/login',{username:'cookie-browser-%d',password:'access-test-password-long'});document.querySelector('#inspect').onclick=()=>call('/me');document.querySelector('#logout').onclick=()=>call('/logout',{});</script></html>`, i+1, i+1, i+1, i)
		})
		if i == 0 {
			mux.HandleFunc("POST /qa/finish", func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				valid := proof["first_coexists"] && proof["second_coexists"] && proof["first_logged_out"] && proof["second_survives"]
				mu.Unlock()
				if !valid {
					http.Error(w, "actual coexistence/logout proof incomplete", 409)
					return
				}
				_, _ = fmt.Fprintln(w, "PASS actual browser coexistence, isolated logout and no main panel changes")
				select {
				case finish <- struct{}{}:
				default:
				}
			})
		}
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capture := &cookieQAResponse{ResponseWriter: w}
			servers[i].ServeHTTP(capture, r)
			if r.Method == "GET" && r.URL.Path == "/api/me" {
				a, b := active(0), active(1)
				mu.Lock()
				if capture.status == 200 && a == 1 && b == 1 {
					if i == 0 {
						proof["first_coexists"] = true
					} else {
						proof["second_coexists"] = true
					}
				}
				if i == 0 && capture.status == 401 && a == 0 && b == 1 {
					proof["first_logged_out"] = true
				}
				if i == 1 && capture.status == 200 && a == 0 && b == 1 {
					proof["second_survives"] = true
				}
				mu.Unlock()
			}
		}))
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
		defer server.Shutdown(context.Background())
		go server.Serve(listener)
	}
	t.Logf("actual browser only: loopback guests 19104/19105 forwarded to host %d/%d; two temporary accounts/databases", firstPort, firstPort+1)
	select {
	case <-finish:
	case <-time.After(10 * time.Minute):
		t.Fatal("actual cookie browser timeout")
	}
	mu.Lock()
	t.Logf("actual browser proof: %v; credential names differ, values never logged, no main panel or executor writes", proof)
	mu.Unlock()
}
