//go:build linux

package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAnalyticsHTMLNativeModuleAndActualResponses(t *testing.T) {
	if os.Getenv("PANEL_QA_ANALYTICS_NATIVE") != "1" {
		t.Skip("requires isolated root-read-only, private mount/network/cgroup fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("fixture needs root for confined extraction, not compiler commands")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	nginx := "/usr/sbin/nginx"
	output, err := exec.CommandContext(ctx, nginx, "-v").CombinedOutput()
	match := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(string(output)))
	if err != nil || len(match) != 2 {
		t.Fatal("actual binary identity", err)
	}
	version := match[1]
	if version != "1.24.0" && version != "1.26.3" {
		t.Fatal("unexpected private fixture binary", version)
	}
	base, err := os.MkdirTemp("/tmp", "analytics-native-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	// Retain build/log/program files in this exclusively owned private fixture.
	work, prefix := filepath.Join(base, "work"), filepath.Join(base, "program")
	s := New(Config{SitesDir: base, NginxBin: nginx})
	step := func(message string) error { t.Log(message); return nil }
	if err := buildAnalyticsHTMLModule(ctx, s, "/tmp/sources", work, prefix, version, nginx, step); err != nil {
		t.Fatal(err)
	}
	moduleSHA, err := wafNativeFileSHA(ctx, filepath.Join(prefix, "ngx_http_js_module.so"), 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual ABI accepted: nginx=%s module_sha256=%s program_sha256=%s", version, moduleSHA, analyticsHTMLProgramSHA)
	uidUser, err := user.Lookup("panel-build")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(uidUser.Uid)
	gid, _ := strconv.Atoi(uidUser.Gid)
	run := filepath.Join(base, "request-probe")
	if err := os.Mkdir(run, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(run, uid, gid); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	insert := `<script defer src="/__yunzhan/analytics/auto.js?site=` + id + `"></script>`
	valid := []string{
		`<!doctype html><html><head><title>中文😀</title></head><body>original</body></html>`,
		`<head><script>const untouched = "</head>";</script></head><body>original</body>`,
		`<head><!-- </head> --><style>a::after{content:"</head>"}</style></head>`,
		`<HEAD><meta name="literal" content="</head>"><title>value &lt;/head&gt;</title></HeAd >`,
		`<head><template><head></head><div title="</head>"></div></template></head>`,
		"\ufeff<head><title>😎</title></head>",
		`<head><noscript>literal </head></noscript></head>`,
	}
	unmodified := [][]byte{
		[]byte(`<html><body>no explicit head</body></html>`),
		[]byte(`<head><title>implicit close</title><body>no end-tag</body>`),
		[]byte(`<head><script>unterminated "</head>"`),
		[]byte(`<head>` + strings.Repeat(`<template>`, 200) + strings.Repeat(`</template>`, 200) + `</head>`),
		[]byte(`<head>` + strings.Repeat(`<meta>`, 4100) + `</head>`),
		[]byte(`<head>` + strings.Repeat("x", 65537) + `</head>`),
		append(append([]byte(`<head><title>`), 0xff), []byte(`</title></head>`)...),
	}
	var zipped bytes.Buffer
	writer := gzip.NewWriter(&zipped)
	_, _ = writer.Write([]byte(valid[1]))
	_ = writer.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"original"`)
		w.Header().Set("Last-Modified", "Thu, 08 Oct 2026 01:00:00 GMT")
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Security-Policy", "script-src 'self'")
		w.Header().Set("Set-Cookie", "original-cookie")
		var body []byte
		var i int
		switch {
		case strings.HasPrefix(r.URL.Path, "/valid/"):
			_, _ = fmt.Sscanf(r.URL.Path, "/valid/%d", &i)
			body = []byte(valid[i])
		case strings.HasPrefix(r.URL.Path, "/unchanged/"):
			_, _ = fmt.Sscanf(r.URL.Path, "/unchanged/%d", &i)
			body = unmodified[i]
		default:
			body = []byte(valid[1])
			if r.URL.Path == "/gzip" {
				w.Header().Set("Content-Encoding", "gzip")
				body = zipped.Bytes()
			}
			if r.URL.Path == "/attachment" {
				w.Header().Set("Content-Disposition", "attachment; filename=file.html")
			}
			if r.URL.Path == "/json" {
				w.Header().Set("Content-Type", "application/json")
			}
			if r.URL.Path == "/latin1" {
				w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
			}
			if r.URL.Path == "/partial" {
				w.WriteHeader(206)
			}
			if r.URL.Path == "/not-found" {
				w.WriteHeader(404)
			}
		}
		if r.URL.Query().Get("chunked") == "1" {
			for offset := 0; offset < len(body); offset += 3 {
				end := offset + 3
				if end > len(body) {
					end = len(body)
				}
				_, _ = w.Write(body[offset:end])
				w.(http.Flusher).Flush()
			}
		} else {
			_, _ = w.Write(body)
		}
	}))
	defer origin.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	tempConfig := ""
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		tempConfig += fmt.Sprintf("%s_temp_path %s;\n", kind, filepath.Join(run, kind+"-tmp"))
	}
	conf := fmt.Sprintf("load_module %s;\ndaemon off;\nmaster_process off;\npid %s;\nerror_log stderr warn;\nevents { worker_connections 32; }\nhttp { access_log off; %s server { listen 127.0.0.1:%d; server_name analytics.example; js_engine qjs; js_context_reuse 2; js_import analytics_html from %s; set $panel_analytics_site %s; location / { js_header_filter analytics_html.header; js_body_filter analytics_html.body buffer_type=buffer; proxy_buffering off; proxy_pass %s; } } }\n", filepath.Join(prefix, "ngx_http_js_module.so"), filepath.Join(run, "nginx.pid"), tempConfig, port, filepath.Join(prefix, "analytics-html.js"), id, origin.URL)
	conf = strings.Replace(conf, "location / {", fmt.Sprintf("set $panel_analytics_engine %s; set $panel_analytics_program_sha %s; location = /engine-health { js_content analytics_html.health; } location / {", id, analyticsHTMLProgramSHA), 1)
	confPath := filepath.Join(run, "nginx.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(base, "native-http.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command("/usr/sbin/runuser", "-u", "panel-build", "--", nginx, "-e", "stderr", "-p", run+"/", "-c", confPath)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}()
	address := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, DisableCompression: true}}
	defer client.CloseIdleConnections()
	ready := false
	for attempt := 0; attempt < 100; attempt++ {
		connection, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
		if e == nil {
			_ = connection.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("private Nginx did not start; retained native-http.log")
	}
	request := func(method, path string, headers map[string]string) ([]byte, http.Header, int) {
		t.Helper()
		req, _ := http.NewRequest(method, address+path, nil)
		req.Host = "analytics.example"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		if resp.Header.Get("Content-Security-Policy") != "script-src 'self'" || resp.Header.Get("Set-Cookie") != "original-cookie" {
			t.Fatal("CSP or cookie modified", resp.Header)
		}
		return body, resp.Header, resp.StatusCode
	}
	checked := 0
	for i, html := range valid {
		for _, chunked := range []string{"0", "1"} {
			body, header, status := request("GET", fmt.Sprintf("/valid/%d?chunked=%s", i, chunked), nil)
			at := strings.LastIndex(strings.ToLower(html), "</head")
			expected := html[:at] + insert + html[at:]
			if string(body) != expected || status != 200 || header.Get("ETag") != "" || header.Get("Last-Modified") != "" {
				t.Fatalf("native context injection %d/%s failed: status %d size %d expected %d headers %v", i, chunked, status, len(body), len(expected), header)
			}
			checked++
		}
	}
	for i, expected := range unmodified {
		body, _, _ := request("GET", fmt.Sprintf("/unchanged/%d", i), nil)
		if !bytes.Equal(body, expected) {
			t.Fatalf("native pass-through %d changed bytes", i)
		}
		checked++
	}
	for _, path := range []string{"/attachment", "/json", "/latin1", "/partial", "/not-found"} {
		body, header, _ := request("GET", path, nil)
		if string(body) != valid[1] || header.Get("ETag") != `"original"` {
			t.Fatal("ineligible representation changed", path, header)
		}
		checked++
	}
	body, header, _ := request("GET", "/gzip", map[string]string{"Accept-Encoding": "gzip"})
	if !bytes.Equal(body, zipped.Bytes()) || header.Get("Content-Encoding") != "gzip" || header.Get("ETag") != `"original"` {
		t.Fatal("compressed response changed", header)
	}
	checked++
	body, _, _ = request("GET", "/range", map[string]string{"Range": "bytes=0-8"})
	if string(body) != valid[1] {
		t.Fatal("range transformed")
	}
	checked++
	body, _, _ = request("POST", "/post", nil)
	if string(body) != valid[1] {
		t.Fatal("POST transformed")
	}
	checked++
	body, header, _ = request("HEAD", "/head", nil)
	if len(body) != 0 || header.Get("ETag") != `"original"` {
		t.Fatal("HEAD changed validators", header)
	}
	checked++
	// Reused QuickJS contexts must not retain a previous unfinished parser.
	_, _, _ = request("GET", "/unchanged/2", nil)
	body, _, _ = request("GET", "/valid/1", nil)
	at := strings.LastIndex(valid[1], "</head")
	if string(body) != valid[1][:at]+insert+valid[1][at:] {
		t.Fatal("request state leaked")
	}
	checked++
	response, err := client.Get(address + "/engine-health")
	if err != nil {
		t.Fatal(err)
	}
	health, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	response.Body.Close()
	var identity map[string]string
	if err != nil || response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Set-Cookie")) != 0 || json.Unmarshal(health, &identity) != nil || len(identity) != 3 || identity["protocol"] != "yunzhan-analytics-html-v1" || identity["job_id"] != id || identity["program_sha256"] != analyticsHTMLProgramSHA {
		t.Fatal("actual loaded QuickJS health fingerprint mismatch", response.StatusCode, string(health))
	}
	checked++
	t.Logf("PASS %d actual HTTP response cases on %s; non-root compiler/server; no real Nginx/site/service changes", checked, version)
	analyticsHTMLNativeGlobalLifecycle(t, ctx, base, prefix, nginx, version)
}
