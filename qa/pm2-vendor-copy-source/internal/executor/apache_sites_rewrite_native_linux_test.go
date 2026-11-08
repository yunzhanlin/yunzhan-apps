//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

var nativeApacheRewritePort = flag.Int("native-apache-rewrite-port", 0, "explicit owned native renderer HTTP companion port")

func TestApacheRewriteReplacementClosedVariables(t *testing.T) {
	for _, tc := range []struct{ in, out, flags string }{
		{"/index.php?name=$1", "/index.php?name=$1", "PT,L"},
		{"/index.php?name=$1&$args", "/index.php?name=$1&%{QUERY_STRING}", "PT,L"},
		{"/index.php?$query_string", "/index.php?%{QUERY_STRING}", "PT,L"},
		{"/index.php$is_args$args", "/index.php?%{QUERY_STRING}", "PT,L"},
		{"/index.php$is_args", "/index.php?", "PT,L,QSA"},
		{"/index.php?path=$uri", "/index.php?path=%{REQUEST_URI}", "PT,L"},
	} {
		t.Run(tc.in, func(t *testing.T) {
			out, flags := apacheRewriteReplacement(tc.in)
			if out != tc.out || flags != tc.flags {
				t.Fatalf("%q %q", out, flags)
			}
		})
	}
}

// This companion executes the production renderer and a genuine installed
// Apache. It uses static marker files in place of PHP, its own listener/PID/
// logs, and no WAF include. Signed Core installs and PHP/WAF enforcement must
// also pass the separate normal installed acceptance; this is not that proof.
func TestApacheRewriteNativeNoFollowAndURLMapping(t *testing.T) {
	if *nativeApacheRewritePort == 0 {
		t.Skip("explicit isolated native HTTP companion required")
	}
	if os.Geteuid() != 0 || *nativeApacheRewritePort < 19110 || *nativeApacheRewritePort > 19199 {
		t.Fatal("root and an owned bounded port required")
	}
	r, err := apacheRelease()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(r.CLI())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("NATIVE_APACHE_REWRITE_BINARY %s %x", r.CLI(), sha256.Sum256(binary))
	root, err := os.MkdirTemp("/run", "panel-qa-apache-rewrite-")
	if err != nil {
		t.Fatal(err)
	}
	// Retain the complete owned config/logs on failure. No installed files are
	// changed, and shutdown is limited to the child this test actually starts.
	t.Log("NATIVE_APACHE_REWRITE_ROOT", root)
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	profiles := []struct{ name, rewrite, pattern, replacement string }{
		{"spa", "spa", "", ""}, {"wordpress", "wordpress", "", ""}, {"thinkphp", "thinkphp", "", ""},
		{"capture", "custom", "^/route/([a-z]+)$", "/index.php?name=$1"},
		{"slashless", "custom", "^route/([a-z]+)$", "/index.php?name=$1"},
		{"args", "custom", "^/route/([a-z]+)$", "/index.php?name=$1&$args"},
		{"query", "custom", "^/route/([a-z]+)$", "/index.php?$query_string"},
		{"isargs", "custom", "^/route/([a-z]+)$", "/index.php$is_args$args"},
		{"uri", "custom", "^/route/([a-z]+)$", "/index.php?path=$uri"},
	}
	var sites []core.Site
	for i, p := range profiles {
		s := core.Site{ID: fmt.Sprintf("%032x", i+1), Domain: p.name + ".localhost", Status: "running", PHPVersionID: "php-8.2", Settings: core.SiteSettings{WebServer: "apache", Rewrite: p.rewrite}}
		if p.rewrite == "custom" {
			s.Settings.Rules = []core.RewriteRule{{Pattern: p.pattern, Replacement: p.replacement, Flag: "last"}}
		}
		public := filepath.Join(root, "sites", s.ID, "public")
		if err = os.MkdirAll(filepath.Join(public, "assets"), 0755); err != nil {
			t.Fatal(err)
		}
		// The outer private-evidence runner deliberately uses umask 077.
		// Grant traversal only to this synthetic web tree, regardless of it.
		for dir := filepath.Join(public, "assets"); dir != root; dir = filepath.Dir(dir) {
			if err = os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"index.html", "index.php", "panel-check-owned.php", "assets/ordinary.txt", "assets/index.html", ".private"} {
			if err = os.WriteFile(filepath.Join(public, name), []byte(name+"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err = os.Chmod(filepath.Join(public, name), 0644); err != nil {
				t.Fatal(err)
			}
		}
		if err = os.Symlink("assets/ordinary.txt", filepath.Join(public, "forbidden-link.txt")); err != nil {
			t.Fatal(err)
		}
		sites = append(sites, s)
	}
	source, count, err := renderApacheSites(sites, filepath.Join(root, "sites"))
	if err != nil || count != len(sites) {
		t.Fatal(count, err)
	}
	// Only isolate resources/optional policy and replace the unavailable
	// synthetic PHP socket. The rendered rewrites and directory authorization
	// are passed unchanged to the actual parser and HTTP server.
	source = strings.ReplaceAll(source, "127.0.0.1:19080", net.JoinHostPort("127.0.0.1", fmt.Sprint(*nativeApacheRewritePort)))
	source = strings.ReplaceAll(source, "PidFile /run/panel-apache.pid", "PidFile "+filepath.Join(root, "httpd.pid"))
	source = strings.ReplaceAll(source, "/var/log/apache2/", root+"/")
	source = strings.ReplaceAll(source, "  "+apacheWAFInclude, "")
	for _, s := range sites {
		handler := fmt.Sprintf("  <FilesMatch \"\\.php$\">\n    SetHandler \"proxy:unix:%s|fcgi://localhost/\"\n  </FilesMatch>\n", poolSocket(s))
		if strings.Count(source, handler) != 1 {
			t.Fatal("exact synthetic PHP handler isolation")
		}
		source = strings.Replace(source, handler, "", 1)
	}
	limits := "DefaultRuntimeDir " + root + "\nStartServers 1\nServerLimit 1\nThreadsPerChild 4\nMaxRequestWorkers 4\nMinSpareThreads 1\nMaxSpareThreads 4\nHeader always set X-Owned-Rewrite-Query \"expr=%{QUERY_STRING}\"\n"
	source = strings.Replace(source, "TypesConfig /etc/mime.types\n", limits+"TypesConfig /etc/mime.types\n", 1)
	if strings.Contains(source, "FollowSymLinks\n") == false || strings.Contains(source, "Options +FollowSymLinks") || strings.Contains(source, "SymLinksIfOwnerMatch") {
		t.Fatal("symlink restriction changed")
	}
	for _, block := range strings.Split(source, "<Directory ")[1:] {
		if strings.Contains(strings.SplitN(block, "</Directory>", 2)[0], "Rewrite") {
			t.Fatal("per-directory rewrite regression")
		}
	}
	config := filepath.Join(root, "httpd.conf")
	if err = os.WriteFile(config, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, r.CLI(), "-t", "-f", config).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	log, err := os.OpenFile(filepath.Join(root, "startup.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, r.CLI(), "-DFOREGROUND", "-f", config)
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Error("owned child shutdown timeout")
		}
	}()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	address := "http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(*nativeApacheRewritePort))
	for deadline := time.Now().Add(5 * time.Second); ; {
		conn, e := net.DialTimeout("tcp", strings.TrimPrefix(address, "http://"), 100*time.Millisecond)
		if e == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned Apache not listening", e)
		}
		time.Sleep(30 * time.Millisecond)
	}
	request := func(t *testing.T, host, path string, status int, body, query string) {
		t.Helper()
		req, e := http.NewRequestWithContext(ctx, "GET", address+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Host = host
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if e != nil {
			t.Fatal(e)
		}
		if resp.StatusCode != status || body != "" && string(raw) != body || query != "*" && resp.Header.Get("X-Owned-Rewrite-Query") != query {
			t.Fatalf("%s %s: status=%d body=%q query=%q", host, path, resp.StatusCode, raw, resp.Header.Get("X-Owned-Rewrite-Query"))
		}
		t.Logf("NATIVE_APACHE_REWRITE_HTTP %s %s status=%d body_sha256=%x query=%q", host, path, resp.StatusCode, sha256.Sum256(raw), resp.Header.Get("X-Owned-Rewrite-Query"))
	}
	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			host := p.name + ".localhost"
			request(t, host, "/panel-check-owned.php", 200, "panel-check-owned.php\n", "")
			request(t, host, "/assets/ordinary.txt?keep=one", 200, "assets/ordinary.txt\n", "keep=one")
			request(t, host, "/assets/", 200, "assets/index.html\n", "")
			request(t, host, "/forbidden-link.txt", 403, "", "*")
			request(t, host, "/.private", 403, "", "*")
			query := map[string]string{"spa": "keep=one", "wordpress": "keep=one", "thinkphp": "s=/route/alpha&keep=one", "capture": "name=alpha", "slashless": "name=alpha", "args": "name=alpha&keep=one", "query": "keep=one", "isargs": "keep=one", "uri": "path=/route/alpha"}[p.name]
			body := "index.php\n"
			if p.name == "spa" {
				body = "index.html\n"
			}
			request(t, host, "/route/alpha?keep=one", 200, body, query)
			if p.name == "isargs" {
				request(t, host, "/route/alpha", 200, body, "")
			}
		})
	}
}
