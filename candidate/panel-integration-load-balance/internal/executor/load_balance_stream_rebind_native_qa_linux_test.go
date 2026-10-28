//go:build linux

package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

// Real kernel/Nginx component only. It neither submits a Core request nor
// creates an app account, changes host network state or grants recovery rights.
func TestLoadBalanceStreamInitialNativeClosedProbeTimeWaitCanBindFreshNginx(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Getenv("PANEL_LBSTREAM_REBIND_PRIVATE_NETNS_QA") != "20261029" {
		t.Skip("explicit private network namespace and installed native Nginx component required")
	}
	host, e1 := os.Readlink("/proc/1/ns/net")
	self, e2 := os.Readlink("/proc/self/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || self == host || host != os.Getenv("PANEL_LBSTREAM_REBIND_QA_HOST_NETNS") {
		t.Fatal("actual separate owned network namespace required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	binary, _, err := holdLoadBalanceStreamEngineFile("/opt/panel/runtimes/nginx/1.30.6/sbin/nginx", true)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.file.Close()
	if !loadBalanceStreamAccountHash(os.Getenv("PANEL_LBSTREAM_REBIND_QA_NGINX_SHA256")) || binary.sha != os.Getenv("PANEL_LBSTREAM_REBIND_QA_NGINX_SHA256") {
		t.Fatal("fixed installed engine bytes differ from pinned actual cohort")
	}
	if out, err := exec.CommandContext(ctx, "/usr/sbin/ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatal("private loopback setup", err, string(out))
	}
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network == "tcp6" {
				address = "[::1]:0"
			}
			listener, err := net.Listen(network, address)
			if err != nil {
				t.Fatal("actual private loopback family unavailable", err)
			}
			defer listener.Close()
			target := listener.Addr().String()
			port := listener.Addr().(*net.TCPAddr).Port
			client, err := net.DialTimeout(network, target, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			server.SetDeadline(time.Now().Add(time.Second))
			client.SetDeadline(time.Now().Add(time.Second))
			if _, err := server.Write([]byte("original-probe")); err != nil {
				t.Fatal(err)
			}
			// Server is the active closer, as for a completed HTTP probe. Its
			// listener and every original accepted descriptor are then closed.
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(client)
			if err != nil || string(got) != "original-probe" {
				t.Fatal("original TCP exchange", err)
			}
			client.Close()
			listener.Close()
			entries := []loadbalancestream.Entry{{Protocol: "tcp", Port: 41080, ProbePort: port}}
			var observed loadBalanceStreamHostSocket
			found := false
			for attempt := 0; attempt < 100; attempt++ {
				census, err := observeLoadBalanceStreamHostSockets(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range census.sockets {
					if int(row.Local.Port()) == port && row.State == 6 && row.Inode == 0 && row.UID == 0 {
						observed = row
						found = true
					}
				}
				current := census.current()
				census.close()
				if !current {
					t.Fatal("namespace changed")
				}
				if found {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !found || streamInitialSocketConflicts(observed, entries) {
				t.Fatal("real ownerless TIME_WAIT remains a false live conflict", found, observed)
			}
			if observed.Local != netip.MustParseAddrPort(target) {
				t.Fatal("different endpoint adopted")
			}
			// The old initial-start predicate rejected this same target port,
			// despite it having no live descriptor. Do not call it port-free;
			// require the actual fixed Nginx to bind and answer under UID65534.
			dir, err := os.MkdirTemp("/var/lib", "panel-own-rebind-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir) // Only this newly created private fixture.
			if strings.ContainsAny(dir, "\n\r\x00\";") {
				t.Fatal("unsafe test fixture path")
			}
			if err := os.Chown(dir, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			configuration := fmt.Sprintf("daemon off;\nmaster_process off;\nworker_processes 1;\npid %s/nginx.pid;\nerror_log stderr notice;\nevents { worker_connections 32; }\nhttp { access_log off; server { listen %s; return 200 'fresh-native-bind'; } }\n", dir, target)
			config := filepath.Join(dir, "nginx.conf")
			if err := os.WriteFile(config, []byte(configuration), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(config, 0644); err != nil {
				t.Fatal(err)
			}
			log, err := os.OpenFile(filepath.Join(dir, "nginx.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			cmd := exec.CommandContext(ctx, "/opt/panel/runtimes/nginx/1.30.6/sbin/nginx", "-e", "stderr", "-p", dir+"/", "-c", config)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
			cmd.Stdout = log
			cmd.Stderr = log
			// Single-process mode has no untracked worker. A creating-thread
			// death also kills only this new unprivileged child.
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}, Pdeathsig: syscall.SIGKILL}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			var reply []byte
			for attempt := 0; attempt < 100; attempt++ {
				connection, err := net.DialTimeout(network, target, 100*time.Millisecond)
				if err == nil {
					connection.SetDeadline(time.Now().Add(time.Second))
					_, err = connection.Write([]byte("GET / HTTP/1.0\r\nHost: rebind.qa\r\nConnection: close\r\n\r\n"))
					if err == nil {
						reply, err = io.ReadAll(io.LimitReader(connection, 4097))
					}
					connection.Close()
					if err == nil && bytes.Contains(reply, []byte("fresh-native-bind")) {
						break
					}
				}
				if ctx.Err() != nil {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if len(reply) > 4096 || !(bytes.HasPrefix(reply, []byte("HTTP/1.1 200")) || bytes.HasPrefix(reply, []byte("HTTP/1.0 200"))) || !bytes.Contains(reply, []byte("fresh-native-bind")) {
				log.Close()
				b, _ := os.ReadFile(filepath.Join(dir, "nginx.log"))
				t.Fatal("actual fresh Nginx did not bind/answer", string(b))
			}
			if err := cmd.Process.Signal(syscall.SIGQUIT); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				waited = true
				t.Fatal("new fixture did not quit cleanly", err)
			}
			waited = true
			t.Logf("actual %s TIME_WAIT state=%d uid=%d inode=%d, original descriptors closed; fixed Nginx bound and returned HTTP200 under UID65534; no Core/service mutation", network, observed.State, observed.UID, observed.Inode)
		})
	}
	if !binary.current() {
		t.Fatal("fixed installed engine identity changed during the component")
	}
}
