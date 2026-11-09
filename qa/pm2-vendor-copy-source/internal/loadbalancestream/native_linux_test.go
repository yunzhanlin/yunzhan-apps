//go:build linux

package loadbalancestream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var nativeNginx = flag.String("lbstream-nginx", "", "QA only: exact trusted installed Nginx; never an install/reload API")
var nativeNginxSHA = flag.String("lbstream-nginx-sha256", "", "QA only: independently pinned Nginx binary")

func processStatus(t *testing.T, pid int) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil || len(raw) > 65536 {
		t.Fatal("owned process status unavailable")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	return values
}

func verifyOwnedWorker(t *testing.T, master int, binary string) {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", master, master))
	if err != nil || len(raw) > 1024 || len(strings.Fields(string(raw))) != 1 {
		t.Fatal("exactly one owned Nginx worker required")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		t.Fatal("owned worker PID invalid")
	}
	status := processStatus(t, pid)
	if strings.Join(strings.Fields(status["Uid"]), ",") != "33,33,33,33" || strings.Join(strings.Fields(status["Gid"]), ",") != "33,33,33,33" || status["NoNewPrivs"] != "1" {
		t.Fatal("owned worker failed non-root/no-new-privileges boundary")
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapAmb"} {
		if status[key] != "0000000000000000" {
			t.Fatal("owned worker retained effective/permitted/ambient authority")
		}
	}
	image, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || image != binary {
		t.Fatal("owned worker executable identity drift")
	}
	parentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	workerNet, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil || workerNet != parentNet {
		t.Fatal("owned worker escaped private network")
	}
	t.Logf("owned worker uid=33 gid=33 effective/permitted/ambient=0 NNP=1 inheritable=%s", status["CapInh"])
}

func nativeBinary(t *testing.T) string {
	t.Helper()
	if *nativeNginx == "" && *nativeNginxSHA == "" {
		t.Skip("requires explicit isolated Linux Nginx fixture; no installed app acceptance")
	}
	if os.Geteuid() != 0 || len(*nativeNginxSHA) != 64 {
		t.Fatal("explicit Root pinned fixture required")
	}
	status := processStatus(t, os.Getpid())
	capabilities, err := strconv.ParseUint(status["CapEff"], 16, 64)
	if err != nil || capabilities&(1<<7) == 0 || status["NoNewPrivs"] != "1" {
		t.Fatal("private Root fixture requires actual SETUID authority and NNP; bounding-set membership alone is insufficient")
	}
	name := *nativeNginx
	real, err := filepath.EvalSymlinks(name)
	info, statErr := os.Lstat(name)
	if err != nil || statErr != nil || real != name || !filepath.IsAbs(name) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		t.Fatal("untrusted native Nginx path")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Nlink != 1 {
		t.Fatal("untrusted native Nginx inode")
	}
	raw, err := os.ReadFile(name)
	if err != nil || len(raw) > 64<<20 {
		t.Fatal("native binary budget")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != *nativeNginxSHA {
		t.Fatal("native Nginx digest drift")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, name, "-V").CombinedOutput()
	if err != nil || len(version) > 65536 || !strings.Contains(string(version), "--with-stream ") {
		t.Fatal("required exact static Stream build is absent")
	}
	return name
}
func echoTCP(t *testing.T, address string, count *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func(connection net.Conn) {
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(5 * time.Second))
				data, err := io.ReadAll(io.LimitReader(connection, 256<<10))
				if err != nil {
					return
				}
				count.Add(1)
				for len(data) > 0 {
					n, err := connection.Write(data)
					if err != nil {
						return
					}
					data = data[n:]
				}
			}(connection)
		}
	}()
}
func echoUDP(t *testing.T, address string, count *atomic.Int32) {
	t.Helper()
	target, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := listener.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			count.Add(1)
			listener.WriteToUDP(buffer[:n], peer)
		}
	}()
}
func runNativeNginx(t *testing.T, binary string, entry Entry) {
	t.Helper()
	if ValidateSet([]Entry{entry}, facts()) != nil {
		t.Fatal("invalid native policy")
	}
	rendered, err := Render(entry)
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	config := filepath.Join(work, "nginx.conf")
	runtime, err := RenderRuntime([]Entry{entry}, work, facts())
	if err != nil {
		t.Fatal(err)
	}
	full := append([]byte("user www-data;\n"), runtime.Main...)
	if err = os.WriteFile(config, full, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	pre, err := exec.CommandContext(ctx, binary, "-t", "-p", work+"/", "-c", config).CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("private Nginx syntax refused: %s", pre)
	}
	log, err := os.OpenFile(filepath.Join(work, "process.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-p", work+"/", "-c", config, "-g", "daemon off;")
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); log.Close() }()
	t.Cleanup(func() {
		command.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
			return
		case <-time.After(2 * time.Second):
		}
		command.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
			return
		case <-time.After(2 * time.Second):
		}
		command.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("only-owned fixture process did not close")
		}
	})
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("own Nginx exited before generation verification: %v", err)
		default:
		}
		response, err := client.Get("http://127.0.0.1:" + fmt.Sprint(entry.ProbePort) + ProbePath(entry.Name))
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
			response.Body.Close()
			if readErr == nil && response.StatusCode == 200 && string(body) == rendered.Fingerprint {
				verifyOwnedWorker(t, command.Process.Pid, binary)
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	errorLog, _ := os.ReadFile(filepath.Join(work, "error.log"))
	t.Fatalf("private generation not ready: %s", errorLog)
}
func tcpExchange(t *testing.T, port int, payload []byte) {
	t.Helper()
	target, err := net.ResolveTCPAddr("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTCP("tcp4", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	for offset := 0; offset < len(payload); {
		n, err := connection.Write(payload[offset:])
		if err != nil {
			t.Fatal(err)
		}
		offset += n
	}
	if err = connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(connection, int64(len(payload)+1)))
	if err != nil || !bytes.Equal(body, payload) {
		t.Fatalf("TCP byte/half-close mismatch: bytes=%d expected=%d error=%v", len(body), len(payload), err)
	}
}
func TestNativeLayer4ForwardingUsesRealPrivateNginx(t *testing.T) {
	binary := nativeBinary(t)
	// Fixed fixture ports are safe ONLY inside the independently verified private
	// network namespace. The runner must never invoke this on the host network.
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == host {
		t.Fatal("requires private network namespace; no host listener may be opened")
	}
	var tcp1, tcp2, udp1, udp2 atomic.Int32
	echoTCP(t, "127.0.0.1:41001", &tcp1)
	echoTCP(t, "127.0.0.2:41002", &tcp2)
	echoUDP(t, "127.0.0.1:41001", &udp1)
	echoUDP(t, "127.0.0.2:41002", &udp2)
	payload := make([]byte, 131073)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	nativeEntry := func(protocol string) Entry {
		entry := fixture()
		entry.Protocol = protocol
		entry.Nodes = []Node{{Address: "127.0.0.1:41001", Weight: 1}, {Address: "127.0.0.2:41002", Weight: 3}}
		if protocol == "udp" {
			entry.UDPRequests = 1
			entry.UDPResponses = 1
		}
		return entry
	}
	t.Run("TCP-binary-weights-and-real-half-close", func(t *testing.T) {
		entry := nativeEntry("tcp")
		runNativeNginx(t, binary, entry)
		a, b := tcp1.Load(), tcp2.Load()
		for i := 0; i < 8; i++ {
			tcpExchange(t, entry.Port, payload)
		}
		if tcp1.Load()-a != 2 || tcp2.Load()-b != 6 {
			t.Fatalf("weighted TCP distribution changed: %d/%d", tcp1.Load()-a, tcp2.Load()-b)
		}
	})
	t.Run("UDP-opaque-48KiB-datagrams-and-weights", func(t *testing.T) {
		entry := nativeEntry("udp")
		runNativeNginx(t, binary, entry)
		a, b := udp1.Load(), udp2.Load()
		connection, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", entry.Port))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		data := payload[:48<<10]
		buffer := make([]byte, 65535)
		for i := 0; i < 8; i++ {
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err = connection.Write(data); err != nil {
				t.Fatal(err)
			}
			n, err := connection.Read(buffer)
			if err != nil || !bytes.Equal(buffer[:n], data) {
				t.Fatalf("UDP datagram changed: bytes=%d error=%v", n, err)
			}
		}
		if udp1.Load()-a != 2 || udp2.Load()-b != 6 {
			t.Fatalf("weighted UDP distribution changed: %d/%d", udp1.Load()-a, udp2.Load()-b)
		}
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		maximum := payload[:65507]
		if _, err = connection.Write(maximum); err != nil {
			t.Fatal(err)
		}
		n, err := connection.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], maximum) {
			t.Fatalf("maximum IPv4 UDP datagram changed: bytes=%d error=%v", n, err)
		}
	})
	t.Run("TCP-least-connections-real-byte-forwarding", func(t *testing.T) {
		entry := nativeEntry("tcp")
		entry.Method = "least-connections"
		runNativeNginx(t, binary, entry)
		for i := 0; i < 4; i++ {
			tcpExchange(t, entry.Port, payload[:8193])
		}
	})
	t.Run("TCP-source-IP-affinity-real-same-client-streams", func(t *testing.T) {
		entry := nativeEntry("tcp")
		entry.Method = "source-ip"
		runNativeNginx(t, binary, entry)
		a, b := tcp1.Load(), tcp2.Load()
		for i := 0; i < 8; i++ {
			tcpExchange(t, entry.Port, payload[:4097])
		}
		left, right := tcp1.Load()-a, tcp2.Load()-b
		if !((left == 8 && right == 0) || (left == 0 && right == 8)) {
			t.Fatalf("same source IP affinity changed: %d/%d", left, right)
		}
	})
	t.Run("TCP-unavailable-primary-uses-explicit-backup", func(t *testing.T) {
		entry := nativeEntry("tcp")
		entry.Nodes = []Node{{Address: "127.0.0.1:41009", Weight: 1}, {Address: "127.0.0.2:41002", Weight: 1, Backup: true}}
		runNativeNginx(t, binary, entry)
		before := tcp2.Load()
		tcpExchange(t, entry.Port, payload[:4097])
		if tcp2.Load() != before+1 {
			t.Fatal("real backup did not receive exactly one stream")
		}
	})
	t.Run("UDP-unavailable-primary-never-replays-to-backup", func(t *testing.T) {
		entry := nativeEntry("udp")
		entry.SessionSeconds = 2
		entry.ConnectMilliseconds = 500
		entry.Nodes = []Node{{Address: "127.0.0.1:41009", Weight: 1}, {Address: "127.0.0.2:41002", Weight: 1, Backup: true}}
		runNativeNginx(t, binary, entry)
		before := udp2.Load()
		connection, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", entry.Port))
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = connection.Write(payload[:97]); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 4096)
		n, err := connection.Read(buffer)
		if n != 0 || err == nil {
			t.Fatal("unexpected replay/response for absent UDP primary")
		}
		if udp2.Load() != before {
			t.Fatal("UDP business datagram replayed to backup")
		}
	})
}
