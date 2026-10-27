//go:build linux

package loadbalancestream

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var nativeNft = flag.String("lbstream-nft", "", "QA only: pinned nft in an independently isolated network namespace")
var nativeNftSHA = flag.String("lbstream-nft-sha256", "", "QA only: independently pinned nft executable SHA256")

func egressPrivateNet(t *testing.T) {
	t.Helper()
	current, err := os.Readlink("/proc/self/ns/net")
	hostPath := "/proc/1/ns/net"
	if os.Geteuid() != 0 {
		// A capability-free UID cannot dereference another UID's /proc/PID/ns
		// links. The Root parent opens both witnesses BEFORE dropping identity;
		// the child verifies its own namespace against those inherited FDs.
		// These read-only FDs confer no setns authority without capabilities.
		hostPath = "/proc/self/fd/4"
		private, privateErr := os.Readlink("/proc/self/fd/5")
		if privateErr != nil || private != current {
			t.Fatal("private child lost its Root-opened network namespace witness")
		}
	}
	host, hostErr := os.Readlink(hostPath)
	validName := func(value string) bool {
		if !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") {
			return false
		}
		number := value[5 : len(value)-1]
		inode, parseErr := strconv.ParseUint(number, 10, 64)
		return parseErr == nil && inode > 0 && strconv.FormatUint(inode, 10) == number
	}
	if err != nil || hostErr != nil || !validName(current) || !validName(host) || current == host {
		t.Fatal("egress fixture must never change the host network")
	}
}

func egressProbeFiles(t *testing.T) []*os.File {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("only the original private Root fixture may open child witnesses")
	}
	egressPrivateNet(t)
	var files []*os.File
	for _, path := range []string{"/proc/self/exe", "/proc/1/ns/net", "/proc/self/ns/net"} {
		file, err := os.Open(path)
		if err != nil {
			for _, opened := range files {
				opened.Close()
			}
			t.Fatal("cannot open the private child's immutable witness", err)
		}
		files = append(files, file)
	}
	return files
}

func egressUnprivileged(t *testing.T, pid int) {
	t.Helper()
	status := processStatus(t, pid)
	if strings.Join(strings.Fields(status["Uid"]), ",") != "991,991,991,991" || strings.Join(strings.Fields(status["Gid"]), ",") != "991,991,991,991" || status["NoNewPrivs"] != "1" {
		t.Fatal("private worker/probe identity or NNP changed")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if status[key] != "0000000000000000" {
			t.Fatalf("private worker/probe retained %s=%s", key, status[key])
		}
	}
}

type nativeEgressProbe struct {
	Network, Address string
	SourcePort       int
	Allowed          bool
}

// This is a socket fixture in a TEST ELF only. It is never included in panel or
// executor programmes and cannot grant production command/socket authority.
func TestNativeEgressSocketProbe(t *testing.T) {
	raw := os.Getenv("PANEL_LB_EGRESS_NATIVE_PROBE")
	if raw == "" {
		t.Skip("private child socket probe only")
	}
	egressPrivateNet(t)
	egressUnprivileged(t, os.Getpid())
	var p nativeEgressProbe
	if len(raw) > 512 || json.Unmarshal([]byte(raw), &p) != nil || (p.Network != "tcp4" && p.Network != "tcp6" && p.Network != "udp4" && p.Network != "udp6") {
		t.Fatal("invalid private probe")
	}
	dialer := net.Dialer{Timeout: 450 * time.Millisecond}
	if p.SourcePort != 0 {
		if !strings.HasSuffix(p.Network, "4") || p.SourcePort < 20000 || p.SourcePort > 60000 {
			t.Fatal("invalid private source port")
		}
		if strings.HasPrefix(p.Network, "tcp") {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: p.SourcePort}
		} else {
			dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p.SourcePort}
		}
	}
	connection, err := dialer.Dial(p.Network, p.Address)
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Fatal("source bind failed; this is not a firewall rejection", err)
	}
	if connection != nil {
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(450 * time.Millisecond))
		data := bytes.Repeat([]byte{0x00, 0xff, 0x42, 0x80}, 2049)
		if _, err = connection.Write(data); err == nil {
			if tcp, ok := connection.(*net.TCPConn); ok {
				err = tcp.CloseWrite()
			}
			if err == nil {
				body := make([]byte, len(data)+1)
				var n int
				if strings.HasPrefix(p.Network, "tcp") {
					body, err = io.ReadAll(io.LimitReader(connection, int64(len(body))))
					n = len(body)
				} else {
					n, err = connection.Read(body)
				}
				if err == nil && !bytes.Equal(body[:n], data) {
					t.Fatal("probe got corrupted/unrelated bytes")
				}
			}
		}
	}
	if p.Allowed && err != nil {
		t.Fatal("explicitly permitted egress failed", err)
	}
	if !p.Allowed {
		var timeout net.Error
		// Linux LOCAL_OUT NF_DROP can be returned synchronously as EPERM
		// for UDP writes (nf_hook_slow); TCP normally retransmits to timeout.
		// The parent separately proves the listener is live before/after and
		// that no unauthorized byte/datagram arrived. Refusal, bind failure,
		// bad addresses, EOF and unrelated errors are not accepted as drops.
		if err == nil || !(errors.As(err, &timeout) && timeout.Timeout() || errors.Is(err, syscall.EPERM)) {
			t.Fatal("negative probe must be a real dropped flow to a live listener", err)
		}
	}
	t.Logf("private zero-capability probe network=%s destination=%s source_port=%d permitted=%v", p.Network, p.Address, p.SourcePort, p.Allowed)
}

func egressProbe(t *testing.T, probe nativeEgressProbe) {
	t.Helper()
	files := egressProbeFiles(t)
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--reuid=991", "--regid=991", "--clear-groups", "--", "/proc/self/fd/3", "-test.run=^TestNativeEgressSocketProbe$", "-test.v", "-test.count=1")
	cmd.ExtraFiles = files
	raw, _ := json.Marshal(probe)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2", "PANEL_LB_EGRESS_NATIVE_PROBE=" + string(raw)}
	result, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(result, []byte("--- PASS: TestNativeEgressSocketProbe")) || bytes.Contains(result, []byte("SKIP")) {
		t.Fatalf("private zero-capability socket probe failed: %v\n%s", err, result)
	}
}

// The parent waits for an exact round trip on an established ORIGINAL flow,
// atomically retires that backend, then releases this child to send again.
func TestNativeEgressEstablishedSocketProbe(t *testing.T) {
	raw := os.Getenv("PANEL_LB_EGRESS_NATIVE_HELD_PROBE")
	if raw == "" {
		t.Skip("private established-connection child only")
	}
	egressPrivateNet(t)
	egressUnprivileged(t, os.Getpid())
	var p nativeEgressProbe
	if len(raw) > 512 || json.Unmarshal([]byte(raw), &p) != nil || (p.Network != "tcp4" && p.Network != "tcp6") || p.SourcePort != 0 || !p.Allowed {
		t.Fatal("invalid private established probe")
	}
	connection, err := net.DialTimeout(p.Network, p.Address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(time.Second))
	initial := []byte("before-retirement\x00\xff")
	if _, err := connection.Write(initial); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len(initial))
	if _, err := io.ReadFull(connection, body); err != nil || !bytes.Equal(body, initial) {
		t.Fatal("existing flow did not initially echo exact bytes", err)
	}
	fmt.Fprintln(os.Stdout, "PANEL-LB-EGRESS-ESTABLISHED-READY")
	command, err := bufio.NewReader(io.LimitReader(os.Stdin, 32)).ReadString('\n')
	if err != nil || command != "backend-retired\n" {
		t.Fatal("private parent retirement synchronization failed", err)
	}
	connection.SetDeadline(time.Now().Add(450 * time.Millisecond))
	err = nil
	if _, err = connection.Write([]byte("after-retirement-must-not-arrive\x00\xff")); err == nil {
		_, err = connection.Read(make([]byte, 128))
	}
	var timeout net.Error
	if err == nil || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("retired established ORIGINAL connection was not dropped", err)
	}
	t.Logf("established ORIGINAL egress revoked network=%s destination=%s", p.Network, p.Address)
}

func egressHeldProbe(t *testing.T, probe nativeEgressProbe) func() {
	t.Helper()
	files := egressProbeFiles(t)
	defer func() {
		for _, file := range files {
			file.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	cmd := exec.CommandContext(ctx, "/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--reuid=991", "--regid=991", "--clear-groups", "--", "/proc/self/fd/3", "-test.run=^TestNativeEgressEstablishedSocketProbe$", "-test.v", "-test.count=1")
	cmd.ExtraFiles = files
	raw, _ := json.Marshal(probe)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2", "PANEL_LB_EGRESS_NATIVE_HELD_PROBE=" + string(raw)}
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		cancel()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		input.Close()
		output.Close()
		cancel()
		t.Fatal(err)
	}
	type result struct {
		output string
		err    error
	}
	ready, done := make(chan struct{}, 1), make(chan result, 1)
	go func() {
		scanner := bufio.NewScanner(io.LimitReader(output, 65537))
		scanner.Buffer(make([]byte, 1024), 65536)
		var captured strings.Builder
		for scanner.Scan() {
			captured.WriteString(scanner.Text() + "\n")
			if scanner.Text() == "PANEL-LB-EGRESS-ESTABLISHED-READY" {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
		waitErr := cmd.Wait()
		done <- result{captured.String() + stderr.String(), errors.Join(scanner.Err(), waitErr)}
	}()
	completed := false
	t.Cleanup(func() {
		input.Close()
		cancel()
		if !completed {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("private held-connection child failed to close")
			}
		}
	})
	select {
	case <-ready:
	case r := <-done:
		completed = true
		t.Fatalf("private established flow did not become ready: %v\n%s", r.err, r.output)
	case <-time.After(2 * time.Second):
		t.Fatal("private established flow readiness timed out")
	}
	return func() {
		t.Helper()
		if completed {
			t.Fatal("established probe may be completed only once")
		}
		if _, err := io.WriteString(input, "backend-retired\n"); err != nil {
			t.Fatal(err)
		}
		input.Close()
		select {
		case r := <-done:
			completed = true
			if r.err != nil || !strings.Contains(r.output, "--- PASS: TestNativeEgressEstablishedSocketProbe") || strings.Contains(r.output, "SKIP") {
				t.Fatalf("private established egress revocation failed: %v\n%s", r.err, r.output)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("private established egress revocation timed out")
		}
	}
}

func egressNft(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, *nativeNft, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil || len(out) > MaxEgressObservationBytes {
		t.Fatalf("private nft command failed: %v %s", err, out)
	}
	return out
}

func egressObserved(t *testing.T, g EgressGuard) EgressGuardObservation {
	t.Helper()
	raw := egressNft(t, nil, "-s", "-j", "list", "table", "inet", EgressTableName)
	observed, err := g.Inspect(raw)
	if err != nil {
		t.Fatalf("complete actual nft rules differ from closed policy: %v\n%s", err, raw)
	}
	return observed
}

type nativeEgressTrace struct {
	bytes.Buffer
	overflow bool
}

func (b *nativeEgressTrace) Write(p []byte) (int, error) {
	n := len(p)
	if n > (256<<10)-b.Len() {
		b.overflow = true
		p = p[:(256<<10)-b.Len()]
	}
	b.Buffer.Write(p)
	return n, nil
}

// TEST-ONLY diagnostics: a separate metadata-only chain in the already proven
// private network, before the unchanged guard. This grants no accept verdict
// and is never compiled into an executor or installed on the host network.
func egressTrace(t *testing.T) {
	t.Helper()
	egressPrivateNet(t)
	if os.Geteuid() != 0 {
		t.Fatal("private nft trace requires original Root fixture")
	}
	egressNft(t, []byte("create table inet panel_lbstream_qa_trace\nadd chain inet panel_lbstream_qa_trace output { type filter hook output priority 9; policy accept; }\nadd rule inet panel_lbstream_qa_trace output meta skuid 991 meta nftrace set 1\nadd rule inet panel_lbstream_qa_trace output tcp sport { 41001, 41002 } meta nftrace set 1\n"), "-f", "-")
	cmd := exec.Command(*nativeNft, "-nn", "monitor", "trace")
	var trace nativeEgressTrace
	cmd.Stdout, cmd.Stderr = &trace, &trace
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(time.Second):
			cmd.Process.Kill()
			<-done
		}
		egressNft(t, []byte("delete table inet panel_lbstream_qa_trace\n"), "-f", "-")
		if trace.overflow {
			t.Error("private bounded packet trace overflowed; diagnostics incomplete")
		}
		if !strings.Contains(trace.String(), "trace id ") {
			t.Error("private packet trace observed no real packets")
		}
		if t.Failed() {
			t.Logf("private packet trace (unchanged guard):\n%s", trace.String())
		}
	})
	select {
	case err := <-done:
		t.Fatalf("private packet trace exited before test: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
}

func egressEchoUDP(t *testing.T, address string, count *atomic.Int32) {
	t.Helper()
	listener, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			count.Add(1)
			listener.WriteTo(buffer[:n], peer)
		}
	}()
}

func egressEchoTCP(t *testing.T, address string, count *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	// TEST-ONLY bounded backend evidence. Record both sides of the echo, not
	// merely a successful Write() to the frontend: that cannot establish which
	// side retained bytes when a full-duplex, half-closed flow times out.
	type report struct {
		Peer, ReadError, WriteError string
		Read, Written               int64
		Duration                    time.Duration
	}
	var mu sync.Mutex
	var reports []report
	var overflow bool
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		if overflow {
			t.Error("private bounded TCP diagnostics overflowed")
		}
		if t.Failed() {
			for _, r := range reports {
				t.Logf("private TCP backend %s: %+v", address, r)
			}
		}
	})
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				started := time.Now()
				r := report{Peer: connection.RemoteAddr().String()}
				defer func() {
					r.Duration = time.Since(started)
					mu.Lock()
					defer mu.Unlock()
					if len(reports) == 64 {
						overflow = true
						return
					}
					reports = append(reports, r)
				}()
				connection.SetDeadline(time.Now().Add(5 * time.Second))
				buffer := make([]byte, 16<<10)
				for received := 0; received < 256<<10; {
					n, readErr := connection.Read(buffer)
					r.Read += int64(n)
					if n > 0 {
						received += n
						count.Add(int32(n))
						written, err := io.Copy(connection, bytes.NewReader(buffer[:n]))
						r.Written += written
						if err != nil {
							r.WriteError = err.Error()
							return
						}
					}
					if readErr != nil {
						r.ReadError = readErr.Error()
						return
					}
				}
			}()
		}
	}()
}

func egressRootExchange(t *testing.T, network, address string) {
	t.Helper()
	connection, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatal("Root positive control listener unavailable", err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(time.Second))
	data := []byte("root-positive-control\x00\xff")
	if _, err := connection.Write(data); err != nil {
		t.Fatal(err)
	}
	if tcp, ok := connection.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
	}
	body := make([]byte, 256)
	n, err := connection.Read(body)
	if err != nil || !bytes.Equal(body[:n], data) {
		t.Fatal("Root positive control did not echo exact bytes", err)
	}
}

func egressRootHalfCloseExchange(t *testing.T, network, address string) {
	t.Helper()
	connection, err := net.DialTimeout(network, address, time.Second)
	if err != nil {
		t.Fatal("non-service TCP listener unavailable", err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	data := bytes.Repeat([]byte{0x00, 0xff, 0x42, 0x80}, 32769)
	if n, err := io.Copy(connection, bytes.NewReader(data)); err != nil || n != int64(len(data)) {
		t.Fatal("non-service TCP write failed", n, err)
	}
	if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(connection, int64(len(data)+1)))
	if err != nil || !bytes.Equal(body, data) {
		t.Fatalf("non-service closed socket data/EOF changed: got=%d want=%d err=%v", len(body), len(data), err)
	}
}

func egressRunNginx(t *testing.T, binary string, entries []Entry) {
	t.Helper()
	work, err := os.MkdirTemp("/run", "panel-lbstream-egress-native-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(work) })
	if err := os.Chown(work, 991, 991); err != nil {
		t.Fatal(err)
	}
	runtime, err := RenderRuntime(entries, work, facts())
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(work, "nginx.conf")
	if err := os.WriteFile(config, runtime.Main, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(config, 991, 991); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(work, "fixture.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/bin/setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--reuid=991", "--regid=991", "--clear-groups", "--", binary, "-p", work+"/", "-c", config, "-g", "daemon off;")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait(); log.Close() }()
	t.Cleanup(func() {
		defer func() {
			if t.Failed() {
				output, readErr := os.ReadFile(filepath.Join(work, "fixture.log"))
				if readErr == nil && len(output) < 64<<10 {
					t.Logf("private guarded Nginx diagnostics: %s", output)
				}
			}
		}()
		command.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
			return
		case <-time.After(2 * time.Second):
		}
		command.Process.Kill()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("only-owned private Nginx failed to close")
		}
	})
	client := &http.Client{Timeout: 450 * time.Millisecond, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	for _, entry := range entries {
		want, _ := Render(entry)
		deadline, ready := time.Now().Add(4*time.Second), false
		for time.Now().Before(deadline) {
			response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(entry.ProbePort) + ProbePath(entry.Name))
			if err == nil {
				body, readErr := io.ReadAll(io.LimitReader(response.Body, 257))
				response.Body.Close()
				if readErr == nil && response.StatusCode == 200 && string(body) == want.Fingerprint {
					ready = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			output, _ := os.ReadFile(filepath.Join(work, "fixture.log"))
			t.Fatalf("private guarded Nginx probe reply failed: %s", output)
		}
	}
	egressUnprivileged(t, command.Process.Pid)
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", command.Process.Pid, command.Process.Pid))
	if err != nil || len(strings.Fields(string(raw))) != 1 {
		t.Fatal("exactly one private worker required")
	}
	worker, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	egressUnprivileged(t, worker)
	actual, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", worker))
	if err != nil || actual != binary {
		t.Fatal("owned guarded worker image changed")
	}
}

func TestNativeEgressGuardRealTCPUDPAndAtomicReplacement(t *testing.T) {
	if *nativeNft == "" && *nativeNftSHA == "" {
		t.Skip("requires explicit pinned nft and private Linux network; no application acceptance")
	}
	egressPrivateNet(t)
	binary := nativeBinary(t)
	if (*nativeNft != "/usr/sbin/nft" && *nativeNft != "/usr/bin/nft") || len(*nativeNftSHA) != 64 {
		t.Fatal("closed pinned nft path required")
	}
	raw, err := os.ReadFile(*nativeNft)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != *nativeNftSHA {
		t.Fatal("native nft digest drift")
	}
	var empty struct{ Nftables []map[string]json.RawMessage }
	if json.Unmarshal(egressNft(t, nil, "-s", "-j", "list", "ruleset"), &empty) != nil || len(empty.Nftables) != 1 || empty.Nftables[0]["metainfo"] == nil {
		t.Fatal("namespace is not fresh/empty; no adoption allowed")
	}
	tcp := fixture()
	tcp.Nodes = []Node{{Address: "127.0.0.2:41001", Weight: 1}, {Address: "[::1]:41002", Weight: 1}}
	udp := clone(tcp)
	udp.Name, udp.Protocol, udp.Port, udp.ProbePort, udp.UDPRequests, udp.UDPResponses = "udp.lb.invalid", "udp", 42001, 43001, 1, 1
	udp.Nodes = []Node{{Address: "127.0.0.2:41003", Weight: 1}, {Address: "[::1]:41004", Weight: 1}}
	entries := []Entry{tcp, udp}
	guard := mustEgress(t, entries, nil)
	create, _ := guard.CreateRules()
	egressNft(t, create, "-c", "-f", "-")
	egressNft(t, create, "-f", "-")
	original := egressObserved(t, guard)
	counts := map[string]*atomic.Int32{}
	for _, address := range []string{"127.0.0.2:41001", "[::1]:41002", "127.0.0.2:41005", "127.0.0.3:41001", "[::1]:41005", "127.0.0.2:41006", "[::1]:41007"} {
		counts["tcp/"+address] = &atomic.Int32{}
		egressEchoTCP(t, address, counts["tcp/"+address])
	}
	for _, address := range []string{"127.0.0.2:41003", "[::1]:41004", "127.0.0.2:41001", "127.0.0.2:41005", "[::1]:41005"} {
		counts["udp/"+address] = &atomic.Int32{}
		egressEchoUDP(t, address, counts["udp/"+address])
	}
	t.Run("positive-controls-and-zero-capability-dual-stack", func(t *testing.T) {
		for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41001", 0, true}, {"tcp6", "[::1]:41002", 0, true}, {"udp4", "127.0.0.2:41003", 0, true}, {"udp6", "[::1]:41004", 0, true}} {
			egressProbe(t, p)
		}
	})
	t.Run("wrong-IP-port-protocol-and-fake-frontend-source", func(t *testing.T) {
		for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41005", 0, false}, {"tcp4", "127.0.0.3:41001", 0, false}, {"tcp6", "[::1]:41005", 0, false}, {"udp4", "127.0.0.2:41001", 0, false}, {"udp6", "[::1]:41005", 0, false}, {"tcp4", "127.0.0.2:41005", 42000, false}, {"udp4", "127.0.0.2:41005", 42001, false}} {
			egressRootExchange(t, p.Network, p.Address)
			counter := counts[p.Network[:3]+"/"+p.Address]
			before := counter.Load()
			egressProbe(t, p)
			if counter.Load() != before {
				t.Fatal("unauthorized bytes reached a live backend")
			}
			egressRootExchange(t, p.Network, p.Address)
		}
	})
	t.Run("non-service-closed-sockets-never-inherit-service-deny", func(t *testing.T) {
		// A full echo followed by EOF can queue its last TCP segment after the
		// backend closes its socket file. Cover both allowed and forbidden
		// service destinations: this Root fixture is NOT the service UID and
		// must retain its existing namespace policy in either case.
		for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41001", 0, true}, {"tcp6", "[::1]:41002", 0, true}, {"tcp4", "127.0.0.2:41005", 0, true}, {"tcp6", "[::1]:41005", 0, true}} {
			for i := 0; i < 4; i++ {
				egressRootHalfCloseExchange(t, p.Network, p.Address)
			}
		}
	})
	t.Run("real-Nginx-client-replies-binary-half-close-and-datagrams", func(t *testing.T) {
		egressTrace(t)
		egressRunNginx(t, binary, entries)
		payload := bytes.Repeat([]byte{0x00, 0xff, 0x42, 0x80}, 32769)
		for i := 0; i < 4; i++ {
			tcpExchange(t, tcp.Port, payload)
		}
		connection, err := net.Dial("udp4", "127.0.0.1:42001")
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		buffer := make([]byte, 65535)
		for i := 0; i < 4; i++ {
			connection.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := connection.Write(payload[:48<<10]); err != nil {
				t.Fatal(err)
			}
			n, err := connection.Read(buffer)
			if err != nil || !bytes.Equal(buffer[:n], payload[:48<<10]) {
				t.Fatal("guarded UDP frontend reply/data changed", err)
			}
		}
	})
	t.Run("original-table-is-never-adopted-or-partially-replaced", func(t *testing.T) {
		before := egressNft(t, nil, "-s", "-j", "list", "table", "inet", EgressTableName)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, *nativeNft, "-f", "-")
		cmd.Stdin = bytes.NewReader(create)
		if output, err := cmd.CombinedOutput(); err == nil || len(output) > 65536 {
			t.Fatal("create merged into an existing table")
		}
		replace, _ := guard.ReplacementRules()
		cmd = exec.CommandContext(ctx, *nativeNft, "-f", "-")
		cmd.Stdin = bytes.NewReader(append(replace, []byte("add rule inet panel_lbstream absent_chain drop\n")...))
		if output, err := cmd.CombinedOutput(); err == nil || len(output) > 65536 {
			t.Fatal("deliberately invalid transaction did not fail")
		}
		after := egressNft(t, nil, "-s", "-j", "list", "table", "inet", EgressTableName)
		if !bytes.Equal(before, after) {
			t.Fatal("failed transaction changed original rules/handles")
		}
	})
	t.Run("two-generation-replacement-and-retirement", func(t *testing.T) {
		nextTCP := clone(tcp)
		nextTCP.Revision++
		nextTCP.Nodes = []Node{{Address: "127.0.0.2:41006", Weight: 1}, {Address: "[::1]:41007", Weight: 1}}
		next := []Entry{nextTCP, udp}
		both := mustEgress(t, next, entries)
		for _, g := range []EgressGuard{both, mustEgress(t, next, nil)} {
			egressObserved(t, guard)
			var held []func()
			var beforeHeld []int32
			draining := g.SHA256() == both.SHA256()
			if !draining {
				for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41001", 0, true}, {"tcp6", "[::1]:41002", 0, true}} {
					held = append(held, egressHeldProbe(t, p))
					beforeHeld = append(beforeHeld, counts["tcp/"+p.Address].Load())
				}
			}
			replace, _ := g.ReplacementRules()
			egressNft(t, replace, "-c", "-f", "-")
			egressNft(t, replace, "-f", "-")
			observed := egressObserved(t, g)
			if observed.TableHandle != original.TableHandle || observed.ChainHandle != original.ChainHandle {
				t.Fatal("replacement replaced the original table/chain identity")
			}
			for i, finish := range held {
				finish()
				address := []string{"127.0.0.2:41001", "[::1]:41002"}[i]
				if counts["tcp/"+address].Load() != beforeHeld[i] {
					t.Fatal("retired established flow delivered unauthorized backend bytes")
				}
			}
			for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41006", 0, true}, {"tcp6", "[::1]:41007", 0, true}, {"udp4", "127.0.0.2:41003", 0, true}} {
				egressProbe(t, p)
			}
			for _, p := range []nativeEgressProbe{{"tcp4", "127.0.0.2:41001", 0, draining}, {"tcp6", "[::1]:41002", 0, draining}} {
				egressRootExchange(t, p.Network, p.Address)
				egressProbe(t, p)
				egressRootExchange(t, p.Network, p.Address)
			}
			guard = g
		}
	})
	t.Logf("actual nft UID=991 reply-only frontends, exact dual-stack backend protocol/IP/port, atomic complete replacement; original table=%d chain=%d; isolated component only, not installed application acceptance", original.TableHandle, original.ChainHandle)
}
