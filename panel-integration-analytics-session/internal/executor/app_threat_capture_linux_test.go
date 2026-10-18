//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real kernel capture against a new loopback-only fixture. It never probes a
// reference or user website, changes a firewall, installs system Suricata, or
// mistakes a syntax check/offline pcap for live capture.
func TestThreatIDSPrivateRuntimeNativePassiveCapture(t *testing.T) {
	threatIDSNativeQA(t)
	beforeUnits := threatIDSNativeUnits(t)
	beforePackages := threatIDSNativePackages(t)
	service := New(Config{})
	runtime, err := service.threatIDSRuntime()
	if err != nil {
		t.Fatal(err)
	}
	in := threatIDSConfig{Interface: "lo", HomeNetworks: []string{"127.0.0.1/32", "::1/128"}}
	yaml, err := threatIDSYAML(in, "/opt/panel/app-modules/network-threat-detection/rules/cloudstack.rules", "/var/lib/panel-network-ids/logs")
	if err != nil {
		t.Fatal(err)
	}
	// Only own brand-new fixed unit/config; preserve any prior live attempt.
	for _, path := range []string{"/etc/panel/network-ids/suricata.yaml", "/etc/systemd/system/panel-network-ids.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("existing live attempt must be retained", path)
		}
	}
	if err := threatIDSTrustedParents("/etc/panel/network-ids", true); err != nil {
		t.Fatal(err)
	}
	if err := threatIDSTrustedParents("/var/lib/panel-network-ids/logs", false); err != nil {
		t.Fatal(err)
	}
	// -T opens an empty output file. Preserve only that exact root-owned,
	// single-link zero-byte fixture separately; never truncate actual events.
	if info, err := os.Lstat("/var/lib/panel-network-ids/logs/eve.json"); err == nil {
		if !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0640 || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
			t.Fatal("existing EVE is not the empty syntax fixture; preserve")
		}
		retained, err := os.MkdirTemp("/var/lib/panel-executor", "ids-empty-syntax-")
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Renameat2(unix.AT_FDCWD, "/var/lib/panel-network-ids/logs/eve.json", unix.AT_FDCWD, retained+"/eve.json", unix.RENAME_NOREPLACE); err != nil {
			t.Fatal("retain empty syntax output", err)
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if existing, err := user.Lookup("panel-network-ids"); err == nil {
		var ownership struct {
			Format         int    `json:"format"`
			UID            string `json:"uid"`
			GID            string `json:"gid"`
			FailedProofSHA string `json:"failed_proof_sha256"`
		}
		b, e := ftpPrivateRead("/var/lib/panel-network-ids/qa-account-ownership.json", 2048)
		if e != nil || decodeFTPPrivateJSON(b, &ownership) != nil || ownership.Format != 1 || ownership.UID != existing.Uid || ownership.GID != existing.Gid || !threatPackageSHA.MatchString(ownership.FailedProofSHA) {
			t.Fatal("pre-existing capture account cannot be adopted")
		}
	} else if _, ok := err.(user.UnknownUserError); !ok {
		t.Fatal(err)
	} else if output, err := exec.Command("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "panel-network-ids").CombinedOutput(); err != nil {
		t.Fatal("fixed private account", string(output), err)
	}
	account, err := user.Lookup("panel-network-ids")
	if err != nil {
		t.Fatal(err)
	}
	uid, e1 := strconv.Atoi(account.Uid)
	gid, e2 := strconv.Atoi(account.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 || uid >= 1000 || gid >= 1000 || account.HomeDir != "/nonexistent" {
		t.Fatal("capture account identity")
	}
	if err := os.Chown("/var/lib/panel-network-ids/logs", uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("/var/lib/panel-network-ids/logs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite("/etc/panel/network-ids/suricata.yaml", []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	unit, err := threatIDSUnit(runtime.Prefix, in)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite("/etc/systemd/system/panel-network-ids.service", []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/usr/bin/systemd-analyze", "verify", "/etc/systemd/system/panel-network-ids.service").CombinedOutput(); err != nil || len(bytes.TrimSpace(output)) != 0 {
		t.Fatal("actual generated unit validation", string(output), err)
	}
	t.Cleanup(func() {
		output, e := exec.Command("/usr/bin/systemctl", "stop", "panel-network-ids").CombinedOutput()
		if e != nil {
			t.Errorf("own QA capture stop failed %s %v", output, e)
		}
	})
	if output, err := exec.Command("/usr/bin/systemctl", "daemon-reload").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	started := time.Now()
	if output, err := exec.Command("/usr/bin/systemctl", "start", "panel-network-ids").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	var pid int
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		data, e := exec.Command("/usr/bin/systemctl", "show", "--value", "--property=MainPID", "panel-network-ids").Output()
		if e != nil {
			t.Fatal(e)
		}
		pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		if pid > 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if pid <= 1 {
		t.Fatal("capture did not start; inspect retained unit journal")
	}
	time.Sleep(time.Second)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal("actual capture process exited", err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(status), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	wantedUID := fmt.Sprintf("%d\t%d\t%d\t%d", uid, uid, uid, uid)
	if fields["Uid"] != wantedUID || fields["CapEff"] != "0000000000002000" || fields["CapBnd"] != "0000000000002000" || fields["NoNewPrivs"] != "1" {
		t.Fatal("actual non-root/capability boundary differs", fields["Uid"], fields["CapEff"], fields["CapBnd"], fields["NoNewPrivs"])
	}
	actualExe, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		t.Fatal(err)
	}
	expectedExe, err := os.Stat(runtime.Binary)
	if err != nil || !os.SameFile(actualExe, expectedExe) {
		t.Fatal("actual process is not verified runtime", err)
	}
	limits, err := exec.Command("/usr/bin/systemctl", "show", "--property=MemoryMax,MemorySwapMax,TasksMax,LimitFSIZE,User,Group,ProtectSystem,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities", "panel-network-ids").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"MemoryMax=402653184\n", "MemorySwapMax=0\n", "TasksMax=32\n", "LimitFSIZE=8388608\n", "User=panel-network-ids\n", "Group=panel-network-ids\n", "ProtectSystem=strict\n", "NoNewPrivileges=yes\n", "CapabilityBoundingSet=cap_net_raw\n", "AmbientCapabilities=cap_net_raw\n"} {
		if !strings.Contains(string(limits), part) {
			t.Fatal("actual unit boundary", part, string(limits))
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &http.Server{ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		w.Header().Set("Connection", "close")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "fixture-ok")
	})}
	go func() { _ = fixture.Serve(listener) }()
	defer fixture.Close()
	marker := "IDS_PRIVATE_SENTINEL_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	send := func(method, path, ua, body string) {
		conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: fixture.invalid\r\nUser-Agent: %s\r\nCookie: session=%s\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", method, path, ua, marker, marker, len(body), body)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(io.LimitReader(conn, 4096))
		if err != nil || !bytes.Contains(response, []byte("200 OK")) {
			t.Fatal("passive IDS altered fixture response", err)
		}
	}
	send("GET", "/clean?token="+marker, "normal-private-client", "")
	send("GET", "/../private?token="+marker, "normal-private-client", "")
	send("GET", "/%2e%2e/private?token="+marker, "normal-private-client", "")
	send("GET", "/scanner?token="+marker, "sqlmap/"+marker, "")
	send("TRACE", "/trace?token="+marker, "normal-private-client", "")
	send("POST", "/body?token="+marker, "normal-private-client", marker+" /bin/sh")
	var report threatEVEReport
	deadline = time.Now().Add(25 * time.Second)
	wantedIDs := map[uint32]bool{9000001: false, 9000002: false, 9000003: false, 9000004: false, 9000005: false}
	var raw []byte
	for time.Now().Before(deadline) {
		raw, err = os.ReadFile("/var/lib/panel-network-ids/logs/eve.json")
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if len(raw) > threatEVEByteLimit {
			t.Fatal("live output exceeded hard ceiling")
		}
		report, err = readThreatEVE(context.Background(), bytes.NewReader(raw), threatEVEFilter{Limit: 200}, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, alert := range report.Alerts {
			if _, ok := wantedIDs[alert.SignatureID]; ok {
				wantedIDs[alert.SignatureID] = true
			}
		}
		complete := true
		for _, found := range wantedIDs {
			complete = complete && found
		}
		if complete && threatIDSCaptureState(report.Stats, time.Now(), started, true) == "observing" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	for id, found := range wantedIDs {
		if !found {
			t.Fatal("real HTTP rule did not detect own fixture", id, "records", report.ScannedRecords, "invalid", report.InvalidRecords)
		}
	}
	if report.InvalidRecords != 0 || report.Partial || threatIDSCaptureState(report.Stats, time.Now(), started, true) != "observing" || *report.Stats.KernelPackets == 0 || *report.Stats.DecodedPackets == 0 {
		t.Fatal("fresh actual packet counters missing/incomplete", report)
	}
	for _, forbidden := range []string{marker, base64.StdEncoding.EncodeToString([]byte(marker)), `"payload"`, `"packet"`, `"http_body"`, `"request_headers"`, `"raw_rule"`, `fixture.invalid`, `normal-private-client`} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private request data persisted in actual EVE", forbidden)
		}
	}
	// Stats legitimately contain numeric protocol counters named http/dns.
	// Check decoded application metadata on actual alert records, not names
	// anywhere in numeric stats (which would reject a private valid capture).
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var entry map[string]json.RawMessage
		if json.Unmarshal(line, &entry) != nil {
			t.Fatal("actual EVE record invalid")
		}
		if string(entry["event_type"]) != `"alert"` {
			continue
		}
		for _, field := range []string{"http", "dns", "smtp", "fileinfo", "flow", "payload", "packet", "metadata", "http_body", "request_headers"} {
			if _, ok := entry[field]; ok {
				t.Fatal("decoded private application data present on actual alert", field)
			}
		}
	}
	for _, alert := range report.Alerts {
		if alert.Action != "allowed" || alert.SourceIP != "127.0.0.1" || alert.DestinationIP != "127.0.0.1" {
			t.Fatal("capture is not passive fixture metadata", alert)
		}
	}
	info, err := os.Lstat("/var/lib/panel-network-ids/logs/eve.json")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Fatal("actual EVE ownership/mode", err)
	}
	if output, err := exec.Command("/usr/bin/systemctl", "stop", "panel-network-ids").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	afterPackages := threatIDSNativePackages(t)
	for name, version := range beforePackages {
		if afterPackages[name] != version {
			t.Fatal("capture changed existing package", name)
		}
	}
	for name, state := range beforeUnits {
		if threatIDSNativeUnits(t)[name] != state {
			t.Fatal("capture changed original service identity", name)
		}
	}
	result, _ := json.Marshal(map[string]any{"live_passive_capture": true, "actual_uid": uid, "effective_capabilities": "NET_RAW only", "actual_alert_rule_ids": wantedIDs, "actual_stats": report.Stats, "private_payload_persisted": false, "original_package_versions_and_service_pids_preserved": true, "unit_sha256": fmt.Sprintf("%x", sha256Bytes([]byte(unit))), "signed_installed_api_and_gui_verified": false})
	t.Log("PASS actual non-root kernel capture, five real HTTP rules, unchanged responses, fresh real counters, private logs and no payload; " + string(result))
}

func sha256Bytes(data []byte) [32]byte { return sha256.Sum256(data) }
