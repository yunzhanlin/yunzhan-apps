//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestWAFNativeProducedBodyThroughRealNginx(t *testing.T) {
	if os.Getenv("PANEL_QA_NGINX_PRODUCED_HTTP") != "1" {
		t.Skip("requires explicit genuine current-source producer private HTTP fixture")
	}
	id := os.Getenv("PANEL_WAF_ENGINE_QA_JOB")
	host, err := os.ReadFile("/etc/hostname")
	if err != nil || os.Geteuid() != 0 || !core.ValidID(id) || strings.TrimSpace(string(host)) != map[string]string{"arm64": "lima-panel-ids24hj-clean-ubuntu24", "amd64": "lima-panel-analytics23t-unit-debian13"}[runtime.GOARCH] {
		t.Fatal("not the exact authorized existing private QA host/root/job")
	}
	const marker = "/etc/panel/.native-waf-http-fixture.json"
	f, err := os.OpenFile(marker, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > 2048 {
		t.Fatal("private fixture marker metadata invalid")
	}
	meta, ok := st.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != 0 || meta.Gid != 0 || meta.Nlink != 1 {
		t.Fatal("private fixture marker not exclusively root-owned")
	}
	var fixture struct {
		Format int    `json:"format"`
		Mount  string `json:"init_mount_namespace"`
		Net    string `json:"init_network_namespace"`
		Job    string `json:"job_id"`
	}
	d := json.NewDecoder(io.LimitReader(f, 2049))
	d.DisallowUnknownFields()
	if d.Decode(&fixture) != nil || fixture.Format != 1 || fixture.Job != id {
		t.Fatal("private fixture marker identity invalid")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !regexp.MustCompile(`^mnt:\[[1-9][0-9]{0,19}\]$`).MatchString(fixture.Mount) || !regexp.MustCompile(`^net:\[[1-9][0-9]{0,19}\]$`).MatchString(fixture.Net) {
		t.Fatal("private fixture marker trailing or namespace metadata invalid")
	}
	for name, original := range map[string]string{"mnt": fixture.Mount, "net": fixture.Net} {
		current, err := os.Readlink("/proc/self/ns/" + name)
		if err != nil || current == original {
			t.Fatal("refuse original mount/network namespace")
		}
	}
	// The normal production verifier proves all five source pins, seventeen
	// patch/license pins, whole sealed tree, current collection contract,
	// actual Nginx/module/library digests and private static-only YAJL linkage.
	if err := VerifyWAFEngineBuild(id); err != nil {
		t.Fatal("genuine current producer verification failed", err)
	}
	record, err := readWAFBuildRecord(id)
	if err != nil {
		t.Fatal(err)
	}
	const base = "/run/panel-waf-produced-http24apg"
	if err := ownedRuntimePath(base, true); err != nil {
		t.Fatal(err)
	}
	manifest := wafQAEngineIdentity{Root: base, State: "ready", Module: filepath.Join(record.Prefix, "nginx/ngx_http_modsecurity_module.so"), ModuleSHA: record.ModuleSHA}
	wafNativeActualBodyResponses(t, base, id, record.NginxBinary, record.NginxVersion, filepath.Join(record.Prefix, "source"), manifest, true)
	if t.Failed() {
		t.Fatal("genuine producer HTTP oracle did not complete successfully")
	}
	t.Log("PASS genuine current-v2 Nginx producer: 69 real HTTP mode cases, 32 concurrent attacks at exact log cap, numeric-only privacy, USR1/same-inode resume; actual workers C0/NNP in all three modes; no site/app activation")
}

func wafProducedPrivateConfigurationSnapshot(t *testing.T) string {
	t.Helper()
	values := map[string]string{}
	for _, root := range []string{"/etc/nginx", "/etc/panel"} {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			values[path] = hex.EncodeToString(sum[:])
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(values)
	return string(data)
}

func verifyWAFProducedHTTPWorkers(t *testing.T, parent int, nginx string, uid int) {
	t.Helper()
	path := filepath.Join("/proc", strconv.Itoa(parent), "task", strconv.Itoa(parent), "children")
	for deadline := time.Now().Add(3 * time.Second); ; {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("actual owned Nginx parent disappeared", err)
		}
		children := strings.Fields(string(data))
		if len(children) == 2 {
			ready := true
			for _, pid := range children {
				if _, err := strconv.ParseUint(pid, 10, 32); err != nil {
					t.Fatal("invalid owned child identity")
				}
				base := filepath.Join("/proc", pid)
				data, err := os.ReadFile(base + "/status")
				if err != nil {
					t.Fatal(err)
				}
				fields := map[string]string{}
				for _, line := range bytes.Split(data, []byte{'\n'}) {
					key, value, ok := strings.Cut(string(line), ":")
					if ok {
						fields[key] = strings.TrimSpace(value)
					}
				}
				ids := strings.Fields(fields["Uid"])
				if len(ids) != 4 || fields["PPid"] != strconv.Itoa(parent) || fields["NoNewPrivs"] != "1" {
					t.Fatal("worker escaped exact identity/parent/NNP")
				}
				if ids[1] == "0" {
					// A listening master may have forked before its child has
					// completed setuid; observe the completed transition only.
					ready = false
					continue
				}
				if ids[1] != strconv.Itoa(uid) || ids[0] != ids[1] || ids[2] != ids[1] || ids[3] != ids[1] {
					t.Fatal("worker selected an unexpected identity")
				}
				for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
					value, err := strconv.ParseUint(fields[name], 16, 64)
					if err != nil || value != 0 {
						t.Fatal("worker retained privilege", name)
					}
				}
				bound, err := strconv.ParseUint(fields["CapBnd"], 16, 64)
				if err != nil || bound & ^uint64(0xeb) != 0 {
					t.Fatal("worker bounding set expanded")
				}
				verifyWAFProducedWorkerExecutableSameUID(t, pid, nginx, uid)
			}
			if ready {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("expected exactly two genuine owned workers", len(children))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Root EB intentionally lacks CAP_SYS_PTRACE, and Linux refuses a different
// UID's /proc/PID/exe even for a dumpable C0 worker. This TEST-ONLY fixed reader
// clears active/inherited/ambient privilege and uses that worker's UID. Never
// widen the production supervisor budget or omit executable identity proof.
func verifyWAFProducedWorkerExecutableSameUID(t *testing.T, pid, nginx string, uid int) {
	t.Helper()
	if uid != 33 {
		t.Fatal("not the fixed private hosts' www-data identity")
	}
	parsed, err := strconv.ParseUint(pid, 10, 32)
	if err != nil || parsed < 2 || strconv.FormatUint(parsed, 10) != pid {
		t.Fatal("non-canonical owned worker PID")
	}
	selected, err := os.Stat(nginx)
	if err != nil || !selected.Mode().IsRegular() {
		t.Fatal("verified Nginx executable disappeared", err)
	}
	selectedMeta, ok := selected.Sys().(*syscall.Stat_t)
	if !ok || selectedMeta.Uid != 0 || selectedMeta.Nlink != 1 || selected.Mode().Perm()&0022 != 0 {
		t.Fatal("selected Nginx executable ownership/link/mode changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/runuser", "-u", "www-data", "--", "/usr/bin/setpriv", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--", "/usr/bin/stat", "-L", "--format=%d:%i", "--", filepath.Join("/proc", pid, "exe"))
	out := &boundedBuffer{max: 128}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		t.Fatal("fixed same-UID executable reader refused", err)
	}
	if out.truncated {
		t.Fatal("fixed inode reader exceeded its numeric output budget")
	}
	dev, ino, err := wafProducedWorkerExecutableInode(out.Bytes())
	if err != nil || dev != uint64(selectedMeta.Dev) || ino != selectedMeta.Ino {
		t.Fatal("owned worker is not the exact verified Nginx inode", err)
	}
}

func wafProducedWorkerExecutableInode(data []byte) (uint64, uint64, error) {
	if len(data) < 4 || len(data) > 128 || !bytes.HasSuffix(data, []byte{'\n'}) || bytes.ContainsAny(data[:len(data)-1], "\n\r\x00") {
		return 0, 0, errors.New("invalid fixed numeric inode record")
	}
	parts := strings.Split(string(data[:len(data)-1]), ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid fixed inode fields")
	}
	values := [2]uint64{}
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != part {
			return 0, 0, errors.New("invalid canonical inode field")
		}
		values[index] = value
	}
	return values[0], values[1], nil
}

func TestWAFProducedWorkerExecutableInodeRecordIsClosed(t *testing.T) {
	dev, ino, err := wafProducedWorkerExecutableInode([]byte("8388625:123456\n"))
	if err != nil || dev != 8388625 || ino != 123456 {
		t.Fatal("canonical numeric inode rejected", err)
	}
	for _, value := range []string{"", "1:2", "1:2\nextra", "1:2\n\n", "1:2\r\n", "1:2\x00\n", "01:2\n", "1:02\n", "0:2\n", "1:0\n", "-1:2\n", "1:+2\n", "1:2:3\n", "18446744073709551616:2\n", strings.Repeat("1", 129) + ":2\n"} {
		if _, _, err := wafProducedWorkerExecutableInode([]byte(value)); err == nil {
			t.Fatal("malformed reader record accepted")
		}
	}
}
