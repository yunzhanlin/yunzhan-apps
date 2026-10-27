//go:build linux

package executor

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamColdBootAbsenceRejectsPartialOrAnyServiceCredential(t *testing.T) {
	good := []byte("Name:\tother\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")
	if !streamColdStatusUIDAbsent(good, 991) {
		t.Fatal("complete other-UID process was refused")
	}
	for _, raw := range [][]byte{
		nil, []byte("Name:\tmissing UID\n"), []byte("Uid:\t0\t0\t0\n"), []byte("Uid:\t0\t0\t0\t0"),
		[]byte("Uid:\t0\t0\t0\t0\nUid:\t0\t0\t0\t0\n"), []byte("Uid:\t0\t0\t00\t0\n"),
		[]byte("Uid:\t0\t0\t4294967296\t0\n"), []byte("Uid:\t0\t0\t0\t0\n\x00"), []byte(strings.Repeat("x", 65536) + "\n"),
		[]byte("Uid:\t991\t0\t0\t0\n"), []byte("Uid:\t0\t991\t0\t0\n"), []byte("Uid:\t0\t0\t991\t0\n"), []byte("Uid:\t0\t0\t0\t991\n"),
	} {
		if streamColdStatusUIDAbsent(raw, 991) {
			t.Fatal("partial/malformed or real/effective/saved/fs service UID became absence")
		}
	}
	unit := map[string]string{"LoadState": "not-found", "ActiveState": "inactive", "SubState": "dead", "MainPID": "0", "ControlPID": "0", "InvocationID": "", "ExecMainStatus": "0", "Result": "success"}
	if !streamColdUnitAbsent(unit) {
		t.Fatal("complete absent unit refused")
	}
	delete(unit, "InvocationID")
	if streamColdUnitAbsent(unit) {
		t.Fatal("missing field became empty original invocation")
	}
	unit["InvocationID"], unit["LoadState"] = "", "loaded"
	if streamColdUnitAbsent(unit) {
		t.Fatal("inactive but loaded unit became absent")
	}
}

func TestLoadBalanceStreamColdBootMissingOriginalCannotRecover(t *testing.T) {
	ctx := context.Background()
	for _, store := range []*loadBalanceStreamConfigurationStore{nil, {}, {first: true}, {released: true}, {priorCaptured: true}, {priorColdBoot: &loadBalanceStreamColdBootWitness{}}} {
		if err := store.observeColdBoot(ctx); err != loadbalancestream.ErrService {
			t.Fatal("missing original generation acquired cold recovery", err)
		}
		for _, witness := range []*loadBalanceStreamColdBootWitness{nil, {}, {uid: 991}} {
			if witness.identityCurrent(ctx, store) != loadbalancestream.ErrService || witness.current(ctx, store) != loadbalancestream.ErrService {
				t.Fatal("claimed metadata became native authority")
			}
		}
	}
	if streamColdUIDAbsent(nil, 991) != loadbalancestream.ErrService || streamColdUIDAbsent(ctx, 0) != loadbalancestream.ErrService {
		t.Fatal("missing context or root identity acquired service absence")
	}
}

func TestLoadBalanceStreamColdBootNativeUIDCensusSeesForeignLiveProcess(t *testing.T) {
	if os.Getenv("PANEL_NATIVE_QA") != "1" || os.Getenv("PANEL_LBSTREAM_EGRESS_PRIVATE_NETNS_QA") != "20261027" {
		t.Skip("explicit isolated native QA only")
	}
	host, e1 := os.Readlink("/proc/1/ns/net")
	self, e2 := os.Readlink("/proc/self/ns/net")
	if os.Geteuid() != 0 || e1 != nil || e2 != nil || host == self || host != os.Getenv("PANEL_LBSTREAM_EGRESS_QA_HOST_NETNS") {
		t.Fatal("new isolated network namespace and real Root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Never assume 991 is unused: Ubuntu assigns it to systemd-resolved.
	// Pick a fixture-only UID/GID absent from both held local NSS originals;
	// a complete native process census must STILL prove it has no live owner.
	used := make(map[uint32]bool)
	for _, name := range []string{"/etc/passwd", "/etc/group"} {
		file, raw, err := openMemcachedUnixNSSFile(name)
		if err != nil {
			t.Fatal("cannot hold original fixture identity inventory", err)
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) != 7 && name == "/etc/passwd" || len(fields) != 4 && name == "/etc/group" {
				t.Fatal("incomplete original local identity inventory")
			}
			id, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil || strconv.FormatUint(id, 10) != fields[2] {
				t.Fatal("noncanonical original local identity")
			}
			used[uint32(id)] = true
		}
		stable := file.current()
		clear(raw)
		file.file.Close()
		if !stable {
			t.Fatal("original local identity inventory changed")
		}
	}
	uid := uint32(930)
	for used[uid] && uid < 980 {
		uid++
	}
	if uid >= 980 {
		t.Fatal("no unused local fixture identity; no account is adopted")
	}
	if err := streamColdUIDAbsent(ctx, uid); err != nil {
		t.Fatal("baseline service UID is occupied or proc census incomplete", err)
	}
	// A fixture-only ordinary cat, with no saved service PID/cgroup/name. It
	// stays in the test's cgroup rather than any panel-lbstream service cgroup.
	// No NSS file, installed service, host firewall or filesystem is changed.
	command := exec.CommandContext(ctx, "/usr/bin/cat")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid, NoSetGroups: true}}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		stdin.Close()
		if !waited {
			command.Wait()
		}
	}()
	if _, err := io.WriteString(stdin, "ready\n"); err != nil {
		t.Fatal(err)
	}
	if ready, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || ready != "ready\n" {
		t.Fatal("actual foreign service-UID process did not become live", err)
	}
	if streamColdUIDAbsent(ctx, uid) != loadbalancestream.ErrService {
		t.Fatal("live same-UID process outside service cgroup was missed")
	}
	stdin.Close()
	err = command.Wait()
	waited = true
	if err != nil || streamColdUIDAbsent(ctx, uid) != nil {
		t.Fatal("own child did not exit cleanly or absence census failed", err)
	}
	t.Logf("component_only=true unused_local_uid=%d foreign_live_uid_denied=true original_service_activated=false", uid)
}
