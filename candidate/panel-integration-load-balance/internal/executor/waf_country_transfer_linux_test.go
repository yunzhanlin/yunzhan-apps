//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
)

func countryTransferStatusFixture(uid, gid uint32, supervisor bool) string {
	active := "0000000000000000"
	if supervisor {
		active = countrySupervisorCapabilities
	}
	return fmt.Sprintf("Name:\tfixture\nUid:\t%d %d %d %d\nGid:\t%d %d %d %d\nGroups:\t\nNoNewPrivs:\t1\nCapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\nCapBnd:\t%s\nCapAmb:\t%s\n", uid, uid, uid, uid, gid, gid, gid, gid, active, active, active, countrySupervisorCapabilities, active)
}

func TestCountryTransferProcessStatusClosed(t *testing.T) {
	for _, supervisor := range []bool{false, true} {
		uid, gid := uint32(65534), uint32(65534)
		if supervisor {
			uid, gid = 0, 0
		}
		good := countryTransferStatusFixture(uid, gid, supervisor)
		if !countryProcessStatus([]byte(good), uid, gid, supervisor) {
			t.Fatal("closed original privilege fixture rejected", supervisor)
		}
		for i, raw := range []string{"", good + "Uid:\t0 0 0 0\n", strings.TrimSuffix(good, "\n"), good + "\x00", strings.Replace(good, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(good, "CapInh:\t"+strings.Fields(strings.Split(good, "CapInh:")[1])[0], "CapInh:\t0000000000000001", 1), strings.Replace(good, "CapAmb:\t"+strings.Fields(strings.Split(good, "CapAmb:")[1])[0], "CapAmb:\t0000000000000001", 1), strings.Replace(good, countrySupervisorCapabilities, "00000000000000e3", 1), strings.Replace(good, "Groups:\t\n", "Groups:\t123\n", 1), strings.Replace(good, "Gid:", "MissingGid:", 1)} {
			if countryProcessStatus([]byte(raw), uid, gid, supervisor) {
				t.Fatal("malformed/escalated process accepted", supervisor, i)
			}
		}
	}
}

func TestCountryTransferProtocolClosedOriginalSelection(t *testing.T) {
	in := core.WAFCountryDataSelection{Action: "download", AppVersion: core.WAFCountryDataVersion, AppManifestSHA: core.Hash("synthetic app"), InstallationSHA: core.Hash("synthetic instance"), Release: "2026-10", Revision: 1, DataManifestSHA: core.Hash("synthetic data"), Countries: []string{"CN", "US"}}
	envelope, _ := json.Marshal(appcatalog.GeoDataEnvelope{AppCatalog: []byte("not signed"), AppSignature: []byte("not signed"), AppManifest: []byte("not signed"), DataManifest: []byte("not signed"), DataSignature: []byte("not signed")})
	raw, _ := json.Marshal(countryTransferInput{1, in, "CN", envelope})
	if _, err := decodeCountryTransfer(raw); err != nil {
		t.Fatal("shape-only fixture rejected; this is NOT signature authority", err)
	}
	for i, bad := range [][]byte{nil, append(bytes.Clone(raw), '\n'), []byte(strings.Replace(string(raw), `"format":1`, `"FORMAT":1`, 1)), []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1)), []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"url":"https://example.invalid"`, 1)), []byte(strings.Replace(string(raw), `"code":"CN"`, `"code":"ZZ"`, 1)), []byte(strings.Replace(string(raw), `"countries":["CN","US"]`, `"countries":["US","CN"]`, 1)), []byte(strings.Replace(string(raw), `"envelope":{`, `"envelope":{"key":"not accepted",`, 1)), []byte(strings.Repeat(" ", countryTransferProtocolLimit+1))} {
		if _, err := decodeCountryTransfer(bad); err == nil {
			t.Fatal("unknown/alias/duplicate/unbound/oversize input accepted", i)
		}
	}
}

func TestCountryTransferWriteOnlyOriginalDescriptor(t *testing.T) {
	f := newCountryCacheFixture(t)
	file, err := os.OpenFile(filepath.Join(filepath.Dir(f.store.base), "original.cidr"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := countryTransferFileIdentity(file, true); err == nil {
		t.Fatal("read/write descriptor crossed child boundary")
	}
	write, err := countryWriteOnlyHandle(file)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	if _, err := write.Read(make([]byte, 1)); err == nil {
		t.Fatal("write-only child handle permits reading")
	}
	if _, err := write.WriteString("only this original file"); err != nil {
		t.Fatal(err)
	}
	if _, err := countryTransferFileIdentity(write, true); err == nil {
		t.Fatal("nonempty original accepted for replay")
	}
	if _, err := countryWriteOnlyHandle(file); err == nil {
		t.Fatal("nonempty original was reopened for another transfer")
	}
	for _, identity := range []countryNetworkIdentity{{}, {1, 0, 1}, {1, 1, 0}, {1, 1000, 1}, {1, 1, 1000}, {2, 123, 123}} {
		if validCountryNetworkIdentity(identity) {
			t.Fatal("non-dedicated system identity accepted", identity)
		}
	}
}

// Opt-in REAL changed-UID kernel/FD/socket/cancellation proof in a private QA
// unit with the exact production supervisor capability budget. No account is
// created, no provider bytes downloaded and no installed WAF policy is changed.
func TestCountryTransferNative(t *testing.T) {
	if os.Getenv("PANEL_QA_COUNTRY_TRANSFER_NATIVE") != "1" {
		t.Skip("explicit private native country privilege fixture required")
	}
	if err := countryCheckOwnProcess(true); err != nil {
		t.Fatal(err)
	}
	reader, err := openDiskHostCoreReader()
	if err != nil {
		t.Fatal("supervisor cannot read fixed Core authorization under readonly host", err)
	}
	defer reader.db.Close()
	var migrationCount int
	if reader.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&migrationCount) != nil || migrationCount < 1 || !reader.current() {
		t.Fatal("actual readonly Core authorization read did not complete")
	}
	const uid, gid = uint32(65534), uint32(65534)
	file, err := os.OpenFile("native-original.cidr", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	write, err := countryWriteOnlyHandle(file)
	if err != nil {
		t.Fatal(err)
	}
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd, executable, err := countryTransferCommand(ctx, countryNetworkIdentity{1, uid, gid}, write)
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	cmd.Args = append(cmd.Args[:len(cmd.Args)-1], "-test.run=^TestCountryTransferNativeChild$", "-test.v", "-test.count=1")
	cmd.Env = append(cmd.Env, "PANEL_QA_COUNTRY_TRANSFER_CHILD=1")
	out := &boundedBuffer{max: 8192}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for fileInfo, e := file.Stat(); e == nil && fileInfo.Size() == 0 && time.Now().Before(deadline); fileInfo, e = file.Stat() {
		time.Sleep(5 * time.Millisecond)
	}
	raw, err := io.ReadAll(io.NewSectionReader(file, 0, 4096))
	if err != nil || string(raw) != "original-low-privilege-only\n" {
		cancel()
		<-wait
		t.Fatal("real non-root child did not confirm FD and closed permissions", string(raw), err, out.String())
	}
	// CAP_KILL is necessary here: Root's changed-UID child must actually be
	// cancelled/reaped, not left running after a request deadline.
	cancel()
	select {
	case err := <-wait:
		var exited *exec.ExitError
		if !errors.As(err, &exited) || ctx.Err() == nil {
			t.Fatal("actual changed-UID cancellation was not observed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("own low-privilege child was not collected")
	}
	if unix.Kill(cmd.Process.Pid, 0) != syscall.ESRCH {
		t.Fatal("own cancelled child still exists")
	}
	info, err := file.Stat()
	if err != nil || !moduleRecordInfo(info, false, false) {
		t.Fatal("original output was re-owned or made public", err)
	}
}

func TestCountryTransferNativeChild(t *testing.T) {
	if os.Getenv("PANEL_QA_COUNTRY_TRANSFER_CHILD") != "1" {
		t.Skip("only the fresh owned private native parent may spawn this fixture")
	}
	if os.Geteuid() != 65534 || os.Getegid() != 65534 || countryCheckOwnProcess(false) != nil {
		t.Fatal("actual changed-UID/NNP/zero active capability boundary missing")
	}
	file := os.NewFile(3, "original-country-only")
	defer file.Close()
	if _, err := countryTransferFileIdentity(file, true); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Read(make([]byte, 1)); err == nil {
		t.Fatal("child received readable original data FD")
	}
	if err := file.Chmod(0644); err == nil {
		t.Fatal("non-root child can change Root file permissions")
	}
	for _, path := range []string{"/var/lib/panel/panel.db", "/etc/panel/panel-access.conf", "/proc/self/fd/3"} {
		if file, err := os.Open(path); err == nil {
			file.Close()
			t.Fatal("child unexpectedly read a private Root/Core path", path)
		}
	}
	dialer := net.Dialer{Timeout: time.Second}
	if conn, err := dialer.Dial("unix", "/run/panel-executor/control.sock"); err == nil {
		conn.Close()
		t.Fatal("child can connect to Root control socket")
	}
	if _, err := file.WriteString("original-low-privilege-only\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	t.Log("actual kernel boundary confirmed at child " + strconv.Itoa(os.Getpid()))
	time.Sleep(15 * time.Second) // Parent must cancel/reap THIS owned child early.
	t.Fatal("private parent did not cancel original child")
}
