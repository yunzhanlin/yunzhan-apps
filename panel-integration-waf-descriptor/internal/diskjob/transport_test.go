package diskjob

import (
	"encoding/json"
	"strings"
	"testing"

	"local/panel/internal/diskusage"
)

func TestHostInventoryWireCompleteBoundedAndNoHiddenMountCredentials(t *testing.T) {
	mounts, err := diskusage.ParseMountInfo(strings.NewReader("31 1 8:1 / / rw - ext4 /dev/fixture rw,password=PRIVATE_FIXTURE\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := Inventory{Host: Host{BootID: selectionFixture().BootID, NamespaceID: selectionFixture().NamespaceID}, Mounts: mounts}
	raw, err := EncodeInventory(in)
	if err != nil || strings.Contains(string(raw), "PRIVATE_FIXTURE") {
		t.Fatal("raw credential/options emitted", err)
	}
	if _, err := DecodeInventory(raw); err != nil {
		t.Fatal(err)
	}
	for _, replace := range [][2]string{
		{`"mount_list_complete":true`, `"mount_list_complete":false`},
		{`"snapshot_consistent":false`, `"snapshot_consistent":true`},
		{`"mount_id":"31"`, `"mount_id":31`},
		{`"mount_id":"31"`, `"mount_id":"31","mount_id":"31"`},
		{`"filesystem_class":"local"`, `"filesystem_class":"pretend-local"`},
		{`"inventory":{`, `"inventory":{"source":"secret",`},
	} {
		bad := strings.Replace(string(raw), replace[0], replace[1], 1)
		if bad == string(raw) {
			t.Fatal("mutation missed actual wire", replace)
		}
		if _, err := DecodeInventory([]byte(bad)); err == nil {
			t.Fatal("ambiguous/partial inventory accepted", replace)
		}
	}
	if _, err := DecodeInventory(make([]byte, InventoryBytesMax+1)); err == nil {
		t.Fatal("oversized collector frame accepted")
	}
	state := HostState{Format: 1, Installed: true, AppVersion: HostAppVersion, InstallationID: selectionFixture().InstallationID, AppSHA: selectionFixture().AppSHA, Inventory: &in}
	if ValidateHostState(state) != nil {
		t.Fatal("complete original state refused")
	}
	state.Inventory = nil
	if ValidateHostState(state) == nil {
		t.Fatal("1.4 authority claimed without complete native inventory")
	}
	state.AppVersion = "1.3.0"
	state.InstallationID = ""
	state.AppSHA = ""
	if ValidateHostState(state) != nil {
		t.Fatal("legacy app cannot show explicit upgrade-required state")
	}
}

func TestHostLauncherExitIsNotScanCompletion(t *testing.T) {
	in, d, _, _ := receiptFixture()
	code := 1
	launch := Launcher{Format: 1, RequestSHA: d.RequestSHA, ExecutorSHA: d.ExecutorSHA, State: "exited", ExitCode: &code, At: "2026-10-15T00:00:01Z"}
	raw, _ := json.Marshal(launch)
	if _, err := DecodeLauncher(raw, d, in); err != nil {
		t.Fatal(err)
	}
	o := Observation{Format: 1, Request: in, State: "uncertain", Process: "unknown", Scope: "empty", Launcher: &launch}
	if ValidateObservation(o, in) != nil {
		t.Fatal("failed pre-start launch cannot be exposed as uncertain")
	}
	o.State = "starting"
	if ValidateObservation(o, in) == nil {
		t.Fatal("already-exited launcher displayed as still starting")
	}
	o.State = "failed"
	o.TerminalVerified = true
	if ValidateObservation(o, in) == nil {
		t.Fatal("launcher exit became fake typed scan completion")
	}
	launch.State = "not_started"
	raw, _ = json.Marshal(launch)
	if _, err := DecodeLauncher(raw, d, in); err == nil {
		t.Fatal("contradictory no-start receipt retained exit code")
	}
	launch.ExitCode = nil
	raw, _ = json.Marshal(launch)
	if _, err := DecodeLauncher(raw, d, in); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(raw), `"state":"not_started"`, `"state":"not_started","state":"not_started"`, 1)
	if _, err := DecodeLauncher([]byte(bad), d, in); err == nil {
		t.Fatal("duplicate root launch state accepted")
	}
}
