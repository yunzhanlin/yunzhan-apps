package diskjob

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func selectionFixture() Selection {
	return Selection{BootID: "00000000-0000-4000-8000-000000000001", NamespaceID: "4:4026531841", MountID: "9007199254740993", MountSHA: strings.Repeat("a", 64), Directory: "srv/磁盘\u00a0分析", AppVersion: HostAppVersion, InstallationID: strings.Repeat("b", 32), AppSHA: strings.Repeat("c", 64)}
}

func TestHostSelectionClosedExactStringsAndNoAuthorityExpansion(t *testing.T) {
	f := selectionFixture()
	raw, _ := json.Marshal(f)
	in, err := DecodeSelection(raw)
	if err != nil || in != f {
		t.Fatal(in, err)
	}
	for _, replace := range [][2]string{{`"mount_id"`, `"Mount_Id"`}, {`"mount_id":"9007199254740993"`, `"mount_id":9007199254740993`}, {`"mount_id":"9007199254740993"`, `"mount_id":null`}, {`"mount_id":"9007199254740993"`, `"mount_id":"9007199254740993","mount_id":"9007199254740993"`}, {`"app_version":"1.4.0"`, `"app_version":"1.3.0"`}} {
		if _, err := DecodeSelection([]byte(strings.Replace(string(raw), replace[0], replace[1], 1))); !errors.Is(err, ErrSelection) {
			t.Fatal("alias/null/numeric/duplicate/old version accepted")
		}
	}
	for _, bad := range []string{string(raw) + "{}", strings.TrimSuffix(string(raw), "}") + `,"actor_id":"` + strings.Repeat("d", 32) + `"}`, strings.TrimSuffix(string(raw), "}") + `,"root":"/"}`} {
		if _, err := DecodeSelection([]byte(bad)); !errors.Is(err, ErrSelection) {
			t.Fatal("public selection accepted authority/path override or trailing input")
		}
	}
	for _, p := range []string{"/etc", ".", "..", "a/../b", "a//b", "a/", "raw-\xff", "control\n"} {
		f.Directory = p
		if ValidateSelection(f) == nil {
			t.Fatal("unsafe directory accepted")
		}
	}
	for _, p := range []string{"", `literal\040`, "a/b", "空 格"} {
		if !RelativeDirectory(p) {
			t.Fatal("valid native relative directory rejected", p)
		}
	}
}

func TestHostPrivateRequestKeepsActorRevisionAndSelection(t *testing.T) {
	f := Request{Format: 1, JobID: strings.Repeat("e", 32), ActorID: strings.Repeat("f", 32), AccessRevision: "9007199254740993", Selection: selectionFixture()}
	raw, _ := json.Marshal(f)
	in, err := DecodeRequest(raw)
	if err != nil || !reflect.DeepEqual(in, f) {
		t.Fatal(in, err)
	}
	for _, bad := range []string{strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1), strings.Replace(string(raw), `"actor_id"`, `"Actor_Id"`, 1), strings.Replace(string(raw), `"access_revision":"9007199254740993"`, `"access_revision":null`, 1), strings.TrimSuffix(string(raw), "}") + `,"command":"du"}`} {
		if _, err := DecodeRequest([]byte(bad)); !errors.Is(err, ErrSelection) {
			t.Fatal("private job accepted ambiguous or arbitrary authority/command")
		}
	}
	for _, value := range []string{"0", "01", "+1", "-1", "18446744073709551616"} {
		f.AccessRevision = value
		if ValidateRequest(f) == nil {
			t.Fatal("noncanonical revision accepted")
		}
	}
}

func TestHostLaunchIsFixedNoShellOrSandboxSubstitution(t *testing.T) {
	id := strings.Repeat("1", 32)
	for _, exe := range []string{"/opt/panel/bin/panel-executor", "/opt/panel/current/bin/panel-executor", "/opt/panel/releases/0.1.0-dev.proapps24diskhost/bin/panel-executor"} {
		for _, inventory := range []bool{false, true} {
			args, err := LaunchArguments(id, exe, inventory)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(args, " ")
			for _, required := range []string{"--scope", "MemoryMax=512M", "CPUQuota=20%", "TasksMax=32", "IOWeight=10", "/usr/bin/nsenter --mount=/proc/1/ns/mnt --root=/proc/1/root --wdns=/ -- /usr/bin/setpriv", "--bounding-set=-all,+dac_read_search", "--no-new-privs"} {
				if !strings.Contains(joined, required) {
					t.Fatal("missing exact launch guard", required)
				}
			}
			if args[len(args)-2] != exe || strings.Contains(joined, "/bin/sh") || strings.Contains(joined, "CAP_SYS_PTRACE") || strings.Contains(joined, "ProtectHome=") {
				t.Fatal("fixed worker altered namespace/root or broadened capabilities")
			}
			if inventory && !strings.Contains(joined, "RuntimeMaxSec=10s") || !inventory && !strings.Contains(joined, "RuntimeMaxSec=1800s") {
				t.Fatal("deadline not bound to mode")
			}
		}
	}
	for _, exe := range []string{"/tmp/worker", "/opt/panel/bin/../bin/panel-executor", "/opt/panel/releases/../../tmp/bin/panel-executor", "/bin/sh", "/opt/panel/current/bin/panel-executor --root=/"} {
		if _, err := LaunchArguments(id, exe, false); !errors.Is(err, ErrLaunch) {
			t.Fatal("arbitrary binary/argument accepted")
		}
	}
	if _, err := LaunchArguments(id+";id", "/opt/panel/bin/panel-executor", false); !errors.Is(err, ErrLaunch) {
		t.Fatal("unit command injection accepted")
	}
}
