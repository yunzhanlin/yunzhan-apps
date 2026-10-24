//go:build linux

package executor

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func redisPrivilegeModel(t *testing.T, fail string) (redisPrivilegeOps, *[]string) {
	t.Helper()
	calls := []string{}
	step := func(name string) error {
		calls = append(calls, name)
		if fail == name {
			return errors.New("own injected boundary failure")
		}
		return nil
	}
	return redisPrivilegeOps{
		root: func() bool { calls = append(calls, "root"); return fail != "not-root" },
		noNewPrivs: func() (int, error) {
			if err := step("nnp"); err != nil {
				return 0, err
			}
			if fail == "nnp-off" {
				return 0, nil
			}
			return 1, nil
		},
		groups: func(v []int) error {
			if !reflect.DeepEqual(v, []int{984}) {
				t.Fatal("foreign supplementary group", v)
			}
			return step("groups")
		},
		gid: func(v int) error {
			if v != 984 {
				t.Fatal("foreign primary group")
			}
			return step("gid")
		},
		uid: func(v int) error {
			if v != 993 {
				t.Fatal("foreign/root UID")
			}
			return step("uid")
		},
		clearAmbient: func() error { return step("ambient") },
		clearCaps:    func() error { return step("caps") },
		verify: func(uid, gid uint32) error {
			if uid != 993 || gid != 984 {
				t.Fatal("rebound post-drop account")
			}
			return step("verify")
		},
	}, &calls
}

func TestRedisPrivilegeModelsStrictOrderAndEveryFailureStops(t *testing.T) {
	complete := []string{"root", "nnp", "groups", "gid", "uid", "ambient", "caps", "verify"}
	ops, calls := redisPrivilegeModel(t, "")
	if redisDropPrivilegesAt(993, 984, ops) != nil || !reflect.DeepEqual(*calls, complete) {
		t.Fatal("full verified boundary missing", *calls)
	}
	for index, name := range complete {
		if name == "root" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ops, calls := redisPrivilegeModel(t, name)
			if redisDropPrivilegesAt(993, 984, ops) == nil || !reflect.DeepEqual(*calls, complete[:index+1]) {
				t.Fatal("continued after failed boundary", *calls)
			}
		})
	}
	for _, bad := range []string{"not-root", "nnp-off"} {
		ops, calls := redisPrivilegeModel(t, bad)
		want := []string{"root"}
		if bad == "nnp-off" {
			want = append(want, "nnp")
		}
		if redisDropPrivilegesAt(993, 984, ops) == nil || !reflect.DeepEqual(*calls, want) {
			t.Fatal("missing initial identity/NNP allowed effects", *calls)
		}
	}
}

func TestRedisPrivilegeModelsRejectInvalidAccountAndMissingVerifierBeforeEffects(t *testing.T) {
	for _, numbers := range [][2]int{{0, 984}, {993, 0}, {-1, 984}, {993, -1}, {1 << 31, 984}, {993, 1 << 31}} {
		ops, calls := redisPrivilegeModel(t, "")
		if redisDropPrivilegesAt(numbers[0], numbers[1], ops) == nil || len(*calls) != 0 {
			t.Fatal("invalid identity performed effects", numbers, *calls)
		}
	}
	for _, change := range []func(*redisPrivilegeOps){
		func(v *redisPrivilegeOps) { v.root = nil }, func(v *redisPrivilegeOps) { v.noNewPrivs = nil },
		func(v *redisPrivilegeOps) { v.groups = nil }, func(v *redisPrivilegeOps) { v.gid = nil }, func(v *redisPrivilegeOps) { v.uid = nil },
		func(v *redisPrivilegeOps) { v.clearAmbient = nil }, func(v *redisPrivilegeOps) { v.clearCaps = nil }, func(v *redisPrivilegeOps) { v.verify = nil },
	} {
		ops, calls := redisPrivilegeModel(t, "")
		change(&ops)
		if redisDropPrivilegesAt(993, 984, ops) == nil || len(*calls) != 0 {
			t.Fatal("incomplete boundary performed effects", *calls)
		}
	}
}

func TestRedisPrivilegeUnitRetainsIdentityChangeOnlyUntilVerifiedExec(t *testing.T) {
	raw, err := os.ReadFile("../../dev/panel-redis@.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, line := range []string{
		"User=root", "Group=panel-redis", "NoNewPrivileges=true",
		"CapabilityBoundingSet=CAP_CHOWN CAP_SETGID CAP_SETUID", "AmbientCapabilities=CAP_SETUID",
		"RuntimeDirectoryMode=0770", "ProtectSystem=strict", "PrivateTmp=true", "ProtectHome=true",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
	} {
		if strings.Count("\n"+text, "\n"+line+"\n") != 1 {
			t.Fatal("fixed bootstrap contract changed", line)
		}
	}
	for _, key := range []string{"CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges="} {
		count := 0
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, key) {
				count++
			}
		}
		if count != 1 {
			t.Fatal("duplicate/overridden service boundary", key)
		}
	}
	// An ambient bootstrap bit is NOT daemon authority. The existing exact
	// peer process guard must still reject any active/inheritable capability.
	valid := "Uid:\t993\t993\t993\t993\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n"
	if !taskSafeProcessStatus(valid, 993) {
		t.Fatal("zero-authority daemon identity")
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		changed := strings.Replace(valid, field+":\t0000000000000000", field+":\t0000000000000080", 1)
		if taskSafeProcessStatus(changed, 993) {
			t.Fatal("bootstrap capability leaked to daemon", field)
		}
	}
}
