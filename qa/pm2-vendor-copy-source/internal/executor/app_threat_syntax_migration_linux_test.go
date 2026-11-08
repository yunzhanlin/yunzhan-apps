//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreatIDSSyntaxMigrationBacksUpExactOwnedGenerationAndRejectsEdits(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	runtime := threatIDSRuntime{Prefix: "apt-0123456789abcdef"}
	guard := "/opt/panel/current/bin/panel-executor"
	old, _ := threatIDSLegacySyntaxUnit(runtime.Prefix)
	next, _ := threatIDSSyntaxUnit(runtime.Prefix)
	path := s.systemPath("/etc/systemd/system/panel-network-ids-check.service")
	if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	if s.threatIDSSyntaxMigrationOwned(runtime, guard) == nil {
		t.Fatal("unowned old unit accepted")
	}
	unit, _ := threatIDSGatedUnit(runtime.Prefix, guard)
	recovery, _ := threatIDSRecoveryUnit(guard)
	record := threatIDSUnitRecord{Format: 1, Guard: guard, Prefix: runtime.Prefix, UnitSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(unit))), RecoverySHA: fmt.Sprintf("%x", sha256.Sum256([]byte(recovery)))}
	recordPath := filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json")
	if err := moduleWrite(recordPath, record); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSSyntaxMigrationOwned(runtime, guard); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateThreatIDSSyntaxUnit(path, old, next); err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != next {
		t.Fatal("fixed private-temporary output override absent")
	}
	backupPath := filepath.Join(s.moduleDir("network-threat-detection"), fmt.Sprintf("syntax-check-%x-backup.json", sha256.Sum256([]byte(old))))
	b, err := ftpPrivateRead(backupPath, 32<<10)
	var backup threatIDSSyntaxBackup
	if err != nil || decodeThreatIDSPrivateJSON(b, &backup) != nil || backup.Old != old || backup.OldSHA != fmt.Sprintf("%x", sha256.Sum256([]byte(old))) || backup.NextSHA != fmt.Sprintf("%x", sha256.Sum256([]byte(next))) {
		t.Fatal("whole prior generation was not durably backed up", err)
	}
	if err := os.WriteFile(path, []byte(old+"# external edit\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if s.migrateThreatIDSSyntaxUnit(path, old, next) == nil {
		t.Fatal("unknown unit edits overwritten")
	}
	if s.migrateThreatIDSSyntaxUnit(path+".other", old, next) == nil {
		t.Fatal("arbitrary migration path accepted")
	}
	record.Guard = "/opt/panel/bin/panel-executor"
	if err := moduleWrite(recordPath, record); err != nil {
		t.Fatal(err)
	}
	if s.threatIDSSyntaxMigrationOwned(runtime, guard) == nil {
		t.Fatal("wrong installed generation adopted")
	}
	if err := os.WriteFile(path, []byte(old), 0644); err != nil {
		t.Fatal(err)
	}
	backup.Old += "changed"
	b, _ = json.Marshal(backup)
	if err := os.WriteFile(backupPath, b, 0600); err != nil {
		t.Fatal(err)
	}
	if s.migrateThreatIDSSyntaxUnit(path, old, next) == nil {
		t.Fatal("foreign backup replaced")
	}
	actual, _ = os.ReadFile(path)
	if string(actual) != old {
		t.Fatal("unit changed after bad backup")
	}
	// A separate digest-addressed backup preserves the earlier failed
	// generation, while the intermediate writable-temporary generation can
	// independently migrate to a result-retaining oneshot.
	intermediate, err := threatIDSLegacySyntaxUnitV2(runtime.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(path, []byte(intermediate), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.migrateThreatIDSSyntaxUnit(path, intermediate, next); err != nil {
		t.Fatal(err)
	}
	actual, _ = os.ReadFile(path)
	if string(actual) != next {
		t.Fatal("intermediate owned generation did not migrate")
	}
	unchanged, _ := os.ReadFile(backupPath)
	if string(unchanged) != string(b) {
		t.Fatal("earlier evidence overwritten")
	}
	strictOld, err := threatIDSLegacySyntaxUnitV3(runtime.Prefix)
	if err != nil || strictOld != strings.Replace(next, "TimeoutStartSec=90s\n", "TimeoutStartSec=40s\n", 1) || intermediate != strings.Replace(strictOld, "RemainAfterExit=yes\n", "", 1) || old != strings.Replace(intermediate, " -l /tmp -c ", " -c ", 1) {
		t.Fatal("known generations no longer reproduce their exact earlier bytes", err)
	}
	if err := atomicWrite(path, []byte(strictOld), 0644); err != nil {
		t.Fatal(err)
	}
	// Known legacy policy is sufficient for read-only identity/safe stop but
	// cannot be silently executed or rewritten by a configuration check.
	if err := atomicWrite(s.systemPath("/etc/systemd/system/panel-network-ids.service"), []byte(unit), 0644); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(s.systemPath("/etc/systemd/system/panel-network-ids-recover.service"), []byte(recovery), 0644); err != nil {
		t.Fatal(err)
	}
	record.Guard = guard
	if err := moduleWrite(recordPath, record); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSUnitRecord(runtime); err != nil {
		t.Fatal("known old budget blocked read-only identity/safe stop", err)
	}
	if err := s.threatIDSRequireCurrentSyntax(runtime); err == nil {
		t.Fatal("known old budget was executable before explicit preparation")
	}
	state := "LoadState=loaded\nActiveState=active\nSubState=exited\nMainPID=0\nFragmentPath=/etc/systemd/system/panel-network-ids-check.service\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\n"
	calls := 0
	s.Config.Run = func(_ context.Context, executable string, args ...string) (string, error) {
		calls++
		if executable != "/usr/bin/systemctl" || strings.Join(args, " ") != "show --all panel-network-ids-check.service --property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,Transient,NeedDaemonReload" {
			t.Fatal("migration mutated or stopped a unit while observing idleness", executable, args)
		}
		return state, nil
	}
	good := state
	for _, bad := range []string{"", strings.Replace(good, "SubState=exited", "SubState=running", 1), strings.Replace(good, "MainPID=0", "MainPID=2", 1), strings.Replace(good, "DropInPaths=\n", "DropInPaths=/etc/systemd/system/panel-network-ids-check.service.d/admin.conf\n", 1), strings.Replace(good, "Transient=no", "Transient=yes", 1), strings.Replace(good, "NeedDaemonReload=no", "NeedDaemonReload=yes", 1), strings.Replace(good, "FragmentPath=/etc/systemd/system/", "FragmentPath=/run/systemd/system/", 1), good + "MainPID=0\n", good + "Unknown=no\n", strings.Replace(good, "DropInPaths=\n", "", 1)} {
		state = bad
		if s.threatIDSSyntaxIdleSource(context.Background()) == nil {
			t.Fatal("active/overridden/unknown parser accepted for migration", bad)
		}
		actual, _ = os.ReadFile(path)
		if string(actual) != strictOld {
			t.Fatal("observing a refused migration rewrote the known unit")
		}
	}
	state = good
	if err := s.threatIDSSyntaxIdleSource(context.Background()); err != nil || calls != 11 {
		t.Fatal("known completed parser cannot be explicitly migrated", err, calls)
	}
	if err := s.migrateThreatIDSSyntaxUnit(path, strictOld, next); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSRequireCurrentSyntax(runtime); err != nil {
		t.Fatal("explicit migration did not install the current bounded parser", err)
	}
	actualUnit, _ := os.ReadFile(s.systemPath("/etc/systemd/system/panel-network-ids.service"))
	actualRecovery, _ := os.ReadFile(s.systemPath("/etc/systemd/system/panel-network-ids-recover.service"))
	if string(actualUnit) != unit || string(actualRecovery) != recovery {
		t.Fatal("non-capture parser migration rewrote capture/recovery policy")
	}
	custom := strings.Replace(next, "TimeoutStartSec=90s", "TimeoutStartSec=91s", 1)
	if err := atomicWrite(path, []byte(custom), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSUnitRecord(runtime); err == nil {
		t.Fatal("arbitrary timeout policy adopted as known source")
	}
	if s.threatIDSRequireCurrentSyntax(runtime) == nil || s.migrateThreatIDSSyntaxUnit(path, strictOld, next) == nil {
		t.Fatal("administrator timeout was executed or overwritten")
	}
}

func TestThreatIDSRecoveryLegacyIdentityIsReadableButNotStartable(t *testing.T) {
	s := threatIDSRotationRootFixture(t)
	runtime := threatIDSRuntime{Prefix: "apt-0123456789abcdef"}
	guard := "/opt/panel/current/bin/panel-executor"
	unit, _ := threatIDSGatedUnit(runtime.Prefix, guard)
	syntax, _ := threatIDSSyntaxUnit(runtime.Prefix)
	legacy, _ := threatIDSLegacyRecoveryUnit(guard)
	for name, data := range map[string]string{"panel-network-ids.service": unit, "panel-network-ids-check.service": syntax, "panel-network-ids-recover.service": legacy} {
		path := s.systemPath("/etc/systemd/system/" + name)
		if err := threatIDSTrustedParents(filepath.Dir(path), true); err != nil {
			t.Fatal(err)
		}
		if err := atomicWrite(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	record := threatIDSUnitRecord{Format: 1, Prefix: runtime.Prefix, Guard: guard, UnitSHA: fmt.Sprintf("%x", sha256.Sum256([]byte(unit))), RecoverySHA: fmt.Sprintf("%x", sha256.Sum256([]byte(legacy)))}
	path := filepath.Join(s.moduleDir("network-threat-detection"), "capture-unit.json")
	if err := moduleWrite(path, record); err != nil {
		t.Fatal(err)
	}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("read-only gate invoked a command")
		return "", nil
	}
	if _, err := s.threatIDSUnitRecord(runtime); err != nil {
		t.Fatal("safe-stop identity lost", err)
	}
	if s.threatIDSRequireCurrentRecovery(runtime) == nil {
		t.Fatal("legacy budget accepted for new capture")
	}
	if err := s.threatIDSSyntaxMigrationOwned(runtime, guard); err != nil {
		t.Fatal("exact original producer record lost", err)
	}
	actual, _ := os.ReadFile(s.systemPath("/etc/systemd/system/panel-network-ids-recover.service"))
	if string(actual) != legacy {
		t.Fatal("read-only status silently migrated a unit")
	}
	// A record pinned to the current source cannot claim an old on-disk unit.
	current, _ := threatIDSRecoveryUnit(guard)
	record.RecoverySHA = fmt.Sprintf("%x", sha256.Sum256([]byte(current)))
	if err := moduleWrite(path, record); err != nil {
		t.Fatal(err)
	}
	if _, err := s.threatIDSUnitRecord(runtime); err == nil {
		t.Fatal("record/unit source mismatch adopted")
	}
	if err := atomicWrite(s.systemPath("/etc/systemd/system/panel-network-ids-recover.service"), []byte(current), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.threatIDSRequireCurrentRecovery(runtime); err != nil {
		t.Fatal("current bounded source rejected", err)
	}
}
