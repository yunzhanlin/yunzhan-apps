package loadbalancestream

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAccountChildPermitBindsEveryOriginalInstallationSeedField(t *testing.T) {
	for _, action := range []string{"install", "update"} {
		t.Run(action, func(t *testing.T) {
			seed, raw, _ := streamInstallationFixture(t, action)
			p, _, _ := accountPermitFixture(t)
			p.JobID, p.ActorID, p.Nonce = seed.JobID, seed.ActorID, seed.Nonce
			p.ProgrammeInputsSHA256, p.SeedSHA256 = seed.ProgrammeInputsSHA256, serviceDigest(raw)
			if !AccountChildPermitBindsSeed(p, raw) {
				t.Fatal("exact seed binding refused")
			}
			for _, field := range []string{"JobID", "ActorID", "Nonce", "AppVersion", "ProgrammeInputsSHA256", "SeedSHA256"} {
				t.Run(field, func(t *testing.T) {
					changed := p
					target := reflect.ValueOf(&changed).Elem().FieldByName(field)
					replacement := strings.Repeat("f", 32)
					if strings.HasSuffix(field, "SHA256") {
						replacement = strings.Repeat("e", 64)
					}
					if field == "AppVersion" {
						replacement = "1.8.5"
					}
					target.SetString(replacement)
					if AccountChildPermitBindsSeed(changed, raw) {
						t.Fatal("foreign/legacy seed binding accepted")
					}
				})
			}
			for _, bad := range [][]byte{nil, []byte("{}"), append(bytes.Clone(raw), ' ')} {
				if AccountChildPermitBindsSeed(p, bad) {
					t.Fatal("invalid original seed accepted")
				}
			}
		})
	}
}
func TestAccountChildPermitPreservesFullUint64KernelIdentities(t *testing.T) {
	p, o, now := accountPermitFixture(t)
	p.ParentStartTicks = 18446744073709551615
	p.JournalDevice = 18446744073709551614
	p.JournalInode = 18446744073709551613
	p.RunLockDevice = 18446744073709551612
	p.RunLockInode = 18446744073709551611
	o.StartTicks = p.ParentStartTicks
	o.JournalDevice = p.JournalDevice
	o.JournalInode = p.JournalInode
	o.RunLockDevice = p.RunLockDevice
	o.RunLockInode = p.RunLockInode
	raw, err := AccountChildPermitBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAccountChildPermit(raw)
	if err != nil || decoded != p || !AccountChildParentMatches(decoded, o, now) {
		t.Fatal("kernel identity lost precision")
	}
}

func accountPermitFixture(t *testing.T) (AccountChildPermit, AccountParentObservation, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 25, 16, 0, 0, 0, time.UTC)
	p := AccountChildPermit{Format: 1, AppVersion: AppVersion, JobID: strings.Repeat("a", 32), ActorID: strings.Repeat("b", 32), Nonce: strings.Repeat("c", 32), BootID: "12345678-1234-1234-1234-123456789abc", ParentPID: 123, ParentStartTicks: 456,
		ParentExeSHA256: strings.Repeat("1", 64), ProgrammeInputsSHA256: strings.Repeat("2", 64), SeedSHA256: strings.Repeat("3", 64), AccountIntentSHA256: strings.Repeat("4", 64), JournalDevice: 11, JournalInode: 12, RunLockDevice: 11, RunLockInode: 13, CreatedAt: now.Format(time.RFC3339)}
	parent, _ := AccountParentUnit(p.JobID)
	child, _ := AccountCreationUnit(p.JobID)
	o := AccountParentObservation{BootID: p.BootID, PID: p.ParentPID, StartTicks: p.ParentStartTicks, ExeSHA256: p.ParentExeSHA256, ProgrammeInputsSHA256: p.ProgrammeInputsSHA256, SeedSHA256: p.SeedSHA256, AccountIntentSHA256: p.AccountIntentSHA256, Unit: parent, ChildUnit: child, ControlGroup: "/system.slice/" + parent, ProcessControlGroup: "/system.slice/" + parent, NoNewPrivileges: true, ActiveRunning: true, ExclusiveRunLock: true, RunLockReadWrite: true, RunLockOrdinary: true, RunLockOwnerPID: p.ParentPID, RunLockMode: 0600, RunLockLinks: 1, JournalDevice: p.JournalDevice, JournalInode: p.JournalInode, RunLockDevice: p.RunLockDevice, RunLockInode: p.RunLockInode, JournalPhase: "account-intent"}
	return p, o, now
}
func TestAccountChildPermitCanonicalCodecAndClosedUnitNames(t *testing.T) {
	p, o, now := accountPermitFixture(t)
	raw, err := AccountChildPermitBytes(p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAccountChildPermit(raw)
	if err != nil || decoded != p {
		t.Fatal("canonical permit roundtrip", err)
	}
	if !AccountChildParentMatches(p, o, now) || !AccountChildParentMatches(p, o, now.Add(AccountChildPermitLifetime)) {
		t.Fatal("exact observations refused")
	}
	for _, bad := range []string{"", "../child", "a.service", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 32) + "\n"} {
		if _, err := AccountParentUnit(bad); err == nil {
			t.Fatal("unsafe parent unit", bad)
		}
		if _, err := AccountCreationUnit(bad); err == nil {
			t.Fatal("unsafe child unit", bad)
		}
	}
	for name, bad := range map[string][]byte{"empty": nil, "space": append(bytes.Clone(raw), ' '), "two": append(bytes.Clone(raw), raw...), "duplicate": bytes.Replace(raw, []byte(`"format":1`), []byte(`"format":1,"format":1`), 1), "unknown": bytes.Replace(raw, []byte(`"format":1`), []byte(`"extra":true,"format":1`), 1), "large": bytes.Repeat([]byte("x"), MaxAccountChildPermitBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAccountChildPermit(bad); err == nil {
				t.Fatal("ambiguous permit normalized")
			}
		})
	}
}
func TestAccountChildPermitEveryKernelAndLeaseObservationIsMandatory(t *testing.T) {
	p, o, now := accountPermitFixture(t)
	value := reflect.ValueOf(&o).Elem()
	for i := 0; i < value.NumField(); i++ {
		t.Run(value.Type().Field(i).Name, func(t *testing.T) {
			changed := o
			field := reflect.ValueOf(&changed).Elem().Field(i)
			switch field.Kind() {
			case reflect.String:
				field.SetString("different")
			case reflect.Uint32, reflect.Uint64:
				field.SetUint(field.Uint() + 1)
			case reflect.Int64:
				field.SetInt(field.Int() + 1)
			case reflect.Bool:
				field.SetBool(!field.Bool())
			default:
				t.Fatal("fixture field type")
			}
			if AccountChildParentMatches(p, changed, now) {
				t.Fatal("changed original kernel observation accepted")
			}
		})
	}
	for _, bad := range []time.Time{time.Time{}, now.Add(-time.Nanosecond), now.Add(AccountChildPermitLifetime + time.Nanosecond)} {
		if AccountChildParentMatches(p, o, bad) {
			t.Fatal("invalid/stale/reversed child start window accepted")
		}
	}
}
func TestAccountChildPermitRejectsInvalidSerializedOwnership(t *testing.T) {
	p, _, _ := accountPermitFixture(t)
	for _, field := range []string{"format", "app_version", "job_id", "actor_id", "nonce", "boot_id", "parent_pid", "parent_start_ticks", "parent_exe_sha256", "programme_inputs_sha256", "seed_sha256", "account_intent_sha256", "journal_device", "journal_inode", "run_lock_device", "run_lock_inode", "created_at"} {
		t.Run(field, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			var values map[string]any
			if json.Unmarshal(raw, &values) != nil {
				t.Fatal("fixture")
			}
			switch field {
			case "format":
				values[field] = float64(2)
			case "parent_pid":
				values[field] = float64(1)
			case "parent_start_ticks", "journal_device", "journal_inode", "run_lock_device", "run_lock_inode":
				values[field] = float64(0)
			default:
				values[field] = "invalid"
			}
			raw, _ = json.Marshal(values)
			var changed AccountChildPermit
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("changed fixture")
			}
			if _, err := AccountChildPermitBytes(changed); err == nil {
				t.Fatal("invalid ownership serialized")
			}
		})
	}
}
