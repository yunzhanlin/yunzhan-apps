//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
)

// Filesystem regression fixtures are separate from the native power-loss
// acceptance. No fixture receipt is promoted into an installation claim.
func pm2ConfigFixtureIntent(t *testing.T) (*Service, pm2App, string, pm2ConfigRecord) {
	t.Helper()
	s, app, path := pm2StateAppFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	next := app
	next.Revision++
	next.MemoryMB = 192
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	owner, err := currentModuleApplyOwner()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := currentPM2ConfigBoot()
	if err != nil {
		t.Fatal(err)
	}
	in := pm2ConfigIntent{Format: 1, ID: core.ID(), AppID: app.ID, SiteID: app.SiteID, CreatedAt: core.Now(), BootID: boot, Owner: owner, RequestSHA: core.Hash("fixture-request"), Before: before, After: raw, BeforeSHA: pm2ConfigHash(before), AfterSHA: pm2ConfigHash(raw), BeforeState: pm2TestState("active", "enabled")}
	if err = validatePM2ConfigIntent(in); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	d, err := s.openPM2ConfigStore(true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = pm2ConfigCreate(d.modulePrivateDirectory, in.ID+".intent.json", raw); err != nil {
		t.Fatal(err)
	}
	return s, app, path, pm2ConfigRecord{Intent: in, SHA: pm2ConfigHash(raw), Raw: raw}
}
func TestPM2ConfigurationStoppedCommitAndOriginalNonceObservation(t *testing.T) {
	s, app, path := pm2StateAppFixture(t)
	before, _ := os.ReadFile(path)
	calls := 0
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		calls++
		return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
	}
	secret := "replacement-not-public"
	in := core.AppModuleInput{ResourceID: app.ID, ExpectedRevision: app.Revision, PM2OperationID: core.ID(), MemoryMB: 192, EnvironmentPatch: map[string]*string{"TOKEN": &secret}}
	result, err := s.modulePM2(context.Background(), "update", in)
	if err != nil {
		t.Fatal(err)
	}
	records, err := s.pm2ConfigRecords()
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	record := records[in.PM2OperationID]
	if record.Receipt == nil || record.Receipt.State != "committed" || !bytes.Equal(record.Intent.Before, before) {
		t.Fatal("missing exact old encrypted bytes or durable commit")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(current, record.Intent.After) {
		t.Fatal("committed bytes differ")
	}
	published, _ := json.Marshal(result)
	stored := append(append([]byte{}, record.Raw...), current...)
	if bytes.Contains(published, []byte(secret)) || bytes.Contains(published, []byte("environment_cipher")) || bytes.Contains(stored, []byte(secret)) {
		t.Fatal("write-only environment leaked")
	}
	if calls != 2 {
		t.Fatal("stopped save dispatched a service change", calls)
	}
	info, _ := os.Lstat(path)
	journal := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", in.PM2OperationID+".intent.json")
	originalJournal, _ := os.ReadFile(journal)
	second, err := s.modulePM2(context.Background(), "update", in)
	if err != nil || second.(map[string]any)["duplicate_observation"] != true || calls != 2 {
		t.Fatal("lost reply replayed business", second, err, calls)
	}
	afterInfo, _ := os.Lstat(path)
	afterJournal, _ := os.ReadFile(journal)
	if !programQueueSame(info, afterInfo) || !bytes.Equal(originalJournal, afterJournal) {
		t.Fatal("observing original commit changed manifest or intent")
	}
	in.MemoryMB = 256
	if _, err = s.modulePM2(context.Background(), "update", in); err == nil {
		t.Fatal("nonce collision accepted a different request")
	}
}
func TestPM2ConfigurationExplicitRecoveryRestoresExactCipherAndRemainsStopped(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			s, app, path, record := pm2ConfigFixtureIntent(t)
			if published {
				if err := s.pm2ConfigPublish(app.ID, record.Intent.ID, record.Intent.Before, record.Intent.After); err != nil {
					t.Fatal(err)
				}
			}
			originalIntentPath := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", record.Intent.ID+".intent.json")
			info, _ := os.Lstat(originalIntentPath)
			calls := []string{}
			s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
				if name != "/usr/bin/systemctl" {
					t.Fatal(name)
				}
				calls = append(calls, strings.Join(args, " "))
				if args[0] == "disable" && reflect.DeepEqual(args, []string{"disable", "--now", "panel-pm2@" + app.ID + ".service"}) {
					return "", nil
				}
				if args[0] == "show" {
					return pm2TestStateText(pm2TestState("inactive", "disabled")), nil
				}
				t.Fatalf("recovery tried to start or replay: %s %v", name, args)
				return "", nil
			}
			input := core.AppModuleInput{ResourceID: app.ID, PM2OperationID: record.Intent.ID, ExpectedSHA: record.SHA, Confirm: "RECOVER PM2 " + record.Intent.ID}
			result, err := s.modulePM2(context.Background(), "recover-configuration", input)
			if err != nil || result.(map[string]any)["service_active"] != false {
				t.Fatal(result, err)
			}
			raw, _ := os.ReadFile(path)
			if !bytes.Equal(raw, record.Intent.Before) || len(calls) != 2 {
				t.Fatal("recovery lost exact cipher or replayed service", calls)
			}
			currentInfo, _ := os.Lstat(originalIntentPath)
			if !programQueueSame(info, currentInfo) {
				t.Fatal("recovery rewrote original intent")
			}
			records, err := s.pm2ConfigRecords()
			if err != nil || records[record.Intent.ID].Receipt.State != "recovered_stopped" {
				t.Fatal(records, err)
			}
			if _, err = s.modulePM2(context.Background(), "recover-configuration", input); err != nil || len(calls) != 2 {
				t.Fatal("recovery receipt re-dispatched stop", err, calls)
			}
		})
	}
}
func TestPM2ConfigurationRecoveryRejectsStaleIdentityAndChangedManifest(t *testing.T) {
	for _, mode := range []string{"sha", "nonce", "confirm", "manifest"} {
		t.Run(mode, func(t *testing.T) {
			s, app, path, record := pm2ConfigFixtureIntent(t)
			in := core.AppModuleInput{ResourceID: app.ID, PM2OperationID: record.Intent.ID, ExpectedSHA: record.SHA, Confirm: "RECOVER PM2 " + record.Intent.ID}
			switch mode {
			case "sha":
				in.ExpectedSHA = strings.Repeat("0", 64)
			case "nonce":
				in.PM2OperationID = core.ID()
			case "confirm":
				in.Confirm = "RECOVER"
			case "manifest":
				other := app
				other.MemoryMB = 256
				if err := moduleWrite(path, other); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			s.Config.Run = func(context.Context, string, ...string) (string, error) {
				t.Fatal("stale recovery dispatched a service command")
				return "", nil
			}
			if _, err := s.modulePM2(context.Background(), "recover-configuration", in); err == nil {
				t.Fatal("stale identity accepted")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("stale identity overwrote live configuration")
			}
		})
	}
}
func TestPM2ConfigurationOwnerFenceRequiresOriginalBootExecutorAndHeldLock(t *testing.T) {
	s, app, path, record := pm2ConfigFixtureIntent(t)
	s.Config.SystemRoot = "/"
	s.Config.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"show", "panel-executor.service", "--property=MainPID", "--value"}) {
			t.Fatal(name, args)
		}
		return fmt.Sprint(os.Getpid()), nil
	}
	lock, err := s.lockPM2Project(app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.checkPM2ConfigurationStart(context.Background(), app.ID); err != nil {
		t.Fatal("original owner with held lock refused", err)
	}
	if err = s.pm2ConfigPublish(app.ID, record.Intent.ID, record.Intent.Before, record.Intent.After); err != nil {
		t.Fatal(err)
	}
	if err = s.checkPM2ConfigurationStart(context.Background(), app.ID); err != nil {
		t.Fatal("owner-bound candidate refused", err)
	}
	lock.Close()
	if err = s.checkPM2ConfigurationStart(context.Background(), app.ID); err == nil {
		t.Fatal("released transaction admitted uncommitted start")
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Equal(raw, record.Intent.After) {
		t.Fatal("read-only fence repaired uncommitted bytes")
	}
}
func TestPM2ConfigurationReadonlyInventoryAndUpgradeRefuseUnresolved(t *testing.T) {
	s, _, _, record := pm2ConfigFixtureIntent(t)
	dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
	before := programQueueTree(t, dir)
	if _, err := s.pm2ConfigurationReport(core.AppModuleInput{}); err != nil {
		t.Fatal(err)
	}
	r := &programQueueReader{ctx: context.Background(), root: "/"}
	// Bind the same original files through a private fixture root.
	relative := "etc/panel/security-apps/modules/pm2-manager/configuration-transactions"
	base := t.TempDir()
	target := filepath.Join(base, relative)
	if err := os.MkdirAll(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, record.Intent.ID+".intent.json"), record.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	r.root = base
	if err := r.pm2Configurations(); err == nil {
		t.Fatal("unresolved configuration crossed upgrade preflight")
	}
	if err := checkProgramUpgradeQueues(context.Background(), base); err == nil || !strings.Contains(err.Error(), "PM2 configuration") {
		t.Fatal("complete original filesystem guard omitted PM2 refusal", err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, dir)) {
		t.Fatal("observer rewrote original intent")
	}
	d, err := s.openPM2ConfigStore(false)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.finish(record, "committed"); err != nil {
		t.Fatal(err)
	}
	d.Close()
	result, _ := os.ReadFile(filepath.Join(dir, record.Intent.ID+".result.json"))
	if err = os.WriteFile(filepath.Join(target, record.Intent.ID+".result.json"), result, 0600); err != nil {
		t.Fatal(err)
	}
	r = &programQueueReader{ctx: context.Background(), root: base}
	if err = r.pm2Configurations(); err != nil {
		t.Fatal("verified terminal intent/receipt refused", err)
	}
	if err := checkProgramUpgradeQueues(context.Background(), base); err != nil {
		t.Fatal("complete original filesystem guard refused settled PM2 receipt", err)
	}
	if err = r.unchanged(); err != nil {
		t.Fatal(err)
	}
}

func TestPM2ConfigurationCancellationClosesUnacceptedNonceWithoutChangingProject(t *testing.T) {
	s, app, path := pm2StateAppFixture(t)
	before, _ := os.ReadFile(path)
	beforeInfo, _ := os.Lstat(path)
	id := core.ID()
	input := core.AppModuleInput{ResourceID: app.ID, PM2OperationID: id, Confirm: "CANCEL PM2 " + id}
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("cancelling an unaccepted request dispatched a service command")
		return "", nil
	}
	absent, err := s.pm2ConfigurationReport(core.AppModuleInput{ResourceID: app.ID, PM2OperationID: id})
	if err != nil || absent.(map[string]any)["selected_operation_absent"] != true {
		t.Fatal(absent, err)
	}
	out, err := s.modulePM2(context.Background(), "cancel-configuration-request", input)
	if err != nil || out.(map[string]any)["request_cancelled"] != true {
		t.Fatal(out, err)
	}
	recordPath := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", id+".cancel.json")
	cancelBytes, _ := os.ReadFile(recordPath)
	cancelInfo, _ := os.Lstat(recordPath)
	late := core.AppModuleInput{ResourceID: app.ID, PM2OperationID: id, ExpectedRevision: app.Revision, MemoryMB: 192}
	if _, err = s.modulePM2(context.Background(), "update", late); err == nil {
		t.Fatal("cancelled delayed request published a new intent")
	}
	if _, err = s.modulePM2(context.Background(), "cancel-configuration-request", input); err != nil {
		t.Fatal("original cancellation could not be observed", err)
	}
	after, _ := os.ReadFile(path)
	afterInfo, _ := os.Lstat(path)
	lastBytes, _ := os.ReadFile(recordPath)
	lastInfo, _ := os.Lstat(recordPath)
	if !bytes.Equal(before, after) || !programQueueSame(beforeInfo, afterInfo) || !bytes.Equal(cancelBytes, lastBytes) || !programQueueSame(cancelInfo, lastInfo) {
		t.Fatal("cancellation or delayed retry changed project or original cancellation")
	}
	report, err := s.pm2ConfigurationReport(core.AppModuleInput{ResourceID: app.ID, PM2OperationID: id})
	if err != nil {
		t.Fatal(err)
	}
	row := report.(map[string]any)["configuration_transactions"].([]any)[0].(map[string]any)
	if row["state"] != "cancelled_before_publication" || row["site_id"] != nil || row["previous_revision"] != nil {
		t.Fatal("cancellation invented a published configuration", row)
	}
	if err = s.checkPM2ConfigurationStart(context.Background(), app.ID); err != nil {
		t.Fatal("a terminal request cancellation blocked the unchanged app", err)
	}
}
func TestPM2ConfigurationCancellationCannotEraseAnAcceptedPendingIntent(t *testing.T) {
	s, app, _, record := pm2ConfigFixtureIntent(t)
	s.Config.Run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("cancelling an accepted request dispatched a service command")
		return "", nil
	}
	out, err := s.modulePM2(context.Background(), "cancel-configuration-request", core.AppModuleInput{ResourceID: app.ID, PM2OperationID: record.Intent.ID, Confirm: "CANCEL PM2 " + record.Intent.ID})
	if err != nil || out.(map[string]any)["request_cancelled"] != false {
		t.Fatal(out, err)
	}
	if _, err = os.Lstat(filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions", record.Intent.ID+".cancel.json")); !os.IsNotExist(err) {
		t.Fatal("accepted pending intent was cancelled or shadowed", err)
	}
	records, err := s.pm2ConfigRecords()
	if err != nil || !pm2ConfigPending(records, app.ID) || !bytes.Equal(records[record.Intent.ID].Raw, record.Raw) {
		t.Fatal("accepted intent was rewritten", err)
	}
}
func TestPM2ConfigurationCancellationUpgradeAndConflictingRecords(t *testing.T) {
	root := programQueueFixture(t)
	id := core.ID()
	relative := "etc/panel/security-apps/modules/pm2-manager/configuration-transactions"
	dir := filepath.Join(root, relative)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	cancel := pm2ConfigCancellation{Format: 1, ID: id, AppID: "owned-project", CreatedAt: core.Now(), CancelledBeforePublication: true}
	raw, _ := json.Marshal(cancel)
	path := filepath.Join(dir, id+".cancel.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	r := &programQueueReader{ctx: context.Background(), root: root}
	before := programQueueTree(t, root)
	if err := r.pm2Configurations(); err != nil {
		t.Fatal("valid terminal cancellation refused upgrade", err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("upgrade observation changed cancellation")
	}
	files := map[string][]byte{id + ".cancel.json": raw, id + ".result.json": []byte("{}")}
	if _, err := decodePM2ConfigurationRecords(files); err == nil {
		t.Fatal("cancellation shadowed a receipt")
	}
	for _, data := range [][]byte{[]byte("{"), []byte(strings.Replace(string(raw), "\"cancelled_before_publication\":true", "\"cancelled_before_publication\":false", 1)), []byte(strings.Replace(string(raw), "\"format\":1", "\"FORMAT\":1,\"format\":1", 1))} {
		if _, err := decodePM2ConfigurationRecords(map[string][]byte{id + ".cancel.json": data}); err == nil {
			t.Fatal("partial/forged cancellation was admitted")
		}
	}
}

func TestPM2ConfigurationDamagedAndUntrustedRecordsAreRetainedAndBlockStart(t *testing.T) {

	for _, mode := range []string{"partial", "unknown", "duplicate", "orphan", "hardlink", "symlink", "public", "old-boot"} {
		t.Run(mode, func(t *testing.T) {
			s, app, _, record := pm2ConfigFixtureIntent(t)
			dir := filepath.Join(s.moduleDir("pm2-manager"), "configuration-transactions")
			path := filepath.Join(dir, record.Intent.ID+".intent.json")
			switch mode {
			case "partial":
				if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown":
				if err := os.WriteFile(filepath.Join(dir, "unknown"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				raw := append([]byte(`{"FORMAT":1,`), record.Raw[1:]...)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "orphan":
				if err := os.WriteFile(filepath.Join(dir, core.ID()+".result.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(t.TempDir(), "original")); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "old-boot":
				record.Intent.BootID = "00000000-0000-0000-0000-000000000000"
				raw, _ := json.Marshal(record.Intent)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := programQueueTree(t, dir)
			if err := s.checkPM2ConfigurationStart(context.Background(), app.ID); err == nil {
				t.Fatal("untrusted or old-boot transaction admitted start")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, dir)) {
				t.Fatal("failed observer altered original records")
			}
		})
	}
}
