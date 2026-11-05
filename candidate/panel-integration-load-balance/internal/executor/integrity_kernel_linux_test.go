//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"local/panel/internal/core"
)

func integrityKernelFixture(t *testing.T) (*Service, core.IntegrityKernelRequest, integrityKernelPlan, *modulePrivateDirectory) {
	t.Helper()
	s, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, s, site, "data.txt", "original website bytes")
	request := core.IntegrityKernelRequest{Format: 1, ID: core.ID(), ActorID: core.ID(), AccessRevision: 1, AppSHA: strings.Repeat("a", 64), Action: "enable", CreatedAt: core.Now(), Input: core.IntegrityKernelInput{SiteID: site, ExpectedAppVersion: core.IntegrityKernelAppVersion, BaselineSHA: strings.Repeat("b", 64), Confirm: "PROTECT SITE " + site}}
	files, _, err := s.openIntegrityWatchFiles(site)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	parent, err := integrityKernelStatRoot(files.root)
	if err != nil {
		t.Fatal(err)
	}
	public, err := integrityKernelStatRoot(files.public)
	if err != nil {
		t.Fatal(err)
	}
	f, err := files.public.Open("data.txt")
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	err = unix.Fstat(int(f.Fd()), &st)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	plan := integrityKernelPlan{Format: 1, OperationID: request.ID, SiteID: site, BaselineSHA: request.Input.BaselineSHA, Site: parent, Public: public, Excludes: []string{}, Targets: []integrityKernelTarget{{Path: ".", Directory: true, Original: integrityInodeFlagState{Identity: public}}, {Path: "data.txt", Original: integrityInodeFlagState{Identity: integrityInodeIdentityOf(st)}, SHA: core.Hash("original website bytes")}}}
	if err = validateIntegrityKernelPlan(plan); err != nil {
		t.Fatal(err)
	}
	d, err := s.integrityKernelStore(true)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.Mkdir(request.ID, 0700); err != nil {
		d.Close()
		t.Fatal(err)
	}
	d, err = integrityKernelChild(d, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err = integrityKernelCreate(d, "request.json", request); err != nil {
		t.Fatal(err)
	}
	return s, request, plan, d
}

func integrityKernelFixtureStart(t *testing.T, d *modulePrivateDirectory, request core.IntegrityKernelRequest, plan integrityKernelPlan) *integrityKernelJournal {
	t.Helper()
	if err := integrityKernelCreate(d, "started.json", integrityKernelStarted{Format: 1, ID: request.ID, RequestSHA: core.IntegrityKernelRequestSHA(request), InstalledAt: "2026-10-01T00:00:00Z", StartedAt: core.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := integrityKernelCreate(d, "plan.json", plan); err != nil {
		t.Fatal(err)
	}
	j, err := newIntegrityKernelJournal(d, request.ID, integrityKernelDigest(plan))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.file.Close() })
	return j
}

func TestIntegrityKernelUnknownStartedTaskNeverReplaysOrDeletes(t *testing.T) {
	s, request, plan, d := integrityKernelFixture(t)
	j := integrityKernelFixtureStart(t, d, request, plan)
	if err := j.append(0, "intent", 0); err != nil {
		t.Fatal(err)
	}
	before, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
	if err != nil {
		t.Fatal(err)
	}
	op, err := s.integrityKernelReadOperation(request.ID)
	if err != nil || op.State != "needs-attention" || op.Request != request || op.Revision != 1 {
		t.Fatal(op, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	s.runIntegrityKernelWorker(ctx)
	after, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
	if err != nil || string(after) != string(before) {
		t.Fatal("original unknown operation was rewritten", err)
	}
	if _, err = d.Lstat("result.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("background worker invented a terminal outcome", err)
	}
	if got := fixtureRead(t, s, request.Input.SiteID, "data.txt"); got != "original website bytes" {
		t.Fatal("original data changed", got)
	}
	if err = s.integrityKernelReference(request.Input.SiteID); err == nil {
		t.Fatal("unknown task lost its site reference")
	}
	if err = s.integrityKernelReference(core.ID()); err != nil {
		t.Fatal("unrelated site was blocked", err)
	}
}

func TestIntegrityKernelOriginalRequestsAndOutcomesAreExclusive(t *testing.T) {
	s, request, _, d := integrityKernelFixture(t)
	original, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.ActorID = core.ID()
	if err = integrityKernelCreate(d, "request.json", changed); !errors.Is(err, os.ErrExist) {
		t.Fatal("original request could be overwritten", err)
	}
	after, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil || string(after) != string(original) {
		t.Fatal("original request changed", err)
	}
	same := request
	same.CreatedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
	got, err := s.integrityKernelSubmit(context.Background(), same)
	if err != nil || got.State != "queued" || got.Request != request {
		t.Fatal("exact retry did not return original identity", got, err)
	}
	if _, err = s.integrityKernelSubmit(context.Background(), changed); err == nil {
		t.Fatal("another actor borrowed original submission key")
	}
	if _, err = d.Lstat("started.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only retry dispatched native work")
	}
}

func TestIntegrityKernelPrivateEvidenceRejectsChangedContainersAndLinks(t *testing.T) {
	for _, scenario := range []string{"mode", "hardlink", "symlink", "unknown-entry", "truncated-request", "case-alias", "duplicate-field", "null-field", "parent-mode", "parent-renamed"} {
		t.Run(scenario, func(t *testing.T) {
			s, request, _, d := integrityKernelFixture(t)
			path := filepath.Join(s.moduleDir(integrityKernelModule), "kernel-protection", request.ID, "request.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "mode":
				err = os.Chmod(path, 0644)
			case "hardlink":
				err = os.Link(path, filepath.Join(t.TempDir(), "retained-original"))
			case "symlink":
				outside := filepath.Join(t.TempDir(), "original.json")
				err = os.WriteFile(outside, raw, 0600)
				if err == nil {
					err = os.Rename(path, path+".retained")
				}
				if err == nil {
					err = os.Symlink(outside, path)
				}
			case "unknown-entry":
				err = os.WriteFile(filepath.Join(filepath.Dir(path), "unexpected"), []byte("preserve"), 0600)
			case "truncated-request":
				err = os.WriteFile(path, raw[:len(raw)/2], 0600)
			case "case-alias":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"actor_id"`, `"ACTOR_ID"`, 1)), 0600)
			case "duplicate-field":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"format":1`, `"format":1,"format":1`, 1)), 0600)
			case "null-field":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"expected_revision":0`, `"expected_revision":null`, 1)), 0600)
			case "parent-mode":
				err = os.Chmod(filepath.Dir(path), 0755)
			case "parent-renamed":
				err = os.Rename(filepath.Dir(path), filepath.Dir(path)+".retained")
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.integrityKernelReadOperation(request.ID); err == nil {
				t.Fatal("changed private evidence was adopted", scenario)
			}
			if err = s.integrityKernelReference(""); err == nil {
				t.Fatal("corrupt/unknown inventory was interpreted as empty", scenario)
			}
			if scenario == "parent-renamed" && d.current() {
				t.Fatal("detached private FD masqueraded as named state")
			}
			if fixtureRead(t, s, request.Input.SiteID, "data.txt") != "original website bytes" {
				t.Fatal("rejected inventory changed site bytes")
			}
		})
	}
}

func TestIntegrityKernelJournalRejectsBrokenChainAndOwnsOnlyRecordedIntents(t *testing.T) {
	for _, scenario := range []string{"valid-partial", "missing", "truncated", "sequence", "previous-sha", "foreign-plan", "unexpected-stage", "wrong-flags", "duplicate-target"} {
		t.Run(scenario, func(t *testing.T) {
			_, request, plan, d := integrityKernelFixture(t)
			j := integrityKernelFixtureStart(t, d, request, plan)
			if err := j.append(0, "intent", 0); err != nil {
				t.Fatal(err)
			}
			if scenario == "duplicate-target" {
				if err := j.append(0, "verified", integrityImmutableFlag); err != nil {
					t.Fatal(err)
				}
				if err := j.append(0, "intent", 0); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := integrityKernelRead(d, "progress.jsonl", integrityKernelRecordBytes)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(d.paths[len(d.paths)-1], "progress.jsonl")
			switch scenario {
			case "missing":
				err = os.Rename(path, path+".retained")
			case "truncated":
				err = os.WriteFile(path, raw[:len(raw)-1], 0600)
			case "sequence":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"sequence":2`, `"sequence":3`, 1)), 0600)
			case "previous-sha":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"previous_sha":""`, `"previous_sha":"`+strings.Repeat("a", 64)+`"`, 1)), 0600)
			case "foreign-plan":
				err = os.WriteFile(path, []byte(strings.ReplaceAll(string(raw), integrityKernelDigest(plan), strings.Repeat("a", 64))), 0600)
			case "unexpected-stage":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"stage":"intent"`, `"stage":"not-owned"`, 1)), 0600)
			case "wrong-flags":
				err = os.WriteFile(path, []byte(strings.Replace(string(raw), `"flags":0`, `"flags":16`, 1)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, err := readIntegrityKernelProgress(d, request, plan)
			if scenario == "valid-partial" {
				if err != nil || len(rows) != 2 || rows[1].Stage != "intent" {
					t.Fatal(rows, err)
				}
			} else if err == nil {
				t.Fatal("broken original journal was accepted", scenario)
			}
		})
	}
}

func TestIntegrityKernelPlanRejectsReplacedRootAndMalformedWitnesses(t *testing.T) {
	for _, scenario := range []string{"valid", "hardlink", "foreign-device", "missing-parent", "duplicate-path", "file-before-root", "wrong-public", "file-count", "invalid-sha", "mode-type", "excluded-file", "relative-escape"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, plan, _ := integrityKernelFixture(t)
			switch scenario {
			case "hardlink":
				plan.Targets[1].Original.Identity.Links = 2
			case "foreign-device":
				plan.Targets[1].Original.Identity.Device++
			case "missing-parent":
				plan.Targets[1].Path = "missing/data.txt"
			case "duplicate-path":
				plan.Targets = append(plan.Targets, plan.Targets[1])
			case "file-before-root":
				plan.Targets[0], plan.Targets[1] = plan.Targets[1], plan.Targets[0]
			case "wrong-public":
				plan.Public.Inode++
			case "file-count":
				plan.Targets = append(plan.Targets, make([]integrityKernelTarget, integrityKernelTargets)...)
			case "invalid-sha":
				plan.Targets[1].SHA = "unknown"
			case "mode-type":
				plan.Targets[1].Original.Identity.Mode = unix.S_IFIFO | 0600
			case "excluded-file":
				plan.Excludes = []string{"data.txt"}
			case "relative-escape":
				plan.Targets[1].Path = "../data.txt"
			}
			err := validateIntegrityKernelPlan(plan)
			if (err == nil) != (scenario == "valid") {
				t.Fatal(scenario, err)
			}
		})
	}
	s, request, plan, _ := integrityKernelFixture(t)
	public := filepath.Join(s.Config.SitesDir, request.Input.SiteID, "public")
	if err := os.Rename(public, public+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.integrityKernelOpenPlan(plan); err == nil {
		t.Fatal("replacement public root accepted")
	}
	got, err := os.ReadFile(filepath.Join(public+".retained", "data.txt"))
	if err != nil || string(got) != "original website bytes" {
		t.Fatal("retained original was damaged", err)
	}
}

func TestIntegrityKernelActiveReferencePrecedesBaselineKeyAndLifecycleWrites(t *testing.T) {
	s, request, plan, d := integrityKernelFixture(t)
	integrityKernelFixtureStart(t, d, request, plan)
	before, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.moduleIntegrity(context.Background(), integrityKernelModule, "baseline", core.AppModuleInput{SiteID: request.Input.SiteID}); err == nil {
		t.Fatal("baseline replaced with unknown kernel task")
	}
	if _, err = os.Lstat(filepath.Join(s.Config.SecurityDir, "modules", "integrity-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected operation created a new baseline key", err)
	}
	if err = s.appModuleLifecycle(context.Background(), integrityKernelModule, "uninstall", nil, func(string) {}); err == nil {
		t.Fatal("application uninstalled while original flags uncertain")
	}
	if err = s.updateSoftware(context.Background(), integrityKernelModule, core.IntegrityKernelAppVersion, func(string) {}); err == nil {
		t.Fatal("active controller identity replaced")
	}
	after, err := integrityKernelRead(d, "request.json", 8192)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("reference checks changed original request", err)
	}
	if fixtureRead(t, s, request.Input.SiteID, "data.txt") != "original website bytes" {
		t.Fatal("rejected lifecycle changed original site")
	}
}

func TestIntegrityKernelJSONDoesNotAdoptNullAliasesOrExcessiveNesting(t *testing.T) {
	_, request, _, _ := integrityKernelFixture(t)
	raw, _ := json.Marshal(request)
	for _, changed := range [][]byte{
		[]byte(strings.Replace(string(raw), `"format":1`, `"FORMAT":1`, 1)),
		[]byte(strings.Replace(string(raw), `"format":1`, `"format":null`, 1)),
		append(append([]byte{}, raw...), []byte(" {}")...),
		[]byte(strings.Repeat("[", 18) + "0" + strings.Repeat("]", 18)),
		[]byte(`{"format":1,"format":1}`),
	} {
		var got core.IntegrityKernelRequest
		if integrityKernelJSON(changed, &got) == nil {
			t.Fatal("unclosed original witness accepted")
		}
	}
}

func TestIntegrityKernelReleaseReopensOnlyOriginalAlreadyWritableDirectory(t *testing.T) {
	s, request, plan, _ := integrityKernelFixture(t)
	site, public, err := s.integrityKernelOpenPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := readIntegrityInodeFlags(public, true)
	public.Close()
	site.Close()
	if err != nil {
		t.Fatal(err)
	}
	if observed.Flags&integrityImmutableFlag != 0 {
		t.Fatal("new owned fixture unexpectedly immutable")
	}
	plan.Targets[0].Original = observed
	root := filepath.Join(s.Config.SitesDir, request.Input.SiteID, "public")
	if err = os.Mkdir(filepath.Join(root, "legitimate-after-release"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.integrityKernelOpenPlan(plan); err == nil {
		t.Fatal("enable/verification adopted a modified original directory")
	}
	opened, pinned, err := s.integrityKernelOpenPlanMode(plan, true)
	if err != nil {
		t.Fatal("legitimate directory changes after an already-cleared original bit stranded recovery", err)
	}
	pinned.Close()
	opened.Close()
	if err = os.Rename(root, root+".retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.integrityKernelOpenPlanMode(plan, true); err == nil {
		t.Fatal("release followed a replacement public directory")
	}
	data, err := os.ReadFile(filepath.Join(root+".retained", "data.txt"))
	if err != nil || string(data) != "original website bytes" {
		t.Fatal("original data changed", err)
	}
}

func TestIntegrityKernelUnsignedVersionLabelDoesNotGrantKernelControls(t *testing.T) {
	s, site, _ := appReliabilityFixture(t)
	fixtureWrite(t, s, site, "data.txt", "original website bytes")
	if err := moduleWrite(filepath.Join(s.moduleDir(integrityKernelModule), "installed.json"), map[string]any{"id": integrityKernelModule, "version": core.IntegrityKernelAppVersion, "installed_at": core.Now(), "settings": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.moduleIntegrity(context.Background(), integrityKernelModule, "baseline", core.AppModuleInput{SiteID: site}); err != nil {
		t.Fatal(err)
	}
	status, err := s.integrityKernelStatus(context.Background(), site)
	if err != nil || status.AppVersion != core.IntegrityKernelAppVersion || status.AppSHA != "" || status.State != "upgrade-required" || status.Error == "" {
		t.Fatal("unsigned version label claimed a usable kernel grant", status, err)
	}
	if fixtureRead(t, s, site, "data.txt") != "original website bytes" {
		t.Fatal("read-only receipt observation changed original data")
	}
}

func TestIntegrityKernelProgramUpgradeFenceRetainsOriginalReadonlyQueues(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("actual Root programme inventory fixture required")
	}
	s, request, _, original := integrityKernelFixture(t)
	root := programQueueFixture(t)
	security := filepath.Join(root, "etc/panel/security-apps")
	if err := os.MkdirAll(filepath.Dir(security), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(s.Config.SecurityDir, security); err != nil {
		t.Fatal(err)
	}
	s.Config.SecurityDir = security
	if original.current() {
		t.Fatal("detached old private root was adopted")
	}
	before := programQueueTree(t, root)
	if err := checkProgramUpgradeQueues(context.Background(), root); err == nil || !strings.Contains(err.Error(), "内核保护") {
		t.Fatal("queued kernel transition did not fence programme replacement", err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("refusal changed original programme or kernel records")
	}
	s.mu.Lock()
	closed, err := s.integrityKernelSealAdmission(core.IntegrityKernelCloseRequest{ID: core.ID(), Request: request})
	s.mu.Unlock()
	if err != nil || closed.State != "sealed" {
		t.Fatal(closed, err)
	}
	before = programQueueTree(t, root)
	if err = checkProgramUpgradeQueues(context.Background(), root); err != nil {
		t.Fatal("proven never-dispatched cancellation did not release only its own fence", err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, root)) {
		t.Fatal("successful read-only inventory changed original records")
	}
	t.Log("actual Root programme queue: active kernel request refused; sealed no-dispatch request released; all original bytes and metadata preserved")
}
