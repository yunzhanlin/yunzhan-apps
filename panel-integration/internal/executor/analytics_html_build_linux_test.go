//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestAnalyticsHTMLBuildContractRequiresExactCompletedProvenance(t *testing.T) {
	id := strings.Repeat("a", 32)
	sha := strings.Repeat("b", 64)
	record := analyticsHTMLBuildRecord{analyticsHTMLEngineIdentity: analyticsHTMLEngineIdentity{Format: 1, JobID: id, State: "ready", Architecture: runtime.GOARCH, Prefix: filepath.Join(analyticsHTMLNativeRoot, id), ProgramSHA: analyticsHTMLProgramSHA, NginxBinary: "/usr/sbin/nginx", NginxSHA: sha, ModuleSHA: sha, TreeSHA: sha}, NginxVersion: "1.24.0", PatchSourceSHA: analyticsNJSHeaderSourceSHA, SourceSHA: map[string]string{}, StartedAt: core.Now(), FinishedAt: core.Now(), Steps: []core.Step{{Time: core.Now(), Message: "actual ABI"}}, ABIValidated: true}
	sources, _ := analyticsHTMLSources(record.NginxVersion)
	for _, source := range sources {
		record.SourceSHA[source.Name] = source.SHA256
	}
	if err := analyticsHTMLBuildContract(record); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*analyticsHTMLBuildRecord){
		func(r *analyticsHTMLBuildRecord) { r.State = "building" }, func(r *analyticsHTMLBuildRecord) { r.ABIValidated = false }, func(r *analyticsHTMLBuildRecord) { r.ProgramSHA = strings.Repeat("c", 64) }, func(r *analyticsHTMLBuildRecord) { r.PatchSourceSHA = "unknown" }, func(r *analyticsHTMLBuildRecord) { r.NginxSHA = strings.ToUpper(sha) }, func(r *analyticsHTMLBuildRecord) { r.FinishedAt = "" }, func(r *analyticsHTMLBuildRecord) { r.Prefix = "/arbitrary" }, func(r *analyticsHTMLBuildRecord) { r.SourceSHA = map[string]string{} }, func(r *analyticsHTMLBuildRecord) { r.Error = "unresolved" },
	} {
		changed := record
		mutate(&changed)
		if analyticsHTMLBuildContract(changed) == nil {
			t.Fatal("incomplete or foreign provenance accepted")
		}
	}
}

func TestAnalyticsHTMLImmutableFileRejectsHardlinksFIFOWritableAndLimits(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "module")
	content := []byte("owned immutable program")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	if got, err := analyticsHTMLFileSHA(context.Background(), path, 1024); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatal(got, err)
	}
	if _, err := analyticsHTMLFileSHA(context.Background(), path, 3); err == nil {
		t.Fatal("oversized program adopted")
	}
	link := filepath.Join(root, "hard")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := analyticsHTMLFileSHA(context.Background(), path, 1024); err == nil {
		t.Fatal("shared program adopted")
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := analyticsHTMLFileSHA(context.Background(), fifo, 1024); err == nil {
		t.Fatal("FIFO accepted")
	}
	writable := filepath.Join(root, "writable")
	if err := os.WriteFile(writable, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0664); err != nil {
		t.Fatal(err)
	}
	if _, err := analyticsHTMLFileSHA(context.Background(), writable, 1024); err == nil {
		t.Fatal("shared writable program accepted")
	}
}

func TestAnalyticsHTMLPrivateRecordsRejectLinksUnknownFieldsAndReuse(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "record.json")
	value := wafEngineRequest{1, core.ID(), core.Now()}
	if err := createAnalyticsHTMLPrivateJSON(path, value); err != nil {
		t.Fatal(err)
	}
	var got wafEngineRequest
	if err := readAnalyticsHTMLPrivateJSON(path, 1024, &got); err != nil || got != value {
		t.Fatal(got, err)
	}
	if createAnalyticsHTMLPrivateJSON(path, value) == nil {
		t.Fatal("immutable request overwritten")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if readAnalyticsHTMLPrivateJSON(link, 1024, &got) == nil {
		t.Fatal("link followed")
	}
	hard := filepath.Join(root, "hard")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if readAnalyticsHTMLPrivateJSON(hard, 1024, &got) == nil {
		t.Fatal("shared hardlink accepted")
	}
	bad := filepath.Join(root, "unknown.json")
	data, _ := json.Marshal(map[string]any{"format": 1, "job_id": value.JobID, "created_at": value.CreatedAt, "url": "untrusted"})
	if err := os.WriteFile(bad, data, 0600); err != nil {
		t.Fatal(err)
	}
	if readAnalyticsHTMLPrivateJSON(bad, 1024, &got) == nil {
		t.Fatal("unknown authority accepted")
	}
	if err := os.Chmod(bad, 0644); err != nil {
		t.Fatal(err)
	}
	if readAnalyticsHTMLPrivateJSON(bad, 1024, &got) == nil {
		t.Fatal("nonprivate record accepted")
	}
}

func TestAnalyticsHTMLPublisherPreservesByteOwnerModeAndImmutableDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "program")
	if err := os.Mkdir(source, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(source, 0755); err != nil {
		t.Fatal(err)
	}
	names := []string{"ngx_http_js_module.so", "analytics-html.js", "source.json", "parse5-LICENSE", "entities-LICENSE", "njs-LICENSE", "nginx-LICENSE", "quickjs-LICENSE", "yunzhan-njs-validator-patch.txt"}
	for _, name := range names {
		path := filepath.Join(source, name)
		if err := os.WriteFile(path, []byte("owned fixture:"+name), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	// systemd's private UMask must not make the resulting worker code unreadable.
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	destination := filepath.Join(root, "published")
	if err := publishAnalyticsHTMLProgram(context.Background(), source, destination); err != nil {
		t.Fatal(err)
	}
	before, err := runtimeTreeSHA(context.Background(), destination, destination)
	if err != nil {
		t.Fatal(err)
	}
	if publishAnalyticsHTMLProgram(context.Background(), source, destination) == nil {
		t.Fatal("existing program replaced")
	}
	after, err := runtimeTreeSHA(context.Background(), destination, destination)
	if err != nil || before != after {
		t.Fatal("old program changed", err)
	}
	if err := os.WriteFile(filepath.Join(source, "unknown-command"), []byte("not executable authority"), 0600); err != nil {
		t.Fatal(err)
	}
	refused := filepath.Join(root, "refused")
	if publishAnalyticsHTMLProgram(context.Background(), source, refused) == nil {
		t.Fatal("unknown resource published")
	}
	if _, err := os.Lstat(refused); !os.IsNotExist(err) {
		t.Fatal("unreviewed resource caused first destination write")
	}
}

func TestAnalyticsHTMLDedicatedUnitStatesAndClosedBuildInputs(t *testing.T) {
	id := strings.Repeat("a", 32)
	s := testService(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name != "/usr/bin/systemctl" || len(args) != 3 || args[2] != "panel-analytics-html-build@"+id+".service" {
			t.Fatal("unreviewed unit", name, args)
		}
		return "LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStartTimestampMonotonic=0\n", nil
	})
	state, _, err := s.analyticsHTMLUnitState(context.Background(), id)
	if err != nil || state != "not-started" {
		t.Fatal(state, err)
	}
	if _, err := s.startAnalyticsHTMLBuild(context.Background(), id); err == nil {
		t.Fatal("uninstalled/nonproduction environment started build")
	}
}
