//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"local/panel/internal/core"
)

func TestProgramUpgradeQueuesApacheCCFormat2IsTerminalOnlyAndFamilySpecific(t *testing.T) {
	for _, family := range []string{"apache-body", "waf-engine", "analytics-html"} {
		for _, format := range []int{0, 1, 2, 3} {
			for _, state := range []string{"ready", "failed", "building", "unknown"} {
				t.Run(family+"-"+string(rune('0'+format))+"-"+state, func(t *testing.T) {
					root, id := programQueueFixture(t), core.ID()
					base := "var/lib/panel-executor/" + family
					control := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
					writeProgramQueueFixture(t, root, base+"-requests", id, control)
					const start, finish = "2026-11-03T00:00:00Z", "2026-11-03T00:00:01Z"
					switch family {
					case "apache-body":
						// Sparse terminal evidence intentionally grants no ABI,
						// source-integrity or website-activation authority.
						writeProgramQueueFixture(t, root, base+"-builds", id, apacheBodyBuildRecord{Format: format, JobID: id, State: state, Architecture: runtime.GOARCH, Prefix: filepath.Join(apacheBodyEngines, id), StartedAt: start, FinishedAt: finish})
					case "waf-engine":
						writeProgramQueueFixture(t, root, base+"-builds", id, wafEngineBuildRecord{Format: format, JobID: id, State: state, Architecture: runtime.GOARCH, Prefix: filepath.Join(wafNativeEngines, id), StartedAt: start, FinishedAt: finish})
					case "analytics-html":
						writeProgramQueueFixture(t, root, base+"-builds", id, analyticsHTMLBuildRecord{analyticsHTMLEngineIdentity: analyticsHTMLEngineIdentity{Format: format, JobID: id, State: state, Architecture: runtime.GOARCH, Prefix: filepath.Join(analyticsHTMLNativeRoot, id)}, StartedAt: start, FinishedAt: finish})
					}
					before := programQueueTree(t, root)
					err := checkProgramUpgradeQueues(context.Background(), root)
					allowed := (format == 1 || family == "apache-body" && format == 2) && (state == "ready" || state == "failed")
					if (err == nil) != allowed {
						t.Fatal(family, format, state, err)
					}
					if !reflect.DeepEqual(before, programQueueTree(t, root)) {
						t.Fatal("terminal observation rewrote original controls or records")
					}
				})
			}
		}
	}
}

func TestProgramUpgradeQueuesApacheCCFormat2KeepsEveryBindingFence(t *testing.T) {
	for _, kind := range []string{"wrong-id", "wrong-architecture", "wrong-prefix", "bad-start", "missing-finish", "reversed-time", "duplicate-key", "unknown-key", "public-record", "linked-record", "cancelled-but-building"} {
		t.Run(kind, func(t *testing.T) {
			root, id := programQueueFixture(t), core.ID()
			base := "var/lib/panel-executor/apache-body"
			control := wafEngineRequest{Format: 1, JobID: id, CreatedAt: core.Now()}
			writeProgramQueueFixture(t, root, base+"-requests", id, control)
			record := apacheBodyBuildRecord{Format: 2, JobID: id, State: "ready", Architecture: runtime.GOARCH, Prefix: filepath.Join(apacheBodyEngines, id), StartedAt: "2026-11-03T00:00:00Z", FinishedAt: "2026-11-03T00:00:01Z"}
			switch kind {
			case "wrong-id":
				record.JobID = core.ID()
			case "wrong-architecture":
				record.Architecture = "foreign"
			case "wrong-prefix":
				record.Prefix = filepath.Join(wafNativeEngines, id)
			case "bad-start":
				record.StartedAt = "unknown"
			case "missing-finish":
				record.FinishedAt = ""
			case "reversed-time":
				record.FinishedAt = "2026-11-02T23:59:59Z"
			case "cancelled-but-building":
				record.State = "building"
				writeProgramQueueFixture(t, root, base+"-cancellations", id, control)
			}
			file := writeProgramQueueFixture(t, root, base+"-builds", id, record)
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "duplicate-key":
				err = os.WriteFile(file, bytesAppendObject(raw, `"format":2`), 0600)
			case "unknown-key":
				err = os.WriteFile(file, bytesAppendObject(raw, `"caller_trust":true`), 0600)
			case "public-record":
				err = os.Chmod(file, 0644)
			case "linked-record":
				err = os.Link(file, filepath.Join(root, "own-alias"))
			}
			if err != nil {
				t.Fatal(err)
			}
			before := programQueueTree(t, root)
			if checkProgramUpgradeQueues(context.Background(), root) == nil {
				t.Fatal("Format2 bypassed an original binding, privacy, pending-state or JSON fence")
			}
			if !reflect.DeepEqual(before, programQueueTree(t, root)) {
				t.Fatal("refusal modified original evidence")
			}
		})
	}
}

var nativeApacheCCProgramQueueJob = flag.String("native-apache-cc-programme-queue-job", "", "test ELF only: existing ready Format2 and full read-only programme queues; no install or app authority")

func TestNativeApacheCCProgrammeQueuesReadOriginalFormat2WithoutWrites(t *testing.T) {
	id := *nativeApacheCCProgramQueueJob
	if id == "" {
		t.Skip("requires explicit genuine native Format2 fixture; no installed-service claim")
	}
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("actual Root and one exact existing native build identity required")
	}
	record, err := readApacheBodyBuildRecord(id)
	if err != nil || record.Format != 2 || record.State != "ready" || record.CCEngine != apacheCCEngineVersion {
		t.Fatal("original ready CC record required", err)
	}
	file := filepath.Join(apacheBodyJobs, id+".json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := verifyApacheBodyBuildContext(ctx, id); err != nil {
		t.Fatal("terminal admission cannot substitute for genuine sealed engine integrity", err)
	}
	if err := checkProgramUpgradeQueues(ctx, "/"); err != nil {
		t.Fatal("full native programme queue check refused original ready Format2", err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("actual queue observation changed the original record", err)
	}
	var actual apacheBodyBuildRecord
	if json.Unmarshal(after, &actual) != nil || actual.Format != 2 {
		t.Fatal("original Format2 was relabelled")
	}
	t.Logf("NATIVE_APACHE_CC_PROGRAM_QUEUE_READONLY %s", id)
}
