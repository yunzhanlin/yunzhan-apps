//go:build linux

package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"local/panel/internal/appcatalog"
	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func TestLoadBalanceStreamInstallParentCapabilitySetIsClosed(t *testing.T) {
	base := "Name:\tfixture\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nNoNewPrivs:\t1\nCapInh:\t0000000000000000\nCapPrm:\t00000000000000cd\nCapEff:\t00000000000000cd\nCapBnd:\t00000000000000cd\nCapAmb:\t0000000000000000\n"
	if !streamInstallRootCapabilities([]byte(base)) {
		t.Fatal("exact minimal identity/NNP/capability set refused")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		for _, fault := range []string{"missing", "duplicate", "extra-bit", "invalid-hex"} {
			t.Run(key+"/"+fault, func(t *testing.T) {
				lines := strings.Split(base, "\n")
				var out []string
				for _, line := range lines {
					if strings.HasPrefix(line, key+":") {
						switch fault {
						case "missing":
							continue
						case "duplicate":
							out = append(out, line)
						case "extra-bit":
							f := strings.Fields(line)
							v, _ := strconv.ParseUint(f[1], 16, 64)
							line = key + ":\t" + strconv.FormatUint(v|(1<<19), 16)
						case "invalid-hex":
							line = key + ":\twrong"
						}
					}
					out = append(out, line)
				}
				if streamInstallRootCapabilities([]byte(strings.Join(out, "\n"))) {
					t.Fatal("expanded or ambiguous kernel capability set accepted")
				}
			})
		}
	}
	for _, bad := range []string{"", strings.Replace(base, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), strings.Replace(base, "Uid:\t0\t0\t0\t0", "Uid:\t100\t0\t0\t0", 1), strings.Replace(base, "Gid:\t0\t0\t0\t0", "Gid:\t0\t100\t0\t0", 1)} {
		if streamInstallRootCapabilities([]byte(bad)) {
			t.Fatal("wrong identity or missing kernel witness accepted")
		}
	}
}

func TestLoadBalanceStreamInstallMemoryAccountsBothChildrenAndHostReserve(t *testing.T) {
	for _, kb := range []int64{0, 1048575, 1048576, 1048577} {
		raw := []byte("MemTotal: 4194304 kB\nMemAvailable: " + strconv.FormatInt(kb, 10) + " kB\n")
		if got := loadBalanceStreamInstallMemoryAdmission(raw); (got == nil) != (kb >= 1048576) {
			t.Fatal("aggregate original parent+child cap or independent reserve changed", kb, got)
		}
	}
	for _, bad := range []string{"", "MemAvailable: 1048576 kB\n", "MemTotal: 4194304 kB\nMemAvailable: 1048576 MB\n", "MemTotal: 4194304 kB\nMemAvailable: 1048576 kB\nMemAvailable: 1048576 kB\n"} {
		if loadBalanceStreamInstallMemoryAdmission([]byte(bad)) == nil {
			t.Fatal("unmeasured or ambiguous host memory admitted")
		}
	}
}

func TestLoadBalanceStreamInstallUnboundParentAndOldOpenerNeverPerformEffects(t *testing.T) {
	if loadBalanceStreamCompiledProgrammeInputsSHA256 != "" {
		t.Skip("unbound component fixture only; frozen release uses the independently compiled cohort")
	}
	for _, job := range []string{"", core.ID(), "bad", "../bad", strings.Repeat("a", 31), strings.Repeat("a", 33)} {
		if err := RunLoadBalanceStreamInstallJob(job); err != errLoadBalanceStreamInstallationGate {
			t.Fatal("unbound fixed parent reached host dispatch", err)
		}
	}
	result := core.LoadBalanceStreamInstallResult{Format: 1, JobID: core.ID(), Version: loadbalancestream.AppVersion, State: "unknown"}
	for _, held := range []*loadBalanceStreamHeldSubmission{nil, {}, {creator: true}, {nativeParentExitObserved: true}} {
		if err := retainLoadBalanceStreamOriginalExit(context.Background(), held, result); err == nil {
			t.Fatal("old/fabricated handoff created original native completion")
		}
	}
}

func TestLoadBalanceStreamInstallPreflightRequiresFreshConcreteOriginalOwner(t *testing.T) {
	for _, owner := range []*loadBalanceStreamUpgradeOwner{nil, {}, {parent: &loadBalanceStreamInstallController{}}, {child: &loadBalanceStreamAccountParent{}}, {submission: &loadBalanceStreamHeldSubmission{}}, {submission: &loadBalanceStreamHeldSubmission{creator: true}}} {
		if err := preflightLoadBalanceStreamInstall(context.Background(), owner); err != errLoadBalanceStreamInstallationGate {
			t.Fatal("fabricated or old preflight owner reached actual host preflight", err)
		}
	}
}

func TestLoadBalanceStreamInstallRPCFixtureRefusesBeforeHostPathsOrCommands(t *testing.T) {
	base := t.TempDir()
	calls := 0
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security"), Run: func(context.Context, string, ...string) (string, error) { calls++; return "", nil }})
	m := http.NewServeMux()
	s.loadBalanceStreamInstallRoutes(m)
	v := core.LoadBalanceStreamInstallSubmission{Format: 1, JobID: core.ID(), Release: appcatalog.LoadBalanceStreamReleaseEnvelope{Catalog: []byte(`{"fixture":true}`), Signature: []byte("not-signed"), AppManifest: []byte(`{"fixture":true}`)}}
	raw, err := core.LoadBalanceStreamInstallSubmissionBytes(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{string(raw), "null", "{}", strings.Replace(string(raw), `"format":1`, `"format":1,"nativeParentExitObserved":true`, 1)} {
		recorder := httptest.NewRecorder()
		m.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/load-balance-stream/install-jobs", strings.NewReader(input)))
		if recorder.Code != 400 && recorder.Code != 409 {
			t.Fatal("unbound native fixture accepted input", recorder.Code)
		}
	}
	for _, job := range []string{"bad", v.JobID} {
		recorder := httptest.NewRecorder()
		m.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/load-balance-stream/install-jobs/"+job, nil))
		if recorder.Code != 400 && recorder.Code != 409 {
			t.Fatal("fixture native GET reached real host or reported completion", recorder.Code)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 || calls != 0 {
		t.Fatal("rejected fixture created paths or dispatched commands", err)
	}
}
