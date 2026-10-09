//go:build linux

package executor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A fast diagnosis may reuse a retained, independently hashed native program.
// It is explicitly separate from compiling or accepting a complete release.
func TestAnalyticsHTMLCanonicalHandoffDiagnosis(t *testing.T) {
	prefix := os.Getenv("PANEL_QA_ANALYTICS_DIAGNOSTIC_PREFIX")
	if prefix == "" {
		t.Skip("explicit private diagnosis only; not complete native build acceptance")
	}
	if os.Getenv("PANEL_QA_ANALYTICS_NATIVE") != "1" || os.Geteuid() != 0 || !regexp.MustCompile(`^/var/lib/panel-executor/analytics23[a-z]-native-private-qa-[a-z0-9_]{8}/tmp/analytics-native-[0-9]+/program$`).MatchString(prefix) {
		t.Fatal("unreviewed diagnosis prefix or authority")
	}
	var root syscall.Statfs_t
	if syscall.Statfs("/", &root) != nil || root.Flags&1 == 0 {
		t.Fatal("diagnosis requires a read-only host root before any file creation")
	}
	for _, kind := range []string{"mnt", "net"} {
		self, e := os.Readlink("/proc/self/ns/" + kind)
		init, e2 := os.Readlink("/proc/1/ns/" + kind)
		if e != nil || e2 != nil || self == init {
			t.Fatal("diagnosis requires private namespaces", kind, e, e2)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	module, err := analyticsHTMLFileSHA(ctx, filepath.Join(prefix, "ngx_http_js_module.so"), 32<<20)
	if err != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(os.Getenv("PANEL_QA_ANALYTICS_DIAGNOSTIC_MODULE_SHA")) || module != os.Getenv("PANEL_QA_ANALYTICS_DIAGNOSTIC_MODULE_SHA") {
		t.Fatal("retained module digest mismatch", err)
	}
	program, err := analyticsHTMLFileSHA(ctx, filepath.Join(prefix, "analytics-html.js"), 1<<20)
	if err != nil || program != analyticsHTMLProgramSHA {
		t.Fatal("retained parser digest mismatch", err)
	}
	nginx := "/usr/sbin/nginx"
	output, err := exec.CommandContext(ctx, nginx, "-v").CombinedOutput()
	match := wafNginxVersionPattern.FindStringSubmatch(strings.TrimSpace(string(output)))
	if err != nil || len(match) != 2 || (match[1] != "1.24.0" && match[1] != "1.26.3") {
		t.Fatal("actual diagnosis Nginx identity", err)
	}
	base, err := os.MkdirTemp("/tmp", "analytics-native-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	// The canonical fixture masks /var/lib/panel-executor inside this private
	// namespace. Copy and recheck all nine files before masking the old path.
	copy := filepath.Join(base, "retained-program")
	if err := publishAnalyticsHTMLProgram(ctx, prefix, copy); err != nil {
		t.Fatal("strict private diagnostic copy", err)
	}
	t.Log("private handoff diagnosis reuses a retained module; NOT source-build, signed release, production unit or power-loss acceptance")
	analyticsHTMLNativeGlobalLifecycle(t, ctx, base, copy, nginx, match[1])
}
