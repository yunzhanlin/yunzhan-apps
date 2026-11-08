package executor

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Compile and execute the shipped C admission algorithm. These deterministic
// budget and process-death regressions are separate from real Apache HTTP,
// signed installation and application-store acceptance.
func TestApacheCCNativeAdmissionBudgetAndProcessRecovery(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("the native CC regression requires a C compiler:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "apache-cc-core-test")
	args := []string{"-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-O2", "-fstack-protector-strong", "-Iassets", "testdata/apache-cc-core-test.c", "-o", binary}
	if runtime.GOOS == "linux" {
		args = append(args, "-pthread")
	}
	if out, err := exec.CommandContext(ctx, cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("compile actual native admission source: %v\n%s", err, out)
	}
	out, err := exec.CommandContext(ctx, binary, t.TempDir()).CombinedOutput()
	if err != nil {
		t.Fatalf("actual native admission regression: %v\n%s", err, out)
	}
	want := 5
	if runtime.GOOS == "linux" {
		want = 6
	}
	if strings.Count(string(out), "PASS ") != want {
		t.Fatalf("expected %d executed native cases, got %s", want, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}
