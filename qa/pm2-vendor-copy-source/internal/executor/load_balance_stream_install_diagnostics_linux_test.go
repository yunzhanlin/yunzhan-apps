//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/core"
)

func TestLoadBalanceStreamInstallDiagnosticKeepsCauseAndUnknownBoundary(t *testing.T) {
	if err := streamInstallPhaseError("资源余量", context.DeadlineExceeded); !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "安装阶段[资源余量]") {
		t.Fatal("original error cause or stage lost", err)
	}
	if err := streamInstallPhaseError("固定前置条件", nil); !errors.Is(err, errLoadBalanceStreamInstallationGate) {
		t.Fatal("missing cause became success", err)
	}
	base := t.TempDir()
	s := New(Config{SystemRoot: base, SecurityDir: filepath.Join(base, "security")})
	result, err := s.submitLoadBalanceStreamInstall(context.Background(), core.LoadBalanceStreamInstallSubmission{Format: 1, JobID: strings.Repeat("a", 32)})
	if !errors.Is(err, errLoadBalanceStreamInstallationGate) || result.State != "unknown" || !strings.Contains(err.Error(), "固定主机与签名构建") {
		t.Fatal("diagnostic bypassed actual host/authority boundary", result, err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected diagnostic reached host or created a native journal", err)
	}
}
