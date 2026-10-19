package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"testing"
	"time"
)

func TestApplyCancelledWhileWaitingDoesNotStartSiteMutation(t *testing.T) {
	s := New(Config{StateDir: t.TempDir()})
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, e := s.Apply(ctx, core.ApplyRequest{})
	if !errors.Is(e, context.DeadlineExceeded) || !result.Restored || len(result.Steps) != 0 {
		t.Fatal(result, e)
	}
}
