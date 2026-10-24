//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWAFBodyLogHealthRejectsUncommittedFirstIndexAndPreservesCurrent(t *testing.T) {
	s, path, data := wafBodyLogFixture(t)
	if err := s.wafBodyLogHealth(context.Background()); err != nil {
		t.Fatal("fresh evidence incorrectly degraded", err)
	}
	_, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(at string) error {
		if at == "intent-index-stage-created" {
			return errors.New("owned first index interruption")
		}
		return nil
	})
	if err == nil {
		t.Fatal("interruption not reached")
	}
	fresh := New(s.Config)
	if err := fresh.wafBodyLogHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "未提交索引") {
		t.Fatal("uncommitted empty first index reported healthy", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(data) {
		t.Fatal("health check modified live evidence")
	}
}

func TestWAFBodyLogHealthChecksCompletedDigestAndRetainedUnknownResult(t *testing.T) {
	for _, kind := range []string{"completed", "digest", "missing", "permissions", "retained-missing"} {
		t.Run(kind, func(t *testing.T) {
			s, path, data := wafBodyLogFixture(t)
			var target string
			if kind == "retained-missing" {
				_, err := s.snapshotAndTruncateWAFBodyLogAt(context.Background(), func(at string) error {
					if at == "intent-durable" {
						return errors.New("owned missing snapshot")
					}
					return nil
				})
				if err == nil {
					t.Fatal("interruption not reached")
				}
				pending, err := s.wafBodyLogRecoveryEntries(context.Background())
				if err != nil || len(pending) != 1 {
					t.Fatal(pending, err)
				}
				if err := s.retainWAFBodyLogSnapshot(context.Background(), pending[0]); err != nil {
					t.Fatal(err)
				}
			} else {
				archive, err := s.snapshotAndTruncateWAFBodyLog(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(s.wafBodyLogArchiveDirectory(), archive.ID+".log")
				if err := os.WriteFile(path, data, 0640); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "digest":
				os.WriteFile(target, []byte(strings.Repeat("x", len(data))), 0600)
			case "missing":
				os.Remove(target)
			case "permissions":
				os.Chmod(target, 0644)
			}
			err := New(s.Config).wafBodyLogHealth(context.Background())
			if (err == nil) != (kind == "completed") {
				t.Fatal("health does not reflect evidence integrity", kind, err)
			}
			after, _ := os.ReadFile(path)
			if string(after) != string(data) {
				t.Fatal("health observation modified live evidence")
			}
		})
	}
}
