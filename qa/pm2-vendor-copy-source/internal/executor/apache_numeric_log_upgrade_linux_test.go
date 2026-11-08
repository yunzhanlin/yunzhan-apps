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

func TestApacheNumericLogUpgradeFenceReadonlyAndPending(t *testing.T) {
	s, path, data := apacheNumericLogFixture(t)
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err != nil {
		t.Fatal("absent histories block an unrelated original programme", err)
	}
	if _, err := os.Lstat(s.moduleDir("apache-waf")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only preflight created an application or lock", err)
	}
	lock, err := s.lockWAFConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err == nil {
		t.Fatal("actual exclusive Apache lease ignored")
	}
	lock.Close()
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err != nil {
		t.Fatal(err)
	}
	entry, err := s.snapshotAndTruncateApacheNumericLogAt(context.Background(), func(stage string) error {
		if stage == "prepared-durable" {
			return errors.New("owned unknown truncate")
		}
		return nil
	})
	if err == nil {
		t.Fatal("unknown cutpoint not reached")
	}
	before, _ := os.ReadFile(path)
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err == nil {
		t.Fatal("unknown snapshot passed programme guard")
	}
	if err := s.recoverApacheWAFBeforeMutation(context.Background()); err == nil {
		t.Fatal("Apache configuration/uninstall bypassed the numeric unknown fence")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(data) || string(after) != string(before) {
		t.Fatal("read guard changed or replayed original data")
	}
	pending, err := s.apacheNumericLogRecoveryEntries(context.Background())
	if err != nil || len(pending) != 1 || pending[0].Archive.ID != entry.ID {
		t.Fatal(err, pending)
	}
	if err := s.retainApacheNumericLogSnapshot(context.Background(), pending[0]); err != nil {
		t.Fatal(err)
	}
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err != nil {
		t.Fatal("explicit retained outcome incorrectly replayed or blocked preservation", err)
	}
	target := filepath.Join(s.apacheNumericLogArchiveDirectory(), entry.ID+".log")
	if err := os.WriteFile(target, []byte(strings.Repeat("x", len(data))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkApacheNumericLogUpgrade(context.Background(), s.Config.SystemRoot); err == nil {
		t.Fatal("changed retained evidence ignored")
	}
}
