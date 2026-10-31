//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPrivateBuildDiskBudgetRetainsCacheLimitAndCallerLabel(t *testing.T) {
	dir := t.TempDir()
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Bsize < 1 || fs.Bavail*uint64(fs.Bsize) < 1<<30 {
		t.Skip("fixture filesystem must have the normal disk safety margin")
	}
	f, err := os.Create(filepath.Join(dir, "sparse-cache-limit-fixture"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate((6 << 30) + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"WAF", "运行时"} {
		err = privateBuildDiskBudget(dir, label)
		if err == nil || !strings.HasPrefix(err.Error(), label+" 私有构建缓存超过 6 GiB") {
			t.Fatal(label, err)
		}
	}
	if err = wafBuildDiskBudget(dir); err == nil || !strings.HasPrefix(err.Error(), "WAF ") {
		t.Fatal("WAF wrapper changed its existing contract", err)
	}
	st, err := os.Stat(filepath.Join(dir, "sparse-cache-limit-fixture"))
	if err != nil || st.Size() != (6<<30)+1 {
		t.Fatal("budget check changed the retained cache", st, err)
	}
}
