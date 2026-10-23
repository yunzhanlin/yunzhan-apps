//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCompilerCollectionPrivateDiagnosticsAreBoundedNumericAndNonAuthorizing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.log")
	log, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	scope := &runtimeCompilerScope{collectionMemberSnapshots: 150, collectionReapedTotal: 4096}
	for pid := 2; pid < 66; pid++ {
		scope.collectionReaped = append(scope.collectionReaped, compilerWaitWitness{pid: pid, status: syscall.WaitStatus(0)})
	}
	scope.collectionReaped[1].status = syscall.WaitStatus(syscall.SIGKILL)
	scope.collectionReaped[2].status = syscall.WaitStatus(42 << 8)
	if err := scope.writeCollectionDiagnostics(log); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 8<<10 || strings.Count(string(data), "compiler-wait ") != 64 || !strings.Contains(string(data), "member_snapshots=150 reaped=4096 sampled=64") || !strings.Contains(string(data), "pid=2 wait_status=0 exit=0 signal=0") || !strings.Contains(string(data), "pid=3 wait_status=9 exit=-1 signal=9") || !strings.Contains(string(data), "pid=4 wait_status=10752 exit=42 signal=0") {
		t.Fatal("fixed numeric private diagnostics changed", err, string(data))
	}
	if len(scope.pidfds) != 0 || scope.collectionReapedTotal != 4096 {
		t.Fatal("logging changed collection authority")
	}
	if err := log.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := scope.writeCollectionDiagnostics(log); err == nil {
		t.Fatal("full log accepted")
	}
	st, err := log.Stat()
	if err != nil || st.Size() != 64<<20 {
		t.Fatal("diagnostic refusal changed full log", err)
	}
}
