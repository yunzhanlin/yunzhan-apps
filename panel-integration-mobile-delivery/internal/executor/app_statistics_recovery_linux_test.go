//go:build linux

package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func statisticsRecoveryTestJournal() []byte {
	raw := make([]byte, 512+2*4104)
	copy(raw, statisticsJournalMagic)
	for offset, value := range map[int]uint32{8: 2, 12: 123, 16: 40, 20: 512, 24: 4096} {
		binary.BigEndian.PutUint32(raw[offset:], value)
	}
	for i := 0; i < 2; i++ {
		offset := 512 + i*4104
		binary.BigEndian.PutUint32(raw[offset:], uint32(i+1))
		binary.BigEndian.PutUint32(raw[offset+4100:], 123)
	}
	return raw
}

func TestStatisticsRecoveryJournalClosedFormatAndChecksums(t *testing.T) {
	valid := statisticsRecoveryTestJournal()
	if err := validateStatisticsRollbackJournal(context.Background(), bytes.NewReader(valid), int64(len(valid)), 40*4096); err != nil {
		t.Fatal(err)
	}
	aligned := (len(valid) + 511) / 512 * 512
	withEmptyHeader := make([]byte, aligned+512)
	copy(withEmptyHeader, valid)
	for offset, value := range map[int]uint32{12: 987, 16: 40, 20: 512, 24: 4096} {
		binary.BigEndian.PutUint32(withEmptyHeader[aligned+offset:], value)
	}
	if err := validateStatisticsRollbackJournal(context.Background(), bytes.NewReader(withEmptyHeader), int64(len(withEmptyHeader)), 40*4096); err != nil {
		t.Fatal("documented native cache flush reserved empty header refused", err)
	}
	for _, offset := range []int{len(valid), aligned, aligned + 8, aligned + 16, aligned + 20, aligned + 24, aligned + 50} {
		bad := append([]byte{}, withEmptyHeader...)
		bad[offset] ^= 1
		if err := validateStatisticsRollbackJournal(context.Background(), bytes.NewReader(bad), int64(len(bad)), 40*4096); err == nil {
			t.Fatal("unsafe next header or padding admitted", offset)
		}
	}
	cases := map[string]func([]byte) []byte{
		"magic":              func(b []byte) []byte { b[0] ^= 1; return b },
		"empty-records":      func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], 0); return b },
		"open-ended-records": func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:], ^uint32(0)); return b },
		"wrong-page-size":    func(b []byte) []byte { binary.BigEndian.PutUint32(b[24:], 8192); return b },
		"sector":             func(b []byte) []byte { binary.BigEndian.PutUint32(b[20:], 513); return b },
		"padding":            func(b []byte) []byte { b[99] = 1; return b },
		"checksum":           func(b []byte) []byte { b[512+4+3896] ^= 1; return b },
		"zero-page":          func(b []byte) []byte { binary.BigEndian.PutUint32(b[512:], 0); return b },
		"outside-original":   func(b []byte) []byte { binary.BigEndian.PutUint32(b[512:], 41); return b },
		"duplicate-page":     func(b []byte) []byte { binary.BigEndian.PutUint32(b[512+4104:], 1); return b },
		"short-record":       func(b []byte) []byte { return b[:len(b)-1] },
		"extra-segment":      func(b []byte) []byte { return append(b, make([]byte, 512)...) },
		"external-super-journal": func(b []byte) []byte {
			return append(b, append([]byte("/unowned/never-touch"), statisticsJournalMagic...)...)
		},
		"embedded-super-journal-tail": func(b []byte) []byte { copy(b[len(b)-8:], statisticsJournalMagic); return b },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := change(append([]byte{}, valid...))
			if err := validateStatisticsRollbackJournal(context.Background(), bytes.NewReader(b), int64(len(b)), 40*4096); err == nil {
				t.Fatal("unsafe/unsupported journal admitted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateStatisticsRollbackJournal(ctx, bytes.NewReader(valid), int64(len(valid)), 40*4096); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled journal read continued", err)
	}
}

func statisticsRecoveryTestHash(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func statisticsRecoveryTestFixture(t *testing.T) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	s := New(Config{SecurityDir: filepath.Join(base, "security"), StateDir: filepath.Join(base, "state"), SystemRoot: base, ConfDir: filepath.Join(base, "conf"), NginxConf: filepath.Join(base, "nginx.conf")})
	db, err := s.openStatisticsHistorySchema(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	// Enough existing pages for a real cache spill, without synthetic journals.
	for i := 0; i < 40; i++ {
		if _, err = db.Exec("INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES('kept',0,'','/committed',200,0,0,?)", strings.Repeat("a", 3800)); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = moduleWrite(filepath.Join(s.moduleDir("website-statistics-v2"), "installed.json"), map[string]any{"id": "website-statistics-v2", "version": "2.5.0", "installed_at": "2026-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	return s, filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")
}

func TestStatisticsRecoveryRealKilledWriterHelper(t *testing.T) {
	file := os.Getenv("PANEL_RECOVERY_KILLED_FIXTURE")
	if file == "" {
		return
	}
	if !filepath.IsAbs(file) || !strings.HasPrefix(file, os.TempDir()+"/TestStatisticsRecovery") {
		t.Fatal("writer is not bound to this isolated test directory")
	}
	// Use the system SQLite engine's documented cacheflush API to guarantee a
	// real hot journal, without hand-editing a header or database page. Exec
	// replaces this helper so the parent kills the actual native writer PID.
	// Production recovery below still uses the actual Go SQLite handler.
	code := `import ctypes,ctypes.util,sys,time
c=ctypes.CDLL(ctypes.util.find_library('sqlite3'));p=ctypes.c_void_p()
c.sqlite3_open_v2.argtypes=[ctypes.c_char_p,ctypes.POINTER(ctypes.c_void_p),ctypes.c_int,ctypes.c_void_p];c.sqlite3_open_v2.restype=ctypes.c_int
c.sqlite3_exec.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p];c.sqlite3_exec.restype=ctypes.c_int
c.sqlite3_db_cacheflush.argtypes=[ctypes.c_void_p];c.sqlite3_db_cacheflush.restype=ctypes.c_int
assert c.sqlite3_open_v2(sys.argv[1].encode(),ctypes.byref(p),2,None)==0
assert c.sqlite3_exec(p,b'PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; BEGIN IMMEDIATE; UPDATE access_rows SET seconds=99;',None,None,None)==0
assert c.sqlite3_db_cacheflush(p)==0
print('RECOVERY_ACTUAL_TRANSACTION_READY',flush=True)
time.sleep(3600)
`
	if err := syscall.Exec("/usr/bin/python3", []string{"python3", "-B", "-c", code, file}, os.Environ()); err != nil {
		t.Fatal(err)
	}
}

func statisticsRecoveryTestKill(t *testing.T, file string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStatisticsRecoveryRealKilledWriterHelper$", "-test.count=1")
	child.Env = append(os.Environ(), "PANEL_RECOVERY_KILLED_FIXTURE="+file)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = child.Stdout
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill() }()
	scanner := bufio.NewScanner(stdout)
	ready := false
	for scanner.Scan() {
		if scanner.Text() == "RECOVERY_ACTUAL_TRANSACTION_READY" {
			ready = true
			break
		}
	}
	if !ready {
		_ = child.Wait()
		t.Fatal("child did not reach uncommitted transaction")
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err == nil {
		t.Fatal("child was not killed")
	}
}

func TestStatisticsRecoveryActualHotJournalBacksUpThenNativeRollbackWithoutTaskReplay(t *testing.T) {
	s, file := statisticsRecoveryTestFixture(t)
	statisticsRecoveryTestKill(t, file)
	journalBefore, err := os.Lstat(file + "-journal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.statisticsHistorySchemaReadOnly(context.Background()); err == nil {
		t.Fatal("fixture is not an actual read-only-refused hot journal")
	}
	journalAfter, err := os.Lstat(file + "-journal")
	if err != nil || !sameStatisticsRecoveryFile(journalBefore, journalAfter) || journalBefore.Sys().(*syscall.Stat_t).Ctim != journalAfter.Sys().(*syscall.Stat_t).Ctim {
		t.Fatal("read-only health touched pending journal bytes or metadata", err)
	}
	root := filepath.Dir(file)
	names := []string{"access.sqlite", "access.sqlite-journal", "installed.json"}
	original := map[string][]byte{}
	parts := []string{}
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		original[name] = raw
		parts = append(parts, statisticsRecoveryTestHash(t, filepath.Join(root, name)))
	}
	expected := strings.Join(parts, ":")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := s.recoverStatisticsHistory(ctx, expected); err != nil {
		t.Fatal("native recovery refused real valid hot journal", err)
	}
	cases, err := filepath.Glob(filepath.Join(root, "history-recovery-*"))
	if err != nil || len(cases) != 1 {
		t.Fatal("missing immutable recovery evidence", cases, err)
	}
	for _, name := range names {
		backup, err := os.ReadFile(filepath.Join(cases[0], name))
		if err != nil || !bytes.Equal(backup, original[name]) {
			t.Fatal("original evidence not preserved", name, err)
		}
	}
	var receipt map[string]any
	raw, _ := os.ReadFile(filepath.Join(cases[0], "result.json"))
	if json.Unmarshal(raw, &receipt) != nil || receipt["complete"] != true || receipt["live_rollback_attempted"] != true {
		t.Fatal("missing truthful terminal receipt", receipt)
	}
	if version, err := s.statisticsHistorySchemaReadOnly(context.Background()); err != nil || version != 2 {
		t.Fatal("original read-only health remains broken", version, err)
	}
	db, err := sql.Open("sqlite", "file:"+file+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	var count int
	err = db.QueryRow("SELECT count(*) FROM access_rows WHERE seconds=0 AND path='/committed'").Scan(&count)
	db.Close()
	if err != nil || count != 40 {
		t.Fatal("committed rows changed or uncommitted data accepted", count, err)
	}
	before := statisticsRecoveryTestHash(t, file)
	if err = s.recoverStatisticsHistory(context.Background(), expected); err == nil || before != statisticsRecoveryTestHash(t, file) {
		t.Fatal("old recovery replayed or changed recovered data", err)
	}
}

func TestStatisticsRecoveryInvalidAuthorityAndForeignSchemaDoNotTouchOriginals(t *testing.T) {
	for _, scenario := range []string{"wrong-hash", "foreign-schema", "wal", "linked-database", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			s, file := statisticsRecoveryTestFixture(t)
			if scenario == "foreign-schema" {
				db, err := sql.Open("sqlite", file)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec("CREATE TABLE unowned(secret TEXT)")
				db.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			statisticsRecoveryTestKill(t, file)
			root := filepath.Dir(file)
			if scenario == "wal" {
				if err := os.WriteFile(file+"-wal", []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "linked-database" {
				if err := os.Link(file, file+".foreign-link"); err != nil {
					t.Fatal(err)
				}
			}
			names := []string{"access.sqlite", "access.sqlite-journal", "installed.json"}
			before, parts := map[string]string{}, []string{}
			for _, name := range names {
				hash := statisticsRecoveryTestHash(t, filepath.Join(root, name))
				before[name] = hash
				parts = append(parts, hash)
			}
			if scenario == "wrong-hash" {
				parts[0] = strings.Repeat("0", 64)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			if err := s.recoverStatisticsHistory(ctx, strings.Join(parts, ":")); err == nil {
				t.Fatal("unsafe recovery admitted")
			}
			after := map[string]string{}
			for _, name := range names {
				after[name] = statisticsRecoveryTestHash(t, filepath.Join(root, name))
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("original evidence changed after refusal")
			}
		})
	}
	if err := (&Service{}).recoverStatisticsHistory(nil, ""); err == nil {
		t.Fatal("missing context accepted")
	}
}
