//go:build linux

package diskusage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

var ErrLedgerUnavailable = errors.New("私有扫描索引的身份、容量或持久化无法核对；未退回无限内存索引或覆盖原索引")
var ErrMetadataChanged = errors.New("同一扫描 inode 的类型或占用已改变；结果不是一致快照")

// Ledger is a fresh private inode index, not a job queue or resume protocol.
// It bounds SQLite pages/cache, uses at most 64 changes per transaction, and
// retains the original spool even on failure. A caller must still impose worker
// CPU/IO/memory/time/filesize limits; max_page_count is not a total-I/O quota.
type Ledger struct {
	mu        sync.Mutex
	db        *sql.DB
	root      *os.Root
	directory *os.File
	file      *os.File
	identity  Identity
	rootInfo  os.FileInfo
	tx        *sql.Tx
	pending   int
	closed    bool
}

func ledgerPrivateInfo(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm() == 0700
	}
	return info.Mode().IsRegular() && st.Nlink == 1 && info.Mode().Perm() == 0600
}

func ledgerParents(name string) bool {
	if !ValidHostPath(name) || name == "/" {
		return false
	}
	for p := filepath.Dir(name); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if p == "/" {
			return true
		}
	}
}

// NewLedger never accepts an API path. Its caller supplies a held, newly created
// root-private worker-job directory. Existing indexes, symlinks, other owners,
// public/writable ancestors and quota changes are refused, never repaired.
func NewLedger(ctx context.Context, root *os.Root, pages int64) (*Ledger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 || root == nil || pages < 16 || pages > 131072 || !ledgerParents(root.Name()) {
		return nil, ErrLedgerUnavailable
	}
	opened, err := root.Stat(".")
	visible, visibleErr := os.Lstat(root.Name())
	if err != nil || visibleErr != nil || !os.SameFile(opened, visible) || !ledgerPrivateInfo(opened, true) || !ledgerPrivateInfo(visible, true) {
		return nil, ErrLedgerUnavailable
	}
	dir, err := root.Open(".")
	if err != nil {
		return nil, ErrLedgerUnavailable
	}
	dm, err := metadataFD(int(dir.Fd()), false)
	if err != nil {
		dir.Close()
		return nil, ErrLedgerUnavailable
	}
	i, err := ReadInventory()
	if err != nil || !i.LocalLookup(strconv.FormatUint(dm.Identity.MountID, 10)) {
		dir.Close()
		return nil, ErrLedgerUnavailable
	}
	f, err := root.OpenFile("inode-index.db", os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		dir.Close()
		return nil, ErrLedgerUnavailable
	}
	l := &Ledger{root: root, directory: dir, file: f, identity: dm.Identity, rootInfo: opened}
	fail := func(cause error) (*Ledger, error) { l.Close(); return nil, ledgerDatabaseFailure(ctx, cause) }
	info, err := f.Stat()
	if err != nil || !ledgerPrivateInfo(info, false) || info.Size() != 0 {
		return fail(nil)
	}
	// Anchor SQLite and its fixed journal to the held private directory, not a
	// fresh path walk through the host being scanned. No URI options are input.
	name := "/proc/self/fd/" + strconv.FormatUint(uint64(dir.Fd()), 10) + "/inode-index.db"
	db, err := sql.Open("sqlite", name)
	if err != nil {
		return fail(nil)
	}
	l.db = db
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	for _, statement := range []string{"PRAGMA page_size=4096", "PRAGMA cache_size=-4096", "PRAGMA mmap_size=0", "PRAGMA temp_store=MEMORY", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=1000", "PRAGMA trusted_schema=OFF", "PRAGMA journal_size_limit=1048576"} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fail(err)
		}
	}
	// SQLite ignores unknown PRAGMAs. Verify settings, never infer enforcement
	// solely from a successful Exec. No large sort/temporary table is used.
	for pragma, wanted := range map[string]int64{"page_size": 4096, "cache_size": -4096, "mmap_size": 0, "temp_store": 2, "synchronous": 2, "trusted_schema": 0, "journal_size_limit": 1048576} {
		var actual int64
		if err := db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&actual); err != nil {
			return fail(err)
		}
		if actual != wanted {
			return fail(nil)
		}
	}
	var actualPages int64
	if err := db.QueryRowContext(ctx, "PRAGMA max_page_count="+strconv.FormatInt(pages, 10)).Scan(&actualPages); err != nil {
		return fail(err)
	}
	if actualPages != pages {
		return fail(nil)
	}
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return fail(err)
	}
	if journal != "delete" {
		return fail(nil)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE inodes(identity TEXT PRIMARY KEY, kind INTEGER NOT NULL, logical TEXT NOT NULL, blocks TEXT NOT NULL) WITHOUT ROWID`); err != nil {
		return fail(err)
	}
	if !l.current() {
		return fail(nil)
	}
	return l, nil
}

func (l *Ledger) current() bool {
	if l.closed || !ledgerParents(l.root.Name()) {
		return false
	}
	a, e1 := l.directory.Stat()
	b, e2 := os.Lstat(l.root.Name())
	c, e3 := l.file.Stat()
	d, e4 := l.root.Lstat("inode-index.db")
	return e1 == nil && e2 == nil && e3 == nil && e4 == nil && os.SameFile(a, l.rootInfo) && os.SameFile(a, b) && ledgerPrivateInfo(a, true) && ledgerPrivateInfo(b, true) && os.SameFile(c, d) && ledgerPrivateInfo(c, false) && ledgerPrivateInfo(d, false)
}

// OwnDirectory is a pinned identity for excluding only the current worker's
// own changing spool directory. No lexical prefix or arbitrary exclusion list.
func (l *Ledger) OwnDirectory() Identity { return l.identity }

func (l *Ledger) flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !l.current() {
		return ErrLedgerUnavailable
	}
	if l.tx != nil {
		if err := l.tx.Commit(); err != nil {
			l.tx = nil
			return ledgerDatabaseFailure(ctx, err)
		}
		l.tx = nil
		l.pending = 0
	}
	return nil
}

func (l *Ledger) Flush(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flush(ctx)
}

// Add returns true once for a kernel identity. A reused/changed inode becomes
// an explicit partial result, not a silently deduplicated apparent success.
func (l *Ledger) Add(ctx context.Context, m Metadata) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !l.current() || m.Identity.Inode == 0 || m.Identity.MountID == 0 {
		return false, ErrLedgerUnavailable
	}
	if l.tx == nil {
		var err error
		l.tx, err = l.db.BeginTx(ctx, nil)
		if err != nil {
			return false, ledgerDatabaseFailure(ctx, err)
		}
	}
	key, kind := MetadataIdentityKey(m), m.Mode&unix.S_IFMT
	logical, blocks := strconv.FormatUint(m.Bytes, 10), strconv.FormatUint(m.Blocks, 10)
	result, err := l.tx.ExecContext(ctx, `INSERT INTO inodes(identity,kind,logical,blocks) VALUES(?,?,?,?) ON CONFLICT(identity) DO NOTHING`, key, kind, logical, blocks)
	if err != nil {
		l.tx.Rollback()
		l.tx = nil
		l.pending = 0
		return false, ledgerDatabaseFailure(ctx, err)
	}
	n, err := result.RowsAffected()
	if err != nil || n < 0 || n > 1 {
		l.tx.Rollback()
		l.tx = nil
		l.pending = 0
		return false, ErrLedgerUnavailable
	}
	if n == 0 {
		var oldKind uint16
		var oldLogical, oldBlocks string
		if err := l.tx.QueryRowContext(ctx, `SELECT kind,logical,blocks FROM inodes WHERE identity=?`, key).Scan(&oldKind, &oldLogical, &oldBlocks); err != nil {
			return false, ledgerDatabaseFailure(ctx, err)
		}
		if oldKind != kind || oldLogical != logical || oldBlocks != blocks {
			return false, ErrMetadataChanged
		}
	}
	l.pending++
	if l.pending >= ReadBatchSize {
		if err := l.flush(ctx); err != nil {
			return false, err
		}
	}
	return n == 1, nil
}

func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var first error
	if l.tx != nil {
		l.tx.Rollback()
		l.tx = nil
	}
	for _, closer := range []interface{ Close() error }{l.db, l.file, l.directory} {
		// db can be nil after a refused open; interface wrapping nil needs an
		// explicit check rather than calling through a typed nil pointer.
		switch c := closer.(type) {
		case *sql.DB:
			if c == nil {
				continue
			}
		case *os.File:
			if c == nil {
				continue
			}
		}
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		return ErrLedgerUnavailable
	}
	return nil
}

// No filename, SQL/path stderr, options or credentials enter a ledger error.
// SQLite may return an interrupt or sql.ErrTxDone when a context rolls back an
// in-flight statement. Keep that real cancellation/deadline as a typed cause,
// while retaining the unavailable-index identity and the fixed public text.
// Only failed SQL operations use this path; identity/quota-policy mismatches
// pass nil and cannot be relabeled by a later cancellation.
type ledgerControlError struct{ cause error }

func (e ledgerControlError) Error() string        { return ErrLedgerUnavailable.Error() }
func (e ledgerControlError) Unwrap() error        { return e.cause }
func (e ledgerControlError) Is(target error) bool { return target == ErrLedgerUnavailable }

func ledgerDatabaseFailure(ctx context.Context, err error) error {
	if err != nil {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			if errors.Is(err, cause) || errors.Is(ctx.Err(), cause) {
				return ledgerControlError{cause: cause}
			}
		}
	}
	return ErrLedgerUnavailable
}

func ledgerError(err error) bool {
	return errors.Is(err, ErrLedgerUnavailable) || errors.Is(err, ErrMetadataChanged)
}
