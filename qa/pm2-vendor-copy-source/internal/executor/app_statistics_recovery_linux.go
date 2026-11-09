//go:build linux

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var statisticsJournalMagic = []byte{0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7}

// Only this closed, single-database journal subset is eligible for the explicit
// maintenance entry. Never interpret filenames/super-journals from a journal.
// Specification: https://sqlite.org/fileformat2.html#the_rollback_journal
// Unsupported segments, incomplete records, external journal pointers and WAL
// remain preserved refusals, not an invitation to delete a recovery file.
func validateStatisticsRollbackJournal(ctx context.Context, r io.ReaderAt, size, databaseBytes int64) error {
	var header [28]byte
	if _, err := r.ReadAt(header[:], 0); err != nil || !bytes.Equal(header[:8], statisticsJournalMagic) {
		return errors.New("统计恢复日志不是完整的已知热日志")
	}
	count := binary.BigEndian.Uint32(header[8:12])
	nonce := binary.BigEndian.Uint32(header[12:16])
	pages := binary.BigEndian.Uint32(header[16:20])
	sector := binary.BigEndian.Uint32(header[20:24])
	pageSize := binary.BigEndian.Uint32(header[24:28])
	if pageSize != 4096 || sector < 512 || sector > 65536 || sector&(sector-1) != 0 || pages == 0 || int64(pages)*4096 > databaseBytes || databaseBytes > 512<<20 || databaseBytes%4096 != 0 || count == 0 || count > pages || size > 512<<20 {
		return errors.New("统计恢复日志分段、页数、容量或固定页大小无法闭合核对")
	}
	end := int64(sector) + int64(count)*4104
	if size != end {
		// Native sqlite3_db_cacheflush may reserve ONE following unsynced,
		// empty sector header. Its zero magic/count means it is not another
		// recoverable segment. Accept only that complete closed structure:
		// zero alignment, matching original/page/sector sizes, zero padding,
		// no page data, trailing pointer or external filename.
		aligned := (end + int64(sector) - 1) / int64(sector) * int64(sector)
		if size != aligned+int64(sector) {
			return errors.New("统计恢复日志存在未核对的尾部或额外分段")
		}
		trailer := make([]byte, int(size-end))
		if _, err := r.ReadAt(trailer, end); err != nil {
			return err
		}
		next := trailer[aligned-end:]
		if !bytes.Equal(trailer[:aligned-end], make([]byte, aligned-end)) || !bytes.Equal(next[:12], make([]byte, 12)) || binary.BigEndian.Uint32(next[16:20]) != pages || binary.BigEndian.Uint32(next[20:24]) != sector || binary.BigEndian.Uint32(next[24:28]) != pageSize || !bytes.Equal(next[28:], make([]byte, len(next)-28)) {
			return errors.New("统计恢复日志未同步空头结构异常，未忽略未知尾部")
		}
	}
	padding := make([]byte, int(sector)-28)
	if _, err := r.ReadAt(padding, 28); err != nil || !bytes.Equal(padding, make([]byte, len(padding))) {
		return errors.New("统计恢复日志扇区填充异常")
	}
	var tail [8]byte
	if _, err := r.ReadAt(tail[:], size-8); err != nil || bytes.Equal(tail[:], statisticsJournalMagic) {
		return errors.New("统计恢复日志包含外部主日志标记，未交给原生恢复器")
	}
	seen := map[uint32]bool{}
	var record [4104]byte
	for i := uint32(0); i < count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := r.ReadAt(record[:], int64(sector)+int64(i)*4104); err != nil {
			return err
		}
		page := binary.BigEndian.Uint32(record[:4])
		if page == 0 || page > pages || seen[page] {
			return errors.New("统计恢复日志页标识越界或重复")
		}
		seen[page] = true
		checksum := nonce
		for x := 4096 - 200; x >= 0; x -= 200 {
			checksum += uint32(record[4+x])
		}
		if checksum != binary.BigEndian.Uint32(record[4100:]) {
			return errors.New("统计恢复日志页校验失败，保留原库及日志")
		}
	}
	return nil
}

type statisticsRecoveryFile struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
	Inode  uint64 `json:"inode"`
	MTime  int64  `json:"mtime_ns"`
}

func sameStatisticsRecoveryFile(a, b os.FileInfo) bool {
	if !moduleRecordInfo(a, false, false) || !moduleRecordInfo(b, false, false) {
		return false
	}
	x, y := a.Sys().(*syscall.Stat_t), b.Sys().(*syscall.Stat_t)
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && a.Mode() == b.Mode() && x.Uid == y.Uid && x.Gid == y.Gid
}

// Check the current owned directory AND named/opened inode on both sides of a
// bounded streaming read. This never normalizes links, permissions or ownership.
func statisticsRecoveryRead(ctx context.Context, root *modulePrivateDirectory, name string, destinations ...io.Writer) (statisticsRecoveryFile, error) {
	var result statisticsRecoveryFile
	before, err := root.Lstat(name)
	if err != nil || !moduleRecordInfo(before, false, false) || before.Size() < 1 || before.Size() > 512<<20 || !root.current() {
		return result, errors.New("统计恢复源文件身份、容量或私有目录异常")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameStatisticsRecoveryFile(before, opened) {
		return result, errors.New("统计恢复源文件打开期间变化")
	}
	hash := sha256.New()
	writers := append([]io.Writer{hash}, destinations...)
	writer := io.MultiWriter(writers...)
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		n, readErr := f.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > before.Size() {
				return result, errors.New("统计恢复源文件读取期间增长")
			}
			if _, err := writer.Write(buffer[:n]); err != nil {
				return result, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	after, statErr := f.Stat()
	visible, visibleErr := root.Lstat(name)
	if statErr != nil || visibleErr != nil || total != before.Size() || !sameStatisticsRecoveryFile(before, after) || !sameStatisticsRecoveryFile(before, visible) || !root.current() {
		return result, errors.New("统计恢复源文件读取期间发生修改")
	}
	st := before.Sys().(*syscall.Stat_t)
	return statisticsRecoveryFile{hex.EncodeToString(hash.Sum(nil)), total, st.Uid, st.Gid, st.Ino, before.ModTime().UnixNano()}, nil
}

func statisticsRecoveryAbsent(root *modulePrivateDirectory, names ...string) error {
	for _, name := range names {
		if _, err := root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return errors.New("统计恢复发现未核对的 WAL、共享文件或待恢复事务；未修改")
		}
	}
	if !root.current() {
		return errors.New("统计恢复目录身份变化")
	}
	return nil
}

func statisticsRecoveryWrite(root *os.Root, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(append(raw, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	return errors.Join(writeErr, syncErr, closeErr)
}

func statisticsRecoverySync(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Opening mode=rw is deliberately confined here, AFTER the complete private
// journal has been verified. SQLite performs rollback itself; no page patches,
// migrations, CREATE, INSERT, DELETE, cursor edits or stale-backup restoration.
func validateStatisticsRecoveredDatabase(ctx context.Context, file string) error {
	u := url.URL{Scheme: "file", Path: file, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var version, pageSize int
	if _, err = db.ExecContext(ctx, "PRAGMA trusted_schema=OFF"); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		return errors.New("恢复副本不是已发布的统计历史第二版")
	}
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil || pageSize != 4096 {
		return errors.New("恢复副本页大小不匹配")
	}
	if err = validateStatisticsSchemaObjects(ctx, db, 2); err != nil {
		return err
	}
	var check string
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
		return errors.New("统计恢复副本完整性检查未通过")
	}
	return db.Close()
}

// Explicit root-only maintenance for ONE hash-bound current installation.
// Not called by health/readiness, automatic retry, app update or startup.
func RecoverStatisticsHistory(expected string) error {
	if os.Geteuid() != 0 {
		return errors.New("统计历史恢复仅接受本机 root 维护入口")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return nativeWAFService().recoverStatisticsHistory(ctx, expected)
}

func (s *Service) recoverStatisticsHistory(ctx context.Context, expected string) (resultErr error) {
	if ctx == nil {
		return errors.New("统计历史恢复缺少固定时间预算")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parts := strings.Split(expected, ":")
	if len(parts) != 3 || !coreSHA.MatchString(parts[0]) || !coreSHA.MatchString(parts[1]) || !coreSHA.MatchString(parts[2]) {
		return errors.New("统计历史恢复需要原库、热日志及安装记录三个完整摘要")
	}
	lock, err := s.statisticsLogTransactionService().lockWAFConfiguration()
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err = os.Lstat(s.statisticsLogTransactionService().wafPendingPath()); !errors.Is(err, os.ErrNotExist) {
		return errors.New("统计日志格式事务尚未核对；不能恢复历史库")
	}
	installed, err := s.moduleInstalledRecord("website-statistics-v2")
	if err != nil || installed["version"] != statisticsIdentityVersion && installed["version"] != statisticsGeographyVersion {
		return errors.New("统计历史恢复不是当前已知的已安装版本")
	}
	root, err := s.moduleRecordDirectory("website-statistics-v2")
	if err != nil {
		return err
	}
	defer root.Close()
	if err = statisticsRecoveryAbsent(root, "access.sqlite-wal", "access.sqlite-shm"); err != nil {
		return err
	}
	names := []string{"access.sqlite", "access.sqlite-journal", "installed.json"}
	originals := make(map[string]statisticsRecoveryFile)
	for i, name := range names {
		item, err := statisticsRecoveryRead(ctx, root, name)
		if err != nil || item.SHA256 != parts[i] {
			return errors.New("统计历史恢复源文件与显式原摘要不一致；未接管")
		}
		originals[name] = item
	}
	journal, err := root.OpenFile("access.sqlite-journal", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	err = validateStatisticsRollbackJournal(ctx, journal, originals[names[1]].Bytes, originals[names[0]].Bytes)
	journal.Close()
	if err != nil {
		return err
	}
	identity := sha256.Sum256([]byte(expected))
	caseName := fmt.Sprintf("history-recovery-%x", identity[:16])
	if err = root.Mkdir(caseName, 0700); err != nil {
		return errors.New("原恢复案例已存在或无法安全创建；未重试、覆盖或重放")
	}
	caseRoot, err := root.OpenRoot(caseName)
	if err != nil {
		return err
	}
	defer caseRoot.Close()
	if err = statisticsRecoveryWrite(caseRoot, "intent.json", map[string]any{"expected": expected, "originals": originals, "started_at": time.Now().UTC(), "scope": "native rollback of one installed private statistics database; original task outcome unchanged"}); err != nil {
		return err
	}
	if err = statisticsRecoverySync(root.Root); err != nil {
		return err
	}
	liveAttempted := false
	defer func() {
		detail := ""
		if resultErr != nil {
			detail = resultErr.Error()
		}
		writeErr := statisticsRecoveryWrite(caseRoot, "result.json", map[string]any{"complete": resultErr == nil, "live_rollback_attempted": liveAttempted, "error": detail, "finished_at": time.Now().UTC(), "originals": originals})
		resultErr = errors.Join(resultErr, writeErr, statisticsRecoverySync(caseRoot))
	}()
	if err = caseRoot.Mkdir("candidate", 0700); err != nil {
		return err
	}
	candidateRoot, err := caseRoot.OpenRoot("candidate")
	if err != nil {
		return err
	}
	defer candidateRoot.Close()
	for _, name := range names {
		backup, err := caseRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		candidate, err := candidateRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			backup.Close()
			return err
		}
		item, copyErr := statisticsRecoveryRead(ctx, root, name, backup, candidate)
		flushErr := errors.Join(backup.Sync(), candidate.Sync(), backup.Close(), candidate.Close())
		if copyErr != nil || flushErr != nil || item != originals[name] {
			return errors.New("统计恢复备份未完整保存或原源发生变化；未操作原库")
		}
	}
	if err = errors.Join(statisticsRecoverySync(caseRoot), statisticsRecoverySync(candidateRoot)); err != nil {
		return err
	}
	casePath := filepath.Join(s.moduleDir("website-statistics-v2"), caseName)
	if err = validateStatisticsRecoveredDatabase(ctx, filepath.Join(casePath, "candidate", "access.sqlite")); err != nil {
		return fmt.Errorf("统计恢复副本验证失败；原库和原日志不变: %w", err)
	}
	// Root the recovered copy with the exact same ownership guards as the live
	// module. This handle is only used for bounded hash reads, never publication.
	candidate := &modulePrivateDirectory{Root: candidateRoot, roots: []*os.Root{candidateRoot}, paths: []string{filepath.Join(casePath, "candidate")}}
	recovered, err := statisticsRecoveryRead(ctx, candidate, "access.sqlite")
	if err != nil {
		return err
	}
	if err = statisticsRecoveryAbsent(candidate, "access.sqlite-journal", "access.sqlite-wal", "access.sqlite-shm"); err != nil {
		return err
	}
	if err = statisticsRecoveryWrite(caseRoot, "candidate.json", recovered); err != nil {
		return err
	}
	if err = statisticsRecoverySync(caseRoot); err != nil {
		return err
	}
	// No live mutation until all three current source files still match their
	// original inodes/owners/bytes, and every immutable backup is durable.
	for _, name := range names {
		current, err := statisticsRecoveryRead(ctx, root, name)
		if err != nil || current != originals[name] {
			return errors.New("统计恢复副本核对期间原源变化；未操作原库")
		}
	}
	if err = statisticsRecoveryAbsent(root, "access.sqlite-wal", "access.sqlite-shm"); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	liveAttempted = true
	if err = validateStatisticsRecoveredDatabase(ctx, filepath.Join(s.moduleDir("website-statistics-v2"), "access.sqlite")); err != nil {
		return fmt.Errorf("统计原生恢复未确认完成；保留原始备份及本次证据，未重试: %w", err)
	}
	after, err := statisticsRecoveryRead(ctx, root, "access.sqlite")
	if err != nil || after.SHA256 != recovered.SHA256 || after.UID != originals[names[0]].UID || after.GID != originals[names[0]].GID || after.Inode != originals[names[0]].Inode {
		return errors.New("统计原生恢复结果或文件身份与已验证副本不一致；未报告完成")
	}
	if err = statisticsRecoveryAbsent(root, "access.sqlite-journal", "access.sqlite-wal", "access.sqlite-shm"); err != nil {
		return err
	}
	record, err := statisticsRecoveryRead(ctx, root, "installed.json")
	if err != nil || record != originals["installed.json"] {
		return errors.New("统计安装记录在恢复期间变化；未报告完成")
	}
	return statisticsRecoveryWrite(caseRoot, "recovered.json", after)
}
