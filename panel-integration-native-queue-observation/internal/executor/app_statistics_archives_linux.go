//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

var statisticsArchiveMetadataPattern = regexp.MustCompile(`^[0-9]+:-?[0-9]+:[0-9]{1,9}:-?[0-9]+:[0-9]{1,9}$`)
var statisticsArchiveIdentityPattern = regexp.MustCompile(`^gzip:[0-9]+:[1-9][0-9]*$`)

type statisticsArchiveEvidence struct {
	Site, Identity, Name, Metadata, Digest string
	Offset, Size, Invalid, Seen            int64
	State, Blocked                         int
}

func (v statisticsArchiveEvidence) checksum() string {
	raw, _ := json.Marshal(v)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// This is an internal consistency checksum, not a claim of authentication
// against a root administrator. It catches changed cached cursors/evidence
// before either skipping a completed archive or retiring an absent one.
func validateStatisticsArchiveEvidence(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT a.site,a.identity,s.name,a.metadata,a.digest,s.offset,s.size,s.invalid,s.seen,a.state,s.blocked,s.anchor,a.evidence_sha FROM access_archives a LEFT JOIN access_streams s ON s.site=a.site AND s.identity=a.identity LIMIT ?", statisticsHistoryStreams+1)
	if err != nil {
		return errors.New("压缩归档证据模式不完整，未覆盖旧数据")
	}
	defer rows.Close()
	count := 0
	emptyDigest := fmt.Sprintf("%x", sha256.Sum256(nil))
	for rows.Next() {
		count++
		var v statisticsArchiveEvidence
		var anchor, sum string
		if err = rows.Scan(&v.Site, &v.Identity, &v.Name, &v.Metadata, &v.Digest, &v.Offset, &v.Size, &v.Invalid, &v.Seen, &v.State, &v.Blocked, &anchor, &sum); err != nil {
			return errors.New("压缩归档证据缺失对应进度，未清理或接管")
		}
		if count > statisticsHistoryStreams || !core.ValidID(v.Site) || !statisticsArchiveIdentityPattern.MatchString(v.Identity) || !statisticsLogArchiveName(v.Site, v.Name) || !strings.HasSuffix(v.Name, ".gz") || len(v.Metadata) > 128 || !statisticsArchiveMetadataPattern.MatchString(v.Metadata) || !statisticsArchiveDigest(v.Digest) || anchor != v.Digest || v.Offset < 0 || v.Size < 0 || v.Offset > v.Size || v.Size > statisticsGzipExpandedBytes || v.Invalid < 0 || v.Invalid > v.Offset || v.Seen <= 0 || v.State < 0 || v.State > 2 || v.Blocked < 0 || v.Blocked > 1 || v.State == 0 && (v.Offset != 0 || v.Size != 0 || v.Invalid != 0 || v.Digest != emptyDigest || v.Blocked != 1) || v.State == 1 && v.Blocked != 0 || v.State == 2 && v.Blocked != 1 || !statisticsArchiveDigest(sum) || sum != v.checksum() {
			return errors.New("压缩归档证据与进度不符，未重置、清理或生成完整报告")
		}
	}
	return rows.Err()
}

// Metadata is only a cache key, never an authentication digest. First import
// and every changed key require the full CRC-verified compressed SHA256. The
// final directory recheck also compares metadata, not just the inode.
func statisticsGzipMetadata(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d:%d", info.Size(), st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
}

func statisticsAddBacklog(old, extra int64) int64 {
	if old < 0 || extra < 0 || extra > math.MaxInt64-old {
		return math.MaxInt64
	}
	return old + extra
}

func statisticsArchiveDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// One archive is CRC-scanned per invocation, at most64MiB compressed and64MiB
// expanded. Plain live logs are processed first. Cached corrupt/oversized
// archives therefore do not repeatedly consume the scan or block later files.
// Rows, request-ID receipts, compressed-source evidence and decompressed
// cursors commit in the SAME SQLite transaction; original logs are untouched.
// This path exists only in schema2, never silently enabled for older apps.
func (s *Service) ingestStatisticsGzipArchives(ctx context.Context, tx *sql.Tx, root *os.Root, names []string, discovered map[string]os.FileInfo, id string, now time.Time, budget *int64, rowBudget, receiptCount, streamCount *int, seen map[string]bool, result *statisticsIngestion) error {
	var archiveCount, missingEvidence int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM access_archives").Scan(&archiveCount); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM access_streams s WHERE s.identity LIKE 'gzip:%' AND NOT EXISTS(SELECT 1 FROM access_archives a WHERE a.site=s.site AND a.identity=s.identity)").Scan(&missingEvidence); err != nil {
		return err
	}
	if archiveCount > *streamCount || archiveCount > statisticsHistoryStreams || missingEvidence != 0 {
		return errors.New("压缩归档记录无法核对，未删除证据或提交读取进度")
	}
	scanned := false
	contentBudget := int64(statisticsGzipSourceBytes)
	contentCtx, contentCancel := context.WithTimeout(ctx, 3*time.Second)
	defer contentCancel()
	emptyDigest := fmt.Sprintf("%x", sha256.Sum256(nil))
	start := 0
	if len(names) > 0 {
		start = s.statisticsArchiveScanCursor[id] % len(names)
	}
	advance := func(index int) {
		if s.statisticsArchiveScanCursor == nil {
			s.statisticsArchiveScanCursor = map[string]int{}
		}
		if _, exists := s.statisticsArchiveScanCursor[id]; exists || len(s.statisticsArchiveScanCursor) < statisticsHistoryStreams {
			s.statisticsArchiveScanCursor[id] = (index + 1) % len(names)
		}
	}
	for ordinal := range names {
		index := (start + ordinal) % len(names)
		name := names[index]
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := regularFile(root, name)
		if err != nil {
			return errors.New("压缩访问日志不是普通无链接文件，未采集")
		}
		info, err := f.Stat()
		original := discovered[name]
		if err != nil || privateLogEntry(info) != nil || !os.SameFile(info, original) || statisticsGzipMetadata(info) != statisticsGzipMetadata(original) {
			f.Close()
			return errors.New("压缩访问日志身份或内容改变，未采集")
		}
		st := info.Sys().(*syscall.Stat_t)
		identity := fmt.Sprintf("gzip:%d:%d", st.Dev, st.Ino)
		metadata := statisticsGzipMetadata(info)
		seen[identity] = true
		offset, size, invalid := int64(0), int64(0), int64(0)
		anchor, digest, cachedMetadata := emptyDigest, emptyDigest, ""
		blocked, state := 0, 0
		err = tx.QueryRowContext(ctx, "SELECT s.offset,s.size,s.anchor,s.blocked,s.invalid,a.metadata,a.digest,a.state FROM access_streams s JOIN access_archives a ON a.site=s.site AND a.identity=s.identity WHERE s.site=? AND s.identity=?", id, identity).Scan(&offset, &size, &anchor, &blocked, &invalid, &cachedMetadata, &digest, &state)
		fresh := errors.Is(err, sql.ErrNoRows)
		if !fresh && err != nil {
			f.Close()
			return err
		}
		if !fresh && (offset < 0 || size < 0 || offset > size || size > statisticsGzipExpandedBytes || invalid < 0 || blocked < 0 || blocked > 1 || state < 0 || state > 2 || len(cachedMetadata) > 128 || !statisticsArchiveMetadataPattern.MatchString(cachedMetadata) || !statisticsArchiveDigest(anchor) || !statisticsArchiveDigest(digest) || digest != anchor || state == 0 && (offset != 0 || size != 0 || digest != emptyDigest || blocked != 1) || state == 1 && blocked != 0 || state == 2 && blocked != 1) {
			f.Close()
			return errors.New("压缩归档读取记录损坏，未重置")
		}
		contentMatches := false
		if !fresh && metadata == cachedMetadata && (state == 1 && offset == size || state == 2) {
			// Same inode/size/mtime/ctime may survive a rewrite within a kernel
			// clock tick. Previously CRC-verified bytes can only be reused after
			// checking the compressed content hash, not a metadata-only cache hit.
			if info.Size() > contentBudget || contentCtx.Err() != nil {
				result.Invalid += invalid
				result.DeferredArchives++
				result.Compressed++
				result.Backlog = statisticsAddBacklog(result.Backlog, max(int64(0), info.Size()))
				f.Close()
				continue
			}
			contentBudget -= info.Size()
			// A hash attempt also advances the fair scan cursor. Otherwise a
			// completed prefix could exhaust the byte/time budget every pass,
			// indefinitely deferring the remaining completed archives.
			advance(index)
			h := sha256.New()
			n, hashErr := io.Copy(h, io.LimitReader(geoStoreContextReader{contentCtx, f}, info.Size()+1))
			if hashErr != nil {
				f.Close()
				if ctx.Err() != nil {
					return ctx.Err()
				}
				result.Invalid += invalid
				result.DeferredArchives++
				result.Compressed++
				result.Backlog = statisticsAddBacklog(result.Backlog, max(int64(0), info.Size()))
				continue
			}
			check, statErr := f.Stat()
			visible, visibleErr := root.Lstat(name)
			if statErr != nil || visibleErr != nil || privateLogEntry(visible) != nil || !os.SameFile(info, visible) || statisticsGzipMetadata(check) != metadata || statisticsGzipMetadata(visible) != metadata {
				f.Close()
				return errors.New("压缩缓存核对期间文件身份变化，未提交进度")
			}
			contentMatches = n == info.Size() && fmt.Sprintf("%x", h.Sum(nil)) == digest
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				f.Close()
				return seekErr
			}
		}
		if !fresh && metadata == cachedMetadata && (state == 0 || state == 2 && !contentMatches || state == 1 && (offset != size || contentMatches)) {
			result.Invalid += invalid
			if state != 1 {
				result.Blocked++
				result.Compressed++
				result.Backlog = statisticsAddBacklog(result.Backlog, max(int64(0), info.Size()))
				f.Close()
				continue
			}
			if offset == size {
				result.VerifiedArchives++
				f.Close()
				continue
			}
			// Remove this first addition: the batch path below adds the updated total.
			result.Invalid -= invalid
		}
		// A recent source can still be under compression. No tentative record is
		// made, and a later worker pass retries it without resetting old progress.
		if scanned || *budget <= 0 || *rowBudget <= 0 || info.ModTime().After(now.Add(-5*time.Second)) {
			result.Invalid += invalid
			result.Compressed++
			if !fresh && state != 1 {
				result.Blocked++
			}
			backlog := max(int64(0), size-offset)
			if fresh || state != 1 {
				backlog = max(int64(0), info.Size())
			}
			result.Backlog = statisticsAddBacklog(result.Backlog, backlog)
			f.Close()
			continue
		}
		if fresh && *streamCount >= statisticsHistoryStreams {
			f.Close()
			return errors.New("统计文件身份记录已满，未丢弃压缩归档证据")
		}
		scanned = true
		advance(index)
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		batch, readErr := readStatisticsGzipBatch(readCtx, f, offset, *budget, *rowBudget)
		cancel()
		check, statErr := f.Stat()
		current, pathErr := root.Lstat(name)
		f.Close()
		if statErr != nil || pathErr != nil || privateLogEntry(current) != nil || !os.SameFile(info, current) || statisticsGzipMetadata(check) != metadata || statisticsGzipMetadata(current) != metadata {
			return errors.New("采集期间压缩归档身份或内容改变，未提交任何新进度")
		}
		if errors.Is(readErr, context.DeadlineExceeded) && ctx.Err() == nil {
			// A slow archive must not roll back this pass's valid live rows or
			// monopolize later archives. No request, receipt, cursor or CRC cache
			// from its unverified batch is written. Scheduling is not authority.
			result.DeferredArchives++
			result.Compressed++
			result.Invalid += invalid
			backlog := max(int64(0), size-offset)
			if fresh || metadata != cachedMetadata {
				backlog = max(int64(0), info.Size())
			}
			result.Backlog = statisticsAddBacklog(result.Backlog, backlog)
			continue
		}
		if readErr != nil && !errors.Is(readErr, errStatisticsGzipUnsupported) {
			return readErr
		}
		if readErr != nil {
			blocked = 1
			if state == 1 || state == 2 {
				state = 2
			} else {
				state = 0
				offset = 0
				size = 0
				anchor = emptyDigest
				digest = emptyDigest
			}
		} else if !fresh && (state == 1 || state == 2) && (batch.SourceSHA256 != digest || batch.Size != size) {
			// Never restart a previously accepted archive at zero just because the
			// writer rewrote/truncated the same inode. Preserve its original evidence.
			blocked, state = 1, 2
		} else {
			for _, line := range batch.Lines {
				row, stamp, valid := statisticsPrivateRow(line, now)
				if valid && stamp >= now.AddDate(0, 0, -statisticsHistoryDays).Unix() {
					// ID-less legacy compressed rows cannot prove that their uncompressed
					// source was not counted earlier. They remain an explicit partial gap.
					if row.RequestID == "" {
						invalid++
					} else {
						duplicate, e := insertStatisticsRequest(ctx, tx, id, row, stamp, receiptCount)
						if e != nil {
							return e
						}
						if duplicate {
							result.Duplicates++
						}
					}
				} else if !valid {
					invalid++
				}
				*budget -= int64(len(line))
				*rowBudget--
			}
			offset, size, anchor, digest = batch.Next, batch.Size, batch.SourceSHA256, batch.SourceSHA256
			blocked, state = 0, 1
			result.VerifiedArchives++
		}
		result.Invalid += invalid
		if blocked != 0 {
			result.Blocked++
			result.Compressed++
			result.Backlog = statisticsAddBacklog(result.Backlog, max(int64(0), info.Size()))
		} else if offset < size {
			result.Compressed++
			result.Backlog = statisticsAddBacklog(result.Backlog, size-offset)
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO access_streams(site,identity,name,offset,anchor,size,seen,blocked,invalid) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(site,identity) DO UPDATE SET name=excluded.name,offset=excluded.offset,anchor=excluded.anchor,size=excluded.size,seen=excluded.seen,blocked=excluded.blocked,invalid=excluded.invalid", id, identity, name, offset, anchor, size, now.Unix(), blocked, invalid); err != nil {
			return err
		}
		evidence := statisticsArchiveEvidence{Site: id, Identity: identity, Name: name, Metadata: metadata, Digest: digest, Offset: offset, Size: size, Invalid: invalid, Seen: now.Unix(), State: state, Blocked: blocked}
		if _, err = tx.ExecContext(ctx, "INSERT INTO access_archives(site,identity,metadata,digest,state,evidence_sha) VALUES(?,?,?,?,?,?) ON CONFLICT(site,identity) DO UPDATE SET metadata=excluded.metadata,digest=excluded.digest,state=excluded.state,evidence_sha=excluded.evidence_sha", id, identity, metadata, digest, state, evidence.checksum()); err != nil {
			return err
		}
		if fresh {
			*streamCount++
		}
	}
	return nil
}
