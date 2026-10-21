//go:build linux

package diskusage

import (
	"context"
	"errors"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var ErrScanBudget = errors.New("全盘扫描预算无效；未开始枚举")
var ErrUsageOverflow = errors.New("元数据占用超出可核对整数范围；未显示溢出数值")
var ErrScanReused = errors.New("扫描索引已有原范围记录；不能当作新扫描或隐式续扫")
var ErrObserver = errors.New("扫描进度或当前执行授权无法保存/核对；已停止枚举")

type observerError struct{ cause error }

func (e observerError) Error() string        { return ErrObserver.Error() }
func (e observerError) Unwrap() error        { return e.cause }
func (e observerError) Is(target error) bool { return target == ErrObserver }

type scanner struct {
	ctx              context.Context
	scope            *Scope
	ledger           *Ledger
	report           ScanReport
	reasons          map[string]bool
	observer         func(ScanReport) error
	published        time.Time
	publishedEntries uint64
}

// Persisted progress is published only after its inode-index transaction is
// flushed. Do not hand mutable slices to an observer or use a callback failure
// as permission to continue. Callback error strings are never exposed.
func (w *scanner) checkpoint(force bool) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.observer == nil || !force && !w.published.IsZero() && time.Since(w.published) < 500*time.Millisecond && w.report.EntriesRead-w.publishedEntries < 4096 {
		return nil
	}
	if err := w.ledger.Flush(w.ctx); err != nil {
		return err
	}
	r := w.report
	r.IndexFlushed = true
	r.TopFiles = append([]UsageRow{}, r.TopFiles...)
	r.TopDirectories = append([]UsageRow{}, r.TopDirectories...)
	r.Reasons = make([]string, 0, len(w.reasons))
	for reason := range w.reasons {
		r.Reasons = append(r.Reasons, reason)
	}
	sort.Strings(r.Reasons)
	if err := w.observer(r); err != nil {
		return observerError{err}
	}
	w.published = time.Now()
	w.publishedEntries = w.report.EntriesRead
	return nil
}

func boundedUsagePath(raw string) (string, bool) {
	actionable := ValidHostPath(raw)
	text := strings.ToValidUTF8(raw, "�")
	text = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '�'
		}
		return r
	}, text)
	if len(text) > 512 {
		text = text[:512]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
		text += "…"
		actionable = false
	}
	return text, actionable
}

func rowBefore(a, b UsageRow) bool {
	if a.AllocatedBytes != b.AllocatedBytes {
		return a.AllocatedBytes > b.AllocatedBytes
	}
	if a.LogicalBytes != b.LogicalBytes {
		return a.LogicalBytes > b.LogicalBytes
	}
	return a.Path < b.Path
}

func retainTop(rows *[]UsageRow, row UsageRow) {
	if len(*rows) < 100 {
		*rows = append(*rows, row)
	} else if rowBefore(row, (*rows)[len(*rows)-1]) {
		(*rows)[len(*rows)-1] = row
	} else {
		return
	}
	sort.Slice(*rows, func(i, j int) bool { return rowBefore((*rows)[i], (*rows)[j]) })
}

func addUsage(current *uint64, amount uint64) error {
	if amount > math.MaxUint64-*current {
		return ErrUsageOverflow
	}
	*current += amount
	return nil
}

func allocation(m Metadata) (uint64, error) {
	if m.Blocks > math.MaxUint64/512 {
		return 0, ErrUsageOverflow
	}
	return m.Blocks * 512, nil
}

func (w *scanner) partial(reason string) { w.reasons[reason] = true }

func (w *scanner) metadataError(err error) {
	w.report.UnknownEntries++
	switch {
	case errors.Is(err, ErrMountBoundary):
		w.report.MountBoundaries++
		w.partial("child_mount_excluded")
	case errors.Is(err, ErrMetadataChanged), errors.Is(err, ErrMountChanged):
		w.partial("inode_or_mount_changed")
	case errors.Is(err, ErrKernelBoundaryUnavailable):
		w.partial("kernel_boundary_unavailable")
	default:
		w.partial("metadata_unavailable")
	}
}

// Allocations are per-inode st_blocks * 512, not exclusive disk extents.
// Reflinks/snapshots/compression/reserved blocks/deleted-open files may make
// these values differ from filesystem used capacity. No contents are opened.
func (w *scanner) file(m Metadata, raw string) (uint64, uint64, error) {
	a, err := allocation(m)
	if err != nil {
		return 0, 0, err
	}
	fresh, err := w.ledger.Add(w.ctx, m)
	if errors.Is(err, ErrMetadataChanged) {
		w.metadataError(err)
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	w.report.Files++
	if err := addUsage(&w.report.LogicalBytes, m.Bytes); err != nil {
		return 0, 0, err
	}
	display, actionable := boundedUsagePath(raw)
	retainTop(&w.report.TopFiles, UsageRow{Path: display, Actionable: actionable, LogicalBytes: m.Bytes, AllocatedBytes: a, Links: m.Links})
	if !fresh {
		w.report.Hardlinks++
		return 0, 0, nil
	}
	w.report.UniqueFiles++
	if a < m.Bytes {
		w.report.Sparse++
	}
	if err := addUsage(&w.report.UniqueLogicalBytes, m.Bytes); err != nil {
		return 0, 0, err
	}
	if err := addUsage(&w.report.FileAllocatedBytes, a); err != nil {
		return 0, 0, err
	}
	if err := addUsage(&w.report.AllocatedBytes, a); err != nil {
		return 0, 0, err
	}
	return m.Bytes, a, nil
}

func (w *scanner) other(m Metadata, kind uint16) (uint64, error) {
	a, err := allocation(m)
	if err != nil {
		return 0, err
	}
	fresh, err := w.ledger.Add(w.ctx, m)
	if errors.Is(err, ErrMetadataChanged) {
		w.metadataError(err)
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if kind == unix.S_IFLNK {
		w.report.Links++
	} else {
		w.report.Special++
	}
	if !fresh {
		return 0, nil
	}
	group := &w.report.SpecialAllocatedBytes
	if kind == unix.S_IFLNK {
		group = &w.report.LinkAllocatedBytes
	}
	if err := addUsage(group, a); err != nil {
		return 0, err
	}
	if err := addUsage(&w.report.AllocatedBytes, a); err != nil {
		return 0, err
	}
	return a, nil
}

func (w *scanner) walk(d *Directory, raw string, depth int) (uint64, uint64, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, 0, err
	}
	m, err := d.Metadata(w.ctx)
	if err != nil {
		w.metadataError(err)
		w.report.SkippedDirectories++
		return 0, 0, nil
	}
	a, err := allocation(m)
	if err != nil {
		return 0, 0, err
	}
	fresh, err := w.ledger.Add(w.ctx, m)
	if errors.Is(err, ErrMetadataChanged) {
		w.metadataError(err)
		w.report.SkippedDirectories++
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	if !fresh {
		if depth == 0 {
			return 0, 0, ErrScanReused
		}
		w.report.Cycles++
		w.partial("directory_inode_repeated")
		return 0, 0, nil
	}
	w.report.Directories++
	if err := addUsage(&w.report.DirectoryAllocatedBytes, a); err != nil {
		return 0, 0, err
	}
	if err := addUsage(&w.report.AllocatedBytes, a); err != nil {
		return 0, 0, err
	}
	logical, allocated := uint64(0), a
	for {
		if err := w.ctx.Err(); err != nil {
			return logical, allocated, err
		}
		if err := w.checkpoint(false); err != nil {
			return logical, allocated, err
		}
		if w.report.EntriesRead >= w.report.Budget.Entries {
			w.partial("entry_budget_reached")
			break
		}
		limit := min(uint64(ReadBatchSize), w.report.Budget.Entries-w.report.EntriesRead)
		batch, readErr := d.ReadBatchLimited(w.ctx, int(limit))
		w.report.EntriesRead += uint64(len(batch))
		for _, entry := range batch {
			if err := w.ctx.Err(); err != nil {
				return logical, allocated, err
			}
			if entry.Error != nil {
				w.metadataError(entry.Error)
				continue
			}
			m := entry.Metadata
			p := raw + "/" + entry.Name
			if raw == "/" {
				p = "/" + entry.Name
			}
			var childLogical, childAllocated uint64
			switch kind := m.Mode & unix.S_IFMT; kind {
			case unix.S_IFREG:
				childLogical, childAllocated, err = w.file(m, p)
			case unix.S_IFDIR:
				if m.Identity == w.ledger.OwnDirectory() {
					w.report.OwnWorkerDirectories++
					w.report.SkippedDirectories++
					w.partial("own_worker_state_excluded")
					continue
				}
				if depth >= w.report.Budget.Depth {
					w.report.SkippedDirectories++
					w.partial("depth_budget_reached")
					continue
				}
				if w.report.EntriesRead >= w.report.Budget.Entries {
					w.report.SkippedDirectories++
					w.partial("entry_budget_reached")
					continue
				}
				child, openErr := d.OpenChild(w.ctx, entry)
				if openErr != nil {
					w.metadataError(openErr)
					w.report.SkippedDirectories++
					continue
				}
				childLogical, childAllocated, err = w.walk(child, p, depth+1)
				child.Close()
			case unix.S_IFLNK, unix.S_IFIFO, unix.S_IFCHR, unix.S_IFBLK, unix.S_IFSOCK:
				childAllocated, err = w.other(m, kind)
			default:
				w.metadataError(ErrPathUnavailable)
				continue
			}
			if err != nil {
				return logical, allocated, err
			}
			if err := addUsage(&logical, childLogical); err != nil {
				return logical, allocated, err
			}
			if err := addUsage(&allocated, childAllocated); err != nil {
				return logical, allocated, err
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					return logical, allocated, readErr
				}
				w.metadataError(readErr)
			}
			break
		}
	}
	display, actionable := boundedUsagePath(raw)
	retainTop(&w.report.TopDirectories, UsageRow{Path: display, Actionable: actionable, LogicalBytes: logical, AllocatedBytes: allocated})
	return logical, allocated, nil
}

// Scan is a read-only, single-mount enumeration primitive for the future fixed
// isolated worker. It starts no goroutine/service and takes no executor mutex.
// Job durability, actor authorization, scheduling, cancellation dispatch and
// native cgroup budgets must be implemented by the caller before API exposure.
func Scan(ctx context.Context, s *Scope, relative string, ledger *Ledger, budget ScanBudget) (ScanReport, error) {
	return ScanObserved(ctx, s, relative, ledger, budget, nil)
}

func ScanObserved(ctx context.Context, s *Scope, relative string, ledger *Ledger, budget ScanBudget, observer func(ScanReport) error) (ScanReport, error) {
	if s == nil || ledger == nil || budget.Entries < 1 || budget.Entries > 100000000 || budget.Depth < 1 || budget.Depth > 1024 || !validRelativeDirectory(relative) {
		return ScanReport{}, ErrScanBudget
	}
	raw := s.mount.rawPoint
	if relative != "" && relative != "." {
		raw = path.Join(raw, relative)
	}
	display, _ := boundedUsagePath(raw)
	w := scanner{ctx: ctx, scope: s, ledger: ledger, reasons: map[string]bool{}, report: ScanReport{Format: 1, MountID: s.mount.ID, BindingSHA: s.mount.BindingSHA, SelectedPath: display, State: "running", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Budget: budget, Accounting: "st_blocks_512_per_inode_not_exclusive_extents", DirectoryAttribution: "first_observed_inode_within_this_scan", Reasons: []string{}, TopFiles: []UsageRow{}, TopDirectories: []UsageRow{}}}
	w.observer = observer
	d, err := s.OpenDirectory(ctx, relative)
	if err == nil {
		if d.identity == ledger.OwnDirectory() {
			err = ErrScanBudget
		} else {
			_, _, err = w.walk(d, raw, 0)
		}
		d.Close()
	}
	if err == nil {
		err = ledger.Flush(ctx)
		w.report.IndexFlushed = err == nil
	}
	if err == nil {
		err = w.checkpoint(true)
	}
	w.report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err != nil {
		w.report.State = "failed"
		switch {
		case errors.Is(err, context.Canceled):
			w.report.State = "canceled"
			w.partial("canceled")
		case errors.Is(err, context.DeadlineExceeded):
			w.partial("deadline_reached")
		case errors.Is(err, ErrLedgerUnavailable):
			w.partial("index_unavailable_or_capacity_reached")
		case errors.Is(err, ErrUsageOverflow):
			w.partial("usage_overflow")
		case errors.Is(err, ErrScanReused):
			w.partial("original_index_already_used")
		case errors.Is(err, ErrObserver):
			w.partial("progress_or_authority_rejected")
		default:
			w.partial("scope_unavailable")
		}
	} else if len(w.reasons) > 0 {
		w.report.State = "partial"
	} else {
		w.report.State = "complete"
		w.report.Complete = true
	}
	for reason := range w.reasons {
		w.report.Reasons = append(w.report.Reasons, reason)
	}
	sort.Strings(w.report.Reasons)
	return w.report, err
}
