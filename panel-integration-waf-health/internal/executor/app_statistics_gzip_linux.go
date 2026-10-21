//go:build linux

package executor

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

const statisticsGzipSourceBytes int64 = 64 << 20
const statisticsGzipExpandedBytes int64 = 64 << 20

var errStatisticsGzipUnsupported = errors.New("压缩统计归档损坏、超限或读取进度不符；未提交归档请求或进度")

type statisticsGzipBatch struct {
	Lines        [][]byte
	Next         int64
	Size         int64
	SourceSHA256 string
}

// There is no tentative database write here. All selected lines remain within
// the existing 4 MiB / 10000-line batch bound, while the COMPLETE gzip stream
// (including every concatenated member) must reach verified EOF. A CRC/trailer
// error, incomplete final line, oversized expansion or cancellation discards
// the entire staged batch. This does not authorize a filesystem source: the
// caller still owns the no-link file descriptor, identity and recheck contract.
func readStatisticsGzipBatch(ctx context.Context, source io.Reader, offset, budget int64, rowBudget int) (statisticsGzipBatch, error) {
	out := statisticsGzipBatch{Next: offset}
	if offset < 0 || offset > statisticsGzipExpandedBytes || budget < 0 || budget > statisticsHistoryBatchBytes || rowBudget < 0 || rowBudget > statisticsHistoryBatchRows {
		return out, errStatisticsGzipUnsupported
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	digest := sha256.New()
	limit := &io.LimitedReader{R: statisticsContextReader{ctx: ctx, source: io.TeeReader(source, digest)}, N: statisticsGzipSourceBytes + 1}
	zipped, err := gzip.NewReader(limit)
	if err != nil {
		return statisticsGzipBatch{}, statisticsGzipReadError(ctx, err)
	}
	defer zipped.Close()
	reader := bufio.NewReaderSize(zipped, 65536)
	remainingBytes, remainingRows := budget, rowBudget
	atBoundary := offset == 0
	selecting := true
	for {
		if err := ctx.Err(); err != nil {
			return statisticsGzipBatch{}, err
		}
		line, readErr := reader.ReadSlice('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return statisticsGzipBatch{}, statisticsGzipReadError(ctx, readErr)
		}
		if int64(len(line)) > statisticsGzipExpandedBytes-out.Size {
			return statisticsGzipBatch{}, errStatisticsGzipUnsupported
		}
		start := out.Size
		out.Size += int64(len(line))
		if len(line) > 0 && line[len(line)-1] != '\n' {
			return statisticsGzipBatch{}, errStatisticsGzipUnsupported
		}
		if start == offset {
			atBoundary = true
		}
		if start < offset && out.Size > offset {
			return statisticsGzipBatch{}, errStatisticsGzipUnsupported
		}
		if len(line) > 0 && start >= offset && selecting {
			// Never jump across a line that did not fit: the next batch resumes that
			// exact decompressed boundary, and byte/row budgets include duplicates.
			if remainingRows > 0 && int64(len(line)) <= remainingBytes {
				out.Lines = append(out.Lines, append([]byte(nil), line...))
				out.Next = out.Size
				remainingBytes -= int64(len(line))
				remainingRows--
			} else {
				selecting = false
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if offset == out.Size {
		atBoundary = true
	}
	if !atBoundary || offset > out.Size || limit.N <= 0 {
		return statisticsGzipBatch{}, errStatisticsGzipUnsupported
	}
	if err := ctx.Err(); err != nil {
		return statisticsGzipBatch{}, err
	}
	out.SourceSHA256 = hex.EncodeToString(digest.Sum(nil))
	return out, nil
}

type statisticsContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r statisticsContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(b)
}
func statisticsGzipReadError(ctx context.Context, err error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return errStatisticsGzipUnsupported
}
