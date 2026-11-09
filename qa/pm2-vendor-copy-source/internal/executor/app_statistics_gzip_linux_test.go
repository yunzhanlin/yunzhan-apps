//go:build linux

package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func statisticsTestGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestStatisticsGzipFullyValidatesConcatenatedMembersBeforeStaging(t *testing.T) {
	first := []byte("one\ntwo\n")
	second := []byte("three\n")
	zipped := append(statisticsTestGzip(t, first), statisticsTestGzip(t, second)...)
	batch, err := readStatisticsGzipBatch(context.Background(), bytes.NewReader(zipped), 0, 8, 2)
	digest := sha256.Sum256(zipped)
	if err != nil || batch.Size != 14 || batch.Next != 8 || len(batch.Lines) != 2 || batch.SourceSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("bounded full-member validation", batch, err)
	}
	next, err := readStatisticsGzipBatch(context.Background(), bytes.NewReader(zipped), batch.Next, statisticsHistoryBatchBytes, statisticsHistoryBatchRows)
	if err != nil || next.Next != 14 || len(next.Lines) != 1 || string(next.Lines[0]) != "three\n" {
		t.Fatal("decompressed boundary continuation", next, err)
	}
	for _, offset := range []int64{1, 3, 5, 13, 15, statisticsGzipExpandedBytes + 1} {
		if out, err := readStatisticsGzipBatch(context.Background(), bytes.NewReader(zipped), offset, statisticsHistoryBatchBytes, statisticsHistoryBatchRows); err == nil || len(out.Lines) != 0 {
			t.Fatal("invalid offset staged tentative rows", offset, err)
		}
	}
}

func TestStatisticsGzipCRCTruncationJunkAndPartialLineDiscardAll(t *testing.T) {
	first := statisticsTestGzip(t, []byte("accepted-looking-line\n"))
	corrupt := append([]byte(nil), first...)
	corrupt[len(corrupt)-8] ^= 1
	late := append(append([]byte(nil), first...), corrupt...)
	for name, input := range map[string][]byte{"crc": corrupt, "late-member-crc": late, "truncated": first[:len(first)-1], "junk": append(append([]byte(nil), first...), []byte("trailing-junk")...), "partial-line": statisticsTestGzip(t, []byte("not-complete")), "overlong-line": statisticsTestGzip(t, []byte(strings.Repeat("x", 65536)+"\n"))} {
		t.Run(name, func(t *testing.T) {
			out, err := readStatisticsGzipBatch(context.Background(), bytes.NewReader(input), 0, statisticsHistoryBatchBytes, statisticsHistoryBatchRows)
			if !errors.Is(err, errStatisticsGzipUnsupported) || len(out.Lines) != 0 || out.SourceSHA256 != "" {
				t.Fatal("unvalidated bytes escaped staging", out, err)
			}
		})
	}
}

func TestStatisticsGzipExpansionCancellationAndBatchBounds(t *testing.T) {
	// Small compressed input expanding past the explicit64MiB scan ceiling
	// must fail without publishing even the first valid-looking batch.
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	chunk := []byte(strings.Repeat("x", 1023) + "\n")
	for n := int64(0); n <= statisticsGzipExpandedBytes/int64(len(chunk)); n++ {
		if _, err := z.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := readStatisticsGzipBatch(context.Background(), bytes.NewReader(b.Bytes()), 0, statisticsHistoryBatchBytes, statisticsHistoryBatchRows)
	if !errors.Is(err, errStatisticsGzipUnsupported) || len(out.Lines) != 0 {
		t.Fatal("zip-bomb budget escaped", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, err = readStatisticsGzipBatch(ctx, bytes.NewReader(b.Bytes()), 0, statisticsHistoryBatchBytes, statisticsHistoryBatchRows); !errors.Is(err, context.Canceled) || len(out.Lines) != 0 {
		t.Fatal("cancellation ignored", err)
	}
	compressed := statisticsTestGzip(t, []byte("1234\nsecond\n"))
	out, err = readStatisticsGzipBatch(context.Background(), bytes.NewReader(compressed), 0, 4, 1)
	if err != nil || out.Next != 0 || len(out.Lines) != 0 {
		t.Fatal("byte budget skipped non-fitting first line", out, err)
	}
	for _, values := range [][3]int64{{-1, 4, 1}, {0, -1, 1}, {0, statisticsHistoryBatchBytes + 1, 1}, {0, 4, -1}, {0, 4, statisticsHistoryBatchRows + 1}} {
		if _, err = readStatisticsGzipBatch(context.Background(), bytes.NewReader(compressed), values[0], values[1], int(values[2])); err == nil {
			t.Fatal("caller escaped closed batch budget", values)
		}
	}
}
