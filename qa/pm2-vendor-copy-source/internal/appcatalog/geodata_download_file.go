package appcatalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DownloadGeoDatabaseFile uses at most four disjoint authenticated-size ranges
// into a NEW private staging file. It never resumes, truncates or adopts an old
// partial file. A server ignoring Range uses this same first response as one
// bounded full stream; malformed partial responses never trigger a fallback.
// The complete signed compressed hash is mandatory before success, followed
// by the executor's unchanged gzip/raw/MMDB checks before publication.
func (c *Client) DownloadGeoDatabaseFile(parent context.Context, a GeoDataAuthority, destination *os.File) error {
	bad := errors.New("地理数据分段下载未完整核对；未选择新库")
	if parent == nil || parent.Err() != nil || c == nil || c.HTTP == nil || destination == nil || !a.verified || a.keySHA != hashRuleFeedFile(c.PublicKey) {
		return bad
	}
	initial, err := destination.Stat()
	if err != nil || !initial.Mode().IsRegular() || initial.Mode().Perm() != 0600 || initial.Size() != 0 {
		return bad
	}
	m := a.data.Manifest()
	ctx, cancel := context.WithTimeout(parent, 240*time.Second)
	defer cancel()
	client := *c.HTTP
	client.Timeout = 240 * time.Second
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	parts := int64(4)
	if m.CompressedBytes < parts {
		parts = m.CompressedBytes
	}
	if parts < 1 {
		return bad
	}
	type span struct{ start, end int64 }
	spans := make([]span, parts)
	for i := int64(0); i < parts; i++ {
		spans[i] = span{m.CompressedBytes * i / parts, m.CompressedBytes*(i+1)/parts - 1}
	}
	request := func(s span) (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Source, nil)
		if err != nil {
			return nil, bad
		}
		r.Header.Set("Accept-Encoding", "identity")
		r.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", s.start, s.end))
		response, err := client.Do(r)
		if err != nil {
			return nil, bad
		}
		return response, nil
	}
	encodingOK := func(r *http.Response) bool {
		values := r.Header.Values("Content-Encoding")
		return !r.Uncompressed && (len(values) == 0 || len(values) == 1 && values[0] == "identity") && !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/")
	}
	partialOK := func(r *http.Response, s span) bool {
		values := r.Header.Values("Content-Range")
		return r.StatusCode == http.StatusPartialContent && encodingOK(r) && len(values) == 1 && values[0] == fmt.Sprintf("bytes %d-%d/%d", s.start, s.end, m.CompressedBytes) && (r.ContentLength == -1 || r.ContentLength == s.end-s.start+1)
	}
	copyPart := func(r *http.Response, start, size int64) error {
		defer r.Body.Close()
		// Never write an overflow byte into an adjacent worker's range. Probe
		// EOF separately so truncated and oversized bodies both fail closed.
		n, err := io.CopyN(io.NewOffsetWriter(destination, start), r.Body, size)
		if err != nil || n != size {
			return bad
		}
		var extra [1]byte
		nExtra, end := io.ReadFull(r.Body, extra[:])
		if nExtra != 0 || end != io.EOF || ctx.Err() != nil {
			return bad
		}
		return nil
	}
	first, err := request(spans[0])
	if err != nil {
		return bad
	}
	if first.StatusCode == http.StatusOK {
		if !encodingOK(first) || len(first.Header.Values("Content-Range")) != 0 || first.ContentLength != -1 && first.ContentLength != m.CompressedBytes {
			first.Body.Close()
			return bad
		}
		if err = copyPart(first, 0, m.CompressedBytes); err != nil {
			return err
		}
	} else {
		if !partialOK(first, spans[0]) {
			first.Body.Close()
			return bad
		}
		var workers sync.WaitGroup
		failures := make(chan error, parts)
		for i, s := range spans {
			workers.Add(1)
			go func(i int, s span) {
				defer workers.Done()
				r := first
				var err error
				if i != 0 {
					r, err = request(s)
				}
				if err == nil && !partialOK(r, s) {
					r.Body.Close()
					err = bad
				}
				if err == nil {
					err = copyPart(r, s.start, s.end-s.start+1)
				}
				if err != nil {
					failures <- err
					cancel()
				}
			}(i, s)
		}
		workers.Wait()
		close(failures)
		for range failures {
			return bad
		}
	}
	beforeHash, err := destination.Stat()
	if err != nil || !os.SameFile(initial, beforeHash) || beforeHash.Size() != m.CompressedBytes || beforeHash.Mode().Perm() != 0600 || ctx.Err() != nil {
		return bad
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.NewSectionReader(destination, 0, m.CompressedBytes))
	afterHash, statErr := destination.Stat()
	if err != nil || statErr != nil || !os.SameFile(beforeHash, afterHash) || beforeHash.Size() != afterHash.Size() || beforeHash.ModTime() != afterHash.ModTime() || afterHash.Mode() != beforeHash.Mode() || n != m.CompressedBytes || hex.EncodeToString(digest.Sum(nil)) != m.CompressedSHA256 || ctx.Err() != nil {
		return bad
	}
	return nil
}
