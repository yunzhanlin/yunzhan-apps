//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"local/panel/internal/core"
)

func TestApacheCCArchiveCurrentDoesNotInventZeroForBusyMissingOrPartialLog(t *testing.T) {
	s, live, _, _ := apacheCCArchiveFixture(t, []byte("original partial"))
	ctx := context.Background()
	before := programQueueTree(t, s.Config.SystemRoot)
	status, err := s.readApacheCCArchiveCurrent(ctx, true)
	if err != nil || !status.Available || status.Bytes != 16 || !status.TailIncomplete || status.CapacityNearLimit || !status.ReadOnly {
		t.Fatal(status, err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("read-only current status changed original bytes")
	}
	writer, err := os.OpenFile(live, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(writer.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readApacheCCArchiveCurrent(ctx, true); err == nil {
		t.Fatal("busy writer shown as a current zero-byte log")
	}
	writer.Close()
	if err := os.Rename(live, live+".owned-retained"); err != nil {
		t.Fatal(err)
	}
	before = programQueueTree(t, s.Config.SystemRoot)
	if _, err := s.readApacheCCArchiveCurrent(ctx, true); err == nil {
		t.Fatal("required missing current log admitted")
	}
	status, err = s.readApacheCCArchiveCurrent(ctx, false)
	if err != nil || status.Available || status.Bytes != 0 || status.TailIncomplete || !status.ReadOnly {
		t.Fatal("known inactive absence not distinct", status, err)
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("missing current status created or repaired storage")
	}
}

func TestApacheCCArchiveRawChunksFitOriginalRPCBudgetAndPreserveWholeSource(t *testing.T) {
	for _, size := range []int{core.ApacheCCArchiveChunkBytes + 17, int(apacheCCLogMaxBytes)} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{'x'}, size)
			data[len(data)-1] = '\n'
			s, live, body, bodyBytes := apacheCCArchiveFixture(t, data)
			ctx := context.Background()
			entry, err := s.archiveApacheCCLogAt(ctx, core.ID(), nil)
			if err != nil {
				t.Fatal(err)
			}
			parts := []int{0, (len(data) - 1) / core.ApacheCCArchiveChunkBytes}
			for _, part := range parts {
				chunk, err := s.apacheCCArchiveChunk(ctx, entry.ID, part)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(chunk)
				if err != nil || len(raw) >= 1<<20 {
					t.Fatal("chunk exceeds the unchanged Core RPC budget", len(raw), err)
				}
				decoded, err := base64.StdEncoding.DecodeString(chunk["data_base64"].(string))
				offset := part * core.ApacheCCArchiveChunkBytes
				if err != nil || !bytes.Equal(decoded, data[offset:min(offset+core.ApacheCCArchiveChunkBytes, len(data))]) || chunk["sha256"] != core.Hash(string(data)) {
					t.Fatal("raw original chunk changed", part, err)
				}
			}
			if _, err := s.apacheCCArchiveChunk(ctx, entry.ID, core.ApacheCCArchiveParts); err == nil {
				t.Fatal("unbounded chunk part admitted")
			}
			archive := filepath.Join(s.apacheCCArchiveDirectory(), entry.ID, "data.log")
			if raw, _ := os.ReadFile(archive); !bytes.Equal(raw, data) {
				t.Fatal("export changed original source")
			}
			if raw, _ := os.ReadFile(live); len(raw) != 0 {
				t.Fatal("export touched active sink")
			}
			if raw, _ := os.ReadFile(body); !bytes.Equal(raw, bodyBytes) {
				t.Fatal("CC export touched separate body log")
			}
			f, err := os.OpenFile(archive, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := f.WriteAt([]byte{'z'}, 0)
			f.Close()
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			if _, err := s.apacheCCArchiveChunk(ctx, entry.ID, 0); err == nil {
				t.Fatal("changed archive exported under original digest")
			}
		})
	}
}

func TestApacheCCArchiveHTTPFixtureCannotGrantProductionAuthority(t *testing.T) {
	s, _, _, _ := apacheCCArchiveFixture(t, []byte("original\n"))
	m := http.NewServeMux()
	s.apacheCCArchiveRoutes(m)
	before := programQueueTree(t, s.Config.SystemRoot)
	for _, op := range []struct{ method, path string }{{"GET", "archives"}, {"GET", "requests/" + core.ID()}, {"GET", "archives/" + core.ID() + "/chunks/0"}, {"POST", "archive"}, {"POST", "requests/" + core.ID() + "/close"}, {"GET", "archives/" + core.ID() + "/recovery"}, {"POST", "archives/" + core.ID() + "/retain"}, {"GET", "archives/" + core.ID() + "/history"}, {"POST", "archives/" + core.ID() + "/history"}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(op.method, "/v1/software/apache-waf/cc-log/"+op.path, strings.NewReader("{}"))
		m.ServeHTTP(w, r)
		if w.Code != 503 {
			t.Fatal("private fixture acquired real Root HTTP authority", w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, programQueueTree(t, s.Config.SystemRoot)) {
		t.Fatal("refused fixture HTTP created or repaired storage")
	}
}
