//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyticsGitMetadataCannotOverrideArchivePaths(t *testing.T) {
	commit := analyticsNJSCommit
	for _, extra := range []map[string]string{{"path": "../../outside"}, {"linkpath": "/etc/passwd"}, {"size": "999999"}, {"mtime": "0"}, {"comment": "wrong"}} {
		header := &tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": commit}}
		for k, v := range extra {
			header.PAXRecords[k] = v
		}
		if err := validatePinnedGitMetadata(header, commit, false); err == nil {
			t.Fatal("global override allowed", extra)
		}
	}
	good := &tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": commit}}
	if err := validatePinnedGitMetadata(good, commit, false); err != nil {
		t.Fatal(err)
	}
	if validatePinnedGitMetadata(good, "", false) == nil || validatePinnedGitMetadata(good, commit, true) == nil {
		t.Fatal("strict WAF or first-header boundary lost")
	}
	fixture := func(records map[string]string, late, duplicate bool) []byte {
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		meta := func() {
			if err := tw.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: records}); err != nil {
				t.Fatal(err)
			}
		}
		if !late {
			meta()
		}
		if duplicate {
			meta()
		}
		if err := tw.WriteHeader(&tar.Header{Name: "reviewed/source", Typeflag: tar.TypeReg, Mode: 0644, Size: 5}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("fixed"))
		if late {
			meta()
		}
		_ = tw.Close()
		_ = gz.Close()
		return out.Bytes()
	}
	for _, tc := range []struct {
		records                 map[string]string
		late, duplicate, accept bool
	}{
		{map[string]string{"comment": commit}, false, false, true},
		{map[string]string{"comment": commit}, true, false, false},
		{map[string]string{"comment": commit}, false, true, false},
		{map[string]string{"comment": commit, "path": "outside"}, false, false, false},
		{map[string]string{"comment": "wrong"}, false, false, false},
	} {
		archive, dest, sha := wafStageFixture(t, fixture(tc.records, tc.late, tc.duplicate))
		err := extractPinnedSourceArchive(context.Background(), archive, dest, "reviewed", sha, commit)
		if (err == nil) != tc.accept {
			t.Fatal("metadata acceptance mismatch", tc, err)
		}
		if tc.accept {
			data, e := os.ReadFile(filepath.Join(dest, "reviewed/source"))
			if e != nil || string(data) != "fixed" {
				t.Fatal("actual safe extraction", e)
			}
		} else if _, e := os.Lstat(dest); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("metadata rejected after write", e)
		}
		strict := dest + "-strict"
		if extractPinnedWAFSource(context.Background(), archive, strict, "reviewed", sha) == nil {
			t.Fatal("unrelated WAF archive policy relaxed")
		}
	}
}
