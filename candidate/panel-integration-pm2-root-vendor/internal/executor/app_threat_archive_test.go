package executor

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func threatArchiveFixture(t *testing.T, change func(*tar.Header), extra bool) []byte {
	t.Helper()
	var output bytes.Buffer
	archive := tar.NewWriter(&output)
	for _, name := range []string{"./usr/bin/suricata", "./usr/share/doc/suricata/copyright"} {
		mode := int64(0644)
		if name == "./usr/bin/suricata" {
			mode = 0755
		}
		header := &tar.Header{Name: name, Mode: mode, Size: 3, Typeflag: tar.TypeReg, Uid: 0, Gid: 0}
		if change != nil && name == "./usr/bin/suricata" {
			change(header)
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := archive.Write([]byte("abc")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if extra {
		if err := archive.WriteHeader(&tar.Header{Name: "./usr/bin/suricata", Mode: 0755, Size: 3, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte("abc")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
func TestThreatIDSArchiveSelectsOnlyClosedFilesAndRetainsCompleteLicense(t *testing.T) {
	data := threatArchiveFixture(t, nil, false)
	files, err := readThreatIDSPackageFiles(context.Background(), bytes.NewReader(data))
	if err != nil || len(files) != 2 || string(files["usr/bin/suricata"]) != "abc" || string(files["usr/share/doc/suricata/copyright"]) != "abc" {
		t.Fatal(files, err)
	}
}
func TestThreatIDSArchiveRejectsSelectedLinksTraversalModeOwnershipAndDuplicate(t *testing.T) {
	for _, change := range []func(*tar.Header){
		func(h *tar.Header) { h.Name = "../../usr/bin/suricata" },
		func(h *tar.Header) { h.Name = "/usr/bin/suricata" },
		func(h *tar.Header) { h.Name = "usr//bin/suricata" },
		func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Linkname = "/etc/passwd"; h.Size = 0 },
		func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Linkname = "etc/passwd"; h.Size = 0 },
		func(h *tar.Header) { h.Uid = 1000 }, func(h *tar.Header) { h.Gid = 1000 },
		func(h *tar.Header) { h.Mode = 0777 }, func(h *tar.Header) { h.Mode = 04755 },
	} {
		if _, err := readThreatIDSPackageFiles(context.Background(), bytes.NewReader(threatArchiveFixture(t, change, false))); err == nil {
			t.Fatal("unsafe package stream accepted")
		}
	}
	if _, err := readThreatIDSPackageFiles(context.Background(), bytes.NewReader(threatArchiveFixture(t, nil, true))); err == nil {
		t.Fatal("duplicate binary accepted")
	}
	if _, err := readThreatIDSPackageFiles(context.Background(), bytes.NewReader([]byte("broken"))); err == nil {
		t.Fatal("broken TAR accepted")
	}
}
func TestThreatIDSArchiveCancellationReadFailureAndTrailingExpansionBound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readThreatIDSPackageFiles(ctx, bytes.NewReader(threatArchiveFixture(t, nil, false))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := readThreatIDSPackageFiles(context.Background(), threatEVEBrokenReader{}); err == nil {
		t.Fatal("read failure ignored")
	}
	input := io.MultiReader(bytes.NewReader(threatArchiveFixture(t, nil, false)), io.LimitReader(threatArchiveZeros{}, threatIDSTarLimit))
	if _, err := readThreatIDSPackageFiles(context.Background(), input); err == nil {
		t.Fatal("post-end expansion ignored")
	}
}

type threatArchiveZeros struct{}

func (threatArchiveZeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
