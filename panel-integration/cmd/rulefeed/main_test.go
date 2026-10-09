package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"local/panel/internal/rulefeed"
	"os"
	"path/filepath"
	"testing"
)

func commandFixture(t *testing.T) (string, string) {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, name := range []string{"LICENSE", "BSD-License.txt"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "internal", "rulefeed", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.WriteHeader(&tar.Header{Name: "rules/" + name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		writer.Write(data)
	}
	rules := []byte("alert tcp any any -> $HOME_NET any (msg:\"own command fixture\";sid:2000001;rev:1;)\nalert tcp any any -> $HOME_NET any (msg:\"second own command fixture\";sid:2000002;rev:1;)\n")
	writer.WriteHeader(&tar.Header{Name: "rules/emerging-fixture.rules", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(rules))})
	writer.Write(rules)
	writer.Close()
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	zip.Write(raw.Bytes())
	zip.Close()
	name := filepath.Join(t.TempDir(), "reviewed.tar.gz")
	if err := os.WriteFile(name, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return name, fmt.Sprintf("%x", sha256.Sum256(compressed.Bytes()))
}

func TestOfflineCommandPrivateCompleteArtifactAndNoOverwrite(t *testing.T) {
	archive, digest := commandFixture(t)
	parent := t.TempDir()
	var out bytes.Buffer
	args := []string{"-archive", archive, "-sha256", digest, "-categories", "emerging-fixture", "-output-parent", parent}
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Directory string            `json:"private_directory"`
		Manifest  rulefeed.Manifest `json:"manifest"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(result.Directory)
	if err != nil || info.Mode().Perm() != 0700 || filepath.Dir(result.Directory) != parent {
		t.Fatal("output not in new private directory")
	}
	entries, err := os.ReadDir(result.Directory)
	if err != nil || len(entries) != 6 {
		t.Fatal("incomplete closed artifact")
	}
	before := map[string]string{}
	for _, entry := range entries {
		name := filepath.Join(result.Directory, entry.Name())
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Lstat(name)
		if info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
			t.Fatal("artifact permissions widened")
		}
		before[name] = fmt.Sprintf("%x", sha256.Sum256(data))
		if entry.Name() != "manifest.json" && before[name] != result.Manifest.Files[entry.Name()] {
			t.Fatal("artifact hash mismatch")
		}
	}
	if result.Manifest.EnabledRuleCount != 2 || result.Manifest.NativeSyntaxVerified || result.Manifest.PublisherSignatureVerified {
		t.Fatal("wrong scope or false native/signature proof")
	}
	out.Reset()
	if err := run(context.Background(), args, &out); err != nil {
		t.Fatal(err)
	}
	var second struct {
		Directory string `json:"private_directory"`
	}
	json.Unmarshal(out.Bytes(), &second)
	if second.Directory == result.Directory {
		t.Fatal("existing artifact replaced")
	}
	for name, digest := range before {
		data, _ := os.ReadFile(name)
		if fmt.Sprintf("%x", sha256.Sum256(data)) != digest {
			t.Fatal("prior artifact modified")
		}
	}
}

func TestOfflineCommandRejectsUnsafeInputsBeforeArtifactCreation(t *testing.T) {
	archive, digest := commandFixture(t)
	for _, scenario := range []string{"archive-link", "parent-link", "writable-parent", "wrong-digest", "empty-category", "over-budget", "cancelled"} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			input := archive
			expected := digest
			category := "emerging-fixture"
			budget := "128"
			outputParent := parent
			ctx := context.Background()
			switch scenario {
			case "archive-link":
				input = filepath.Join(t.TempDir(), "source-link")
				if err := os.Symlink(archive, input); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				outputParent = filepath.Join(t.TempDir(), "output-link")
				if err := os.Symlink(parent, outputParent); err != nil {
					t.Fatal(err)
				}
			case "writable-parent":
				if err := os.Chmod(parent, 0770); err != nil {
					t.Fatal(err)
				}
			case "wrong-digest":
				expected = fmt.Sprintf("%064d", 0)
			case "empty-category":
				category = ""
			case "over-budget":
				budget = "1"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var out bytes.Buffer
			err := run(ctx, []string{"-archive", input, "-sha256", expected, "-categories", category, "-max-rules", budget, "-output-parent", outputParent}, &out)
			entries, readErr := os.ReadDir(parent)
			if err == nil || out.Len() != 0 || readErr != nil || len(entries) != 0 {
				t.Fatal("unsafe command created/announced artifact", err)
			}
		})
	}
}

type failingResultWriter struct{}

func (failingResultWriter) Write([]byte) (int, error) {
	return 0, errors.New("owned result writer failure")
}

func TestOfflineCommandListReadOnlyAndFailedResultRetained(t *testing.T) {
	archive, digest := commandFixture(t)
	parent := t.TempDir()
	var out bytes.Buffer
	if err := run(context.Background(), []string{"-archive", archive, "-sha256", digest, "-list"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[\"emerging-fixture\"]\n" {
		t.Fatal("unexpected inventory")
	}
	if err := run(context.Background(), []string{"-archive", archive, "-sha256", digest, "-categories", "emerging-fixture", "-output-parent", parent}, failingResultWriter{}); err == nil {
		t.Fatal("failed result write reported success")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("failed output not retained privately")
	}
	files, err := os.ReadDir(filepath.Join(parent, entries[0].Name()))
	if err != nil || len(files) != 6 {
		t.Fatal("retained output incomplete")
	}
}
