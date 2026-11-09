//go:build linux

package executor

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func TestNginxPrivateYAJLHeadersRemainPublicUnderPrivateWorkerUMask(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("PANEL_QA_NGINX_YAJL_HEADERS") != "1" {
		t.Skip("requires explicit root Linux private worker fixture")
	}
	builder, err := user.Lookup("panel-build")
	if err != nil {
		t.Fatal(err)
	}
	uid, uerr := strconv.Atoi(builder.Uid)
	gid, gerr := strconv.Atoi(builder.Gid)
	if uerr != nil || gerr != nil || uid <= 0 || gid <= 0 {
		t.Fatal("invalid fixed compiler identity")
	}
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	root := t.TempDir()
	assets, prefix := filepath.Join(root, "assets"), filepath.Join(root, "prefix")
	for _, p := range []string{assets, prefix} {
		if err := os.Mkdir(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h"} {
		if err := os.WriteFile(filepath.Join(assets, "private-yajl-"+name), []byte("fixed private header fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareNginxPrivateYAJL(context.Background(), assets, prefix, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"yajl_common.h", "yajl_parse.h", "yajl_gen.h", "yajl_tree.h", "yajl_version.h"} {
		st, err := os.Lstat(filepath.Join(prefix, "include/yajl", name))
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0644 {
			t.Fatal("non-root compiler cannot read public header", name, err)
		}
		meta, ok := st.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != 0 || meta.Nlink != 1 {
			t.Fatal("public header lost exclusive original root ownership")
		}
		if name != "yajl_version.h" {
			private, err := os.Stat(filepath.Join(assets, "private-yajl-"+name))
			if err != nil || private.Mode().Perm() != 0600 {
				t.Fatal("private source header permissions widened", err)
			}
		}
	}
	src := filepath.Join(assets, "private-yajl-yajl_parse.h")
	dst := filepath.Join(prefix, "include/yajl/yajl_parse.h")
	before, _ := os.ReadFile(dst)
	if err := copyNginxPrivateYAJLHeader(context.Background(), src, dst); err == nil {
		t.Fatal("existing public header overwritten")
	}
	if after, _ := os.ReadFile(dst); string(after) != string(before) {
		t.Fatal("existing public header modified on refusal")
	}
	for _, kind := range []string{"symbolic-source", "hardlinked-source", "writable-source", "oversize-source"} {
		p := filepath.Join(assets, kind)
		switch kind {
		case "symbolic-source":
			err = os.Symlink(src, p)
		case "hardlinked-source":
			err = os.Link(src, p)
		case "writable-source":
			err = os.WriteFile(p, []byte("unsafe\n"), 0600)
			if err == nil {
				err = os.Chmod(p, 0666)
			}
		case "oversize-source":
			err = os.WriteFile(p, make([]byte, (64<<10)+1), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(prefix, kind)
		if err := copyNginxPrivateYAJLHeader(context.Background(), p, output); err == nil {
			t.Fatal("unsafe header accepted", kind)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("unsafe header published", kind)
		}
	}
	t.Log("PASS private worker UMask=0077: public root-owned YAJL headers exactly 0644; source copies remain 0600; unsafe publication refused")
}

func TestNginxPrivateYAJLActualPinnedArchiveKeepsGlobalMetadataStrict(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("PANEL_QA_NGINX_YAJL_ARCHIVE") != "1" {
		t.Skip("requires explicit root Linux private fixed-archive fixture")
	}
	const archive = "/run/panel-nginx-yajl-native-source24aox/yajl.tar.gz"
	source := wafEngineSources()[3]
	if source.Name != "nginx-yajl" || source.SHA256 != "3fb73364a5a30efe615046d07e6db9d09fd2b41c763c5f7d3bfb121cd5c5ac5a" {
		t.Fatal("unexpected independent source pin")
	}
	root := t.TempDir()
	strict := filepath.Join(root, "generic-strict")
	if err := extractPinnedWAFSource(context.Background(), archive, strict, "yajl-2.1.0", source.SHA256); err == nil {
		t.Fatal("generic extraction silently accepted global Git metadata")
	}
	if _, err := os.Lstat(strict); !os.IsNotExist(err) {
		t.Fatal("generic metadata refusal wrote a destination")
	}
	approved := filepath.Join(root, "nginx-exact")
	if err := extractWAFEngineSource(context.Background(), source, archive, approved); err != nil {
		t.Fatal("exact reviewed Nginx YAJL Git export rejected", err)
	}
	if _, err := os.Stat(filepath.Join(approved, "yajl-2.1.0/src/api/yajl_parse.h")); err != nil {
		t.Fatal("actual fixed archive extraction missing header", err)
	}
	other := filepath.Join(root, "apache-alias")
	if err := extractWAFEngineSource(context.Background(), apacheBodySources()[1], archive, other); err == nil {
		t.Fatal("same upstream bytes granted another engine's source identity")
	}
	if _, err := os.Lstat(other); !os.IsNotExist(err) {
		t.Fatal("unreviewed source alias wrote a destination")
	}
	t.Log("PASS actual SHA-pinned YAJL Git export: exact independent Nginx source accepted; generic global metadata and Apache alias refused before writes")
}
