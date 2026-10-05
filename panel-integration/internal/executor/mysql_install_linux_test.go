//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMySQLArchiveBoundary(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
		valid   bool
	}{
		{"official repeated directory", []*tar.Header{{Name: "mysql-test/bin", Typeflag: tar.TypeDir}, {Name: "mysql-test/bin", Typeflag: tar.TypeDir}, {Name: "mysql-test/bin/mysql", Typeflag: tar.TypeReg, Size: 2, Mode: 0755}}, true},
		{"duplicate file", []*tar.Header{{Name: "mysql-test/bin/mysql", Typeflag: tar.TypeReg, Size: 2}, {Name: "mysql-test/bin/mysql", Typeflag: tar.TypeReg, Size: 2}}, false},
		{"parent escape", []*tar.Header{{Name: "mysql-test/../escape", Typeflag: tar.TypeReg, Size: 2}}, false},
		{"external link", []*tar.Header{{Name: "mysql-test/lib/x", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, false},
		{"linked parent", []*tar.Header{{Name: "mysql-test/lib/p", Typeflag: tar.TypeSymlink, Linkname: ".."}, {Name: "mysql-test/lib/p/mysql", Typeflag: tar.TypeReg, Size: 2}}, false},
		{"internal library link", []*tar.Header{{Name: "mysql-test/lib/libx.so.1", Typeflag: tar.TypeReg, Size: 2}, {Name: "mysql-test/lib/libx.so", Typeflag: tar.TypeSymlink, Linkname: "libx.so.1"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			w := tar.NewWriter(&b)
			for _, h := range c.headers {
				if e := w.WriteHeader(h); e != nil {
					t.Fatal(e)
				}
				if h.Size > 0 {
					w.Write([]byte("ok"))
				}
			}
			w.Close()
			dest := t.TempDir()
			e := extractMySQLTar(tar.NewReader(&b), dest, "mysql-test")
			if (e == nil) != c.valid {
				t.Fatalf("valid=%v error=%v", c.valid, e)
			}
			if c.name == "internal library link" && e == nil {
				st, e := os.Lstat(filepath.Join(dest, "lib/libx.so"))
				if e != nil || !st.Mode().IsRegular() {
					t.Fatal("library alias was not materialized")
				}
			}
		})
	}
}
func TestMigrationRowFingerprintDetectsChangedData(t *testing.T) {
	a, b, c := &rowFingerprintWriter{}, &rowFingerprintWriter{}, &rowFingerprintWriter{}
	a.Write([]byte("INSERT INTO `a` VALUES (1,'x');\nINSERT INTO `a` VALUES (2,'y');\n"))
	b.Write([]byte("-- ignored metadata\nINSERT INTO `a` VALUES (2,'y');\nINSERT INTO `a` VALUES (1,'x');\n"))
	c.Write([]byte("INSERT INTO `a` VALUES (1,'x');\nINSERT INTO `a` VALUES (2,'z');\n"))
	if a.rows != 2 || a.sum.Cmp(&b.sum) != 0 || a.sum.Cmp(&c.sum) == 0 {
		t.Fatal("multiset fingerprint failed")
	}
}
