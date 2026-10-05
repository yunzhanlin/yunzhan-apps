//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestMariaDBArchiveBoundary(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
		valid   bool
	}{
		{"required tools", []*tar.Header{{Name: "mariadb-test/bin", Typeflag: tar.TypeDir}, {Name: "mariadb-test/bin/mariadbd", Typeflag: tar.TypeReg, Size: 2, Mode: 0755}, {Name: "mariadb-test/bin/mariadb", Typeflag: tar.TypeReg, Size: 2, Mode: 0755}}, true},
		{"parent escape", []*tar.Header{{Name: "mariadb-test/../escape", Typeflag: tar.TypeReg, Size: 2}}, false},
		{"external link", []*tar.Header{{Name: "mariadb-test/lib/x", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}, false},
		{"special device", []*tar.Header{{Name: "mariadb-test/bin/x", Typeflag: tar.TypeChar}}, false},
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
					_, _ = w.Write([]byte("ok"))
				}
			}
			_ = w.Close()
			e := extractDatabaseTar(tar.NewReader(&b), t.TempDir(), "mariadb-test", mariadbArchiveKeep, "MariaDB")
			if (e == nil) != c.valid {
				t.Fatalf("valid=%v error=%v", c.valid, e)
			}
		})
	}
}
