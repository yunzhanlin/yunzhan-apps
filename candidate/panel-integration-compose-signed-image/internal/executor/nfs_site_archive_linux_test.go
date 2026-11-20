//go:build linux

package executor

import (
	"context"
	"errors"
	"local/panel/internal/core"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNFSSiteArchivePreflightMatchesExecutionAndPreservesData(t *testing.T) {
	for _, kind := range []string{"referenced", "pending", "corrupt-config", "corrupt-receipt", "receipt-symlink", "unrelated", "not-installed"} {
		t.Run(kind, func(t *testing.T) {
			s, site := archiveFixture(t, func(context.Context, string, ...string) (string, error) {
				t.Fatal("NFS preflight invoked native command")
				return "", errors.New("forbidden")
			})
			dir := s.moduleDir("nfs-manager")
			if kind != "not-installed" {
				if err := moduleWrite(filepath.Join(dir, "installed.json"), map[string]any{"id": "nfs-manager", "version": "1.3.1"}); err != nil {
					t.Fatal(err)
				}
				cfg := defaultNFSServerConfig()
				cfg.Revision = 1
				target := site.ID
				if kind == "unrelated" {
					target = core.ID()
				}
				cfg.Exports = []nfsExport{{ID: "owned-share", SiteID: target, Path: "", Clients: []string{"127.0.0.1"}, ReadOnly: true, ExportID: 1, UID: 988, GID: 33, Device: 1, Inode: 2}}
				raw, err := jsonMarshalNFSConfig(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err = atomicWrite(filepath.Join(dir, "server.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "pending":
					if err = os.WriteFile(filepath.Join(dir, "pending-server.json"), []byte("{broken"), 0600); err != nil {
						t.Fatal(err)
					}
				case "corrupt-config":
					if err = os.WriteFile(filepath.Join(dir, "server.json"), []byte("{broken"), 0600); err != nil {
						t.Fatal(err)
					}
				case "corrupt-receipt":
					if err = os.WriteFile(filepath.Join(dir, "installed.json"), []byte("{broken"), 0600); err != nil {
						t.Fatal(err)
					}
				case "receipt-symlink":
					if err = os.Rename(filepath.Join(dir, "installed.json"), filepath.Join(dir, "original.json")); err != nil {
						t.Fatal(err)
					}
					if err = os.Symlink("original.json", filepath.Join(dir, "installed.json")); err != nil {
						t.Fatal(err)
					}
				}
			}
			snapshot := func() map[string]string {
				result := map[string]string{}
				err := filepath.WalkDir(dir, func(p string, d os.DirEntry, e error) error {
					if errors.Is(e, os.ErrNotExist) && p == dir {
						return nil
					}
					if e != nil {
						return e
					}
					if d.IsDir() {
						return nil
					}
					if d.Type()&os.ModeSymlink != 0 {
						v, e := os.Readlink(p)
						if e != nil {
							return e
						}
						result[p] = "link:" + v
						return nil
					}
					raw, e := os.ReadFile(p)
					if e != nil {
						return e
					}
					result[p] = string(raw)
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			before := snapshot()
			configPath := filepath.Join(s.Config.ConfDir, site.ID+".conf")
			configBefore, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			check := httptest.NewRecorder()
			s.Handler().ServeHTTP(check, httptest.NewRequest("GET", "/v1/sites/"+site.ID+"/archive-check", nil))
			denied := kind != "unrelated" && kind != "not-installed"
			if denied {
				if check.Code != 409 || !strings.Contains(check.Body.String(), "NFS") {
					t.Fatal("NFS reference queued by preflight", check.Code, check.Body.String())
				}
				if _, err = s.ArchiveSite(context.Background(), core.SiteArchiveRequest{Site: site, JobID: core.ID()}); err == nil || !strings.Contains(err.Error(), "NFS") {
					t.Fatal("execution did not repeat NFS guard", err)
				}
			} else if check.Code != 200 {
				t.Fatal("unreferenced site blocked", check.Code, check.Body.String())
			}
			after := snapshot()
			if len(before) != len(after) {
				t.Fatal("NFS files created or removed")
			}
			for p, raw := range before {
				if after[p] != raw {
					t.Fatal("NFS file changed", p)
				}
			}
			if got, e := os.ReadFile(configPath); e != nil || string(got) != string(configBefore) {
				t.Fatal("site config changed", e)
			}
			if _, e := os.Stat(filepath.Join(s.Config.SitesDir, site.ID, ".panel-site.json")); e != nil {
				t.Fatal("site moved", e)
			}
		})
	}
}
