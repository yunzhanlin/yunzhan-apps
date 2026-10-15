//go:build linux

package executor

import (
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSitePHPScriptRejectsSymlinksAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	if e := os.Mkdir(filepath.Join(root, "cron"), 0750); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "cron", "task.php"), []byte("<?php echo PHP_VERSION;"), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := sitePHPScriptPath(root, "cron/task.php"); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(root, "cron"), filepath.Join(root, "linked")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(root, "cron", "task.php"), filepath.Join(root, "linked.php")); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"linked/task.php", "linked.php", "../task.php", "cron"} {
		if _, e := sitePHPScriptPath(root, p); e == nil {
			t.Fatal("unsafe script", p)
		}
	}
}

func TestSitePHPScriptExactCLIAndIdentity(t *testing.T) {
	in := core.AdminScriptRequest{JobID: core.ID(), SiteID: core.ID(), PHPVersionID: "php-8.3.33", Script: "cron/task.php", TimeoutSeconds: 10}
	in.ScriptSHA256 = core.AdminScriptHash(in.Script, in.SiteID, in.PHPVersionID)
	if e := validateAdminScriptRequest(in); e != nil {
		t.Fatal(e)
	}
	site := core.Site{ID: in.SiteID, PHPVersionID: in.PHPVersionID}
	args, e := sitePHPScriptArgs(in, site, "/opt/panel/runtime/php-8.3.33/bin/php", "/srv/panel/sites/"+in.SiteID+"/public/cron/task.php", []string{"-d", "memory_limit=128M"}, 10)
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Join(args, "\n")
	for _, required := range []string{"--property=User=" + siteUser(in.SiteID), "--property=ProtectSystem=strict", "--property=NoNewPrivileges=yes", "--property=RuntimeMaxSec=10s", "/opt/panel/runtime/php-8.3.33/bin/php", "memory_limit=128M"} {
		if !strings.Contains(s, required) {
			t.Fatal("missing restriction/runtime", required, s)
		}
	}
	site.PHPVersionID = "php-8.5.10"
	if _, e = sitePHPScriptArgs(in, site, "php", "cron/task.php", nil, 10); e == nil {
		t.Fatal("changed binding accepted")
	}
	in.PHPVersionID = "php-8.5.10"
	if validateAdminScriptRequest(in) == nil {
		t.Fatal("changed receipt identity accepted")
	}
}
