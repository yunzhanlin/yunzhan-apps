//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"local/panel/internal/core"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Opt-in on an isolated installed Linux VM. This invokes the actual systemd
// sandbox and catalogued PHP binary; it is not a command-runner mock.
func TestSitePHPScriptRealSystemd(t *testing.T) {
	id := os.Getenv("PANEL_PHP_SCHEDULE_ACCEPT_SITE")
	if id == "" {
		t.Skip("isolated real PHP site required")
	}
	if os.Geteuid() != 0 || !core.ValidID(id) {
		t.Fatal("root and valid isolated site required")
	}
	b, e := os.ReadFile(filepath.Join(phpConfigRoot, "bindings", id+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var site core.Site
	if e = json.Unmarshal(b, &site); e != nil || site.PHPVersionID == "" {
		t.Fatal(e, site)
	}
	account, e := user.Lookup(siteUser(id))
	if e != nil {
		t.Fatal(e)
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	if uid == 0 || gid == 0 {
		t.Fatal("root site user")
	}
	task, e := user.Lookup("panel-task")
	if e != nil {
		t.Fatal(e)
	}
	taskUID, _ := strconv.Atoi(task.Uid)
	taskGID, _ := strconv.Atoi(task.Gid)
	nonce := core.ID()
	script := "m112-cron-" + nonce + ".php"
	marker := script + ".count"
	public := "/srv/panel/sites/" + id + "/public"
	content := `<?php
$marker=__FILE__.'.count';
$n=is_file($marker)?(int)file_get_contents($marker):0;
if (file_put_contents($marker,(string)($n+1))===false) exit(21);
if (@file_put_contents('/etc/panel-m112-escape','denied')!==false) exit(22);
$socket=@fsockopen('127.0.0.1',19100,$errno,$error,3);
if (!$socket) exit(23);
fclose($socket);
echo json_encode(['php'=>PHP_VERSION,'cwd'=>getcwd(),'uid'=>posix_geteuid(),'memory'=>ini_get('memory_limit')]);
`
	file := filepath.Join(public, script)
	if e = os.WriteFile(file, []byte(content), 0640); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(file, uid, gid); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(file)
	defer os.Remove(filepath.Join(public, marker))
	state, tasks := adminScriptTestDirs(t)
	in := core.AdminScriptRequest{JobID: nonce, SiteID: id, PHPVersionID: site.PHPVersionID, Script: script, TimeoutSeconds: 15}
	in.ScriptSHA256 = core.AdminScriptHash(in.Script, in.SiteID, in.PHPVersionID)
	runner := func(ctx context.Context, _ string, timeout int) (string, bool, error) {
		return runSitePHPScriptSystemd(ctx, in, timeout)
	}
	first, e := executeAdminScriptAt(context.Background(), in, state, tasks, taskUID, taskGID, runner)
	if e != nil {
		t.Fatal(e, first.Output)
	}
	var result struct {
		PHP, CWD, Memory string
		UID              int
	}
	if e = json.Unmarshal([]byte(first.Output), &result); e != nil {
		t.Fatal(e, first.Output)
	}
	if result.PHP != strings.TrimPrefix(site.PHPVersionID, "php-") || result.CWD != public || result.UID != uid {
		t.Fatal(result)
	}
	for _, pair := range core.PHPIniValues(site.Settings.PHP) {
		if pair[0] == "memory_limit" && result.Memory != pair[1] {
			t.Fatal("settings differ", result.Memory, pair[1])
		}
	}
	if _, e = executeAdminScriptAt(context.Background(), in, state, tasks, taskUID, taskGID, runner); e != nil {
		t.Fatal(e)
	}
	count, e := os.ReadFile(filepath.Join(public, marker))
	if e != nil || string(count) != "1" {
		t.Fatal("duplicate execution", string(count), e)
	}
	if e = os.WriteFile(file, []byte("<?php sleep(5); file_put_contents(__FILE__.'.late','late');"), 0640); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(file + ".late")
	in.JobID = core.ID()
	in.TimeoutSeconds = 1
	start := time.Now()
	if _, _, e = runSitePHPScriptSystemd(context.Background(), in, 1); e == nil {
		t.Fatal("timeout not enforced")
	}
	if time.Since(start) > 12*time.Second {
		t.Fatal("timeout exceeded bound")
	}
	time.Sleep(5 * time.Second)
	if _, e = os.Stat(file + ".late"); !os.IsNotExist(e) {
		t.Fatal("timed-out PHP continued")
	}
	in.PHPVersionID = "php-8.5.10"
	if in.PHPVersionID == site.PHPVersionID {
		in.PHPVersionID = "php-8.2.33"
	}
	in.ScriptSHA256 = core.AdminScriptHash(in.Script, in.SiteID, in.PHPVersionID)
	if _, _, e = runSitePHPScriptSystemd(context.Background(), in, 5); e == nil || !strings.Contains(e.Error(), "绑定已变更") {
		t.Fatal("version change not rejected", e)
	}
	t.Logf("real PHP %s: non-root site user, own-site write, system write denied, local network, settings, once-only receipt, timeout and changed-binding rejection passed", result.PHP)
}
