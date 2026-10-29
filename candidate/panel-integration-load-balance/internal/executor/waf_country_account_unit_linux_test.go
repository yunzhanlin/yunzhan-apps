//go:build linux

package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCountryAccountPreparationTemplateAndDispatchScope(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "dev", "panel-waf-country-account@.service"))
	if err != nil || !bytes.Equal(raw, []byte(countryAccountUnitBody)) {
		t.Fatal("account template drift", err)
	}
	for _, required := range []string{
		"ExecStart=/opt/panel/bin/panel-executor --waf-country-account=%i\n",
		"NoNewPrivileges=true\n", "ProtectSystem=strict\n",
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK\n", "TimeoutStartSec=15s\n",
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatal("unbounded account helper", required)
		}
	}
	if strings.Contains(string(raw), "apt-get") || strings.Contains(string(raw), "AF_INET") {
		t.Fatal("account helper gained installer/network")
	}
	id := strings.Repeat("a", 32)
	data := "LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nFragmentPath=/etc/systemd/system/panel-waf-country-account@.service\nDropInPaths=\nTransient=no\nNeedDaemonReload=no\n"
	if !countryFixedLoadedPolicy(data, id, "/etc/systemd/system/panel-waf-country-account@.service") || countryTaskLoadedPolicy(data, id) {
		t.Fatal("account and transfer unit identities collapsed")
	}
	if err := RunWAFCountryNetworkAccountJob("not-original"); err == nil {
		t.Fatal("unbound account entry accepted")
	}
}
