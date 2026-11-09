//go:build linux

package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func TestRenderPanelAccessSecurityBoundary(t *testing.T) {
	id := core.ID()
	out, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443, CertificateID: id, AllowedCIDRs: []string{"10.0.0.1/8", "192.168.1.0/24"}, HTTPSEnabled: true, Revision: 7})
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{
		"listen 127.0.0.1:19443 ssl;",
		"listen [::1]:19443 ssl;",
		"server_name panel.localhost;",
		"ssl_protocols TLSv1.2 TLSv1.3;",
		"ssl_session_tickets off;",
		"allow 127.0.0.1;",
		"allow ::1;",
		"allow 10.0.0.0/8;",
		"allow 192.168.1.0/24;",
		"deny all;",
		"proxy_set_header X-Forwarded-Proto https;",
		"/etc/panel/certificates/" + id + "/key.pem",
	} {
		if !strings.Contains(out, required) {
			t.Fatal("missing panel access directive", required)
		}
	}
	if _, e = renderPanelAccess(core.PanelAccess{Domain: "panel.localhost; include /etc/passwd", Port: 19443, HTTPSEnabled: false}); e == nil {
		t.Fatal("domain injection accepted")
	}
	if _, e = renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443, CertificateID: id, AllowedCIDRs: []string{"127.0.0.1; deny all"}, HTTPSEnabled: true}); e == nil {
		t.Fatal("CIDR injection accepted")
	}
	disabled, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443})
	if e != nil || strings.Contains(disabled, "server {") {
		t.Fatal("disabled entry rendered a server", disabled, e)
	}
	changed, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19444, CertificateID: id, HTTPSEnabled: true})
	if e != nil || !strings.Contains(changed, "listen 127.0.0.1:19444 ssl;") {
		t.Fatal("alternate port not rendered", e)
	}
	for _, port := range []int{0, 80, 19100, 65536} {
		if _, e = renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: port}); e == nil {
			t.Fatalf("invalid port %d accepted", port)
		}
	}
}

func TestRenderPublicHTTPEntryGate(t *testing.T) {
	entry := "aB3dE5fG7h"
	out, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 27727, HTTPEntry: entry})
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{"listen 0.0.0.0:27727;", "server_name 192.0.2.10;", "location = /" + entry, "return 302 /" + entry + "/;", "location ^~ /" + entry + "/", "location / { return 404; }", "X-Panel-Connection public-http;", "proxy_set_header X-Real-IP $remote_addr;"} {
		if !strings.Contains(out, required) {
			t.Fatal("missing public HTTP gate", required)
		}
	}
	if _, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 27727, HTTPEntry: entry + "; include /etc/passwd"}); e == nil {
		t.Fatal("entry path injection accepted")
	}
	legacy := strings.Repeat("a", 32)
	if _, e := renderPanelAccess(core.PanelAccess{Domain: "panel.localhost", Port: 19443, HTTPEnabled: true, HTTPIP: "192.0.2.10", HTTPPort: 27727, HTTPEntry: legacy}); e != nil {
		t.Fatal("existing entry cannot be rendered during rollback", e)
	}
}
