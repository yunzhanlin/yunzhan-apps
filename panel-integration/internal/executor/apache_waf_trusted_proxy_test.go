package executor

import (
	"local/panel/internal/core"
	"strings"
	"testing"
)

func apacheTrustedProxyFixture() *core.WAFTrustedProxyConfig {
	return &core.WAFTrustedProxyConfig{Enabled: true, Header: "X-Forwarded-For", Recursive: true, TrustedCIDRs: []string{"127.0.0.1/32", "2001:db8:100::/48"}, AcknowledgeHeaderControl: true}
}

func TestApacheWAFTrustedProxySourceDoesNotImportImplicitTrust(t *testing.T) {
	module := "/opt/panel/runtimes/apache/2.4.68/modules/mod_remoteip.so"
	source := "# managed by panel\n<VirtualHost 127.0.0.1:19080>\n ServerName a.localhost\n " + apacheWAFInclude + "</VirtualHost>\n"
	proxy := apacheTrustedProxyFixture()
	prepared, err := prepareApacheWAFTrustedProxySource(source, proxy, module)
	if err != nil || strings.Count(prepared, "LoadModule remoteip_module ") != 1 || strings.Contains(prepared, "RemoteIPHeader") {
		t.Fatal(prepared, err)
	}
	again, err := prepareApacheWAFTrustedProxySource(prepared, proxy, module)
	if err != nil || again != prepared {
		t.Fatal("module insertion not idempotent", err)
	}
	proxy.Enabled = false
	if got, err := prepareApacheWAFTrustedProxySource(prepared, proxy, module); err != nil || got != prepared {
		t.Fatal("disable rewrote unrelated global module", err)
	}
	for _, conflict := range []string{"RemoteIPHeader X-Real-IP\n", "remoteipinternalproxy 10.0.0.0/8\n", "RemoteIPTrustedProxy 127.0.0.0/8\n", "RemoteIPProxyProtocol On\n", "Include /etc/apache2/extra.conf\n", "IncludeOptional /etc/apache2/conf.d/*.conf\n", "LoadModule remoteip_module /tmp/unknown.so\n"} {
		if _, err := prepareApacheWAFTrustedProxySource(source+conflict, proxy, module); err == nil {
			t.Fatal("external trust not rejected", conflict)
		}
		if _, err := prepareApacheWAFTrustedProxySource(source+conflict, nil, module); err == nil {
			t.Fatal("historical omission imported external trust", conflict)
		}
	}
	if _, err := prepareApacheWAFTrustedProxySource(prepared+"LoadModule remoteip_module \""+module+"\"\n", proxy, module); err == nil {
		t.Fatal("duplicate module accepted")
	}
}

func TestApacheWAFTrustedProxyRenderingExplicitPeersAndDualIdentity(t *testing.T) {
	for _, mode := range []string{"off", "observe", "block"} {
		cfg := core.DefaultApacheWAFConfig()
		cfg.Policy.Mode = mode
		cfg.TrustedProxy = apacheTrustedProxyFixture()
		rules, err := renderApacheWAF(cfg, map[string][]string{})
		if err != nil || strings.Count(rules, "RemoteIPInternalProxy ") != 2 || strings.Count(rules, "RemoteIPHeader X-Forwarded-For") != 1 || !strings.Contains(rules, `%{c}a`) {
			t.Fatal(rules, err)
		}
		cfg.TrustedProxy.Enabled = false
		rules, err = renderApacheWAF(cfg, map[string][]string{})
		if err != nil || strings.Contains(rules, "RemoteIPHeader") || strings.Contains(rules, "RemoteIPInternalProxy") {
			t.Fatal("disabled identity still trusts peers", rules, err)
		}
	}
	cfg := core.DefaultApacheWAFConfig()
	cfg.TrustedProxy = apacheTrustedProxyFixture()
	cfg.TrustedProxy.TrustedCIDRs = nil
	if _, err := renderApacheWAF(cfg, map[string][]string{}); err == nil {
		t.Fatal("renderer could emit globally trusting header")
	}
}
