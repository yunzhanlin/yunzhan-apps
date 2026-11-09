package executor

import (
	"strings"
	"testing"
)

func TestRuntimeCompilerPIDFDTaskRequiresExactKernelReapingWitness(t *testing.T) {
	for _, pid := range []string{"1", "12345", "-1"} {
		value, err := runtimeCompilerPIDFDTask([]byte("pos:\t0\nflags:\t02000002\nmnt_id:\t5\nino:\t27\nPid:\t" + pid + "\nNSpid:\t" + pid + "\n"))
		if err != nil || (pid == "-1" && value != -1) || (pid != "-1" && value < 1) {
			t.Fatal(pid, value, err)
		}
	}
	for _, text := range []string{"", "Pid:\t0\n", "Pid:\t-2\n", "Pid:\t+1\n", "Pid:\t01\n", "Pid:\t1", "Pid:\t1\r\n", "Pid:\t1\x00\n", "Pid:\t1\nPid:\t-1\n", "Pid: 1\n", "NSpid:\t-1\n", "Pid:\t999999999999999999999999\n", "Pid:\t-1\n" + strings.Repeat("x", 4097) + "\n"} {
		if _, err := runtimeCompilerPIDFDTask([]byte(text)); err == nil {
			t.Fatal("partial/ambiguous fdinfo accepted", text)
		}
	}
}

func TestNativeCompilerFourAuthoritiesNeverAlias(t *testing.T) {
	decoders := []func(string) (string, error){decodeRuntimeCompilerCgroup, decodeApacheBodyCompilerCgroup, decodeNginxWAFCompilerCgroup, decodeAnalyticsHTMLCompilerCgroup}
	units := [][]string{
		{"panel-install@" + strings.Repeat("a", 32) + ".service", "panel-own-runtime-reap24anq-arm64-own123.service"},
		{"panel-apache-body-build@" + strings.Repeat("b", 32) + ".service", "panel-own-apache-body-worker24ant-arm64-own123.service"},
		{"panel-waf-engine-build@" + strings.Repeat("c", 32) + ".service", "panel-own-waf-engine-build24any-arm64-own123.service"},
		{"panel-analytics-html-build@" + strings.Repeat("d", 32) + ".service", "panel-own-analytics-html-worker24any-arm64-own123.service"},
	}
	for kind, list := range units {
		for _, unit := range list {
			for index, decode := range decoders {
				path, err := decode("0::/system.slice/" + unit + "\n")
				if (err == nil) != (kind == index) || (err == nil && path != "/system.slice/"+unit) {
					t.Fatal("compiler authority aliased or refused", kind, index, unit, path, err)
				}
			}
		}
	}
	for _, bad := range []string{"panel.service", "panel-executor.service", "nginx.service", "panel-own-waf-engine-http24any.service", "panel-own-analytics-html-http24any.service", "panel-waf-engine-build@short.service", "panel-analytics-html-build@" + strings.Repeat("A", 32) + ".service"} {
		for _, decode := range decoders {
			if _, err := decode("0::/system.slice/" + bad + "\n"); err == nil {
				t.Fatal("foreign compiler service accepted", bad)
			}
		}
	}
}

func TestRuntimeCompilerCgroupAuthorityIsSingleClosedDedicatedService(t *testing.T) {
	for _, unit := range []string{"panel-install@" + strings.Repeat("a", 32) + ".service", "panel-app-dependencies@pure-ftpd.service", "panel-own-runtime-collection24amv-arm64-abcdef1234.service", "panel-own-apache-runtime24auu-arm64-own_abcdef.service"} {
		path, err := decodeRuntimeCompilerCgroup("0::/system.slice/" + unit + "\n")
		if err != nil || path != "/system.slice/"+unit {
			t.Fatal(unit, path, err)
		}
	}
	for _, value := range []string{"", "0::/system.slice/panel-executor.service\n", "0::/system.slice/panel.service\n", "0::/system.slice/nginx.service\n", "0::/system.slice/panel-app-dependencies@other.service\n", "0::/system.slice/panel-install@../other.service\n", "0::/system.slice/panel-install@short.service\n", "0::/system.slice/panel-install@" + strings.Repeat("A", 32) + ".service\n", "0::/user.slice/panel-install@" + strings.Repeat("a", 32) + ".service\n", "0::/system.slice/panel-own-runtime-scope.scope\n", "0::/system.slice/panel-own-runtime-bad.service/children\n", "0::/system.slice/panel-own-runtime-bad.service\r\n", "0::/system.slice/panel-own-runtime-bad.service\x00\n", "0::/system.slice/panel-own-runtime-bad.service", "0::/system.slice/panel-own-runtime-bad.service\n0::/system.slice/panel.service\n", "2:cpu:/system.slice/panel-install@" + strings.Repeat("a", 32) + ".service\n", strings.Repeat("a", 4097) + "\n"} {
		if path, err := decodeRuntimeCompilerCgroup(value); err == nil || path != "" {
			t.Fatal("foreign/partial scope accepted", value, path, err)
		}
	}
}

func TestApacheBodyCompilerCgroupAuthorityNeverAliasesRuntimeOrReportServices(t *testing.T) {
	for _, unit := range []string{"panel-apache-body-build@" + strings.Repeat("a", 32) + ".service", "panel-own-apache-body-worker24ang-arm64-abcdef1234.service"} {
		text := "0::/system.slice/" + unit + "\n"
		path, err := decodeApacheBodyCompilerCgroup(text)
		if err != nil || path != "/system.slice/"+unit {
			t.Fatal("dedicated Apache compiler refused", unit, path, err)
		}
		if _, err := decodeRuntimeCompilerCgroup(text); err == nil {
			t.Fatal("Apache authority widened generic runtime compiler", unit)
		}
	}
	for _, text := range []string{"", "0::/system.slice/panel.service\n", "0::/system.slice/panel-executor.service\n", "0::/system.slice/panel-install@" + strings.Repeat("a", 32) + ".service\n", "0::/system.slice/panel-app-dependencies@pure-ftpd.service\n", "0::/system.slice/panel-own-runtime-collection24ani-arm64-abcdef.service\n", "0::/system.slice/panel-own-apache-body-http24ane-arm64-abcdef.service\n", "0::/system.slice/panel-own-apache-events24ana-arm64-abcdef.service\n", "0::/system.slice/panel-apache-body-build@short.service\n", "0::/system.slice/panel-apache-body-build@" + strings.Repeat("A", 32) + ".service\n", "0::/user.slice/panel-apache-body-build@" + strings.Repeat("a", 32) + ".service\n", "0::/system.slice/panel-own-apache-body-worker24ang.service/child\n", "0::/system.slice/panel-own-apache-body-worker24ang.scope\n", "0::/system.slice/panel-own-apache-body-worker24ang.service\r\n", "0::/system.slice/panel-own-apache-body-worker24ang.service\x00\n", "0::/system.slice/panel-own-apache-body-worker24ang.service", "0::/system.slice/panel-own-apache-body-worker24ang.service\n0::/system.slice/panel.service\n", "2:cpu:/system.slice/panel-own-apache-body-worker24ang.service\n", strings.Repeat("x", 4097) + "\n"} {
		if path, err := decodeApacheBodyCompilerCgroup(text); err == nil || path != "" {
			t.Fatal("foreign/partial Apache scope accepted", text, path, err)
		}
	}
}
