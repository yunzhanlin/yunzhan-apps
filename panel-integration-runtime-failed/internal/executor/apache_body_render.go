package executor

import (
	"errors"
	"fmt"
	"strings"

	"local/panel/internal/core"
)

// A site identity must exist before phase 1 alerts; Apache SetEnvIf can run
// later than the early request hook. Only a validated immutable managed-site
// ID may enter this fixed action, never headers, a hostname or administrator text.
func renderApacheBodySiteRules(v wafBodyPolicy, sourceRoot, temporaryRoot, siteID string) (string, error) {
	if !core.ValidID(siteID) {
		return "", errors.New("Apache 请求体站点标识无效")
	}
	b, err := renderApacheBodyRules(v, sourceRoot, temporaryRoot)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("SecAction \"id:128000,phase:1,t:none,pass,nolog,setenv:PANEL_AW_SITE=%s\"\n", siteID) + b, nil
}

// The v2 PCRE limits are main-server-only. Its status and Unicode mapping are
// process-wide too; emit them once, outside every VirtualHost. Never silently
// copy v3's server-local configuration scope into native Apache v2.
func renderApacheBodyGlobalRules(sourceRoot string) (string, error) {
	if !wafEngineConfigPath(sourceRoot) {
		return "", errors.New("Apache WAF 全局资源路径无效")
	}
	return fmt.Sprintf("SecStatusEngine Off\nSecPcreMatchLimit 10000\nSecPcreMatchLimitRecursion 10000\nSecUnicodeMapFile %s/modsecurity-v2.9.15/unicode.mapping 20127\n", sourceRoot), nil
}

// Shares the closed, reviewed body-policy directives only, not a v3 Apache
// connector or an installed-engine claim. Native v2 -t, parser and real HTTP
// tests must verify the complete generated configuration before activation.
func renderApacheBodyRules(v wafBodyPolicy, sourceRoot, temporaryRoot string) (string, error) {
	b, err := renderWAFBodyRules(v, sourceRoot, temporaryRoot)
	if err != nil {
		return "", err
	}
	b = strings.Replace(b, "# managed native WAF engine "+wafBodyEngineVersion+" / connector "+wafBodyConnectorVersion+" / OWASP CRS "+wafBodyCRSVersion, "# managed native Apache WAF engine "+apacheBodyEngineVersion+" / static YAJL "+apacheBodyYAJLVersion+" / OWASP CRS "+wafBodyCRSVersion, 1)
	b = strings.Replace(b, "SecPcreMatchLimit 10000\nSecPcreMatchLimitRecursion 10000\n", "", 1)
	b = strings.Replace(b, fmt.Sprintf("SecUnicodeMapFile %s/modsecurity-v3.0.17/unicode.mapping 20127\n", sourceRoot), "", 1)
	if v.Mode == "observe" {
		// Bound inspection only; the native v2 input filter forwards retained
		// chunks and the remaining original stream without enforcing a 413.
		b = strings.Replace(b, "SecRequestBodyLimitAction Reject\n", "SecRequestBodyLimitAction ProcessPartial\n", 1)
	}
	return b, nil
}
