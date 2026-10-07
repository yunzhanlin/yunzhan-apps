package executor

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"local/panel/internal/core"
)

// This is a native-engine contract, not a claim that an engine is installed.
// It is not enabled by the older metadata-only WAF setting. Integration must
// validate the selected Nginx binary, source manifest, module and config first.
type wafBodyPolicy = core.WAFBodyPolicy

func defaultWAFBodyPolicy() wafBodyPolicy {
	return core.DefaultWAFBodyPolicy()
}

func validateWAFBodyPolicy(v wafBodyPolicy) error {
	return core.ValidateWAFBodyPolicy(v)
}

var wafEnginePathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

func wafEngineConfigPath(path string) bool {
	return len(path) <= 512 && path != "/" && filepath.IsAbs(path) && filepath.Clean(path) == path && wafEnginePathPattern.MatchString(path)
}

// Managed rules never include downloaded configuration text, administrator
// snippets, raw request data, remote rules, audit bodies or response contents.
// The supplied directories are independently verified root-owned engine state.
func renderWAFBodyRules(v wafBodyPolicy, sourceRoot, temporaryRoot string) (string, error) {
	if err := validateWAFBodyPolicy(v); err != nil {
		return "", err
	}
	if !wafEngineConfigPath(sourceRoot) || !wafEngineConfigPath(temporaryRoot) {
		return "", errors.New("WAF 引擎资源路径无效；禁止配置注入和路径跳转")
	}
	engine := "On"
	if v.Mode == "observe" {
		engine = "DetectionOnly"
	} else if v.Mode == "off" {
		engine = "Off"
	}
	var out strings.Builder
	fmt.Fprintf(&out, "# managed native WAF engine %s / connector %s / OWASP CRS %s\n", wafBodyEngineVersion, wafBodyConnectorVersion, wafBodyCRSVersion)
	fmt.Fprintf(&out, "SecRuleEngine %s\n", engine)
	out.WriteString("SecRequestBodyAccess On\nSecResponseBodyAccess Off\nSecAuditEngine Off\nSecDebugLog /dev/null\nSecDebugLogLevel 0\nSecXmlExternalEntity Off\nSecUploadKeepFiles Off\nSecUploadFileMode 0600\n")
	fmt.Fprintf(&out, "SecTmpDir %s\nSecRequestBodyLimit %d\nSecRequestBodyNoFilesLimit %d\nSecRequestBodyLimitAction Reject\nSecRequestBodyJsonDepthLimit %d\nSecArgumentsLimit %d\n", temporaryRoot, v.BodyLimitKiB*1024, v.NonFileLimitKiB*1024, v.JSONDepth, v.ArgumentLimit)
	// The pinned CRS setup defines the two phase defaults. Defining them a
	// second time would make the actual native parser reject the configuration.
	out.WriteString("SecPcreMatchLimit 10000\nSecPcreMatchLimitRecursion 10000\n")
	// Processor choice is determined by Content-Type, not request content or
	// arbitrary external filenames. XML external entities remain disabled.
	out.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx ^application/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)" "id:128001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"` + "\n")
	out.WriteString(`SecRule REQUEST_HEADERS:Content-Type "@rx ^(?:application|text)/(?:[a-z0-9.+-]+\+)?xml(?:\s*;|$)" "id:128002,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"` + "\n")
	out.WriteString(`SecRule REQUEST_HEADERS:Content-Encoding "!@rx ^(?:identity)?$" "id:128003,phase:1,t:none,t:lowercase,deny,status:415,log"` + "\n")
	out.WriteString(`SecRule INBOUND_DATA_ERROR "!@eq 0" "id:128005,phase:2,t:none,deny,status:413,log"` + "\n")
	out.WriteString(`SecRule REQBODY_ERROR "!@eq 0" "id:128004,phase:2,t:none,deny,status:400,log"` + "\n")
	out.WriteString(`SecRule MULTIPART_STRICT_ERROR "!@eq 0" "id:128006,phase:2,t:none,deny,status:400,log"` + "\n")
	out.WriteString(`SecRule MULTIPART_UNMATCHED_BOUNDARY "@eq 1" "id:128007,phase:2,t:none,deny,status:400,log"` + "\n")
	fmt.Fprintf(&out, "SecRule &ARGS \"@ge %d\" \"id:128008,phase:2,t:none,deny,status:400,log\"\n", v.ArgumentLimit)
	fmt.Fprintf(&out, "SecAction \"id:128020,phase:1,t:none,pass,nolog,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", v.Paranoia, v.Paranoia, v.Threshold)
	out.WriteString(`SecAction "id:128021,phase:1,t:none,pass,nolog,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"` + "\n")
	fmt.Fprintf(&out, "SecUnicodeMapFile %s/modsecurity-v3.0.17/unicode.mapping 20127\n", sourceRoot)
	fmt.Fprintf(&out, "Include %s/coreruleset-%s/crs-setup.conf.example\nInclude %s/coreruleset-%s/rules/*.conf\n", sourceRoot, wafBodyCRSVersion, sourceRoot, wafBodyCRSVersion)
	return out.String(), nil
}
