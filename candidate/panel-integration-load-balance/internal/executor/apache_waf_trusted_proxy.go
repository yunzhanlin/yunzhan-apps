package executor

import (
	"errors"
	"fmt"
	"local/panel/internal/core"
	"regexp"
	"strconv"
	"strings"
)

// Loading a module does not establish trust. Header and peer directives live in
// the owned WAF include and disappear on explicit disable. The managed global
// module line remains available when sites are subsequently regenerated.
func prepareApacheWAFTrustedProxySource(source string, proxy *core.WAFTrustedProxyConfig, modulePath string) (string, error) {
	if err := core.ValidateApacheWAFTrustedProxy(proxy); err != nil {
		return "", err
	}
	if proxy == nil {
		// Historical omission means default-off, not permission to inherit an
		// unknown RemoteIP directive or external include from the global file.
		proxy = &core.WAFTrustedProxyConfig{Header: "X-Forwarded-For", Recursive: true}
	}
	if !strings.HasPrefix(source, "# managed by panel\n") {
		return "", errors.New("可信代理仅允许修改云栈受管 Apache 配置")
	}
	if regexp.MustCompile(`(?im)^\s*RemoteIP[A-Za-z]+\s`).MatchString(source) {
		return "", errors.New("Apache 配置包含外部 RemoteIP 指令；先明确移除冲突，本应用不覆盖或继承未知信任范围")
	}
	for _, include := range regexp.MustCompile(`(?im)^\s*Include(?:Optional)?\s+[^\n]+`).FindAllString(source, -1) {
		if strings.TrimSpace(include) != strings.TrimSpace(apacheWAFInclude) {
			return "", errors.New("Apache 配置引用了外部 include，无法核实代理信任范围；未覆盖或继续应用")
		}
	}
	wanted := fmt.Sprintf("LoadModule remoteip_module %s", strconv.Quote(modulePath))
	loads := regexp.MustCompile(`(?im)^\s*LoadModule\s+remoteip_module\s+[^\n]+`).FindAllString(source, -1)
	if len(loads) > 1 || len(loads) == 1 && strings.TrimSpace(loads[0]) != wanted {
		return "", errors.New("Apache remoteip 模块加载路径或次数异常；未修改配置")
	}
	if proxy.Enabled && len(loads) == 0 {
		return strings.Replace(source, "# managed by panel\n", "# managed by panel\n"+wanted+"\n", 1), nil
	}
	return source, nil
}
