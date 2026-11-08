package executor

import (
	"errors"
	"strings"
)

func validateNginxPrivateYAJLDynamicTags(output string) error {
	if len(output) == 0 || len(output) > 64<<10 || strings.ContainsAny(output, "\x00\r") || !strings.Contains(output, "Dynamic section") || !strings.Contains(output, "(NEEDED)") || strings.Contains(output, "libyajl.so") || strings.Contains(output, "(RPATH)") || strings.Contains(output, "(RUNPATH)") {
		return errors.New("Nginx 引擎依赖了系统共享 YAJL、可替换路径或动态库验证输出异常")
	}
	return nil
}
