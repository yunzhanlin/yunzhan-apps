package executor

import (
	"errors"
	"path/filepath"
	"strings"
)

type wafBuildCommand struct {
	Label       string
	Directory   string
	Program     string
	Arguments   []string
	Environment []string
}

// These are compiler invocations derived exclusively from the signed source
// manifest and owned build paths. No Nginx configure output, app settings,
// catalog text, user snippet, shell interpolation or arbitrary -j is executed.
func wafNativeBuildPlan(work, prefix, assets, nginxVersion string) ([]wafBuildCommand, error) {
	if _, ok := wafNginxBuildSource(nginxVersion); !ok {
		return nil, errors.New("当前 Nginx 版本没有审核过的模块构建源码")
	}
	for _, p := range []string{work, prefix, assets} {
		if !wafEngineConfigPath(p) {
			return nil, errors.New("WAF 构建路径不允许配置或命令注入")
		}
	}
	if work == prefix || work == assets || prefix == assets || strings.HasPrefix(work, prefix+"/") || strings.HasPrefix(prefix, work+"/") {
		return nil, errors.New("WAF 编译工作区与发布目录必须分开")
	}
	engine := filepath.Join(work, "modsecurity", "modsecurity-v3.0.17")
	connector := filepath.Join(work, "connector", "ModSecurity-nginx-v1.0.4")
	nginx := filepath.Join(work, "nginx", "nginx-"+nginxVersion)
	return []wafBuildCommand{
		{"验证并应用引擎隐私及请求体限额补丁", engine, "/usr/bin/patch", []string{"--batch", "--forward", "--fuzz=0", "-p1", "-i", filepath.Join(assets, "modsecurity-metadata-only-logs.patch")}, nil},
		{"验证并应用连接器独立元数据日志补丁", connector, "/usr/bin/patch", []string{"--batch", "--forward", "--fuzz=0", "-p1", "-i", filepath.Join(assets, "modsecurity-nginx-private-context.patch")}, nil},
		{"验证并应用元数据日志并发锁及 32 MiB 硬上限补丁", connector, "/usr/bin/patch", []string{"--batch", "--forward", "--fuzz=0", "-p1", "-i", filepath.Join(assets, "modsecurity-nginx-bounded-events.patch")}, nil},
		{"非特权配置请求体引擎", engine, "./configure", []string{"--prefix=" + prefix, "--disable-static", "--disable-examples", "--disable-doxygen-doc", "--disable-debug-logs", "--with-yajl=yes", "--with-lua=no", "--with-lmdb=no", "--with-geoip=no", "--with-ssdeep=no", "--with-curl=no"}, nil},
		{"非特权编译请求体引擎（最多 2 核）", engine, "/usr/bin/make", []string{"-j2"}, nil},
		{"将引擎写入独立待验证目录，不改系统程序", engine, "/usr/bin/make", []string{"install"}, nil},
		{"匹配精确 Nginx 源码生成兼容动态模块", nginx, "./configure", []string{"--with-compat", "--with-debug", "--with-threads", "--with-http_ssl_module", "--with-http_v2_module", "--with-http_realip_module", "--with-http_stub_status_module", "--add-dynamic-module=" + connector}, []string{"MODSECURITY_INC=" + filepath.Join(prefix, "include"), "MODSECURITY_LIB=" + filepath.Join(prefix, "lib")}},
		{"非特权编译 Nginx 动态模块，不安装或替换 Nginx", nginx, "/usr/bin/make", []string{"-j2", "modules"}, nil},
	}, nil
}

func validateWAFBuildCommand(command wafBuildCommand) error {
	if !wafEngineConfigPath(command.Directory) {
		return errors.New("WAF 命令工作目录无效")
	}
	switch command.Program {
	case "./configure", "/usr/bin/patch", "/usr/bin/make":
	default:
		return errors.New("WAF 构建命令不在固定清单中")
	}
	if len(command.Arguments) > 16 || len(command.Environment) > 2 {
		return errors.New("WAF 构建命令参数超限")
	}
	for _, value := range command.Arguments {
		if len(value) > 1024 || strings.ContainsAny(value, "\n\r\x00") {
			return errors.New("WAF 构建命令参数包含非法字符")
		}
	}
	for _, value := range command.Environment {
		name, path, ok := strings.Cut(value, "=")
		if !ok || (name != "MODSECURITY_INC" && name != "MODSECURITY_LIB") || !wafEngineConfigPath(path) {
			return errors.New("WAF 构建环境不允许覆盖命令、用户或系统环境")
		}
	}
	return nil
}
