package executor

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
)

type apacheBodyBuildPaths struct {
	Work, Prefix, Assets, Apache string
}

var apacheYAJLCFiles = [...]string{
	"yajl", "yajl_lex", "yajl_parser", "yajl_buf", "yajl_encode",
	"yajl_gen", "yajl_alloc", "yajl_tree", "yajl_version",
}

// CMake's reviewed source list is compiled one object at a time. The private
// patched YAJL is statically linked into the DSO, never installed into /usr,
// selected through system pkg-config, or loaded through a writable RPATH.
func apacheBodyNativeBuildPlan(paths apacheBodyBuildPaths) ([]wafBuildCommand, error) {
	roots := []string{paths.Work, paths.Prefix, paths.Assets, paths.Apache}
	for i, p := range roots {
		if !wafEngineConfigPath(p) {
			return nil, errors.New("Apache 请求体构建路径无效")
		}
		for j := 0; j < i; j++ {
			if p == roots[j] || strings.HasPrefix(p, roots[j]+"/") || strings.HasPrefix(roots[j], p+"/") {
				return nil, errors.New("Apache 源码、发布、资源与运行时目录必须彼此隔离")
			}
		}
	}
	yajl := filepath.Join(paths.Work, "yajl", "yajl-2.1.0")
	mod := filepath.Join(paths.Work, "modsecurity", "modsecurity-v2.9.15")
	plan := []wafBuildCommand{}
	for _, cve := range []string{"2017-16516", "2022-24795", "2023-33460"} {
		plan = append(plan, wafBuildCommand{"应用固定 YAJL CVE 补丁 " + cve, yajl, "/usr/bin/patch", []string{"--batch", "--forward", "--fuzz=0", "-p1", "-i", filepath.Join(paths.Assets, "apache-body-yajl-CVE-"+cve+".patch")}, nil})
	}
	objects := []string{}
	for _, name := range apacheYAJLCFiles {
		object := filepath.Join(paths.Work, name+".o")
		objects = append(objects, object)
		plan = append(plan, wafBuildCommand{"非特权单路编译已修补 JSON 解析器 " + name, yajl, "/usr/bin/cc", []string{"-O2", "-g0", "-fPIC", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=2", "-DYAJL_BUILD", "-I" + filepath.Join(paths.Prefix, "include"), "-c", filepath.Join(yajl, "src", name+".c"), "-o", object}, nil})
	}
	plan = append(plan, wafBuildCommand{"创建私有 JSON 静态依赖，不修改系统库", yajl, "/usr/bin/ar", append([]string{"rcsD", filepath.Join(paths.Prefix, "lib", "libyajl.a")}, objects...), nil})
	for _, patch := range []string{"apache-body-private-yajl.patch", "apache-body-metadata-only.patch", "apache-body-parser-limits.patch", "apache-body-pcre2-no-rpath.patch"} {
		plan = append(plan, wafBuildCommand{"应用已审核 Apache 补丁 " + patch, mod, "/usr/bin/patch", []string{"--batch", "--forward", "--fuzz=0", "-p1", "-i", filepath.Join(paths.Assets, patch)}, nil})
	}
	plan = append(plan,
		// The signed source already contains the matching reviewed generated
		// configure script. Both it and its m4 source are patched together;
		// preserve that generated-file ordering instead of invoking a different
		// (possibly absent) host Autotools toolchain. Content is not changed.
		wafBuildCommand{"保留已审核生成脚本时间顺序，不调用宿主生成器", mod, "/usr/bin/touch", []string{"-r", filepath.Join(mod, "aclocal.m4"), filepath.Join(mod, "build/find_yajl.m4"), filepath.Join(mod, "apache2/Makefile.am")}, nil},
		wafBuildCommand{"非特权配置原生 Apache 请求体引擎", mod, "./configure", []string{"--prefix=" + paths.Prefix, "--with-apxs=" + filepath.Join(paths.Apache, "bin/apxs"), "--with-apr=/usr/bin/apr-1-config", "--with-apu=/usr/bin/apu-1-config", "--with-pcre=no", "--with-pcre2=/usr/bin/pcre2-config", "--with-yajl=" + paths.Prefix, "--with-lua=no", "--with-curl=no", "--with-ssdeep=no", "--disable-mlogc", "--disable-standalone-module", "--disable-alp2", "--disable-docs", "--disable-htaccess-config", "--enable-pcre-match-limit=10000", "--enable-pcre-match-limit-recursion=10000"}, nil},
		wafBuildCommand{"非特权单路编译 Apache 模块，不替换 Apache", mod, "/usr/bin/make", []string{"-j1", "-C", "apache2"}, nil},
	)
	return plan, nil
}

// Re-derive the entire closed plan; accepting a cc executable alone would let
// future callers accidentally introduce arbitrary compiler/source arguments.
func validateApacheBodyBuildCommand(paths apacheBodyBuildPaths, index int, command wafBuildCommand) error {
	plan, err := apacheBodyNativeBuildPlan(paths)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(plan) || !reflect.DeepEqual(plan[index], command) {
		return errors.New("Apache 构建命令不是固定审核计划的对应步骤")
	}
	return nil
}

const apacheBodyYAJLVersionHeader = `#ifndef YAJL_VERSION_H_
#define YAJL_VERSION_H_
#include <yajl/yajl_common.h>
#define YAJL_MAJOR 2
#define YAJL_MINOR 1
#define YAJL_MICRO 0
#define YAJL_VERSION ((YAJL_MAJOR * 10000) + (YAJL_MINOR * 100) + YAJL_MICRO)
#ifdef __cplusplus
extern "C" {
#endif
extern int YAJL_API yajl_version(void);
#ifdef __cplusplus
}
#endif
#endif
`
