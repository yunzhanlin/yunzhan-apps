//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

const analyticsQuickJSCommit = "535a7c250ff4a577ec36c3e103daab6dadeea650"
const analyticsQuickJSSHA = "23ceaa703c8e88716f33720f893221b65faa3ac6375b8a1eb7516af4b5d5f5da"
const analyticsNJSSHA = "8bb0eb931a934da5d2efc87032f60072242145760a77f2396656930bb60ad2c7"
const analyticsNJSCommit = "1b648f8805596c95368f8fa428a5c38c5d279857"

// This is an isolated program builder, not a module activator. Callers must
// supply a dedicated bounded service and the global runtime-build lock. No
// settings/catalog/HTTP input can choose source versions, flags or programs.
func buildAnalyticsHTMLModule(ctx context.Context, s *Service, archives, work, prefix, version, nginx string, step func(string) error) (err error) {
	source, ok := wafNginxBuildSource(version)
	if !ok || version == "1.18.0" {
		return errors.New("实际 Nginx 缺少已审核的精确版本源码")
	}
	for _, path := range []string{archives, work, prefix, nginx} {
		if !wafEngineConfigPath(path) {
			return errors.New("HTML 引擎构建路径无效")
		}
	}
	if work == prefix || filepath.Dir(work) != filepath.Dir(prefix) {
		return errors.New("HTML 引擎必须使用同一私有父目录下分开的新工作区与程序目录")
	}
	if err := ownedRuntimePath(archives, true); err != nil {
		return err
	}
	if err := ownedRuntimePath(filepath.Dir(work), true); err != nil {
		return err
	}
	if err := os.Mkdir(work, 0755); err != nil {
		return err
	}
	if err := os.Mkdir(prefix, 0755); err != nil {
		return err
	}
	buildUser, err := user.Lookup("panel-build")
	if err != nil {
		return errors.New("缺少非特权 panel-build 构建用户")
	}
	uid, uidErr := strconv.Atoi(buildUser.Uid)
	gid, gidErr := strconv.Atoi(buildUser.Gid)
	if uidErr != nil || gidErr != nil || uid <= 0 || gid <= 0 {
		return errors.New("HTML 引擎构建用户不能为 root")
	}
	defer func() {
		// Collect compiler processes before revoking write authority. Never
		// delete failed source/program trees or silently reuse an engine.
		err = errors.Join(err, sealWAFNativeTree(work, uid), sealWAFNativeTree(prefix, uid))
	}()
	inputs := []struct{ name, file, directory, top, sha, commit string }{
		{"njs", "njs-1.0.1.tar.gz", "njs", "njs-1.0.1", analyticsNJSSHA, analyticsNJSCommit},
		{"quickjs", "quickjs-" + analyticsQuickJSCommit + ".tar.gz", "quickjs", "quickjs-" + analyticsQuickJSCommit, analyticsQuickJSSHA, analyticsQuickJSCommit},
		{"nginx", "nginx-" + version + ".tar.gz", "nginx", "nginx-" + version, source.SHA256, ""},
	}
	licenses := map[string][]byte{}
	for _, input := range inputs {
		if err := step("固定摘要预检与私有解包：" + input.name); err != nil {
			return err
		}
		destination := filepath.Join(work, input.directory)
		if err := extractPinnedSourceArchive(ctx, filepath.Join(archives, input.file), destination, input.top, input.sha, input.commit); err != nil {
			return err
		}
		license := filepath.Join(destination, input.top, "LICENSE")
		if err := ownedRuntimePath(license, false); err != nil {
			return err
		}
		data, err := os.ReadFile(license)
		if err != nil || len(data) == 0 || len(data) > 32768 {
			return errors.New("引擎源许可缺失或超过限额")
		}
		licenses[input.name+"-LICENSE"] = data
	}
	// nginx regenerates a deleted Last-Modified header from its parsed time
	// unless the pinned QuickJS handler also clears that time. Preserve the
	// patch provenance alongside the immutable program and complete licenses.
	patchedPath := filepath.Join(work, "njs/njs-1.0.1/nginx/ngx_http_js_module.c")
	if err := ownedRuntimePath(patchedPath, false); err != nil {
		return err
	}
	original, err := os.ReadFile(patchedPath)
	if err != nil || len(original) > 2<<20 {
		return errors.New("QuickJS 固定补丁目标不可读取或超过限额")
	}
	patched, err := patchAnalyticsNJSHeaders(original)
	if err != nil {
		return err
	}
	if err := atomicWrite(patchedPath, patched, 0644); err != nil {
		return err
	}
	licenses["yunzhan-njs-validator-patch.txt"] = []byte("njs 1.0.1 QuickJS Last-Modified deletion fix (Yunzhan).\nOriginal ngx_http_js_module.c SHA-256: " + analyticsNJSHeaderSourceSHA + "\nExact replacement, deletion only:\n" + analyticsNJSHeaderAfter)
	if _, err := s.moduleCommand(ctx, time.Minute, "/usr/bin/chown", "-R", "-h", "-P", "panel-build:panel-build", work); err != nil {
		return err
	}
	for _, input := range inputs {
		if err := os.Chmod(filepath.Join(work, input.directory), 0755); err != nil {
			return err
		}
	}
	quickjs := filepath.Join(work, "quickjs", "quickjs-"+analyticsQuickJSCommit)
	nginxSource := filepath.Join(work, "nginx", "nginx-"+version)
	plan := []wafBuildCommand{
		{"单路非特权编译固定 QuickJS 静态库", quickjs, "/usr/bin/make", []string{"-j1", "libquickjs.a"}, []string{"CFLAGS=-O2 -g0 -fPIC"}},
		{"匹配实际 Nginx 源码配置独立 QuickJS 动态模块", nginxSource, "./configure", []string{"--with-compat", "--with-debug", "--with-threads", "--with-http_ssl_module", "--with-http_v2_module", "--with-http_realip_module", "--with-http_stub_status_module", "--add-dynamic-module=" + filepath.Join(work, "njs/njs-1.0.1/nginx"), "--with-cc-opt=-I" + quickjs, "--with-ld-opt=-L" + quickjs}, []string{"NJS_LIBXSLT=NO"}},
		{"单路非特权编译动态模块，不替换或安装 Nginx", nginxSource, "/usr/bin/make", []string{"-j1", "modules"}, nil},
	}
	for _, command := range plan {
		if err := step(command.Label); err != nil {
			return err
		}
		if err := runWAFNativeBuildCommand(ctx, command, filepath.Join(filepath.Dir(work), "build.log"), work); err != nil {
			return err
		}
	}
	module := filepath.Join(nginxSource, "objs/ngx_http_js_module.so")
	if err := copyWAFNativeFile(ctx, module, filepath.Join(prefix, "ngx_http_js_module.so"), 32<<20, uid); err != nil {
		return err
	}
	program, err := verifiedAnalyticsHTMLProgram()
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(prefix, "analytics-html.js"), program, 0644); err != nil {
		return err
	}
	for _, name := range []string{"source.json", "parse5-LICENSE", "entities-LICENSE"} {
		data, err := analyticsHTMLAssets.ReadFile("analytics_html_vendor/" + name)
		if err != nil {
			return err
		}
		licenses[name] = data
	}
	for name, data := range licenses {
		if err := atomicWrite(filepath.Join(prefix, name), data, 0644); err != nil {
			return err
		}
	}
	probe := filepath.Join(filepath.Dir(work), "abi-probe")
	if err := os.Mkdir(probe, 0755); err != nil {
		return err
	}
	// Every temp directory and the early error logger must be private too:
	// distribution defaults can otherwise create/chown /var/lib/nginx paths
	// even for nginx -t. No global configuration or cache may be touched.
	tempConfig := ""
	for _, kind := range []string{"client_body", "proxy", "fastcgi", "uwsgi", "scgi"} {
		tempConfig += fmt.Sprintf("%s_temp_path %s;\n", kind, filepath.Join(probe, kind+"-tmp"))
	}
	conf := fmt.Sprintf("load_module %s;\nuser panel-build;\npid %s;\nerror_log stderr warn;\nevents { worker_connections 16; }\nhttp { %s access_log off; server { listen 127.0.0.1:1; js_engine qjs; js_import analytics_html from %s; location / { js_header_filter analytics_html.header; js_body_filter analytics_html.body buffer_type=buffer; return 200 '<head></head>'; } } }\n", filepath.Join(prefix, "ngx_http_js_module.so"), filepath.Join(probe, "nginx.pid"), tempConfig, filepath.Join(prefix, "analytics-html.js"))
	confPath := filepath.Join(probe, "nginx.conf")
	if err := atomicWrite(confPath, []byte(conf), 0644); err != nil {
		return err
	}
	if err := step("实际 Nginx 独立 -t 验证模块 ABI、QuickJS 与完整固定解析器；不重载任何现有服务"); err != nil {
		return err
	}
	_, err = s.moduleCommand(ctx, 30*time.Second, nginx, "-e", "stderr", "-t", "-p", probe+"/", "-c", confPath)
	return err
}
