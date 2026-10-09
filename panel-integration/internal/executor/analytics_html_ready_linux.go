//go:build linux

package executor

import (
	"context"
	"errors"
	"io"
	"local/panel/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type analyticsHTMLEngineIdentity struct {
	Format       int    `json:"format"`
	JobID        string `json:"job_id"`
	State        string `json:"state"`
	Architecture string `json:"architecture"`
	Prefix       string `json:"prefix"`
	NginxBinary  string `json:"nginx_binary"`
	NginxSHA     string `json:"nginx_sha256"`
	ModuleSHA    string `json:"module_sha256"`
	ProgramSHA   string `json:"program_sha256"`
	TreeSHA      string `json:"tree_sha256"`
}

func (s *Service) requireAnalyticsHTMLReady(ctx context.Context) error {
	var identity analyticsHTMLEngineIdentity
	active := s.systemPath("/etc/panel/analytics-html/active.json")
	if err := ownedRuntimePath(active, false); err != nil {
		return errors.New("HTML 引擎启用记录缺失或路径所有权异常")
	}
	if err := readAnalyticsHTMLPrivateJSON(active, 64<<10, &identity); err != nil {
		return errors.New("缺少已启用、可验证的独立 QuickJS 引擎记录")
	}
	wantPrefix := filepath.Join(appNativeRoot, "website-analytics/html-engines", identity.JobID)
	if identity.Format != 1 || !core.ValidID(identity.JobID) || identity.State != "active" || identity.Architecture != runtime.GOARCH || identity.Prefix != wantPrefix || identity.ProgramSHA != analyticsHTMLProgramSHA {
		return errors.New("HTML 引擎记录身份不匹配")
	}
	nginx, err := s.nginxBinary()
	if err != nil || identity.NginxBinary != nginx {
		return errors.New("实际 Nginx 已改变，拒绝加载旧 ABI 引擎")
	}
	for _, item := range []struct {
		path, sha string
		limit     int64
	}{
		{nginx, identity.NginxSHA, 32 << 20},
		{s.systemPath(filepath.Join(wantPrefix, "ngx_http_js_module.so")), identity.ModuleSHA, 32 << 20},
		{s.systemPath(analyticsHTMLProgramPath()), identity.ProgramSHA, 1 << 20},
	} {
		if sha, err := analyticsHTMLFileSHA(ctx, item.path, item.limit); err != nil || sha != item.sha {
			return errors.New("HTML 引擎或实际 Nginx 程序摘要不匹配")
		}
	}
	prefix := s.systemPath(wantPrefix)
	if sha, err := runtimeTreeSHA(ctx, prefix, prefix); err != nil || sha != identity.TreeSHA {
		return errors.New("独立 HTML 引擎程序树摘要不匹配")
	}
	// Do not parse a capped nginx -T dump: large panels can legitimately emit
	// much more than the command output limit. Read only the bounded owned main
	// file and ask the actual selected binary to validate its complete includes.
	if err := ownedRuntimePath(s.Config.NginxConf, false); err != nil {
		return errors.New("HTML 引擎主配置路径、权限或所有权异常")
	}
	f, err := os.OpenFile(s.Config.NginxConf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > 1<<20 {
		return errors.New("HTML 引擎主配置读取失败或超过 1 MiB")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return errors.New("HTML 引擎主配置具有异常共享链接")
	}
	main, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(main) > 1<<20 {
		return errors.New("HTML 引擎主配置读取失败或超限")
	}
	if err := verifyAnalyticsHTMLLoader(string(main), identity.JobID); err != nil {
		return err
	}
	if strings.Count(string(main), analyticsHTMLHealthBegin+analyticsHTMLHealthInclude+analyticsHTMLHealthEnd) != 1 {
		return errors.New("HTML 引擎缺少唯一受管工作进程检查挂载")
	}
	if _, err := renderAnalyticsHTMLHealthMount(string(main), true); err != nil {
		return err
	}
	expected, err := analyticsHTMLHealthConfiguration(identity.JobID)
	if err != nil {
		return err
	}
	healthPath := s.systemPath("/etc/panel/analytics-html/health.conf")
	if err := ownedRuntimePath(healthPath, false); err != nil {
		return err
	}
	health, err := apacheWAFReadStableFile(healthPath, 64<<10)
	if err != nil || string(health) != expected {
		return errors.New("HTML 引擎工作进程检查配置与身份不一致")
	}
	if _, err := s.moduleCommand(ctx, 30*time.Second, nginx, "-t", "-c", s.Config.NginxConf); err != nil {
		return errors.New("实际 Nginx 完整配置未通过 HTML 引擎语法和 ABI 验证")
	}
	return s.probeAnalyticsHTMLLoaded(ctx, identity)
}
