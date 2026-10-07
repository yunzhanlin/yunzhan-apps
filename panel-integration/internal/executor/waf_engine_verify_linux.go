//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
)

func nativeWAFService() *Service {
	return New(Config{SitesDir: "/srv/panel/sites", ConfDir: "/etc/panel/sites-enabled", StateDir: "/var/lib/panel-executor", NginxBin: "/usr/sbin/nginx"})
}

func wafBuildRecordContract(record wafEngineBuildRecord) error {
	if record.Format != 1 || !core.ValidID(record.JobID) || record.State != "ready" || record.Error != "" || !record.ABIValidated || record.ProductionUsed || record.Architecture != runtime.GOARCH || record.Engine != wafBodyEngineVersion || record.Connector != wafBodyConnectorVersion || record.CRS != wafBodyCRSVersion || record.Prefix != filepath.Join(wafNativeEngines, record.JobID) {
		return errors.New("WAF 引擎记录未完成、架构不匹配或发布身份异常")
	}
	nginxSource, ok := wafNginxBuildSource(record.NginxVersion)
	if !ok {
		return errors.New("WAF Nginx 构建版本不在固定清单中")
	}
	validBinary := record.NginxBinary == "/usr/sbin/nginx"
	if release, ok := runtimecatalog.Find("nginx-" + record.NginxVersion); ok && record.NginxBinary == release.CLI() {
		validBinary = true
	}
	if !validBinary {
		return errors.New("WAF 引擎记录包含未管理的 Nginx 程序路径")
	}
	for _, digest := range []string{record.NginxSHA, record.ModuleSHA, record.LibrarySHA, record.TreeSHA} {
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || digest != strings.ToLower(digest) {
			return errors.New("WAF 引擎完整摘要缺失或格式异常")
		}
	}
	sources := append(wafEngineSources(), nginxSource)
	if len(record.SourceSHA) != len(sources) || len(record.AssetSHA) != len(wafEngineAssetPins()) {
		return errors.New("WAF 引擎来源或许可资源清单不完整")
	}
	for _, source := range sources {
		if record.SourceSHA[source.Name] != source.SHA256 {
			return errors.New("WAF 原始源码摘要不是本发布审核版本")
		}
	}
	for name, sha := range wafEngineAssetPins() {
		if record.AssetSHA[name] != sha {
			return errors.New("WAF 补丁、许可或变更通知摘要不匹配")
		}
	}
	start, err := time.Parse(time.RFC3339, record.StartedAt)
	if err != nil {
		return errors.New("WAF 构建开始时间无效")
	}
	finish, err := time.Parse(time.RFC3339, record.FinishedAt)
	if err != nil || finish.Before(start) || len(record.Steps) == 0 || len(record.Steps) > 32 {
		return errors.New("WAF 构建结束时间或审计步骤无效")
	}
	return nil
}

func readWAFBuildRecord(id string) (wafEngineBuildRecord, error) {
	var record wafEngineBuildRecord
	if !core.ValidID(id) {
		return record, errors.New("WAF 引擎任务标识无效")
	}
	path := filepath.Join(wafEngineJobs, id+".json")
	if err := ownedRuntimePath(path, false); err != nil {
		return record, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return record, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 || st.Mode().Perm() != 0600 {
		return record, errors.New("WAF 构建记录类型、权限或大小异常")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return record, errors.New("WAF 构建记录所有者或链接数异常")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return record, errors.New("WAF 构建记录读取失败或超限")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return record, errors.New("WAF 构建记录包含额外数据")
	}
	if record.JobID != id {
		return record, errors.New("WAF 构建记录任务身份不匹配")
	}
	return record, nil
}

// This is a read-only prerequisite for site activation, not activation itself.
// Missing/damaged modules, changed rules or a package/runtime Nginx update must
// never be accepted just because an older record once said "ready".
func VerifyWAFEngineBuild(id string) error {
	return verifyWAFEngineBuildContext(context.Background(), id)
}

func verifyWAFEngineBuildContext(parent context.Context, id string) error {
	ctx, cancel := context.WithTimeout(parent, time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	record, err := readWAFBuildRecord(id)
	if err != nil {
		return err
	}
	if err := wafBuildRecordContract(record); err != nil {
		return err
	}
	nginx, err := nativeWAFService().nginxBinary()
	if err != nil || nginx != record.NginxBinary {
		return errors.New("当前 Nginx 选择与模块构建程序不匹配")
	}
	for _, item := range []struct {
		path, sha string
		limit     int64
	}{{nginx, record.NginxSHA, 32 << 20}, {filepath.Join(record.Prefix, "nginx/ngx_http_modsecurity_module.so"), record.ModuleSHA, 32 << 20}, {filepath.Join(record.Prefix, "lib/libmodsecurity.so.3.0.17"), record.LibrarySHA, 64 << 20}} {
		actual, err := wafNativeFileSHA(ctx, item.path, item.limit)
		if err != nil || actual != item.sha {
			return errors.New("WAF 引擎或 Nginx 实际程序缺失、变化或摘要错误")
		}
	}
	actual, err := runtimeTreeSHA(ctx, record.Prefix, record.Prefix)
	if err != nil || actual != record.TreeSHA {
		return errors.New("WAF 完整程序、规则或许可目录发生变化；拒绝启用")
	}
	return ctx.Err()
}
