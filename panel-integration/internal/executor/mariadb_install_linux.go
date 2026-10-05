//go:build linux

package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/panel/internal/core"
	"local/panel/internal/runtimecatalog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func mariadbDownload(ctx context.Context, r runtimecatalog.Release, dst string) error {
	client := &http.Client{Timeout: 20 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 1 || req.URL.Scheme != "https" || req.URL.Host != "archive.mariadb.org" {
			return errors.New("MariaDB 下载重定向超出官方归档来源")
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", r.URL, nil)
	if e != nil {
		return e
	}
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MariaDB 官方归档 HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength <= 0 || resp.ContentLength > 1024*1024*1024 {
		return errors.New("MariaDB 包大小超出限制")
	}
	f, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, 1024*1024*1024+1))
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if n != resp.ContentLength {
		return errors.New("MariaDB 包下载长度不匹配")
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !hashArchive(dst, r.SHA256) {
		return errors.New("MariaDB SHA-256 不匹配，拒绝安装")
	}
	return nil
}

func mariadbArchiveKeep(rel string) bool {
	first := strings.Split(rel, "/")[0]
	if first == "bin" {
		return true
	}
	return first == "lib" || first == "lib64" || first == "share" || first == "scripts" || first == "support-files" || first == "include" || rel == "README.md" || rel == "README" || strings.HasPrefix(rel, "LICENSE")
}

func installMariaDB(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) error {
	if runtime.GOARCH != "amd64" {
		return errors.New("MariaDB 官方通用二进制当前仅提供 x86_64")
	}
	base := filepath.Join("/var/cache/panel-build", id)
	if e := os.MkdirAll(base, 0755); e != nil {
		return e
	}
	archive := filepath.Join(base, "mariadb.tar.gz")
	if !hashArchive(archive, r.SHA256) {
		if e := add("从 MariaDB Foundation 官方归档下载 x86_64 精确版本"); e != nil {
			return e
		}
		if e := mariadbDownload(ctx, r, archive); e != nil {
			return e
		}
	}
	if e := add("官方 MariaDB 二进制包 SHA-256 校验通过"); e != nil {
		return e
	}
	if _, e := os.Stat(r.Prefix()); e == nil {
		return errors.New("目标版本目录存在但清单不完整，拒绝覆盖")
	}
	if e := os.MkdirAll(filepath.Dir(r.Prefix()), 0755); e != nil {
		return e
	}
	temp := r.Prefix() + ".pending-" + id
	if e := os.RemoveAll(temp); e != nil {
		return e
	}
	if e := os.Mkdir(temp, 0755); e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	top := strings.TrimSuffix(filepath.Base(r.URL), ".tar.gz")
	if e = extractDatabaseTar(tar.NewReader(gz), temp, top, mariadbArchiveKeep, "MariaDB"); e != nil {
		return e
	}
	if e = add("运行文件已安全解包到独立暂存目录"); e != nil {
		return e
	}
	for _, binary := range []string{"mariadbd", "mariadb", "mariadb-dump", "mariadb-admin", "../scripts/mariadb-install-db"} {
		path := temp + "/bin/" + binary
		if e = ordinary(path, false); e != nil {
			return fmt.Errorf("MariaDB 缺少 %s: %w", binary, e)
		}
		if strings.Contains(binary, "install-db") {
			continue
		}
		c := exec.CommandContext(ctx, path, "--no-defaults", "--version")
		c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LD_LIBRARY_PATH=" + temp + "/lib:" + temp + "/lib64"}
		out, er := c.CombinedOutput()
		if er != nil || !strings.Contains(string(out), r.Version) {
			return fmt.Errorf("MariaDB %s 版本/共享库核验失败: %s", binary, string(out))
		}
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{}, Configure: []string{"official-systemd-generic-binary", "x86_64-only", "sha256-pinned"}}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if e = atomicWrite(temp+"/.panel-runtime.json", b, 0644); e != nil {
		return e
	}
	if e = os.Rename(temp, r.Prefix()); e != nil {
		return e
	}
	return add("MariaDB " + r.Version + " 客户端、服务端与初始化工具核验通过；已提交独立安装目录")
}
