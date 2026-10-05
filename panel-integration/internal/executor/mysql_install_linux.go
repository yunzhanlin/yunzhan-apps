//go:build linux

package executor

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

func hashArchive(path, digest string) bool {
	if e := ordinary(path, false); e != nil {
		return false
	}
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 1536*1024*1024+1))
	return e == nil && n <= 1536*1024*1024 && hex.EncodeToString(h.Sum(nil)) == digest
}
func mysqlDownload(ctx context.Context, r runtimecatalog.Release, dst string) error {
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 3 || req.URL.Scheme != "https" || (req.URL.Host != "cdn.mysql.com" && req.URL.Host != "dev.mysql.com") {
			return errors.New("MySQL 下载重定向超出官方来源")
		}
		return nil
	}}
	req, e := http.NewRequestWithContext(ctx, "GET", r.URL, nil)
	if e != nil {
		return e
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, e := client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	parts := strings.Split(resp.Header.Get("Content-Range"), "/")
	if resp.StatusCode != 206 || len(parts) != 2 {
		return errors.New("官方服务器暂不支持分段下载，请稍后重试")
	}
	size, e := strconv.ParseInt(parts[1], 10, 64)
	if e != nil || size <= 0 || size > 1536*1024*1024 {
		return errors.New("MySQL 包大小超出限制")
	}
	url := resp.Request.URL.String()
	resp.Body.Close()
	f, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = f.Truncate(size); e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch := make(chan int64)
	var wg sync.WaitGroup
	var first error
	var mu sync.Mutex
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for lo := range ch {
				hi := lo + 4*1024*1024 - 1
				if hi >= size {
					hi = size - 1
				}
				var er error
				for attempt := 0; attempt < 3; attempt++ {
					er = func() error {
						q, e := http.NewRequestWithContext(ctx, "GET", url, nil)
						if e != nil {
							return e
						}
						q.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", lo, hi))
						res, e := client.Do(q)
						if e != nil {
							return e
						}
						defer res.Body.Close()
						if res.StatusCode != 206 || res.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", lo, hi, size) {
							return errors.New("下载分段范围不匹配")
						}
						b, e := io.ReadAll(io.LimitReader(res.Body, hi-lo+2))
						if e != nil {
							return e
						}
						if int64(len(b)) != hi-lo+1 {
							return errors.New("下载分段长度不匹配")
						}
						_, e = f.WriteAt(b, lo)
						return e
					}()
					if er == nil {
						break
					}
					if ctx.Err() != nil {
						break
					}
				}
				if er != nil {
					mu.Lock()
					if first == nil {
						first = er
					}
					mu.Unlock()
					cancel()
					return
				}
			}
		}()
	}
send:
	for lo := int64(0); lo < size; lo += 4 * 1024 * 1024 {
		select {
		case <-ctx.Done():
			break send
		case ch <- lo:
		}
	}
	close(ch)
	wg.Wait()
	if first != nil {
		return first
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if !hashArchive(dst, r.SHA256) {
		return errors.New("MySQL SHA-256 不匹配，拒绝安装")
	}
	return nil
}
func installMySQL(ctx context.Context, r runtimecatalog.Release, id string, add func(string) error) error {
	base := filepath.Join("/var/cache/panel-build", id)
	if e := os.MkdirAll(base, 0755); e != nil {
		return e
	}
	filename := filepath.Base(r.URL)
	archive := filepath.Join("/var/cache/panel-source-verification/mysql", filename)
	if !hashArchive(archive, r.SHA256) {
		archive = filepath.Join(base, "mysql.tar.xz")
		if !hashArchive(archive, r.SHA256) {
			if e := add("按当前 CPU 架构下载官方 MySQL 包，6 个受限分段连接"); e != nil {
				return e
			}
			if e := mysqlDownload(ctx, r, archive); e != nil {
				return e
			}
		}
	}
	if e := add("官方 MySQL 二进制包 SHA-256 校验通过；发布目录已核对官方 PGP 签名"); e != nil {
		return e
	}
	if _, e := os.Stat(r.Prefix()); e == nil {
		return errors.New("目标版本目录存在但清单不完整，拒绝覆盖")
	}
	parent := filepath.Dir(r.Prefix())
	if e := os.MkdirAll(parent, 0755); e != nil {
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
	cmd := exec.CommandContext(ctx, "/usr/bin/xz", "--decompress", "--stdout", "--", archive)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return e
	}
	top := strings.TrimSuffix(filename, ".tar.xz")
	e = extractMySQLTar(tar.NewReader(pipe), temp, top)
	if e != nil {
		_ = cmd.Process.Kill()
	}
	we := cmd.Wait()
	if e != nil {
		return e
	}
	if we != nil {
		return we
	}
	if e = add("运行文件已解包至暂存目录；未安装测试集和调试服务程序"); e != nil {
		return e
	}
	// Keep the distro's compatible AIO ABI private to this runtime, so a
	// Debian 12 to 13 host upgrade cannot remove the library it was built with.
	triplet := "aarch64-linux-gnu"
	if runtime.GOARCH == "amd64" {
		triplet = "x86_64-linux-gnu"
	}
	var libaio string
	for _, name := range []string{"libaio.so.1t64", "libaio.so.1"} {
		candidate := filepath.Join("/usr/lib", triplet, name)
		if _, statErr := os.Stat(candidate); statErr == nil {
			libaio = candidate
			break
		}
	}
	if libaio == "" {
		return errors.New("未找到系统 libaio 共享库")
	}
	if e = os.MkdirAll(temp+"/lib/private", 0755); e != nil {
		return e
	}
	data, er := os.ReadFile(libaio)
	if er != nil {
		return er
	}
	if e = os.WriteFile(temp+"/lib/private/libaio.so.1", data, 0644); e != nil {
		return e
	}
	for _, binary := range []string{"mysqld", "mysql", "mysqldump"} {
		c := exec.CommandContext(ctx, temp+"/bin/"+binary, "--no-defaults", "--version")
		c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LD_LIBRARY_PATH=" + temp + "/lib/private:" + temp + "/lib"}
		out, er := c.CombinedOutput()
		if er != nil || !strings.Contains(string(out), r.Version) {
			return fmt.Errorf("MySQL %s 版本/共享库核验失败: %s", binary, string(out))
		}
	}
	manifest := RuntimeManifest{Release: r, Architecture: runtime.GOARCH, InstalledAt: core.Now(), Extensions: []string{}, Configure: []string{"official-generic-binary", "private-debian-libaio-compat", "excluded-debug-and-test-programs"}}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if e = atomicWrite(temp+"/.panel-runtime.json", b, 0644); e != nil {
		return e
	}
	if e = os.Rename(temp, r.Prefix()); e != nil {
		return e
	}
	return add("MySQL 精确版本与客户端验证通过，已提交独立安装目录；尚未创建数据实例")
}
func mysqlArchiveKeep(rel string) bool {
	first := strings.Split(rel, "/")[0]
	if first == "bin" {
		return rel == "bin" || rel == "bin/mysql" || rel == "bin/mysqld" || rel == "bin/mysqldump" || rel == "bin/mysqladmin" || rel == "bin/mysqlcheck"
	}
	return (first == "lib" && !strings.Contains(rel, "/debug/") && !strings.HasSuffix(rel, ".debug")) || first == "share" || rel == "LICENSE" || rel == "README"
}
func extractMySQLTar(tr *tar.Reader, dest, top string) error {
	return extractDatabaseTar(tr, dest, top, mysqlArchiveKeep, "MySQL")
}
func extractDatabaseTar(tr *tar.Reader, dest, top string, keep func(string) bool, label string) error {
	type link struct{ rel, target string }
	links := []link{}
	seen := map[string]byte{}
	var total int64
	count := 0
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		count++
		if h.Size < 0 || h.Size > 8*1024*1024*1024-total || count > 100000 {
			return errors.New(label + " 归档超过解包限制")
		}
		total += h.Size
		clean := filepath.Clean(h.Name)
		if !filepath.IsLocal(clean) || strings.Split(clean, "/")[0] != top {
			return errors.New(label + " 归档路径越界或根目录不匹配")
		}
		rel := strings.TrimPrefix(clean, top)
		rel = strings.TrimPrefix(rel, "/")
		if rel == "" {
			continue
		}
		if !keep(rel) {
			continue
		}
		if previous, ok := seen[rel]; ok {
			if previous == tar.TypeDir && h.Typeflag == tar.TypeDir {
				continue
			}
			return errors.New(label + " 归档重复文件: " + rel)
		}
		seen[rel] = h.Typeflag
		target := filepath.Join(dest, rel)
		switch h.Typeflag {
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		case tar.TypeDir:
			if e = os.MkdirAll(target, 0755); e != nil {
				return e
			}
		case tar.TypeReg, tar.TypeRegA:
			if h.Size > 1024*1024*1024 {
				return errors.New(label + " 单文件超过 1 GiB")
			}
			if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
				return e
			}
			mode := os.FileMode(0644)
			if h.Mode&0111 != 0 {
				mode = 0755
			}
			f, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if e != nil {
				return e
			}
			_, e = io.CopyN(f, tr, h.Size)
			ce := f.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		case tar.TypeSymlink, tar.TypeLink:
			linkPath := filepath.Clean(filepath.Join(filepath.Dir(rel), h.Linkname))
			if h.Typeflag == tar.TypeLink {
				if !strings.HasPrefix(h.Linkname, top+"/") {
					return errors.New(label + " 硬链接越界")
				}
				linkPath = strings.TrimPrefix(filepath.Clean(h.Linkname), top+"/")
			}
			if filepath.IsAbs(h.Linkname) || !filepath.IsLocal(linkPath) {
				return errors.New(label + " 链接越界")
			}
			links = append(links, link{rel, linkPath})
		default:
			return errors.New(label + " 归档包含特殊文件")
		}
	}
	// Materialize validated internal links after extraction. No link is ever
	// present while archive paths are being created, preventing parent traversal.
	for len(links) > 0 {
		next := []link{}
		progress := false
		for _, l := range links {
			src := filepath.Join(dest, l.target)
			if _, e := os.Stat(src); errors.Is(e, os.ErrNotExist) {
				next = append(next, l)
				continue
			}
			if e := ordinary(src, false); e != nil {
				return e
			}
			if e := os.MkdirAll(filepath.Dir(filepath.Join(dest, l.rel)), 0755); e != nil {
				return e
			}
			if e := os.Link(src, filepath.Join(dest, l.rel)); e != nil {
				return e
			}
			progress = true
		}
		if !progress {
			return errors.New(label + " 归档含缺失或循环链接")
		}
		links = next
	}
	return nil
}
