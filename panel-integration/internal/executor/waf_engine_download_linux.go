//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"local/panel/internal/core"
)

const wafNativeSourceBytes = 32 << 20

var errWAFSourceTransport = errors.New("WAF 官方源码连接中断或暂时不可用")
var errWAFSourceRedirect = errors.New("WAF 源码重定向超出官方来源")

func wafSourceRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var network net.Error
	return errors.Is(err, errWAFSourceTransport) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || (errors.As(err, &network) && network.Timeout())
}

func wafSourceRedirectAllowed(u *url.URL, redirects int) bool {
	if u == nil || redirects > 3 || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "nginx.org":
		return strings.HasPrefix(u.Path, "/download/nginx-") && strings.HasSuffix(u.Path, ".tar.gz") && u.RawQuery == ""
	case "github.com":
		return strings.HasPrefix(u.Path, "/owasp-modsecurity/ModSecurity/releases/download/") || strings.HasPrefix(u.Path, "/owasp-modsecurity/ModSecurity-nginx/releases/download/") || strings.HasPrefix(u.Path, "/coreruleset/coreruleset/releases/download/")
	case "release-assets.githubusercontent.com":
		return strings.HasPrefix(u.Path, "/github-production-release-asset/")
	default:
		return false
	}
}

// No URL, digest, destination, compiler command or TLS option comes from a
// website, downloaded catalog or caller-supplied application setting.
func downloadWAFEngineSource(ctx context.Context, source wafEngineSource, destination string) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := downloadWAFEngineSourceAttempt(ctx, source, destination)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !wafSourceRetryable(err) || attempt == 2 {
			return err
		}
		timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errWAFSourceTransport
}

func downloadWAFEngineSourceAttempt(ctx context.Context, source wafEngineSource, destination string) error {
	if !reviewedWAFEngineSource(source) {
		return errors.New("WAF 源码未在固定发布清单中审核")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ownedRuntimePath(filepath.Dir(destination), true); err != nil {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("源码目标已存在，拒绝覆盖")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Timeout: 8 * time.Minute, Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if !wafSourceRedirectAllowed(r.URL, len(via)) {
			return errWAFSourceRedirect
		}
		return nil
	}}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errWAFSourceRedirect) {
			return errWAFSourceRedirect
		}
		var certificate *tls.CertificateVerificationError
		if errors.As(err, &certificate) {
			return errors.New("WAF 官方源码 HTTPS 证书校验失败，拒绝重试或跳过校验")
		}
		// Do not expose a temporary signed CDN redirect URL in API errors.
		return fmt.Errorf("%w；未执行或发布源码", errWAFSourceTransport)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 408 || resp.StatusCode == 429 || resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			return fmt.Errorf("%w（HTTP %d）", errWAFSourceTransport, resp.StatusCode)
		}
		return fmt.Errorf("WAF 官方源码返回 HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > wafNativeSourceBytes {
		return errors.New("WAF 官方源码包超过 32 MiB")
	}
	return streamVerifiedWAFSource(resp.Body, source.SHA256, destination)
}

// An incomplete/unverified download is retained only as a private .pending
// file. Exclusive link publication cannot replace an existing file/symlink.
func streamVerifiedWAFSource(body io.Reader, want, destination string) (err error) {
	if decoded, e := hex.DecodeString(want); e != nil || len(decoded) != 32 {
		return errors.New("源码固定哈希无效")
	}
	if e := ownedRuntimePath(filepath.Dir(destination), true); e != nil {
		return e
	}
	pending := destination + ".pending-" + core.ID()
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, wafNativeSourceBytes+1))
	if err != nil {
		return err
	}
	if n > wafNativeSourceBytes {
		return errors.New("源码超过 32 MiB，拒绝发布")
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return errors.New("WAF 源码 SHA-256 不匹配，拒绝编译")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	closed = true
	if err = os.Link(pending, destination); err != nil {
		return fmt.Errorf("源码目标发生变化，拒绝覆盖: %w", err)
	}
	// This is only the exclusive private duplicate created above, never a user
	// path selected through the API. The verified target remains recoverable.
	if err = os.Remove(pending); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
