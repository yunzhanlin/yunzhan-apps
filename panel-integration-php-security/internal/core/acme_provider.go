package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang.org/x/crypto/acme"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type ACMEProvider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Directory string `json:"directory"`
	Test      bool   `json:"test"`
	Terms     string `json:"terms,omitempty"`
}

func acmeProviders() []ACMEProvider {
	out := []ACMEProvider{{ID: "letsencrypt", Name: "Let's Encrypt", Directory: acme.LetsEncryptURL}, {ID: "letsencrypt-staging", Name: "Let's Encrypt 测试环境", Directory: "https://acme-staging-v02.api.letsencrypt.org/directory", Test: true}}
	if info, e := os.Lstat("/etc/panel-development-vm"); e == nil && info.Mode().IsRegular() {
		out = append(out, ACMEProvider{ID: "pebble", Name: "本机 Pebble 验收 CA", Directory: "https://localhost:14000/dir", Test: true})
	}
	return out
}
func findACMEProvider(id string) (ACMEProvider, error) {
	for _, p := range acmeProviders() {
		if p.ID == id {
			return p, nil
		}
	}
	return ACMEProvider{}, errors.New("不支持的 CA 或本机测试 CA 未启用")
}

type acmeTransport struct {
	base   http.RoundTripper
	origin *url.URL
}

func (t acmeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.origin.Host || r.URL.User != nil || r.URL.Fragment != "" {
		return nil, errors.New("CA 返回了目录来源之外的资源地址")
	}
	response, e := t.base.RoundTrip(r)
	if e != nil {
		return nil, e
	}
	response.Body = &acmeBoundedBody{ReadCloser: response.Body, remaining: 1024 * 1024}
	return response, nil
}

type acmeBoundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *acmeBoundedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errors.New("CA 响应超过大小限制")
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, e := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, e
}
func acmeHTTPClient(provider ACMEProvider) (*http.Client, error) {
	origin, e := url.Parse(provider.Directory)
	if e != nil || origin.Scheme != "https" || origin.Host == "" {
		return nil, errors.New("CA 目录无效")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if provider.ID == "pebble" {
		if _, e = findACMEProvider(provider.ID); e != nil {
			return nil, e
		}
		p := "/etc/panel/acme/pebble-ca.pem"
		info, e := os.Lstat(p)
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("本地测试 CA 信任文件不可用")
		}
		raw, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("本地测试 CA 格式无效")
		}
		config.RootCAs = roots
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: config, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
	return &http.Client{Timeout: 30 * time.Second, Transport: acmeTransport{base: transport, origin: origin}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("CA 资源不能重定向到其他地址")
	}}, nil
}
func discoverACME(ctx context.Context, p ACMEProvider) (ACMEProvider, error) {
	h, e := acmeHTTPClient(p)
	if e != nil {
		return p, e
	}
	defer h.CloseIdleConnections()
	c := &acme.Client{DirectoryURL: p.Directory, HTTPClient: h}
	dir, e := c.Discover(ctx)
	if e != nil {
		return p, e
	}
	if p.ID != "pebble" {
		u, e := url.Parse(dir.Terms)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return p, errors.New("CA 未返回可确认的 HTTPS 服务条款")
		}
	}
	if len(dir.Terms) > 2048 || strings.ContainsAny(dir.Terms, "\r\n") {
		return p, errors.New("CA 服务条款地址无效")
	}
	p.Terms = dir.Terms
	return p, nil
}

func (t acmeTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
