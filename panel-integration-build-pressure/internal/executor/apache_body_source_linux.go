//go:build linux

package executor

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

func apacheBodySourceRedirectAllowed(u *url.URL, redirects int) bool {
	if u == nil || redirects > 3 || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "deb.debian.org":
		return u.Path == "/debian/pool/main/y/yajl/yajl_2.1.0.orig.tar.gz" && u.RawQuery == ""
	case "github.com":
		return u.Path == "/owasp-modsecurity/ModSecurity/releases/download/v2.9.15/modsecurity-v2.9.15.tar.gz" && u.RawQuery == ""
	case "release-assets.githubusercontent.com":
		return strings.HasPrefix(u.Path, "/github-production-release-asset/")
	}
	return false
}

func downloadApacheBodySource(ctx context.Context, source wafEngineSource, destination string) error {
	if !reviewedApacheBodySource(source) {
		return errors.New("Apache 请求体源码未在固定发布清单中审核")
	}
	for attempt := 0; attempt < 3; attempt++ {
		err := downloadPinnedNativeSourceAttempt(ctx, source, destination, apacheBodySourceRedirectAllowed)
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

func extractApacheBodySource(ctx context.Context, source wafEngineSource, archive, destination string) error {
	if !reviewedApacheBodySource(source) {
		return errors.New("Apache 请求体源码未审核，不能解包")
	}
	prefix := "modsecurity-v2.9.15"
	if source.Name == "apache-yajl" {
		prefix = "yajl-2.1.0"
		// Debian's SHA-pinned orig archive is a Git export with exactly this
		// global comment. Do not accept arbitrary PAX path/size/link metadata
		// or weaken the existing strict ModSecurity/Nginx extraction policy.
		return extractPinnedSourceArchive(ctx, archive, destination, prefix, source.SHA256, "a0ecdde0c042b9256170f2f8890dd9451a4240aa")
	}
	return extractPinnedWAFSource(ctx, archive, destination, prefix, source.SHA256)
}
