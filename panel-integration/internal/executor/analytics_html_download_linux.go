//go:build linux

package executor

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

func analyticsHTMLSourceRedirectAllowed(u *url.URL, redirects int) bool {
	if u == nil || redirects > 3 || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return false
	}
	switch u.Host {
	case "nginx.org":
		return strings.HasPrefix(u.Path, "/download/nginx-") && strings.HasSuffix(u.Path, ".tar.gz") && u.RawQuery == ""
	case "github.com":
		return u.Path == "/nginx/njs/releases/download/1.0.1/njs-1.0.1.tar.gz" && u.RawQuery == ""
	case "codeload.github.com":
		return u.Path == "/bellard/quickjs/tar.gz/"+analyticsQuickJSCommit && u.RawQuery == ""
	case "release-assets.githubusercontent.com":
		return strings.HasPrefix(u.Path, "/github-production-release-asset/")
	default:
		return false
	}
}

func downloadAnalyticsHTMLSource(ctx context.Context, source wafEngineSource, destination string) error {
	if !reviewedAnalyticsHTMLSource(source) {
		return errors.New("HTML 引擎源码不在固定发布清单中")
	}
	for attempt := 0; attempt < 3; attempt++ {
		err := downloadPinnedNativeSourceAttempt(ctx, source, destination, analyticsHTMLSourceRedirectAllowed)
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
