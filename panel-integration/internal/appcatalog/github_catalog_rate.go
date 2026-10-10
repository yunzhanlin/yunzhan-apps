package appcatalog

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// This is retry evidence, never signing authority. No upstream error body,
// arbitrary URL, credential, or unbounded header is reflected to the panel.
type githubCatalogRetryError struct {
	until        time.Time
	checkedAt    time.Time
	status       int
	rateLimited  bool
	primaryQuota bool
	transport    string
}

func (e *githubCatalogRetryError) Error() string {
	reason := "GitHub 暂时拒绝请求"
	if e.transport == "git-smart-http" {
		reason = "GitHub Git 引用检查未完成"
	}
	if e.rateLimited {
		reason = "GitHub 限流"
	}
	if e.status == 0 {
		return fmt.Sprintf("%s，暂缓请求至 %s；尚未确认仓库最新版本", reason, e.until.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("%s（HTTP %d），暂缓请求至 %s；尚未确认仓库最新版本", reason, e.status, e.until.UTC().Format(time.RFC3339))
}
func githubCatalogRetry(response *http.Response, now time.Time) *githubCatalogRetryError {
	result := &githubCatalogRetryError{until: now.Add(time.Minute), checkedAt: now, status: response.StatusCode, rateLimited: response.StatusCode == http.StatusTooManyRequests}
	one := func(name string) string {
		values := response.Header.Values(name)
		if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 20 {
			return ""
		}
		for _, r := range values[0] {
			if r < '0' || r > '9' {
				return ""
			}
		}
		return values[0]
	}
	update := func(candidate time.Time) {
		if candidate.After(result.until) && !candidate.After(now.Add(24*time.Hour)) {
			result.until = candidate
		}
	}
	if seconds, err := strconv.ParseInt(one("Retry-After"), 10, 64); err == nil && seconds > 0 && seconds <= 24*60*60 {
		result.rateLimited = true
		update(now.Add(time.Duration(seconds) * time.Second))
	}
	if one("X-RateLimit-Remaining") == "0" {
		result.rateLimited = true
		if reset, err := strconv.ParseInt(one("X-RateLimit-Reset"), 10, 64); err == nil && reset > 0 {
			// Only a documented REST primary-quota exhaustion allows the
			// independent official read-only Git ref service. A generic 403,
			// secondary Retry-After, malformed or missing reset never does.
			result.primaryQuota = response.StatusCode == http.StatusForbidden &&
				len(response.Header.Values("Retry-After")) == 0 &&
				time.Unix(reset, 0).After(now) && !time.Unix(reset, 0).After(now.Add(24*time.Hour))
			update(time.Unix(reset, 0).Add(time.Second))
		}
	}
	return result
}
func (c *Client) githubBackoff() *githubCatalogRetryError {
	if c.BaseURL != DefaultBaseURL {
		return nil
	}
	c.githubRefMu.Lock()
	defer c.githubRefMu.Unlock()
	if c.githubRetry == nil || !time.Now().Before(c.githubRetry.until) {
		return nil
	}
	if c.githubRetry.primaryQuota {
		if c.githubGitRetry != nil && time.Now().Before(c.githubGitRetry.until) {
			return c.githubGitRetry
		}
		return nil
	}
	return c.githubRetry
}
func catalogFailureInfo(modified time.Time, err error) LoadInfo {
	result := LoadInfo{Source: "verified-cache", Stale: true, FetchedAt: modified.UTC().Format(time.RFC3339), CheckedAt: time.Now().UTC().Format(time.RFC3339), Error: "仓库检查失败: " + err.Error()}
	var retry *githubCatalogRetryError
	if errors.As(err, &retry) {
		result.CheckedAt = retry.checkedAt.UTC().Format(time.RFC3339)
		result.RetryAt = retry.until.UTC().Format(time.RFC3339)
	}
	return result
}
