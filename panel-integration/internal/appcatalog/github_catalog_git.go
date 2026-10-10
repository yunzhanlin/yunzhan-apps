package appcatalog

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// This is the official repository's documented read-only Git advertisement,
// not a mirror, external git process, API cooldown override, or mutable-main
// catalog. It is used only after an explicit REST primary-quota response.
const githubCatalogGitRefURL = "https://github.com/yunzhanlin/yunzhan-apps.git/info/refs?service=git-upload-pack"
const githubGitAdvertisementLimit = 128 << 10
const githubGitAdvertisementPacketLimit = 8192
const githubGitAdvertisementRefLimit = 512

func (c *Client) catalogReferenceTransport(commit string) string {
	if c.BaseURL != DefaultBaseURL || commit == "" {
		return ""
	}
	c.githubRefMu.Lock()
	defer c.githubRefMu.Unlock()
	if c.githubResolvedCommit != commit {
		return ""
	}
	return c.githubResolvedTransport
}

// The caller owns githubRefMu. REST and Git cooldowns are separate, and a
// failed Git request never causes another API request or a redirect/mirror.
func (c *Client) resolveGitCatalogCommitLocked(ctx context.Context) (string, error) {
	if c.BaseURL != DefaultBaseURL || c.githubRetry == nil || !c.githubRetry.primaryQuota {
		return "", errors.New("拒绝未授权的 Git 引用检查")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c.githubGitRetry != nil && time.Now().Before(c.githubGitRetry.until) {
		return "", c.githubGitRetry
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubCatalogGitRefURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/x-git-upload-pack-advertisement")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "YunzhanPanel-AppCatalog")
	raw, err := c.readResponse(req, githubGitAdvertisementLimit)
	var commit string
	if err == nil {
		commit, err = parseGitCatalogAdvertisement(raw)
	}
	if err != nil {
		if cancelled := ctx.Err(); cancelled != nil {
			return "", cancelled
		}
		now := time.Now()
		retry := &githubCatalogRetryError{until: now.Add(time.Minute), checkedAt: now, transport: "git-smart-http"}
		var remote *githubCatalogRetryError
		if errors.As(err, &remote) {
			copy := *remote
			retry = &copy
			retry.primaryQuota = false
			retry.transport = "git-smart-http"
		}
		if c.githubGitFailures < 6 {
			c.githubGitFailures++
		}
		minimum := now.Add(time.Minute * time.Duration(1<<(c.githubGitFailures-1)))
		if minimum.After(retry.until) {
			retry.until = minimum
		}
		c.githubGitRetry = retry
		return "", retry
	}
	c.githubGitRetry = nil
	c.githubGitFailures = 0
	c.githubResolvedCommit = commit
	c.githubResolvedTransport = "github-smart-http"
	return commit, nil
}

// Parse the whole bounded v0 advertisement before trusting the fixed main
// branch. No service mismatch, truncated packet, duplicate ref, capability on
// later rows, protocol v2/control packet, null SHA, or trailing bytes may pass.
func parseGitCatalogAdvertisement(raw []byte) (string, error) {
	bad := errors.New("官方 Git 引用响应无效")
	if len(raw) > githubGitAdvertisementLimit {
		return "", bad
	}
	offset := 0
	packet := func() ([]byte, bool, error) {
		if len(raw)-offset < 4 {
			return nil, false, bad
		}
		header := raw[offset : offset+4]
		for _, v := range header {
			if !((v >= '0' && v <= '9') || (v >= 'a' && v <= 'f')) {
				return nil, false, bad
			}
		}
		n, err := strconv.ParseUint(string(header), 16, 16)
		if err != nil {
			return nil, false, bad
		}
		offset += 4
		if n == 0 {
			return nil, true, nil
		}
		if n < 5 || n > githubGitAdvertisementPacketLimit || int(n)-4 > len(raw)-offset {
			return nil, false, bad
		}
		value := raw[offset : offset+int(n)-4]
		offset += int(n) - 4
		return value, false, nil
	}
	first, flush, err := packet()
	if err != nil || flush || !bytes.Equal(bytes.TrimSuffix(first, []byte("\n")), []byte("# service=git-upload-pack")) {
		return "", bad
	}
	_, flush, err = packet()
	if err != nil || !flush {
		return "", bad
	}
	seen := map[string]bool{}
	commit := ""
	for count := 0; ; count++ {
		value, end, err := packet()
		if err != nil {
			return "", bad
		}
		if end {
			if offset != len(raw) || count == 0 || commit == "" {
				return "", bad
			}
			return commit, nil
		}
		if count >= githubGitAdvertisementRefLimit {
			return "", bad
		}
		line := bytes.TrimSuffix(value, []byte("\n"))
		if bytes.ContainsAny(line, "\r\n") {
			return "", bad
		}
		parts := bytes.Split(line, []byte{0})
		if (count == 0 && len(parts) != 2) || (count > 0 && len(parts) != 1) {
			return "", bad
		}
		if count == 0 {
			if len(parts[1]) == 0 {
				return "", bad
			}
			for _, v := range parts[1] {
				if v < 32 || v > 126 {
					return "", bad
				}
			}
		}
		fields := bytes.Split(parts[0], []byte{' '})
		if len(fields) != 2 || !githubCommitPattern.Match(fields[0]) || bytes.Equal(fields[0], bytes.Repeat([]byte{'0'}, 40)) {
			return "", bad
		}
		name := string(fields[1])
		if !validAdvertisedGitRef(name) || seen[name] {
			return "", bad
		}
		seen[name] = true
		if name == "refs/heads/main" {
			commit = string(fields[0])
		}
	}
}

func validAdvertisedGitRef(name string) bool {
	if name == "HEAD" {
		return true
	}
	if !utf8.ValidString(name) || len(name) > 1024 || !strings.HasPrefix(name, "refs/") {
		return false
	}
	if strings.HasSuffix(name, "^{}") {
		if !strings.HasPrefix(name, "refs/tags/") {
			return false
		}
		name = strings.TrimSuffix(name, "^{}")
	}
	if strings.HasSuffix(name, "/") || strings.Contains(name, "//") || strings.Contains(name, "..") || strings.Contains(name, "@{") {
		return false
	}
	for _, r := range name {
		if r <= 32 || unicode.IsControl(r) || strings.ContainsRune("~:^?[*\\", r) {
			return false
		}
	}
	parts := strings.Split(name, "/")
	if len(parts) < 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}
