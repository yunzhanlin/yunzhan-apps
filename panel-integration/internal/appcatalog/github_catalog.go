package appcatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const githubCatalogRefURL = "https://api.github.com/repos/yunzhanlin/yunzhan-apps/git/ref/heads/main"
const githubCatalogCommitBase = "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/"

var githubCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// The official branch is located through the documented, bounded Git reference
// API, then all catalog/signature reads use that immutable commit. A cached raw
// main response cannot silently be labelled a successful current-branch check.
// GitHub metadata is not an authority signature: Ed25519 verification, signed
// original package URLs, manifest hashes and rollback checks still apply.
func (c *Client) resolveCatalogCommit(ctx context.Context) (string, error) {
	if c.BaseURL != DefaultBaseURL {
		// Custom distribution servers keep their existing signed protocol. They
		// are never guessed into GitHub API targets or credential-bearing URLs.
		return "", nil
	}
	c.githubRefMu.Lock()
	defer c.githubRefMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c.githubRetry != nil && time.Now().Before(c.githubRetry.until) {
		if c.githubRetry.primaryQuota {
			return c.resolveGitCatalogCommitLocked(ctx)
		}
		return "", c.githubRetry
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubCatalogRefURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "YunzhanPanel-AppCatalog")
	raw, err := c.readResponse(req, 16<<10)
	if err != nil {
		var retry *githubCatalogRetryError
		if errors.As(err, &retry) {
			if c.githubFailures < 6 {
				c.githubFailures++
			}
			minimum := time.Now().Add(time.Minute * time.Duration(1<<(c.githubFailures-1)))
			if minimum.After(retry.until) {
				retry.until = minimum
			}
			c.githubRetry = retry
			if retry.primaryQuota {
				return c.resolveGitCatalogCommitLocked(ctx)
			}
		}
		return "", fmt.Errorf("无法定位官方仓库当前提交: %w", err)
	}
	c.githubRetry = nil
	c.githubFailures = 0
	c.githubGitRetry = nil
	c.githubGitFailures = 0
	// Ignore GitHub's unrelated metadata; never use its supplied URLs. A second
	// JSON value, duplicate critical fields or a different ref/type is refused.
	var reference struct {
		Ref    string `json:"ref"`
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := uniqueGitHubReference(raw); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&reference); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", errors.New("官方仓库提交响应无效")
	}
	if reference.Ref != "refs/heads/main" || reference.Object.Type != "commit" || !githubCommitPattern.MatchString(reference.Object.SHA) {
		return "", errors.New("官方仓库提交身份无效")
	}
	c.githubResolvedCommit = reference.Object.SHA
	c.githubResolvedTransport = "github-git-ref-api"
	return reference.Object.SHA, nil
}

// Reject ambiguous duplicate fields without depending on GitHub's metadata
// schema. Only objects/arrays/scalars are accepted and nesting is bounded.
func uniqueGitHubReference(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("官方仓库提交响应嵌套过深")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("官方仓库提交响应包含重复字段")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("官方仓库提交响应结构无效")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("官方仓库提交响应包含多余内容")
	}
	return nil
}

func (c *Client) getCatalogAtCommit(ctx context.Context, commit, relative string, limit int64) ([]byte, error) {
	if relative != "signatures/catalog-v1.bundle.json" && relative != "dist/catalog-v1.json" && relative != "signatures/catalog-v1.sig" {
		return nil, errors.New("拒绝访问未授权的目录路径")
	}
	if commit == "" {
		if c.BaseURL == DefaultBaseURL {
			return nil, errors.New("官方仓库目录缺少已定位提交")
		}
		return c.get(ctx, c.BaseURL+"/"+relative, limit)
	}
	if c.BaseURL != DefaultBaseURL || !githubCommitPattern.MatchString(commit) {
		return nil, errors.New("应用仓库目录提交无效")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubCatalogCommitBase+commit+"/"+relative, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	// An immutable commit needs no synthetic timestamp query. Keep the original
	// signed main URLs inside the payload unchanged for offline/root verification.
	return c.readResponse(req, limit)
}
