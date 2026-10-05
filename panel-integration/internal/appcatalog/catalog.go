package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const DefaultBaseURL = "https://raw.githubusercontent.com/yunzhanlin/yunzhan-apps/main"

const defaultPublicKey = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAq/Lp03Rt0HZlhJF6fac3sFsb2Tq2Q75cFL+tpRNWNvc=
-----END PUBLIC KEY-----
`

const maxCatalogBytes = 2 << 20
const maxManifestBytes = 128 << 10

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
var targetPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,127}$`)

type Catalog struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Repository    string        `json:"repository"`
	Apps          []CatalogItem `json:"apps"`
}

type CatalogItem struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Version      string   `json:"version"`
	Summary      string   `json:"summary"`
	Stage        string   `json:"stage"`
	Risk         string   `json:"risk"`
	Provider     string   `json:"provider"`
	Target       string   `json:"target"`
	ManageRoute  string   `json:"manage_route"`
	Capabilities []string `json:"capabilities"`
	PackageURL   string   `json:"package_url"`
	SHA256       string   `json:"sha256"`
}

type Delivery struct {
	Provider    string `json:"provider"`
	Target      string `json:"target"`
	Image       string `json:"image,omitempty"`
	ManageRoute string `json:"manage_route,omitempty"`
	Isolation   string `json:"isolation,omitempty"`
}

type Compatibility struct {
	OS            []string `json:"os"`
	Architectures []string `json:"architectures"`
}

type Health struct {
	Probe  string `json:"probe"`
	Target string `json:"target,omitempty"`
}

type Uninstall struct {
	PreserveData   bool `json:"preserve_data"`
	ReferenceCheck bool `json:"reference_check"`
}

type Manifest struct {
	SchemaVersion int           `json:"schema_version"`
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Category      string        `json:"category"`
	Version       string        `json:"version"`
	Summary       string        `json:"summary"`
	Stage         string        `json:"stage"`
	Risk          string        `json:"risk"`
	Delivery      Delivery      `json:"delivery"`
	Compatibility Compatibility `json:"compatibility"`
	Capabilities  []string      `json:"capabilities"`
	Health        Health        `json:"health"`
	Uninstall     Uninstall     `json:"uninstall"`
}

type LoadInfo struct {
	Source    string `json:"source"`
	Stale     bool   `json:"stale"`
	FetchedAt string `json:"fetched_at,omitempty"`
}

type Client struct {
	BaseURL   string
	PublicKey ed25519.PublicKey
	HTTP      *http.Client
}

func parsePublicKey(contents []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("应用仓库公钥格式无效")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("应用仓库公钥不是 Ed25519")
	}
	return key, nil
}

func New(baseURL string, publicKeyPEM []byte, client *http.Client) (*Client, error) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("应用仓库基础地址无效")
	}
	key, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Client{BaseURL: baseURL, PublicKey: key, HTTP: client}, nil
}

func Default() *Client {
	client, err := New(DefaultBaseURL, []byte(defaultPublicKey), nil)
	if err != nil {
		panic(err)
	}
	return client
}

func (c *Client) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	if rawURL != c.BaseURL+"/dist/catalog-v1.json" && rawURL != c.BaseURL+"/signatures/catalog-v1.sig" && !strings.HasPrefix(rawURL, c.BaseURL+"/dist/apps/") {
		return nil, errors.New("拒绝访问未授权的应用仓库地址")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain;q=0.8")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("应用仓库 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("应用仓库响应超过上限")
	}
	return body, nil
}

func strictJSON(raw []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("JSON 包含多余内容")
	}
	return nil
}

func (c *Client) validateCatalog(catalog Catalog) error {
	if catalog.SchemaVersion != 1 || len(catalog.Apps) == 0 || len(catalog.Apps) > 512 {
		return errors.New("应用目录版本或数量无效")
	}
	if _, err := time.Parse(time.RFC3339, catalog.GeneratedAt); err != nil {
		return errors.New("应用目录时间无效")
	}
	seen := map[string]bool{}
	for _, app := range catalog.Apps {
		if seen[app.ID] || !idPattern.MatchString(app.ID) || app.Name == "" || app.Version == "" || len(app.Summary) < 8 {
			return errors.New("应用目录包含重复或无效项")
		}
		seen[app.ID] = true
		if app.Category != "deployment" && app.Category != "professional" {
			return errors.New("应用分类无效")
		}
		if app.Stage != "ready" && app.Stage != "integration" && app.Stage != "design" {
			return errors.New("应用阶段无效")
		}
		if app.Provider != "runtime" && app.Provider != "compose" && app.Provider != "panel-module" {
			return errors.New("应用处理器无效")
		}
		if !targetPattern.MatchString(app.Target) || len(app.Capabilities) == 0 || len(app.Capabilities) > 12 {
			return errors.New("应用目录处理目标或功能无效")
		}
		expected := fmt.Sprintf("%s/dist/apps/%s/%s/manifest.json", c.BaseURL, app.ID, app.Version)
		if app.PackageURL != expected {
			return errors.New("应用包地址不在受信仓库路径中")
		}
		if digest, err := hex.DecodeString(app.SHA256); err != nil || len(digest) != sha256.Size {
			return errors.New("应用包 SHA-256 无效")
		}
	}
	return nil
}

func (c *Client) verifyCatalog(raw, signature []byte) (Catalog, error) {
	var catalog Catalog
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signature)))
	if err != nil || len(decoded) != ed25519.SignatureSize || !ed25519.Verify(c.PublicKey, raw, decoded) {
		return catalog, errors.New("应用目录 Ed25519 签名无效")
	}
	if err = strictJSON(raw, &catalog); err != nil {
		return catalog, fmt.Errorf("应用目录 JSON 无效: %w", err)
	}
	if err = c.validateCatalog(catalog); err != nil {
		return catalog, err
	}
	return catalog, nil
}

func (c *Client) FetchCatalog(ctx context.Context) (Catalog, []byte, []byte, error) {
	var empty Catalog
	raw, err := c.get(ctx, c.BaseURL+"/dist/catalog-v1.json", maxCatalogBytes)
	if err != nil {
		return empty, nil, nil, err
	}
	signature, err := c.get(ctx, c.BaseURL+"/signatures/catalog-v1.sig", 4096)
	if err != nil {
		return empty, nil, nil, err
	}
	catalog, err := c.verifyCatalog(raw, signature)
	return catalog, raw, signature, err
}

func atomicWrite(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".catalog-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(body)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	return err
}

func (c *Client) cachedCatalog(cacheDir string) (Catalog, time.Time, error) {
	var empty Catalog
	rawPath := filepath.Join(cacheDir, "catalog-v1.json")
	sigPath := filepath.Join(cacheDir, "catalog-v1.sig")
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		return empty, time.Time{}, err
	}
	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return empty, time.Time{}, err
	}
	catalog, err := c.verifyCatalog(raw, signature)
	if err != nil {
		return empty, time.Time{}, err
	}
	info, err := os.Stat(rawPath)
	if err != nil {
		return empty, time.Time{}, err
	}
	return catalog, info.ModTime(), nil
}

func (c *Client) LoadCatalog(ctx context.Context, cacheDir string, maxAge time.Duration) (Catalog, LoadInfo, error) {
	if cached, modified, err := c.cachedCatalog(cacheDir); err == nil && time.Since(modified) <= maxAge {
		return cached, LoadInfo{Source: "verified-cache", FetchedAt: modified.UTC().Format(time.RFC3339)}, nil
	}
	catalog, raw, signature, fetchErr := c.FetchCatalog(ctx)
	if fetchErr == nil {
		if err := atomicWrite(filepath.Join(cacheDir, "catalog-v1.json"), raw, 0600); err != nil {
			return Catalog{}, LoadInfo{}, err
		}
		if err := atomicWrite(filepath.Join(cacheDir, "catalog-v1.sig"), signature, 0600); err != nil {
			return Catalog{}, LoadInfo{}, err
		}
		return catalog, LoadInfo{Source: "github", FetchedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}
	if cached, modified, err := c.cachedCatalog(cacheDir); err == nil {
		return cached, LoadInfo{Source: "verified-cache", Stale: true, FetchedAt: modified.UTC().Format(time.RFC3339)}, nil
	}
	return Catalog{}, LoadInfo{}, fetchErr
}

func (c *Client) FetchManifest(ctx context.Context, item CatalogItem, cacheDir string) (Manifest, error) {
	var manifest Manifest
	if err := c.validateCatalog(Catalog{SchemaVersion: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Apps: []CatalogItem{item}}); err != nil {
		return manifest, err
	}
	raw, err := c.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return manifest, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != item.SHA256 {
		return manifest, errors.New("应用包 SHA-256 与已签名目录不一致")
	}
	if err = strictJSON(raw, &manifest); err != nil {
		return manifest, err
	}
	if manifest.SchemaVersion != 1 || manifest.ID != item.ID || manifest.Name != item.Name || manifest.Version != item.Version || manifest.Category != item.Category || manifest.Stage != item.Stage || manifest.Risk != item.Risk {
		return Manifest{}, errors.New("应用包身份与目录不一致")
	}
	if manifest.Delivery.Provider != item.Provider || manifest.Delivery.Target != item.Target || manifest.Delivery.ManageRoute != item.ManageRoute || !targetPattern.MatchString(manifest.Delivery.Target) || len(manifest.Capabilities) == 0 || len(manifest.Capabilities) > 12 {
		return Manifest{}, errors.New("应用包处理器或功能声明无效")
	}
	if manifest.Stage != "ready" {
		return Manifest{}, errors.New("该应用尚未通过安装验收")
	}
	path := filepath.Join(cacheDir, manifest.ID, manifest.Version, "manifest.json")
	if err = atomicWrite(path, raw, 0600); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Find(catalog Catalog, id string) (CatalogItem, bool) {
	for _, app := range catalog.Apps {
		if app.ID == id {
			return app, true
		}
	}
	return CatalogItem{}, false
}
