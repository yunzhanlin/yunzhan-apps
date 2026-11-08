package appcatalog

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
)

// Fetch only the exact signed Unix catalog/manifest bytes. No application
// archive, OCI image or installed project is changed. Root still independently
// verifies its compiled key, current actor/reservation and live project.
func (client *Client) FetchMemcachedUnixReleaseEnvelope(ctx context.Context, version, manifestSHA string) (MemcachedUnixReleaseEnvelope, error) {
	return client.fetchMemcachedUnixReleaseEnvelope(ctx, version, manifestSHA, panelFeatureAvailable)
}

// Unexported crypto/capability fixture seam; not configuration or HTTP input.
func (client *Client) fetchMemcachedUnixReleaseEnvelope(ctx context.Context, version, manifestSHA string, available func(string) bool) (MemcachedUnixReleaseEnvelope, error) {
	var empty MemcachedUnixReleaseEnvelope
	if ctx == nil || client == nil || client.HTTP == nil || version != MemcachedUnixVersion || !ruleFeedSHAPattern.MatchString(manifestSHA) {
		return empty, errors.New("Memcached Unix 下载版本、摘要或上下文无效")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if available == nil || !available(MemcachedDigestFeature) || !available(MemcachedUnixFeature) || !available(MemcachedUnixRetirementFeature) {
		return empty, errors.New("Memcached Unix 独立软件能力尚未启用，请先升级面板")
	}
	transport := *client.HTTP
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: client.BaseURL, PublicKey: append(ed25519.PublicKey(nil), client.PublicKey...), HTTP: &transport}
	catalog, raw, signature, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "memcached")
	if !found || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errors.New("Memcached Unix 签名目录已变化，请刷新；未拉取软件包")
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	envelope := MemcachedUnixReleaseEnvelope{Catalog: raw, Signature: signature, AppManifest: manifest}
	if _, err = verifyMemcachedUnixReleaseEnvelope(ctx, guarded, envelope, version, manifestSHA, available); err != nil {
		return empty, err
	}
	return envelope, nil
}
