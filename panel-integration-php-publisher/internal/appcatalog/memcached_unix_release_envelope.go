package appcatalog

import (
	"context"
	"crypto/ed25519"
	"errors"
)

// The wire format shares the bounded three-byte-buffer transfer, but this is
// an independent application authority. The published compat2 verifier and
// update journal are not widened to accept Unix or the withdrawn compat3.
type MemcachedUnixReleaseEnvelope MemcachedReleaseEnvelope

type MemcachedUnixReleaseAuthority struct {
	version, manifestSHA, catalogSHA, image string
	verified                                bool
}

func (a MemcachedUnixReleaseAuthority) Matches(version, manifestSHA string) bool {
	return a.verified && version == MemcachedUnixVersion && version == a.version &&
		manifestSHA == a.manifestSHA && ruleFeedSHAPattern.MatchString(manifestSHA) &&
		a.image == MemcachedDigestImage
}

func (a MemcachedUnixReleaseAuthority) CatalogSHA256() string { return a.catalogSHA }

func DecodeMemcachedUnixReleaseEnvelope(raw []byte) (MemcachedUnixReleaseEnvelope, error) {
	value, err := DecodeMemcachedReleaseEnvelope(raw)
	return MemcachedUnixReleaseEnvelope(value), err
}

// Public Root verification always uses the compiled official key AND compiled
// availability. A crypto fixture must never supply either to the Root path.
// This does not grant an actor permission, reserve a job, or inspect Docker.
func VerifyMemcachedUnixReleaseEnvelope(ctx context.Context, in MemcachedUnixReleaseEnvelope, version, manifestSHA string) (MemcachedUnixReleaseAuthority, error) {
	client := Default()
	client.HTTP = nil
	return verifyMemcachedUnixReleaseEnvelope(ctx, client, in, version, manifestSHA, panelFeatureAvailable)
}

// A private crypto/capability seam for self-contained signed fixtures only.
// There is no route/configuration field for a key, URL or available callback.
func verifyMemcachedUnixReleaseEnvelope(ctx context.Context, client *Client, in MemcachedUnixReleaseEnvelope, version, manifestSHA string, available func(string) bool) (MemcachedUnixReleaseAuthority, error) {
	var empty MemcachedUnixReleaseAuthority
	if ctx == nil {
		return empty, errors.New("Memcached Unix 交付缺少请求上下文")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if client == nil || len(client.PublicKey) != ed25519.PublicKeySize || version != MemcachedUnixVersion ||
		!ruleFeedSHAPattern.MatchString(manifestSHA) || !memcachedReleaseEnvelopeBounds(MemcachedReleaseEnvelope(in)) {
		return empty, errors.New("Memcached Unix 交付容量、固定版本或摘要无效")
	}
	// Authority never retains mutable decoder buffers.
	raw := append([]byte(nil), in.Catalog...)
	signature := append([]byte(nil), in.Signature...)
	manifestRaw := append([]byte(nil), in.AppManifest...)
	if unambiguousMemcachedReleaseJSON(raw) != nil || unambiguousMemcachedReleaseJSON(manifestRaw) != nil {
		return empty, errors.New("Memcached Unix 签名 JSON 不完整或有歧义")
	}
	catalog, err := client.verifyCatalog(raw, signature)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "memcached")
	if !found || item.Version != version || item.SHA256 != manifestSHA || hashRuleFeedFile(manifestRaw) != manifestSHA {
		return empty, errors.New("Memcached Unix 交付不属于原已签名版本与摘要")
	}
	var manifest Manifest
	if strictJSON(manifestRaw, &manifest) != nil || manifest.SchemaVersion != 1 ||
		manifest.ID != item.ID || manifest.Name != item.Name || manifest.Version != item.Version ||
		manifest.Category != item.Category || manifest.Stage != item.Stage || manifest.Risk != item.Risk ||
		manifest.Delivery.Provider != item.Provider || manifest.Delivery.Target != item.Target ||
		manifest.Delivery.ManageRoute != item.ManageRoute || manifest.Stage != "ready" ||
		len(manifest.Capabilities) == 0 || len(manifest.Capabilities) > 12 {
		return empty, errors.New("Memcached Unix 交付身份、处理器或功能与签名目录不一致")
	}
	// This exact independent contract also refuses all foreign/future manifests.
	// No shared old manifest decoder or legacy compat2 availability is changed.
	if handled, err := validateMemcachedUnixRequirement(manifest, available); !handled || err != nil {
		return empty, errors.New("Memcached Unix 缺少固定完整交付或独立已实现处理器")
	}
	if validateRuleFeeds(manifest) != nil || validateGeoDataChannel(manifest) != nil {
		return empty, errors.New("Memcached Unix 交付包含外来数据通道")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return MemcachedUnixReleaseAuthority{version: version, manifestSHA: manifestSHA, catalogSHA: hashRuleFeedFile(raw), image: manifest.Delivery.Image, verified: true}, nil
}
