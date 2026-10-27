package appcatalog

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sort"
	"strings"

	"local/panel/internal/loadbalancestream"
)

const LoadBalanceStreamFeature = "load-balance-stream-controller-v1"

// Only the three closed bounded byte buffers are shared with the older wire
// codec. No Memcached feature, key, image or installation authority is borrowed.
type LoadBalanceStreamReleaseEnvelope MemcachedReleaseEnvelope

type LoadBalanceStreamReleaseAuthority struct {
	version, manifestSHA, catalogSHA string
	verified                         bool
}

var errLoadBalanceStreamRelease = errors.New("TCP/UDP 独立交付的签名目录、固定版本、摘要或完整处理器无法核对；未授权安装或服务变更")

func (a LoadBalanceStreamReleaseAuthority) Matches(version, manifestSHA string) bool {
	return a.verified && version == loadbalancestream.AppVersion && version == a.version && manifestSHA == a.manifestSHA && ruleFeedSHAPattern.MatchString(manifestSHA) && manifestSHA != strings.Repeat("0", 64)
}
func (a LoadBalanceStreamReleaseAuthority) CatalogSHA256() string { return a.catalogSHA }

func DecodeLoadBalanceStreamReleaseEnvelope(raw []byte) (LoadBalanceStreamReleaseEnvelope, error) {
	v, err := DecodeMemcachedReleaseEnvelope(raw)
	if err != nil {
		return LoadBalanceStreamReleaseEnvelope{}, errLoadBalanceStreamRelease
	}
	return LoadBalanceStreamReleaseEnvelope(v), nil
}

func streamReleaseSet(got, expected []string) bool {
	a, b := append([]string(nil), got...), append([]string(nil), expected...)
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Stable availability remains closed. The fixed official candidate programme
// channel permits normal signed installation and acceptance without exposing
// an unqualified update in the stable application catalogue.
func isLoadBalanceStreamManifest(m Manifest) bool {
	return m.SchemaVersion == 1 && m.ID == "load-balance" && m.Version == loadbalancestream.AppVersion && m.Stage == "ready" && m.Category == "professional" && m.Risk == "privileged" &&
		m.Delivery == (Delivery{Provider: "panel-module", Target: "load-balance", ManageRoute: "app-modules"}) &&
		m.Health == (Health{Probe: "panel-api", Target: "/api/app-modules/load-balance"}) && m.Uninstall == (Uninstall{PreserveData: true, ReferenceCheck: true}) &&
		len(m.RequiredPanelFeatures) == 1 && m.RequiredPanelFeatures[0] == LoadBalanceStreamFeature && len(m.RuleFeeds) == 0 && m.RuleDataChannel == nil && m.GeoDataChannel == nil &&
		streamReleaseSet(m.Compatibility.OS, []string{"debian-12", "debian-13", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04"}) && streamReleaseSet(m.Compatibility.Architectures, []string{"amd64", "arm64"})
}

func validateLoadBalanceStreamRequirement(m Manifest, available func(string) bool) (bool, error) {
	if m.ID != "load-balance" {
		for _, feature := range m.RequiredPanelFeatures {
			if feature == LoadBalanceStreamFeature {
				return true, errLoadBalanceStreamRelease
			}
		}
		return false, nil
	}
	base, _, _ := strings.Cut(m.Version, "-")
	comparison, valid := CompareVersions(base, loadbalancestream.AppVersion)
	if !valid {
		return true, errLoadBalanceStreamRelease
	}
	if comparison < 0 {
		for _, feature := range m.RequiredPanelFeatures {
			if feature == LoadBalanceStreamFeature {
				return true, errLoadBalanceStreamRelease
			}
		}
		return false, nil
	}
	if !isLoadBalanceStreamManifest(m) || len(m.Capabilities) == 0 || len(m.Capabilities) > 12 || available == nil || !available(LoadBalanceStreamFeature) {
		return true, errLoadBalanceStreamRelease
	}
	return true, nil
}

// Root always uses the compiled official trust root and actual availability.
// No route/CLI/configuration may supply a key, URL, feature callback or success
// flag. This reads no network and grants no actor/native/boot authority.
func VerifyLoadBalanceStreamReleaseEnvelope(ctx context.Context, in LoadBalanceStreamReleaseEnvelope, version, manifestSHA string) (LoadBalanceStreamReleaseAuthority, error) {
	client := Default()
	client.HTTP = nil
	return verifyLoadBalanceStreamReleaseEnvelope(ctx, client, in, version, manifestSHA, panelFeatureAvailable)
}

// Private crypto fixture seam only. Not a production key/capability override.
func verifyLoadBalanceStreamReleaseEnvelope(ctx context.Context, client *Client, in LoadBalanceStreamReleaseEnvelope, version, manifestSHA string, available func(string) bool) (LoadBalanceStreamReleaseAuthority, error) {
	var empty LoadBalanceStreamReleaseAuthority
	if ctx == nil || ctx.Err() != nil || client == nil || len(client.PublicKey) != ed25519.PublicKeySize || version != loadbalancestream.AppVersion || !ruleFeedSHAPattern.MatchString(manifestSHA) || manifestSHA == strings.Repeat("0", 64) || !memcachedReleaseEnvelopeBounds(MemcachedReleaseEnvelope(in)) || available == nil || !available(LoadBalanceStreamFeature) {
		return empty, errLoadBalanceStreamRelease
	}
	raw, signature, manifestRaw := append([]byte(nil), in.Catalog...), append([]byte(nil), in.Signature...), append([]byte(nil), in.AppManifest...)
	if unambiguousMemcachedReleaseJSON(raw) != nil || unambiguousMemcachedReleaseJSON(manifestRaw) != nil {
		return empty, errLoadBalanceStreamRelease
	}
	catalog, err := client.verifyCatalog(raw, signature)
	if err != nil {
		return empty, errLoadBalanceStreamRelease
	}
	item, found := Find(catalog, "load-balance")
	if !found || item.Version != version || item.SHA256 != manifestSHA || hashRuleFeedFile(manifestRaw) != manifestSHA {
		return empty, errLoadBalanceStreamRelease
	}
	var m Manifest
	if strictJSON(manifestRaw, &m) != nil || !isLoadBalanceStreamManifest(m) || m.Name != item.Name || m.Category != item.Category || m.Stage != item.Stage || m.Risk != item.Risk || m.Delivery.Provider != item.Provider || m.Delivery.Target != item.Target || m.Delivery.ManageRoute != item.ManageRoute || len(m.Capabilities) == 0 || len(m.Capabilities) > 12 || ctx.Err() != nil {
		return empty, errLoadBalanceStreamRelease
	}
	return LoadBalanceStreamReleaseAuthority{version, manifestSHA, hashRuleFeedFile(raw), true}, nil
}

// Normal Core download of only the exact signed metadata. The Root recipient
// must verify it again independently; a client/cache is not native authority.
func (c *Client) FetchLoadBalanceStreamReleaseEnvelope(ctx context.Context, version, manifestSHA string) (LoadBalanceStreamReleaseEnvelope, error) {
	return c.fetchLoadBalanceStreamReleaseEnvelope(ctx, version, manifestSHA, panelFeatureAvailable)
}

func (c *Client) fetchLoadBalanceStreamReleaseEnvelope(ctx context.Context, version, manifestSHA string, available func(string) bool) (LoadBalanceStreamReleaseEnvelope, error) {
	var empty LoadBalanceStreamReleaseEnvelope
	if ctx == nil || ctx.Err() != nil || c == nil || c.HTTP == nil || version != loadbalancestream.AppVersion || !ruleFeedSHAPattern.MatchString(manifestSHA) || available == nil || !available(LoadBalanceStreamFeature) {
		return empty, errLoadBalanceStreamRelease
	}
	transport := *c.HTTP
	transport.Jar = nil
	transport.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: c.BaseURL, PublicKey: append(ed25519.PublicKey(nil), c.PublicKey...), HTTP: &transport}
	catalog, raw, signature, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "load-balance")
	if !found || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errLoadBalanceStreamRelease
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	in := LoadBalanceStreamReleaseEnvelope{Catalog: raw, Signature: signature, AppManifest: manifest}
	if _, err = verifyLoadBalanceStreamReleaseEnvelope(ctx, guarded, in, version, manifestSHA, available); err != nil {
		return empty, err
	}
	return in, nil
}
