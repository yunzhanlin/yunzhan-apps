package executor

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"local/panel/internal/runtimecatalog"
)

// Reviewed sources and patches are part of a signed panel release. Neither an
// application setting nor a downloaded rule can change a URL/hash/patch.
const wafBodyEngineVersion = "3.0.17-yz2"
const wafBodyConnectorVersion = "1.0.4-yz2"
const wafBodyCRSVersion = "4.30.0"

type wafEngineSource struct {
	Name, Version, URL, SHA256, Verification string
}

func wafEngineSources() []wafEngineSource {
	return []wafEngineSource{
		{"modsecurity", "3.0.17", "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v3.0.17/modsecurity-v3.0.17.tar.gz", "f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50", "official GitHub release asset SHA-256 digest; not a PGP claim"},
		{"modsecurity-nginx", "1.0.4", "https://github.com/owasp-modsecurity/ModSecurity-nginx/releases/download/v1.0.4/ModSecurity-nginx-v1.0.4.tar.gz", "6bdc7570911be884c1e43aaf85046137f9fde0cfa0dd4a55b853c81c45a13313", "official release .sha256 file"},
		{"owasp-crs", "4.30.0", "https://github.com/coreruleset/coreruleset/releases/download/v4.30.0/coreruleset-4.30.0-minimal.tar.gz", "3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427", "official GitHub release asset SHA-256 digest; not a PGP claim"},
	}
}

// The distribution Nginx module is built against exactly this source version.
// Its ABI must still be proven by the selected binary's isolated nginx -t;
// version equality alone cannot authorize a module or a global reload.
func wafNginxBuildSource(version string) (wafEngineSource, bool) {
	if version == "1.24.0" {
		return wafEngineSource{"nginx-build", "1.24.0", "https://nginx.org/download/nginx-1.24.0.tar.gz", "77a2541637b92a621e3ee76776c8b7b40cf6d707e69ba53a940283e30ff2f55d", "official detached PGP signature; signer 13C82A63B603576156E30A4EA0EA981B66B0D967 from nginx.org/keys/thresh.key"}, true
	}
	if version == "1.26.3" {
		return wafEngineSource{"nginx-build", "1.26.3", "https://nginx.org/download/nginx-1.26.3.tar.gz", "69ee2b237744036e61d24b836668aad3040dda461fe6f570f1787eab570c75aa", "official detached PGP signature; signer D6786CE303D9A9022998DC6CC8464D549AF75C0A from nginx.org/keys/pluknet.key"}, true
	}
	for _, r := range runtimecatalog.Nginx {
		if r.Version == version {
			return wafEngineSource{"nginx-build", r.Version, r.URL, r.SHA256, r.Source}, true
		}
	}
	return wafEngineSource{}, false
}

func reviewedWAFEngineSource(source wafEngineSource) bool {
	if source.Name == "nginx-build" {
		want, ok := wafNginxBuildSource(source.Version)
		return ok && want == source
	}
	for _, want := range wafEngineSources() {
		if want == source {
			return true
		}
	}
	return false
}

//go:embed assets/modsecurity-metadata-only-logs.patch assets/modsecurity-nginx-private-context.patch assets/modsecurity-nginx-bounded-events.patch assets/modsecurity-LICENSE assets/modsecurity-nginx-LICENSE assets/modsecurity-crs-LICENSE assets/modsecurity-libinjection-COPYING assets/modsecurity-mbedtls-LICENSE assets/modsecurity-tf-psa-crypto-LICENSE assets/modsecurity-nginx-build-LICENSE assets/modsecurity-NOTICES.txt
var wafEngineAssets embed.FS

func wafEngineAssetPins() map[string]string {
	return map[string]string{
		"modsecurity-NOTICES.txt":                 "98470b12d983dcc0b02a2537c1728d35b66e253e5c447ae9a646eb09bdeb8366",
		"modsecurity-nginx-bounded-events.patch":  "31ee0da5e27cf6ab203c29c51a7afab925efd49ca638b0a4ec2beb05af7f644d",
		"modsecurity-metadata-only-logs.patch":    "173027af3174dfc93394cc2a2fa69a11ae7a1ecfb8011afc9b0f690e165898fe",
		"modsecurity-nginx-private-context.patch": "6c752ff3d2b8b3e32bac9a3c51d179be3430e7c81a1bd211f12917471cc8495c",
		"modsecurity-LICENSE":                     "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
		"modsecurity-nginx-LICENSE":               "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
		"modsecurity-crs-LICENSE":                 "676a192d3fc5205a288934ee02c5f934b782b91604a4b93589ba64520a4fec13",
		"modsecurity-libinjection-COPYING":        "0f99a954c6c009245b50c8fbd64de90b8667350df40a72a0f2b2843a521d24c9",
		"modsecurity-mbedtls-LICENSE":             "9b405ef4c89342f5eae1dd828882f931747f71001cfba7d114801039b52ad09b",
		"modsecurity-tf-psa-crypto-LICENSE":       "da8c58f05f135a9d15e9ffad4ecf854cfcc1f014c8abfd75ba05f62630ccc118",
		"modsecurity-nginx-build-LICENSE":         "ececed0b0e7243a4766cbc62b26df4bd3513b41de3a07425da1679c836d06320",
	}
}

func verifiedWAFEngineAsset(name string) ([]byte, error) {
	want, ok := wafEngineAssetPins()[name]
	if !ok {
		return nil, errors.New("WAF 构建资源不在固定审核清单中")
	}
	b, err := wafEngineAssets.ReadFile("assets/" + name)
	if err != nil {
		return nil, err
	}
	sha := sha256.Sum256(b)
	if hex.EncodeToString(sha[:]) != want {
		return nil, fmt.Errorf("WAF 构建资源 %s 的固定哈希不匹配", name)
	}
	return b, nil
}
