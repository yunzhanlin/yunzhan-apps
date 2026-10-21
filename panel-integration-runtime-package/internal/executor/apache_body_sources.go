package executor

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
)

// Independent source authority. The v3 Apache connector is not used; upstream
// recommends v2.9.x for Apache. These hashes are reviewed release/DSC digests,
// not a claim of a verified detached PGP signature. No application input selects
// URLs, versions, hashes, patches, compiler flags or dependency commands.
const apacheBodyEngineVersion = "2.9.15-yz5"
const apacheBodyYAJLVersion = "2.1.0-debian5-yz1"

func apacheBodySources() []wafEngineSource {
	return []wafEngineSource{
		{"apache-modsecurity", "2.9.15", "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v2.9.15/modsecurity-v2.9.15.tar.gz", "4fae2d684672a24541607cb0b563d88b88eb4543b88cd090345149bb47309477", "official GitHub release SHA-256; metadata-only local patch; not a PGP claim"},
		{"apache-yajl", "2.1.0", "https://deb.debian.org/debian/pool/main/y/yajl/yajl_2.1.0.orig.tar.gz", "3fb73364a5a30efe615046d07e6db9d09fd2b41c763c5f7d3bfb121cd5c5ac5a", "Debian 2.1.0-5 DSC SHA-256; three embedded Debian CVE patches required; not a PGP claim"},
	}
}

func reviewedApacheBodySource(source wafEngineSource) bool {
	for _, want := range apacheBodySources() {
		if source == want {
			return true
		}
	}
	return false
}

//go:embed assets/apache-body-*
var apacheBodyAssets embed.FS

func apacheBodyAssetPins() map[string]string {
	return map[string]string{
		"apache-body-metadata-only.patch":       "614289344d86f2aeeba727e5116d1a57ea82cdedc64f9fc45e20759b8522a07d",
		"apache-body-parser-limits.patch":       "fe2e0b4189eb85d56e592e65eca7c95f08322398502b5cf5d8a342b02dc8f195",
		"apache-body-pcre2-no-rpath.patch":      "db4a442cc84f6c81617c5b2d52accd99957f02fc157ad78d68b67fed943f6e96",
		"apache-body-private-yajl.patch":        "89e63095cbf0b023ca53f79fb5bdbda180718e8e04b2afc96ec80926acbfd83f",
		"apache-body-yajl-CVE-2017-16516.patch": "dcb6f0097f46b67bc38254c706ca572f2d062f4d827b8f6dfd8335c31728dbb0",
		"apache-body-yajl-CVE-2022-24795.patch": "0ce576a63d7b9d2a66b9527bfe5ff49e62eca67551b629e5124ea952d2dbca79",
		"apache-body-yajl-CVE-2023-33460.patch": "c2651de7a6cfad741c82755f0188215c62d3a9e734d9db25c05a1519ee376747",
		"apache-body-modsecurity-LICENSE":       "2c564f5a67e49e74c80e5a7dcacd1904e7408f1fd6a95218b38c04f012d94cb9",
		"apache-body-modsecurity-NOTICE":        "7c5ab21c71d6f8ace2eed03222eed7035a77dc3cf84d56f307caa9d879ec475e",
		"apache-body-libinjection-COPYING":      "0f99a954c6c009245b50c8fbd64de90b8667350df40a72a0f2b2843a521d24c9",
		"apache-body-yajl-COPYING":              "054bf2c11686c5442850b1da58ad592e3d1d2a236a362e67279b957f8e662f5a",
		"apache-body-yajl-debian-copyright":     "ba9f487cdfba5ab1318f86cb24bd459ee698fb8350aeb4a07d2bef935d07d57f",
	}
}

func verifiedApacheBodyAsset(name string) ([]byte, error) {
	want, ok := apacheBodyAssetPins()[name]
	if !ok {
		return nil, errors.New("Apache 请求体构建资源未审核")
	}
	b, err := apacheBodyAssets.ReadFile("assets/" + name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(b)
	if hex.EncodeToString(digest[:]) != want {
		return nil, errors.New("Apache 请求体构建资源固定哈希不匹配")
	}
	return b, nil
}
