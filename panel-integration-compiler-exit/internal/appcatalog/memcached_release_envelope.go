package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// This is a closed transfer of exact signed bytes, not a job or an instruction
// to Docker. No supplied key, URL, executable, destination or verified flag is
// accepted. The privileged receiver uses its compiled official trust root.
const MaxMemcachedReleaseEnvelopeBytes = 3 << 20

type MemcachedReleaseEnvelope struct {
	Catalog     []byte `json:"catalog"`
	Signature   []byte `json:"signature"`
	AppManifest []byte `json:"app_manifest"`
}

// The zero value is not authority. Strings are detached immutable bindings;
// returning a Manifest or caller-owned buffers would expose mutable authority.
type MemcachedReleaseAuthority struct {
	version, manifestSHA, catalogSHA, image string
	verified                                bool
}

func (a MemcachedReleaseAuthority) Matches(version, manifestSHA string) bool {
	return a.verified && version == MemcachedDigestVersion && version == a.version && manifestSHA == a.manifestSHA && ruleFeedSHAPattern.MatchString(manifestSHA) && a.image == MemcachedDigestImage
}

func (a MemcachedReleaseAuthority) CatalogSHA256() string { return a.catalogSHA }

// VerifyMemcachedReleaseEnvelope never uses a caller-supplied client/key and
// never reads the network or filesystem. Verification is not actor permission,
// proof of branch freshness, a project precondition, or update/retry authority.
func VerifyMemcachedReleaseEnvelope(ctx context.Context, in MemcachedReleaseEnvelope, version, manifestSHA string) (MemcachedReleaseAuthority, error) {
	client := Default()
	client.HTTP = nil
	return verifyMemcachedReleaseEnvelope(ctx, client, in, version, manifestSHA)
}

func verifyMemcachedReleaseEnvelope(ctx context.Context, client *Client, in MemcachedReleaseEnvelope, version, manifestSHA string) (MemcachedReleaseAuthority, error) {
	var empty MemcachedReleaseAuthority
	if ctx == nil {
		return empty, errors.New("Memcached 交付验证缺少请求上下文")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if client == nil || len(client.PublicKey) != ed25519.PublicKeySize || version != MemcachedDigestVersion || !ruleFeedSHAPattern.MatchString(manifestSHA) || !memcachedReleaseEnvelopeBounds(in) {
		return empty, errors.New("Memcached 交付容量或固定版本、摘要绑定无效")
	}
	// Do not retain references to buffers that the request decoder owns.
	raw := append([]byte(nil), in.Catalog...)
	signature := append([]byte(nil), in.Signature...)
	manifestRaw := append([]byte(nil), in.AppManifest...)
	if err := unambiguousMemcachedReleaseJSON(raw); err != nil {
		return empty, err
	}
	if err := unambiguousMemcachedReleaseJSON(manifestRaw); err != nil {
		return empty, err
	}
	catalog, err := client.verifyCatalog(raw, signature)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "memcached")
	if !found || item.Version != version || item.SHA256 != manifestSHA {
		return empty, errors.New("Memcached 交付不属于指定的已签名应用版本与摘要")
	}
	manifest, err := client.verifyManifestData(item, manifestRaw)
	if err != nil {
		return empty, err
	}
	if handled, err := validateMemcachedDigestRequirement(manifest, panelFeatureAvailable); !handled || err != nil {
		return empty, errors.New("Memcached 交付未通过固定 Compose 摘要处理器验证")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return MemcachedReleaseAuthority{version: version, manifestSHA: manifestSHA, catalogSHA: hashRuleFeedFile(raw), image: manifest.Delivery.Image, verified: true}, nil
}

// FetchMemcachedReleaseEnvelope explicitly downloads only catalog and manifest.
// An application release is immutable by its signed digest; catalog generation
// time is not falsely treated as branch freshness or a short-lived user grant.
// The recipient MUST call the package-level verifier with compiled trust.
func (client *Client) FetchMemcachedReleaseEnvelope(ctx context.Context, version, manifestSHA string) (MemcachedReleaseEnvelope, error) {
	var empty MemcachedReleaseEnvelope
	if ctx == nil || client == nil || client.HTTP == nil || version != MemcachedDigestVersion || !ruleFeedSHAPattern.MatchString(manifestSHA) {
		return empty, errors.New("Memcached 下载版本或摘要绑定无效")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
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
		return empty, errors.New("Memcached 目录已变化，请刷新；未下载或更新应用")
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, err
	}
	in := MemcachedReleaseEnvelope{Catalog: raw, Signature: signature, AppManifest: manifest}
	if _, err = verifyMemcachedReleaseEnvelope(ctx, guarded, in, version, manifestSHA); err != nil {
		return empty, err
	}
	return in, nil
}

func memcachedReleaseEnvelopeBounds(in MemcachedReleaseEnvelope) bool {
	return len(in.Catalog) > 0 && len(in.Catalog) <= maxCatalogBytes && len(in.Signature) > 0 && len(in.Signature) <= 4096 && len(in.AppManifest) > 0 && len(in.AppManifest) <= maxManifestBytes
}

// DecodeMemcachedReleaseEnvelope accepts exactly three canonical base64 string
// fields. json.Unmarshal into []byte also accepts integer arrays, so it is not
// sufficient for this privileged boundary. No global executor limit is raised.
func DecodeMemcachedReleaseEnvelope(raw []byte) (MemcachedReleaseEnvelope, error) {
	var empty MemcachedReleaseEnvelope
	if len(raw) == 0 || len(raw) > MaxMemcachedReleaseEnvelopeBytes || !utf8.Valid(raw) {
		return empty, errors.New("Memcached 交付文本为空、编码无效或超过容量")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return empty, errors.New("Memcached 交付必须为闭合对象")
	}
	limits := map[string]int{"catalog": maxCatalogBytes, "signature": 4096, "app_manifest": maxManifestBytes}
	values := make(map[string][]byte, 3)
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		limit := limits[name]
		if err != nil || !ok || limit == 0 || values[name] != nil {
			return empty, errors.New("Memcached 交付包含未知、重复或非规范字段")
		}
		token, err := d.Token()
		encoded, ok := token.(string)
		if err != nil || !ok || encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(limit) {
			return empty, errors.New("Memcached 交付成员必须为有界 base64 字符串")
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(data) == 0 || len(data) > limit || base64.StdEncoding.EncodeToString(data) != encoded {
			return empty, errors.New("Memcached 交付成员编码不规范或超过容量")
		}
		values[name] = data
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(values) != 3 {
		return empty, errors.New("Memcached 交付字段集合不完整")
	}
	if _, err := d.Token(); err != io.EOF {
		return empty, errors.New("Memcached 交付包含多余内容")
	}
	return MemcachedReleaseEnvelope{Catalog: values["catalog"], Signature: values["signature"], AppManifest: values["app_manifest"]}, nil
}

// Apply a stricter boundary only to this new transfer. Existing signed catalog
// compatibility stays intact. Unknown fields are rejected by the shared typed
// verifiers; here duplicate/escaped aliases, case aliases and nulls are refused
// at every depth before their permissive encoding/json interpretation.
func unambiguousMemcachedReleaseJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("Memcached 签名 JSON 编码无效")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 8 {
			return errors.New("Memcached 签名 JSON 嵌套超限")
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return errors.New("Memcached 签名 JSON 不完整或含 null")
		}
		delim, nested := token.(json.Delim)
		if !nested {
			if depth == 0 {
				return errors.New("Memcached 签名 JSON 须为对象")
			}
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || name != strings.ToLower(name) || seen[name] {
					return errors.New("Memcached 签名 JSON 含重复或非规范字段")
				}
				seen[name] = true
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			if depth == 0 {
				return errors.New("Memcached 签名 JSON 须为对象")
			}
			for d.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("Memcached 签名 JSON 结构无效")
		}
		end, err := d.Token()
		if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return errors.New("Memcached 签名 JSON 未闭合")
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("Memcached 签名 JSON 包含多余值")
	}
	return nil
}
