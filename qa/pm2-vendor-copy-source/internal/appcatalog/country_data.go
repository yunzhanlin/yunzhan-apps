package appcatalog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"local/panel/internal/geodata"
)

// This exact ABI includes the independent original data task, isolated
// transfer, fixed account preparation and ordinary WAF transaction binding.
const CountryDataFeature = "waf-country-signed-data-v1"

// Compiled capability only, not proof of an installed app, prepared data,
// active Nginx enforcement, or commercial acceptance.
func CountryDataSupported() bool { return panelFeatureAvailable(CountryDataFeature) }

func validateCountryDataRequirement(m Manifest) error {
	found := 0
	for _, f := range m.RequiredPanelFeatures {
		if f == CountryDataFeature {
			found++
		}
	}
	if found > 0 && (m.ID != "nginx-waf" || m.Version != "2.6.0" || found != 1 || len(m.RequiredPanelFeatures) != 1 || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "security") {
		return errors.New("country data ABI belongs only to exact nginx-waf2.6.0 handler")
	}
	if m.ID == "nginx-waf" {
		base, _, _ := strings.Cut(m.Version, "-")
		cmp, ok := CompareVersions(base, "2.6.0")
		if !ok {
			return errors.New("country WAF version invalid")
		}
		if cmp >= 0 && (m.Version != "2.6.0" || found != 1 || len(m.RequiredPanelFeatures) != 1) {
			return errors.New("nginx-waf2.6 requires exact version and signed-country handler")
		}
	}
	return nil
}

func validateCountryDataChannel(m Manifest) error {
	if err := validateCountryDataRequirement(m); err != nil {
		return err
	}
	has := false
	for _, f := range m.RequiredPanelFeatures {
		has = has || f == CountryDataFeature
	}
	if m.CountryDataChannel == nil {
		if has {
			return errors.New("country data channel missing")
		}
		return nil
	}
	if !has || m.ID != "nginx-waf" || m.Version != "2.6.0" || m.Delivery.Provider != "panel-module" || m.Delivery.Target != m.ID || m.Delivery.ManageRoute != "security" || m.CountryDataChannel.ID != geodata.CountryChannel || m.CountryDataChannel.Format != 1 || m.GeoDataChannel != nil {
		return errors.New("country channel not the fixed implemented Nginx data ABI")
	}
	return nil
}

type CountryDataAuthority struct {
	data                       geodata.CountryAuthority
	appVersion, appSHA, keySHA string
	envelope                   GeoDataEnvelope
	verified                   bool
}

func (a CountryDataAuthority) Data() geodata.CountryAuthority { return a.data }
func (a CountryDataAuthority) AppVersion() string             { return a.appVersion }
func (a CountryDataAuthority) AppSHA256() string              { return a.appSHA }
func (a CountryDataAuthority) Envelope() GeoDataEnvelope      { return cloneGeoEnvelope(a.envelope) }

func (c *Client) VerifyCountryDataEnvelope(in GeoDataEnvelope, version, appSHA string, now time.Time, previous *CountryDataAuthority) (CountryDataAuthority, error) {
	return c.verifyCountryDataEnvelope(in, version, appSHA, now, previous, panelFeatureAvailable)
}

func (c *Client) verifyCountryDataEnvelope(in GeoDataEnvelope, version, appSHA string, now time.Time, previous *CountryDataAuthority, available func(string) bool) (CountryDataAuthority, error) {
	var empty CountryDataAuthority
	if c == nil || len(c.PublicKey) != ed25519.PublicKeySize || version != "2.6.0" || !digestPatternForGeo(appSHA) || len(in.AppCatalog) < 1 || len(in.AppCatalog) > maxCatalogBytes || len(in.AppSignature) < 1 || len(in.AppSignature) > 4096 || len(in.AppManifest) < 1 || len(in.AppManifest) > maxManifestBytes || len(in.DataManifest) < 1 || len(in.DataManifest) > geodata.MaxCountryManifestBytes || len(in.DataSignature) < 1 || len(in.DataSignature) > 128 {
		return empty, errors.New("country app/data authority inputs invalid")
	}
	in = cloneGeoEnvelope(in)
	catalog, err := c.verifyCatalog(in.AppCatalog, in.AppSignature)
	if err != nil {
		return empty, err
	}
	item, found := Find(catalog, "nginx-waf")
	if !found || item.Version != version || item.SHA256 != appSHA {
		return empty, errors.New("country data not bound to selected signed Nginx WAF app")
	}
	m, err := c.verifyManifestDataWithAvailability(item, in.AppManifest, available)
	if err != nil || validateCountryDataChannel(m) != nil || m.CountryDataChannel == nil {
		return empty, errors.New("country signed application channel cannot be verified")
	}
	keySHA := hashRuleFeedFile(c.PublicKey)
	var prior *geodata.CountryAuthority
	if previous != nil {
		if !previous.verified || previous.keySHA != keySHA || previous.appVersion != version || previous.appSHA != appSHA {
			return empty, errors.New("country previous authority belongs to another app/key")
		}
		prior = &previous.data
	}
	data, err := geodata.VerifyCountryManifest(in.DataManifest, in.DataSignature, c.PublicKey, now, prior)
	if err != nil {
		return empty, err
	}
	return CountryDataAuthority{data, version, appSHA, keySHA, in, true}, nil
}

// Only small original signed materials cross the Core/Root hand-off. Neither
// data bytes, a public key, arbitrary URL, output path nor executable is taken
// from a panel request. Root re-verifies the identical immutable selection.
func (c *Client) FetchCountryDataEnvelope(ctx context.Context, expectedDataSHA string, now time.Time) (GeoDataEnvelope, CountryDataAuthority, error) {
	var empty GeoDataEnvelope
	var none CountryDataAuthority
	if ctx == nil || c == nil || c.HTTP == nil || expectedDataSHA != "" && !digestPatternForGeo(expectedDataSHA) {
		return empty, none, errors.New("country repository selection invalid")
	}
	httpClient := *c.HTTP
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	guarded := &Client{BaseURL: c.BaseURL, PublicKey: bytes.Clone(c.PublicKey), HTTP: &httpClient}
	catalog, raw, sig, err := guarded.FetchCatalog(ctx)
	if err != nil {
		return empty, none, err
	}
	item, found := Find(catalog, "nginx-waf")
	if !found || item.Version != "2.6.0" {
		return empty, none, errors.New("signed repository does not yet provide Nginx country data ABI")
	}
	manifest, err := guarded.get(ctx, item.PackageURL, maxManifestBytes)
	if err != nil {
		return empty, none, err
	}
	url := guarded.BaseURL + "/data/geodata/" + geodata.CountryChannel + "/catalog.signed.json"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return empty, none, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-cache")
	q := request.URL.Query()
	q.Set("check", strconv.FormatInt(now.UnixNano(), 10))
	request.URL.RawQuery = q.Encode()
	bundle, err := guarded.readResponse(request, geodata.MaxCountryManifestBytes*2)
	if err != nil {
		return empty, none, err
	}
	if len(bundle) == 0 || !utf8.Valid(bundle) {
		return empty, none, errors.New("country signed catalog encoding invalid")
	}
	d := json.NewDecoder(bytes.NewReader(bundle))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return empty, none, errors.New("country signed catalog object missing")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || name != "manifest" && name != "signature" || seen[name] {
			return empty, none, errors.New("country signed catalog duplicate or unknown field")
		}
		seen[name] = true
		value, err := d.Token()
		if _, ok := value.(string); err != nil || !ok {
			return empty, none, errors.New("country signed catalog requires original signed text")
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') || len(seen) != 2 {
		return empty, none, errors.New("country signed catalog incomplete")
	}
	if _, err := d.Token(); err != io.EOF {
		return empty, none, errors.New("country signed catalog has trailing data")
	}
	var value struct {
		Manifest  string `json:"manifest"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(bundle, &value) != nil {
		return empty, none, errors.New("country signed catalog decode failed")
	}
	in := GeoDataEnvelope{raw, sig, manifest, []byte(value.Manifest), []byte(value.Signature)}
	a, err := guarded.VerifyCountryDataEnvelope(in, item.Version, item.SHA256, now, nil)
	if err != nil {
		return empty, none, err
	}
	if expectedDataSHA != "" && a.Data().SHA256() != expectedDataSHA {
		return empty, none, errors.New("country signed selection changed; refresh explicitly, no silent substitution")
	}
	return a.Envelope(), a, nil
}
