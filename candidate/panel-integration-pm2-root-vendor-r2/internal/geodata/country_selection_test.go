package geodata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"
)

func countrySelectionInputs(codes []string, files map[string][]byte) []io.Reader {
	inputs := make([]io.Reader, len(codes))
	for i, code := range codes {
		inputs[i] = bytes.NewReader(files[code])
	}
	return inputs
}

func TestCountrySelectionJointStreamingBindsEveryFileAndBothAddressFamilies(t *testing.T) {
	m, pub, key, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, key)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{"AU", "CH", "CN", "US"}
	got, err := VerifyCountrySelection(context.Background(), a, codes, countrySelectionInputs(codes, files))
	if err != nil || got.ManifestSHA256 != a.SHA256() || got.ParentManifestSHA256 != hash([]byte(m.ParentManifest)) || got.Bytes != m.Bytes || got.Networks != m.Networks || !reflect.DeepEqual(got.Countries, []CountryCIDRCount{{"AU", 1}, {"CH", 1}, {"CN", 1}, {"US", 3}}) {
		t.Fatal(got, err)
	}
	selected := []string{"CN", "US"}
	got, err = VerifyCountrySelection(context.Background(), a, selected, countrySelectionInputs(selected, files))
	if err != nil || got.Networks != 4 || len(got.Countries) != 2 {
		t.Fatal("subset coverage differs", got, err)
	}
}

func TestCountrySelectionRejectsDuplicateAndNestedCrossCountryPrefixesEvenWhenEveryFileIsSignedValid(t *testing.T) {
	for _, item := range []struct{ name, code, prefix string }{{"duplicate", "CN", "8.8.8.0/25"}, {"nested-v4", "CN", "8.8.8.0/24"}, {"nested-v6", "AU", "2606:4700::/32"}} {
		t.Run(item.name, func(t *testing.T) {
			m, pub, key, files := countryManifestFixture(t)
			var parent Manifest
			if json.Unmarshal([]byte(m.ParentManifest), &parent) != nil {
				t.Fatal("fixture parent")
			}
			var out bytes.Buffer
			_, err := EncodeCountryCIDR(context.Background(), CountryNetworkExport{ManifestSHA256: hash([]byte(m.ParentManifest)), DatabaseSHA256: parent.SHA256, RecordsVisited: 1, Networks: []CountryNetwork{{netip.MustParsePrefix(item.prefix), item.code}}}, &out)
			if err != nil {
				t.Fatal(err)
			}
			files[item.code] = bytes.Clone(out.Bytes())
			var assets []CountryAsset
			if json.Unmarshal([]byte(m.AssetsJSON), &assets) != nil {
				t.Fatal("fixture assets")
			}
			m.Bytes, m.Networks = 0, 0
			for i := range assets {
				metadata, err := ValidateCountryCIDR(context.Background(), bytes.NewReader(files[assets[i].Code]))
				if err != nil {
					t.Fatal(err)
				}
				assets[i].Bytes, assets[i].Networks, assets[i].SHA256 = metadata.Bytes, metadata.Networks, metadata.SHA256
				m.Bytes += metadata.Bytes
				m.Networks += metadata.Networks
			}
			assetsRaw, _ := json.Marshal(assets)
			m.AssetsJSON = string(assetsRaw)
			raw, sig := signCountryFixture(t, m, key)
			a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
			if err != nil {
				t.Fatal(err)
			}
			codes := []string{"AU", "CH", "CN", "US"}
			for _, code := range codes {
				if _, err := VerifyCountryAsset(context.Background(), a, code, bytes.NewReader(files[code])); err != nil {
					t.Fatal("fixture file not individually signed-valid", code, err)
				}
			}
			got, err := VerifyCountrySelection(context.Background(), a, codes, countrySelectionInputs(codes, files))
			if err == nil || !reflect.DeepEqual(got, CountrySelectionMetadata{}) {
				t.Fatal("ambiguous country set accepted", got, err)
			}
		})
	}
}

func TestCountrySelectionNeverReturnsEarlyFilesOnLateHashLabelTruncationOrContextFailure(t *testing.T) {
	m, pub, key, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, key)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{"AU", "CH", "CN", "US"}
	for _, kind := range []string{"truncated", "extra", "swapped", "missing", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inputs := countrySelectionInputs(codes, files)
			last := len(inputs) - 1
			data := files["US"]
			switch kind {
			case "truncated":
				inputs[last] = bytes.NewReader(data[:len(data)-1])
			case "extra":
				inputs[last] = bytes.NewReader(append(bytes.Clone(data), '\n'))
			case "swapped":
				inputs[last] = bytes.NewReader(files["CN"])
			case "missing":
				inputs[last] = nil
			case "cancelled":
				inputs[last] = io.MultiReader(bytes.NewReader(data[:len(data)/2]), countryCancelReader{cancel})
			}
			got, err := VerifyCountrySelection(ctx, a, codes, inputs)
			if err == nil || !reflect.DeepEqual(got, CountrySelectionMetadata{}) {
				t.Fatal("partial file set accepted", got, err)
			}
			if kind == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was obscured", err)
			}
		})
	}
	if got, err := VerifyCountrySelection(context.Background(), CountryAuthority{}, codes, countrySelectionInputs(codes, files)); err == nil || !reflect.DeepEqual(got, CountrySelectionMetadata{}) {
		t.Fatal("unsigned combined data accepted", got, err)
	}
	if got, err := VerifyCountrySelection(context.Background(), a, codes, countrySelectionInputs(codes[:3], files)); err == nil || !reflect.DeepEqual(got, CountrySelectionMetadata{}) {
		t.Fatal("partial inputs accepted", got, err)
	}
}

type countrySmallRead struct {
	io.Reader
	largest int
}

func (r *countrySmallRead) Read(p []byte) (int, error) {
	if len(p) > r.largest {
		r.largest = len(p)
	}
	if len(p) > 256 {
		return 0, errors.New("stream parser requested unbounded read buffer")
	}
	return r.Reader.Read(p)
}

func TestCountrySelectionKeepsFixedSmallPerFileReadBuffersAndOriginalConsumerBudget(t *testing.T) {
	m, pub, key, files := countryManifestFixture(t)
	raw, sig := signCountryFixture(t, m, key)
	a, err := VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{"AU", "CH", "CN", "US"}
	inputs := make([]io.Reader, len(codes))
	readers := make([]*countrySmallRead, len(codes))
	for i, code := range codes {
		readers[i] = &countrySmallRead{Reader: bytes.NewReader(files[code])}
		inputs[i] = readers[i]
	}
	if _, err := VerifyCountrySelection(context.Background(), a, codes, inputs); err != nil {
		t.Fatal(err)
	}
	for _, reader := range readers {
		if reader.largest < 1 || reader.largest > 256 {
			t.Fatal("per-file stream buffer was not bounded", reader.largest)
		}
	}
	var assets []CountryAsset
	json.Unmarshal([]byte(m.AssetsJSON), &assets)
	assets[0].Networks = maxCountryNetworks
	m.Networks = 0
	for _, asset := range assets {
		m.Networks += asset.Networks
	}
	b, _ := json.Marshal(assets)
	m.AssetsJSON = string(b)
	raw, sig = signCountryFixture(t, m, key)
	a, err = VerifyCountryManifest(raw, sig, pub, fixtureNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyCountrySelection(context.Background(), a, codes, countrySelectionInputs(codes, files)); err == nil || !reflect.DeepEqual(got, CountrySelectionMetadata{}) {
		t.Fatal("publisher capacity granted to consumer", got, err)
	}
}
