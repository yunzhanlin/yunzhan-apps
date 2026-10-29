package geodata

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// Codec fixtures are synthetic, NOT a claim of provider coverage or WAF use.
func countryCIDRFixture() CountryNetworkExport {
	return CountryNetworkExport{ManifestSHA256: strings.Repeat("a", 64), DatabaseSHA256: strings.Repeat("b", 64), RecordsVisited: 9, Networks: []CountryNetwork{
		{netip.MustParsePrefix("8.8.8.0/24"), "US"},
		{netip.MustParsePrefix("9.9.9.0/24"), "CH"},
		{netip.MustParsePrefix("2001:4860::/32"), "US"},
		{netip.MustParsePrefix("2606:4700::/32"), "AU"},
	}}
}

func TestCountryCIDRCompleteCanonicalRoundTripBindsParentsAndExactBytes(t *testing.T) {
	var b bytes.Buffer
	encoded, err := EncodeCountryCIDR(context.Background(), countryCIDRFixture(), &b)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ValidateCountryCIDR(context.Background(), bytes.NewReader(b.Bytes()))
	if err != nil || !reflect.DeepEqual(encoded, decoded) || encoded.Bytes != int64(b.Len()) || encoded.SHA256 != hash(b.Bytes()) || encoded.Networks != 4 || !reflect.DeepEqual(encoded.Countries, []CountryCIDRCount{{"AU", 1}, {"CH", 1}, {"US", 2}}) {
		t.Fatal("canonical bytes/parent/count identities differ", encoded, decoded, err)
	}
	if !strings.HasSuffix(b.String(), "2606:4700::/32 AU;\n") || !strings.Contains(b.String(), "# parent-manifest-sha256: "+strings.Repeat("a", 64)+"\n") {
		t.Fatal("not closed Nginx geo data")
	}
}

func TestCountryCIDRRejectsDirectivesMalformedTruncatedAndNoncanonicalData(t *testing.T) {
	var b bytes.Buffer
	if _, err := EncodeCountryCIDR(context.Background(), countryCIDRFixture(), &b); err != nil {
		t.Fatal(err)
	}
	valid := b.String()
	cases := map[string]string{
		"empty": "", "header-only": countryCIDRHeader, "truncated": strings.TrimSuffix(valid, "\n"),
		"directive": valid + "include /etc/passwd;\n", "variable": valid + "$remote_addr US;\n", "new-header": strings.Replace(valid, "networks-v1", "networks-v2", 1),
		"blank": valid + "\n", "extra-space": strings.Replace(valid, " US;", "  US;", 1), "long-line": valid + strings.Repeat("a", 257) + "\n",
		"upper-digest": strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1), "lower-code": strings.Replace(valid, " US;", " us;", 1),
		"unknown-code": strings.Replace(valid, " US;", " ZZ;", 1), "CRLF": strings.ReplaceAll(valid, "\n", "\r\n"),
		"host-bits": strings.Replace(valid, "8.8.8.0/24", "8.8.8.1/24", 1), "IPv6-alias": strings.Replace(valid, "2001:4860::/32", "2001:4860:0:0:0:0:0:0/32", 1),
		"private": strings.Replace(valid, "8.8.8.0/24", "10.0.0.0/8", 1), "mixed-private": strings.Replace(valid, "8.8.8.0/24", "8.0.0.0/5", 1),
		"v4-mapped": strings.Replace(valid, "2001:4860::/32", "::ffff:8.8.8.0/120", 1),
		"duplicate": strings.Replace(valid, "9.9.9.0/24 CH;", "8.8.8.0/24 CH;", 1),
		"overlap":   strings.Replace(valid, "9.9.9.0/24 CH;", "8.8.8.0/25 CH;", 1),
		"order":     strings.Replace(valid, "8.8.8.0/24 US;", "9.9.10.0/24 US;", 1),
		"unmerged":  strings.Replace(valid, "8.8.8.0/24 US;", "8.8.8.0/25 US;\n8.8.8.128/25 US;", 1),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ValidateCountryCIDR(context.Background(), strings.NewReader(text))
			if err == nil || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
				t.Fatal("untrusted/partial data accepted", got, err)
			}
		})
	}
}

func TestCountryCIDREncoderPrevalidatesEntireInputBeforeAnyWrite(t *testing.T) {
	for _, kind := range []string{"bad-parent", "missing-records", "bad-last-code", "special-last-prefix", "unsorted", "zero-networks", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			data := countryCIDRFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "bad-parent":
				data.ManifestSHA256 = "missing"
			case "missing-records":
				data.RecordsVisited = 0
			case "bad-last-code":
				data.Networks[len(data.Networks)-1].CountryCode = "US; include private"
			case "special-last-prefix":
				data.Networks[len(data.Networks)-1].Prefix = netip.MustParsePrefix("fc00::/7")
			case "unsorted":
				data.Networks[0], data.Networks[1] = data.Networks[1], data.Networks[0]
			case "zero-networks":
				data.Networks = nil
			case "cancelled":
				cancel()
			}
			var output bytes.Buffer
			got, err := EncodeCountryCIDR(ctx, data, &output)
			if err == nil || output.Len() != 0 || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
				t.Fatal("invalid complete input emitted partial bytes/authority", output.Len(), got, err)
			}
		})
	}
}

type countryFailWriter struct{}

func (countryFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type countryCancelReader struct{ cancel context.CancelFunc }

func (r countryCancelReader) Read([]byte) (int, error) { r.cancel(); return 0, context.Canceled }

func TestCountryCIDRStreamFailureAndCancellationReturnNoAcceptedMetadata(t *testing.T) {
	if got, err := EncodeCountryCIDR(context.Background(), countryCIDRFixture(), countryFailWriter{}); !errors.Is(err, io.ErrClosedPipe) || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
		t.Fatal("short/failed output became accepted metadata", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if got, err := ValidateCountryCIDR(ctx, countryCancelReader{cancel}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, CountryCIDRMetadata{}) {
		t.Fatal("cancelled stream accepted or lost original cancellation", got, err)
	}
	count := countryCIDRBytes{count: MaxCountryCIDRBytes}
	if n, err := count.Write([]byte{1}); n != 0 || err == nil || count.count != MaxCountryCIDRBytes {
		t.Fatal("fixed byte budget widened")
	}
}

func TestAllCountryPrefixesSameVerifiedTreeAndZeroPartialBudget(t *testing.T) {
	snapshot := countryFixture(t, netip.MustParsePrefix("8.8.8.0/24"), true, fixtureRecord())
	selected, err := snapshot.CountryPrefixes(context.Background(), []string{"CN", "US"}, 8)
	if err != nil {
		t.Fatal(err)
	}
	all, err := snapshot.AllCountryPrefixes(context.Background(), 8)
	if err != nil || !reflect.DeepEqual(selected, all) {
		t.Fatal("offline publisher traversal differs from original verified selection", all, err)
	}
	var output bytes.Buffer
	if _, err := EncodeCountryCIDR(context.Background(), all, &output); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, -1, maxCountryNetworks + 1} {
		got, err := snapshot.AllCountryPrefixes(context.Background(), limit)
		if err == nil || !reflect.DeepEqual(got, CountryNetworkExport{}) {
			t.Fatal("publisher bypassed original traversal budget", got, err)
		}
	}
}
