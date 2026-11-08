package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/panel/internal/geodata"
)

func TestCountryPublisherRequiresExplicitClosedOfflineInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"-network", "https://invalid.example"}, {"-manifest", "missing"}, {"-manifest", "m", "-signature", "s", "-compressed", "g", "-public-key", "k", "foreign"}} {
		var output, diagnostic bytes.Buffer
		if err := run(context.Background(), args, &output, &diagnostic); err == nil || output.Len() != 0 {
			t.Fatal("incomplete/extra request accepted or emitted data", args, err)
		}
	}
}

func TestCountryPublisherStandaloneValidatorNeverGrantsSignatureOrInstallAuthority(t *testing.T) {
	var data, output bytes.Buffer
	fixture := geodata.CountryNetworkExport{ManifestSHA256: strings.Repeat("a", 64), DatabaseSHA256: strings.Repeat("b", 64), RecordsVisited: 1, Networks: []geodata.CountryNetwork{{Prefix: netip.MustParsePrefix("8.8.8.0/24"), CountryCode: "US"}}}
	metadata, err := geodata.EncodeCountryCIDR(context.Background(), fixture, &data)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateData(context.Background(), bytes.NewReader(data.Bytes()), &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		DataFormatOnly bool                        `json:"data_format_only"`
		Signature      bool                        `json:"parent_signature_verified"`
		Authority      bool                        `json:"installation_authority"`
		Data           geodata.CountryCIDRMetadata `json:"data"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || !result.DataFormatOnly || result.Signature || result.Authority || result.Data.SHA256 != metadata.SHA256 {
		t.Fatal("unsigned synthetic data became install authority", output.String())
	}
	if err := validateData(context.Background(), bytes.NewReader(data.Bytes()), nil); err == nil {
		t.Fatal("nil output accepted")
	}
}

func TestCountryPublisherRejectsLinkedNonregularAndOversizedInputObjects(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "public")
	if err := os.WriteFile(file, []byte("public test bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked")
	if err := os.Symlink(file, linked); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{linked, dir, filepath.Join(dir, "missing")} {
		if raw, err := readBounded(name, 32); err == nil || raw != nil {
			t.Fatal("linked/nonregular input accepted", name, err)
		}
	}
	if raw, err := readBounded(file, 4); err == nil || raw != nil {
		t.Fatal("input byte capacity widened", err)
	}
	if raw, err := readBounded(file, 32); err != nil || string(raw) != "public test bytes" {
		t.Fatal("ordinary bounded PUBLIC input rejected", err)
	}
}

func TestCountryPublisherNeverAcceptsPrivateKeyObjectsOrEmitsDataOnBadParentAuthority(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for name, data := range map[string][]byte{"public": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "private-type": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic invalid fixture, NOT a key")}), "manifest": []byte("{}\n"), "signature": []byte("bad\n"), "gzip": []byte("not a gzip")} {
		files[name] = filepath.Join(dir, name)
		if err := os.WriteFile(files[name], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"public", "private-type"} {
		var output, diagnostic bytes.Buffer
		err := run(context.Background(), []string{"-public-key", files[key], "-manifest", files["manifest"], "-signature", files["signature"], "-compressed", files["gzip"]}, &output, &diagnostic)
		if err == nil || output.Len() != 0 || strings.Contains(diagnostic.String(), "synthetic invalid fixture") {
			t.Fatal("bad authority produced derived data or printed key content", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, []string{"-public-key", files["public"], "-manifest", files["manifest"], "-signature", files["signature"], "-compressed", files["gzip"]}, &bytes.Buffer{}, &bytes.Buffer{}); !errors.Is(err, context.Canceled) {
		t.Fatal("original cancellation lost", err)
	}
}
