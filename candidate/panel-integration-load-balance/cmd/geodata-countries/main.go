// geodata-countries is an OFFLINE PUBLISHER, not a panel request handler.
// stdout is bounded canonical Nginx geo data; stderr success is its metadata.
// Callers must stage exclusively and require exit0 plus independent validation
// before signing any derived manifest. Partial stdout is never an installation.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"local/panel/internal/geodata"
)

func readBounded(name string, limit int64) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, errors.New("publisher input is missing, linked, not regular or outside its fixed budget")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("publisher input changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	visible, visibleErr := os.Lstat(name)
	if err != nil || statErr != nil || visibleErr != nil || !visible.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(opened, visible) || !opened.ModTime().Equal(after.ModTime()) || opened.Size() != after.Size() || int64(len(raw)) != opened.Size() || int64(len(raw)) > limit {
		return nil, errors.New("publisher input changed or read outside its fixed budget")
	}
	return raw, nil
}

func run(ctx context.Context, args []string, output, diagnostic io.Writer) error {
	if ctx == nil || output == nil || diagnostic == nil {
		return errors.New("publisher context or output is missing")
	}
	flags := flag.NewFlagSet("geodata-countries", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	manifestName := flags.String("manifest", "", "authenticated parent manifest")
	signatureName := flags.String("signature", "", "parent detached signature")
	keyName := flags.String("public-key", "", "trusted PUBLISHER PUBLIC key, never a private signing key")
	compressedName := flags.String("compressed", "", "exact signed parent gzip")
	outputDirectory := flags.String("output-directory", "", "new exclusive OFFLINE country-shard staging directory; never an installation path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestName == "" || *signatureName == "" || *keyName == "" || *compressedName == "" {
		return errors.New("all four explicit parent inputs required; no network or fallback input")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	pubRaw, err := readBounded(*keyName, 4096)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(pubRaw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("publisher requires one PUBLIC KEY object")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	pub, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return errors.New("publisher requires an Ed25519 PUBLIC key")
	}
	manifest, err := readBounded(*manifestName, 32<<10)
	if err != nil {
		return err
	}
	signature, err := readBounded(*signatureName, 256)
	if err != nil {
		return err
	}
	authority, err := geodata.VerifyManifest(manifest, signature, pub, time.Now().UTC(), nil)
	if err != nil {
		return err
	}
	// Already signed size/hash/gzip/metadata/full-tree checks remain unchanged.
	compressed, err := readBounded(*compressedName, geodata.MaxCompressedBytes)
	if err != nil {
		return err
	}
	snapshot, err := geodata.Open(ctx, authority, bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	defer snapshot.Close()
	if *outputDirectory != "" {
		return generateShards(ctx, snapshot, manifest, signature, pubRaw, *outputDirectory, output)
	}
	exported, err := snapshot.AllCountryPrefixes(ctx, 1<<20)
	if err != nil {
		return err
	}
	metadata, err := geodata.EncodeCountryCIDR(ctx, exported, output)
	if err != nil {
		return err
	}
	keyDigest := sha256.Sum256(pubRaw)
	return json.NewEncoder(diagnostic).Encode(struct {
		Format                    int                         `json:"format"`
		OfflinePublisherOnly      bool                        `json:"offline_publisher_only"`
		RequiresDerivedSignature  bool                        `json:"requires_derived_original_key_signature_before_install"`
		PublicKeySHA256           string                      `json:"parent_public_key_sha256"`
		ParentManifest            string                      `json:"parent_manifest"`
		ParentSignature           string                      `json:"parent_signature"`
		RecordsVisited            int                         `json:"records_visited"`
		Data                      geodata.CountryCIDRMetadata `json:"data"`
		AttributionURL            string                      `json:"attribution_url"`
		License                   string                      `json:"license"`
		PanelInstallationOrWAFUse bool                        `json:"panel_installation_or_WAF_use"`
		CommercialAll50           bool                        `json:"commercial_all50"`
	}{1, true, true, hex.EncodeToString(keyDigest[:]), string(manifest), string(signature), exported.RecordsVisited, metadata, geodata.AttributionURL, geodata.LicenseURL, false, false})
}

// Standalone format validation is deliberately NOT parent-signature or
// installation authority. A caller still needs its independently authenticated
// derived manifest; these provenance comments cannot provide it.
func validateData(ctx context.Context, input io.Reader, output io.Writer) error {
	if output == nil {
		return errors.New("country data format validator output is missing")
	}
	metadata, err := geodata.ValidateCountryCIDR(ctx, input)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		DataFormatOnly        bool                        `json:"data_format_only"`
		ParentSignatureKnown  bool                        `json:"parent_signature_verified"`
		InstallationAuthority bool                        `json:"installation_authority"`
		Data                  geodata.CountryCIDRMetadata `json:"data"`
	}{true, false, false, metadata})
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var err error
	if len(os.Args) == 2 && os.Args[1] == "-verify-data" {
		err = validateData(ctx, os.Stdin, os.Stdout)
	} else {
		err = run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "offline country generation failed:", err)
		os.Exit(1)
	}
}
