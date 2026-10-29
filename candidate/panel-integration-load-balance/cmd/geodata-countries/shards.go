package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"

	"local/panel/internal/geodata"
)

const maxCountryPublisherBytes int64 = 256 << 20

type countryShardReceipt struct {
	Code string                      `json:"code"`
	File string                      `json:"file"`
	Data geodata.CountryCIDRMetadata `json:"data"`
}

type countryPublisherReceipt struct {
	Format                    int                   `json:"format"`
	OfflinePublisherOnly      bool                  `json:"offline_publisher_only"`
	RequiresDerivedSignature  bool                  `json:"requires_derived_original_key_signature_before_install"`
	PublicKeySHA256           string                `json:"parent_public_key_sha256"`
	ParentManifest            string                `json:"parent_manifest"`
	ParentSignature           string                `json:"parent_signature"`
	RecordsVisited            int                   `json:"records_visited"`
	Networks                  int                   `json:"networks"`
	Bytes                     int64                 `json:"bytes"`
	Files                     []countryShardReceipt `json:"files"`
	License                   string                `json:"license"`
	AttributionURL            string                `json:"attribution_url"`
	ElapsedSeconds            float64               `json:"elapsed_seconds"`
	HeapLiveBytes             uint64                `json:"heap_live_bytes"`
	AllocatedBytes            uint64                `json:"allocated_bytes"`
	PanelInstallationOrWAFUse bool                  `json:"panel_installation_or_WAF_use"`
	CommercialAll50           bool                  `json:"commercial_all50"`
}

// Only an EXPLICIT new publisher directory. No mkdir-all, repair, overwrite,
// app path, command, key signing or activation. Errors preserve private partial
// output. Only complete independently checked data receives a receipt. An
// unknown stdout result must inspect that original receipt, never overwrite
// it or infer installation/signature authority.
func generateShards(ctx context.Context, snapshot *geodata.Snapshot, manifest, signature, pub []byte, directory string, output io.Writer) error {
	if ctx == nil || output == nil || directory == "" || filepath.Clean(directory) != directory {
		return errors.New("offline shard staging path/context invalid")
	}
	started := time.Now()
	shards, err := snapshot.CountryShards(ctx)
	if err != nil {
		return err
	}
	if len(shards.Shards) == 0 || shards.Networks < 1 {
		return errors.New("offline country shards contain no public coverage")
	}
	parentHash := sha256.Sum256(manifest)
	if hex.EncodeToString(parentHash[:]) != shards.ManifestSHA256 {
		return errors.New("offline shard source manifest differs from authenticated snapshot")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stage, err := openCountryPublisherStage(directory)
	if err != nil {
		return err
	}
	defer stage.Close()
	root := stage.root
	write := func(name string, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		if _, err = f.Write(raw); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	keyHash := sha256.Sum256(pub)
	receipt := countryPublisherReceipt{Format: 1, OfflinePublisherOnly: true, RequiresDerivedSignature: true, PublicKeySHA256: hex.EncodeToString(keyHash[:]), ParentManifest: string(manifest), ParentSignature: string(signature), RecordsVisited: shards.RecordsVisited, Networks: shards.Networks, Files: []countryShardReceipt{}, License: geodata.LicenseURL, AttributionURL: geodata.AttributionURL}
	count := 0
	for i, shard := range shards.Shards {
		if err := ctx.Err(); err != nil {
			return err
		}
		code := shard.Code
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || i > 0 && shards.Shards[i-1].Code >= code {
			return errors.New("offline shard code or ordering invalid")
		}
		name := code + ".cidr"
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		metadata, err := geodata.EncodeCountryCIDR(ctx, shard.Data, f)
		if err == nil {
			err = f.Sync()
		}
		if err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
		var validated geodata.CountryCIDRMetadata
		if err == nil {
			validated, err = geodata.ValidateCountryCIDR(ctx, f)
		}
		info, statErr := f.Stat()
		visible, visibleErr := root.Lstat(name)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if statErr != nil || visibleErr != nil || !visible.Mode().IsRegular() || !os.SameFile(info, visible) || info.Mode().Perm() != 0600 || info.Size() != metadata.Bytes || !reflect.DeepEqual(validated, metadata) || len(metadata.Countries) != 1 || metadata.Countries[0].Code != code || metadata.ParentManifestSHA256 != shards.ManifestSHA256 || metadata.ParentDatabaseSHA256 != shards.DatabaseSHA256 {
			return errors.New("offline shard independent readback or original identity differs")
		}
		receipt.Bytes += metadata.Bytes
		count += metadata.Networks
		if receipt.Bytes > maxCountryPublisherBytes {
			return errors.New("offline publisher aggregate bytes exceeded; no success receipt")
		}
		receipt.Files = append(receipt.Files, countryShardReceipt{code, name, metadata})
	}
	if count != shards.Networks {
		return errors.New("offline publisher lost or duplicated country coverage")
	}
	for name, raw := range map[string][]byte{"parent-manifest.json": manifest, "parent-manifest.sig": signature, "parent-public.pem": pub, "NOTICE.txt": []byte("IP location data by DB-IP.\n" + geodata.AttributionURL + "\nLicense: " + geodata.LicenseURL + "\nDerived country CIDR shards; source identity is recorded in parent-manifest.json.\nNo installation authority without a separately trusted derived signature.\n")} {
		if err := write(name, raw); err != nil {
			return err
		}
	}
	if err := stage.Current(); err != nil {
		return err
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	receipt.HeapLiveBytes = memory.HeapAlloc
	receipt.AllocatedBytes = memory.TotalAlloc
	receipt.ElapsedSeconds = time.Since(started).Seconds()
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := write("generation.json", raw); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := output.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}
