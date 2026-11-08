//go:build linux

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamInstallationsRoot = "/var/lib/panel-executor/load-balance-stream-installations"

// Durable original installation evidence, NOT an API capability, a listener
// health claim or permission to resume an interrupted parent. Runtime starts
// belong to the separate original configuration controller. A completed empty
// install must never say that a traffic process was provisioned or activated.
type loadBalanceStreamInstallationReceipt struct {
	Format                   int    `json:"format"`
	InstallationID           string `json:"installation_id"`
	JobID                    string `json:"job_id"`
	Version                  string `json:"version"`
	SeedSHA256               string `json:"seed_sha256"`
	FinalEventSHA256         string `json:"final_event_sha256"`
	PublishedModuleSHA256    string `json:"published_module_sha256"`
	AccountReceiptSHA256     string `json:"account_receipt_sha256"`
	NSSSHA256                string `json:"nss_sha256"`
	ProgrammeInputsSHA256    string `json:"programme_inputs_sha256"`
	NginxReleaseID           string `json:"nginx_release_id"`
	NginxSHA256              string `json:"nginx_sha256"`
	NginxManifestSHA256      string `json:"nginx_manifest_sha256"`
	EmptyConfigurationSHA256 string `json:"empty_configuration_sha256"`
	RuntimeProvisioned       bool   `json:"runtime_provisioned"`
}

func streamInstallationReceiptBytes(v loadBalanceStreamInstallationReceipt) ([]byte, error) {
	if v.Format != 1 || !core.ValidID(v.InstallationID) || !core.ValidID(v.JobID) || v.Version != loadbalancestream.AppVersion || v.RuntimeProvisioned || v.NginxReleaseID != "nginx-1.30.6" && v.NginxReleaseID != "nginx-1.31.5" {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	for _, h := range []string{v.SeedSHA256, v.FinalEventSHA256, v.PublishedModuleSHA256, v.AccountReceiptSHA256, v.NSSSHA256, v.ProgrammeInputsSHA256, v.NginxSHA256, v.NginxManifestSHA256, v.EmptyConfigurationSHA256} {
		if !loadBalanceStreamAccountHash(h) {
			return nil, errLoadBalanceStreamInstallationJournal
		}
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 8191 {
		return nil, errLoadBalanceStreamInstallationJournal
	}
	return append(raw, '\n'), nil
}

func decodeStreamInstallationReceipt(raw []byte) (loadBalanceStreamInstallationReceipt, error) {
	var v loadBalanceStreamInstallationReceipt
	if len(raw) == 0 || len(raw) > 8192 || json.Unmarshal(raw, &v) != nil {
		return v, errLoadBalanceStreamInstallationJournal
	}
	canonical, err := streamInstallationReceiptBytes(v)
	if err != nil || !bytes.Equal(raw, canonical) {
		return loadBalanceStreamInstallationReceipt{}, errLoadBalanceStreamInstallationJournal
	}
	return v, nil
}

func writeStreamInstallationReceipt(ctx context.Context, v loadBalanceStreamInstallationReceipt, authorize func(context.Context) error) error {
	raw, err := streamInstallationReceiptBytes(v)
	if ctx == nil || ctx.Err() != nil || err != nil || authorize == nil || authorize(ctx) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	root, err := openLoadBalanceStreamFixedRoot(loadBalanceStreamInstallationsRoot, true)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	entries, readErr := dir.ReadDir(129)
	dir.Close()
	if readErr != nil && readErr != io.EOF || len(entries) >= 128 {
		return errLoadBalanceStreamInstallationJournal
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if !strings.HasSuffix(entry.Name(), ".json") || !core.ValidID(strings.TrimSuffix(entry.Name(), ".json")) || err != nil || !streamJournalFileInfo(info, 8192) {
			return errLoadBalanceStreamInstallationJournal
		}
	}
	if authorize(ctx) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	f, err := root.OpenFile(v.InstallationID+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	defer f.Close()
	if f.Chown(0, 0) != nil || f.Chmod(0600) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	if n, err := f.Write(raw); err != nil || n != len(raw) || f.Sync() != nil || ruleFeedStoreSync(root) != nil || authorize(ctx) != nil {
		return errLoadBalanceStreamInstallationJournal
	}
	if !streamModulePublicationMatches(root, v.InstallationID+".json", raw) {
		return errLoadBalanceStreamInstallationJournal
	}
	return nil
}

func loadBalanceStreamAccountReceiptHash(ctx context.Context) (loadBalanceStreamIdentity, string, error) {
	identity, err := loadBalanceStreamManagedSystemIdentity(ctx)
	if err != nil {
		return loadBalanceStreamIdentity{}, "", err
	}
	store, err := openLoadBalanceStreamAccountStoreAt(loadBalanceStreamAccountStorePath)
	if err != nil {
		return loadBalanceStreamIdentity{}, "", err
	}
	defer store.root.Close()
	record, err := store.read("account.json")
	if err != nil {
		return loadBalanceStreamIdentity{}, "", err
	}
	defer record.close()
	receipt, err := decodeLoadBalanceStreamAccountReceipt(record.bytes())
	if err != nil || receipt.UID != identity.UID || receipt.GID != identity.GID || receipt.NSSSHA != identity.SHA256 || !record.current() || ctx.Err() != nil {
		return loadBalanceStreamIdentity{}, "", errLoadBalanceStreamAccount
	}
	return identity, core.Hash(string(record.bytes())), nil
}
