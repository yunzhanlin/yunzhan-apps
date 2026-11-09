package executor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

const loadBalanceStreamModuleLimit = 4 << 20

var errLoadBalanceStreamModule = errors.New("TCP/UDP 安装原记录、完整备份或发布身份无法核对；保留原始结果，不接管、覆盖不明记录或重放")

// A bounded, duplicate-aware decoder shared by the proposal and the held Root
// publisher. It neither reads a host path nor supplies installation authority.
// Numbers in legacy settings remain json.Number, not lossy float64 values.
func decodeLoadBalanceStreamModule(raw []byte) (map[string]any, error) {
	return decodeLoadBalanceStreamModuleVersion(raw, false)
}

// The read-only programme-upgrade fence must recognize pre-1.9 HTTP history,
// including pre-versioned records. This does NOT authorize native migration:
// the effect-side proposal/held publisher still call the strict decoder above.
func decodeLoadBalanceStreamModuleVersion(raw []byte, legacyInventory bool) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > loadBalanceStreamModuleLimit {
		return nil, errLoadBalanceStreamModule
	}
	fields := map[string]bool{"id": true, "version": true, "settings": true, "installed_at": true, "updated_at": true, "installation_id": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var visit func(int) error
	visit = func(depth int) error {
		nodes++
		if depth > 16 || nodes > 100000 {
			return errLoadBalanceStreamModule
		}
		token, err := d.Token()
		if err != nil {
			return errLoadBalanceStreamModule
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			if depth == 0 {
				return errLoadBalanceStreamModule
			}
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err := d.Token()
				key, ok := token.(string)
				if err != nil || !ok || seen[strings.ToLower(key)] || depth == 0 && !fields[key] {
					return errLoadBalanceStreamModule
				}
				seen[strings.ToLower(key)] = true
				if visit(depth+1) != nil {
					return errLoadBalanceStreamModule
				}
			}
		case '[':
			if depth == 0 {
				return errLoadBalanceStreamModule
			}
			for d.More() {
				if visit(depth+1) != nil {
					return errLoadBalanceStreamModule
				}
			}
		default:
			return errLoadBalanceStreamModule
		}
		end, err := d.Token()
		if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
			return errLoadBalanceStreamModule
		}
		return nil
	}
	if visit(0) != nil {
		return nil, errLoadBalanceStreamModule
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errLoadBalanceStreamModule
	}
	var record map[string]any
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&record) != nil || record["id"] != "load-balance" {
		return nil, errLoadBalanceStreamModule
	}
	version, ok := record["version"].(string)
	if !ok || version != "1.8.4" && version != "1.8.5" && version != loadbalancestream.AppVersion && !(legacyInventory && !loadBalanceStreamIndependentLifecycle(version)) {
		return nil, errLoadBalanceStreamModule
	}
	if settings, present := record["settings"]; present && settings != nil {
		if _, ok := settings.(map[string]any); !ok {
			return nil, errLoadBalanceStreamModule
		}
	}
	for _, field := range []string{"installed_at", "updated_at"} {
		if value, exists := record[field]; exists {
			stamp, ok := value.(string)
			when, err := time.Parse(time.RFC3339, stamp)
			if !ok || err != nil || when.Year() < 2026 || when.UTC().Format(time.RFC3339) != stamp || when.After(time.Now().Add(time.Second)) {
				return nil, errLoadBalanceStreamModule
			}
		}
	}
	if first, ok := record["installed_at"].(string); ok {
		if last, ok := record["updated_at"].(string); ok && last < first {
			return nil, errLoadBalanceStreamModule
		}
	}
	epoch, hasEpoch := record["installation_id"]
	if version == loadbalancestream.AppVersion {
		value, ok := epoch.(string)
		if !hasEpoch || !ok || !core.ValidID(value) {
			return nil, errLoadBalanceStreamModule
		}
	} else if hasEpoch {
		return nil, errLoadBalanceStreamModule
	}
	return record, nil
}

// Serialization only. The actual controller must retain the COMPLETE original
// bytes before publishing, hold the fixed module and original journal leases,
// verify live Core/signature/identity authority, and recheck the original inode.
// HTTP entries live separately and are never interpreted as stream listeners.
func loadBalanceStreamModuleProposal(seedRaw, original []byte, now time.Time) ([]byte, error) {
	seed, err := loadbalancestream.DecodeInstallationSeed(seedRaw)
	created, clockErr := time.Parse(time.RFC3339, seed.JobCreatedAt)
	if err != nil || clockErr != nil || now.IsZero() || now.Before(created) || now.After(time.Now().Add(time.Second)) {
		return nil, errLoadBalanceStreamModule
	}
	record := map[string]any{"id": "load-balance", "settings": map[string]any{}, "installed_at": seed.JobCreatedAt}
	if seed.Action == "install" {
		if len(original) != 0 {
			return nil, errLoadBalanceStreamModule
		}
	} else {
		if core.Hash(string(original)) != seed.OriginalModuleSHA256 {
			return nil, errLoadBalanceStreamModule
		}
		record, err = decodeLoadBalanceStreamModule(original)
		if err != nil || record["version"] != seed.OriginalModuleVersion {
			return nil, errLoadBalanceStreamModule
		}
		if stamp, exists := record["installed_at"]; exists {
			when, err := time.Parse(time.RFC3339, stamp.(string))
			if err != nil || when.After(now) {
				return nil, errLoadBalanceStreamModule
			}
		} else {
			record["installed_at"] = seed.JobCreatedAt
		}
	}
	if record["version"] != loadbalancestream.AppVersion {
		record["installation_id"] = seed.Nonce
	}
	record["version"] = loadbalancestream.AppVersion
	record["updated_at"] = now.UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil || len(raw)+1 > loadBalanceStreamModuleLimit {
		return nil, errLoadBalanceStreamModule
	}
	raw = append(raw, '\n')
	if _, err = decodeLoadBalanceStreamModule(raw); err != nil {
		return nil, errLoadBalanceStreamModule
	}
	return raw, nil
}
