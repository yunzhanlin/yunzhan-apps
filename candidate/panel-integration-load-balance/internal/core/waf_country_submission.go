package core

import (
	"encoding/json"
	"errors"
	"net/url"

	"local/panel/internal/appcatalog"
)

const WAFCountrySubmissionMaxBytes = appcatalog.MaxGeoDataEnvelopeBytes + 8192

type WAFCountryDataSubmission struct {
	Actor     string                     `json:"actor_id"`
	Selection WAFCountryDataSelection    `json:"selection"`
	Envelope  appcatalog.GeoDataEnvelope `json:"envelope"`
}

func DecodeWAFCountryDataSubmission(raw []byte) (WAFCountryDataSubmission, error) {
	var empty WAFCountryDataSubmission
	bad := errors.New("国家数据提交必须完整绑定原账户、原选择和原始签名交付，不能含路径、密钥或激活操作")
	var wire struct {
		Actor     string          `json:"actor_id"`
		Selection json.RawMessage `json:"selection"`
		Envelope  json.RawMessage `json:"envelope"`
	}
	if len(raw) < 1 || len(raw) > WAFCountrySubmissionMaxBytes || !wafInventoryJSONShape(raw, []string{"actor_id", "selection", "envelope"}) || json.Unmarshal(raw, &wire) != nil || !ValidID(wire.Actor) {
		return empty, bad
	}
	selection, err := DecodeWAFCountryDataSelection(wire.Selection)
	if err != nil {
		return empty, bad
	}
	envelope, err := appcatalog.DecodeGeoDataEnvelope(wire.Envelope)
	if err != nil {
		return empty, bad
	}
	return WAFCountryDataSubmission{wire.Actor, selection, envelope}, nil
}

func WAFCountryObservationQuery(actor, payloadSHA string) url.Values {
	return url.Values{"actor_id": {actor}, "payload_sha256": {payloadSHA}}
}

func ParseWAFCountryObservationQuery(q url.Values) (string, string, error) {
	if len(q) != 2 || len(q["actor_id"]) != 1 || len(q["payload_sha256"]) != 1 || !ValidID(q.Get("actor_id")) || !validLowerSHA256(q.Get("payload_sha256")) {
		return "", "", errors.New("国家数据原任务只读查询必须绑定唯一原账户与完整内容摘要")
	}
	return q.Get("actor_id"), q.Get("payload_sha256"), nil
}

type WAFCountryDataState struct {
	Installed                    bool   `json:"installed"`
	AppVersion                   string `json:"app_version"`
	InstallationSHA              string `json:"installation_sha256"`
	Supported                    bool   `json:"supported"`
	MaxCountries                 int    `json:"max_countries"`
	MaxBytes                     int64  `json:"max_bytes"`
	MaxNetworks                  int    `json:"max_networks"`
	DownloadsDoNotActivatePolicy bool   `json:"downloads_do_not_activate_policy"`
}

func DecodeWAFCountryDataState(raw []byte) (WAFCountryDataState, error) {
	var out WAFCountryDataState
	bad := errors.New("国家数据安装状态、实例或固定容量无法完整核对")
	fields := []string{"installed", "app_version", "installation_sha256", "supported", "max_countries", "max_bytes", "max_networks", "downloads_do_not_activate_policy"}
	if len(raw) < 1 || len(raw) > 4096 || !wafInventoryJSONShape(raw, fields) || json.Unmarshal(raw, &out) != nil || out.MaxCountries != 32 || out.MaxBytes != 64<<20 || out.MaxNetworks != 1<<20 || !out.DownloadsDoNotActivatePolicy {
		return WAFCountryDataState{}, bad
	}
	if !out.Installed {
		if out.AppVersion != "" || out.InstallationSHA != "" || out.Supported {
			return WAFCountryDataState{}, bad
		}
		return out, nil
	}
	if _, valid := appcatalog.CompareVersions(out.AppVersion, "0.0.0"); !valid {
		return WAFCountryDataState{}, bad
	}
	if out.Supported && (out.AppVersion != WAFCountryDataVersion || !validLowerSHA256(out.InstallationSHA)) || !out.Supported && out.InstallationSHA != "" {
		return WAFCountryDataState{}, bad
	}
	return out, nil
}
