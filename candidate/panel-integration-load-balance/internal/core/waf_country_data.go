package core

import (
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// This is the closed DATA-only protocol for the unfinished country feature.
// It is not WAFVersion and must not advertise availability or enable a rule.
const WAFCountryDataVersion = "2.6.0"

type WAFCountryDataSelection struct {
	Action          string   `json:"action"`
	AppVersion      string   `json:"app_version"`
	AppManifestSHA  string   `json:"app_manifest_sha256"`
	InstallationSHA string   `json:"installation_sha256"`
	Release         string   `json:"release"`
	Revision        int      `json:"revision"`
	DataManifestSHA string   `json:"data_manifest_sha256"`
	Countries       []string `json:"countries"`
}

var wafCountrySelectionFields = []string{"action", "app_version", "app_manifest_sha256", "installation_sha256", "release", "revision", "data_manifest_sha256", "countries"}

func ValidateWAFCountryDataSelection(in WAFCountryDataSelection) error {
	bad := errors.New("国家数据任务只允许下载明确签名的国家集合，不得启用规则、指定路径或更换应用实例")
	if in.Action != "download" || in.AppVersion != WAFCountryDataVersion || !validLowerSHA256(in.AppManifestSHA) || !validLowerSHA256(in.InstallationSHA) || !validLowerSHA256(in.DataManifestSHA) || !statisticsGeoMonth.MatchString(in.Release) || in.Revision < 1 || in.Revision > 1000 || len(in.Countries) < 1 || len(in.Countries) > 32 {
		return bad
	}
	previous := ""
	for _, code := range in.Countries {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || code <= previous {
			return bad
		}
		previous = code
	}
	return nil
}

func DecodeWAFCountryDataSelection(raw []byte) (WAFCountryDataSelection, error) {
	var in WAFCountryDataSelection
	bad := errors.New("国家数据请求含缺失、重复、未知、空值或非规范字段")
	if len(raw) < 1 || len(raw) > 2048 || !wafInventoryJSONShape(raw, wafCountrySelectionFields) || json.Unmarshal(raw, &in) != nil || ValidateWAFCountryDataSelection(in) != nil {
		return WAFCountryDataSelection{}, bad
	}
	return in, nil
}

func SameWAFCountryDataSelection(a, b WAFCountryDataSelection) bool {
	return ValidateWAFCountryDataSelection(a) == nil && ValidateWAFCountryDataSelection(b) == nil && reflect.DeepEqual(a, b)
}

func WAFCountryDataSelectionQuery(in WAFCountryDataSelection) url.Values {
	return url.Values{"action": {in.Action}, "app_version": {in.AppVersion}, "app_manifest_sha256": {in.AppManifestSHA}, "installation_sha256": {in.InstallationSHA}, "release": {in.Release}, "revision": {strconv.Itoa(in.Revision)}, "data_manifest_sha256": {in.DataManifestSHA}, "countries": {strings.Join(in.Countries, ",")}}
}

func ParseWAFCountryDataSelectionQuery(q url.Values) (WAFCountryDataSelection, error) {
	var in WAFCountryDataSelection
	bad := errors.New("国家数据查询绑定含重复、未知或非规范字段")
	if len(q) != len(wafCountrySelectionFields) {
		return in, bad
	}
	for _, field := range wafCountrySelectionFields {
		if len(q[field]) != 1 || len(q[field][0]) > 1024 {
			return in, bad
		}
	}
	revision, err := strconv.Atoi(q.Get("revision"))
	if err != nil || q.Get("revision") != strconv.Itoa(revision) {
		return in, bad
	}
	in = WAFCountryDataSelection{q.Get("action"), q.Get("app_version"), q.Get("app_manifest_sha256"), q.Get("installation_sha256"), q.Get("release"), revision, q.Get("data_manifest_sha256"), strings.Split(q.Get("countries"), ",")}
	if err := ValidateWAFCountryDataSelection(in); err != nil {
		return WAFCountryDataSelection{}, bad
	}
	return in, nil
}
