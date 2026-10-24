//go:build linux

package executor

import (
	_ "embed"
	"encoding/json"
	"errors"
	"regexp"
)

//go:embed intrusion_filter_metadata.py
var intrusionFilterMetadataScript string

//go:embed intrusion_filter_projection.py
var intrusionFilterProjectionScript string

type intrusionFilterMetadata struct {
	Format  int    `json:"format"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// json's case-insensitive struct aliases are not this private wire schema.
// Retain duplicate/depth/trailing-data guards and require all three exact keys
// even when this descriptor is nested inside a complete configuration dump.
func (value *intrusionFilterMetadata) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if len(raw) > 256 || decodeProgramQueueJSON(raw, &fields) != nil || len(fields) != 3 || fields["format"] == nil || fields["version"] == nil || fields["sha256"] == nil {
		return errors.New("过滤器元数据不是三个规范命名字段")
	}
	type literal intrusionFilterMetadata
	var decoded literal
	if err := decodeProgramQueueJSON(raw, &decoded); err != nil || !intrusionFilterMetadataValid(intrusionFilterMetadata(decoded)) {
		return errors.New("过滤器元数据格式、摘要或版本无效")
	}
	*value = intrusionFilterMetadata(decoded)
	return nil
}

var intrusionFilterDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func intrusionFilterMetadataValid(value intrusionFilterMetadata) bool {
	return value.Format == 1 && (value.Version == "1.0.2" || value.Version == "1.1.0") && intrusionFilterDigest.MatchString(value.SHA256)
}

func intrusionReadFilterMetadata(read func(string, ...string) (string, error)) (intrusionFilterMetadata, error) {
	var value intrusionFilterMetadata
	raw, err := read("/usr/bin/fail2ban-client", "get", "sshd", "filter-metadata")
	if err != nil || len(raw) > 256 || decodeProgramQueueJSON([]byte(raw), &value) != nil || !intrusionFilterMetadataValid(value) {
		return intrusionFilterMetadata{}, errors.New("运行中过滤器可读元数据无法完整核对，未猜测默认匹配规则")
	}
	return value, nil
}
