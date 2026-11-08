package executor

import (
	"errors"
	"regexp"
	"strings"
)

var threatIDSBuildInfoVersion = regexp.MustCompile(`(?m)^This is Suricata version ([0-9]+\.[0-9]+\.[0-9]+)(?: RELEASE)?$`)

func validateThreatIDSBuildInfo(packageVersion, output string) error {
	packageMatch := threatIDSEngineVersion.FindStringSubmatch(packageVersion)
	versions := threatIDSBuildInfoVersion.FindAllStringSubmatch(output, -1)
	if len(output) > 128<<10 || len(packageMatch) != 4 || len(versions) != 1 || versions[0][1] != packageMatch[1]+"."+packageMatch[2]+"."+packageMatch[3] {
		return errors.New("IDS 实际原生程序版本与已认证包记录不同，或无法唯一核对")
	}
	features := 0
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "Features:") {
			continue
		}
		for _, feature := range strings.Fields(strings.TrimPrefix(line, "Features:")) {
			if feature == "AF_PACKET" {
				features++
			}
		}
	}
	if features != 1 {
		return errors.New("IDS 实际原生程序没有唯一核对的 AF_PACKET 捕获能力")
	}
	return nil
}
