//go:build linux

package executor

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/runtimecatalog"
)

func TestLoadBalanceStreamEngineManifestLegacyFormattingDoesNotChangeTrust(t *testing.T) {
	r, ok := runtimecatalog.Find("nginx-1.30.6")
	if !ok {
		t.Fatal("reviewed native fixture release missing")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		original := RuntimeManifest{Release: r, Architecture: arch, InstalledAt: "2026-10-21T09:22:57Z", Extensions: []string{"stream", "stream_ssl_module"}, Configure: []string{"--prefix=" + r.Prefix(), "--with-stream", "--with-stream_ssl_module"}}
		compact, _ := json.Marshal(original)
		pretty, _ := json.MarshalIndent(original, "", "  ")
		for _, raw := range [][]byte{compact, pretty, append(bytes.Clone(pretty), '\n')} {
			before := bytes.Clone(raw)
			got, err := validateLoadBalanceStreamEngineManifest(raw, r, arch)
			if err != nil || !reflect.DeepEqual(got, original) || !bytes.Equal(before, raw) {
				t.Fatal("known historical JSON formatting was rejected, changed or granted different content", err)
			}
		}
		for _, fault := range []string{"source", "architecture", "config", "extensions", "clock", "unknown", "duplicate", "case-duplicate", "trailing"} {
			t.Run(arch+"/"+fault, func(t *testing.T) {
				v := original
				v.Extensions = append([]string(nil), original.Extensions...)
				v.Configure = append([]string(nil), original.Configure...)
				switch fault {
				case "source":
					v.Release.SHA256 = strings.Repeat("1", 64)
				case "architecture":
					v.Architecture = "wrong"
				case "config":
					v.Configure = []string{"--with-stream_ssl_module"}
				case "extensions":
					v.Extensions = []string{"stream"}
				case "clock":
					v.InstalledAt = "2099-10-21T09:22:57Z"
				}
				raw, _ := json.MarshalIndent(v, "", "  ")
				switch fault {
				case "unknown":
					raw = bytes.Replace(raw, []byte(`"release": {`), []byte(`"unknown":true,"release": {`), 1)
				case "duplicate":
					raw = bytes.Replace(raw, []byte(`"architecture":`), []byte(`"architecture":"`+arch+`","architecture":`), 1)
				case "case-duplicate":
					raw = bytes.Replace(raw, []byte(`"architecture":`), []byte(`"Architecture":"`+arch+`","architecture":`), 1)
				case "trailing":
					raw = append(raw, []byte(`{}`)...)
				}
				if _, err := validateLoadBalanceStreamEngineManifest(raw, r, arch); err == nil {
					t.Fatal("ambiguous or unreviewed native manifest accepted", fault)
				}
			})
		}
	}
}
