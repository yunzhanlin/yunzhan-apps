//go:build linux

package executor

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestIntrusionFilterMetadataCannotDefaultMissingMalformedOrForeignState(t *testing.T) {
	valid, _ := json.Marshal(intrusionDeclaredFilterMetadata("1.0.2"))
	for name, raw := range map[string]string{
		"empty": "", "missing": `{}`, "unknown-version": strings.Replace(string(valid), "1.0.2", "1.0.3", 1),
		"bad-digest": strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"duplicate":  strings.Replace(string(valid), `"format":1`, `"format":1,"format":1`, 1),
		"case-alias": strings.Replace(string(valid), `"format":1`, `"Format":1`, 1),
		"extra":      strings.Replace(string(valid), `"format":1`, `"format":1,"regex":"private"`, 1),
		"trailing":   string(valid) + `{}`, "oversize": string(valid) + strings.Repeat(" ", 257),
	} {
		t.Run(name, func(t *testing.T) {
			read := func(string, ...string) (string, error) { return raw, nil }
			if value, err := intrusionReadFilterMetadata(read); err == nil || value.Format != 0 {
				t.Fatal("unknown filter certified", value, err)
			}
		})
	}
	if value, err := intrusionReadFilterMetadata(func(program string, args ...string) (string, error) {
		if program != "/usr/bin/fail2ban-client" || strings.Join(args, " ") != "get sshd filter-metadata" {
			t.Fatal("nonfixed metadata key", program, args)
		}
		return string(valid), nil
	}); err != nil || value != intrusionDeclaredFilterMetadata("1.0.2") {
		t.Fatal(value, err)
	}
}

func TestIntrusionFilterAgreementRefusesUnreadLiveStateAndDiskMismatch(t *testing.T) {
	runtime := intrusionEffectiveRuntimeFixture(t, "arm64")
	for _, kind := range []string{"absent", "different-digest", "different-version"} {
		t.Run(kind, func(t *testing.T) {
			var dump intrusionEffectiveDump
			if err := json.Unmarshal(intrusionEffectiveARMFixture, &dump); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "absent":
				dump.FilterMetadata = nil
			case "different-digest":
				dump.FilterMetadata.SHA256 = strings.Repeat("b", 64)
			case "different-version":
				dump.FilterMetadata.Version = "1.1.0"
			}
			raw, _ := json.Marshal(dump)
			if _, err := intrusionEffectiveConfigurationDecode(raw, runtime, runtime.Settings); err == nil {
				t.Fatal("disk/live filter disagreement accepted")
			}
		})
	}
	runtime.FilterMetadata = intrusionFilterMetadata{}
	s := &Service{Config: Config{Run: func(context.Context, string, ...string) (string, error) {
		t.Fatal("missing runtime metadata reached external helper")
		return "", nil
	}}}
	if _, err := s.readIntrusionEffectiveConfiguration(context.Background(), runtime, runtime.Settings); err == nil {
		t.Fatal("missing live metadata acquired authority")
	}
}

func TestIntrusionRuntimeFilterDriftAcrossKernelObservationIsRejected(t *testing.T) {
	s, answers, _ := intrusionRuntimeFixture(t)
	run := s.Config.Run
	changed := false
	s.Config.Run = func(ctx context.Context, program string, args ...string) (string, error) {
		raw, err := run(ctx, program, args...)
		if !changed && program == "/usr/sbin/nft" {
			metadata := intrusionDeclaredFilterMetadata("1.0.2")
			metadata.SHA256 = strings.Repeat("b", 64)
			encoded, _ := json.Marshal(metadata)
			answers["/usr/bin/fail2ban-client get sshd filter-metadata"] = string(encoded)
			changed = true
		}
		return raw, err
	}
	if _, err := s.readIntrusionMutationRuntime(context.Background()); err == nil || !changed {
		t.Fatal("torn filter observation accepted", err)
	}
}

func TestIntrusionFilterFingerprintIsPureClosedAndDoesNotClaimHiddenFlags(t *testing.T) {
	code := `import copy,sys
scope={'__name__':'pure_filter_metadata_test'};exec(compile(sys.stdin.read(),'<pure-filter-metadata>','exec'),scope);fingerprint=scope['filter_metadata_fingerprint']
value={'usedns':'no','prefregex':None,'failregex':['^readable regex$'],'ignoreregex':[],'maxlines':1,'datepattern':[None,'LINE BEGIN'],'ignorecommand':'','ignorecache':None,'ignoreself':True,'ignoreip':[],'logencoding':'UTF-8','logtimezone':None}
original=copy.deepcopy(value);first=fingerprint('1.0.2',value);assert value==original and len(first['sha256'])==64
other=copy.deepcopy(value);other['logencoding']='utf8';other['ignorecommand']=False;other['datepattern']=tuple(other['datepattern']);assert first==fingerprint('1.0.2',other)
assert first!=fingerprint('1.1.0',value)
other=copy.deepcopy(value);other['failregex']=['^changed text$'];assert first!=fingerprint('1.0.2',other)
for field,bad in [('usedns','NO'),('maxlines',True),('maxlines',1025),('failregex',[]),('failregex',['x'*65537]),('ignoreregex',['unseen']),('ignorecommand','echo private'),('ignorecache',{}),('ignoreip',['192.0.2.1']),('ignoreself',False),('logtimezone','UTC'),('datepattern',[]),('hidden_regex_flags',8)]:
 changed=copy.deepcopy(value);changed[field]=bad
 try:fingerprint('1.0.2',changed)
 except Exception:pass
 else:raise AssertionError('unreadable or unsupported filter state accepted: '+field)
print('PURE_FILTER_METADATA_OK')
`
	cmd := exec.Command("/usr/bin/python3", "-I", "-B", "-c", code)
	cmd.Stdin = strings.NewReader(intrusionFilterMetadataScript)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "PURE_FILTER_METADATA_OK" {
		t.Fatal(err, string(out))
	}
}
