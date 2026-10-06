package core

import "testing"

func TestApacheWAFRejectsUnsupportedRateControls(t *testing.T) {
	cfg := DefaultApacheWAFConfig()
	if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err != nil {
		t.Fatal(err)
	}
	cfg.Policy.CCEnabled = true
	if _, err := DecodeApacheWAFConfig(WAFSettings(cfg)); err == nil {
		t.Fatal("unsupported CC falsely accepted")
	}
}
