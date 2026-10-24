package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func runtimeMagicFixture(data []byte, nonString bool) []byte {
	var b strings.Builder
	b.WriteString(runtimeMagicHeader)
	fmt.Fprintf(&b, "const unsigned char php_magic_database[%d]", len(data))
	if nonString {
		b.WriteString(" ZEND_NONSTRING")
	}
	b.WriteString(" = {\n")
	for _, value := range data {
		fmt.Fprintf(&b, "0x%02X, ", value)
	}
	b.WriteString("};\n")
	return []byte(b.String())
}

// Independent decoder: no call to the production source parser and no C
// execution. Native tests separately check the real compiler's ELF symbol.
func runtimeMagicDecodeTestOutput(t *testing.T, out []byte, size int, nonString bool) []byte {
	t.Helper()
	tag := "const unsigned char php_magic_database[" + strconv.Itoa(size) + "]"
	if nonString {
		tag += " ZEND_NONSTRING"
	}
	tag += " =\n"
	index := bytes.Index(out, []byte(tag))
	if index < 0 || bytes.Count(out, []byte("const unsigned char")) != 1 {
		t.Fatal("original exact array length, declaration or qualifier lost")
	}
	lines := strings.Split(strings.TrimSuffix(string(out[index+len(tag):]), ";\n"), "\n")
	var decoded []byte
	for _, line := range lines {
		if line == "" {
			continue
		}
		if len(line) < 6 || line[0] != '"' || line[len(line)-1] != '"' || (len(line)-2)%4 != 0 || len(line)-2 > 4096 {
			t.Fatal("noncanonical or oversized C string token")
		}
		for i := 1; i < len(line)-1; i += 4 {
			if line[i] != '\\' || line[i+1] < '0' || line[i+1] > '3' || line[i+2] < '0' || line[i+2] > '7' || line[i+3] < '0' || line[i+3] > '7' {
				t.Fatal("ambiguous, invalid or overflowing octal escape")
			}
			decoded = append(decoded, (line[i+1]-'0')*64+(line[i+2]-'0')*8+(line[i+3]-'0'))
		}
	}
	if len(decoded) != size {
		t.Fatalf("payload length changed: %d != %d", len(decoded), size)
	}
	return decoded
}

func TestRuntimeMagicBuildRepresentationRetainsEveryByteAndExactArraySize(t *testing.T) {
	var alphabet []byte
	for i := 0; i < 256; i++ {
		alphabet = append(alphabet, byte(i))
	}
	for _, size := range []int{1, 255, 256, 1023, 1024, 1025, 4097} {
		for _, nonString := range []bool{false, true} {
			data := make([]byte, size)
			for i := range data {
				data[i] = alphabet[i%len(alphabet)]
			}
			input := runtimeMagicFixture(data, nonString)
			original := append([]byte(nil), input...)
			out, digest, err := runtimeMagicStringSource(input, len(data), nonString)
			if err != nil {
				t.Fatal(err)
			}
			wantSHA := sha256.Sum256(data)
			if !bytes.Equal(input, original) || digest != hex.EncodeToString(wantSHA[:]) ||
				!bytes.Equal(runtimeMagicDecodeTestOutput(t, out, len(data), nonString), data) {
				t.Fatal("raw source modified, byte changed or implicit NUL/padding introduced")
			}
			again, nextSHA, err := runtimeMagicStringSource(input, len(data), nonString)
			if err != nil || nextSHA != digest || !bytes.Equal(out, again) {
				t.Fatal("build representation is not deterministic")
			}
		}
	}
}

func TestRuntimeMagicBuildRepresentationRejectsUnknownOrPartialC(t *testing.T) {
	valid := string(runtimeMagicFixture([]byte{0, 10, 255}, false))
	for name, input := range map[string]string{
		"missing-header":              strings.TrimPrefix(valid, runtimeMagicHeader),
		"size-mismatch":               strings.Replace(valid, "[3]", "[2]", 1),
		"qualifier-mismatch":          strings.Replace(valid, "[3]", "[3] ZEND_NONSTRING", 1),
		"lowercase-unreviewed-format": strings.Replace(valid, "0xFF", "0xff", 1),
		"missing-comma":               strings.Replace(valid, "0x0A,", "0x0A", 1),
		"short-literal":               strings.Replace(valid, "0x0A", "0xA", 1),
		"long-literal":                strings.Replace(valid, "0x0A", "0x10A", 1),
		"invalid-hex":                 strings.Replace(valid, "0xFF", "0xGG", 1),
		"vertical-whitespace":         strings.Replace(valid, "0x0A", "\v0x0A", 1),
		"form-feed":                   strings.Replace(valid, "0x0A", "\f0x0A", 1),
		"unicode-space":               strings.Replace(valid, "0x0A", "\u00a00x0A", 1),
		"extra-byte":                  strings.Replace(valid, "};", "0x01, };", 1),
		"missing-byte":                strings.Replace(valid, "0xFF,", "", 1),
		"truncated-footer":            strings.TrimSuffix(valid, "};\n"),
		"trailing-code":               valid + "int injected = 1;\n",
		"duplicate-array":             valid + valid,
	} {
		t.Run(name, func(t *testing.T) {
			out, hash, err := runtimeMagicStringSource([]byte(input), 3, false)
			if err == nil || out != nil || hash != "" {
				t.Fatal("partial or unknown C accepted")
			}
		})
	}
	for _, size := range []int{-1, 0, 16<<20 + 1} {
		if _, _, err := runtimeMagicStringSource([]byte(valid), size, false); err == nil {
			t.Fatal("size bound bypassed")
		}
	}
}

func TestRuntimeMagicBuildRepresentationPinsOnlyTheTwoAffectedOfficialSources(t *testing.T) {
	for _, id := range []string{"php-8.2.35", "php-8.3.36"} {
		spec, ok := runtimeMagicSpecification(id)
		if !ok || len(spec.archiveSHA) != 64 || len(spec.inputSHA) != 64 || len(spec.dataSHA) != 64 ||
			spec.rawBytes < spec.dataBytes*5 || spec.rawBytes > 64<<20 || spec.dataBytes > 16<<20 {
			t.Fatal("unbound official input", id)
		}
		out := []byte("owned model output")
		record := runtimeMagicTransformRecord(spec, out)
		digest := sha256.Sum256(out)
		if record.ID != runtimeMagicTransformID || record.Path != runtimeMagicPath || record.UpstreamCommit != runtimeMagicUpstreamCommit ||
			record.InputSHA256 != spec.inputSHA || record.DataSHA256 != spec.dataSHA || record.DataBytes != spec.dataBytes || record.OutputSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatal("build provenance dropped")
		}
	}
	for _, id := range []string{"php-8.2.33", "php-8.3.33", "php-8.4.27", "php-8.5.12", "php-5.2.17", "php-8.2.35-extra", "", "../php-8.2.35", "nginx-1.30.6"} {
		if _, ok := runtimeMagicSpecification(id); ok {
			t.Fatal("unreviewed source borrowed build-transform authority", id)
		}
	}
}
