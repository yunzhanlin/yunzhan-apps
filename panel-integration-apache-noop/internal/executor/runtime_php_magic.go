package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
)

// RuntimeBuildTransform identifies a reviewed build-only representation change.
// The verified upstream archive and exact decoded database bytes remain bound;
// this is not a source-security patch, a disabled extension or a memory override.
type RuntimeBuildTransform struct {
	ID             string `json:"id"`
	Path           string `json:"path"`
	UpstreamCommit string `json:"upstream_commit"`
	InputSHA256    string `json:"input_sha256"`
	OutputSHA256   string `json:"output_sha256"`
	DataSHA256     string `json:"data_sha256"`
	DataBytes      int    `json:"data_bytes"`
}

const runtimeMagicTransformID = "php-fileinfo-octal-strings-v1"
const runtimeMagicUpstreamCommit = "bcd3eec44aa4e4eeb7deb4ee6b6cfb596dcc7baa"
const runtimeMagicPath = "ext/fileinfo/data_file.c"
const runtimeMagicHeader = "/* This is a generated file, do not modify */\n/* Usage: php create_data_file.php /path/to/magic.mgc > data_file.c */\n"

type runtimeMagicSpec struct {
	archiveSHA string
	inputSHA   string
	dataSHA    string
	rawBytes   int
	dataBytes  int
	nonString  bool
}

func runtimeMagicSpecification(id string) (runtimeMagicSpec, bool) {
	switch id {
	case "php-8.2.35":
		return runtimeMagicSpec{
			archiveSHA: "9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910",
			inputSHA:   "d2375f7306b94d7b35f42cd9afc83f54b3072936fc1dfb90eac2add22d60ef5a",
			dataSHA:    "2aa3463ba3b5e4a1e729c5d288719a8b666510c51bd32e1083fbc6068f16f27e",
			rawBytes:   42528803,
			dataBytes:  7015032,
		}, true
	case "php-8.3.36":
		return runtimeMagicSpec{
			archiveSHA: "c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53",
			inputSHA:   "9e18775970ba5aa3efab3912de48b7baaa90128c8ccb9880465d80422ff9537f",
			dataSHA:    "e49c1e50fdfcb2c60d170559ff6bcb2417ff2a7c157e0c2d2602d1d554507031",
			rawBytes:   48227568,
			dataBytes:  7955032,
			nonString:  true,
		}, true
	default:
		return runtimeMagicSpec{}, false
	}
}

func runtimeMagicHex(v byte) (byte, bool) {
	switch {
	case v >= '0' && v <= '9':
		return v - '0', true
	case v >= 'A' && v <= 'F':
		return v - 'A' + 10, true
	}
	return 0, false
}

func runtimeMagicSpace(v byte) bool {
	return v == ' ' || v == '\t' || v == '\r' || v == '\n'
}

// Use the upstream octal-string approach, but keep the original ONE-dimensional
// array's exact length. Unlike upstream's padded 2-D table, no padding/NUL byte
// can change sizeof() or old libmagic's database length. All -O2 and other build
// flags stay unchanged. An independent native ELF test must check symbol bytes.
func runtimeMagicStringSource(raw []byte, size int, nonString bool) ([]byte, string, error) {
	if size < 1 || size > 16<<20 || len(raw) > 64<<20 {
		return nil, "", errors.New("fileinfo 构建表示容量异常")
	}
	declaration := "const unsigned char php_magic_database[" + strconv.Itoa(size) + "]"
	if nonString {
		declaration += " ZEND_NONSTRING"
	}
	prefix := runtimeMagicHeader + declaration + " = {\n"
	if !bytes.HasPrefix(raw, []byte(prefix)) {
		return nil, "", errors.New("fileinfo 上游生成格式与审核版本不符")
	}
	payload := make([]byte, size)
	out := make([]byte, 0, len(prefix)+size*4+(size/1024+1)*3+256)
	out = append(out, runtimeMagicHeader...)
	out = append(out, "/* Reviewed byte-exact build representation based on upstream "...)
	out = append(out, runtimeMagicUpstreamCommit...)
	out = append(out, "; original one-dimensional size retained. */\n"...)
	out = append(out, declaration...)
	out = append(out, " =\n"...)
	pos := len(prefix)
	for i := range payload {
		for pos < len(raw) && runtimeMagicSpace(raw[pos]) {
			pos++
		}
		if len(raw)-pos < 5 || raw[pos] != '0' || raw[pos+1] != 'x' || raw[pos+4] != ',' {
			return nil, "", errors.New("fileinfo 数据字面量数量或格式异常，未替换源码")
		}
		hi, highOK := runtimeMagicHex(raw[pos+2])
		lo, lowOK := runtimeMagicHex(raw[pos+3])
		if !highOK || !lowOK {
			return nil, "", errors.New("fileinfo 数据含未知字面量")
		}
		value := hi<<4 | lo
		payload[i] = value
		if i%1024 == 0 {
			out = append(out, '"')
		}
		// Always exactly three octal digits; no quote, backslash, digit,
		// newline, NUL or following literal can extend another escape.
		out = append(out, '\\', '0'+value>>6, '0'+(value>>3)&7, '0'+value&7)
		if i%1024 == 1023 || i == size-1 {
			out = append(out, '"', '\n')
		}
		pos += 5
	}
	for pos < len(raw) && runtimeMagicSpace(raw[pos]) {
		pos++
	}
	if !bytes.Equal(bytes.TrimRight(raw[pos:], " \t\r\n"), []byte("};")) {
		return nil, "", errors.New("fileinfo 数据尾部含额外值、代码或未知内容")
	}
	out = append(out, ';', '\n')
	digest := sha256.Sum256(payload)
	return out, hex.EncodeToString(digest[:]), nil
}

func runtimeMagicTransformRecord(spec runtimeMagicSpec, out []byte) RuntimeBuildTransform {
	digest := sha256.Sum256(out)
	return RuntimeBuildTransform{ID: runtimeMagicTransformID, Path: runtimeMagicPath,
		UpstreamCommit: runtimeMagicUpstreamCommit, InputSHA256: spec.inputSHA,
		OutputSHA256: hex.EncodeToString(digest[:]), DataSHA256: spec.dataSHA, DataBytes: spec.dataBytes}
}
