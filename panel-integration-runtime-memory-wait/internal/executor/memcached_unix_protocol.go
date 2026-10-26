package executor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"

	"local/panel/internal/core"
)

var errMemcachedUnixProtocol = errors.New("Memcached 实际协议回复、容量或版本不能核对；不重发")
var errMemcachedUnixCAS = errors.New("缓存已被其他客户端修改；原子版本校验未通过，未覆盖或删除")
var errMemcachedUnixMissing = errors.New("缓存已过期或不存在；未重建")
var errMemcachedUnixExists = errors.New("缓存已存在；未覆盖")
var errMemcachedUnixConsoleLarge = errors.New("缓存值超出面板48KiB编辑预算；未截断、改写或删除，业务客户端仍可使用实例的4MiB项上限")

// Fixed1.6.45 Meta protocol, primary reference:
// https://github.com/memcached/memcached/blob/1.6.45/doc/protocol.txt
// Base64-key flag b, add-only ME, atomic C-token update/delete. Read uses u
// and no N/R/T/E modifiers: no vivification, TTL extension or LRU/hit bump.
// Payload construction alone is never authority to connect to a destination.
func memcachedUnixCachePacket(in core.MemcachedUnixCacheInput) ([]byte, error) {
	if err := core.ValidateMemcachedUnixCacheInput(in); err != nil {
		return nil, err
	}
	key, flag := "", ""
	if in.Action != "stats" {
		var err error
		key, flag, err = core.MemcachedUnixCacheKeyToken(in.KeyBase64)
		if err != nil {
			return nil, err
		}
	}
	switch in.Action {
	case "get":
		return []byte("mg " + key + flag + " f c t v u\r\n"), nil
	case "delete":
		return []byte("md " + key + flag + " C" + in.CAS + "\r\n"), nil
	case "stats":
		if in.Stats == "basic" {
			return []byte("stats\r\n"), nil
		}
		return []byte("stats " + in.Stats + "\r\n"), nil
	case "add", "cas":
		value, _ := base64.StdEncoding.DecodeString(in.ValueBase64)
		defer clear(value)
		condition := "ME"
		if in.Action == "cas" {
			condition = "C" + in.CAS
		}
		header := "ms " + key + " " + strconv.Itoa(len(value)) + flag + " " + condition + " F" + strconv.FormatUint(uint64(in.Flags), 10) + " T" + strconv.Itoa(in.TTLSeconds) + " c\r\n"
		packet := make([]byte, 0, len(header)+len(value)+2)
		packet = append(packet, header...)
		packet = append(packet, value...)
		packet = append(packet, '\r', '\n')
		return packet, nil
	}
	return nil, core.ErrMemcachedUnixCacheInput
}

func memcachedUnixProtocolLine(r *bufio.Reader) (string, error) {
	raw, err := r.ReadSlice('\n')
	if err != nil || len(raw) < 2 || len(raw) > 4096 || raw[len(raw)-2] != '\r' {
		return "", errMemcachedUnixProtocol
	}
	for _, c := range raw[:len(raw)-2] {
		if c < 32 || c > 126 {
			return "", errMemcachedUnixProtocol
		}
	}
	return string(raw[:len(raw)-2]), nil
}

func memcachedUnixMetaToken(raw string, max uint64) (uint64, error) {
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v > max || strconv.FormatUint(v, 10) != raw {
		return 0, errMemcachedUnixProtocol
	}
	return v, nil
}

func memcachedUnixGetReply(r *bufio.Reader) (core.MemcachedUnixCacheResult, error) {
	out := core.MemcachedUnixCacheResult{Action: "get", TTLRemaining: -1}
	line, err := memcachedUnixProtocolLine(r)
	if err != nil {
		return out, err
	}
	if line == "EN" {
		return out, nil
	}
	parts := strings.Split(line, " ")
	if len(parts) < 5 || len(parts) > 8 || parts[0] != "VA" {
		return out, errMemcachedUnixProtocol
	}
	size, err := memcachedUnixMetaToken(parts[1], 4<<20)
	if err != nil {
		return out, err
	}
	if size > core.MemcachedUnixConsoleValueBytes {
		return out, errMemcachedUnixConsoleLarge
	}
	seen := map[byte]bool{}
	for _, part := range parts[2:] {
		if part == "" || seen[part[0]] {
			return out, errMemcachedUnixProtocol
		}
		seen[part[0]] = true
		switch part[0] {
		case 'f':
			v, e := memcachedUnixMetaToken(part[1:], 0xffffffff)
			if e != nil {
				return out, e
			}
			out.Flags = uint32(v)
		case 'c':
			if !core.MemcachedUnixCASToken(part[1:], false) {
				return out, errMemcachedUnixProtocol
			}
			out.CAS = part[1:]
		case 't':
			v, e := strconv.ParseInt(part[1:], 10, 64)
			if e != nil || v < -1 || v > 0xffffffff || strconv.FormatInt(v, 10) != part[1:] {
				return out, errMemcachedUnixProtocol
			}
			out.TTLRemaining = v
		case 'X', 'W', 'Z':
			if len(part) != 1 {
				return out, errMemcachedUnixProtocol
			}
			out.Stale = true
		case 'b':
			if len(part) != 1 {
				return out, errMemcachedUnixProtocol
			}
		default:
			return out, errMemcachedUnixProtocol
		}
	}
	if !seen['f'] || !seen['c'] || !seen['t'] || seen['W'] && seen['Z'] {
		return out, errMemcachedUnixProtocol
	}
	value := make([]byte, int(size)+2)
	if _, err := io.ReadFull(r, value); err != nil || !bytes.Equal(value[len(value)-2:], []byte("\r\n")) {
		return out, errMemcachedUnixProtocol
	}
	out.Found, out.ValueBytes, out.ValueBase64 = true, int(size), base64.StdEncoding.EncodeToString(value[:len(value)-2])
	return out, nil
}

func memcachedUnixMutationReply(r *bufio.Reader, action string) (core.MemcachedUnixCacheResult, error) {
	out := core.MemcachedUnixCacheResult{Action: action, TTLRemaining: -1}
	line, err := memcachedUnixProtocolLine(r)
	if err != nil {
		return out, err
	}
	parts := strings.Split(line, " ")
	if action == "delete" {
		if len(parts) != 1 {
			return out, errMemcachedUnixProtocol
		}
		switch line {
		case "HD":
			out.Changed = true
			return out, nil
		case "NF":
			return out, errMemcachedUnixMissing
		case "EX":
			return out, errMemcachedUnixCAS
		default:
			return out, errMemcachedUnixProtocol
		}
	}
	if len(parts) < 1 || len(parts) > 2 {
		return out, errMemcachedUnixProtocol
	}
	if len(parts) == 2 && (len(parts[1]) < 2 || parts[1][0] != 'c' || !core.MemcachedUnixCASToken(parts[1][1:], true)) {
		return out, errMemcachedUnixProtocol
	}
	switch parts[0] {
	case "HD":
		if len(parts) != 2 || !core.MemcachedUnixCASToken(parts[1][1:], false) {
			return out, errMemcachedUnixProtocol
		}
		out.Changed, out.CAS = true, parts[1][1:]
		return out, nil
	case "NS":
		if action == "add" {
			return out, errMemcachedUnixExists
		}
	case "EX":
		if action == "cas" {
			return out, errMemcachedUnixCAS
		}
	case "NF":
		if action == "cas" {
			return out, errMemcachedUnixMissing
		}
	}
	return out, errMemcachedUnixProtocol
}

func memcachedUnixStatsReply(r *bufio.Reader) (core.MemcachedUnixCacheResult, error) {
	out := core.MemcachedUnixCacheResult{Action: "stats", TTLRemaining: -1, Statistics: map[string]string{}}
	for count := 0; count <= 2048; count++ {
		line, err := memcachedUnixProtocolLine(r)
		if err != nil {
			return out, err
		}
		if line == "END" {
			return out, nil
		}
		if count == 2048 || !strings.HasPrefix(line, "STAT ") {
			return out, errMemcachedUnixProtocol
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(line, "STAT "), " ")
		if !ok || len(key) == 0 || len(key) > 128 || len(value) > 512 {
			return out, errMemcachedUnixProtocol
		}
		for _, c := range []byte(key) {
			if c < '!' || c > '~' {
				return out, errMemcachedUnixProtocol
			}
		}
		if _, duplicate := out.Statistics[key]; duplicate {
			return out, errMemcachedUnixProtocol
		}
		out.Statistics[key] = value
	}
	return out, errMemcachedUnixProtocol
}

func readMemcachedUnixCacheReply(source io.Reader, action string) (core.MemcachedUnixCacheResult, error) {
	var empty core.MemcachedUnixCacheResult
	if source == nil {
		return empty, errMemcachedUnixProtocol
	}
	budget := &io.LimitedReader{R: source, N: (128 << 10) + 1}
	r := bufio.NewReaderSize(budget, 4096)
	var out core.MemcachedUnixCacheResult
	var err error
	switch action {
	case "get":
		out, err = memcachedUnixGetReply(r)
	case "add", "cas", "delete":
		out, err = memcachedUnixMutationReply(r, action)
	case "stats":
		out, err = memcachedUnixStatsReply(r)
	default:
		return empty, core.ErrMemcachedUnixCacheInput
	}
	if err != nil {
		return empty, err
	}
	if budget.N == 0 || r.Buffered() != 0 {
		return empty, errMemcachedUnixProtocol
	}
	return out, nil
}
