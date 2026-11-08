package core

import (
	"encoding/base64"
	"errors"
	"strconv"
)

const MemcachedUnixConsoleValueBytes = 48 << 10
const MemcachedUnixCacheInputBytes = (72 << 10)

// No raw command, path, address, UID or account. Values/keys are canonical
// base64 to preserve bytes and prevent text-protocol command injection. This
// DTO is data only, NOT actor/original-install/peer or mutation authority.
type MemcachedUnixCacheInput struct {
	Action      string `json:"action"`
	KeyBase64   string `json:"key_base64,omitempty"`
	ValueBase64 string `json:"value_base64,omitempty"`
	CAS         string `json:"cas,omitempty"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
	Flags       uint32 `json:"flags,omitempty"`
	Stats       string `json:"stats,omitempty"`
}

type MemcachedUnixCacheResult struct {
	Action       string            `json:"action"`
	Found        bool              `json:"found"`
	Changed      bool              `json:"changed"`
	ValueBase64  string            `json:"value_base64,omitempty"`
	ValueBytes   int               `json:"value_bytes,omitempty"`
	CAS          string            `json:"cas,omitempty"`
	Flags        uint32            `json:"flags,omitempty"`
	TTLRemaining int64             `json:"ttl_remaining"`
	Stale        bool              `json:"stale,omitempty"`
	Statistics   map[string]string `json:"statistics,omitempty"`
}

var ErrMemcachedUnixCacheInput = errors.New("Memcached 缓存操作、规范编码、版本标记或容量不符合固定策略")
var ErrMemcachedUnixCacheKeyEncoding = errors.New("固定 Memcached1.6.45 Meta 协议限制：含空白或控制字节的键最多186字节；其他键最多250字节，未连接或发送命令")

func MemcachedUnixCASToken(raw string, zero bool) bool {
	v, err := strconv.ParseUint(raw, 10, 64)
	return err == nil && strconv.FormatUint(v, 10) == raw && (zero || v != 0)
}

func MemcachedUnixCacheKey(raw string) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 336 {
		return nil, ErrMemcachedUnixCacheInput
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) == 0 || len(key) > 250 || base64.StdEncoding.EncodeToString(key) != raw {
		return nil, ErrMemcachedUnixCacheInput
	}
	return key, nil
}

// 1.6.45 checks the encoded token length BEFORE decoding flag b. A 187+
// byte binary key containing separators cannot be represented safely here.
// Long delimiter-free keys use their exact native token, never re-encoding,
// truncating, renaming, or creating a different logical key as a fallback.
func MemcachedUnixCacheKeyToken(raw string) (string, string, error) {
	key, err := MemcachedUnixCacheKey(raw)
	if err != nil {
		return "", "", err
	}
	if len(raw) <= 250 {
		return raw, " b", nil
	}
	for _, b := range key {
		if b <= 32 || b == 127 {
			return "", "", ErrMemcachedUnixCacheKeyEncoding
		}
	}
	return string(key), "", nil
}

func ValidateMemcachedUnixCacheInput(in MemcachedUnixCacheInput) error {
	if len(in.ValueBase64) > ((MemcachedUnixConsoleValueBytes+2)/3)*4 {
		return ErrMemcachedUnixCacheInput
	}
	if in.Action == "stats" {
		if in.KeyBase64 != "" || in.ValueBase64 != "" || in.CAS != "" || in.TTLSeconds != 0 || in.Flags != 0 || (in.Stats != "basic" && in.Stats != "settings" && in.Stats != "items" && in.Stats != "slabs") {
			return ErrMemcachedUnixCacheInput
		}
		return nil
	}
	if _, _, err := MemcachedUnixCacheKeyToken(in.KeyBase64); err != nil || in.Stats != "" {
		if err != nil {
			return err
		}
		return ErrMemcachedUnixCacheInput
	}
	switch in.Action {
	case "get":
		if in.ValueBase64 != "" || in.CAS != "" || in.TTLSeconds != 0 || in.Flags != 0 {
			return ErrMemcachedUnixCacheInput
		}
	case "add", "cas":
		value, err := base64.StdEncoding.DecodeString(in.ValueBase64)
		defer clear(value)
		if err != nil || len(value) > MemcachedUnixConsoleValueBytes || base64.StdEncoding.EncodeToString(value) != in.ValueBase64 || in.TTLSeconds < 0 || in.TTLSeconds == 1 || in.TTLSeconds > 30*24*60*60 || in.Action == "add" && in.CAS != "" || in.Action == "cas" && !MemcachedUnixCASToken(in.CAS, false) {
			return ErrMemcachedUnixCacheInput
		}
	case "delete":
		if in.ValueBase64 != "" || !MemcachedUnixCASToken(in.CAS, false) || in.TTLSeconds != 0 || in.Flags != 0 {
			return ErrMemcachedUnixCacheInput
		}
	default:
		return ErrMemcachedUnixCacheInput
	}
	return nil
}
