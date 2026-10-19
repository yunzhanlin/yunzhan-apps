package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// This opaque snapshot identity binds the original URL, encrypted grant and
// creation identity. It is not a bearer, and needs no destructive migration.
func platformHostIdentity(id, address string, encrypted []byte, created string) string {
	raw, _ := json.Marshal([4]string{id, address, hex.EncodeToString(encrypted), created})
	return Hash(string(raw))
}

// Public identifiers are SHA-256 digests, not accepted bearer values. Keeping
// the original digest allows revocation even if the one-time secret reply was
// lost. Never recover or expose a stored plaintext secret.
func (s *Store) platformTokenList(ctx context.Context) (any, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT token_hash,created_at FROM app_platform_tokens ORDER BY created_at,token_hash LIMIT 129`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, created string
		if err = rows.Scan(&id, &created); err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339, created)
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(id) || err != nil || at.UTC().Format(time.RFC3339) != created {
			return nil, errors.New("授权清单身份或创建时间无法核对；保留原记录，不返回部分正常清单")
		}
		items = append(items, map[string]any{"token_id": id, "created_at": created, "scope": "health-read-only"})
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(items) > 128 {
		return nil, errors.New("授权清单超过 128 个上限；保留原记录，未用部分结果冒充完整清单")
	}
	return map[string]any{"tokens": items, "total": len(items), "limit": 128, "read_only": true, "scope": "本机全部只读授权的公开摘要标识，可按标识撤销；不是访问令牌，不提供令牌恢复，不自动删除"}, nil
}
