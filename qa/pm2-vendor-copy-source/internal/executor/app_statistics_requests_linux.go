//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

func statisticsRequestID(value string) bool {
	if len(value) != 32 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == value
}

// Deduplication is by the native Nginx random request ID, never a line digest:
// two identical legitimate requests must still count twice. Retained receipts
// are independent of capacity-evicted report rows, within the SAME 512 MiB
// database budget. Their own closed ceiling fails before either row or cursor
// commits. No ID is invented for historical logs that cannot prove identity.
func insertStatisticsRequest(ctx context.Context, tx *sql.Tx, site string, row analyticsAccess, stamp int64, count *int) (bool, error) {
	if count != nil && (*count < 0 || *count > statisticsHistoryReceipts) || count == nil && row.RequestID != "" {
		return false, errors.New("统计请求身份计数无法核对，未提交")
	}
	payload, err := json.Marshal(row)
	if err != nil {
		return false, errors.New("统计请求无法序列化，未提交")
	}
	if row.RequestID != "" {
		if !statisticsRequestID(row.RequestID) {
			return false, errors.New("统计请求身份无效，未提交")
		}
		sum := sha256.Sum256(payload)
		digest := hex.EncodeToString(sum[:])
		var original string
		var originalStamp int64
		err := tx.QueryRowContext(ctx, "SELECT payload_sha,stamp FROM access_receipts WHERE site=? AND request_id=?", site, row.RequestID).Scan(&original, &originalStamp)
		if err == nil {
			if original != digest || originalStamp != stamp {
				return false, errors.New("统计请求身份对应不同内容，保留原记录并拒绝重复采集")
			}
			return true, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if *count >= statisticsHistoryReceipts {
			return false, errors.New("统计请求身份记录已满，未删除去重证据或提交新进度")
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO access_receipts(site,request_id,payload_sha,stamp) VALUES(?,?,?,?)", site, row.RequestID, digest, stamp); err != nil {
			return false, errors.New("统计请求身份写入失败，未提交新进度")
		}
		*count++
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO access_rows(site,stamp,ip,path,status,seconds,bot,payload) VALUES(?,?,?,?,?,?,?,?)", site, stamp, row.Remote, row.Path, row.Status, row.Seconds, strings.Contains(row.Agent, "bot"), string(payload)); err != nil {
		return false, errors.New("统计历史容量不足或写入失败，未提交新进度")
	}
	return false, nil
}
