package core

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"time"
)

// No certificate private keys, decryption, per-row reference queries or
// unbounded inventory allocation are needed to count saved certificate expiry.
func (s *Store) dailyCertificatesDue(ctx context.Context, at time.Time) (int, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,length(CAST(metadata AS BLOB)),CASE WHEN length(CAST(metadata AS BLOB)) BETWEEN 2 AND 131072 THEN metadata ELSE NULL END,length(CAST(certificate_pem AS BLOB)),CASE WHEN length(CAST(certificate_pem AS BLOB)) BETWEEN 1 AND 32768 THEN certificate_pem ELSE NULL END FROM certificates ORDER BY id LIMIT 8193`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count, records, total := 0, 0, int64(0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var id string
		var metaBytes, pemBytes int64
		var metadata, material sql.NullString
		if err := rows.Scan(&id, &metaBytes, &metadata, &pemBytes, &material); err != nil {
			return 0, err
		}
		records++
		total += metaBytes + pemBytes
		if records > 8192 || metaBytes < 2 || metaBytes > 131072 || pemBytes < 1 || pemBytes > 32768 || total > 32<<20 || !metadata.Valid || !material.Valid || int64(len(metadata.String)) != metaBytes || int64(len(material.String)) != pemBytes || !ValidID(id) {
			return 0, errors.New("证书清单身份或容量无法完整核对")
		}
		meta, err := decodeDailyReportRecord([]byte(metadata.String))
		if err != nil || meta["id"] != id || meta["chain_sha256"] != Hash(material.String) {
			return 0, errors.New("证书元数据与保存材料无法核对")
		}
		raw := bytes.TrimSpace([]byte(material.String))
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return 0, errors.New("保存的证书材料无法核对")
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return 0, errors.New("保存的证书材料无法核对")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil || meta["fingerprint"] != Hash(string(block.Bytes)) {
			return 0, errors.New("保存的叶证书无法核对")
		}
		for key, actual := range map[string]time.Time{"not_before": leaf.NotBefore, "not_after": leaf.NotAfter} {
			value, ok := meta[key].(string)
			parsed, err := time.Parse(time.RFC3339, value)
			if !ok || err != nil || !parsed.Equal(actual) {
				return 0, errors.New("证书有效期元数据与真实叶证书不一致")
			}
		}
		if leaf.NotAfter.Before(at.AddDate(0, 0, 14)) {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}
