package geodata

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

const StructureProtocol = "PANEL_GEODATA_STRUCTURE_V1\n"

// StructureInput frames ONLY a bounded manifest and read-only raw bytes.
// There is no pathname, destination, executable or authority flag in the IPC.
func StructureInput(m Manifest, raw io.Reader) (io.Reader, error) {
	if raw == nil || m.Bytes < 1 || m.Bytes > MaxDatabaseBytes || !digestPattern.MatchString(m.SHA256) {
		return nil, errors.New("地域结构核对输入无效")
	}
	encoded, err := json.Marshal(m)
	if err != nil || len(encoded) > maxManifestBytes {
		return nil, errors.New("地域结构核对清单超限")
	}
	return io.MultiReader(strings.NewReader(StructureProtocol), bytes.NewReader(append(encoded, '\n')), raw), nil
}

// VerifyStructureStream is a read-only worker entry, not a signed-data loader.
// The caller must separately verify its own pinned signatures. The worker
// independently checks the exact raw size/hash, metadata and ENTIRE tree.
// Its synchronous Verify call is terminated externally by the fixed sandbox.
func VerifyStructureStream(ctx context.Context, input io.Reader, output io.Writer) error {
	if ctx == nil || input == nil || output == nil {
		return errors.New("地域结构核对流未初始化")
	}
	r := bufio.NewReaderSize(contextReader{ctx, input}, maxManifestBytes+2)
	first, err := r.ReadSlice('\n')
	if err != nil || string(first) != StructureProtocol {
		return errors.New("地域结构核对协议不符")
	}
	line, err := r.ReadSlice('\n')
	var m Manifest
	if err != nil || len(line) > maxManifestBytes+1 || decodeManifest(line, &m) != nil || m.Format != 1 || m.Channel != Channel || m.Bytes < 1 || m.Bytes > MaxDatabaseBytes || !digestPattern.MatchString(m.SHA256) {
		return errors.New("地域结构核对清单无效或超限")
	}
	raw, err := readExact(ctx, r, m.Bytes)
	if err != nil || hash(raw) != m.SHA256 {
		return errors.New("地域结构核对原始字节大小或摘要不符")
	}
	db, err := maxminddb.OpenBytes(raw, maxminddb.DisableStringCache())
	if err != nil {
		return errors.New("地域结构核对无法解析数据库")
	}
	defer db.Close()
	if !databaseIdentity(m, db) {
		return errors.New("地域结构核对数据库身份不同")
	}
	if err := db.Verify(); err != nil {
		return errors.New("地域结构核对未通过完整树及数据验证")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = io.WriteString(output, StructureProtocol+m.SHA256+"\n")
	return err
}
