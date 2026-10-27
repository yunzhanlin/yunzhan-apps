package executor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

var errLoadBalanceStreamAccount = errors.New("TCP/UDP 专用身份的原始创建凭据或当前授权无法核对；保留原始记录，不接管或重试不确定的创建")

// These private records prove original ownership only after a held Root store,
// the original operation's independent authority and fresh NSS all agree. They
// are not RPC input, permission grants, account adoption or a recovery command.
type loadBalanceStreamAccountIntent struct {
	Format           int    `json:"format"`
	Name             string `json:"name"`
	Nonce            string `json:"nonce"`
	JobID            string `json:"job_id"`
	ActorID          string `json:"actor_id"`
	ConfigurationSHA string `json:"configuration_sha256"`
	ManifestSHA      string `json:"manifest_sha256"`
}

type loadBalanceStreamAccountReceipt struct {
	Format    int    `json:"format"`
	Name      string `json:"name"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	IntentSHA string `json:"intent_sha256"`
	NSSSHA    string `json:"nss_sha256"`
}

func loadBalanceStreamAccountHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) || value == strings.Repeat("0", 64) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func loadBalanceStreamAccountBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return append(raw, '\n')
}

func decodeLoadBalanceStreamAccountIntent(raw []byte) (loadBalanceStreamAccountIntent, error) {
	var v loadBalanceStreamAccountIntent
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil || v.Format != 1 ||
		v.Name != loadbalancestream.ServiceAccount || !core.ValidID(v.Nonce) || !core.ValidID(v.JobID) || !core.ValidID(v.ActorID) ||
		!loadBalanceStreamAccountHash(v.ConfigurationSHA) || !loadBalanceStreamAccountHash(v.ManifestSHA) || !bytes.Equal(raw, loadBalanceStreamAccountBytes(v)) {
		return loadBalanceStreamAccountIntent{}, errLoadBalanceStreamAccount
	}
	return v, nil
}

func decodeLoadBalanceStreamAccountReceipt(raw []byte) (loadBalanceStreamAccountReceipt, error) {
	var v loadBalanceStreamAccountReceipt
	if len(raw) == 0 || len(raw) > 2048 || json.Unmarshal(raw, &v) != nil || v.Format != 1 || v.Name != loadbalancestream.ServiceAccount ||
		v.UID < 100 || v.UID >= 1000 || v.GID < 100 || v.GID >= 1000 || !loadBalanceStreamAccountHash(v.IntentSHA) ||
		!loadBalanceStreamAccountHash(v.NSSSHA) || !bytes.Equal(raw, loadBalanceStreamAccountBytes(v)) {
		return loadBalanceStreamAccountReceipt{}, errLoadBalanceStreamAccount
	}
	return v, nil
}

// The OS implementation holds each private inode until NSS verification ends.
// Pure models use the same protocol; no exported configurable filesystem seam.
type loadBalanceStreamHeldAccountRecord interface {
	bytes() []byte
	current() bool
	close() error
}

type loadBalanceStreamAccountStore interface {
	closed() bool
	read(string) (loadBalanceStreamHeldAccountRecord, error)
	writeExclusive(string, []byte) error
}

type loadBalanceStreamAccountOps struct {
	authorize func(context.Context) error
	absent    func(context.Context) error
	create    func(context.Context) error
	resolve   func(context.Context) (loadBalanceStreamIdentity, error)
}

func loadBalanceStreamManagedIdentityAt(ctx context.Context, store loadBalanceStreamAccountStore, resolve func(context.Context) (loadBalanceStreamIdentity, error)) (loadBalanceStreamIdentity, error) {
	var empty loadBalanceStreamIdentity
	if ctx == nil || ctx.Err() != nil || store == nil || resolve == nil || !store.closed() {
		return empty, errLoadBalanceStreamAccount
	}
	intent, err := store.read("account-intent.json")
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer intent.close()
	if _, err := decodeLoadBalanceStreamAccountIntent(intent.bytes()); err != nil {
		return empty, err
	}
	record, err := store.read("account.json")
	if err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	defer record.close()
	receipt, err := decodeLoadBalanceStreamAccountReceipt(record.bytes())
	if err != nil || receipt.IntentSHA != core.Hash(string(intent.bytes())) {
		return empty, errLoadBalanceStreamAccount
	}
	identity, err := resolve(ctx)
	if err != nil || identity.UID != receipt.UID || identity.GID != receipt.GID || identity.SHA256 != receipt.NSSSHA ||
		ctx.Err() != nil || !store.closed() || !intent.current() || !record.current() {
		return empty, errLoadBalanceStreamAccount
	}
	return identity, nil
}

// The forthcoming fixed Root operation supplies original-journal/actor/grant
// authority and the actual locked NSS tools. This unexported primitive starts
// no production command by itself. An intent without its completed receipt is
// permanently refused: no retry, same-name adoption, deletion or repair path.
func prepareLoadBalanceStreamAccountAt(ctx context.Context, store loadBalanceStreamAccountStore, intent loadBalanceStreamAccountIntent, ops loadBalanceStreamAccountOps) (loadBalanceStreamIdentity, error) {
	var empty loadBalanceStreamIdentity
	raw := loadBalanceStreamAccountBytes(intent)
	if ctx == nil || ctx.Err() != nil || store == nil || !store.closed() || ops.authorize == nil || ops.absent == nil || ops.create == nil || ops.resolve == nil {
		return empty, errLoadBalanceStreamAccount
	}
	if _, err := decodeLoadBalanceStreamAccountIntent(raw); err != nil || ops.authorize(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	if receipt, err := store.read("account.json"); err == nil {
		receipt.close()
		identity, err := loadBalanceStreamManagedIdentityAt(ctx, store, ops.resolve)
		if err != nil || ops.authorize(ctx) != nil || ctx.Err() != nil {
			return empty, errLoadBalanceStreamAccount
		}
		return identity, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, errLoadBalanceStreamAccount
	}
	if original, err := store.read("account-intent.json"); err == nil {
		original.close()
		return empty, errLoadBalanceStreamAccount
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, errLoadBalanceStreamAccount
	}
	if ops.absent(ctx) != nil || ctx.Err() != nil || ops.authorize(ctx) != nil || !store.closed() {
		return empty, errLoadBalanceStreamAccount
	}
	if err := store.writeExclusive("account-intent.json", raw); err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	if ctx.Err() != nil || ops.authorize(ctx) != nil || ops.create(ctx) != nil {
		return empty, errLoadBalanceStreamAccount
	}
	identity, err := ops.resolve(ctx)
	if err != nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamAccount
	}
	receipt := loadBalanceStreamAccountBytes(loadBalanceStreamAccountReceipt{1, loadbalancestream.ServiceAccount, identity.UID, identity.GID, core.Hash(string(raw)), identity.SHA256})
	if _, err := decodeLoadBalanceStreamAccountReceipt(receipt); err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	// Retain ownership of the already-created exact account even if a later
	// revoke prevents its use. No rollback ever deletes a system identity.
	if err := store.writeExclusive("account.json", receipt); err != nil {
		return empty, errLoadBalanceStreamAccount
	}
	verified, err := loadBalanceStreamManagedIdentityAt(ctx, store, ops.resolve)
	if err != nil || ops.authorize(ctx) != nil || ctx.Err() != nil {
		return empty, errLoadBalanceStreamAccount
	}
	return verified, nil
}
