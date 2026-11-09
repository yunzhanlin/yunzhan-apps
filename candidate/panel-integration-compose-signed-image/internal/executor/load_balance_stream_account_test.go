package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"local/panel/internal/core"
	"local/panel/internal/loadbalancestream"
)

func streamAccountFixture() (loadBalanceStreamAccountIntent, loadBalanceStreamIdentity) {
	return loadBalanceStreamAccountIntent{1, loadbalancestream.ServiceAccount, strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 64), strings.Repeat("e", 64)}, loadBalanceStreamIdentity{810, 811, strings.Repeat("f", 64)}
}

func TestLoadBalanceStreamAccountRecordsAreCanonicalAndNotForeignAuthority(t *testing.T) {
	intent, identity := streamAccountFixture()
	i := loadBalanceStreamAccountBytes(intent)
	receipt := loadBalanceStreamAccountReceipt{1, loadbalancestream.ServiceAccount, identity.UID, identity.GID, core.Hash(string(i)), identity.SHA256}
	r := loadBalanceStreamAccountBytes(receipt)
	originalI, originalR := bytes.Clone(i), bytes.Clone(r)
	if v, err := decodeLoadBalanceStreamAccountIntent(i); err != nil || v != intent {
		t.Fatal("canonical original intent refused", err)
	}
	if v, err := decodeLoadBalanceStreamAccountReceipt(r); err != nil || v != receipt {
		t.Fatal("canonical completed receipt refused", err)
	}
	for _, item := range []struct{ name, old, replacement string }{
		{"unknown-field", `"format":1`, `"foreign":true,"format":1`},
		{"duplicate-field", `"format":1`, `"format":1,"format":1`},
		{"case-alias", `"format":1`, `"Format":1`},
		{"float-format", `"format":1`, `"format":1.0`},
		{"other-format", `"format":1`, `"format":2`},
		{"memcached-name", loadbalancestream.ServiceAccount, "panel-memcached"},
		{"site-name", loadbalancestream.ServiceAccount, "panel-site-123"},
		{"ids-name", loadbalancestream.ServiceAccount, "panel-network-ids"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := decodeLoadBalanceStreamAccountIntent(bytes.Replace(i, []byte(item.old), []byte(item.replacement), 1)); err == nil {
				t.Fatal("unknown/noncanonical intent accepted")
			}
			if _, err := decodeLoadBalanceStreamAccountReceipt(bytes.Replace(r, []byte(item.old), []byte(item.replacement), 1)); err == nil {
				t.Fatal("unknown/noncanonical receipt accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`[]`), []byte(strings.Repeat("x", 2049)), append([]byte(" "), i...), append(bytes.Clone(i), '\n'), r} {
		if _, err := decodeLoadBalanceStreamAccountIntent(raw); err == nil {
			t.Fatal("incomplete/oversize/receipt-as-intent accepted")
		}
	}
	for _, raw := range [][]byte{nil, []byte(`null`), []byte(`{}`), []byte(strings.Repeat("x", 2049)), append([]byte(" "), r...), append(bytes.Clone(r), '\n'), i} {
		if _, err := decodeLoadBalanceStreamAccountReceipt(raw); err == nil {
			t.Fatal("incomplete/oversize/intent-as-receipt accepted")
		}
	}
	for _, field := range []string{"Nonce", "JobID", "ActorID"} {
		for _, bad := range []string{"", "../other", strings.Repeat("A", 32), strings.Repeat("a", 31), strings.Repeat("a", 33)} {
			t.Run(field+"-"+bad, func(t *testing.T) {
				v := intent
				reflect.ValueOf(&v).Elem().FieldByName(field).SetString(bad)
				if _, err := decodeLoadBalanceStreamAccountIntent(loadBalanceStreamAccountBytes(v)); err == nil {
					t.Fatal("invalid original operation/actor/nonce identity accepted")
				}
			})
		}
	}
	for _, field := range []string{"ConfigurationSHA", "ManifestSHA"} {
		for _, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
			t.Run(field+"-"+bad, func(t *testing.T) {
				v := intent
				reflect.ValueOf(&v).Elem().FieldByName(field).SetString(bad)
				if _, err := decodeLoadBalanceStreamAccountIntent(loadBalanceStreamAccountBytes(v)); err == nil {
					t.Fatal("invalid original configuration/manifest binding accepted")
				}
			})
		}
	}
	for _, field := range []string{"UID", "GID"} {
		for _, bad := range []uint32{0, 1, 99, 1000, 65534, 1 << 31} {
			v := receipt
			reflect.ValueOf(&v).Elem().FieldByName(field).SetUint(uint64(bad))
			if _, err := decodeLoadBalanceStreamAccountReceipt(loadBalanceStreamAccountBytes(v)); err == nil {
				t.Fatal("root/non-system identity accepted", field, bad)
			}
		}
	}
	for _, field := range []string{"IntentSHA", "NSSSHA"} {
		for _, bad := range []string{"", strings.Repeat("0", 64), strings.Repeat("B", 64), strings.Repeat("z", 64), strings.Repeat("b", 63), strings.Repeat("b", 65)} {
			v := receipt
			reflect.ValueOf(&v).Elem().FieldByName(field).SetString(bad)
			if _, err := decodeLoadBalanceStreamAccountReceipt(loadBalanceStreamAccountBytes(v)); err == nil {
				t.Fatal("invalid original ownership/NSS binding accepted", field)
			}
		}
	}
	if !bytes.Equal(i, originalI) || !bytes.Equal(r, originalR) {
		t.Fatal("decoder changed original caller bytes")
	}
}

type streamAccountModelStore struct {
	values       map[string][]byte
	valid        bool
	readFailure  string
	writeFailure string
	opened       int
}

type streamAccountModelRecord struct {
	s      *streamAccountModelStore
	name   string
	raw    []byte
	closed bool
}

func (r *streamAccountModelRecord) bytes() []byte { return r.raw }
func (r *streamAccountModelRecord) current() bool {
	return !r.closed && r.s.closed() && bytes.Equal(r.raw, r.s.values[r.name])
}
func (r *streamAccountModelRecord) close() error {
	if r.closed {
		return errors.New("double-close")
	}
	r.closed = true
	r.s.opened--
	return nil
}
func (s *streamAccountModelStore) closed() bool { return s != nil && s.valid }
func (s *streamAccountModelStore) read(name string) (loadBalanceStreamHeldAccountRecord, error) {
	if !s.closed() || s.readFailure == name {
		return nil, errLoadBalanceStreamAccount
	}
	raw, ok := s.values[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	s.opened++
	return &streamAccountModelRecord{s, name, bytes.Clone(raw), false}, nil
}
func (s *streamAccountModelStore) writeExclusive(name string, raw []byte) error {
	if !s.closed() || s.writeFailure == name {
		return errLoadBalanceStreamAccount
	}
	if _, exists := s.values[name]; exists {
		return os.ErrExist
	}
	s.values[name] = bytes.Clone(raw)
	return nil
}

func TestLoadBalanceStreamAccountCreatesOnceThenOnlyVerifiesOriginalIdentity(t *testing.T) {
	intent, identity := streamAccountFixture()
	s := &streamAccountModelStore{values: map[string][]byte{}, valid: true}
	absent, created, resolved, authorized := 0, 0, 0, 0
	ops := loadBalanceStreamAccountOps{
		authorize: func(context.Context) error { authorized++; return nil },
		absent:    func(context.Context) error { absent++; return nil },
		create:    func(context.Context) error { created++; return nil },
		resolve: func(context.Context) (loadBalanceStreamIdentity, error) {
			resolved++
			return identity, nil
		},
	}
	actual, err := prepareLoadBalanceStreamAccountAt(context.Background(), s, intent, ops)
	if err != nil || actual != identity || absent != 1 || created != 1 || resolved != 2 || authorized != 4 || len(s.values) != 2 || s.opened != 0 {
		t.Fatal("original exact creation model", actual, err, absent, created, resolved, authorized, s.opened)
	}
	original := map[string][]byte{}
	for name, raw := range s.values {
		original[name] = bytes.Clone(raw)
	}
	// A later legitimate configuration uses the exact original owned identity;
	// it never replaces the original creation job/actor/manifest/intent bytes.
	intent.JobID = strings.Repeat("9", 32)
	intent.ConfigurationSHA = strings.Repeat("8", 64)
	actual, err = prepareLoadBalanceStreamAccountAt(context.Background(), s, intent, ops)
	if err != nil || actual != identity || absent != 1 || created != 1 || resolved != 3 || authorized != 6 || !reflect.DeepEqual(original, s.values) || s.opened != 0 {
		t.Fatal("later use adopted/recreated/rewrote original ownership", actual, err)
	}
	if _, err := loadBalanceStreamManagedIdentityAt(context.Background(), s, ops.resolve); err != nil || s.opened != 0 {
		t.Fatal("held read-only original ownership refused", err)
	}
}

func TestLoadBalanceStreamAccountRefusesIncompleteOrRevokedWithoutReplay(t *testing.T) {
	for _, fault := range []string{"nil-context", "cancelled", "invalid-intent", "untrusted-store", "no-authorize", "no-absent", "no-create", "no-resolve", "initial-revoke", "absence-refused", "pre-intent-revoke", "intent-write", "pre-create-revoke", "create-unknown", "resolve-failed", "invalid-resolved-id", "invalid-resolved-sha", "receipt-write", "post-create-revoke", "held-intent-changed", "held-receipt-changed", "store-changed", "receipt-unreadable", "intent-unreadable"} {
		t.Run(fault, func(t *testing.T) {
			intent, identity := streamAccountFixture()
			s := &streamAccountModelStore{values: map[string][]byte{}, valid: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			authorized, creates, resolves := 0, 0, 0
			ops := loadBalanceStreamAccountOps{
				authorize: func(context.Context) error {
					authorized++
					if fault == "initial-revoke" && authorized == 1 || fault == "pre-intent-revoke" && authorized == 2 || fault == "pre-create-revoke" && authorized == 3 || fault == "post-create-revoke" && authorized == 4 {
						return errLoadBalanceStreamAccount
					}
					return nil
				},
				absent: func(context.Context) error {
					if fault == "absence-refused" {
						return errLoadBalanceStreamAccount
					}
					return nil
				},
				create: func(context.Context) error {
					creates++
					if fault == "create-unknown" {
						return errLoadBalanceStreamAccount
					}
					return nil
				},
				resolve: func(context.Context) (loadBalanceStreamIdentity, error) {
					resolves++
					if fault == "resolve-failed" {
						return loadBalanceStreamIdentity{}, errLoadBalanceStreamAccount
					}
					if fault == "invalid-resolved-id" {
						identity.UID = 0
					}
					if fault == "invalid-resolved-sha" {
						identity.SHA256 = strings.Repeat("0", 64)
					}
					if resolves == 2 {
						switch fault {
						case "held-intent-changed":
							s.values["account-intent.json"] = []byte("changed")
						case "held-receipt-changed":
							s.values["account.json"] = []byte("changed")
						case "store-changed":
							s.valid = false
						}
					}
					return identity, nil
				},
			}
			switch fault {
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			case "invalid-intent":
				intent.JobID = "foreign"
			case "untrusted-store":
				s.valid = false
			case "no-authorize":
				ops.authorize = nil
			case "no-absent":
				ops.absent = nil
			case "no-create":
				ops.create = nil
			case "no-resolve":
				ops.resolve = nil
			case "intent-write":
				s.writeFailure = "account-intent.json"
			case "receipt-write":
				s.writeFailure = "account.json"
			case "receipt-unreadable":
				s.readFailure = "account.json"
			case "intent-unreadable":
				s.readFailure = "account-intent.json"
			}
			if got, err := prepareLoadBalanceStreamAccountAt(ctx, s, intent, ops); err == nil || got != (loadBalanceStreamIdentity{}) || s.opened != 0 || creates > 1 {
				t.Fatal("uncertain/revoked account accepted or leaked", got, err, creates, s.opened)
			}
			// Clearing an injected error is NOT authority to retry a creation.
			// If any intent exists, a fresh request must leave it byte-exact.
			if _, exists := s.values["account-intent.json"]; exists && len(s.values) == 1 {
				before := bytes.Clone(s.values["account-intent.json"])
				attempted := creates
				s.valid, s.writeFailure, s.readFailure = true, "", ""
				retryOps := loadBalanceStreamAccountOps{func(context.Context) error { return nil }, func(context.Context) error { t.Fatal("incomplete intent called absent"); return nil }, func(context.Context) error { creates++; return nil }, func(context.Context) (loadBalanceStreamIdentity, error) {
					t.Fatal("incomplete intent adopted current NSS")
					return identity, nil
				}}
				intent, _ = streamAccountFixture()
				if _, err := prepareLoadBalanceStreamAccountAt(context.Background(), s, intent, retryOps); err == nil || creates != attempted || !bytes.Equal(before, s.values["account-intent.json"]) || s.opened != 0 {
					t.Fatal("incomplete original creation replayed/adopted/rewritten", err)
				}
			}
			if fault == "post-create-revoke" && (len(s.values) != 2 || creates != 1) {
				t.Fatal("revoke deleted already-created account ownership")
			}
		})
	}
}

func TestLoadBalanceStreamAccountOwnedReadBindsEveryOriginalIdentityField(t *testing.T) {
	intent, identity := streamAccountFixture()
	for _, fault := range []string{"intent-missing", "receipt-missing", "intent-foreign", "receipt-foreign", "intent-digest", "UID", "GID", "NSS", "resolve-error", "context-cancelled"} {
		t.Run(fault, func(t *testing.T) {
			i := loadBalanceStreamAccountBytes(intent)
			r := loadBalanceStreamAccountReceipt{1, loadbalancestream.ServiceAccount, identity.UID, identity.GID, core.Hash(string(i)), identity.SHA256}
			s := &streamAccountModelStore{values: map[string][]byte{"account-intent.json": i}, valid: true}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch fault {
			case "intent-missing":
				delete(s.values, "account-intent.json")
			case "intent-foreign":
				s.values["account-intent.json"] = bytes.Replace(i, []byte(loadbalancestream.ServiceAccount), []byte("panel-memcached"), 1)
			case "receipt-foreign":
				r.Name = "panel-network-ids"
			case "intent-digest":
				r.IntentSHA = strings.Repeat("1", 64)
			case "UID":
				r.UID++
			case "GID":
				r.GID++
			case "NSS":
				r.NSSSHA = strings.Repeat("2", 64)
			case "context-cancelled":
				cancel()
			}
			if fault != "receipt-missing" {
				s.values["account.json"] = loadBalanceStreamAccountBytes(r)
			}
			if got, err := loadBalanceStreamManagedIdentityAt(ctx, s, func(context.Context) (loadBalanceStreamIdentity, error) {
				if fault == "resolve-error" {
					return loadBalanceStreamIdentity{}, errLoadBalanceStreamIdentity
				}
				return identity, nil
			}); err == nil || got != (loadBalanceStreamIdentity{}) || s.opened != 0 {
				t.Fatal("unbound original ownership accepted", got, err, s.opened)
			}
		})
	}
}
