//go:build linux

package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemBundleEncryptionRejectsWrongPasswordAndTamper(t *testing.T) {
	plain := []byte("private panel metadata")
	cipher, e := encryptSystemBundle(plain, "long-test-passphrase")
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decryptSystemBundle(cipher, "long-test-passphrase")
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatalf("decode=%q error=%v", decoded, e)
	}
	if _, e = decryptSystemBundle(cipher, "wrong-password-value"); e == nil {
		t.Fatal("wrong password accepted")
	}
	cipher[len(cipher)-1] ^= 1
	if _, e = decryptSystemBundle(cipher, "long-test-passphrase"); e == nil {
		t.Fatal("tamper accepted")
	}
}

func TestSystemRestoreRejectsTraversalWithoutWriting(t *testing.T) {
	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	tw := tar.NewWriter(gz)
	body := []byte("escape")
	if e := tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0600, Size: int64(len(body))}); e != nil {
		t.Fatal(e)
	}
	tw.Write(body)
	tw.Close()
	gz.Close()
	cipher, e := encryptSystemBundle(plain.Bytes(), "long-test-passphrase")
	if e != nil {
		t.Fatal(e)
	}
	base := t.TempDir()
	bundle := filepath.Join(base, "bad.pbackup")
	dest := filepath.Join(base, "restore")
	os.WriteFile(bundle, cipher, 0600)
	os.Mkdir(dest, 0755)
	if _, e = extractSystemBundle(bundle, "long-test-passphrase", dest); e == nil {
		t.Fatal("traversal accepted")
	}
	if _, e = os.Stat(filepath.Join(base, "escape")); !os.IsNotExist(e) {
		t.Fatalf("escape file written: %v", e)
	}
}
