//go:build linux

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMemcachedWorkerUnsignedJournalAndRealLeasesNeverBecomeExecutionAuthority(t *testing.T) {
	store, seed := memcachedJournalFixture(t)
	j := memcachedJournalPrepare(t, store, seed)
	run, err := j.lease()
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	engine, err := dockerMutationFixture(t).acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	base, _, coreSeed := memcachedCoreAuthorityFixture(t, false)
	if coreSeed != seed.Record {
		t.Fatal("independently constructed original SQL and journal fixtures differ")
	}
	reader, err := openMemcachedUpdateCoreAuthorityAt(context.Background(), base, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	projectBase := filepath.Join(filepath.Dir(store.base), "compose")
	for name, raw := range map[string][]byte{"compose.yaml": seed.OriginalCompose, "metadata.json": seed.OriginalMetadata} {
		if err := os.WriteFile(filepath.Join(projectBase, seed.Record.Dispatch.ProjectID, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := openComposeUpdateDirectory(projectBase, seed.Record.Dispatch.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, si, _ := d.read("compose.yaml", 48<<10)
	_, mi, _ := d.read("metadata.json", 16<<10)
	w := &memcachedUpdateWorker{seed: seed.Record, run: run, engine: engine, core: reader, project: d, source: si, metadata: mi}
	before, err := j.inventory()
	if err != nil {
		t.Fatal(err)
	}
	if reader.check(context.Background(), seed.Record) != nil {
		t.Fatal("isolated original SQL condition not valid")
	}
	if w.authority(context.Background(), false) == nil || w.authority(context.Background(), true) == nil || w.execute(context.Background()) == nil {
		t.Fatal("actual protected SQL + journal + flocks forged official release execution authority")
	}
	after, err := j.inventory()
	if err != nil || len(after) != len(before) {
		t.Fatal("unsigned worker mutated original journal", err)
	}
	for name, info := range before {
		if !geoStoreStableInfo(info, after[name]) {
			t.Fatal("unsigned worker wrote an event or image intent", name)
		}
	}
	var nilWorker *memcachedUpdateWorker
	if nilWorker.authority(context.Background(), false) == nil {
		t.Fatal("nil worker authorized")
	}
}
