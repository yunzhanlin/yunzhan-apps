package geodata

import (
	"container/heap"
	"context"
	"errors"
	"io"
)

type CountrySelectionMetadata struct {
	ManifestSHA256       string
	ParentManifestSHA256 string
	ParentDatabaseSHA256 string
	Bytes                int64
	Networks             int
	Countries            []CountryCIDRCount
}

type countryMergeItem struct {
	row  CountryNetwork
	slot int
}
type countryMergeHeap []countryMergeItem

func (h countryMergeHeap) Len() int { return len(h) }
func (h countryMergeHeap) Less(i, j int) bool {
	a, b := h[i].row.Prefix, h[j].row.Prefix
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}
func (h countryMergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *countryMergeHeap) Push(v any)   { *h = append(*h, v.(countryMergeItem)) }
func (h *countryMergeHeap) Pop() any {
	old := *h
	n := len(old)
	v := old[n-1]
	old[n-1] = countryMergeItem{}
	*h = old[:n-1]
	return v
}

// VerifyCountrySelection jointly streams all explicitly selected immutable
// country files. Every file must independently match its original signed hash,
// length, code/count and parent; the combined address space must have NO
// overlaps, including nested prefixes from DIFFERENT otherwise valid files.
// Memory is O(selected countries), not O(network count). No row or partial
// metadata escapes on failure/cancellation; this still activates no rule.
func VerifyCountrySelection(ctx context.Context, a CountryAuthority, codes []string, inputs []io.Reader) (CountrySelectionMetadata, error) {
	var empty CountrySelectionMetadata
	if ctx == nil || len(codes) != len(inputs) {
		return empty, errors.New("country selection streams or context invalid")
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	assets, err := a.Select(codes)
	if err != nil {
		return empty, err
	}
	cursors := make([]*countryCIDRCursor, len(assets))
	var heads countryMergeHeap
	var totalBytes int64
	finish := func(slot int) error {
		metadata, err := cursors[slot].result()
		if err != nil {
			return err
		}
		if err := verifyCountryAssetMetadata(a, assets[slot], metadata); err != nil {
			return err
		}
		totalBytes += metadata.Bytes
		return nil
	}
	for i, asset := range assets {
		if inputs[i] == nil {
			return empty, errors.New("country selection stream missing")
		}
		cursor, err := newCountryCIDRCursor(ctx, &io.LimitedReader{R: inputs[i], N: asset.Bytes + 1})
		if err != nil {
			return empty, err
		}
		cursors[i] = cursor
		row, err := cursor.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return empty, errors.New("country selection lacks complete first network")
			}
			return empty, err
		}
		if row.CountryCode != asset.Code {
			return empty, errors.New("country selection file label differs from signed code")
		}
		heads = append(heads, countryMergeItem{row, i})
	}
	heap.Init(&heads)
	state := countryCIDRState{codes: map[string]int{}}
	for heads.Len() > 0 {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		item := heap.Pop(&heads).(countryMergeItem)
		if err := state.append(item.row); err != nil {
			return empty, err
		}
		row, err := cursors[item.slot].next()
		if errors.Is(err, io.EOF) {
			if err := finish(item.slot); err != nil {
				return empty, err
			}
			continue
		}
		if err != nil {
			return empty, err
		}
		if row.CountryCode != assets[item.slot].Code {
			return empty, errors.New("country selection file label differs from signed code")
		}
		heap.Push(&heads, countryMergeItem{row, item.slot})
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	counts := state.metadata(totalBytes, "", a.parent.digest, a.parent.manifest.SHA256)
	return CountrySelectionMetadata{a.SHA256(), counts.ParentManifestSHA256, counts.ParentDatabaseSHA256, totalBytes, counts.Networks, counts.Countries}, nil
}
