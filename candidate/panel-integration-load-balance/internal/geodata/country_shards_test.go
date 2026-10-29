package geodata

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestCountryShardsKeepOriginalPerFileBoundsAndFixedPublisherAggregate(t *testing.T) {
	if maxCountryNetworks != 1<<20 || MaxCountryCIDRBytes != 64<<20 || maxCountryPublishNetworks != 4<<20 {
		t.Fatal("original consumer bounds widened")
	}
	for _, values := range [][2]int{{1, 1}, {maxCountryNetworks, maxCountryNetworks}, {maxCountryPublishNetworks, 1}} {
		if err := countryShardBudget(values[0], values[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, values := range [][2]int{{0, 0}, {0, 1}, {maxCountryPublishNetworks + 1, 1}, {maxCountryNetworks + 1, maxCountryNetworks + 1}} {
		if err := countryShardBudget(values[0], values[1]); err == nil {
			t.Fatal("publisher or per-file budget bypassed", values)
		}
	}
}

func TestCountryShardsSameVerifiedTreeAsIndependentSelection(t *testing.T) {
	for _, text := range []string{"8.8.8.0/24", "2606:4700::/32"} {
		t.Run(text, func(t *testing.T) {
			s := countryFixture(t, netip.MustParsePrefix(text), true, fixtureRecord())
			selected, err := s.CountryPrefixes(context.Background(), []string{"CN", "US"}, 8)
			if err != nil || len(selected.Networks) == 0 {
				t.Fatal(err)
			}
			got, err := s.CountryShards(context.Background())
			if err != nil || got.RecordsVisited != selected.RecordsVisited || got.Networks != len(selected.Networks) || len(got.Shards) != 1 || got.Shards[0].Code != selected.Networks[0].CountryCode || !reflect.DeepEqual(got.Shards[0].Data, selected) {
				t.Fatal("shards differ from original independent selected traversal", got, err)
			}
		})
	}
}

func TestCountryShardsCancellationClosedAndMalformedProduceZeroPartialResult(t *testing.T) {
	for _, kind := range []string{"cancelled", "closed", "malformed", "private-only"} {
		t.Run(kind, func(t *testing.T) {
			row := fixtureRecord()
			if kind == "malformed" {
				row["country"] = map[string]any{"iso_code": "bad"}
			}
			prefix := netip.MustParsePrefix("8.8.8.0/24")
			if kind == "private-only" {
				prefix = netip.MustParsePrefix("10.0.0.0/8")
			}
			s := countryFixture(t, prefix, false, row)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			if kind == "closed" {
				s.Close()
			}
			got, err := s.CountryShards(ctx)
			if kind == "private-only" {
				if err != nil || got.Networks != 0 || len(got.Shards) != 0 {
					t.Fatal("private country became coverage", got, err)
				}
				return
			}
			if err == nil || !reflect.DeepEqual(got, CountryShardExport{}) || kind == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("partial shard inventory or cancellation accepted", got, err)
			}
		})
	}
}
