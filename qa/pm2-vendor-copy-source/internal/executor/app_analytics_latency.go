package executor

import (
	"context"
	"sort"
)

// Exact nearest-rank quantiles are for the accepted, filtered population, not
// a reservoir or the first N requests. If the bounded population is exceeded,
// discard all samples and report unavailable quantiles rather than a biased
// tail. Histogram counters continue to cover every accepted request.
const analyticsLatencySampleLimit = 250000

var analyticsLatencyBounds = [...]float64{.05, .1, .25, .5, 1, 2, 5, 10}
var analyticsLatencyLabels = [...]string{"0–50 ms", ">50–100 ms", ">100–250 ms", ">250–500 ms", ">500–1000 ms", ">1–2 s", ">2–5 s", ">5–10 s", ">10 s"}

type analyticsLatencyBucket struct {
	Range        string   `json:"range"`
	UpperSeconds *float64 `json:"upper_seconds"`
	Requests     int      `json:"requests"`
	Percent      float64  `json:"percent"`
}

type analyticsLatencyReport struct {
	Source             string                   `json:"source"`
	Method             string                   `json:"method"`
	Requests           int                      `json:"requests"`
	Samples            int                      `json:"samples"`
	SampleLimit        int                      `json:"sample_limit"`
	QuantilesAvailable bool                     `json:"quantiles_available"`
	SampleLimited      bool                     `json:"sample_limited"`
	PopulationPartial  bool                     `json:"population_partial"`
	P50                *float64                 `json:"p50_seconds"`
	P90                *float64                 `json:"p90_seconds"`
	P95                *float64                 `json:"p95_seconds"`
	P99                *float64                 `json:"p99_seconds"`
	Histogram          []analyticsLatencyBucket `json:"histogram"`
}

type analyticsLatencyAccumulator struct {
	requests int
	samples  []float64
	limited  bool
	buckets  [9]int
}

// Called only after the shared accumulator's finite/range and request-filter
// validation; no query, IP, user agent or per-request identity is retained.
func (a *analyticsLatencyAccumulator) add(seconds float64) {
	a.requests++
	bucket := len(analyticsLatencyBounds)
	for i, upper := range analyticsLatencyBounds {
		if seconds <= upper {
			bucket = i
			break
		}
	}
	a.buckets[bucket]++
	if a.limited {
		return
	}
	if len(a.samples) == analyticsLatencySampleLimit {
		a.limited = true
		a.samples = nil
		return
	}
	// No retained backing array exceeds 2 MiB; growth briefly retains both
	// arrays (less than 4 MiB), still independent of request identity or count.
	if len(a.samples) == cap(a.samples) {
		n := min(max(1024, 2*cap(a.samples)), analyticsLatencySampleLimit)
		next := make([]float64, len(a.samples), n)
		copy(next, a.samples)
		a.samples = next
	}
	a.samples = append(a.samples, seconds)
}

func (a *analyticsLatencyAccumulator) report(ctx context.Context, partial bool) (analyticsLatencyReport, error) {
	out := analyticsLatencyReport{Source: "nginx_request_time", Method: "nearest_rank", Requests: a.requests, Samples: len(a.samples), SampleLimit: analyticsLatencySampleLimit, SampleLimited: a.limited, PopulationPartial: partial, Histogram: make([]analyticsLatencyBucket, len(a.buckets))}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	for i, n := range a.buckets {
		b := analyticsLatencyBucket{Range: analyticsLatencyLabels[i], Requests: n}
		if i < len(analyticsLatencyBounds) {
			upper := analyticsLatencyBounds[i]
			b.UpperSeconds = &upper
		}
		if a.requests > 0 {
			b.Percent = 100 * float64(n) / float64(a.requests)
		}
		out.Histogram[i] = b
	}
	if len(a.samples) == 0 || a.limited {
		return out, nil
	}
	sort.Float64s(a.samples)
	if err := ctx.Err(); err != nil {
		return out, err
	}
	// Integer ceiling avoids float-rounding errors at exact rank boundaries.
	quantile := func(percent int) *float64 {
		rank := (len(a.samples)*percent + 99) / 100
		v := a.samples[rank-1]
		return &v
	}
	out.P50, out.P90, out.P95, out.P99 = quantile(50), quantile(90), quantile(95), quantile(99)
	out.QuantilesAvailable = true
	return out, nil
}
