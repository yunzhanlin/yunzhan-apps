package core

import (
	"errors"
	"math"
	"sort"
)

const AnalyticsRouteAppVersion = "2.4.0"
const analyticsPerformanceGroupLimit = 100

func analyticsPassivePerformance(kind string) bool {
	return kind == "performance" || kind == "route-performance"
}

// Route readiness is explicitly reported by the website after its own render
// promise. It is not a new document navigation, Core Web Vital or proof of a
// business transaction. Omission is unknown; an explicit measured zero is valid.
func validateAnalyticsRouteTiming(v *AnalyticsEvent) error {
	if n := v.RouteReadyMillis; n != nil && (math.IsNaN(*n) || math.IsInf(*n, 0) || *n < 0 || *n > 300000) {
		return errors.New("路由就绪耗时无效或超出五分钟范围")
	}
	if v.Kind == "route-performance" {
		if v.RouteReadyMillis == nil || v.PerformanceSeq < 1 {
			return errors.New("路由性能缺少实际测量值或事件顺序")
		}
	} else {
		v.RouteReadyMillis = nil
	}
	return nil
}

type analyticsPerformancePage struct {
	Path        string                    `json:"path"`
	Kind        string                    `json:"kind"`
	Navigations int                       `json:"navigations"`
	Metrics     map[string]map[string]any `json:"metrics"`
}

type analyticsPerformancePages struct {
	Rows          []analyticsPerformancePage `json:"rows"`
	Partial       bool                       `json:"partial"`
	SampledVisits int                        `json:"sampled_visits"`
	GroupLimit    int                        `json:"group_limit"`
}

func analyticsPerformanceMetric(events []AnalyticsEvent, value func(AnalyticsEvent) (float64, bool)) map[string]any {
	values := []float64{}
	for _, v := range events {
		if n, measured := value(v); measured && !math.IsNaN(n) && !math.IsInf(n, 0) && n >= 0 {
			values = append(values, n)
		}
	}
	sort.Float64s(values)
	out := map[string]any{"samples": len(values)}
	if len(values) > 0 {
		out["p75"] = values[int(math.Ceil(float64(len(values))*.75))-1]
	}
	return out
}

func analyticsDocumentPerformance(events []AnalyticsEvent) map[string]map[string]any {
	measure := func(fn func(AnalyticsEvent) float64, available func(AnalyticsEvent) bool) map[string]any {
		return analyticsPerformanceMetric(events, func(v AnalyticsEvent) (float64, bool) {
			n := fn(v)
			return n, v.Kind == "performance" && (n > 0 || available != nil && available(v))
		})
	}
	return map[string]map[string]any{
		"ttfb": measure(func(v AnalyticsEvent) float64 { return v.TTFB }, nil),
		"fcp":  measure(func(v AnalyticsEvent) float64 { return v.FCP }, nil),
		"lcp":  measure(func(v AnalyticsEvent) float64 { return v.LCP }, nil),
		"cls":  measure(func(v AnalyticsEvent) float64 { return v.CLS }, func(v AnalyticsEvent) bool { return v.CLSAvailable }),
		"inp":  measure(func(v AnalyticsEvent) float64 { return v.INP }, func(v AnalyticsEvent) bool { return v.INPAvailable }),
	}
}

func analyticsPerformanceByPage(events []AnalyticsEvent, partial bool) analyticsPerformancePages {
	groups := map[[2]string][]AnalyticsEvent{}
	for _, v := range events {
		if !analyticsPassivePerformance(v.Kind) {
			continue
		}
		key := [2]string{v.Path, v.Kind}
		groups[key] = append(groups[key], v)
	}
	out := analyticsPerformancePages{Rows: []analyticsPerformancePage{}, Partial: partial, SampledVisits: len(events), GroupLimit: analyticsPerformanceGroupLimit}
	for key, group := range groups {
		row := analyticsPerformancePage{Path: key[0], Kind: "document", Navigations: len(group), Metrics: analyticsDocumentPerformance(group)}
		if key[1] == "route-performance" {
			row.Kind = "spa"
			row.Metrics = map[string]map[string]any{"route_ready_ms": analyticsPerformanceMetric(group, func(v AnalyticsEvent) (float64, bool) {
				if v.RouteReadyMillis == nil {
					return 0, false
				}
				return *v.RouteReadyMillis, true
			})}
		}
		out.Rows = append(out.Rows, row)
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		a, b := out.Rows[i], out.Rows[j]
		if a.Navigations != b.Navigations {
			return a.Navigations > b.Navigations
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Kind < b.Kind
	})
	if len(out.Rows) > analyticsPerformanceGroupLimit {
		out.Rows = out.Rows[:analyticsPerformanceGroupLimit]
		out.Partial = true
	}
	return out
}
