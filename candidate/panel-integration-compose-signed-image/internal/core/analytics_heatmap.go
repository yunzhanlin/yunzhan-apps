package core

import (
	"context"
	"encoding/hex"
	"slices"
	"sort"

	"local/panel/internal/appcatalog"
)

const AnalyticsLayoutHeatmapAppVersion = "2.4.4"

func analyticsClickViewport(value string) bool {
	switch value {
	case "narrow", "medium", "wide":
		return true
	default:
		return false
	}
}

func (s *Store) analyticsLayoutInstalled(ctx context.Context) bool {
	return s.analyticsHasReceipt(ctx, AnalyticsLayoutHeatmapAppVersion, appcatalog.AnalyticsGeographyVersion, appcatalog.AnalyticsSessionActivityVersion)
}

func (s *Store) analyticsHasReceipt(ctx context.Context, versions ...string) bool {
	var version, digest string
	if err := s.DB.QueryRowContext(ctx, `SELECT version, sha256 FROM app_registry_receipts
		WHERE app_id='website-analytics' AND scope='website-analytics'
		AND target='website-analytics'`).Scan(&version, &digest); err != nil || !slices.Contains(versions, version) {
		return false
	}
	raw, err := hex.DecodeString(digest)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == digest
}

type analyticsHeatLayoutKey struct {
	path, viewport string
	x, y           int
}

type analyticsHeatLayoutPoint struct {
	analyticsHeatPoint
	Viewport string `json:"viewport"`
}

type analyticsHeatLayouts struct {
	points  map[analyticsHeatLayoutKey]int
	bytes   int
	partial bool
}

func (h *analyticsHeatLayouts) observe(event AnalyticsEvent, x, y int) {
	viewport := event.ClickViewport
	if !analyticsClickViewport(viewport) {
		viewport = "unknown"
	}
	key := analyticsHeatLayoutKey{event.Path, viewport, x, y}
	if h.points == nil {
		h.points = make(map[analyticsHeatLayoutKey]int)
	}
	if h.points[key] == 0 {
		// Bound the additional report both by unique cells and output bytes.
		// The worst JSON escape expansion is six bytes per input byte.
		cost := 6*len(key.path) + 96
		if len(h.points) >= 2000 || h.bytes+cost > 1<<20 {
			h.partial = true
			return
		}
		h.bytes += cost
	}
	h.points[key]++
}

func (h *analyticsHeatLayouts) report(partial bool) map[string]any {
	rows := make([]analyticsHeatLayoutPoint, 0, len(h.points))
	for key, count := range h.points {
		rows = append(rows, analyticsHeatLayoutPoint{
			analyticsHeatPoint: analyticsHeatPoint{Path: key.path, X: key.x, Y: key.y, Count: count},
			Viewport:           key.viewport,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Viewport != b.Viewport {
			return a.Viewport < b.Viewport
		}
		if a.X != b.X {
			return a.X < b.X
		}
		return a.Y < b.Y
	})
	return map[string]any{"points": rows, "partial": partial || h.partial}
}
