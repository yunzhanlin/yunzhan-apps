package core

import (
	"errors"
	"sort"
)

const AnalyticsNavigationOrderAppVersion = "2.4.1"
const analyticsNavigationSequenceLimit int64 = 1000000000

func validateAnalyticsNavigationSequence(v *AnalyticsEvent) error {
	if v.NavigationSeq < 0 || v.NavigationSeq > analyticsNavigationSequenceLimit {
		return errors.New("页面访问顺序无效或超出范围")
	}
	if v.Kind != "pageview" {
		v.NavigationSeq = 0
	}
	return nil
}

type analyticsPageOrdering struct {
	Events          []AnalyticsEvent
	Source          string
	Uncertain       bool
	ReceivedOrdered bool
}

// The collector's asynchronous requests can arrive out of navigation order,
// including within one server-clock second. A complete, non-conflicting
// browser sequence orders visits within one scoped browser session. It is
// analytics metadata, never evidence of payment or a business transaction.
// Legacy/mixed/conflicting metadata retains the original server arrival order
// and is explicitly labelled uncertain; historical rows are never rewritten.
func analyticsOrderedPageviews(events []AnalyticsEvent) analyticsPageOrdering {
	out := analyticsPageOrdering{Events: append([]AnalyticsEvent(nil), events...), Source: "server-receive-order", Uncertain: true, ReceivedOrdered: true}
	if len(events) == 0 {
		return out
	}
	type visit struct {
		sequence int64
		path     string
	}
	sequences := map[int64]string{}
	pages := map[string]visit{}
	first := events[0]
	for _, v := range events {
		if v.Kind != "pageview" || v.Visitor != first.Visitor || v.Session != first.Session || !ValidID(v.PageID) || v.NavigationSeq < 1 || v.NavigationSeq > analyticsNavigationSequenceLimit {
			return out
		}
		if page, exists := sequences[v.NavigationSeq]; exists && page != v.PageID {
			return out
		}
		identity := visit{sequence: v.NavigationSeq, path: v.Path}
		if old, exists := pages[v.PageID]; exists && old != identity {
			return out
		}
		sequences[v.NavigationSeq], pages[v.PageID] = v.PageID, identity
	}
	sort.SliceStable(out.Events, func(i, j int) bool { return out.Events[i].NavigationSeq < out.Events[j].NavigationSeq })
	out.Source, out.Uncertain = "browser-navigation-sequence", false
	for i := 1; i < len(out.Events); i++ {
		if out.Events[i].Received < out.Events[i-1].Received {
			out.ReceivedOrdered = false
		}
	}
	return out
}
