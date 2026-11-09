package core

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func analyticsAdmissionClock() time.Time {
	return time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
}

func TestAnalyticsMinuteAdmissionCoversChurnAndFreshClients(t *testing.T) {
	a := &Server{}
	start := analyticsAdmissionClock()
	for i := 0; i < analyticsMinuteGrantLimit; i++ {
		now := start.Add(time.Duration(i/analyticsGlobalSecondLimit) * time.Second)
		identity := fmt.Sprintf("unverified-proxy-visitor:site-a:%032x", i)
		if i == 2048 {
			identity = "192.0.2.211"
		}
		if i == 2049 {
			identity = "unverified-proxy-visitor:site-b:other-visitor"
		}
		if i == 2050 {
			identity = "2001:db8::212"
		}
		if !a.analyticsGlobalAllowed(now) || !a.analyticsClientAllowed(identity, now, now) {
			t.Fatalf("identity occupancy denied an otherwise valid global grant at%d", i)
		}
	}
	if len(a.analyticsRates) != 6000 || a.analyticsMinute.Count != 6000 {
		t.Fatal("minute accounting not exact", len(a.analyticsRates), a.analyticsMinute)
	}
	if a.analyticsGlobalAllowed(start.Add(59*time.Second + 999*time.Millisecond)) {
		t.Fatal("full minute accepted an extra grant")
	}
	next := start.Add(time.Minute)
	if !a.analyticsGlobalAllowed(next) || !a.analyticsClientAllowed("fresh-next-minute", next, next) || len(a.analyticsRates) != 1 {
		t.Fatal("minute rollover did not release the original bounded capacity")
	}
}

func TestAnalyticsCarriedRequestMustReenterCurrentGlobalBudget(t *testing.T) {
	a := &Server{}
	start := analyticsAdmissionClock()
	admitted := start.Add(59 * time.Second)
	if !a.analyticsGlobalAllowed(admitted) {
		t.Fatal("original admission")
	}
	current := start.Add(time.Minute)
	for i := 0; i < analyticsGlobalSecondLimit; i++ {
		if !a.analyticsGlobalAllowed(current) {
			t.Fatal("new minute ordinary admission", i)
		}
	}
	if a.analyticsClientAllowed("carried-legacy-visitor", admitted, current) || len(a.analyticsRates) != 0 {
		t.Fatal("old-minute grant allocated through a full current-second budget")
	}
	later := current.Add(time.Second)
	if !a.analyticsClientAllowed("another-carried-visitor", admitted, later) {
		t.Fatal("a new carried request with current capacity was rejected")
	}
	if a.analyticsGlobal.Count != 1 || a.analyticsMinute.Count != 101 || len(a.analyticsRates) != 1 {
		t.Fatal("carried grant was not charged exactly once to the allocation window", a.analyticsGlobal, a.analyticsMinute)
	}
	for _, rate := range a.analyticsRates {
		if rate.Window != later.Unix()/60 || rate.Count != 1 {
			t.Fatal("wrong allocation minute", rate)
		}
	}
}

func TestAnalyticsStaleOrReversedClockCannotResetCurrentBudgets(t *testing.T) {
	a := &Server{}
	start := analyticsAdmissionClock()
	old := start.Add(59 * time.Second)
	current := start.Add(time.Minute)
	if !a.analyticsGlobalAllowed(old) || !a.analyticsGlobalAllowed(current) || !a.analyticsClientAllowed("current-managed", current, current) {
		t.Fatal("ordinary current client failed")
	}
	global, minute := a.analyticsGlobal, a.analyticsMinute
	if a.analyticsGlobalAllowed(old) || a.analyticsClientAllowed("stale-reader", old, old) || a.analyticsClientAllowed("clock-reversal", current, old) {
		t.Fatal("stale time rewound admission")
	}
	if a.analyticsGlobal != global || a.analyticsMinute != minute || len(a.analyticsRates) != 1 {
		t.Fatal("refused stale request changed active accounting")
	}
}

func TestAnalyticsExactClientMinuteLimitAndOtherClientsStayIndependent(t *testing.T) {
	a := &Server{}
	start := analyticsAdmissionClock()
	for i := 0; i < analyticsIdentityMinuteLimit; i++ {
		now := start.Add(time.Duration(i/analyticsGlobalSecondLimit) * time.Second)
		if !a.analyticsGlobalAllowed(now) || !a.analyticsClientAllowed("192.0.2.21", now, now) {
			t.Fatal("ordinary client grant", i)
		}
	}
	now := start.Add(12 * time.Second)
	if !a.analyticsGlobalAllowed(now) || a.analyticsClientAllowed("192.0.2.21", now, now) {
		t.Fatal("client minute limit changed")
	}
	if !a.analyticsGlobalAllowed(now) || !a.analyticsClientAllowed("192.0.2.22", now, now) {
		t.Fatal("other client inherited the exhausted limit")
	}
	if len(a.analyticsRates) != 2 || a.analyticsMinute.Count != 1202 {
		t.Fatal("exact client accounting changed")
	}
}

func TestAnalyticsConcurrentCarriedRequestsRemainWithinCurrentBudget(t *testing.T) {
	a := &Server{}
	start := analyticsAdmissionClock()
	admissions := make([]time.Time, 200)
	for i := range admissions {
		admissions[i] = start.Add(time.Duration(58+i/100) * time.Second)
		if !a.analyticsGlobalAllowed(admissions[i]) {
			t.Fatal("initial carried admission", i)
		}
	}
	var allowed atomic.Int32
	var wg sync.WaitGroup
	now := start.Add(time.Minute)
	for i, at := range admissions {
		wg.Add(1)
		go func(i int, at time.Time) {
			defer wg.Done()
			if a.analyticsClientAllowed(fmt.Sprintf("carried-%032x", i), at, now) {
				allowed.Add(1)
			}
		}(i, at)
	}
	wg.Wait()
	if allowed.Load() != 100 || len(a.analyticsRates) != 100 || a.analyticsGlobal.Count != 100 || a.analyticsMinute.Count != 100 {
		t.Fatal("concurrent re-admission exceeded the unchanged current budget", allowed.Load(), len(a.analyticsRates), a.analyticsGlobal, a.analyticsMinute)
	}
}
