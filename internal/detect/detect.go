// Package detect looks for suspicious activity in parsed events.
package detect

import (
	"fmt"
	"sort"
	"time"

	"github.com/Apoo007/mini-siem/internal/parser"
)

// Severity levels for alerts.
const (
	SeverityMedium = "MEDIUM"
	SeverityHigh   = "HIGH"
)

// Alert is one detection hit.
type Alert struct {
	Time      time.Time
	Rule      string
	Severity  string
	MitreID   string
	MitreName string
	User      string
	SourceIP  string
	Summary   string
}

// Settings for the brute force rule.
const (
	BruteForceThreshold = 5               // failed logins...
	BruteForceWindow    = 2 * time.Minute // ...within this time, from one IP
	FollowUpWindow      = time.Hour       // a success this soon after brute force is suspicious
)

// Privileged groups on Linux. Adding a user to one gives admin rights.
var privilegedGroups = map[string]bool{"sudo": true, "wheel": true, "admin": true, "root": true}

// Run runs all rules on the events and returns alerts sorted by time.
func Run(events []parser.Event) []Alert {
	sorted := make([]parser.Event, len(events))
	copy(sorted, events)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	var alerts []Alert
	brute := bruteForce(sorted)
	alerts = append(alerts, brute...)
	alerts = append(alerts, successAfterBruteForce(sorted, brute)...)
	alerts = append(alerts, newUser(sorted)...)
	alerts = append(alerts, privilegedGroupAdd(sorted)...)

	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].Time.Before(alerts[j].Time) })
	return alerts
}

// bruteForce alerts when one IP has BruteForceThreshold failed SSH logins
// within BruteForceWindow. One alert per burst.
func bruteForce(events []parser.Event) []Alert {
	failsByIP := map[string][]parser.Event{}
	for _, ev := range events {
		if ev.Action == parser.ActionSSHFailed {
			failsByIP[ev.SourceIP] = append(failsByIP[ev.SourceIP], ev)
		}
	}

	var alerts []Alert
	for ip, fails := range failsByIP {
		start := 0
		alerted := false
		for end := range fails {
			// Move the window start forward until it fits in BruteForceWindow.
			for fails[end].Timestamp.Sub(fails[start].Timestamp) > BruteForceWindow {
				start++
				alerted = false
			}
			count := end - start + 1
			if count >= BruteForceThreshold && !alerted {
				alerts = append(alerts, Alert{
					Time:      fails[end].Timestamp,
					Rule:      "SSH brute force",
					Severity:  SeverityMedium,
					MitreID:   "T1110.001",
					MitreName: "Brute Force: Password Guessing",
					User:      fails[end].User,
					SourceIP:  ip,
					Summary:   fmt.Sprintf("%d failed SSH logins from %s within %s", count, ip, BruteForceWindow),
				})
				alerted = true
			}
		}
	}
	return alerts
}

// successAfterBruteForce alerts when an IP that was brute forcing
// later logs in successfully. The attacker probably got in.
func successAfterBruteForce(events []parser.Event, brute []Alert) []Alert {
	lastBrute := map[string]time.Time{}
	for _, a := range brute {
		if a.Time.After(lastBrute[a.SourceIP]) {
			lastBrute[a.SourceIP] = a.Time
		}
	}

	var alerts []Alert
	for _, ev := range events {
		if ev.Action != parser.ActionSSHSuccess {
			continue
		}
		t, ok := lastBrute[ev.SourceIP]
		if !ok || ev.Timestamp.Before(t) || ev.Timestamp.Sub(t) > FollowUpWindow {
			continue
		}
		alerts = append(alerts, Alert{
			Time:      ev.Timestamp,
			Rule:      "Login after brute force",
			Severity:  SeverityHigh,
			MitreID:   "T1078",
			MitreName: "Valid Accounts",
			User:      ev.User,
			SourceIP:  ev.SourceIP,
			Summary:   fmt.Sprintf("%s logged in from %s, an IP that was brute forcing %s earlier", ev.User, ev.SourceIP, ev.Timestamp.Sub(t).Round(time.Minute)),
		})
	}
	return alerts
}

// newUser alerts on every new local account.
func newUser(events []parser.Event) []Alert {
	var alerts []Alert
	for _, ev := range events {
		if ev.Action != parser.ActionUserCreated {
			continue
		}
		alerts = append(alerts, Alert{
			Time:      ev.Timestamp,
			Rule:      "New local user",
			Severity:  SeverityMedium,
			MitreID:   "T1136.001",
			MitreName: "Create Account: Local Account",
			User:      ev.User,
			Summary:   fmt.Sprintf("new user %q created on %s", ev.User, ev.Host),
		})
	}
	return alerts
}

// privilegedGroupAdd alerts when a user is added to an admin group.
func privilegedGroupAdd(events []parser.Event) []Alert {
	var alerts []Alert
	for _, ev := range events {
		if ev.Action != parser.ActionGroupAdd || !privilegedGroups[ev.Detail] {
			continue
		}
		alerts = append(alerts, Alert{
			Time:      ev.Timestamp,
			Rule:      "User added to admin group",
			Severity:  SeverityHigh,
			MitreID:   "T1098",
			MitreName: "Account Manipulation",
			User:      ev.User,
			Summary:   fmt.Sprintf("%q added to privileged group %q", ev.User, ev.Detail),
		})
	}
	return alerts
}
