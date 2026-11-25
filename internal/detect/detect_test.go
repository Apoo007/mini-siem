package detect

import (
	"testing"
	"time"

	"github.com/Apoo007/mini-siem/internal/parser"
)

func at(sec int) time.Time {
	return time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
}

func failed(sec int, ip string) parser.Event {
	return parser.Event{Timestamp: at(sec), Action: parser.ActionSSHFailed, User: "root", SourceIP: ip}
}

func countRule(alerts []Alert, rule string) int {
	n := 0
	for _, a := range alerts {
		if a.Rule == rule {
			n++
		}
	}
	return n
}

func TestBruteForceFiresOnceAtThreshold(t *testing.T) {
	var evs []parser.Event
	for i := 0; i < 7; i++ {
		evs = append(evs, failed(i*2, "203.0.113.45"))
	}
	alerts := Run(evs)
	if got := countRule(alerts, "SSH brute force"); got != 1 {
		t.Fatalf("got %d brute force alerts, want 1", got)
	}
}

func TestBruteForceBelowThreshold(t *testing.T) {
	var evs []parser.Event
	for i := 0; i < BruteForceThreshold-1; i++ {
		evs = append(evs, failed(i, "203.0.113.45"))
	}
	if got := countRule(Run(evs), "SSH brute force"); got != 0 {
		t.Fatalf("got %d alerts, want 0 below threshold", got)
	}
}

func TestBruteForceSlowAttemptsIgnored(t *testing.T) {
	var evs []parser.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, failed(i*60, "203.0.113.45")) // one per minute: only 3 in any 2-minute window
	}
	if got := countRule(Run(evs), "SSH brute force"); got != 0 {
		t.Fatalf("got %d alerts, want 0 for slow attempts", got)
	}
}

func TestSuccessAfterBruteForce(t *testing.T) {
	var evs []parser.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, failed(i, "203.0.113.45"))
	}
	evs = append(evs,
		parser.Event{Timestamp: at(600), Action: parser.ActionSSHSuccess, User: "backdoor", SourceIP: "203.0.113.45"},
		parser.Event{Timestamp: at(700), Action: parser.ActionSSHSuccess, User: "apoorva", SourceIP: "192.168.0.50"},
	)
	alerts := Run(evs)
	if got := countRule(alerts, "Login after brute force"); got != 1 {
		t.Fatalf("got %d alerts, want 1", got)
	}
}

func TestPrivilegedGroupOnly(t *testing.T) {
	evs := []parser.Event{
		{Timestamp: at(0), Action: parser.ActionGroupAdd, User: "bob", Detail: "sudo"},
		{Timestamp: at(1), Action: parser.ActionGroupAdd, User: "bob", Detail: "audio"},
	}
	if got := countRule(Run(evs), "User added to admin group"); got != 1 {
		t.Fatalf("got %d alerts, want 1 (only sudo)", got)
	}
}

func TestSampleLogTellsTheAttackStory(t *testing.T) {
	events, _, err := parser.ParseFile("../../testdata/auth.log", 2026)
	if err != nil {
		t.Fatal(err)
	}
	alerts := Run(events)
	want := []string{"SSH brute force", "New local user", "User added to admin group", "Login after brute force"}
	if len(alerts) != len(want) {
		t.Fatalf("got %d alerts, want %d", len(alerts), len(want))
	}
	for i, rule := range want {
		if alerts[i].Rule != rule {
			t.Errorf("alert %d = %q, want %q", i, alerts[i].Rule, rule)
		}
	}
}