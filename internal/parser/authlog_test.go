package parser

import "testing"

func TestParseLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		action Action
		user   string
		ip     string
		detail string
	}{
		{
			name:   "failed password",
			line:   "Nov 24 09:15:22 web01 sshd[1250]: Failed password for root from 203.0.113.45 port 40112 ssh2",
			action: ActionSSHFailed, user: "root", ip: "203.0.113.45",
		},
		{
			name:   "failed password invalid user",
			line:   "Nov 24 09:15:33 web01 sshd[1251]: Failed password for invalid user admin from 203.0.113.45 port 40130 ssh2",
			action: ActionSSHFailed, user: "admin", ip: "203.0.113.45",
		},
		{
			name:   "accepted publickey",
			line:   "Nov 24 09:12:01 web01 sshd[1201]: Accepted publickey for apoorva from 192.168.0.50 port 51234 ssh2",
			action: ActionSSHSuccess, user: "apoorva", ip: "192.168.0.50",
		},
		{
			name:   "sudo",
			line:   "Nov 24 09:20:10 web01 sudo:  apoorva : TTY=pts/0 ; PWD=/home/apoorva ; USER=root ; COMMAND=/usr/bin/apt update",
			action: ActionSudo, user: "apoorva", detail: "/usr/bin/apt update",
		},
		{
			name:   "user created",
			line:   "Nov 24 09:25:44 web01 useradd[1302]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash",
			action: ActionUserCreated, user: "backdoor",
		},
		{
			name:   "added to group",
			line:   "Nov 24 09:26:01 web01 usermod[1305]: add 'backdoor' to group 'sudo'",
			action: ActionGroupAdd, user: "backdoor", detail: "sudo",
		},
		{
			name:   "unknown message",
			line:   "Nov 24 09:40:00 web01 CRON[1400]: pam_unix(cron:session): session opened for user root",
			action: ActionOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := ParseLine(tt.line, 2026)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ev.Action != tt.action {
				t.Errorf("action = %q, want %q", ev.Action, tt.action)
			}
			if ev.User != tt.user {
				t.Errorf("user = %q, want %q", ev.User, tt.user)
			}
			if ev.SourceIP != tt.ip {
				t.Errorf("ip = %q, want %q", ev.SourceIP, tt.ip)
			}
			if ev.Detail != tt.detail {
				t.Errorf("detail = %q, want %q", ev.Detail, tt.detail)
			}
			if ev.Timestamp.Year() != 2026 {
				t.Errorf("year = %d, want 2026", ev.Timestamp.Year())
			}
		})
	}
}

func TestParseLineRejectsGarbage(t *testing.T) {
	if _, err := ParseLine("this is not a log line", 2026); err == nil {
		t.Error("expected an error for a non-syslog line")
	}
}

func TestParseFile(t *testing.T) {
	events, skipped, err := ParseFile("../../testdata/auth.log", 2026)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(events) != 12 {
		t.Errorf("got %d events, want 12", len(events))
	}
	if skipped != 0 {
		t.Errorf("skipped %d lines, want 0", skipped)
	}
}
