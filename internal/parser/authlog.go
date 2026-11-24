// Package parser turns raw log lines into structured events.
package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Action describes what happened in a log line.
type Action string

const (
	ActionSSHFailed   Action = "ssh_failed"
	ActionSSHSuccess  Action = "ssh_success"
	ActionSudo        Action = "sudo"
	ActionUserCreated Action = "user_created"
	ActionGroupAdd    Action = "group_add"
	ActionOther       Action = "other"
)

// Event is one parsed line from auth.log.
type Event struct {
	Timestamp time.Time
	Host      string
	Program   string
	PID       int
	Action    Action
	User      string
	SourceIP  string
	Detail    string // extra info, e.g. the sudo command or the group name
	Message   string
	Raw       string
}

// Syslog line: "Nov 24 09:15:22 web01 sshd[1250]: message"
var lineRe = regexp.MustCompile(`^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([\w.\-]+)(?:\[(\d+)\])?: (.*)$`)

var (
	failedRe   = regexp.MustCompile(`^Failed password for (?:invalid user )?(\S+) from (\S+) port`)
	acceptedRe = regexp.MustCompile(`^Accepted (?:password|publickey) for (\S+) from (\S+) port`)
	sudoRe     = regexp.MustCompile(`^\s*(\S+) : .*COMMAND=(.*)$`)
	useraddRe  = regexp.MustCompile(`^new user: name=([^,]+),`)
	groupAddRe = regexp.MustCompile(`^add '([^']+)' to group '([^']+)'`)
)

// ParseLine parses one auth.log line. auth.log has no year, so the caller gives it.
func ParseLine(line string, year int) (Event, error) {
	m := lineRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("not a syslog line: %q", line)
	}

	ts, err := time.Parse("Jan _2 15:04:05", m[1])
	if err != nil {
		return Event{}, fmt.Errorf("bad timestamp %q: %w", m[1], err)
	}
	ts = ts.AddDate(year, 0, 0)

	ev := Event{
		Timestamp: ts,
		Host:      m[2],
		Program:   m[3],
		Message:   m[5],
		Raw:       line,
		Action:    ActionOther,
	}
	if m[4] != "" {
		ev.PID, _ = strconv.Atoi(m[4])
	}

	classify(&ev)
	return ev, nil
}

// classify fills Action, User, SourceIP and Detail based on the program and message.
func classify(ev *Event) {
	msg := ev.Message
	switch ev.Program {
	case "sshd":
		if m := failedRe.FindStringSubmatch(msg); m != nil {
			ev.Action, ev.User, ev.SourceIP = ActionSSHFailed, m[1], m[2]
		} else if m := acceptedRe.FindStringSubmatch(msg); m != nil {
			ev.Action, ev.User, ev.SourceIP = ActionSSHSuccess, m[1], m[2]
		}
	case "sudo":
		if m := sudoRe.FindStringSubmatch(msg); m != nil {
			ev.Action, ev.User, ev.Detail = ActionSudo, m[1], m[2]
		}
	case "useradd":
		if m := useraddRe.FindStringSubmatch(msg); m != nil {
			ev.Action, ev.User = ActionUserCreated, m[1]
		}
	case "usermod":
		if m := groupAddRe.FindStringSubmatch(msg); m != nil {
			ev.Action, ev.User, ev.Detail = ActionGroupAdd, m[1], m[2]
		}
	}
}

// ParseFile reads an auth.log file and returns all events it could parse,
// plus how many lines it had to skip.
func ParseFile(path string, year int) ([]Event, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var events []Event
	skipped := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		ev, err := ParseLine(line, year)
		if err != nil {
			skipped++
			continue
		}
		events = append(events, ev)
	}
	return events, skipped, sc.Err()
}