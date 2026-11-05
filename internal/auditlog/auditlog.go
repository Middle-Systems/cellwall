// Package auditlog reads the gateway's audit log (JSON Lines, rotated) for `kennel logs`.
package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
	"github.com/middle-systems/kennel/internal/policy"
	"github.com/middle-systems/kennel/internal/proxy"
)

// Filter selects records.
type Filter struct {
	Since      time.Time // zero = no lower bound
	DeniedOnly bool      // denied or errored connection decisions only
}

// Match reports whether r passes the filter.
func (f Filter) Match(r audit.Record) bool {
	if !f.Since.IsZero() && r.TS.Before(f.Since) {
		return false
	}
	if f.DeniedOnly {
		return r.Event == audit.EventDecision && (r.Action == audit.ActionDeny || r.Action == audit.ActionError)
	}
	return true
}

// Files lists the log files in age order, oldest first: audit.jsonl.N ... audit.jsonl.1, audit.jsonl.
func Files(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	type rotated struct {
		n    int
		path string
	}
	var rot []rotated
	active := ""
	for _, en := range entries {
		name := en.Name()
		switch {
		case name == audit.FileName:
			active = filepath.Join(dir, name)
		case strings.HasPrefix(name, audit.FileName+"."):
			if n, err := strconv.Atoi(strings.TrimPrefix(name, audit.FileName+".")); err == nil && n > 0 {
				rot = append(rot, rotated{n, filepath.Join(dir, name)})
			}
		}
	}
	sort.Slice(rot, func(i, j int) bool { return rot[i].n > rot[j].n })
	var out []string
	for _, r := range rot {
		out = append(out, r.path)
	}
	if active != "" {
		out = append(out, active)
	}
	return out, nil
}

// Read returns every matching record, oldest first. Lines that are not valid records (a torn
// final line, for example) are skipped and counted.
func Read(dir string, f Filter) (recs []audit.Record, skipped int, err error) {
	files, err := Files(dir)
	if err != nil {
		return nil, 0, err
	}
	for _, p := range files {
		fh, err := os.Open(p) //nolint:gosec // the audit directory under the project's state dir
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue // rotated away between listing and opening
			}
			return nil, skipped, err
		}
		n := scan(fh, func(r audit.Record) {
			if f.Match(r) {
				recs = append(recs, r)
			}
		})
		skipped += n
		_ = fh.Close()
	}
	return recs, skipped, nil
}

// scan feeds every valid record to fn and returns how many lines were not records.
func scan(r io.Reader, fn func(audit.Record)) (skipped int) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			var rec audit.Record
			if json.Unmarshal(line, &rec) == nil && rec.Event != "" {
				fn(rec)
			} else {
				skipped++
			}
		}
		if err != nil {
			return skipped
		}
	}
}

// Follow prints new matching records as they are appended until ctx is done. It starts at the end
// of the active file and survives rotation.
//
// The file is opened only for the instant of each read and never held between polls. On Windows an
// open file cannot be renamed, and the gateway rotates the log by renaming it (through the bind
// mount), so a reader that kept the handle would make rotation fail.
func Follow(ctx context.Context, dir string, f Filter, emit func(audit.Record), poll time.Duration) error {
	if poll <= 0 {
		poll = 300 * time.Millisecond
	}
	path := filepath.Join(dir, audit.FileName)
	var (
		info   os.FileInfo
		offset int64
		carry  []byte
	)
	if st, err := os.Stat(path); err == nil {
		info, offset = st, st.Size()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(poll):
		}
		cur, err := os.Stat(path)
		if err != nil {
			info = nil // not there (mid-rotation); start from the top when it reappears
			continue
		}
		// A different file at the path (rotation) or a shorter one: start again from the top.
		if info == nil || !os.SameFile(cur, info) || cur.Size() < offset {
			offset, carry = 0, nil
		}
		info = cur
		if cur.Size() == offset {
			continue
		}
		data, err := readFrom(path, offset)
		if err != nil {
			continue
		}
		offset += int64(len(data))
		data = append(carry, data...)
		carry = nil
		for len(data) > 0 {
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				carry = append([]byte(nil), data...) // a partial line: wait for the rest
				break
			}
			var rec audit.Record
			if json.Unmarshal(data[:i], &rec) == nil && rec.Event != "" && f.Match(rec) {
				emit(rec)
			}
			data = data[i+1:]
		}
	}
}

// readFrom returns the bytes of path from offset to the end, holding the file open only briefly.
func readFrom(path string, offset int64) ([]byte, error) {
	fh, err := os.Open(path) //nolint:gosec // the audit directory under the project's state dir
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(fh)
}

// ParseSince accepts a Go duration ("90m", "1h30m") or a day count ("2d") and returns the time
// that far before now.
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 {
			return time.Time{}, fmt.Errorf("invalid --since %q (examples: 30m, 2h, 1d)", s)
		}
		return now.Add(-time.Duration(n) * 24 * time.Hour), nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil || dur < 0 {
		return time.Time{}, fmt.Errorf("invalid --since %q (examples: 30m, 2h, 1d)", s)
	}
	return now.Add(-dur), nil
}

// Denied is one destination that was refused, with how often and why.
type Denied struct {
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Count    int       `json:"count"`
	Reason   string    `json:"reason"`
	Rule     string    `json:"rule,omitempty"`
	LastSeen time.Time `json:"last_seen"`
	// Suggest is the command that would allow it, or "" with Why when a rule cannot help.
	Suggest string `json:"suggest,omitempty"`
	Why     string `json:"why,omitempty"`
}

// GroupDenied groups denied decisions by host and port, most frequent first.
func GroupDenied(recs []audit.Record) []Denied {
	type key struct {
		host string
		port int
	}
	m := map[key]*Denied{}
	var order []key
	for _, r := range recs {
		if r.Event != audit.EventDecision || (r.Action != audit.ActionDeny && r.Action != audit.ActionError) {
			continue
		}
		host := r.Host
		if host == "" {
			host = "(unknown)"
		}
		k := key{host, r.Port}
		d, ok := m[k]
		if !ok {
			d = &Denied{Host: host, Port: r.Port, Reason: r.Reason, Rule: r.Rule}
			m[k] = d
			order = append(order, k)
		}
		d.Count++
		if r.TS.After(d.LastSeen) {
			d.LastSeen, d.Reason, d.Rule = r.TS, r.Reason, r.Rule
		}
	}
	out := make([]Denied, 0, len(order))
	for _, k := range order {
		d := m[k]
		d.Suggest, d.Why = suggestion(*d)
		out = append(out, *d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// suggestion says how to allow a denied destination, or why no rule can.
func suggestion(d Denied) (cmd, why string) {
	switch d.Reason {
	case proxy.ReasonIPLiteral:
		return "", "IP addresses are never allowed; the program should use a hostname"
	case proxy.ReasonBlockedAddress:
		return "", "the name resolves to a private, loopback or metadata address, which kennel blocks"
	case proxy.ReasonSNIMismatch, proxy.ReasonNoSNI, proxy.ReasonECH:
		return "", "the TLS handshake did not match the requested host; allowing the host does not change that"
	case proxy.ReasonBadTarget, proxy.ReasonNotProxy, proxy.ReasonBadScheme, proxy.ReasonUpgrade:
		return "", "not a request a rule can allow (" + d.Reason + ")"
	case proxy.ReasonRateLimited, proxy.ReasonAtCapacity, proxy.ReasonSuspicious:
		return "", "refused by a safety limit (" + d.Reason + "), not by the allowlist"
	case policy.ReasonExplicitDeny:
		return "", "an explicit deny rule applies (" + d.Rule + "); edit .kennel/policy.yaml to change it"
	case policy.ReasonHTTPNotAllow:
		return "", "plain HTTP is refused; use https"
	case proxy.ReasonResolveFailed, proxy.ReasonDialFailed:
		return "", "the host was allowed but could not be reached (" + d.Reason + ")"
	}
	if d.Host == "(unknown)" || strings.ContainsAny(d.Host, " /") {
		return "", ""
	}
	cmd = "kennel allow " + d.Host
	if d.Port != 0 && d.Port != 443 {
		cmd += " --port " + strconv.Itoa(d.Port)
	}
	return cmd, ""
}

// Line renders one record for terminals.
func Line(r audit.Record) string {
	ts := r.TS.Local().Format("15:04:05")
	switch r.Event {
	case audit.EventDecision:
		dest := r.Host
		if r.Port != 0 {
			dest += ":" + strconv.Itoa(r.Port)
		}
		verb := strings.ToUpper(r.Action)
		detail := r.Reason
		if r.Rule != "" {
			detail = strings.TrimSpace(detail + " " + r.Rule)
		}
		return fmt.Sprintf("%s  %-5s %s  %s", ts, verb, dest, detail)
	case audit.EventClose:
		dest := r.Host
		if r.Port != 0 {
			dest += ":" + strconv.Itoa(r.Port)
		}
		extra := ""
		if r.BytesUp != nil && r.BytesDown != nil {
			extra = fmt.Sprintf(" up=%dB down=%dB", *r.BytesUp, *r.BytesDown)
		}
		return fmt.Sprintf("%s  close %s  %s%s", ts, dest, r.Reason, extra)
	default:
		return fmt.Sprintf("%s  %s %s %s", ts, r.Event, r.Action, r.Reason)
	}
}
