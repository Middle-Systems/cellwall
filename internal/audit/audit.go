// Package audit writes the gateway's JSON Lines audit log.
//
// Contract (docs/decisions/0005): every connection produces a "decision" record when the policy
// is consulted, and every allowed connection a "close" record when it ends. The proxy writes the
// decision record BEFORE letting an allowed connection proceed and refuses the connection if the
// write fails, so there is no such thing as an unaudited allow (unless fail-open is configured).
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Event kinds.
const (
	EventDecision = "decision"
	EventClose    = "close"
	// EventPolicy records a policy reload (Action "reload" or "reload-failed").
	EventPolicy = "policy"
)

// Actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
	// ActionError marks a connection policy allowed but that failed (resolve, dial, timeouts).
	ActionError = "error"
)

// FileName is the active log file inside the audit directory. Rotated files are FileName.1 (newest)
// through FileName.N (oldest).
const FileName = "audit.jsonl"

// Record is one audit line. Fields that do not apply to an event are omitted.
type Record struct {
	TS    time.Time `json:"ts"`
	Event string    `json:"event"`
	// ID correlates a connection's decision and close records.
	ID     string `json:"id,omitempty"`
	Action string `json:"action,omitempty"`
	Proto  string `json:"proto,omitempty"` // "connect" or "http"
	Src    string `json:"src,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   int    `json:"port,omitempty"`
	SNI    string `json:"sni,omitempty"`
	// Rule identifies the deciding rule, e.g. "rules[3] registry.npmjs.org (preset:node)".
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Close-record fields. They are pointers/omitempty-safe: a close record always carries them.
	BytesUp    *int64 `json:"bytes_up,omitempty"`
	BytesDown  *int64 `json:"bytes_down,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
	Suspicious bool   `json:"suspicious,omitempty"`
	// Policy is the first 12 hex digits of the effective policy hash that made the decision.
	Policy string `json:"policy,omitempty"`
}

// Int64 returns a pointer for the optional counters.
func Int64(v int64) *int64 { return &v }

// Options configures a Logger. Zero values use the defaults noted.
type Options struct {
	Dir      string // required
	MaxSize  int64  // bytes before rotating; default 50 MiB
	MaxFiles int    // rotated files kept besides the active one; default 5
	Now      func() time.Time
}

// Defaults.
const (
	DefaultMaxSize  = int64(50) << 20
	DefaultMaxFiles = 5
)

// Logger is safe for concurrent use.
type Logger struct {
	opts Options

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open creates the directory if needed and opens the active file for appending.
func Open(opts Options) (*Logger, error) {
	if opts.Dir == "" {
		return nil, errors.New("audit: directory is required")
	}
	if opts.MaxSize <= 0 {
		opts.MaxSize = DefaultMaxSize
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	// 0755: the directory is bind-mounted from the host, where the (different) host user must be
	// able to read the log. It holds hostnames and counters, no secrets.
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil { //nolint:gosec // see comment above: host user must read the log
		return nil, fmt.Errorf("audit: create directory: %w", err)
	}
	l := &Logger{opts: opts}
	if err := l.openLocked(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) path(n int) string {
	p := filepath.Join(l.opts.Dir, FileName)
	if n > 0 {
		p += "." + strconv.Itoa(n)
	}
	return p
}

func (l *Logger) openLocked() error {
	f, err := os.OpenFile(l.path(0), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644) // #nosec G302 -- host user must read the log
	if err != nil {
		return fmt.Errorf("audit: open log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("audit: stat log: %w", err)
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Log writes one record. It returns an error if the record could not be durably handed to the
// operating system; callers that must not proceed unaudited should treat that as a denial. A
// failed Logger heals itself: the next call reopens the file.
func (l *Logger) Log(r Record) error {
	if r.TS.IsZero() {
		r.TS = l.opts.Now()
	}
	r.TS = r.TS.UTC()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&r); err != nil { // Encode appends the newline
		return fmt.Errorf("audit: encode: %w", err)
	}
	line := buf.Bytes()

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		if err := l.openLocked(); err != nil {
			return err
		}
	}
	if l.size > 0 && l.size+int64(len(line)) > l.opts.MaxSize {
		if err := l.rotateLocked(); err != nil {
			return err
		}
	}
	// One Write call per record keeps lines intact: with O_APPEND the kernel appends atomically.
	n, err := l.f.Write(line)
	l.size += int64(n)
	if err != nil || n != len(line) {
		_ = l.f.Close()
		l.f = nil // reopen on the next call
		if err == nil {
			err = errors.New("short write")
		}
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

func (l *Logger) rotateLocked() error {
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit: sync before rotate: %w", err)
	}
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("audit: close before rotate: %w", err)
	}
	l.f = nil
	// Shift .N-1 -> .N ... .1 -> .2, active -> .1; the oldest falls off the end.
	_ = os.Remove(l.path(l.opts.MaxFiles))
	for i := l.opts.MaxFiles - 1; i >= 0; i-- {
		if err := os.Rename(l.path(i), l.path(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			_ = l.openLocked() // keep logging to whatever is there rather than going dark
			return fmt.Errorf("audit: rotate: %w", err)
		}
	}
	return l.openLocked()
}

// Close syncs and closes the log.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Sync()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}
