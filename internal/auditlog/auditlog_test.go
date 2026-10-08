package auditlog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/middle-systems/cellwall/internal/audit"
)

var t0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func rec(sec int, event, action, host string, port int, reason string) audit.Record {
	return audit.Record{TS: t0.Add(time.Duration(sec) * time.Second), Event: event, Action: action, Host: host, Port: port, Reason: reason}
}

func write(t *testing.T, path string, recs ...audit.Record) {
	t.Helper()
	var b strings.Builder
	for _, r := range recs {
		j, _ := json.Marshal(r)
		b.Write(j)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadSpansRotatedFilesInOrderAndSkipsTornLines(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "audit.jsonl.2"), rec(1, "decision", "allow", "a.com", 443, "rule"))
	write(t, filepath.Join(dir, "audit.jsonl.1"), rec(2, "decision", "deny", "b.com", 443, "default-deny"))
	write(t, filepath.Join(dir, "audit.jsonl"), rec(3, "decision", "deny", "c.com", 443, "default-deny"))
	f, _ := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString(`{"ts":"2026-10-08T12:00:09Z","event":"deci`) // torn: the gateway was killed mid-write
	_ = f.Close()
	_ = os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o644)

	recs, skipped, err := Read(dir, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, r := range recs {
		hosts = append(hosts, r.Host)
	}
	if strings.Join(hosts, ",") != "a.com,b.com,c.com" || skipped != 1 {
		t.Fatalf("hosts=%v skipped=%d", hosts, skipped)
	}

	denied, _, _ := Read(dir, Filter{DeniedOnly: true})
	if len(denied) != 2 {
		t.Errorf("denied = %d", len(denied))
	}
	recent, _, _ := Read(dir, Filter{Since: t0.Add(2 * time.Second)})
	if len(recent) != 2 {
		t.Errorf("since filter kept %d records", len(recent))
	}
}

func TestReadOfAMissingDirectoryIsEmptyNotAnError(t *testing.T) {
	recs, _, err := Read(filepath.Join(t.TempDir(), "nope"), Filter{})
	if err != nil || len(recs) != 0 {
		t.Fatalf("recs=%v err=%v", recs, err)
	}
}

func TestParseSince(t *testing.T) {
	now := t0
	for in, want := range map[string]time.Duration{"30m": 30 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour, "90s": 90 * time.Second} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(now.Add(-want)) {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if got, err := ParseSince("", now); err != nil || !got.IsZero() {
		t.Error("empty means no bound")
	}
	for _, bad := range []string{"soon", "-1h", "1x", "d", "-2d"} {
		if _, err := ParseSince(bad, now); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestGroupDeniedCountsAndSuggestsOnlyWhatARuleCanFix(t *testing.T) {
	recs := []audit.Record{
		rec(1, "decision", "deny", "registry.example.com", 443, "default-deny"),
		rec(2, "decision", "deny", "registry.example.com", 443, "default-deny"),
		rec(3, "decision", "deny", "registry.example.com", 443, "default-deny"),
		rec(4, "decision", "deny", "api.example.com", 8443, "port-not-allowed"),
		rec(5, "decision", "deny", "10.0.0.1", 443, "ip-literal"),
		rec(6, "decision", "deny", "evil.internal.example.com", 443, "blocked-address"),
		rec(7, "decision", "deny", "tracker.example.com", 443, "explicit-deny"),
		rec(8, "decision", "deny", "plain.example.com", 80, "http-not-allowed"),
		rec(9, "decision", "allow", "ok.example.com", 443, "rule"),
		rec(10, "close", "", "registry.example.com", 443, "done"),
	}
	got := GroupDenied(recs)
	if len(got) != 6 {
		t.Fatalf("groups = %d: %+v", len(got), got)
	}
	if got[0].Host != "registry.example.com" || got[0].Count != 3 || got[0].Suggest != "cellwall allow registry.example.com" {
		t.Errorf("top group = %+v", got[0])
	}
	by := map[string]Denied{}
	for _, d := range got {
		by[d.Host] = d
	}
	if by["api.example.com"].Suggest != "cellwall allow api.example.com --port 8443" {
		t.Errorf("non-default port: %+v", by["api.example.com"])
	}
	for _, h := range []string{"10.0.0.1", "evil.internal.example.com", "tracker.example.com", "plain.example.com"} {
		if by[h].Suggest != "" || by[h].Why == "" {
			t.Errorf("%s must not suggest a rule and must say why: %+v", h, by[h])
		}
	}
}

func TestFollowSeesNewLinesAndSurvivesRotation(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	write(t, active, rec(1, "decision", "deny", "old.example.com", 443, "default-deny"))

	var mu sync.Mutex
	var seen []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = Follow(ctx, dir, Filter{}, func(r audit.Record) {
			mu.Lock()
			seen = append(seen, r.Host)
			mu.Unlock()
		}, 10*time.Millisecond)
		close(done)
	}()
	waitFor := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			l := len(seen)
			mu.Unlock()
			if l >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("saw %v, want %d records", seen, n)
	}

	time.Sleep(50 * time.Millisecond) // let Follow open the file at its end
	appendLine := func(r audit.Record, partial bool) {
		f, _ := os.OpenFile(active, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		j, _ := json.Marshal(r)
		if partial {
			_, _ = f.Write(j[:10])
		} else {
			_, _ = f.Write(append(j, '\n'))
		}
		_ = f.Close()
	}
	appendLine(rec(2, "decision", "deny", "new1.example.com", 443, "default-deny"), false)
	waitFor(1)

	// A partial line is held back until it is complete.
	j, _ := json.Marshal(rec(3, "decision", "deny", "new2.example.com", 443, "default-deny"))
	f, _ := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.Write(j[:15])
	_ = f.Close()
	time.Sleep(60 * time.Millisecond)
	f, _ = os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.Write(append(j[15:], '\n'))
	_ = f.Close()
	waitFor(2)

	// Rotation: the active file is renamed away and a fresh one appears.
	if err := os.Rename(active, filepath.Join(dir, "audit.jsonl.1")); err != nil {
		t.Fatal(err)
	}
	write(t, active, rec(4, "decision", "deny", "after-rotation.example.com", 443, "default-deny"))
	waitFor(3)

	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	want := "new1.example.com,new2.example.com,after-rotation.example.com"
	if strings.Join(seen, ",") != want {
		t.Errorf("seen %v, want %s (and nothing from before Follow started)", seen, want)
	}
}

func TestLineFormats(t *testing.T) {
	l := Line(rec(0, "decision", "deny", "x.example.com", 443, "default-deny"))
	if !strings.Contains(l, "DENY") || !strings.Contains(l, "x.example.com:443") || !strings.Contains(l, "default-deny") {
		t.Errorf("line = %q", l)
	}
}
