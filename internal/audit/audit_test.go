package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func TestRecordFormat(t *testing.T) {
	dir := t.TempDir()
	fixed := time.Date(2026, 10, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	l, err := Open(Options{Dir: dir, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(l.Log(Record{Event: EventDecision, ID: "c1", Action: ActionDeny, Proto: "connect", Host: "evil.com", Port: 443,
		Rule: "default", Reason: "default-deny", Policy: "abcdef012345"}))
	must(l.Log(Record{Event: EventClose, ID: "c1", Host: "ok.com", Port: 443, BytesUp: Int64(0), BytesDown: Int64(0), DurationMS: Int64(12)}))
	must(l.Close())

	lines := readLines(t, filepath.Join(dir, FileName))
	if len(lines) != 2 {
		t.Fatalf("got %d lines", len(lines))
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m["ts"] != "2026-10-01T11:00:00Z" { // normalised to UTC
		t.Errorf("ts = %v", m["ts"])
	}
	for _, k := range []string{"event", "id", "action", "host", "port", "rule", "reason", "policy"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing field %q in %s", k, lines[0])
		}
	}
	if _, ok := m["bytes_up"]; ok {
		t.Error("decision record must not carry byte counters")
	}
	// A close record reports zero bytes explicitly rather than omitting them.
	if !strings.Contains(lines[1], `"bytes_up":0`) || !strings.Contains(lines[1], `"duration_ms":12`) {
		t.Errorf("close record must carry explicit counters: %s", lines[1])
	}
}

func TestHostileStringsStayOnOneLine(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir})
	evil := "a.com\n{\"event\":\"decision\",\"action\":\"allow\"}\r\x00 "
	if err := l.Log(Record{Event: EventDecision, Action: ActionDeny, Host: evil, SNI: evil, Reason: evil}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	lines := readLines(t, filepath.Join(dir, FileName))
	if len(lines) != 1 {
		t.Fatalf("log injection: got %d lines: %q", len(lines), lines)
	}
	var r Record
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil || r.Host != evil {
		t.Fatalf("round trip failed: %v / %q", err, r.Host)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir, MaxSize: 300, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		if err := l.Log(Record{Event: EventDecision, Action: ActionDeny, Host: fmt.Sprintf("h%02d.example.com", i), Port: 443}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		info, _ := e.Info()
		if info.Size() > 300+200 { // never much over MaxSize (one record can straddle)
			t.Errorf("%s is %d bytes", e.Name(), info.Size())
		}
	}
	want := []string{"audit.jsonl", "audit.jsonl.1", "audit.jsonl.2", "audit.jsonl.3"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v; want %v (older files must be deleted)", names, want)
	}
	// Newest records are in the active file, in order, and every kept line is intact JSON.
	var all []string
	for _, n := range []string{"audit.jsonl.3", "audit.jsonl.2", "audit.jsonl.1", "audit.jsonl"} {
		for _, line := range readLines(t, filepath.Join(dir, n)) {
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("%s: corrupt line %q: %v", n, line, err)
			}
			all = append(all, r.Host)
		}
	}
	if len(all) == 0 || all[len(all)-1] != "h59.example.com" {
		t.Errorf("newest record missing; tail = %v", all[max(0, len(all)-3):])
	}
	for i := 1; i < len(all); i++ {
		if all[i] <= all[i-1] {
			t.Fatalf("records out of order across rotation: %v", all)
		}
	}
}

func TestConcurrentWritesKeepLinesIntact(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir, MaxSize: 4096, MaxFiles: 50})
	var wg sync.WaitGroup
	const workers, each = 16, 50
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := l.Log(Record{Event: EventDecision, Action: ActionAllow, Host: strings.Repeat("x", 30) + ".com", Port: 443}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	_ = l.Close()
	total := 0
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		for _, line := range readLines(t, filepath.Join(dir, e.Name())) {
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				t.Fatalf("interleaved/corrupt line %q", line)
			}
			total++
		}
	}
	if total != workers*each {
		t.Errorf("wrote %d records, found %d", workers*each, total)
	}
}

func TestFailureIsReportedAndHeals(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir})
	if err := l.Log(Record{Event: EventDecision}); err != nil {
		t.Fatal(err)
	}
	// Break the underlying file out from under the logger.
	l.mu.Lock()
	_ = l.f.Close()
	l.mu.Unlock()
	if err := l.Log(Record{Event: EventDecision}); err == nil {
		t.Fatal("a failed write must be reported so the proxy can fail closed")
	}
	if err := l.Log(Record{Event: EventDecision}); err != nil {
		t.Fatalf("logger must reopen and recover: %v", err)
	}
	_ = l.Close()
}

func TestAppendsToExistingFile(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(Options{Dir: dir})
	_ = l.Log(Record{Event: EventDecision, Host: "one.com"})
	_ = l.Close()
	l, _ = Open(Options{Dir: dir})
	_ = l.Log(Record{Event: EventDecision, Host: "two.com"})
	_ = l.Close()
	if n := len(readLines(t, filepath.Join(dir, FileName))); n != 2 {
		t.Fatalf("restart must append, not truncate: %d lines", n)
	}
}

func TestOpenRequiresDir(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("expected error")
	}
}
