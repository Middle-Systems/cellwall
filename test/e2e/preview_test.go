//go:build e2e

package e2e

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// httpBody GETs a URL on the host and returns the status and body.
func httpBody(url string) (int, string, error) {
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get(url) //nolint:noctx // test helper with a client timeout
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), err
}

// waitHTTP polls until the URL answers 200 with a body satisfying ok, or fails with diag().
func waitHTTP(t *testing.T, url string, timeout time.Duration, ok func(body string) bool, diag func() string) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		st, body, err := httpBody(url)
		switch {
		case err != nil:
			last = err.Error()
		case st == 200 && ok(body):
			return body
		default:
			last = fmt.Sprintf("status %d, body %.120q", st, body)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("%s never became ready (%s)\n%s", url, last, diag())
	return ""
}

// ---- a minimal WebSocket client: enough to receive Vite's HMR messages through the forwarder ----

func wsConnect(addr, path, subprotocol string) (net.Conn, *bufio.Reader, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: %s\r\nOrigin: http://%s\r\n\r\n",
		path, addr, base64.StdEncoding.EncodeToString(key), subprotocol, addr)
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		_ = c.Close()
		return nil, nil, fmt.Errorf("websocket upgrade refused: %q %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return nil, nil, err
		}
		if line == "\r\n" {
			break
		}
	}
	return c, br, nil
}

// wsText reads the next text message (server frames are unmasked).
func wsText(c net.Conn, br *bufio.Reader, timeout time.Duration) (string, error) {
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	for {
		var h [2]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return "", err
		}
		opcode, n := h[0]&0x0f, uint64(h[1]&0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(br, b[:]); err != nil {
				return "", err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(br, b[:]); err != nil {
				return "", err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			return "", err
		}
		if opcode == 1 {
			return string(payload), nil
		}
		if opcode == 8 {
			return "", io.EOF
		}
		// ping/pong/binary: skip
	}
}

// TestVitePreview serves a real Vite dev server from the sandbox on the host's 127.0.0.1 and
// proves hot module reload works end to end: a file edited on the host reaches the dev server in
// the container, and the browser's HMR WebSocket (relayed by the gateway) is told about it.
func TestVitePreview(t *testing.T) {
	requireDocker(t)
	p := newProject(t, "node-vite")
	p.must(p.cw("", "init"), "init")
	p.must(p.cw("", "up"), "up")

	install := p.sh("cd /workspace && npm ci --no-audit --no-fund 2>&1 | tail -5")
	if install.code != 0 {
		t.Fatalf("npm ci through the gateway failed (exit %d):\n%s\n%s", install.code, install.out, install.err)
	}
	diag := func() string {
		log := p.sh("cat /tmp/vite.log 2>&1 | tail -30")
		denied := p.cw("", "logs", "--denied", "--since", "30m")
		ports := p.cw("", "ports", "ls")
		return "--- vite.log\n" + log.out + "\n--- logs --denied\n" + denied.out + "\n--- ports ls\n" + ports.out
	}
	start := p.sh("cd /workspace && (setsid nohup npx vite --host 0.0.0.0 --port 5173 --strictPort >/tmp/vite.log 2>&1 </dev/null &) ; echo started")
	if !strings.Contains(start.out, "started") {
		t.Fatalf("could not start vite: %+v", start)
	}

	base := "http://127.0.0.1:5173"
	waitHTTP(t, base+"/", 90*time.Second, func(b string) bool { return strings.Contains(b, "/src/main.js") }, diag)

	ports := p.must(p.cw("", "ports", "ls"), "ports ls").out
	if !strings.Contains(ports, "all-interfaces") {
		t.Errorf("ports ls should show the dev server reachable:\n%s", ports)
	}
	if v := p.must(p.cw("", "verify", "--only", "preview-inbound", "--strict"), "verify preview-inbound"); !strings.Contains(v.out, "PASS") {
		t.Errorf("verify preview-inbound with a real dev server:\n%s", v.out)
	}

	// Source served before the edit.
	_, before, err := httpBody(base + "/src/main.js")
	if err != nil || !strings.Contains(before, "hello") {
		t.Fatalf("main.js before the edit: %v %.200q", err, before)
	}

	// Open the HMR socket the way the browser's client does.
	_, client, err := httpBody(base + "/@vite/client")
	if err != nil {
		t.Fatal(err)
	}
	token := ""
	if m := regexp.MustCompile(`wsToken\s*=\s*"([^"]+)"`).FindStringSubmatch(client); m != nil {
		token = m[1]
	}
	wsPath := "/"
	if token != "" {
		wsPath = "/?token=" + token
	}
	conn, br, err := wsConnect("127.0.0.1:5173", wsPath, "vite-hmr")
	if err != nil {
		t.Fatalf("HMR websocket through the forwarder: %v\n%s", err, diag())
	}
	defer func() { _ = conn.Close() }()
	msg, err := wsText(conn, br, 10*time.Second)
	if err != nil || !strings.Contains(msg, "connected") {
		t.Fatalf("expected Vite's connected message, got %q %v", msg, err)
	}

	// Edit on the HOST (the workspace is a bind mount) and wait for the push.
	main := filepath.Join(p.ws, "src", "main.js")
	if err := os.WriteFile(main, []byte(`console.log("hello, edited on the host");`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		m, err := wsText(conn, br, 30*time.Second)
		if err != nil {
			t.Fatalf("no HMR message after the edit: %v\n%s", err, diag())
		}
		if strings.Contains(m, `"update"`) || strings.Contains(m, "full-reload") {
			got = m
			break
		}
	}
	if got == "" {
		t.Fatalf("Vite never announced the change\n%s", diag())
	}
	_, after, err := httpBody(base + "/src/main.js")
	if err != nil || !strings.Contains(after, "edited on the host") {
		t.Errorf("the dev server serves stale code after the edit: %v %.200q", err, after)
	}
}

// TestFlaskPreview does the same for a server-side reloader: Flask in debug mode restarts when the
// file changes, and the next request through the preview port returns the new response.
func TestFlaskPreview(t *testing.T) {
	requireDocker(t)
	p := newProject(t, "python-flask")
	p.must(p.cw("", "init"), "init")
	p.must(p.cw("", "up"), "up")

	cfg := p.must(p.cw("", "ports", "ls", "--json"), "ports ls").out
	if !strings.Contains(cfg, `"port": 5000`) {
		p.must(p.cw("", "ports", "add", "5000"), "ports add 5000")
	}

	setup := p.sh("cd /workspace && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt 2>&1 | tail -5")
	if setup.code != 0 {
		t.Fatalf("pip install through the gateway failed (exit %d):\n%s\n%s", setup.code, setup.out, setup.err)
	}
	diag := func() string {
		log := p.sh("cat /tmp/flask.log 2>&1 | tail -30")
		denied := p.cw("", "logs", "--denied", "--since", "30m")
		return "--- flask.log\n" + log.out + "\n--- logs --denied\n" + denied.out
	}
	start := p.sh("cd /workspace && (setsid nohup .venv/bin/flask --app app run --host 0.0.0.0 --port 5000 --debug >/tmp/flask.log 2>&1 </dev/null &) ; echo started")
	if !strings.Contains(start.out, "started") {
		t.Fatalf("could not start flask: %+v", start)
	}

	base := "http://127.0.0.1:5000/"
	waitHTTP(t, base, 60*time.Second, func(b string) bool { return strings.TrimSpace(b) == "hello" }, diag)

	app := filepath.Join(p.ws, "app.py")
	src, err := os.ReadFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(app, []byte(strings.Replace(string(src), `return "hello"`, `return "hello, reloaded"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	waitHTTP(t, base, 45*time.Second, func(b string) bool { return strings.Contains(b, "reloaded") }, diag)
}
