//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/proxy/proxytest"
)

func hello(sni string) []byte { return proxytest.Records(proxytest.HelloOpts{SNI: sni}) }

func rec(host, event, key, val string) func(map[string]any) bool {
	return func(m map[string]any) bool {
		return m["host"] == host && m["event"] == event && m[key] == val
	}
}

// TestEscapeSuite runs the gateway-facing checks from spec section 10 against a live topology.
// Numbering follows the spec: 3 allow/deny via proxy, 4 IP literals, 5 resolved-address guard,
// 6 SNI/ECH, 7 plain HTTP, 12 hot reload.
func TestEscapeSuite(t *testing.T) {
	l := newLab(t)

	t.Run("00 topology: agent reaches only the proxy port", func(t *testing.T) {
		if out, err := exec.Command("docker", "exec", l.agent, "sh", "-c", "nc -w 2 -z gateway 3128").CombinedOutput(); err != nil {
			t.Fatalf("control: agent should reach gateway:3128: %v %s", err, out)
		}
		for _, port := range []string{"3129", "22", "443", "80"} {
			if err := exec.Command("docker", "exec", l.agent, "sh", "-c", "nc -w 2 -z gateway "+port).Run(); err == nil {
				t.Errorf("agent must not reach gateway:%s (admin/control surface and everything else stay closed)", port)
			}
		}
		if err := exec.Command("docker", "exec", l.agent, "sh", "-c", "nc -w 2 -z upstream 443").Run(); err == nil {
			t.Error("agent must not reach the upstream directly; its only path is through the gateway")
		}
		if err := exec.Command("docker", "exec", l.agent, "sh", "-c", "nc -w 2 -z 1.1.1.1 443").Run(); err == nil {
			t.Error("agent must not reach the internet directly")
		}
	})

	t.Run("03 allowlisted host succeeds; others get 403 and an audit deny", func(t *testing.T) {
		h := hello("upstream")
		out := l.via(append(connectReq("upstream:443"), h...))
		r := parseReply(t, out)
		if r.Status != 200 {
			t.Fatalf("allowlisted host refused: %d %s", r.Status, r.Body)
		}
		if !bytes.Contains(r.Rest, h[:20]) {
			t.Errorf("no echo through the tunnel (hello must reach the upstream verbatim): %q", r.Rest)
		}
		l.waitAudit(rec("upstream", "decision", "action", "allow"))
		l.waitAudit(rec("upstream", "close", "action", "allow"))

		r = parseReply(t, l.quick(connectReq("evil.example.org:443")))
		if r.Status != 403 || r.Reason != "default-deny" {
			t.Fatalf("not allowlisted: %d %q", r.Status, r.Reason)
		}
		for _, want := range []string{"evil.example.org:443", "kennel allow evil.example.org"} {
			if !strings.Contains(r.Body, want) {
				t.Errorf("403 body must be actionable, missing %q:\n%s", want, r.Body)
			}
		}
		l.waitAudit(rec("evil.example.org", "decision", "action", "deny"))
	})

	t.Run("04 CONNECT to an IP literal is denied", func(t *testing.T) {
		for _, target := range []string{"1.1.1.1:443", "[2606:4700:4700::1111]:443", "10.0.0.1:443", "127.0.0.1:443", "169.254.169.254:80", "2130706433:443", "0x7f.1:443"} {
			r := parseReply(t, l.quick(connectReq(target)))
			if r.Status != 403 || r.Reason != "ip-literal" {
				t.Errorf("%s: %d %q", target, r.Status, r.Reason)
			}
		}
	})

	t.Run("05 names resolving to loopback/private/link-local/metadata are denied", func(t *testing.T) {
		for _, name := range []string{"lo4", "lo6", "mapped", "rfc1918-a", "rfc1918-b", "rfc1918-c", "cgnat", "linklocal", "meta", "metav6", "ula", "zero", "nat64", "mixed"} {
			host := name + ".rebind.test"
			r := parseReply(t, l.quick(connectReq(host+":443")))
			if r.Status != 403 || r.Reason != "blocked-address" {
				t.Errorf("%s: %d %q %s", host, r.Status, r.Reason, strings.TrimSpace(r.Body))
			}
		}
		// The block is by address class: the audit trail says which class.
		m := l.waitAudit(rec("meta.rebind.test", "decision", "reason", "blocked-address"))
		if m["action"] != "deny" {
			t.Errorf("%v", m)
		}
	})

	t.Run("06 SNI mismatch and ECH are closed and logged", func(t *testing.T) {
		// CONNECT to the allowed host, ClientHello for another name.
		out := l.via(append(connectReq("upstream:443"), hello("evil.example.org")...))
		r := parseReply(t, out)
		if r.Status != 200 {
			t.Fatalf("%d", r.Status)
		}
		if len(r.Rest) != 0 {
			t.Errorf("a mismatching hello must not be echoed by the upstream: %q", r.Rest)
		}
		m := l.waitAudit(func(m map[string]any) bool { return m["event"] == "close" && m["reason"] == "sni-mismatch" })
		if m["sni"] != "evil.example.org" || m["action"] != "deny" {
			t.Errorf("%v", m)
		}

		ech := proxytest.Records(proxytest.HelloOpts{SNI: "upstream", ECH: 0xfe0d})
		parseReply(t, l.via(append(connectReq("upstream:443"), ech...)))
		l.waitAudit(func(m map[string]any) bool { return m["event"] == "close" && m["reason"] == "ech" })

		parseReply(t, l.via(append(connectReq("upstream:443"), proxytest.Records(proxytest.HelloOpts{})...)))
		l.waitAudit(func(m map[string]any) bool { return m["event"] == "close" && m["reason"] == "no-sni" })

		parseReply(t, l.via(append(connectReq("upstream:443"), []byte("SSH-2.0-OpenSSH_9.0\r\n")...)))
		l.waitAudit(func(m map[string]any) bool { return m["event"] == "close" && m["reason"] == "tls-not-tls" })
	})

	t.Run("07 plain HTTP is denied by default", func(t *testing.T) {
		req := "GET http://upstream/ HTTP/1.1\r\nHost: upstream\r\nConnection: close\r\n\r\n"
		out := string(l.quick([]byte(req)))
		if !strings.HasPrefix(out, "HTTP/1.1 403") || !strings.Contains(strings.ToLower(out), "x-kennel-reason: http-not-allowed") {
			t.Fatalf("plain HTTP must be denied:\n%s", out)
		}
		l.waitAudit(func(m map[string]any) bool {
			return m["proto"] == "http" && m["action"] == "deny" && m["reason"] == "http-not-allowed"
		})
	})

	t.Run("12 hot reload applies within 2s and does not drop an in-flight connection", func(t *testing.T) {
		// Hold a tunnel open through the reload.
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", l.agent, "sh", "-c", "nc gateway 3128")
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = cmd.Process.Kill() }()
		br := bufio.NewReader(stdout)
		h := hello("upstream")
		_, _ = stdin.Write(append(connectReq("upstream:443"), h...))
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("long-lived tunnel not established: %v %v", resp, err)
		}
		echo := make([]byte, len(h))
		if _, err := io.ReadFull(br, echo); err != nil {
			t.Fatalf("no echo before reload: %v", err)
		}

		// A name the policy does not allow, so the transition is allow-list driven.
		if r := parseReply(t, l.quick(connectReq("new.example.test:443"))); r.Reason != "default-deny" {
			t.Fatalf("before: %q", r.Reason)
		}
		changed := l.setPolicy(`{"version":1,"rules":[{"host":"new.example.test"},{"host":"*.rebind.test"}]}`)

		// Spec: `allow` takes effect within 2s. The authoritative measurement is the gateway's own
		// audit timestamp for the reload (same host, same clock) minus the instant the file was
		// replaced. Timing a docker-exec probe would mostly measure docker exec.
		var reloadedAt time.Time
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && reloadedAt.IsZero() {
			for _, m := range l.auditRecords() {
				if m["event"] != "policy" || m["action"] != "reload" {
					continue
				}
				ts, err := time.Parse(time.RFC3339Nano, m["ts"].(string))
				if err == nil && !ts.Before(changed) {
					reloadedAt = ts
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		if reloadedAt.IsZero() {
			t.Fatal("gateway never logged the reload")
		}
		latency := reloadedAt.Sub(changed)
		t.Logf("policy reload latency (gateway audit clock - file replace): %v", latency)
		if latency > 2*time.Second {
			t.Errorf("reload took %v; the requirement is 2s", latency)
		}
		// And the new policy really is what is being enforced for new connections.
		if r := parseReply(t, l.quick(connectReq("new.example.test:443"))); r.Reason == "default-deny" {
			t.Errorf("reload was logged but the allow is not in effect: %q", r.Reason)
		}

		// The reload dropped the `upstream` rule; new connections to it are denied...
		if r := parseReply(t, l.quick(connectReq("upstream:443"))); r.Reason != "default-deny" {
			t.Errorf("removed rule still allowed: %q", r.Reason)
		}
		// ...but the tunnel opened before the reload keeps working.
		_, _ = stdin.Write([]byte("STILL-ALIVE-AFTER-RELOAD"))
		got := make([]byte, len("STILL-ALIVE-AFTER-RELOAD"))
		if _, err := io.ReadFull(br, got); err != nil || string(got) != "STILL-ALIVE-AFTER-RELOAD" {
			t.Errorf("in-flight connection was dropped by the reload: %v %q", err, got)
		}

		// A broken edit is rejected: the last good policy keeps enforcing.
		l.setPolicy(`{"version":1,"rules":[`)
		time.Sleep(700 * time.Millisecond)
		if r := parseReply(t, l.quick(connectReq("evil.example.org:443"))); r.Reason != "default-deny" {
			t.Errorf("bad policy opened the gate: %q", r.Reason)
		}
		l.waitAudit(func(m map[string]any) bool { return m["event"] == "policy" && m["action"] == "reload-failed" })
		l.waitAudit(func(m map[string]any) bool { return m["event"] == "policy" && m["action"] == "reload" })
	})

}
