//go:build e2e

// Package e2e runs the gateway in a real container topology and attacks it from the agent side.
// These are the first scenarios of the escape suite (spec section 10); M4 moves them into
// `cellwall verify` so the same checks run live against a user's sandbox.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const busybox = "busybox:1.36"

// lab is the running topology.
type lab struct {
	t         *testing.T
	id        string
	root      string // repo root
	tmp       string
	policyDir string
	auditDir  string
	sandbox   string
	egress    string
	gateway   string
	agent     string
	image     string
}

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		if os.Getenv("CELLWALL_E2E_REQUIRE") != "" {
			t.Fatalf("docker is required (CELLWALL_E2E_REQUIRE is set): %v", err)
		}
		t.Skip("docker not available")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// docker runs a docker command and returns its trimmed combined output.
func (l *lab) docker(args ...string) string {
	l.t.Helper()
	out, err := l.dockerErr(args...)
	if err != nil {
		l.t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (l *lab) dockerErr(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (l *lab) buildLinux(pkg, out string) string {
	l.t.Helper()
	dst := filepath.Join(l.tmp, out)
	cmd := exec.Command("go", "build", "-trimpath", "-o", dst, pkg)
	cmd.Dir = l.root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if b, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return dst
}

const initialPolicy = `{
  "version": 1,
  "rules": [
    {"host": "upstream", "unsafe_allow_private": true, "note": "e2e upstream container"},
    {"host": "*.rebind.test"}
  ]
}`

// DNS fixture: ordinary-looking names that resolve to addresses the gateway must never dial.
var dnsRecords = []string{
	"lo4.rebind.test=127.0.0.1",
	"lo6.rebind.test=::1",
	"mapped.rebind.test=::ffff:127.0.0.1",
	"rfc1918-a.rebind.test=10.1.2.3",
	"rfc1918-b.rebind.test=172.16.5.5",
	"rfc1918-c.rebind.test=192.168.1.1",
	"cgnat.rebind.test=100.64.0.9",
	"linklocal.rebind.test=169.254.10.10",
	"meta.rebind.test=169.254.169.254",
	"metav6.rebind.test=fd00:ec2::254",
	"ula.rebind.test=fd12:3456::1",
	"zero.rebind.test=0.0.0.0",
	"nat64.rebind.test=64:ff9b::a00:1",
	"mixed.rebind.test=93.184.216.34,10.0.0.5",
	"reload.rebind.test=127.0.0.1",
}

func newLab(t *testing.T) *lab {
	requireDocker(t)
	l := &lab{t: t, id: fmt.Sprintf("cwe2e%d", time.Now().UnixNano()%1_000_000), root: repoRoot(t), tmp: t.TempDir()}
	l.sandbox, l.egress = l.id+"-sandbox", l.id+"-egress"
	l.gateway, l.agent = l.id+"-gateway", l.id+"-agent"
	l.image = l.id + "-gw"
	l.policyDir, l.auditDir = filepath.Join(l.tmp, "policy"), filepath.Join(l.tmp, "audit")
	for _, d := range []string{l.policyDir, l.auditDir} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(d, 0o777) // the gateway runs as uid 65532
	}
	t.Cleanup(l.teardown)
	l.setPolicy(initialPolicy)

	// Gateway image from the real static binary.
	bin := l.buildLinux("./cmd/cellwall", "cellwall")
	dnsd := l.buildLinux("./test/e2e/fixtures/dnsd", "dnsd")
	ctxDir := filepath.Join(l.tmp, "ctx")
	_ = os.MkdirAll(ctxDir, 0o755)
	copyFile(t, bin, filepath.Join(ctxDir, "cellwall"), 0o755)
	copyFile(t, filepath.Join(l.root, "internal/gatewayimage/Dockerfile"), filepath.Join(ctxDir, "Dockerfile"), 0o644)
	l.docker("build", "-q", "-t", l.image, ctxDir)

	// The sandbox network is exactly the topology from ADR 0001.
	l.docker("network", "create", "--internal", "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated", l.sandbox)
	l.docker("network", "create", l.egress)

	l.docker(append([]string{"run", "-d", "--name", l.id + "-dns", "--network", l.egress,
		"-v", dnsd + ":/dnsd:ro", busybox, "/dnsd"}, dnsRecords...)...)
	dnsIP := l.docker("inspect", "-f", fmt.Sprintf("{{(index .NetworkSettings.Networks %q).IPAddress}}", l.egress), l.id+"-dns")

	l.docker("run", "-d", "--name", l.id+"-upstream", "--network", l.egress, "--network-alias", "upstream",
		busybox, "sh", "-c", "nc -lk -p 443 -e /bin/cat")

	l.docker("run", "-d", "--name", l.gateway, "--network", l.egress, "--network-alias", "gateway", "--dns", dnsIP,
		"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "65532:65532",
		"-v", l.policyDir+":/etc/cellwall/policy:ro", "-v", l.auditDir+":/var/log/cellwall",
		l.image, "--policy", "/etc/cellwall/policy/policy.json", "--audit-dir", "/var/log/cellwall",
		"--reload-interval", "200ms", "--log-format", "text")
	l.docker("network", "connect", "--alias", "gateway", l.sandbox, l.gateway)
	l.waitHealthy()

	l.docker("run", "-d", "--name", l.agent, "--network", l.sandbox, busybox, "sleep", "3600")
	return l
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		t.Fatal(err)
	}
}

func (l *lab) waitHealthy() {
	l.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := l.dockerErr("inspect", "-f", "{{.State.Health.Status}}", l.gateway)
		if out == "healthy" {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	logs, _ := l.dockerErr("logs", l.gateway)
	l.t.Fatalf("gateway never became healthy:\n%s", logs)
}

func (l *lab) teardown() {
	if l.t.Failed() {
		logs, _ := l.dockerErr("logs", l.gateway)
		l.t.Logf("gateway logs:\n%s", logs)
	}
	for _, c := range []string{l.agent, l.gateway, l.id + "-upstream", l.id + "-dns"} {
		_, _ = l.dockerErr("rm", "-f", c)
	}
	for _, n := range []string{l.sandbox, l.egress} {
		_, _ = l.dockerErr("network", "rm", n)
	}
	_, _ = l.dockerErr("rmi", "-f", l.image)
}

// setPolicy replaces the policy file atomically (temp file + rename), exactly as the host CLI will,
// and returns the moment the new file became visible.
func (l *lab) setPolicy(content string) time.Time {
	l.t.Helper()
	tmp := filepath.Join(l.policyDir, "policy.json.tmp")
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		l.t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(l.policyDir, "policy.json")); err != nil {
		l.t.Fatal(err)
	}
	return time.Now()
}

// via sends raw bytes to the gateway from inside the agent container and returns what came back.
// It holds the connection open for a second after sending so tunnelled replies can arrive.
func (l *lab) via(payload []byte) []byte { return l.viaHold(payload, "1") }

// quick is for requests the gateway answers and closes immediately (denials): no hold.
func (l *lab) quick(payload []byte) []byte { return l.viaHold(payload, "0.2") }

func (l *lab) viaHold(payload []byte, hold string) []byte {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", l.agent, "sh", "-c", "(cat; sleep "+hold+") | nc -w 3 gateway 3128")
	cmd.Stdin = bytes.NewReader(payload)
	out, _ := cmd.Output()
	return out
}

func connectReq(target string) []byte {
	return []byte(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target))
}

// reply is a parsed gateway response to a CONNECT.
type reply struct {
	Status int
	Reason string
	Body   string
	Rest   []byte // bytes after the response head (the tunnel, when Status is 200)
}

func parseReply(t *testing.T, raw []byte) reply {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(raw))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("no HTTP response from gateway (got %q): %v", raw, err)
	}
	var rest bytes.Buffer
	_, _ = rest.ReadFrom(br)
	r := reply{Status: resp.StatusCode, Reason: resp.Header.Get("X-Cellwall-Reason"), Rest: rest.Bytes()}
	if resp.StatusCode != 200 {
		r.Body = rest.String()
		r.Rest = nil
	}
	return r
}

// auditRecords reads the gateway's audit log from the host side.
func (l *lab) auditRecords() []map[string]any {
	l.t.Helper()
	b, err := os.ReadFile(filepath.Join(l.auditDir, "audit.jsonl"))
	if err != nil {
		return nil
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func (l *lab) waitAudit(match func(map[string]any) bool) map[string]any {
	l.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range l.auditRecords() {
			if match(r) {
				return r
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatalf("no matching audit record; log has %d records: %v", len(l.auditRecords()), l.auditRecords())
	return nil
}
