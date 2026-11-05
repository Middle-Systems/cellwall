package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/middle-systems/kennel/internal/audit"
)

// Checks returns the escape suite in order. The numbering follows PROJECT_SPEC.md section 10.
func Checks() []Check {
	return []Check{
		{ID: 1, Name: "direct-egress", Title: "direct connections to public IPs fail", Run: checkDirect},
		{ID: 2, Name: "dns-leak", Title: "external DNS does not leak", Run: checkDNS},
		{ID: 3, Name: "proxy-policy", Title: "via the proxy: allowed hosts pass, others get 403 and an audit deny", Run: checkProxyPolicy},
		{ID: 4, Name: "ip-literal", Title: "CONNECT to an IP literal is denied", Run: checkIPLiteral},
		{ID: 5, Name: "internal-addresses", Title: "names that resolve to loopback/private addresses are refused", Mutates: true, Run: checkInternalAddresses},
		{ID: 6, Name: "tls-sni-ech", Title: "SNI mismatch, ECH and non-TLS tunnels are closed and logged", Run: checkTLS},
		{ID: 7, Name: "plain-http", Title: "plain HTTP is denied by default", Run: checkPlainHTTP},
		{ID: 8, Name: "protected-paths", Title: "protected paths are read-only; policy is not reachable", Run: checkProtected},
		{ID: 9, Name: "hardening", Title: "no Docker socket, no capabilities, no-new-privileges, non-root", Run: checkHardening},
		{ID: 10, Name: "host-isolation", Title: "the host and the gateway's control surface are unreachable", Run: checkHostIsolation},
		{ID: 11, Name: "preview-inbound", Title: "previews reach the agent and only the agent", Run: checkPreview},
		{ID: 12, Name: "hot-reload", Title: "an allow takes effect within 2s without dropping a connection", Mutates: true, Run: checkHotReload},
	}
}

// 1 ----------------------------------------------------------------------------------------------

func checkDirect(ctx context.Context, e *Env) (Status, string) {
	var res []struct {
		To        string `json:"to"`
		Connected bool   `json:"connected"`
		Err       string `json:"err"`
	}
	if err := pyJSON(ctx, e, &res, pyDirect); err != nil {
		return Fail, err.Error()
	}
	if len(res) == 0 {
		return Fail, "the probe reported nothing"
	}
	var bad, ok []string
	for _, r := range res {
		if r.Connected {
			bad = append(bad, r.To)
		} else {
			ok = append(ok, fmt.Sprintf("%s (%s)", r.To, r.Err))
		}
	}
	if len(bad) > 0 {
		return Fail, "the agent opened a direct connection to " + strings.Join(bad, ", ") + ": the sandbox has a route to the internet"
	}
	return Pass, "no route: " + strings.Join(ok, ", ")
}

// 2 ----------------------------------------------------------------------------------------------

func checkDNS(ctx context.Context, e *Env) (Status, string) {
	var r struct {
		Resolv          []string `json:"resolv"`
		GatewayResolves bool     `json:"gateway_resolves"`
		PublicResolves  bool     `json:"public_resolves"`
		UDPLeaks        []string `json:"udp_leaks"`
	}
	if err := pyJSON(ctx, e, &r, pyDNS); err != nil {
		return Fail, err.Error()
	}
	switch {
	case len(r.UDPLeaks) > 0:
		return Fail, "a DNS query reached public resolvers " + strings.Join(r.UDPLeaks, ", ") + " directly"
	case r.PublicResolves:
		return Fail, "the agent resolved example.com on its own: names leave the sandbox through DNS"
	case !r.GatewayResolves:
		return Fail, "the agent cannot even resolve the gateway, so this result proves nothing (is the sandbox healthy?)"
	}
	return Pass, fmt.Sprintf("public names do not resolve, no direct DNS reaches public resolvers, the gateway resolves (resolvers: %s)", strings.Join(r.Resolv, ", "))
}

// 3, 4, 7: requests through the proxy ---------------------------------------------------------------

type proxied struct {
	Status int    `json:"status"`
	Reason string `json:"reason"`
	Line   string `json:"line"`
	Body   string `json:"body"`
}

func viaProxy(ctx context.Context, e *Env, raws ...string) ([]proxied, error) {
	arg, _ := json.Marshal(raws)
	var out []proxied
	if err := pyJSON(ctx, e, &out, pyProxy, string(arg)); err != nil {
		return nil, err
	}
	if len(out) != len(raws) {
		return nil, fmt.Errorf("sent %d requests, got %d answers", len(raws), len(out))
	}
	return out, nil
}

func connectReq(target string) string {
	return fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
}

func checkProxyPolicy(ctx context.Context, e *Env) (Status, string) {
	denied := "verify-" + e.Token() + ".kennel-verify.invalid"
	allowed := allowedHost(e.Policy)
	reqs := []string{connectReq(denied + ":443")}
	if allowed != "" {
		reqs = append(reqs, connectReq(allowed+":443"))
	}
	out, err := viaProxy(ctx, e, reqs...)
	if err != nil {
		return Fail, err.Error()
	}
	if out[0].Status != 403 || out[0].Reason != "default-deny" {
		return Fail, fmt.Sprintf("an unlisted host was not refused with 403 default-deny: %q (reason %q)", out[0].Line, out[0].Reason)
	}
	if !strings.Contains(out[0].Body, "kennel allow") {
		return Fail, "the 403 body does not tell the agent how to allow the host: " + truncate(out[0].Body, 120)
	}
	if _, ok := waitAudit(e, func(r audit.Record) bool {
		return r.Event == audit.EventDecision && r.Action == audit.ActionDeny && r.Host == denied
	}); !ok {
		return Fail, "the request was refused but no deny record for " + denied + " reached the audit log"
	}
	if allowed == "" {
		return Skip, "unlisted hosts get 403 and an audit record, but the policy has no exact allowed host to test the other half with"
	}
	st := out[1].Status
	if st == 403 {
		return Fail, fmt.Sprintf("%s is in the policy but was refused: %s (reason %q)", allowed, out[1].Line, out[1].Reason)
	}
	if st != 200 && st != 502 && st != 504 {
		return Fail, fmt.Sprintf("unexpected answer for the allowed host %s: %s", allowed, out[1].Line)
	}
	how := "tunnel opened"
	if st != 200 {
		how = "policy allowed it; the gateway could not reach it (no outbound network?)"
	}
	return Pass, fmt.Sprintf("%s -> 403 + audit deny; %s -> %d (%s)", denied, allowed, st, how)
}

func checkIPLiteral(ctx context.Context, e *Env) (Status, string) {
	targets := []string{"1.1.1.1:443", "169.254.169.254:80", "[::1]:443", "[fd00::1]:443", "2130706433:443", "0x7f.1:80", "127.1:80"}
	var raws []string
	for _, t := range targets {
		raws = append(raws, connectReq(t))
	}
	out, err := viaProxy(ctx, e, raws...)
	if err != nil {
		return Fail, err.Error()
	}
	for i, o := range out {
		if o.Status != 403 && o.Status != 400 {
			return Fail, fmt.Sprintf("CONNECT %s was not refused: %s", targets[i], o.Line)
		}
	}
	if out[0].Reason != "ip-literal" {
		return Fail, fmt.Sprintf("CONNECT 1.1.1.1:443 was refused for %q, not ip-literal", out[0].Reason)
	}
	return Pass, fmt.Sprintf("%d IP-literal forms refused (including cloud metadata, IPv6, decimal and hex)", len(targets))
}

func checkPlainHTTP(ctx context.Context, e *Env) (Status, string) {
	unlisted := "verify-" + e.Token() + ".kennel-verify.invalid"
	allowed := allowedHost(e.Policy)
	reqs := []string{fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", unlisted, unlisted)}
	if allowed != "" {
		reqs = append(reqs, fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", allowed, allowed))
	}
	out, err := viaProxy(ctx, e, reqs...)
	if err != nil {
		return Fail, err.Error()
	}
	for i, o := range out {
		if o.Status != 403 {
			return Fail, fmt.Sprintf("plain HTTP was not refused: %s", o.Line)
		}
		if i == 1 && o.Reason != "http-not-allowed" {
			return Fail, fmt.Sprintf("plain HTTP to the allowed host %s was refused for %q, expected http-not-allowed", allowed, o.Reason)
		}
	}
	if allowed == "" {
		return Pass, "plain HTTP to an unlisted host is refused (the policy has no allowed host to test the https-only rule on)"
	}
	return Pass, fmt.Sprintf("plain HTTP is refused, even to %s which is allowed over https", allowed)
}

// 5 ----------------------------------------------------------------------------------------------

func checkInternalAddresses(ctx context.Context, e *Env) (Status, string) {
	// "localhost" resolves to loopback in the gateway. It is allowed only for the duration of the
	// check, so the answer proves the address guard (not the allowlist) is what refuses it.
	undo, _, err := e.AllowTemp(ctx, []string{"localhost"})
	if err != nil {
		return Fail, "could not set up the check: " + err.Error()
	}
	defer undo()
	out, err := viaProxy(ctx, e, connectReq("localhost:443"))
	if err != nil {
		return Fail, err.Error()
	}
	o := out[0]
	if o.Status == 200 {
		return Fail, "the gateway opened a tunnel to a name that resolves to loopback"
	}
	if o.Status != 403 || o.Reason != "blocked-address" {
		return Fail, fmt.Sprintf("expected 403 blocked-address for a name resolving to loopback, got %s (reason %q)", o.Line, o.Reason)
	}
	return Pass, "localhost, although allowed by policy for this check, is refused after resolution (blocked-address). Other ranges are covered by the unit and e2e suites"
}

// 6 ----------------------------------------------------------------------------------------------

func checkTLS(ctx context.Context, e *Env) (Status, string) {
	host := allowedHost(e.Policy)
	if host == "" {
		return Skip, "the policy has no exact allowed host to open a tunnel to"
	}
	badSNI := "mismatch-" + e.Token() + ".example.net"
	start := e.Now().Add(-5 * time.Second)
	var r struct {
		Connect     int    `json:"connect"`
		Control     string `json:"control"`
		SNIMismatch string `json:"sni_mismatch"`
		ECH         string `json:"ech"`
		NoTLS       string `json:"no_tls"`
	}
	if err := pyJSON(ctx, e, &r, pyTLS, host, badSNI); err != nil {
		return Fail, err.Error()
	}
	if r.Connect != 200 {
		return Skip, fmt.Sprintf("cannot open a tunnel to %s (answer %d): this check needs outbound network from the gateway", host, r.Connect)
	}
	if r.Control != "ok" {
		return Skip, fmt.Sprintf("a correct TLS handshake through the tunnel to %s did not complete (%s), so refusals could not be told from a broken path", host, r.Control)
	}
	var problems []string
	if r.SNIMismatch != "closed" {
		problems = append(problems, "a ClientHello whose SNI differs from the CONNECT host was let through")
	}
	if r.ECH != "closed" {
		problems = append(problems, "a ClientHello carrying encrypted_client_hello was let through")
	}
	if r.NoTLS != "closed" {
		problems = append(problems, "non-TLS bytes through the tunnel were let through")
	}
	if len(problems) > 0 {
		return Fail, strings.Join(problems, "; ")
	}
	if _, ok := waitAudit(e, func(a audit.Record) bool {
		return a.Reason == "sni-mismatch" && a.SNI == badSNI
	}); !ok {
		return Fail, "the mismatching handshake was closed but the audit log has no sni-mismatch record for it"
	}
	if _, ok := waitAudit(e, func(a audit.Record) bool {
		return a.Reason == "ech" && a.Host == host && a.TS.After(start)
	}); !ok {
		return Fail, "the ECH handshake was closed but the audit log has no ech record for it"
	}
	return Pass, fmt.Sprintf("through %s: correct handshake works; SNI mismatch, ECH and non-TLS are closed and logged", host)
}

// 8 ----------------------------------------------------------------------------------------------

const shProtected = `
cd /workspace || exit 3
rc=0
mounts=$(cat /proc/self/mountinfo)
for p in "$@"; do
  [ -e "$p" ] || { echo "missing:$p"; continue; }
  if printf '%s\n' "$mounts" | awk -v m="/workspace/$p" '$5==m {print $6}' | grep -q '\bro\b'; then echo "mount-ro:$p"; else echo "NOT-A-RO-MOUNT:$p"; rc=1; fi
  if [ -d "$p" ]; then
    t="$p/.kennel-verify-$$"
    if ( : > "$t" ) 2>/dev/null; then echo "WRITABLE:$p"; rm -f "$t"; rc=1; else echo "write-refused:$p"; fi
  else
    if ( : >> "$p" ) 2>/dev/null; then echo "WRITABLE:$p"; rc=1; else echo "write-refused:$p"; fi
  fi
  d="$p"
  while [ "$d" != "." ] && [ "$d" != "/" ]; do
    if mv "$d" "$d.verify-moved" 2>/dev/null; then echo "RENAMABLE:$d"; mv "$d.verify-moved" "$d"; rc=1; else echo "pinned:$d"; fi
    d=$(dirname "$d")
  done
done
[ -z "$(ls -A /workspace/.kennel/state 2>/dev/null)" ] || { echo "STATE-VISIBLE"; rc=1; }
[ ! -e /etc/kennel ] || { echo "ETC-KENNEL"; rc=1; }
exit $rc
`

const shIsolation = `
m="$1"
cd /workspace || exit 3
rc=0
[ ! -e "/workspace/$m-host" ] || { echo "HOST-FILE-VISIBLE"; rc=1; }
: > "/workspace/$m-agent" || { echo "CANNOT-WRITE-WORKSPACE"; exit 1; }
echo "agent-wrote"
[ -z "$(ls -A /workspace/.kennel/state 2>/dev/null)" ] || { echo "STATE-VISIBLE"; rc=1; }
[ ! -e /etc/kennel ] || { echo "ETC-KENNEL"; rc=1; }
exit $rc
`

// checkWorkspaceIsolation is check 8 in volume mode. There are no read-only mounts to test: the
// protection is that the host working tree is not in the container at all, so nothing the agent
// writes can land in it except through `kennel fetch`, which gates protected files.
func checkWorkspaceIsolation(ctx context.Context, e *Env) (Status, string) {
	if e.HostMarker == nil || e.HostHas == nil {
		return Fail, "internal error: volume mode needs host-side file access for this check"
	}
	tok := "verify-" + e.Token()
	cleanup, err := e.HostMarker(tok + "-host")
	if err != nil {
		return Fail, "could not create a marker in your repository: " + err.Error()
	}
	defer cleanup()
	// The marker the agent creates is left in place while the host looks for it.
	defer func() { _, _ = e.Exec(ctx, "rm", "-f", "--", "/workspace/"+tok+"-agent") }()
	o, err := e.Exec(ctx, "sh", "-c", shIsolation, "verify", tok)
	if err != nil {
		return Fail, err.Error()
	}
	if o.Code != 0 || !strings.Contains(o.Stdout, "agent-wrote") {
		return Fail, "the agent's workspace is not isolated from the host: " + strings.TrimSpace(strings.ReplaceAll(o.Stdout+" "+o.Stderr, "\n", " "))
	}
	if e.HostHas(tok + "-agent") {
		return Fail, "a file the agent created in /workspace appeared in your repository: the workspace is shared with the host"
	}
	return Pass, "the agent's workspace is a separate copy: a file created in your repository does not appear in it, a file the agent creates does not appear on the host, and gateway state is not visible. Changes reach you only through `kennel fetch`, which holds protected files for confirmation"
}

func checkProtected(ctx context.Context, e *Env) (Status, string) {
	if e.VolumeMode {
		return checkWorkspaceIsolation(ctx, e)
	}
	if len(e.Protected) == 0 {
		return Skip, "no protected path exists in this project to test"
	}
	argv := append([]string{"sh", "-c", shProtected, "verify"}, e.Protected...)
	o, err := e.Exec(ctx, argv...)
	if err != nil {
		return Fail, err.Error()
	}
	var bad []string
	checked := 0
	for _, l := range strings.Split(o.Stdout, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "write-refused:"):
			checked++
		case l == "":
		case strings.HasPrefix(l, "mount-ro:"), strings.HasPrefix(l, "pinned:"), strings.HasPrefix(l, "missing:"):
		default:
			bad = append(bad, l)
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Fail, "the agent could escape the protections: " + strings.Join(bad, ", ")
	}
	if o.Code != 0 {
		return Fail, fmt.Sprintf("the probe failed (exit %d): %s", o.Code, truncate(o.Stderr, 200))
	}
	if checked == 0 {
		return Fail, "no protected path could be probed"
	}
	return Pass, fmt.Sprintf("%d protected path(s): read-only mounts, writes refused, they and their parents cannot be renamed; gateway state and policy are not visible", checked)
}

// 9 ----------------------------------------------------------------------------------------------

const shHardening = `
grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status
echo "uid=$(id -u)"
for s in /var/run/docker.sock /run/docker.sock /docker.sock; do [ -e "$s" ] && echo "SOCKET=$s"; done
grep -q docker.sock /proc/self/mountinfo && echo "SOCKET-MOUNT"
# Docker masks /proc/kcore with /dev/null, which is "readable" but empty; only data is a leak.
[ -n "$(head -c 16 /proc/kcore 2>/dev/null | head -c 1)" ] && echo "READABLE=/proc/kcore"
[ -w /proc/sysrq-trigger ] && echo "WRITABLE=/proc/sysrq-trigger"
for d in mem kmem port; do [ -e "/dev/$d" ] && echo "DEVICE=/dev/$d"; done
echo done
`

func checkHardening(ctx context.Context, e *Env) (Status, string) {
	o, err := e.Exec(ctx, "sh", "-c", shHardening)
	if err != nil {
		return Fail, err.Error()
	}
	if !strings.Contains(o.Stdout, "done") {
		return Fail, "the probe did not finish: " + truncate(o.Stderr, 200)
	}
	vals := map[string]string{}
	var flags []string
	for _, l := range strings.Split(o.Stdout, "\n") {
		l = strings.TrimSpace(l)
		if k, v, ok := strings.Cut(l, ":"); ok && !strings.Contains(k, "=") {
			vals[k] = strings.TrimSpace(v)
		} else if k, v, ok := strings.Cut(l, "="); ok && k == "uid" {
			vals["uid"] = v
		} else if l != "" && l != "done" {
			flags = append(flags, l)
		}
	}
	var bad []string
	if strings.Trim(vals["CapEff"], "0") != "" || vals["CapEff"] == "" {
		bad = append(bad, "CapEff="+vals["CapEff"]+" (want 0)")
	}
	if vals["NoNewPrivs"] != "1" {
		bad = append(bad, "NoNewPrivs="+vals["NoNewPrivs"]+" (want 1)")
	}
	if n, err := strconv.Atoi(vals["uid"]); err != nil || n == 0 {
		bad = append(bad, "the agent runs as uid "+vals["uid"])
	}
	bad = append(bad, flags...)
	if len(bad) > 0 {
		return Fail, strings.Join(bad, ", ")
	}
	sec := "seccomp filter active"
	if vals["Seccomp"] == "0" {
		sec = "seccomp: none (the engine's default profile is disabled)"
	}
	return Pass, fmt.Sprintf("uid %s, CapEff 0, NoNewPrivs 1, no Docker socket, no host memory devices; %s", vals["uid"], sec)
}

// 10 ---------------------------------------------------------------------------------------------

func checkHostIsolation(ctx context.Context, e *Env) (Status, string) {
	var r struct {
		HostDockerInternal bool     `json:"host_docker_internal"`
		DefaultRoutes      []string `json:"default_routes"`
		Reachable          []string `json:"reachable"`
		ProxyControl       bool     `json:"proxy_control"`
	}
	if err := pyJSON(ctx, e, &r, pyHost); err != nil {
		return Fail, err.Error()
	}
	switch {
	case r.HostDockerInternal:
		return Fail, "host.docker.internal resolves inside the sandbox"
	case len(r.Reachable) > 0:
		return Fail, "the agent reached " + strings.Join(r.Reachable, ", ") + " (host services or the gateway's control surface)"
	case !r.ProxyControl:
		return Fail, "the agent cannot reach the gateway's proxy port either, so unreachable results prove nothing"
	}
	routes := "no default route"
	if len(r.DefaultRoutes) > 0 {
		routes = "default route via " + strings.Join(r.DefaultRoutes, ", ") + " (nothing behind it answers)"
	}
	return Pass, "host.docker.internal does not resolve; common host-service ports on likely host addresses and the gateway's admin port are unreachable; the proxy port is (" + routes + ")"
}

// 11 ---------------------------------------------------------------------------------------------

func checkPreview(ctx context.Context, e *Env) (Status, string) {
	if len(e.Ports) == 0 {
		return Skip, "no preview ports are configured (kennel ports add <port>)"
	}
	port := e.Ports[0]
	listeners, err := e.Listeners(ctx)
	if err != nil {
		return Fail, "could not inspect the agent's listeners: " + err.Error()
	}
	switch listeners[port] {
	case "loopback-only":
		return Fail, fmt.Sprintf("the dev server on port %d listens on localhost inside the container, so the gateway cannot reach it; make it listen on 0.0.0.0", port)
	case "all-interfaces":
		line, err := e.HostGet(ctx, port)
		if err != nil {
			return Fail, fmt.Sprintf("a dev server listens on %d but 127.0.0.1:%d on the host does not reach it: %v", port, port, err)
		}
		return Pass, fmt.Sprintf("host 127.0.0.1:%d reaches the dev server in the agent (%s)", port, line)
	}

	// Nothing is listening: stand up a throwaway server so the path can still be proven.
	held, err := e.Hold(ctx, "sh", "-c", fmt.Sprintf("exec timeout 25 python3 -m http.server %d --bind 0.0.0.0 --directory /tmp", port))
	if err != nil {
		return Fail, "could not start the throwaway server: " + err.Error()
	}
	defer func() { _ = held.Close() }()
	var line string
	var herr error
	for i := 0; i < 40; i++ {
		if line, herr = e.HostGet(ctx, port); herr == nil && strings.HasPrefix(line, "HTTP/") {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if herr != nil || !strings.HasPrefix(line, "HTTP/") {
		return Fail, fmt.Sprintf("a server listening on 0.0.0.0:%d in the agent is not reachable at 127.0.0.1:%d on the host: %v", port, port, herr)
	}

	// The forwarder relays bytes to the agent and nothing else: ask it, from inside the sandbox,
	// to fetch an unrelated address and see who answers.
	var out []struct {
		Server string `json:"server"`
	}
	script := `
import socket, json, sys
port = int(sys.argv[1])
s = socket.create_connection(("gateway", port), timeout=5); s.settimeout(5)
s.sendall(b"GET http://1.1.1.1/ HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
buf = b""
try:
    while len(buf) < 4096:
        d = s.recv(2048)
        if not d: break
        buf += d
except Exception: pass
server = ""
for l in buf.decode("latin1").split("\r\n"):
    if l.lower().startswith("server:"): server = l.split(":", 1)[1].strip()
print(json.dumps([{"server": server}]))
`
	if err := pyJSON(ctx, e, &out, script, strconv.Itoa(port)); err != nil {
		return Fail, err.Error()
	}
	if len(out) != 1 || !strings.Contains(out[0].Server, "SimpleHTTP") {
		return Fail, fmt.Sprintf("a request for 1.1.1.1 sent to the forwarder was not answered by the agent's own server (Server: %q)", out[0].Server)
	}
	return Pass, fmt.Sprintf("host 127.0.0.1:%d reaches the agent (%s); a request for an outside address sent to the forwarder is answered by the agent's server, not relayed", port, line)
}

// 12 ---------------------------------------------------------------------------------------------

func checkHotReload(ctx context.Context, e *Env) (Status, string) {
	host := allowedHost(e.Policy)
	if host == "" {
		return Skip, "the policy has no exact allowed host to hold a connection open to"
	}
	held, err := e.Hold(ctx, "python3", "-c", pyHold, host)
	if err != nil {
		return Fail, "could not start the probe: " + err.Error()
	}
	defer func() { _ = held.Close() }()
	line, err := held.ReadLine(30 * time.Second)
	if err != nil {
		return Fail, "the probe did not report: " + err.Error()
	}
	if strings.HasPrefix(line, "NOTUNNEL") {
		return Skip, fmt.Sprintf("cannot open a tunnel to %s (%s): this check needs outbound network from the gateway", host, line)
	}
	if line != "READY" {
		return Fail, "unexpected probe output: " + line
	}

	fresh := "reload-" + e.Token() + ".kennel-verify.invalid"
	undo, took, err := e.AllowTemp(ctx, []string{fresh})
	if err != nil {
		return Fail, "could not add the rule: " + err.Error()
	}
	defer undo()
	if took > 2*time.Second {
		return Fail, fmt.Sprintf("the gateway took %s to enforce a new rule (limit 2s)", took.Round(time.Millisecond))
	}
	out, err := viaProxy(ctx, e, connectReq(fresh+":443"))
	if err != nil {
		return Fail, err.Error()
	}
	if out[0].Status == 403 {
		return Fail, fmt.Sprintf("the gateway reported the new policy but still refuses %s: %s (%s)", fresh, out[0].Line, out[0].Reason)
	}

	if err := held.Send("GO"); err != nil {
		return Fail, "could not resume the held connection: " + err.Error()
	}
	res, err := held.ReadLine(30 * time.Second)
	if err != nil {
		return Fail, "the held connection gave no answer after the reload: " + err.Error()
	}
	if res != "ALIVE" {
		return Fail, "the in-flight connection was dropped by the reload: " + res
	}
	return Pass, fmt.Sprintf("a new rule was enforced in %s; a tunnel to %s opened before the reload still completed a TLS handshake afterwards", took.Round(time.Millisecond), host)
}
