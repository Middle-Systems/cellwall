package verify

// The probes are small Python programs run inside the agent container. Python is used because the
// agent image always has it and its socket and ssl modules can express every attempt precisely.
// Each prints exactly one JSON document on its last line.

// pyProxy sends raw requests to the proxy named by $HTTPS_PROXY (so the proxy environment is
// part of what is verified) and reports status, X-Cellwall-Reason and the start of the body.
const pyProxy = `
import socket, json, os, sys, urllib.parse
u = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "http://gateway:3128")
addr = (u.hostname, u.port or 3128)
def probe(raw):
    s = socket.create_connection(addr, timeout=10); s.settimeout(10)
    s.sendall(raw.encode())
    buf = b""
    try:
        while len(buf) < 16384:
            d = s.recv(4096)
            if not d: break
            buf += d
            head, sep, body = buf.partition(b"\r\n\r\n")
            if sep and head.startswith(b"HTTP/1.1 200"): break
    except Exception as e:
        pass
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin1").split("\r\n")
    st = 0
    try: st = int(lines[0].split()[1])
    except Exception: pass
    reason = ""
    for l in lines[1:]:
        if l.lower().startswith("x-cellwall-reason:"): reason = l.split(":", 1)[1].strip()
    return {"status": st, "reason": reason, "line": lines[0][:80], "body": body.decode("latin1")[:200]}
print(json.dumps([probe(r) for r in json.loads(sys.argv[1])]))
`

// pyDirect tries to open connections that must have no route.
const pyDirect = `
import socket, json
res = []
for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443), ("2606:4700:4700::1111", 443)]:
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(4)
    except OSError as e:
        # No IPv6 in this kernel at all: certainly no IPv6 route out.
        res.append({"to": "%s:%d" % (host, port), "connected": False, "err": "unsupported"})
        continue
    try:
        s.connect((host, port)); res.append({"to": "%s:%d" % (host, port), "connected": True})
    except Exception as e:
        res.append({"to": "%s:%d" % (host, port), "connected": False, "err": type(e).__name__})
    finally:
        s.close()
print(json.dumps(res))
`

// pyDNS looks for any way a name can leave through DNS.
const pyDNS = `
import socket, json, struct
out = {}
try: out["resolv"] = [l.split()[1] for l in open("/etc/resolv.conf") if l.startswith("nameserver")]
except Exception: out["resolv"] = []
try: socket.getaddrinfo("gateway", 3128); out["gateway_resolves"] = True
except Exception: out["gateway_resolves"] = False
try: socket.getaddrinfo("example.com", 443); out["public_resolves"] = True
except Exception: out["public_resolves"] = False
def query(name):
    h = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return h + q + struct.pack(">HH", 1, 1)
leaks = []
for srv in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(query("example.com"), (srv, 53)); s.recvfrom(512); leaks.append(srv)
    except Exception:
        pass
    finally:
        s.close()
out["udp_leaks"] = leaks
print(json.dumps(out))
`

// pyTLS opens a tunnel to an allowed host and sends handshakes the gateway must refuse.
const pyTLS = `
import socket, ssl, json, os, sys, struct, urllib.parse
host, bad_sni = sys.argv[1], sys.argv[2]
u = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY") or "http://gateway:3128")
addr = (u.hostname, u.port or 3128)
def tunnel():
    s = socket.create_connection(addr, timeout=15); s.settimeout(15)
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(4096)
        if not d: break
        buf += d
    try: st = int(buf.split(b"\r\n")[0].split()[1])
    except Exception: st = 0
    return s, st
def hello(sni, ech):
    def ext(t, b): return struct.pack(">HH", t, len(b)) + b
    n = sni.encode()
    sn = struct.pack(">BH", 0, len(n)) + n
    exts = ext(0, struct.pack(">H", len(sn)) + sn) + ext(0x2b, b"\x02\x03\x04") + ext(0x0a, struct.pack(">HHH", 4, 0x001d, 0x0017))
    if ech: exts += ext(0xfe0d, b"\x00" + os.urandom(32))
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
def closed_after(payload):
    s, st = tunnel()
    if st != 200: return "no-tunnel:%d" % st
    try:
        s.sendall(payload)
        d = s.recv(4096)
        return "open" if d else "closed"
    except (ConnectionResetError, BrokenPipeError, socket.timeout) as e:
        return "closed" if not isinstance(e, socket.timeout) else "open"
    finally:
        s.close()
res = {}
s, st = tunnel()
res["connect"] = st
if st != 200:
    print(json.dumps(res)); sys.exit(0)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    t = ctx.wrap_socket(s, server_hostname=host); res["control"] = "ok"; t.close()
except Exception as e:
    res["control"] = "fail:" + type(e).__name__
    try: s.close()
    except Exception: pass
try:
    s2, st2 = tunnel()
    ctx.wrap_socket(s2, server_hostname=bad_sni); res["sni_mismatch"] = "open"
except Exception as e:
    res["sni_mismatch"] = "closed"
res["ech"] = closed_after(hello(host, True))
res["no_tls"] = closed_after(b"GET / HTTP/1.0\r\n\r\n")
print(json.dumps(res))
`

// pyHold opens a tunnel, waits for GO on stdin, then proves the tunnel still works by completing
// a TLS handshake through it.
const pyHold = `
import socket, ssl, os, sys, json, urllib.parse
host = sys.argv[1]
u = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY") or "http://gateway:3128")
s = socket.create_connection((u.hostname, u.port or 3128), timeout=15); s.settimeout(20)
s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n" % (host, host)).encode())
buf = b""
while b"\r\n\r\n" not in buf:
    d = s.recv(4096)
    if not d: break
    buf += d
try: st = int(buf.split(b"\r\n")[0].split()[1])
except Exception: st = 0
if st != 200:
    print("NOTUNNEL %d" % st, flush=True); sys.exit(0)
print("READY", flush=True)
sys.stdin.readline()
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
try:
    ctx.wrap_socket(s, server_hostname=host); print("ALIVE", flush=True)
except Exception as e:
    print("DROPPED " + type(e).__name__, flush=True)
`

// pyHost reports whether the sandbox can reach the host or the gateway's control surface.
const pyHost = `
import socket, json, struct
from concurrent.futures import ThreadPoolExecutor
out = {}
try: socket.getaddrinfo("host.docker.internal", 80); out["host_docker_internal"] = True
except Exception: out["host_docker_internal"] = False
gws = []
try:
    for l in open("/proc/net/route").read().splitlines()[1:]:
        f = l.split()
        if f[1] == "00000000" and f[7] == "00000000":
            gws.append(socket.inet_ntoa(struct.pack("<L", int(f[2], 16))))
except Exception: pass
out["default_routes"] = gws
def tryconn(t):
    host, port = t
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.5)
    try: s.connect((host, port)); return "%s:%d" % (host, port)
    except Exception: return None
    finally: s.close()
cands = set(gws) | {"172.17.0.1", "192.168.65.254", "192.168.65.2", "10.0.2.2", "169.254.169.254"}
targets = [(h, p) for h in cands for p in (22, 80, 443, 2375, 2376, 3306, 5432, 6379, 8080, 9090)]
targets += [("gateway", p) for p in (22, 80, 2375, 3129, 9090, 9100)]
with ThreadPoolExecutor(32) as ex:
    out["reachable"] = [r for r in ex.map(tryconn, targets) if r]
out["proxy_control"] = tryconn(("gateway", 3128)) is not None
print(json.dumps(out))
`
