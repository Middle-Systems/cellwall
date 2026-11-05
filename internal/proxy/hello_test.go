package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/middle-systems/kennel/internal/proxy/proxytest"
)

func helloErrCode(t *testing.T, err error) string {
	t.Helper()
	var he *HelloError
	if !errors.As(err, &he) {
		t.Fatalf("want HelloError, got %v", err)
	}
	return he.Code
}

func TestReadClientHelloBasic(t *testing.T) {
	stream := proxytest.Records(proxytest.HelloOpts{SNI: "registry.npmjs.org"})
	info, raw, err := ReadClientHello(bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasSNI || info.SNI != "registry.npmjs.org" || info.ECH {
		t.Fatalf("%+v", info)
	}
	if !bytes.Equal(raw, stream) {
		t.Error("raw bytes must be the exact stream, to forward verbatim")
	}
}

func TestReadClientHelloNoSNI(t *testing.T) {
	for name, o := range map[string]proxytest.HelloOpts{
		"no sni ext":    {},
		"no extensions": {NoExt: true},
	} {
		info, _, err := ReadClientHello(bytes.NewReader(proxytest.Records(o)))
		if err != nil || info.HasSNI {
			t.Errorf("%s: info=%+v err=%v", name, info, err)
		}
	}
}

func TestReadClientHelloDoesNotOverRead(t *testing.T) {
	// Application data pipelined right behind the hello must be left in the reader.
	stream := proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com"})
	r := bytes.NewReader(append(append([]byte{}, stream...), []byte("PIPELINED-APP-DATA")...))
	_, raw, err := ReadClientHello(r)
	if err != nil || !bytes.Equal(raw, stream) {
		t.Fatalf("raw mismatch: %v", err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "PIPELINED-APP-DATA" {
		t.Errorf("rest = %q", rest)
	}
}

func TestReadClientHelloFragmented(t *testing.T) {
	for _, sizes := range [][]int{{10}, {1, 1, 1, 1, 1}, {5, 20, 5}, {4}, {3}} {
		o := proxytest.HelloOpts{SNI: "frag.example.com", RecordSize: sizes}
		stream := proxytest.Records(o)
		info, raw, err := ReadClientHello(bytes.NewReader(stream))
		if err != nil {
			// Many tiny records legitimately exceed the record cap.
			if helloErrCode(t, err) != HelloBadRecord {
				t.Errorf("sizes %v: %v", sizes, err)
			}
			continue
		}
		if info.SNI != "frag.example.com" || !bytes.Equal(raw, stream) {
			t.Errorf("sizes %v: %+v", sizes, info)
		}
	}
	// A handshake header split across records still parses.
	stream := proxytest.Records(proxytest.HelloOpts{SNI: "x.example.com", RecordSize: []int{2, 2}})
	if info, _, err := ReadClientHello(bytes.NewReader(stream)); err != nil || info.SNI != "x.example.com" {
		t.Errorf("header split across records: %v %+v", err, info)
	}
}

func TestReadClientHelloECH(t *testing.T) {
	for _, cp := range []uint16{0xfe0d, 0xfe0c, 0xfe0b, 0xfe0a, 0xfe09, 0xfe08, 0xffce} {
		info, _, err := ReadClientHello(bytes.NewReader(proxytest.Records(proxytest.HelloOpts{SNI: "public.example.com", ECH: cp})))
		if err != nil || !info.ECH {
			t.Errorf("code point 0x%04x not detected: %+v %v", cp, info, err)
		}
	}
	// Extensions that real clients send and that must never be mistaken for ECH.
	for _, cp := range []uint16{0x1234, 0xff01 /* renegotiation_info */, 0xff02, 0xff03, 0x0015 /* padding */, 0xfe0e, 0xfe07} {
		info, _, _ := ReadClientHello(bytes.NewReader(proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", ECH: cp})))
		if info.ECH {
			t.Errorf("extension 0x%04x must not be flagged as ECH", cp)
		}
	}
}

func TestReadClientHelloRejectsAmbiguity(t *testing.T) {
	tests := []struct {
		name string
		o    proxytest.HelloOpts
		code string
	}{
		{"two host_names in one extension", proxytest.HelloOpts{SNI: "a.example.com", ExtraSNI: []string{"evil.com"}}, HelloMultiSNI},
		{"server_name extension twice", proxytest.HelloOpts{SNI: "a.example.com", DupSNIExt: true}, HelloDupExtension},
		{"data after hello", proxytest.HelloOpts{SNI: "a.example.com", Trailing: []byte("EVIL")}, HelloTrailing},
		{"bad record version", proxytest.HelloOpts{SNI: "a.example.com", Version: [2]byte{0x02, 0x00}}, HelloNotTLS},
	}
	for _, tt := range tests {
		_, _, err := ReadClientHello(bytes.NewReader(proxytest.Records(tt.o)))
		if got := helloErrCode(t, err); got != tt.code {
			t.Errorf("%s: code %s, want %s", tt.name, got, tt.code)
		}
	}
}

func TestReadClientHelloRejectsNonTLS(t *testing.T) {
	for name, in := range map[string]string{
		"http":     "GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
		"ssh":      "SSH-2.0-OpenSSH_9.0\r\n",
		"alert":    "\x15\x03\x03\x00\x02\x02\x28",
		"appdata":  "\x17\x03\x03\x00\x05hello",
		"zeros":    strings.Repeat("\x00", 64),
		"sslv2":    "\x80\x2e\x01\x03\x01",
		"zero len": "\x16\x03\x01\x00\x00",
		"huge rec": "\x16\x03\x01\xff\xff",
	} {
		_, _, err := ReadClientHello(strings.NewReader(in))
		if err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	// Not a ClientHello message type.
	rec := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00} // ServerHello header
	if _, _, err := ReadClientHello(bytes.NewReader(rec)); helloErrCode(t, err) != HelloBadHello {
		t.Errorf("non-ClientHello handshake: %v", err)
	}
}

func TestReadClientHelloTruncated(t *testing.T) {
	stream := proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com"})
	for _, n := range []int{0, 1, 4, 5, 6, 20, len(stream) - 1} {
		_, _, err := ReadClientHello(bytes.NewReader(stream[:n]))
		if err == nil {
			t.Errorf("truncated at %d should fail", n)
			continue
		}
		if helloErrCode(t, err) != HelloTruncated {
			t.Errorf("truncated at %d: %v", n, err)
		}
	}
}

func TestReadClientHelloSizeCaps(t *testing.T) {
	// Declared handshake length above the cap is refused before buffering it.
	rec := []byte{0x16, 0x03, 0x01, 0x00, 0x08, 0x01, 0xff, 0xff, 0xff, 0, 0, 0, 0}
	if _, _, err := ReadClientHello(bytes.NewReader(rec)); helloErrCode(t, err) != HelloTooLarge {
		t.Errorf("oversize declaration: %v", err)
	}
	// A large but legal hello (padding) still works.
	big := proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", Pad: 9000, RecordSize: []int{4000, 4000, 4000}})
	if info, _, err := ReadClientHello(bytes.NewReader(big)); err != nil || info.SNI != "a.example.com" {
		t.Errorf("large legal hello: %v", err)
	}
}

func TestReadClientHelloMalformedBodies(t *testing.T) {
	good := proxytest.Handshake(proxytest.HelloOpts{SNI: "a.example.com"})
	// Corrupt every byte one at a time and require no panic; most corruptions must be rejected
	// or at least yield a sane result.
	for i := range good {
		bad := append([]byte{}, good...)
		bad[i] ^= 0xff
		_, _ = ParseClientHello(bad)
	}
	// Lengths that disagree with the data.
	short := good[:len(good)-1]
	if _, err := ParseClientHello(short); err == nil {
		t.Error("length mismatch must be rejected")
	}
}

// A genuine crypto/tls ClientHello — what real agents will send — must parse and match.
func TestRealGoClientHello(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		cl := tls.Client(c1, &tls.Config{ServerName: "Registry.NpmJS.org", MinVersion: tls.VersionTLS12})
		_ = c1.SetDeadline(time.Now().Add(2 * time.Second))
		_ = cl.Handshake() // will fail when the peer closes; we only want the hello
	}()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	info, raw, err := ReadClientHello(c2)
	if err != nil {
		t.Fatal(err)
	}
	if info.SNI != "Registry.NpmJS.org" && info.SNI != "registry.npmjs.org" {
		t.Errorf("SNI = %q", info.SNI)
	}
	if info.ECH || len(raw) < 100 {
		t.Errorf("%+v raw=%d", info, len(raw))
	}
}

// Real TLS stacks, when installed, must produce hellos we parse without flagging ECH. This is the
// regression test for false positives, which would break legitimate traffic.
func TestRealClients(t *testing.T) {
	type client struct {
		name string
		argv func(port string) []string
	}
	clients := []client{
		{"openssl", func(p string) []string {
			return []string{"openssl", "s_client", "-connect", "127.0.0.1:" + p, "-servername", "Real.Example.com", "-brief"}
		}},
		{"curl", func(p string) []string {
			return []string{"curl", "-sk", "--noproxy", "*", "--max-time", "3", "--resolve", "real.example.com:" + p + ":127.0.0.1", "https://real.example.com:" + p + "/"}
		}},
		{"python3", func(p string) []string {
			return []string{"python3", "-c", "import socket,ssl,sys\nc=ssl.create_default_context();c.check_hostname=False;c.verify_mode=ssl.CERT_NONE\n" +
				"s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=3)\ntry: c.wrap_socket(s,server_hostname='real.example.com')\nexcept Exception: pass", p}
		}},
		{"node", func(p string) []string {
			return []string{"node", "-e", "require('tls').connect({host:'127.0.0.1',port:+process.argv[1],servername:'real.example.com',rejectUnauthorized:false}).on('error',()=>{}).setTimeout(3000,function(){this.destroy()})", p}
		}},
	}
	for _, c := range clients {
		t.Run(c.name, func(t *testing.T) {
			argv := c.argv("0")
			if _, err := exec.LookPath(argv[0]); err != nil {
				t.Skipf("%s not installed", argv[0])
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Skip(err)
			}
			defer ln.Close()
			// Never let a client that fails to connect hang the suite (e.g. one that honours a
			// proxy environment variable and talks to the proxy instead of this listener).
			// Generous: Node's cold start on a Windows CI runner takes several seconds.
			_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(25 * time.Second))
			_, port, _ := net.SplitHostPort(ln.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, c.argv(port)[0], c.argv(port)[1:]...) // #nosec G204 -- fixed test argv
			cmd.Env = append(os.Environ(), "HTTPS_PROXY=", "https_proxy=", "HTTP_PROXY=", "http_proxy=", "ALL_PROXY=", "all_proxy=")
			if err := cmd.Start(); err != nil {
				t.Skip(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			conn, err := ln.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			info, _, err := ReadClientHello(conn)
			if err != nil {
				t.Fatalf("%s hello rejected: %v", c.name, err)
			}
			if !strings.EqualFold(info.SNI, "real.example.com") {
				t.Errorf("%s SNI = %q", c.name, info.SNI)
			}
			if info.ECH {
				t.Errorf("%s hello flagged as ECH: legitimate clients would be blocked", c.name)
			}
		})
	}
}
