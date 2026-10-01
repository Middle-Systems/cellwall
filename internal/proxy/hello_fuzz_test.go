package proxy

import (
	"bytes"
	"testing"

	"github.com/middle-systems/cellwall/internal/proxy/proxytest"
)

func helloSeeds(f *testing.F) {
	f.Add(proxytest.Records(proxytest.HelloOpts{SNI: "registry.npmjs.org"}))
	f.Add(proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", RecordSize: []int{7, 3}}))
	f.Add(proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", ECH: 0xfe0d}))
	f.Add(proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", ExtraSNI: []string{"b.example.com"}}))
	f.Add(proxytest.Records(proxytest.HelloOpts{SNI: "a.example.com", DupSNIExt: true}))
	f.Add(proxytest.Records(proxytest.HelloOpts{NoExt: true}))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})
}

// ReadClientHello must never panic, must only ever return a prefix of the input as the consumed
// bytes (so forwarding them verbatim is faithful), and may only accept hellos whose own length
// fields are consistent.
func FuzzReadClientHello(f *testing.F) {
	helloSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		info, raw, err := ReadClientHello(r)
		if !bytes.HasPrefix(data, raw) {
			t.Fatalf("consumed bytes are not a prefix of the input")
		}
		if err != nil {
			return
		}
		if info == nil {
			t.Fatal("nil info without error")
		}
		if len(raw) > maxHelloBytes+5*maxHelloRecords {
			t.Fatalf("buffered %d bytes", len(raw))
		}
		if info.HasSNI == (info.SNI == "") {
			t.Fatalf("HasSNI=%v but SNI=%q", info.HasSNI, info.SNI)
		}
		// Re-parsing exactly the consumed bytes must give the same answer: the decision cannot
		// depend on what happened to follow the hello on the wire.
		again, raw2, err := ReadClientHello(bytes.NewReader(raw))
		if err != nil || *again != *info || !bytes.Equal(raw, raw2) {
			t.Fatalf("not stable on re-parse: %v %+v vs %+v", err, again, info)
		}
	})
}

// ParseClientHello on arbitrary bytes must never panic and must agree with itself.
func FuzzParseClientHello(f *testing.F) {
	for _, o := range []proxytest.HelloOpts{
		{SNI: "a.example.com"}, {SNI: "a.example.com", ECH: 0xfe0d}, {NoExt: true}, {SNI: "x.y.z", SessionID: 32},
	} {
		f.Add(proxytest.Handshake(o))
	}
	f.Add([]byte{0x01, 0, 0, 0})
	f.Fuzz(func(t *testing.T, msg []byte) {
		info, err := ParseClientHello(msg)
		if err != nil {
			return
		}
		if info.HasSNI == (info.SNI == "") {
			t.Fatalf("inconsistent SNI state: %+v", info)
		}
	})
}
