package proxy

import (
	"strings"
	"testing"
)

// Anything ParseConnectTarget accepts must be plain printable ASCII with a valid port, so the
// host can be logged and echoed without further escaping.
func FuzzParseConnectTarget(f *testing.F) {
	for _, s := range []string{"example.com:443", "[::1]:443", "a@b:1", "x:99999", "", "a b:1", "例:1", "a:1/b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		h, p, err := ParseConnectTarget(in)
		if err != nil {
			return
		}
		if p < 1 || p > 65535 || h == "" {
			t.Fatalf("bad result %q %d from %q", h, p, in)
		}
		for i := 0; i < len(in); i++ {
			if in[i] <= 0x20 || in[i] >= 0x7f {
				t.Fatalf("accepted control/non-ASCII byte in %q", in)
			}
		}
		if strings.ContainsAny(h, "/@?#\\ ") {
			t.Fatalf("accepted host %q with delimiter", h)
		}
		_ = Suspicious(h)
		_ = printable(h)
	})
}
