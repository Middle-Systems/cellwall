package policy

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	long63 := strings.Repeat("a", 63)
	tests := []struct {
		in, want, code string
	}{
		{in: "example.com", want: "example.com"},
		{in: "EXAMPLE.Com", want: "example.com"},
		{in: "example.com.", want: "example.com"}, // single trailing dot stripped
		{in: "a-b.example.com", want: "a-b.example.com"},
		{in: "xn--bcher-kva.example", want: "xn--bcher-kva.example"}, // punycode passes through literally
		{in: "localhost", want: "localhost"},
		{in: long63 + ".com", want: long63 + ".com"},

		{in: "", code: HostEmpty},
		{in: ".", code: HostEmpty},
		{in: "example.com..", code: HostEmptyLabel},
		{in: ".example.com", code: HostEmptyLabel},
		{in: "a..b", code: HostEmptyLabel},
		{in: "-a.com", code: HostBadHyphen},
		{in: "a-.com", code: HostBadHyphen},
		{in: "a_b.com", code: HostBadChar},
		{in: "a b.com", code: HostBadChar},
		{in: "a/b.com", code: HostBadChar},
		{in: "a@b.com", code: HostBadChar},
		{in: "a:443", code: HostBadChar},
		{in: "exa\x00mple.com", code: HostBadChar},
		{in: "exa\nmple.com", code: HostBadChar},
		{in: "bücher.example", code: HostNonASCII}, // never silently IDNA-converted
		{in: "例え.jp", code: HostNonASCII},
		{in: "ex\u202eample.com", code: HostNonASCII}, // bidi override
		{in: long63 + "a.com", code: HostLabelTooLong},
		{in: strings.Repeat("a.", 127) + "a", code: HostTooLong}, // 255 bytes
	}
	for _, tt := range tests {
		got, err := NormalizeHost(tt.in, 0, 0)
		if tt.code == "" {
			if err != nil || got != tt.want {
				t.Errorf("NormalizeHost(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
			continue
		}
		var he *HostError
		if !errors.As(err, &he) || he.Code != tt.code {
			t.Errorf("NormalizeHost(%q) error = %v; want code %s", tt.in, err, tt.code)
		}
	}
}

func TestNormalizeHostConfigurableLimits(t *testing.T) {
	if _, err := NormalizeHost("abcdefghijk.com", 0, 10); err == nil {
		t.Error("label over a configured limit of 10 must be rejected")
	}
	if _, err := NormalizeHost("a.example.com", 8, 0); err == nil {
		t.Error("host over a configured limit of 8 must be rejected")
	}
	// A configured limit can only tighten: values above the RFC maximum are clamped.
	if _, err := NormalizeHost(strings.Repeat("a", 64)+".com", 10000, 10000); err == nil {
		t.Error("limits above the RFC maximum must be clamped, not honoured")
	}
}

func TestLooksLikeIP(t *testing.T) {
	yes := []string{
		"127.0.0.1", "10.0.0.1", "8.8.8.8", "169.254.169.254", "0.0.0.0",
		"::1", "[::1]", "::ffff:127.0.0.1", "fe80::1%eth0", "2001:db8::1", "[2001:db8::1]",
		"2130706433",    // 127.0.0.1 as one integer
		"0x7f000001",    // hex integer
		"0x7f.1",        // mixed hex
		"127.1",         // shorthand
		"0177.0.0.1",    // octal
		"1.2.3.4.",      // trailing dot
		"example.123",   // numeric TLD can never be a real name
		"evil.0xdeadbe", // hex-looking last label
	}
	for _, h := range yes {
		if !LooksLikeIP(h) {
			t.Errorf("LooksLikeIP(%q) = false; want true", h)
		}
	}
	no := []string{"example.com", "a1.b2.example.org", "1password.com", "123.example.com", "xn--abc.com", "localhost", "registry-1.docker.io", ""}
	for _, h := range no {
		if LooksLikeIP(h) {
			t.Errorf("LooksLikeIP(%q) = true; want false", h)
		}
	}
}

func TestPatternMatching(t *testing.T) {
	tests := []struct {
		pattern string
		match   []string
		noMatch []string
	}{
		{"example.com",
			[]string{"example.com"},
			[]string{"a.example.com", "xexample.com", "example.com.evil.com", "example.co", "evil-example.com"}},
		{"*.example.com",
			[]string{"a.example.com", "files-1.example.com"},
			[]string{"example.com", "a.b.example.com", "xexample.com", "a.example.com.evil.com", "example.com.example.com.evil"}},
		{"**.example.com",
			[]string{"a.example.com", "a.b.example.com", "a.b.c.example.com"},
			[]string{"example.com", "xexample.com", "a.example.com.evil.com", ".example.com"}},
	}
	for _, tt := range tests {
		p, err := ParsePattern(tt.pattern)
		if err != nil {
			t.Fatalf("ParsePattern(%q): %v", tt.pattern, err)
		}
		for _, h := range tt.match {
			if !p.Matches(h) {
				t.Errorf("%q should match %q", tt.pattern, h)
			}
		}
		for _, h := range tt.noMatch {
			if p.Matches(h) {
				t.Errorf("%q must NOT match %q", tt.pattern, h)
			}
		}
	}
}

func TestParsePatternRejects(t *testing.T) {
	bad := []string{
		"", "*", "**", "*.", "a*.example.com", "*a.example.com", "example.*", "a.*.example.com", "*.*.example.com",
		"***.example.com", "127.0.0.1", "*.127.0.0.1", "::1", "[::1]", "2130706433", "bücher.example", "a_b.example",
		"http://example.com", "example.com/path", "example.com:443", " example.com",
	}
	for _, s := range bad {
		if _, err := ParsePattern(s); err == nil {
			t.Errorf("ParsePattern(%q) should fail", s)
		}
	}
}

func TestPatternNormalizesCase(t *testing.T) {
	p, err := ParsePattern("*.Example.COM")
	if err != nil || p.Base != "example.com" {
		t.Fatalf("got %+v, %v", p, err)
	}
}
