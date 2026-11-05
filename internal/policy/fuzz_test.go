package policy

import (
	"strings"
	"testing"
)

// Invariants for any input NormalizeHost accepts: the output is lowercase LDH, within the DNS
// limits, stable under re-normalization, and never looks like an IP address literal unless
// LooksLikeIP says so (callers check LooksLikeIP separately, so it must never panic).
func FuzzNormalizeHost(f *testing.F) {
	for _, s := range []string{"example.com", "EXAMPLE.com.", "a..b", "xn--bcher-kva.example", "127.0.0.1", "::1", "-a.com", "a_b", strings.Repeat("a", 70) + ".com", "\x00", "例え.jp"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		_ = LooksLikeIP(in)
		out, err := NormalizeHost(in, 0, 0)
		if err != nil {
			return
		}
		if len(out) == 0 || len(out) > MaxHostLen {
			t.Fatalf("bad length %d for %q -> %q", len(out), in, out)
		}
		if out != strings.ToLower(out) || strings.HasSuffix(out, ".") || strings.HasPrefix(out, ".") {
			t.Fatalf("not canonical: %q -> %q", in, out)
		}
		for _, label := range strings.Split(out, ".") {
			if label == "" || len(label) > MaxLabelLen || label[0] == '-' || label[len(label)-1] == '-' {
				t.Fatalf("bad label %q in %q -> %q", label, in, out)
			}
			for i := 0; i < len(label); i++ {
				c := label[i]
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
					t.Fatalf("non-LDH byte %q in %q -> %q", c, in, out)
				}
			}
		}
		again, err := NormalizeHost(out, 0, 0)
		if err != nil || again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q (%v)", in, out, again, err)
		}
	})
}

// A host is allowed only if some allow rule's pattern really matches it (so the index lookup can
// never allow a name the pattern semantics would not), and a matching deny rule always wins.
func FuzzMatch(f *testing.F) {
	c, err := Compile(&Policy{Version: 1, Rules: []Rule{
		{Host: "registry.npmjs.org"},
		{Host: "*.pythonhosted.org"},
		{Host: "**.deep.example.com"},
		{Host: "*.example.com"},
		{Host: "blocked.example.com", Action: ActionDeny},
		{Host: "plain.example.org", UnsafeAllowHTTP: true},
	}}, false)
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"registry.npmjs.org", "a.pythonhosted.org", "x.y.deep.example.com", "blocked.example.com", "a.example.com", "example.com", "a.b.example.com", "plain.example.org"} {
		f.Add(s, 443, false)
	}
	f.Fuzz(func(t *testing.T, raw string, port int, http bool) {
		host, err := NormalizeHost(raw, 0, 0)
		if err != nil {
			return
		}
		proto := ProtoTunnel
		if http {
			proto = ProtoHTTP
		}
		d := c.Match(host, port, proto)
		if !d.Allowed {
			return
		}
		if d.Rule == nil || d.Rule.Deny || !d.Rule.Pattern.Matches(host) {
			t.Fatalf("allowed %q:%d without a matching allow rule: %+v", host, port, d)
		}
		for _, r := range c.Policy.Rules {
			if r.IsDeny() && r.Pattern().Matches(host) && (len(r.Ports) == 0 || containsPort(r.Ports, port)) {
				t.Fatalf("allowed %q:%d despite deny rule %q", host, port, r.Host)
			}
		}
	})
}

// Pattern.Matches must agree with its documented semantics for any base and host.
func FuzzPattern(f *testing.F) {
	f.Add("*.example.com", "a.example.com")
	f.Add("**.example.com", "a.b.example.com")
	f.Add("example.com", "example.com")
	f.Fuzz(func(t *testing.T, pat, raw string) {
		p, err := ParsePattern(pat)
		if err != nil {
			return
		}
		host, err := NormalizeHost(raw, 0, 0)
		if err != nil {
			return
		}
		got := p.Matches(host)
		var want bool
		switch p.Kind {
		case Exact:
			want = host == p.Base
		case SingleLabel:
			head, tail, ok := strings.Cut(host, ".")
			want = ok && head != "" && tail == p.Base
		case MultiLabel:
			want = strings.HasSuffix(host, "."+p.Base) && len(host) > len(p.Base)+1
		}
		if got != want {
			t.Fatalf("%v.Matches(%q) = %v, want %v", p, host, got, want)
		}
		if got && host == p.Base && p.Kind != Exact {
			t.Fatalf("wildcard %v matched its own apex", p)
		}
	})
}

// Parse must never panic, and anything it accepts must be safe to Validate and Compile.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"version: 1\nrules:\n  - host: a.com\n",
		"version: 1\npresets: [node]\nlimits: {idle_timeout: 5s}\n",
		`{"version":1,"rules":[{"host":"*.a.com","ports":[443]}]}`,
		"version: 1\nrules:\n  - &a {host: a.com}\n",
		"- a\n", "", "---\n---\n", "version: !!str 1\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse("fuzz", data)
		if err != nil {
			return
		}
		if err := p.Validate(false); err != nil {
			return
		}
		if c, err := Compile(p, false); err == nil {
			_ = c.Match("a.com", 443, ProtoTunnel)
			if _, err := Canonical(c.Policy); err != nil {
				t.Fatalf("accepted policy cannot be encoded: %v", err)
			}
		}
	})
}
