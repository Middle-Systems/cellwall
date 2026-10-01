package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse("test.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, src)
	}
	return p
}

func mustCompile(t *testing.T, src string) *Compiled {
	t.Helper()
	c, err := Compile(mustParse(t, src), false)
	if err != nil {
		t.Fatalf("Compile: %v\n%s", err, src)
	}
	return c
}

func TestParseErrorsHavePositions(t *testing.T) {
	tests := []struct {
		name, src, want string
		line, col       int
	}{
		{"typo suggests key", "version: 1\nrules:\n  - hots: a.com\n", `unknown key "rules[0].hots"`, 3, 5},
		{"unknown top key", "version: 1\nruels: []\n", `did you mean "rules"?`, 2, 1},
		{"unknown limit", "version: 1\nlimits:\n  max_conn: 5\n", `did you mean "max_conns"?`, 3, 3},
		{"duplicate key", "version: 1\nversion: 1\n", `duplicate key "version"`, 2, 1},
		{"alias", "version: 1\nrules:\n  - &a {host: a.com}\n", "anchors are not allowed", 3, 5},
		{"tag", "version: !!str 1\n", "explicit YAML tags", 1, 10},
		{"rules not list", "version: 1\nrules: x\n", `"rules" must be a list`, 2, 8},
		{"rule not map", "version: 1\nrules:\n  - a.com\n", "must be a mapping", 3, 5},
		{"limits not map", "version: 1\nlimits: 5\n", `"limits" must be a mapping`, 2, 9},
		{"top not map", "- a\n", "must be a mapping", 1, 1},
		{"multi doc", "version: 1\n---\nversion: 1\n", "multiple YAML documents", 2, 1},
	}
	for _, tt := range tests {
		_, err := Parse("p.yaml", []byte(tt.src))
		var se *SyntaxError
		if !errors.As(err, &se) {
			t.Errorf("%s: got %v, want SyntaxError", tt.name, err)
			continue
		}
		if !strings.Contains(se.Msg, tt.want) {
			t.Errorf("%s: msg %q does not contain %q", tt.name, se.Msg, tt.want)
		}
		if se.Line != tt.line || se.Col != tt.col {
			t.Errorf("%s: position %d:%d, want %d:%d (%v)", tt.name, se.Line, se.Col, tt.line, tt.col, se)
		}
	}
}

func TestParseEmptyAndOversize(t *testing.T) {
	if _, err := Parse("p", nil); err == nil {
		t.Error("empty file must fail")
	}
	if _, err := Parse("p", []byte(strings.Repeat("#", MaxPolicyBytes+1))); err == nil {
		t.Error("oversize file must fail")
	}
}

func TestParseAcceptsJSON(t *testing.T) {
	p := mustParse(t, `{"version": 1, "rules": [{"host": "a.example.com"}]}`)
	if len(p.Rules) != 1 || p.Rules[0].Host != "a.example.com" {
		t.Fatalf("%+v", p)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct{ name, src, want string }{
		{"wrong version", "version: 2\n", "version must be 1"},
		{"allow by default refused", "version: 1\ndefault: allow\n", "allow-by-default is not supported"},
		{"bad action", "version: 1\nrules:\n  - {host: a.com, action: permit}\n", "action must be"},
		{"port range", "version: 1\nrules:\n  - {host: a.com, ports: [0]}\n", "out of range"},
		{"port high", "version: 1\nrules:\n  - {host: a.com, ports: [70000]}\n", "out of range"},
		{"port dup", "version: 1\nrules:\n  - {host: a.com, ports: [443, 443]}\n", "listed twice"},
		{"ip host", "version: 1\nrules:\n  - {host: 10.0.0.1}\n", "IP addresses are not allowed"},
		{"missing host", "version: 1\nrules:\n  - {note: x}\n", "host is required"},
		{"source forbidden", "version: 1\nrules:\n  - {host: a.com, source: preset:x}\n", "set by cellwall"},
		{"unsafe on deny", "version: 1\nrules:\n  - {host: a.com, action: deny, unsafe_allow_http: true}\n", "only make sense on allow"},
		{"private on wildcard", "version: 1\nrules:\n  - {host: '*.a.com', unsafe_allow_private: true}\n", "exact host"},
		{"control char in note", "version: 1\nrules:\n  - {host: a.com, note: \"a\\u0007b\"}\n", "control characters"},
		{"bad limit", "version: 1\nlimits: {max_conns: -5}\n", "max_conns"},
		{"label limit unlimited", "version: 1\nlimits: {max_label_len: -1}\n", "cannot be unlimited"},
		{"label limit too big", "version: 1\nlimits: {max_label_len: 64}\n", "cannot exceed"},
	}
	for _, tt := range tests {
		p := mustParse(t, tt.src)
		err := p.Validate(false)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want error containing %q", tt.name, err, tt.want)
		}
	}
}

func TestValidateErrorPointsAtRuleLine(t *testing.T) {
	p := mustParse(t, "version: 1\nrules:\n  - host: ok.com\n  - host: 10.0.0.1\n")
	var se *SyntaxError
	if err := p.Validate(false); !errors.As(err, &se) || se.Line != 4 {
		t.Fatalf("want SyntaxError at line 4, got %v", err)
	}
}

func TestMatchBasics(t *testing.T) {
	c := mustCompile(t, `
version: 1
rules:
  - host: registry.npmjs.org
  - host: "*.pythonhosted.org"
  - host: api.example.com
    ports: [443, 8443]
  - host: web.example.com
    unsafe_allow_http: true
`)
	tests := []struct {
		host   string
		port   int
		proto  Proto
		want   bool
		reason string
	}{
		{"registry.npmjs.org", 443, ProtoTunnel, true, ReasonRule},
		{"registry.npmjs.org", 80, ProtoTunnel, false, ReasonPortNotAllow},
		{"registry.npmjs.org", 443, ProtoHTTP, false, ReasonHTTPNotAllow},
		{"evil.com", 443, ProtoTunnel, false, ReasonDefaultDeny},
		{"files.pythonhosted.org", 443, ProtoTunnel, true, ReasonRule},
		{"pythonhosted.org", 443, ProtoTunnel, false, ReasonDefaultDeny},
		{"a.b.pythonhosted.org", 443, ProtoTunnel, false, ReasonDefaultDeny},
		{"api.example.com", 8443, ProtoTunnel, true, ReasonRule},
		{"api.example.com", 22, ProtoTunnel, false, ReasonPortNotAllow},
		{"web.example.com", 80, ProtoHTTP, true, ReasonRule},
		{"web.example.com", 443, ProtoTunnel, true, ReasonRule},         // unsafe_allow_http defaults ports to 80+443
		{"web.example.com", 8080, ProtoHTTP, false, ReasonHTTPNotAllow}, // allowed host, not over plain HTTP: say "use https"
		{"registry.npmjs.org", 80, ProtoHTTP, false, ReasonHTTPNotAllow},
	}
	for _, tt := range tests {
		d := c.Match(tt.host, tt.port, tt.proto)
		if d.Allowed != tt.want || d.Reason != tt.reason {
			t.Errorf("Match(%s:%d,%v) = %+v; want allowed=%v reason=%s", tt.host, tt.port, tt.proto, d, tt.want, tt.reason)
		}
	}
}

func TestDenyBeatsAllowRegardlessOfOrder(t *testing.T) {
	for _, src := range []string{`
version: 1
rules:
  - host: "*.example.com"
  - {host: bad.example.com, action: deny}
`, `
version: 1
rules:
  - {host: bad.example.com, action: deny}
  - host: "*.example.com"
`} {
		c := mustCompile(t, src)
		if d := c.Match("bad.example.com", 443, ProtoTunnel); d.Allowed || d.Reason != ReasonExplicitDeny {
			t.Errorf("deny must win: %+v", d)
		}
		if d := c.Match("good.example.com", 443, ProtoTunnel); !d.Allowed {
			t.Errorf("sibling must stay allowed: %+v", d)
		}
	}
}

func TestDenyRulesForOtherPortsDoNotMakeAHostPortDenied(t *testing.T) {
	c := mustCompile(t, "version: 1\nrules:\n  - {host: a.example.com, action: deny, ports: [8443]}\n")
	if d := c.Match("a.example.com", 443, ProtoTunnel); d.Allowed || d.Reason != ReasonDefaultDeny {
		t.Errorf("a host with only deny rules must be default-deny, got %+v", d)
	}
}

func TestDenyWithPortsOnlyDeniesThosePorts(t *testing.T) {
	c := mustCompile(t, `
version: 1
rules:
  - {host: a.example.com, ports: [443, 8443]}
  - {host: a.example.com, action: deny, ports: [8443]}
`)
	if !c.Match("a.example.com", 443, ProtoTunnel).Allowed {
		t.Error("443 should stay allowed")
	}
	if c.Match("a.example.com", 8443, ProtoTunnel).Allowed {
		t.Error("8443 must be denied")
	}
}

func TestMultiLabelAndSingleLabelIndexing(t *testing.T) {
	c := mustCompile(t, `
version: 1
rules:
  - host: "*.single.example.com"
  - host: "**.multi.example.com"
`)
	allowed := []string{"a.single.example.com", "a.multi.example.com", "a.b.multi.example.com", "a.b.c.multi.example.com"}
	denied := []string{"single.example.com", "a.b.single.example.com", "multi.example.com", "multi.example.com.evil.com", "xmulti.example.com", "a.example.com"}
	for _, h := range allowed {
		if !c.Match(h, 443, ProtoTunnel).Allowed {
			t.Errorf("%s should be allowed", h)
		}
	}
	for _, h := range denied {
		if c.Match(h, 443, ProtoTunnel).Allowed {
			t.Errorf("%s must be denied", h)
		}
	}
}

func TestFirstAllowRuleWinsAndCarriesFlags(t *testing.T) {
	c := mustCompile(t, `
version: 1
rules:
  - {host: a.example.com, note: first}
  - {host: a.example.com, note: second, unsafe_allow_ech: true}
`)
	d := c.Match("a.example.com", 443, ProtoTunnel)
	if d.Rule == nil || d.Rule.Rule.Note != "first" || d.Rule.Rule.UnsafeAllowECH {
		t.Fatalf("first allow rule must win and its flags apply: %+v", d.Rule)
	}
}

func TestCompileRefusesDangerousWildcards(t *testing.T) {
	bad := map[string]string{
		"*.com":                   "wildcard-tld",
		"**.org":                  "wildcard-tld",
		"*.co.uk":                 "wildcard-public-suffix",
		"*.github.io":             "wildcard-user-content",
		"**.s3.amazonaws.com":     "wildcard-user-content",
		"*.myorg.github.io":       "wildcard-user-content", // under a user-content suffix
		"*.vercel.app":            "wildcard-user-content",
		"*.githubusercontent.com": "wildcard-user-content",
		"*.ngrok-free.app":        "wildcard-user-content",
	}
	for host, code := range bad {
		p := mustParse(t, "version: 1\nrules:\n  - host: '"+host+"'\n")
		_, err := Compile(p, false)
		if err == nil || !strings.Contains(err.Error(), code) {
			t.Errorf("%s: want refusal with %s, got %v", host, code, err)
		}
	}
}

func TestDangerousWildcardWaiverIsReportedAsRelaxation(t *testing.T) {
	c := mustCompile(t, "version: 1\nrules:\n  - {host: '*.github.io', unsafe_allow_dangerous_wildcard: true}\n")
	var found bool
	for _, line := range Relaxations(c.Findings) {
		if strings.Contains(line, "wildcard-user-content-waived") {
			found = true
		}
	}
	if !found {
		t.Errorf("waived wildcard must surface as a relaxation: %v", c.Findings)
	}
}

func TestExactHostsOnUserContentDomainsAreAllowed(t *testing.T) {
	// Only wildcards are dangerous here; an exact bucket/page host is a deliberate choice.
	mustCompile(t, "version: 1\nrules:\n  - host: mybucket.s3.amazonaws.com\n  - host: raw.githubusercontent.com\n")
}

func TestLintFindings(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - {host: a.example.com, unsafe_allow_private: true}
  - {host: b.example.com, unsafe_allow_http: true}
  - {host: c.example.com, unsafe_allow_ech: true}
  - {host: d.example.com, unsafe_skip_tls_check: true, ports: [22]}
  - {host: "**.deep.example.com"}
  - {host: e.example.com, ports: [8080]}
  - {host: f.example.com}
  - {host: f.example.com}
  - {host: "*.shadow.example.com"}
  - {host: "x.shadow.example.com", action: deny}
  - {host: "x.shadow.example.com"}
limits: {max_conns: -1}
`)
	exp, err := Expand(p)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Level{}
	relax := map[string]bool{}
	for _, f := range Lint(exp) {
		got[f.Code] = f.Level
		if f.Relaxation {
			relax[f.Code] = true
		}
	}
	want := map[string]Level{
		"unsafe-private": LevelWarn, "unsafe-http": LevelWarn, "unsafe-ech": LevelWarn, "unsafe-skip-tls": LevelWarn,
		"wildcard-multi-label": LevelWarn, "wildcard": LevelInfo, "nonstandard-port": LevelInfo,
		"duplicate-rule": LevelInfo, "shadowed-by-deny": LevelInfo, "unlimited-max_conns": LevelWarn,
	}
	for code, lvl := range want {
		if got[code] != lvl {
			t.Errorf("finding %s = %q, want %q (all: %v)", code, got[code], lvl, got)
		}
	}
	for _, code := range []string{"unsafe-private", "unsafe-http", "unsafe-ech", "unsafe-skip-tls", "unlimited-max_conns"} {
		if !relax[code] {
			t.Errorf("%s must be flagged as a relaxation", code)
		}
	}
}

func TestLimitsEffective(t *testing.T) {
	e := Limits{}.Effective()
	if e.MaxConns != DefaultMaxConns || e.IdleTimeout != DefaultIdleTimeout || e.MaxBytesPerConn != DefaultMaxBytesPerConn ||
		e.MaxLabelLen != 63 || e.MaxHostLen != 253 {
		t.Errorf("defaults wrong: %+v", e)
	}
	e = Limits{MaxConns: -1, IdleTimeout: Duration(-1), MaxBytesPerConn: -1, MaxNewConnsPerHostPerMin: -1}.Effective()
	if e.MaxConns != 0 || e.IdleTimeout != 0 || e.MaxBytesPerConn != 0 || e.MaxNewConnsPerHostPerMin != 0 {
		t.Errorf("-1 must translate to 0 (unlimited) for consumers: %+v", e)
	}
	e = Limits{MaxConns: 5, IdleTimeout: Duration(3 * time.Second)}.Effective()
	if e.MaxConns != 5 || e.IdleTimeout != 3*time.Second {
		t.Errorf("explicit values lost: %+v", e)
	}
}

func TestDurationParsing(t *testing.T) {
	p := mustParse(t, "version: 1\nlimits: {idle_timeout: 90s, total_timeout: unlimited}\n")
	if p.Limits.IdleTimeout != Duration(90*time.Second) || p.Limits.TotalTimeout >= 0 {
		t.Fatalf("%+v", p.Limits)
	}
	for _, bad := range []string{"0s", "-5s", "soon", "5"} {
		if _, err := Parse("p", []byte("version: 1\nlimits: {idle_timeout: "+bad+"}\n")); err == nil {
			t.Errorf("idle_timeout %q should fail", bad)
		}
	}
}

func TestMergeLayers(t *testing.T) {
	base := mustParse(t, "version: 1\npresets: [node]\nrules:\n  - {host: a.com}\nlimits: {max_conns: 10, deny_suspicious: true}\n")
	over := mustParse(t, "version: 1\npresets: [node, python]\nrules:\n  - {host: b.com}\nlimits: {max_conns: 20, idle_timeout: 5s}\n")
	m := Merge(base, nil, over)
	if got := strings.Join(m.Presets, ","); got != "node,python" {
		t.Errorf("presets = %s", got)
	}
	if len(m.Rules) != 2 || m.Rules[0].Host != "a.com" || m.Rules[1].Host != "b.com" {
		t.Errorf("rules must accumulate in layer order: %+v", m.Rules)
	}
	if m.Limits.MaxConns != 20 || m.Limits.IdleTimeout != Duration(5*time.Second) {
		t.Errorf("higher layer must override limits: %+v", m.Limits)
	}
	if !m.Limits.DenySuspicious {
		t.Error("a higher layer must not be able to turn deny_suspicious back off")
	}
}

func TestExpandIsIdempotentAndTagsSources(t *testing.T) {
	p := mustParse(t, "version: 1\npresets: [node, node]\nrules:\n  - {host: x.com}\n")
	e1, err := Expand(p)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Expand(e1)
	if err != nil {
		t.Fatal(err)
	}
	if Hash(e1) != Hash(e2) {
		t.Error("Expand must be idempotent")
	}
	var sawPreset, sawPolicy bool
	for _, r := range e1.Rules {
		sawPreset = sawPreset || r.Source == "preset:node"
		sawPolicy = sawPolicy || (r.Source == "policy" && r.Host == "x.com")
	}
	if !sawPreset || !sawPolicy {
		t.Errorf("sources not tagged: %+v", e1.Rules)
	}
}

func TestEffectivePolicyRoundTrip(t *testing.T) {
	c1 := mustCompile(t, "version: 1\npresets: [claude, github]\nrules:\n  - {host: api.example.com, ports: [443, 8443], note: mine}\nlimits: {idle_timeout: 30s, max_bytes_per_conn: -1}\n")
	b, err := Canonical(c1.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatal("canonical output is not JSON")
	}
	p2, err := Parse("effective.json", b)
	if err != nil {
		t.Fatalf("effective policy must parse back: %v\n%s", err, b)
	}
	c2, err := Compile(p2, true)
	if err != nil {
		t.Fatalf("effective policy must compile: %v", err)
	}
	if c1.Hash != c2.Hash {
		t.Errorf("hash changed across round trip: %s vs %s", c1.Hash, c2.Hash)
	}
	b2, _ := Canonical(c2.Policy)
	if string(b) != string(b2) {
		t.Error("canonical encoding is not stable")
	}
	// A user-authored file may not smuggle in a source.
	if _, err := Compile(p2, false); err == nil {
		t.Error("source fields must be rejected in non-effective policies")
	}
}

func TestHashChangesWithPolicy(t *testing.T) {
	a := mustCompile(t, "version: 1\nrules:\n  - {host: a.com}\n")
	b := mustCompile(t, "version: 1\nrules:\n  - {host: b.com}\n")
	if a.Hash == b.Hash || len(a.Hash) != 64 {
		t.Errorf("hashes: %s %s", a.Hash, b.Hash)
	}
}

func TestPresets(t *testing.T) {
	names := PresetNames()
	for _, want := range []string{"claude", "node", "python", "go", "rust", "java", "github", "docker-hub"} {
		found := false
		for _, n := range names {
			found = found || n == want
		}
		if !found {
			t.Errorf("spec requires preset %q", want)
		}
	}
	for _, name := range names {
		p, err := LoadPreset(name)
		if err != nil {
			t.Errorf("preset %s: %v", name, err)
			continue
		}
		if len(p.Rules) == 0 {
			t.Errorf("preset %s has no rules", name)
		}
		// Presets pass the wildcard linter with no errors or warnings, and are exact-host only.
		exp, _ := Expand(&Policy{Version: 1, Presets: []string{name}})
		for _, f := range Lint(exp) {
			if f.Level != LevelInfo {
				t.Errorf("preset %s: %s", name, f)
			}
		}
		for _, r := range p.Rules {
			if pat := r.Pattern(); pat.Kind != Exact {
				t.Errorf("preset %s: %s is a wildcard; presets pin specific hostnames", name, r.Host)
			}
		}
		if _, err := Compile(&Policy{Version: 1, Presets: []string{name}}, false); err != nil {
			t.Errorf("preset %s does not compile: %v", name, err)
		}
	}
}

func TestPresetCannotContainRelaxationsOrLimits(t *testing.T) {
	// Exercise the loader's guard directly with in-memory documents.
	for _, bad := range []string{
		"version: 1\nrules:\n  - {host: a.com, unsafe_allow_http: true}\n",
		"version: 1\nrules:\n  - {host: a.com, action: deny}\n",
		"version: 1\nlimits: {max_conns: 5}\nrules:\n  - {host: a.com}\n",
		"version: 1\npresets: [node]\nrules:\n  - {host: a.com}\n",
	} {
		p := mustParse(t, bad)
		if err := checkPresetShape("x", p); err == nil {
			t.Errorf("preset shape check should reject:\n%s", bad)
		}
	}
}

func TestUnknownPreset(t *testing.T) {
	_, err := Compile(&Policy{Version: 1, Presets: []string{"nope"}}, false)
	if err == nil || !strings.Contains(err.Error(), "available:") {
		t.Fatalf("want helpful error listing presets, got %v", err)
	}
	if _, err := LoadPreset("../etc/passwd"); err == nil {
		t.Fatal("path traversal in preset names must be rejected")
	}
}
