package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/middle-systems/kennel/internal/policy"
)

// Reasons used in audit records and X-Kennel-Reason, beyond the policy package's own.
const (
	ReasonBadTarget        = "bad-target"
	ReasonIPLiteral        = "ip-literal"
	ReasonBlockedAddress   = "blocked-address"
	ReasonRateLimited      = "rate-limited"
	ReasonAtCapacity       = "at-capacity"
	ReasonSuspicious       = "suspicious-hostname"
	ReasonNoSNI            = "no-sni"
	ReasonSNIMismatch      = "sni-mismatch"
	ReasonECH              = "ech"
	ReasonUpgrade          = "upgrade-not-supported"
	ReasonNotProxy         = "not-a-proxy-request"
	ReasonBadScheme        = "unsupported-scheme"
	ReasonAuditUnavailable = "audit-unavailable"
	ReasonResolveFailed    = "resolve-failed"
	ReasonDialFailed       = "dial-failed"
	ReasonHandshakeTimeout = "handshake-timeout"
)

// denyResponse is a client-visible refusal. Messages name the host and the next command to run,
// because the agent (and the human reading its output) only sees this text.
type denyResponse struct {
	Status int
	Reason string
	Body   string
}

func hostHint(host string) string {
	if host == "" || strings.ContainsAny(host, "?") {
		return "<host>"
	}
	return host
}

func messageFor(host string, port int, reason, detail string) denyResponse {
	target := hostPort(printable(host), port)
	allow := "kennel allow " + hostHint(printable(host))
	var status int
	var why string
	switch reason {
	case policy.ReasonDefaultDeny:
		status, why = http.StatusForbidden, fmt.Sprintf("%s is not in the allowlist.\nTo allow it for this session: %s\nTo keep it in the project policy: %s --save", target, allow, allow)
	case policy.ReasonPortNotAllow:
		status, why = http.StatusForbidden, fmt.Sprintf("the host is allowed, but not on port %d.\nTo allow it: %s --port %d", port, allow, port)
	case policy.ReasonHTTPNotAllow:
		status, why = http.StatusForbidden, "plain HTTP is not allowed for this host. Use https:// instead."
	case policy.ReasonExplicitDeny:
		status, why = http.StatusForbidden, fmt.Sprintf("%s is explicitly denied by policy (%s).\nEdit .kennel/policy.yaml to change this.", target, detail)
	case ReasonIPLiteral:
		status, why = http.StatusForbidden, "IP addresses are not allowed as destinations. Use the hostname."
	case ReasonBlockedAddress:
		status, why = http.StatusForbidden, fmt.Sprintf("%s resolved to a non-public address (%s). The gateway never connects to private, loopback, link-local or metadata addresses.", target, detail)
	case ReasonSuspicious:
		status, why = http.StatusForbidden, "the hostname looks like encoded data (deny_suspicious is on)."
	case ReasonBadTarget:
		status, why = http.StatusBadRequest, "the request target is malformed: "+detail
	case ReasonRateLimited:
		status, why = http.StatusTooManyRequests, fmt.Sprintf("too many new connections to %s per minute (limits.max_new_conns_per_host_per_min). Retry shortly.", printable(host))
	case ReasonAtCapacity:
		status, why = http.StatusServiceUnavailable, "the gateway is at its connection limit (limits.max_conns). Retry shortly."
	case ReasonAuditUnavailable:
		status, why = http.StatusServiceUnavailable, "the gateway cannot write its audit log, so it is refusing new connections."
	case ReasonUpgrade:
		status, why = http.StatusForbidden, "protocol upgrades (WebSocket etc.) are not supported over plain HTTP; use https://."
	case ReasonBadScheme:
		status, why = http.StatusBadRequest, "only http:// URLs are accepted in plain proxy requests; use CONNECT for HTTPS."
	case ReasonNotProxy:
		status, why = http.StatusBadRequest, "this is a proxy. Configure HTTPS_PROXY / HTTP_PROXY to point here instead of requesting it directly."
	case ReasonResolveFailed:
		status, why = http.StatusBadGateway, fmt.Sprintf("could not resolve %s.", printable(host))
	case ReasonDialFailed:
		status, why = http.StatusBadGateway, fmt.Sprintf("could not connect to %s.", target)
	default:
		status, why = http.StatusForbidden, fmt.Sprintf("request to %s refused (%s).", target, reason)
	}
	return denyResponse{Status: status, Reason: reason, Body: "kennel: " + why + "\n"}
}
