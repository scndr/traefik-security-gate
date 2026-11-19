package traefik_security_gate

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// ipAllowListRule passes a request only when the client IP belongs to at least
// one of the configured CIDR ranges or exact IP addresses.
//
// IP extraction:
//   - ipDepth == 0 (default): uses req.RemoteAddr (direct TCP peer).
//   - ipDepth  > 0:           uses X-Forwarded-For, skipping the last (depth-1)
//     entries from the right. depth=1 → rightmost entry, depth=2 → second-from-right, etc.
//     Mirrors the behaviour of the built-in Traefik ipAllowList ipStrategy.depth.
type ipAllowListRule struct {
	allowed []*net.IPNet
	depth   int // 0 = remoteAddr, >0 = X-Forwarded-For depth
}

func newIPAllowListRule(cfg RuleConfig) (*ipAllowListRule, error) {
	if len(cfg.SourceRange) == 0 {
		return nil, errors.New("sourceRange must contain at least one IP or CIDR")
	}

	if cfg.IPDepth < 0 {
		return nil, errors.New("ipDepth must be >= 0")
	}

	allowed := make([]*net.IPNet, 0, len(cfg.SourceRange))
	for _, raw := range cfg.SourceRange {
		raw = strings.TrimSpace(raw)

		// Accept plain IPs (e.g. "192.168.1.5") by converting them to host CIDRs.
		if !strings.Contains(raw, "/") {
			parsed := net.ParseIP(raw)
			if parsed == nil {
				return nil, fmt.Errorf("invalid IP address %q", raw)
			}
			bits := 32
			if parsed.To4() == nil {
				bits = 128
			}
			raw = fmt.Sprintf("%s/%d", parsed.String(), bits)
		}

		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		allowed = append(allowed, cidr)
	}

	return &ipAllowListRule{allowed: allowed, depth: cfg.IPDepth}, nil
}

func (r *ipAllowListRule) check(req *http.Request) bool {
	raw := r.extractIP(req)
	if raw == "" {
		log.Printf("securitygate: %s — %s", "KO IPALLOWLIST", "raw empty")
		return false
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		log.Printf("securitygate: %s — %s", "KO IPALLOWLIST", "ip nil")
		return false
	}
	for _, cidr := range r.allowed {
		if cidr.Contains(ip) {
			return true
		}
	}
	log.Printf("securitygate: %s — %s : %s", "KO IPALLOWLIST", ip, "ip not valid")
	return false
}

func (*ipAllowListRule) postCheck(*http.Request) {}

// extractIP returns the raw IP string (no port) according to the configured depth.
func (r *ipAllowListRule) extractIP(req *http.Request) string {
	if r.depth == 0 {
		host, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			return req.RemoteAddr // no port present, use as-is
		}
		return host
	}
	return ipFromXFF(req.Header.Get("X-Forwarded-For"), r.depth)
}

// ipFromXFF extracts the Nth IP from the right of an X-Forwarded-For header.
// depth=1 → rightmost entry, depth=2 → second-from-right, etc.
// Returns "" when the header is absent or depth exceeds the number of entries.
func ipFromXFF(xff string, depth int) string {
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	idx := len(parts) - depth
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(parts[idx])
}
