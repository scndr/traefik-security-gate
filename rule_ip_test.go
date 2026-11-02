package traefik_security_gate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// helpers ---------------------------------------------------------------------

func ipReq(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	return req
}

func ipReqWithXFF(remoteAddr, xff string) *http.Request {
	req := ipReq(remoteAddr)
	req.Header.Set("X-Forwarded-For", xff)
	return req
}

func newIPRule(t *testing.T, cfg RuleConfig) *ipAllowListRule {
	t.Helper()
	r, err := newIPAllowListRule(cfg)
	if err != nil {
		t.Fatalf("newIPAllowListRule: %v", err)
	}
	return r
}

// constructor validation ------------------------------------------------------

func TestIPAllowList_ValidationEmptySourceRange(t *testing.T) {
	if _, err := newIPAllowListRule(RuleConfig{}); err == nil {
		t.Error("empty sourceRange must be rejected")
	}
}

func TestIPAllowList_ValidationNegativeDepth(t *testing.T) {
	if _, err := newIPAllowListRule(RuleConfig{SourceRange: []string{"10.0.0.0/8"}, IPDepth: -1}); err == nil {
		t.Error("negative ipDepth must be rejected")
	}
}

func TestIPAllowList_ValidationInvalidCIDR(t *testing.T) {
	if _, err := newIPAllowListRule(RuleConfig{SourceRange: []string{"not-a-cidr"}}); err == nil {
		t.Error("invalid CIDR must be rejected")
	}
}

func TestIPAllowList_ValidationInvalidPlainIP(t *testing.T) {
	if _, err := newIPAllowListRule(RuleConfig{SourceRange: []string{"999.999.999.999"}}); err == nil {
		t.Error("invalid plain IP must be rejected")
	}
}

func TestIPAllowList_ValidationValid(t *testing.T) {
	cases := [][]string{
		{"192.168.1.0/24"},
		{"10.0.0.1"},        // plain IPv4 accepted
		{"::1"},             // plain IPv6 accepted
		{"10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32"},
	}
	for _, sr := range cases {
		if _, err := newIPAllowListRule(RuleConfig{SourceRange: sr}); err != nil {
			t.Errorf("sourceRange %v should be valid, got: %v", sr, err)
		}
	}
}

// remoteAddr (depth == 0) -----------------------------------------------------

func TestIPAllowList_RemoteAddrAllowed(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"192.168.1.0/24"}})

	if !r.check(ipReq("192.168.1.42:5000")) {
		t.Error("IP inside the allowed range must pass")
	}
}

func TestIPAllowList_RemoteAddrDenied(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"192.168.1.0/24"}})

	if r.check(ipReq("10.0.0.1:5000")) {
		t.Error("IP outside the allowed range must be denied")
	}
}

func TestIPAllowList_RemoteAddrMultipleRanges(t *testing.T) {
	r := newIPRule(t, RuleConfig{
		SourceRange: []string{"127.0.0.1/32", "192.168.1.0/24", "10.8.0.0/24", "172.18.0.0/16"},
	})

	allowed := []string{
		"127.0.0.1:1234",
		"192.168.1.100:80",
		"10.8.0.55:443",
		"172.18.5.200:8080",
	}
	for _, addr := range allowed {
		if !r.check(ipReq(addr)) {
			t.Errorf("remoteAddr %q must be allowed", addr)
		}
	}

	denied := []string{
		"192.168.2.1:80",
		"10.9.0.1:80",
		"8.8.8.8:53",
	}
	for _, addr := range denied {
		if r.check(ipReq(addr)) {
			t.Errorf("remoteAddr %q must be denied", addr)
		}
	}
}

func TestIPAllowList_PlainIPInSourceRange(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"192.168.1.5"}})

	if !r.check(ipReq("192.168.1.5:8080")) {
		t.Error("exact plain IP must be allowed")
	}
	if r.check(ipReq("192.168.1.6:8080")) {
		t.Error("different IP must be denied")
	}
}

func TestIPAllowList_RemoteAddrWithoutPort(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}})

	// RemoteAddr without port is unusual but should be handled gracefully.
	if !r.check(ipReq("10.0.0.1")) {
		t.Error("remoteAddr without port must still be matched")
	}
}

// XFF depth -------------------------------------------------------------------

func TestIPAllowList_DepthRightmost(t *testing.T) {
	// depth=1 → rightmost entry in X-Forwarded-For
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}, IPDepth: 1})

	if !r.check(ipReqWithXFF("1.2.3.4:0", "203.0.113.1, 10.0.0.5")) {
		t.Error("rightmost XFF IP in allowed range must pass")
	}
	if r.check(ipReqWithXFF("1.2.3.4:0", "10.0.0.5, 203.0.113.1")) {
		t.Error("rightmost XFF IP outside allowed range must be denied")
	}
}

func TestIPAllowList_DepthSecondFromRight(t *testing.T) {
	// depth=2 → second entry from the right
	// XFF: "clientIP, proxy1IP, proxy2IP"  →  depth=1 = proxy2IP, depth=2 = proxy1IP
	r := newIPRule(t, RuleConfig{SourceRange: []string{"192.168.1.0/24"}, IPDepth: 2})

	// proxy1 (second from right) is in range → pass
	if !r.check(ipReqWithXFF("1.2.3.4:0", "10.0.0.1, 192.168.1.50, 203.0.113.1")) {
		t.Error("second-from-right XFF IP in allowed range must pass")
	}
	// proxy1 (second from right) is NOT in range → deny
	if r.check(ipReqWithXFF("1.2.3.4:0", "192.168.1.50, 10.0.0.1, 203.0.113.1")) {
		t.Error("second-from-right XFF IP outside allowed range must be denied")
	}
}

func TestIPAllowList_DepthExceedsEntries(t *testing.T) {
	// depth greater than the number of XFF entries → should deny (empty string)
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}, IPDepth: 5})

	if r.check(ipReqWithXFF("1.2.3.4:0", "10.0.0.1, 10.0.0.2")) {
		t.Error("depth exceeding XFF entries must be denied")
	}
}

func TestIPAllowList_DepthMissingXFFHeader(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}, IPDepth: 1})

	// No X-Forwarded-For header at all.
	if r.check(ipReq("10.0.0.1:80")) {
		t.Error("missing XFF header with depth>0 must be denied")
	}
}

func TestIPAllowList_DepthIgnoresRemoteAddr(t *testing.T) {
	// When depth > 0, remoteAddr is NOT used for the check, only XFF.
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}, IPDepth: 1})

	// remoteAddr is in range, XFF rightmost is not → must deny
	if r.check(ipReqWithXFF("10.0.0.1:80", "203.0.113.99")) {
		t.Error("depth mode must use XFF, not remoteAddr")
	}
	// remoteAddr is NOT in range, XFF rightmost is → must allow
	if !r.check(ipReqWithXFF("203.0.113.99:80", "10.0.0.1")) {
		t.Error("depth mode must allow when XFF IP matches, regardless of remoteAddr")
	}
}

// postCheck -------------------------------------------------------------------

func TestIPAllowList_PostCheckIsNoop(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"10.0.0.0/8"}})
	req := ipReq("10.0.0.1:80")
	// postCheck must not panic and must not alter the request.
	r.postCheck(req)
}

// ipFromXFF unit tests --------------------------------------------------------

func TestIPFromXFF(t *testing.T) {
	cases := []struct {
		xff   string
		depth int
		want  string
	}{
		{"", 1, ""},
		{"1.2.3.4", 1, "1.2.3.4"},
		{"1.2.3.4, 5.6.7.8", 1, "5.6.7.8"},
		{"1.2.3.4, 5.6.7.8", 2, "1.2.3.4"},
		{"1.2.3.4, 5.6.7.8", 3, ""},
		{"  10.0.0.1  ,  10.0.0.2  ", 1, "10.0.0.2"}, // whitespace trimmed
	}
	for _, c := range cases {
		if got := ipFromXFF(c.xff, c.depth); got != c.want {
			t.Errorf("ipFromXFF(%q, %d) = %q, want %q", c.xff, c.depth, got, c.want)
		}
	}
}

// IPv6 ------------------------------------------------------------------------

func TestIPAllowList_IPv6(t *testing.T) {
	r := newIPRule(t, RuleConfig{SourceRange: []string{"::1/128", "fd00::/8"}})

	if !r.check(ipReq("[::1]:80")) {
		t.Error("loopback IPv6 must pass")
	}
	if !r.check(ipReq("[fd00::1]:443")) {
		t.Error("IPv6 in fd00::/8 must pass")
	}
	if r.check(ipReq("[2001:db8::1]:80")) {
		t.Error("IPv6 outside allowed ranges must be denied")
	}
}
