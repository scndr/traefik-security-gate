package traefik_security_gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubRule struct{ pass bool }

func (s stubRule) check(_ *http.Request) bool { return s.pass }

func (stubRule) postCheck(_ *http.Request) {}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name  string
		anyOf bool
		rules []rule
		want  bool
	}{
		{"anyOf one pass", true, []rule{stubRule{pass: false}, stubRule{pass: true}}, true},
		{"anyOf none pass", true, []rule{stubRule{pass: false}, stubRule{pass: false}}, false},
		{"allOf all pass", false, []rule{stubRule{pass: true}, stubRule{pass: true}}, true},
		{"allOf one fails", false, []rule{stubRule{pass: true}, stubRule{pass: false}}, false},
	}
	for _, c := range cases {
		sg := &SecurityGate{anyOf: c.anyOf, rules: c.rules}
		if got := sg.evaluate(httptest.NewRequest(http.MethodGet, "/", nil)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNewValidation(t *testing.T) {
	next := http.NotFoundHandler()
	bad := []*Config{
		{},
		{Mode: "bogus", Rules: []RuleConfig{{Type: "header", HeaderName: "X", HeaderValue: "y"}}},
		{Rules: []RuleConfig{{Type: "header", HeaderName: "X"}}},
		{Rules: []RuleConfig{{Type: "nope"}}},
	}
	for i, cfg := range bad {
		if _, err := New(nil, next, cfg, "t"); err == nil { //nolint:staticcheck
			t.Errorf("case %d: expected error", i)
		}
	}
}

// ----- end-to-end: ServeHTTP -------------------------------------------------

// probe is a backend that records whether it was reached and what it saw.
type probe struct {
	called bool
	header http.Header
}

func (p *probe) ServeHTTP(_ http.ResponseWriter, req *http.Request) {
	p.called = true
	p.header = req.Header.Clone()
}

func serve(t *testing.T, cfg *Config, req *http.Request) (*httptest.ResponseRecorder, *probe) {
	t.Helper()
	p := &probe{}
	h, err := New(context.Background(), p, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, p
}

func headerReq(value string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	if value != "" {
		req.Header.Set("X-Key", value)
	}
	return req
}

func headerRuleCfg(forward bool) RuleConfig {
	return RuleConfig{Type: "header", HeaderName: "X-Key", HeaderValue: "secret", ForwardHeader: forward}
}

func TestServeHTTPHeaderAllowedStripsSecret(t *testing.T) {
	rec, p := serve(t, &Config{Rules: []RuleConfig{headerRuleCfg(false)}}, headerReq("secret"))
	if rec.Code != http.StatusOK || !p.called {
		t.Fatalf("expected request to be forwarded, code=%d called=%v", rec.Code, p.called)
	}
	if got := p.header.Get("X-Key"); got != "" {
		t.Errorf("secret header must be stripped, backend saw %q", got)
	}
}

func TestServeHTTPHeaderForwardHeader(t *testing.T) {
	_, p := serve(t, &Config{Rules: []RuleConfig{headerRuleCfg(true)}}, headerReq("secret"))
	if !p.called {
		t.Fatal("request must be forwarded")
	}
	if got := p.header.Get("X-Key"); got != "secret" {
		t.Errorf("forwardHeader=true must keep the header, backend saw %q", got)
	}
}

func TestServeHTTPDenied(t *testing.T) {
	for _, value := range []string{"", "wrong"} {
		rec, p := serve(t, &Config{Rules: []RuleConfig{headerRuleCfg(false)}}, headerReq(value))
		if rec.Code != http.StatusForbidden {
			t.Errorf("value %q: code = %d, want 403", value, rec.Code)
		}
		if p.called {
			t.Errorf("value %q: backend must not be reached", value)
		}
		if body := rec.Body.String(); body != "Forbidden\n" {
			t.Errorf("value %q: body = %q, want uniform 403 body", value, body)
		}
	}
}

func TestServeHTTPAnyOfMTLSPassStillStripsHeader(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	cfg := &Config{Mode: "anyOf", Rules: []RuleConfig{{Type: "mtls"}, headerRuleCfg(false)}}

	req := reqWith(leaf, true)
	req.Header.Set("X-Key", "whatever-the-client-sent")
	rec, p := serve(t, cfg, req)

	if rec.Code != http.StatusOK || !p.called {
		t.Fatalf("verified cert must pass, code=%d called=%v", rec.Code, p.called)
	}
	if got := p.header.Get("X-Key"); got != "" {
		t.Errorf("header must be stripped even when mTLS let the request through, saw %q", got)
	}
}

func TestServeHTTPAllOf(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	cfg := &Config{Mode: "allOf", Rules: []RuleConfig{{Type: "mtls"}, headerRuleCfg(false)}}

	// cert ok, header missing -> denied
	if rec, p := serve(t, cfg, reqWith(leaf, true)); rec.Code != http.StatusForbidden || p.called {
		t.Errorf("allOf with missing header: code=%d called=%v", rec.Code, p.called)
	}

	// header ok, no verified cert -> denied
	req := reqWith(leaf, false)
	req.Header.Set("X-Key", "secret")
	if rec, p := serve(t, cfg, req); rec.Code != http.StatusForbidden || p.called {
		t.Errorf("allOf with unverified cert: code=%d called=%v", rec.Code, p.called)
	}

	// both ok -> forwarded, secret stripped
	req = reqWith(leaf, true)
	req.Header.Set("X-Key", "secret")
	rec, p := serve(t, cfg, req)
	if rec.Code != http.StatusOK || !p.called {
		t.Fatalf("allOf with both rules ok: code=%d called=%v", rec.Code, p.called)
	}
	if got := p.header.Get("X-Key"); got != "" {
		t.Errorf("secret must be stripped, saw %q", got)
	}
}
