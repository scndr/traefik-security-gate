package securitygate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHeader_HeaderRule(t *testing.T) {
	r := &headerRule{name: "X-Key", value: "secret"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if r.check(req) {
		t.Error("missing header must fail")
	}
	req.Header.Set("X-Key", "wrong")
	if r.check(req) {
		t.Error("wrong header must fail")
	}
	req.Header.Set("X-Key", "secret")
	if !r.check(req) {
		t.Error("correct header must pass")
	}
}

func TestHeader_RuleValidation(t *testing.T) {
	if _, err := newHeaderRule(RuleConfig{HeaderValue: "v"}); err == nil {
		t.Error("missing headerName must be rejected")
	}
	if _, err := newHeaderRule(RuleConfig{HeaderName: "X"}); err == nil {
		t.Error("missing headerValue must be rejected")
	}
	if _, err := newHeaderRule(RuleConfig{HeaderName: "X", HeaderValue: "v"}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestHeader_ForwardHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Key", "secret")

	(&headerRule{name: "X-Key", value: "secret", forward: true}).postCheck(req)
	if req.Header.Get("X-Key") == "" {
		t.Error("forward=true must keep the header")
	}

	(&headerRule{name: "X-Key", value: "secret"}).postCheck(req)
	if req.Header.Get("X-Key") != "" {
		t.Error("forward=false must remove the header")
	}
}
