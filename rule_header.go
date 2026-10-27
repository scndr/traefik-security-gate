package securitygate

import (
	"errors"
	"net/http"
)

type headerRule struct {
	name    string
	value   string
	forward bool
}

func newHeaderRule(cfg RuleConfig) (*headerRule, error) {
	if cfg.HeaderName == "" {
		return nil, errors.New("headerName is required")
	}
	if cfg.HeaderValue == "" {
		return nil, errors.New("headerValue is required")
	}
	return &headerRule{name: cfg.HeaderName, value: cfg.HeaderValue, forward: cfg.ForwardHeader}, nil
}

func (r *headerRule) check(req *http.Request) bool {
	return req.Header.Get(r.name) == r.value
}

func (r *headerRule) postCheck(req *http.Request) {
	if !r.forward {
		req.Header.Del(r.name)
	}
}
