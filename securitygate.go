// Package securitygate is a Traefik middleware plugin that enforces access
// based on a configurable list of rules evaluated with anyOf or allOf logic.
//
// Supported rule types:
//   - mtls:   passes if the request carries a TLS client certificate that was
//     VERIFIED by the TLS layer (VerifiedChains), optionally checked
//     against a CRL. Secure by default; two explicit "insecure*"
//     flags relax the behavior (see RuleConfig).
//   - header: passes if a specific HTTP header matches the expected value
//
// mode: anyOf (default) — at least one rule must pass
// mode: allOf           — every rule must pass
//
// NOTE: the mtls rule relies on Traefik verifying the client certificate
// against your CA. Configure the TLS option with clientAuth.caFiles and
// clientAuthType = VerifyClientCertIfGiven or RequireAndVerifyClientCert.
// With any other value VerifiedChains is empty and the rule always fails
// (safe by design) unless insecureAllowUnverifiedClientCert is set.
package traefik_security_gate

import (
	"context"
	"fmt"
	"net/http"
)

type Config struct {
	Mode  string       `json:"mode,omitempty"`
	Rules []RuleConfig `json:"rules,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Mode: "anyOf",
	}
}

type SecurityGate struct {
	next  http.Handler
	anyOf bool // true = anyOf, false = allOf
	rules []rule
}

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Rules) == 0 {
		return nil, fmt.Errorf("securitygate[%s]: at least one rule is required", name)
	}

	var anyOf bool
	switch config.Mode {
	case "", "anyOf":
		anyOf = true
	case "allOf":
		anyOf = false
	default:
		return nil, fmt.Errorf("securitygate[%s]: unknown mode %q (want \"anyOf\" or \"allOf\")", name, config.Mode)
	}

	rules, err := compileRules(config.Rules, name)
	if err != nil {
		return nil, err
	}

	return &SecurityGate{next: next, anyOf: anyOf, rules: rules}, nil
}

func (sg *SecurityGate) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if sg.evaluate(req) {
		for _, r := range sg.rules {
			r.postCheck(req)
		}
		sg.next.ServeHTTP(rw, req)
		return
	}
	http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

func (sg *SecurityGate) evaluate(req *http.Request) bool {
	for _, r := range sg.rules {
		passed := r.check(req)
		if sg.anyOf && passed {
			return true // short-circuit: one is enough
		}
		if !sg.anyOf && !passed {
			return false // short-circuit: one failure is enough
		}
	}
	return !sg.anyOf
}
