package traefik_security_gate

import (
	"fmt"
	"net/http"
)

type RuleType string

const (
	RuleTypeHeader      RuleType = "header"
	RuleTypeMTLS        RuleType = "mtls"
	RuleTypeIPAllowList RuleType = "ipAllowList"
)

type rule interface {
	check(req *http.Request) bool
	postCheck(req *http.Request)
}

type RuleConfig struct {
	Type RuleType `json:"type"`

	// --- header rule fields ---
	HeaderName  string `json:"headerName,omitempty"`
	HeaderValue string `json:"headerValue,omitempty"`

	// ForwardHeader: by default (false) the header is removed from the
	// request once it is allowed, so the shared secret never reaches the
	// backend (and its logs). Set to true to forward it unchanged.
	ForwardHeader bool `json:"forwardHeader,omitempty"`

	// --- mtls rule fields ---
	CRLFilePath       string `json:"crlFilePath,omitempty"`
	CRLReloadInterval int    `json:"crlReloadInterval,omitempty"` // seconds

	// InsecureAllowUnverifiedClientCert: by default (false) only certificates with a verified chain (req.TLS.VerifiedChains) are accepted. If true,
	// when no verified chain is present the first presented certificate
	// (req.TLS.PeerCertificates[0]) is used instead. That certificate has NOT
	// been validated by anyone: a client can present any self-signed
	// certificate. INSECURE: only use it if trust is established elsewhere.
	InsecureAllowUnverifiedClientCert bool `json:"insecureAllowUnverifiedClientCert,omitempty"`

	// InsecureFailOpen: by default (false) the rule is fail-close.
	// If the CRL is missing, unparsable or expired, every certificate is rejected.
	// If true, certificates are accepted in that situation
	InsecureFailOpen bool `json:"insecureFailOpen,omitempty"`

	// --- ipAllowList rule fields ---

	// SourceRange is the list of allowed IP addresses or CIDR ranges (e.g. "10.0.0.0/8", "192.168.1.5").
	SourceRange []string `json:"sourceRange,omitempty"`

	// IPDepth: when > 0, the client IP is taken from X-Forwarded-For by skipping
	// the last N-1 entries from the right (depth=1 → rightmost, depth=2 → second-from-right, etc.).
	// When 0 (default), req.RemoteAddr is used directly.
	IPDepth int `json:"ipDepth,omitempty"`
}

func compileRules(cfgs []RuleConfig, pluginName string) ([]rule, error) {
	rules := make([]rule, 0, len(cfgs))
	for i, cfg := range cfgs {
		var err error

		switch cfg.Type {
		case RuleTypeHeader:
			var r *headerRule
			if r, err = newHeaderRule(cfg); err == nil {
				rules = append(rules, r)
			}

		case RuleTypeMTLS:
			var r *mtlsRule
			if r, err = newMTLSRule(pluginName, cfg); err == nil {
				rules = append(rules, r)
			}

		case RuleTypeIPAllowList:
			var r *ipAllowListRule
			if r, err = newIPAllowListRule(cfg); err == nil {
				rules = append(rules, r)
			}

		default:
			err = fmt.Errorf("unknown type %q (want %q, %q or %q)", cfg.Type, RuleTypeHeader, RuleTypeMTLS, RuleTypeIPAllowList)
		}

		if err != nil {
			return nil, fmt.Errorf("securitygate[%s]: rule[%d] %s: %w", pluginName, i, cfg.Type, err)
		}
	}
	return rules, nil
}
