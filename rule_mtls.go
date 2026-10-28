package traefik_security_gate

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const defaultCRLReloadInterval = 60 // seconds

type mtlsRule struct {
	lastCheck int64
	degraded  int32

	name            string // plugin name, for logging
	crlFilePath     string
	failOpen        bool // insecureFailOpen
	allowUnverified bool // insecureAllowUnverifiedClientCert
	interval        time.Duration
	snapshot        atomic.Value // *crlSnapshot
}

type revocationKey struct {
	issuer string
	serial string
}

type crlSnapshot struct {
	revoked map[revocationKey]struct{}
	modTime time.Time
}

func newMTLSRule(pluginName string, cfg RuleConfig) (*mtlsRule, error) {
	if cfg.CRLReloadInterval < 0 {
		return nil, errors.New("crlReloadInterval must not be negative")
	}
	interval := cfg.CRLReloadInterval
	if interval == 0 {
		interval = defaultCRLReloadInterval
	}

	r := &mtlsRule{
		name:            pluginName,
		crlFilePath:     cfg.CRLFilePath,
		failOpen:        cfg.InsecureFailOpen,
		allowUnverified: cfg.InsecureAllowUnverifiedClientCert,
		interval:        time.Duration(interval) * time.Second,
	}

	if r.allowUnverified {
		log.Printf("securitygate[%s]: WARNING insecureAllowUnverifiedClientCert is enabled — "+
			"unverified client certificates are accepted", pluginName)
	}
	if r.failOpen && r.crlFilePath != "" {
		log.Printf("securitygate[%s]: WARNING insecureFailOpen is enabled — "+
			"certificates are accepted when the CRL is missing or unreadable", pluginName)
	}

	if r.crlFilePath != "" {
		r.reloadIfChanged()
		atomic.StoreInt64(&r.lastCheck, time.Now().UnixNano())
	}

	return r, nil
}

func (r *mtlsRule) check(req *http.Request) bool {
	cert := r.clientCert(req)
	if cert == nil {
		return false
	}
	return r.isCertAllowed(cert)
}

func (*mtlsRule) postCheck(*http.Request) {}

func (r *mtlsRule) clientCert(req *http.Request) *x509.Certificate {
	if req.TLS == nil {
		log.Printf("securitygate[%s]: %s — %s", r.name, "TLS connection state is nil", "rejecting")
		return nil
	}
	if len(req.TLS.VerifiedChains) > 0 && len(req.TLS.VerifiedChains[0]) > 0 {
		return req.TLS.VerifiedChains[0][0]
	}
	if r.allowUnverified && len(req.TLS.PeerCertificates) > 0 {
		return req.TLS.PeerCertificates[0]
	}

	log.Printf("securitygate[%s]: %s — %s", r.name, "KO", "rejecting")
	return nil
}

func (r *mtlsRule) isCertAllowed(cert *x509.Certificate) bool {
	if r.crlFilePath == "" {
		return true
	}

	r.maybeReload()

	snap := r.current()

	if snap != nil {
		key := revocationKey{issuer: string(cert.RawIssuer), serial: cert.SerialNumber.String()}
		if _, revoked := snap.revoked[key]; revoked {
			log.Printf("securitygate[%s]: blocked revoked certificate CN=%q serial=%s",
				r.name, cert.Subject.CommonName, key.serial)
			return false
		}
	} else {
		r.setDegraded(true, "CRL unavailable")
		return r.failOpen
	}
	r.setDegraded(false, "")
	return true
}

func (r *mtlsRule) setDegraded(on bool, reason string) {
	var want int32
	if on {
		want = 1
	}
	if atomic.SwapInt32(&r.degraded, want) == want {
		return
	}
	if !on {
		log.Printf("securitygate[%s]: CRL healthy again", r.name)
		return
	}
	policy := "fail-closed, rejecting"
	if r.failOpen {
		policy = "fail-open, forwarding"
	}
	log.Printf("securitygate[%s]: %s — %s", r.name, reason, policy)
}

func (r *mtlsRule) current() *crlSnapshot {
	snap, _ := r.snapshot.Load().(*crlSnapshot)
	return snap
}

func (r *mtlsRule) maybeReload() {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&r.lastCheck)
	if now-last < int64(r.interval) {
		return
	}
	if !atomic.CompareAndSwapInt64(&r.lastCheck, last, now) {
		return
	}
	r.reloadIfChanged()
}

func (r *mtlsRule) reloadIfChanged() {
	info, err := os.Stat(r.crlFilePath)
	if err != nil {
		log.Printf("securitygate[%s]: cannot stat CRL %q: %v", r.name, r.crlFilePath, err)
		return
	}

	if snap := r.current(); snap != nil && info.ModTime().Equal(snap.modTime) {
		return
	}

	data, err := os.ReadFile(r.crlFilePath)
	if err != nil {
		log.Printf("securitygate[%s]: cannot read CRL %q: %v", r.name, r.crlFilePath, err)
		return
	}

	parsed, err := parseCRL(data)
	if err != nil {
		log.Printf("securitygate[%s]: cannot parse CRL %q: %v", r.name, r.crlFilePath, err)
		return
	}

	issuer := string(parsed.RawIssuer)
	revoked := make(map[revocationKey]struct{}, len(parsed.RevokedCertificateEntries))
	for _, rc := range parsed.RevokedCertificateEntries {
		revoked[revocationKey{issuer: issuer, serial: rc.SerialNumber.String()}] = struct{}{}
	}

	r.snapshot.Store(&crlSnapshot{
		revoked: revoked,
		modTime: info.ModTime(),
	})
	log.Printf("securitygate[%s]: CRL loaded — %d revoked serial(s)", r.name, len(revoked))
}

func parseCRL(data []byte) (*x509.RevocationList, error) {
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("unexpected PEM block type %q (want \"X509 CRL\")", block.Type)
		}
		return x509.ParseRevocationList(block.Bytes)
	}
	return x509.ParseRevocationList(data)
}
