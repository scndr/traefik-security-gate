package traefik_security_gate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeCRL(t *testing.T, path string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, nextUpdate time.Time, revoked ...int64) {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: nextUpdate.Add(-time.Hour),
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                nextUpdate.Add(-2 * time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reqWith(cert *x509.Certificate, verified bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	cs := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if verified {
		cs.VerifiedChains = [][]*x509.Certificate{{cert}}
	}
	r.TLS = cs
	return r
}

func newRule(path string, failOpen bool) *mtlsRule {
	r, err := newMTLSRule("test", RuleConfig{Type: "mtls", CRLFilePath: path, InsecureFailOpen: failOpen})
	if err != nil {
		panic(err)
	}
	return r
}

func TestMTLSRequiresVerifiedChain(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	r := newRule("", false)

	if r.check(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("no TLS must fail")
	}
	if r.check(reqWith(leaf, false)) {
		t.Error("presented-but-unverified certificate must fail")
	}
	if !r.check(reqWith(leaf, true)) {
		t.Error("verified certificate must pass")
	}
}

func TestMTLSInsecureAllowUnverified(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	revoked := newLeaf(t, ca, caKey, 11)
	path := filepath.Join(t.TempDir(), "crl.pem")
	writeCRL(t, path, ca, caKey, time.Now().Add(time.Hour), 11)

	r, err := newMTLSRule("test", RuleConfig{Type: "mtls", CRLFilePath: path, InsecureAllowUnverifiedClientCert: true})
	if err != nil {
		t.Fatal(err)
	}

	if r.check(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Error("no TLS must still fail")
	}
	if !r.check(reqWith(leaf, false)) {
		t.Error("unverified certificate must pass when the insecure flag is set")
	}
	if !r.check(reqWith(leaf, true)) {
		t.Error("verified certificate must pass")
	}
	if r.check(reqWith(revoked, false)) {
		t.Error("CRL must still apply to unverified certificates")
	}
}

func TestMTLSRevoked(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	good := newLeaf(t, ca, caKey, 10)
	bad := newLeaf(t, ca, caKey, 11)
	path := filepath.Join(t.TempDir(), "crl.pem")
	writeCRL(t, path, ca, caKey, time.Now().Add(time.Hour), 11)

	r := newRule(path, false)
	if !r.check(reqWith(good, true)) {
		t.Error("non-revoked certificate must pass")
	}
	if r.check(reqWith(bad, true)) {
		t.Error("revoked certificate must fail")
	}
}

func TestMTLSSameSerialDifferentIssuer(t *testing.T) {
	ca1, key1 := newCA(t, "ca1")
	ca2, key2 := newCA(t, "ca2")
	revokedInCA1 := newLeaf(t, ca1, key1, 42)
	sameSerialCA2 := newLeaf(t, ca2, key2, 42)
	path := filepath.Join(t.TempDir(), "crl.pem")
	writeCRL(t, path, ca1, key1, time.Now().Add(time.Hour), 42)

	r := newRule(path, false)
	if r.check(reqWith(revokedInCA1, true)) {
		t.Error("cert revoked by CA1 must fail")
	}
	if !r.check(reqWith(sameSerialCA2, true)) {
		t.Error("same serial from another CA must not collide")
	}
}

func TestMTLSCRLMissingPolicy(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	missing := filepath.Join(t.TempDir(), "nope.pem")

	if newRule(missing, false).check(reqWith(leaf, true)) {
		t.Error("fail-closed (default) must reject when CRL is missing")
	}
	if !newRule(missing, true).check(reqWith(leaf, true)) {
		t.Error("fail-open must accept when CRL is missing")
	}
}


func TestMTLSLazyReload(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	leaf := newLeaf(t, ca, caKey, 10)
	path := filepath.Join(t.TempDir(), "crl.pem")
	writeCRL(t, path, ca, caKey, time.Now().Add(time.Hour))

	r := newRule(path, false)
	r.interval = 0 // check the file on every request
	if !r.check(reqWith(leaf, true)) {
		t.Fatal("certificate must pass before revocation")
	}

	writeCRL(t, path, ca, caKey, time.Now().Add(time.Hour), 10)
	future := time.Now().Add(5 * time.Second) // avoid mtime granularity issues
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if r.check(reqWith(leaf, true)) {
		t.Error("certificate must be rejected after the CRL is updated")
	}
}

func TestMTLSKeepsOldSnapshotOnBadReload(t *testing.T) {
	ca, caKey := newCA(t, "ca")
	bad := newLeaf(t, ca, caKey, 11)
	path := filepath.Join(t.TempDir(), "crl.pem")
	writeCRL(t, path, ca, caKey, time.Now().Add(time.Hour), 11)

	r := newRule(path, true)
	r.interval = 0

	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(5 * time.Second)
	_ = os.Chtimes(path, future, future)

	if r.check(reqWith(bad, true)) {
		t.Error("a corrupted CRL file must not wipe the last good snapshot")
	}
}

func TestMTLSNegativeReloadInterval(t *testing.T) {
	if _, err := newMTLSRule("test", RuleConfig{Type: "mtls", CRLReloadInterval: -1}); err == nil {
		t.Error("negative crlReloadInterval must be rejected")
	}
}
