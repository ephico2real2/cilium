// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package issuerprofile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net/url"
	"testing"

	"github.com/cilium/cilium/pkg/time"
)

type lineageTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func lineageCA(t *testing.T, name string, parent *lineageTestCA, now time.Time, depth int, change func(*x509.Certificate)) *lineageTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: depth, MaxPathLenZero: depth == 0}
	if change != nil {
		change(tmpl)
	}
	signer, signingKey := tmpl, key
	if parent != nil {
		signer, signingKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &lineageTestCA{cert: cert, key: key, pem: canonical(cert)}
}
func lineageIssuer(signer, parent *lineageTestCA, root string) Issuer {
	return Issuer{CertificatePEM: signer.pem, ChainPEM: parent.pem, SPKISHA256: SHA(signer.cert.RawSubjectPublicKeyInfo), RootSHA256: root}
}
func lineageApproval(t *testing.T, rootDepth, parentDepth int, parentChange func(*x509.Certificate)) (Approval, []string, time.Time, *lineageTestCA, []*lineageTestCA) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	root := lineageCA(t, "organization", nil, now, rootDepth, nil)
	a := Approval{SchemaVersion: 1, Generation: 7, ExpiresAt: Stamp(now.Add(time.Hour)), Roots: []Root{{CertificatePEM: root.pem, SHA256: SHA(root.cert.Raw)}}}
	var parents []*lineageTestCA
	for _, id := range []string{"cmtc-a", "cmtc-b"} {
		parent := lineageCA(t, id+" cluster CA", root, now, parentDepth, parentChange)
		signer := lineageCA(t, id+" SPIRE CA", parent, now, 0, nil)
		parents = append(parents, parent)
		a.Clusters = append(a.Clusters, Cluster{ClusterID: id, TrustDomain: id + ".mesh.example", Issuers: []Issuer{lineageIssuer(signer, parent, a.Roots[0].SHA256)}})
	}
	return a, []string{a.Roots[0].SHA256}, now, root, parents
}
func checkLineage(t *testing.T, a Approval, pins []string, now time.Time) (*Validated, error) {
	t.Helper()
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return Validate(body, pins, "cmtc-a", now)
}
func TestApprovedSingleClusterCAAndSameClusterRotation(t *testing.T) {
	a, pins, now, _, parents := lineageApproval(t, 2, 1, nil)
	valid, err := checkLineage(t, a, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	signer2 := lineageCA(t, "a rotated SPIRE CA", parents[0], now, 0, nil)
	a.Clusters[0].Issuers = append(a.Clusters[0].Issuers, lineageIssuer(signer2, parents[0], a.Roots[0].SHA256))
	rotated, err := checkLineage(t, a, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	if valid.Digest == rotated.Digest {
		t.Fatal("new explicit signer did not change authority digest")
	}
	if rotated.Approval.Clusters[0].Issuers[0].ChainPEM != parents[0].pem {
		t.Fatal("approved exact parent was not canonicalized")
	}
}
func TestRejectUnapprovedAmbiguousAndDepthInvalidLineage(t *testing.T) {
	for _, kind := range []string{"missing-parent", "wrong-parent", "extra-root", "duplicate-parent", "root-as-parent", "shared-parent-across-clusters", "root-depth", "parent-depth", "parent-ku", "parent-extension", "parent-future", "parent-expired", "unused-parent", "parent-key-as-workload-signer", "cyclic-parent", "parent-certificate-incarnation"} {
		t.Run(kind, func(t *testing.T) {
			depthRoot, depthParent := 2, 1
			var change func(*x509.Certificate)
			switch kind {
			case "root-depth":
				depthRoot = 1
			case "parent-depth":
				depthParent = 0
			case "parent-ku":
				change = func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }
			case "parent-extension":
				change = func(c *x509.Certificate) { c.DNSNames = []string{"not-an-approved-constraint"} }
			case "parent-future":
				change = func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(2 * time.Hour) }
			case "parent-expired":
				change = func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(30 * time.Minute) }
			}
			a, pins, now, root, parents := lineageApproval(t, depthRoot, depthParent, change)
			switch kind {
			case "cyclic-parent":
				signer := lineageCA(t, "cycle SPIRE CA", parents[0], now, 0, nil)
				cyclic := reissueLineageParent(t, parents[0], signer)
				a.Clusters[0].Issuers[0] = lineageIssuer(signer, cyclic, a.Roots[0].SHA256)
			case "parent-certificate-incarnation":
				changed := reissueLineageParent(t, parents[0], root)
				signer := lineageCA(t, "rotation under changed parent certificate", changed, now, 0, nil)
				a.Clusters[0].Issuers = append(a.Clusters[0].Issuers, lineageIssuer(signer, changed, a.Roots[0].SHA256))
			case "missing-parent":
				a.Clusters[0].Issuers[0].ChainPEM = ""
			case "wrong-parent":
				a.Clusters[0].Issuers[0].ChainPEM = parents[1].pem
			case "extra-root":
				a.Clusters[0].Issuers[0].ChainPEM += root.pem
			case "duplicate-parent":
				a.Clusters[0].Issuers[0].ChainPEM += parents[0].pem
			case "root-as-parent":
				a.Clusters[0].Issuers[0].ChainPEM = root.pem
			case "shared-parent-across-clusters":
				signer := lineageCA(t, "b CA below a parent", parents[0], now, 0, nil)
				a.Clusters[1].Issuers[0] = lineageIssuer(signer, parents[0], a.Roots[0].SHA256)
			case "unused-parent":
				signer := lineageCA(t, "direct root signer", root, now, 0, nil)
				a.Clusters[0].Issuers[0] = lineageIssuer(signer, parents[0], a.Roots[0].SHA256)
			case "parent-key-as-workload-signer":
				a.Clusters[1].Issuers[0] = Issuer{CertificatePEM: parents[0].pem, SPKISHA256: SHA(parents[0].cert.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256}
			}
			if _, err := checkLineage(t, a, pins, now); err == nil {
				t.Fatal("invalid explicit hierarchy accepted")
			}
		})
	}
}
func TestClusterCAExpiryBoundsApprovalAndNewApprovedLineageRecovers(t *testing.T) {
	a, pins, now, root, _ := lineageApproval(t, 2, 1, func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(time.Hour + 5*time.Second) })
	valid, err := checkLineage(t, a, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	if !valid.Until.Equal(now.Add(5 * time.Second)) {
		t.Fatal("parent expiry did not bound approval")
	}
	if _, err = checkLineage(t, a, pins, now.Add(5*time.Second)); err == nil {
		t.Fatal("expired parent retained authority")
	}
	for i, id := range []string{"cmtc-a", "cmtc-b"} {
		parent := lineageCA(t, id+" replacement parent", root, now, 1, nil)
		signer := lineageCA(t, id+" replacement SPIRE CA", parent, now, 0, nil)
		a.Clusters[i].Issuers = []Issuer{lineageIssuer(signer, parent, a.Roots[0].SHA256)}
	}
	a.Generation++
	if _, err = checkLineage(t, a, pins, now.Add(6*time.Second)); err != nil {
		t.Fatalf("new explicitly approved hierarchy failed: %v", err)
	}
}

func TestSPIRECAHintIsOneExactApprovedTrustDomainURI(t *testing.T) {
	for _, kind := range []string{"exact", "wrong-domain", "workload-path", "duplicate-uri", "dns-and-uri", "uri-on-parent"} {
		t.Run(kind, func(t *testing.T) {
			a, pins, now, root, parents := lineageApproval(t, 2, 1, nil)
			uri, _ := url.Parse("spiffe://cmtc-a.mesh.example")
			parent := parents[0]
			if kind == "uri-on-parent" {
				parent = lineageCA(t, "parent with forbidden URI", root, now, 1, func(c *x509.Certificate) { c.URIs = []*url.URL{uri} })
			}
			signer := lineageCA(t, "SPIRE CA with trust-domain URI", parent, now, -1, func(c *x509.Certificate) {
				c.URIs = []*url.URL{uri}
				switch kind {
				case "wrong-domain":
					other, _ := url.Parse("spiffe://cmtc-b.mesh.example")
					c.URIs = []*url.URL{other}
				case "workload-path":
					other, _ := url.Parse("spiffe://cmtc-a.mesh.example/ns/orders/sa/api")
					c.URIs = []*url.URL{other}
				case "duplicate-uri":
					c.URIs = append(c.URIs, uri)
				case "dns-and-uri":
					c.DNSNames = []string{"extra.example"}
				}
			})
			a.Clusters[0].Issuers[0] = lineageIssuer(signer, parent, a.Roots[0].SHA256)
			_, err := checkLineage(t, a, pins, now)
			if kind == "exact" && err != nil {
				t.Fatal(err)
			}
			if kind != "exact" && err == nil {
				t.Fatal("unapproved SPIRE CA SAN accepted")
			}
		})
	}
}
func TestExactDomainSANRejectsExtraGeneralNameTypes(t *testing.T) {
	domain := "cmtc-a.mesh.example"
	uri, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte("spiffe://" + domain)})
	if err != nil {
		t.Fatal(err)
	}
	wrap := func(body []byte) []byte {
		t.Helper()
		b, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: body})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if !exactDomainSAN(wrap(uri), domain) {
		t.Fatal("single canonical URI rejected")
	}
	other, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x05, 0}})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{wrap(append(append([]byte{}, uri...), other...)), wrap(append(append([]byte{}, uri...), uri...)), append(wrap(uri), 0), {0x30, 0}} {
		if exactDomainSAN(bad, domain) {
			t.Fatal("extra, duplicate or malformed GeneralName accepted")
		}
	}
}

func reissueLineageParent(t *testing.T, old, parent *lineageTestCA) *lineageTestCA {
	t.Helper()
	tmpl := *old.cert
	tmpl.SerialNumber = new(big.Int).Add(old.cert.SerialNumber, big.NewInt(1))
	tmpl.AuthorityKeyId = parent.cert.SubjectKeyId
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, parent.cert, &old.key.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &lineageTestCA{cert: cert, key: old.key, pem: canonical(cert)}
}

// intermediateApproval pins each cluster's SPIRE intermediate (signsSPIRECA), as cert-manager issues it under the root.
func intermediateApproval(t *testing.T, rootDepth, intermediateDepth int) (Approval, []string, time.Time, *lineageTestCA, []*lineageTestCA) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	root := lineageCA(t, "mesh root", nil, now, rootDepth, nil)
	a := Approval{SchemaVersion: 1, Generation: 8, ExpiresAt: Stamp(now.Add(time.Hour)), Roots: []Root{{CertificatePEM: root.pem, SHA256: SHA(root.cert.Raw)}}}
	var intermediates []*lineageTestCA
	for _, id := range []string{"cmtc-a", "cmtc-b"} {
		intermediate := lineageCA(t, id+" SPIRE intermediate", root, now, intermediateDepth, nil)
		intermediates = append(intermediates, intermediate)
		a.Clusters = append(a.Clusters, Cluster{ClusterID: id, TrustDomain: id + ".mesh.example", Issuers: []Issuer{{CertificatePEM: intermediate.pem, SPKISHA256: SHA(intermediate.cert.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256, SignsSPIRECA: true}}})
	}
	return a, []string{a.Roots[0].SHA256}, now, root, intermediates
}

func TestSPIREIntermediatePinIsApprovedAndBoundsTheApproval(t *testing.T) {
	// -1 leaves the path length unset, as cert-manager does for the mesh root and the SPIRE intermediates.
	a, pins, now, _, intermediates := intermediateApproval(t, -1, -1)
	valid, err := checkLineage(t, a, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	issuer := valid.Approval.Clusters[0].Issuers[0]
	if !issuer.SignsSPIRECA || issuer.ChainPEM != "" || issuer.CertificatePEM != intermediates[0].pem {
		t.Fatalf("intermediate pin not kept as approved: %+v", issuer)
	}
	plain, _, _, _, _ := intermediateApproval(t, -1, -1)
	for i := range plain.Clusters {
		plain.Clusters[i].Issuers[0].SignsSPIRECA = false
	}
	body, err := json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("signsSPIRECA")) {
		t.Fatal("an approval without the flag must encode as before, so its digest is unchanged")
	}
}

func TestRejectSPIREIntermediatePinWithoutRoomForOneSPIRECA(t *testing.T) {
	for name, change := range map[string]func(t *testing.T) (Approval, []string, time.Time){
		"a chain as well": func(t *testing.T) (Approval, []string, time.Time) {
			a, pins, now, root, _ := intermediateApproval(t, -1, -1)
			parent := lineageCA(t, "extra parent", root, now, -1, nil)
			intermediate := lineageCA(t, "cmtc-a SPIRE intermediate", parent, now, -1, nil)
			a.Clusters[0].Issuers[0] = Issuer{CertificatePEM: intermediate.pem, ChainPEM: parent.pem, SPKISHA256: SHA(intermediate.cert.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256, SignsSPIRECA: true}
			return a, pins, now
		},
		"intermediate path length zero": func(t *testing.T) (Approval, []string, time.Time) {
			a, pins, now, _, _ := intermediateApproval(t, -1, 0)
			return a, pins, now
		},
		"root path length one": func(t *testing.T) (Approval, []string, time.Time) {
			a, pins, now, _, _ := intermediateApproval(t, 1, -1)
			return a, pins, now
		},
		"intermediate not signed by the root": func(t *testing.T) (Approval, []string, time.Time) {
			a, pins, now, _, _ := intermediateApproval(t, -1, -1)
			other := lineageCA(t, "other root", nil, now, -1, nil)
			intermediate := lineageCA(t, "cmtc-a SPIRE intermediate", other, now, -1, nil)
			a.Clusters[0].Issuers[0] = Issuer{CertificatePEM: intermediate.pem, SPKISHA256: SHA(intermediate.cert.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256, SignsSPIRECA: true}
			return a, pins, now
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, pins, now := change(t)
			if _, err := checkLineage(t, a, pins, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSPIREIntermediatePinIsProjectedForZtunnel(t *testing.T) {
	a, pins, now, _, _ := intermediateApproval(t, -1, -1)
	valid, err := checkLineage(t, a, pins, now)
	if err != nil {
		t.Fatal(err)
	}
	p := &Publication{State: "published", Reason: "Validated", Approval: &valid.Approval, PublishedAt: Stamp(now), ValidUntil: Stamp(now.Add(MaxLease))}
	body, err := project(p, Install{})
	if err != nil {
		t.Fatal(err)
	}
	var wire DERProfile
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	for _, cluster := range wire.Clusters {
		if len(cluster.Issuers) != 1 || !cluster.Issuers[0].SignsSPIRECA || len(cluster.Issuers[0].LineageDER) != 0 {
			t.Fatalf("%s: the SPIRE intermediate pin must reach ztunnel with signsSPIRECA and no lineage", cluster.ClusterID)
		}
	}
}
