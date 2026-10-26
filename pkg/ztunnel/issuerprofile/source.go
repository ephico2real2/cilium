// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Port of CMTC internal/trustprofile/profile.go at 7e606195f58359b0e0af82f219cafd5291268c67,
// with the CMTC approval source-succession contract of VerifyCurrent (2026-10-26).
// Package issuerprofile validates explicitly administered PUBLIC issuer mappings.
// It does not issue keys, attest endpoints, deliver xDS, or grant traffic.
package issuerprofile

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// MaxBytes bounds administrator-supplied approval JSON and its canonical form.
const MaxBytes = 64 * 1024

// MaxPublicationBytes bounds the larger envelope stored in a ConfigMap. Keep
// this far below Kubernetes' 1 MiB ConfigMap object limit.
const MaxPublicationBytes = 256 * 1024
const MaxJSONDepth = 12
const SchemaVersion = 1
const MaxLease = 30 * time.Second
const RenewBefore = 15 * time.Second
const DataKey = "profile.json"
const ApprovalKey = "approval.json"
const OutputLabel = "security.cmtc.io/issuer-profile-output"
const InitializedAnnotation = "security.cmtc.io/issuer-profile-initialized"

type Root struct {
	CertificatePEM string `json:"certificatePEM"`
	SHA256         string `json:"sha256"`
}
type Issuer struct {
	CertificatePEM string `json:"certificatePEM"`
	ChainPEM       string `json:"chainPEM,omitempty"`
	SPKISHA256     string `json:"spkiSHA256"`
	RootSHA256     string `json:"rootSHA256"`
}
type Cluster struct {
	ClusterID   string   `json:"clusterID"`
	TrustDomain string   `json:"trustDomain"`
	Issuers     []Issuer `json:"issuers"`
}
type Approval struct {
	SchemaVersion int       `json:"schemaVersion"`
	Generation    uint64    `json:"generation"`
	ExpiresAt     string    `json:"expiresAt"`
	Roots         []Root    `json:"roots"`
	Clusters      []Cluster `json:"clusters"`
}
type Source struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resourceVersion"`
	Generation      uint64 `json:"generation"`
}
type Publication struct {
	SchemaVersion          int       `json:"schemaVersion"`
	Sequence               uint64    `json:"sequence"`
	State                  string    `json:"state"`
	Reason                 string    `json:"reason"`
	ProducerCluster        string    `json:"producerCluster"`
	OutputUID              string    `json:"outputUID"`
	ExpectedSourceUID      string    `json:"expectedSourceUID"`
	Source                 Source    `json:"source"`
	AcceptedGeneration     uint64    `json:"acceptedGeneration"`
	AcceptedSourceUID      string    `json:"acceptedSourceUID,omitempty"`
	AcceptedApprovalDigest string    `json:"acceptedApprovalDigest,omitempty"`
	ApprovalDigest         string    `json:"approvalDigest,omitempty"`
	Approval               *Approval `json:"approval,omitempty"`
	PublishedAt            string    `json:"publishedAt"`
	ValidUntil             string    `json:"validUntil"`
	Digest                 string    `json:"digest,omitempty"`
}
type Validated struct {
	Approval Approval
	Digest   string
	Until    time.Time
}
type ValidationError struct {
	Reason string
	Err    error
}

func (e *ValidationError) Error() string     { return e.Reason + ": " + e.Err.Error() }
func (e *ValidationError) Unwrap() error     { return e.Err }
func invalid(reason string, err error) error { return &ValidationError{reason, err} }
func SHA(data []byte) string                 { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func ClusterValid(name string) bool {
	return len(name) > 0 && len(name) <= 32 && len(validation.IsDNS1123Label(name)) == 0
}
func PinValid(pin string) bool {
	if len(pin) != 64 || pin != strings.ToLower(pin) {
		return false
	}
	_, err := hex.DecodeString(pin)
	return err == nil
}
func Stamp(t time.Time) string { return t.UTC().Truncate(time.Second).Format(time.RFC3339) }
func parseTime(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || Stamp(t) != value {
		return time.Time{}, errors.New("time must be whole-second UTC RFC3339")
	}
	return t, nil
}

// All input/publication objects have explicit struct fields; reject duplicates
// and noncanonical aliases before encoding/json's case-insensitive matching.
func decode(data []byte, out any) error {
	return decodeBounded(data, out, MaxBytes)
}

func decodeBounded(data []byte, out any, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("bounded nonempty JSON required")
	}
	allowed := map[string]bool{}
	for s := range strings.FieldsSeq("schemaVersion generation expiresAt roots clusters certificatePEM sha256 clusterID trustDomain issuers chainPEM spkiSHA256 rootSHA256 sequence state reason producerCluster outputUID expectedSourceUID source namespace name uid resourceVersion acceptedGeneration acceptedSourceUID acceptedApprovalDigest approvalDigest approval publishedAt validUntil digest") {
		allowed[s] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	depth := 0
	var scan func() error
	scan = func() error {
		depth++
		defer func() { depth-- }()
		if depth > MaxJSONDepth {
			return errors.New("JSON nesting exceeds issuer-profile schema")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					keyToken, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := keyToken.(string)
					if !ok || !allowed[key] || seen[key] {
						return errors.New("unknown, aliased or duplicate JSON key")
					}
					seen[key] = true
					if e := scan(); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return errors.New("invalid object")
				}
			case '[':
				for d.More() {
					if e := scan(); e != nil {
						return e
					}
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return errors.New("invalid array")
				}
			default:
				return errors.New("invalid JSON delimiter")
			}
		}
		return nil
	}
	if err := scan(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("one JSON object required")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}
func oneCertificate(value string) (*x509.Certificate, error) {
	blocks, err := certificates(value)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 1 {
		return nil, errors.New("exactly one public certificate required")
	}
	return blocks[0], nil
}
func certificates(value string) ([]*x509.Certificate, error) {
	rest := bytes.TrimSpace([]byte(value))
	var result []*x509.Certificate
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("non-certificate PEM prefix")
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("only public CERTIFICATE PEM blocks allowed")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		result = append(result, cert)
		if len(result) > 5 {
			return nil, errors.New("certificate chain too long")
		}
		rest = next
	}
	if len(result) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	return result, nil
}
func canonical(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
func exactDomainSAN(encoded []byte, domain string) bool {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return false
	}
	var uri asn1.RawValue
	rest, err = asn1.Unmarshal(sequence.Bytes, &uri)
	return err == nil && len(rest) == 0 && uri.Class == 2 && uri.Tag == 6 && !uri.IsCompound && string(uri.Bytes) == "spiffe://"+domain
}
func caCurrent(cert *x509.Certificate, now time.Time) error { return caCurrentForDomain(cert, now, "") }
func caCurrentForDomain(cert *x509.Certificate, now time.Time, domain string) error {
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certificate is not an explicit signing CA")
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return errors.New("CA certificate is not current")
	}
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()
		if oid == "2.5.29.17" && domain != "" {
			if !exactDomainSAN(ext.Value, domain) || len(cert.DNSNames) != 0 || len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://"+domain {
				return errors.New("SPIRE CA SAN must be the single exact approved trust-domain URI")
			}
			continue
		}
		if oid != "2.5.29.19" && oid != "2.5.29.15" && oid != "2.5.29.14" && oid != "2.5.29.35" {
			return errors.New("CA extension outside current direct-issuer verifier profile")
		}
		if oid == "2.5.29.19" && !ext.Critical {
			return errors.New("CA basic constraints must be critical")
		}
	}
	if len(cert.UnhandledCriticalExtensions) > 0 {
		return errors.New("unhandled critical CA extension")
	}
	return nil
}

// caDepthAllows includes every CA below this certificate in the eventual
// SVID path. x509.Verify(targetCA) does not itself count that target as the
// intermediate it will be when it signs a workload leaf.
func caDepthAllows(cert *x509.Certificate, below int) bool {
	if cert.MaxPathLenZero {
		return below == 0
	}
	return cert.MaxPathLen < 0 || cert.MaxPathLen >= below
}

type approvedParent struct{ cluster, certificate string }

func minimum(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func Validate(data []byte, rootPins []string, localCluster string, now time.Time) (*Validated, error) {
	var a Approval
	if err := decode(data, &a); err != nil {
		return nil, invalid("SourceInvalid", err)
	}
	if a.SchemaVersion != SchemaVersion || a.Generation == 0 || len(a.Roots) != 1 || len(a.Clusters) == 0 || len(a.Clusters) > 16 {
		return nil, invalid("SourceInvalid", errors.New("invalid schema/generation/cardinality"))
	}
	until, err := parseTime(a.ExpiresAt)
	if err != nil {
		return nil, invalid("SourceInvalid", err)
	}
	if !now.Before(until) {
		return nil, invalid("SourceExpired", errors.New("administrator approval expired"))
	}
	if until.After(now.Add(30 * 24 * time.Hour)) {
		return nil, invalid("SourceInvalid", errors.New("approval exceeds 30-day horizon"))
	}
	if len(rootPins) == 0 || len(rootPins) > 4 {
		return nil, invalid("SourceInvalid", errors.New("bounded installation root pins required"))
	}
	allowed := map[string]bool{}
	for _, pin := range rootPins {
		if !PinValid(pin) || allowed[pin] {
			return nil, invalid("SourceInvalid", errors.New("invalid/duplicate installation root pin"))
		}
		allowed[pin] = true
	}
	if len(allowed) == 0 {
		return nil, invalid("SourceInvalid", errors.New("explicit installation root pins required"))
	}
	roots := map[string]*x509.Certificate{}
	rootKeys := map[string]bool{}
	for i, r := range a.Roots {
		cert, e := oneCertificate(r.CertificatePEM)
		if e != nil {
			return nil, invalid("SourceInvalid", e)
		}
		hash, key := SHA(cert.Raw), SHA(cert.RawSubjectPublicKeyInfo)
		if !PinValid(r.SHA256) || r.SHA256 != hash || !allowed[hash] || roots[hash] != nil || rootKeys[key] {
			return nil, invalid("SourceInvalid", errors.New("unapproved or duplicate root certificate/key"))
		}
		if e := caCurrent(cert, now); e != nil {
			return nil, invalid("SourceInvalid", e)
		}
		if cert.MaxPathLenZero || !bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
			return nil, invalid("SourceInvalid", errors.New("root must be self-signed"))
		}
		roots[hash] = cert
		rootKeys[key] = true
		until = minimum(until, cert.NotAfter)
		a.Roots[i].CertificatePEM = canonical(cert)
	}
	clusters, domains, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}
	parents := map[string]approvedParent{}
	local := false
	for ci, c := range a.Clusters {
		if !ClusterValid(c.ClusterID) || clusters[c.ClusterID] || len(validation.IsDNS1123Subdomain(c.TrustDomain)) != 0 || domains[c.TrustDomain] || len(c.Issuers) == 0 || len(c.Issuers) > 2 {
			return nil, invalid("SourceInvalid", errors.New("noncanonical/duplicate cluster/domain or issuer cardinality"))
		}
		clusters[c.ClusterID] = true
		domains[c.TrustDomain] = true
		local = local || c.ClusterID == localCluster
		for ii, pin := range c.Issuers {
			cert, e := oneCertificate(pin.CertificatePEM)
			if e != nil {
				return nil, invalid("SourceInvalid", e)
			}
			root := roots[pin.RootSHA256]
			key := SHA(cert.RawSubjectPublicKeyInfo)
			if root == nil || !PinValid(pin.SPKISHA256) || pin.SPKISHA256 != key || keys[key] || rootKeys[key] || parents[key].cluster != "" {
				return nil, invalid("SourceInvalid", errors.New("unapproved root or reused/mismatched direct issuer key"))
			}
			if e := caCurrentForDomain(cert, now, c.TrustDomain); e != nil {
				return nil, invalid("SourceInvalid", e)
			}

			intermediatePool := x509.NewCertPool()
			chainPEM := ""
			expectedChain := []*x509.Certificate{cert}
			signer := root
			if pin.ChainPEM != "" {
				// Approval carries exactly one cluster CA, excluding the root.
				// Do not discover ancestors from a remote trust bundle.
				parent, err := oneCertificate(pin.ChainPEM)
				if err != nil {
					return nil, invalid("SourceInvalid", err)
				}
				if err = caCurrent(parent, now); err != nil {
					return nil, invalid("SourceInvalid", err)
				}
				parentKey := SHA(parent.RawSubjectPublicKeyInfo)
				old := parents[parentKey]
				if rootKeys[parentKey] || keys[parentKey] || parentKey == key || old.cluster != "" && (old.cluster != c.ClusterID || old.certificate != SHA(parent.Raw)) {
					return nil, invalid("SourceInvalid", errors.New("cluster CA key reused across roles, clusters or certificate incarnations"))
				}
				if !caDepthAllows(root, 2) || !caDepthAllows(parent, 1) || !bytes.Equal(parent.RawIssuer, root.RawSubject) || parent.CheckSignatureFrom(root) != nil {
					return nil, invalid("SourceInvalid", errors.New("cluster CA lacks approved root lineage or SVID path depth"))
				}
				parents[parentKey] = approvedParent{cluster: c.ClusterID, certificate: SHA(parent.Raw)}
				intermediatePool.AddCert(parent)
				chainPEM = canonical(parent)
				expectedChain = append(expectedChain, parent)
				signer = parent
				until = minimum(until, parent.NotAfter)
			} else if !caDepthAllows(root, 1) {
				return nil, invalid("SourceInvalid", errors.New("organizational root excludes direct issuer depth"))
			}
			if !bytes.Equal(cert.RawIssuer, signer.RawSubject) || cert.CheckSignatureFrom(signer) != nil {
				return nil, invalid("SourceInvalid", errors.New("SPIRE issuer lacks exact approved direct parent signature"))
			}
			expectedChain = append(expectedChain, root)
			rootPool := x509.NewCertPool()
			rootPool.AddCert(root)
			chains, err := cert.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if err != nil {
				return nil, invalid("SourceInvalid", fmt.Errorf("verify approved issuer lineage: %w", err))
			}
			if len(chains) != 1 || len(chains[0]) != len(expectedChain) {
				return nil, invalid("SourceInvalid", errors.New("unused or ambiguous approved CA lineage"))
			}
			for i, ancestor := range chains[0] {
				if !bytes.Equal(ancestor.Raw, expectedChain[i].Raw) {
					return nil, invalid("SourceInvalid", errors.New("CA lineage differs from explicit approval order"))
				}
			}

			keys[key] = true
			until = minimum(until, cert.NotAfter)
			a.Clusters[ci].Issuers[ii].CertificatePEM = canonical(cert)
			a.Clusters[ci].Issuers[ii].ChainPEM = chainPEM
		}
		sort.Slice(a.Clusters[ci].Issuers, func(i, j int) bool {
			return a.Clusters[ci].Issuers[i].SPKISHA256 < a.Clusters[ci].Issuers[j].SPKISHA256
		})
	}
	if !local {
		return nil, invalid("SourceInvalid", errors.New("local configured cluster has no approved binding"))
	}
	sort.Slice(a.Roots, func(i, j int) bool { return a.Roots[i].SHA256 < a.Roots[j].SHA256 })
	sort.Slice(a.Clusters, func(i, j int) bool { return a.Clusters[i].ClusterID < a.Clusters[j].ClusterID })
	body, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBytes {
		return nil, invalid("SourceInvalid", errors.New("canonical approval exceeds issuer-profile size limit"))
	}
	return &Validated{Approval: a, Digest: SHA(body), Until: until.UTC().Truncate(time.Second)}, nil
}

func boundedApprovalJSON(a *Approval) ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	body, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBytes {
		return nil, errors.New("canonical approval exceeds issuer-profile size limit")
	}
	return body, nil
}

func Encode(p Publication) ([]byte, error) {
	if _, err := boundedApprovalJSON(p.Approval); err != nil {
		return nil, err
	}
	p.Digest = ""
	body, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	if len(body) > MaxPublicationBytes {
		return nil, errors.New("publication exceeds issuer-profile envelope size limit")
	}
	p.Digest = SHA(body)
	encoded, e := json.Marshal(p)
	if e != nil {
		return nil, e
	}
	if len(encoded) > MaxPublicationBytes {
		return nil, errors.New("publication exceeds issuer-profile envelope size limit")
	}
	return encoded, nil
}
func DecodePublication(data []byte) (*Publication, error) {
	var p Publication
	if err := decodeBounded(data, &p, MaxPublicationBytes); err != nil {
		return nil, err
	}
	digest := p.Digest
	p.Digest = ""
	body, err := json.Marshal(p)
	if err != nil || !PinValid(digest) || SHA(body) != digest {
		return nil, errors.New("publication digest mismatch")
	}
	p.Digest = digest
	if p.SchemaVersion != SchemaVersion || p.Sequence == 0 || p.OutputUID == "" || p.ExpectedSourceUID == "" || (p.State != "published" && p.State != "withdrawn") {
		return nil, errors.New("invalid publication envelope")
	}
	if _, err := parseTime(p.PublishedAt); err != nil {
		return nil, err
	}
	if _, err := parseTime(p.ValidUntil); err != nil {
		return nil, err
	}
	if p.State == "published" && (p.Approval == nil || p.AcceptedGeneration == 0 || p.AcceptedSourceUID != p.Source.UID || p.AcceptedApprovalDigest != p.ApprovalDigest || p.Approval.Generation != p.AcceptedGeneration || p.Source.Generation != p.AcceptedGeneration || p.Source.UID != p.ExpectedSourceUID || !PinValid(p.ApprovalDigest)) {
		return nil, errors.New("published envelope lacks approved source binding")
	}
	if p.State == "published" {
		a, e := boundedApprovalJSON(p.Approval)
		if e != nil || SHA(a) != p.ApprovalDigest {
			return nil, errors.New("approval digest mismatch")
		}
		published, e := parseTime(p.PublishedAt)
		if e != nil {
			return nil, e
		}
		until, e := parseTime(p.ValidUntil)
		if e != nil || !until.After(published) || until.After(published.Add(MaxLease)) {
			return nil, errors.New("invalid publication lease")
		}
	}
	if p.State == "withdrawn" {
		if p.Approval != nil || p.ApprovalDigest != "" || p.ValidUntil != p.PublishedAt {
			return nil, errors.New("withdrawn envelope retains anchors or a live lease")
		}
		if p.AcceptedGeneration == 0 {
			if p.AcceptedSourceUID != "" || p.AcceptedApprovalDigest != "" {
				return nil, errors.New("withdrawn envelope has partial rollback floor")
			}
		} else if p.AcceptedSourceUID == "" || !PinValid(p.AcceptedApprovalDigest) {
			return nil, errors.New("withdrawn envelope lost accepted rollback floor")
		}
	}
	return &p, nil
}

// VerifyCurrent is a pure consumer-side contract, not Cilium integration. A
// future API-backed Cilium watcher must also prove authorized object origin,
// maintain its own durable sequence floor, deliver xDS, ACK and drain on expiry.
//
// SourceName and SourceUID name the approval object accepted at
// MinimumGeneration and bind only that generation. Approvals are immutable,
// so each new approval generation is a new object: a successor object in
// SourceNamespace is current when its generation is strictly greater. The UID
// identifies the object; a caller that reads the live object by its name
// proves that the name belongs to it.
type Expected struct {
	OutputUID, SourceUID, SourceNamespace, SourceName, Cluster string
	MinimumGeneration, MinimumSequence                         uint64
	RootPins                                                   []string
}

func VerifyCurrent(data []byte, e Expected, now time.Time) (*Publication, error) {
	p, err := DecodePublication(data)
	if err != nil {
		return nil, err
	}
	if p.State != "published" || p.Reason != "Validated" || p.OutputUID != e.OutputUID || p.Source.Namespace != e.SourceNamespace || p.Source.ResourceVersion == "" || p.ProducerCluster != e.Cluster || p.AcceptedGeneration < e.MinimumGeneration || p.Sequence < e.MinimumSequence {
		return nil, errors.New("publication not authorized/current for configured source")
	}
	// DecodePublication binds Source.UID to ExpectedSourceUID and
	// AcceptedSourceUID for a published profile.
	if len(validation.IsDNS1123Subdomain(p.Source.Name)) != 0 || p.Source.UID == e.OutputUID || p.AcceptedGeneration == e.MinimumGeneration && p.Source.UID != e.SourceUID {
		return nil, errors.New("publication approval source is neither the floor object nor a successor")
	}
	at, _ := parseTime(p.PublishedAt)
	until, _ := parseTime(p.ValidUntil)
	if now.Before(at) || !now.Before(until) {
		return nil, errors.New("publication lease expired or from future")
	}
	body, err := json.Marshal(p.Approval)
	if err != nil {
		return nil, err
	}
	valid, err := Validate(body, e.RootPins, e.Cluster, now)
	if err != nil {
		return nil, err
	}
	if valid.Digest != p.ApprovalDigest || until.After(valid.Until) {
		return nil, errors.New("publication exceeds approved issuer validity")
	}
	return p, nil
}
