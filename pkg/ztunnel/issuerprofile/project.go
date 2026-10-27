// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package issuerprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	typedcore "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Install is supplied independently by the Cilium installation, never read
// from the profile objects. Its floors MUST be durable before runtime use.
// Expected.SourceName and SourceUID name the approval object accepted at
// MinimumGeneration; they bind only that generation (see VerifyCurrent).
type Install struct {
	Expected
	OutputNamespace, OutputName, Node string
	// Optional checkpoint digests bind equality at the persisted numeric floors.
	// Empty is only for a new independently administered bootstrap checkpoint.
	ApprovalDigestAtMinimum, PublicationDigestAtMinimum string
}

type DERIssuer struct {
	CertificateDER []byte   `json:"certificateDER"`
	SPKISHA256     string   `json:"spkiSHA256"`
	LineageDER     [][]byte `json:"lineageDER,omitempty"`
	// SignsSPIRECA: the pin is the cluster's SPIRE intermediate (see Issuer).
	SignsSPIRECA bool `json:"signsSPIRECA,omitempty"`
}
type DERCluster struct {
	ClusterID   string      `json:"clusterID"`
	TrustDomain string      `json:"trustDomain"`
	Issuers     []DERIssuer `json:"issuers"`
}

// Uint64 values are canonical decimal strings; JSON float precision is not part
// of the protocol. []byte is padded standard base64 of the exact DER bytes.
type DERProfile struct {
	WireVersion       uint32       `json:"wireVersion"`
	Cluster           string       `json:"cluster"`
	Node              string       `json:"node"`
	SourceNamespace   string       `json:"sourceNamespace"`
	SourceName        string       `json:"sourceName"`
	SourceUID         string       `json:"sourceUID"`
	OutputNamespace   string       `json:"outputNamespace"`
	OutputName        string       `json:"outputName"`
	OutputUID         string       `json:"outputUID"`
	Sequence          string       `json:"sequence"`
	Generation        string       `json:"generation"`
	ApprovalDigest    string       `json:"approvalDigest"`
	PublicationDigest string       `json:"publicationDigest"`
	State             string       `json:"state"`
	Reason            string       `json:"reason"`
	PublishedUnix     string       `json:"publishedUnix"`
	ValidUntilUnix    string       `json:"validUntilUnix"`
	RootSHA256        string       `json:"rootSHA256"`
	RootDER           []byte       `json:"rootDER"`
	Clusters          []DERCluster `json:"clusters"`
}

func (e Install) validate() error {
	if e.OutputUID == "" || e.SourceUID == "" || e.OutputUID == e.SourceUID || e.MinimumGeneration == 0 || e.MinimumSequence == 0 || !ClusterValid(e.Cluster) || len(validation.IsDNS1123Subdomain(e.Node)) != 0 || e.Node == "" || e.OutputNamespace != e.SourceNamespace || e.OutputName == e.SourceName {
		return errors.New("explicit independent source/output/node pins and positive durable floors required")
	}
	for _, namespace := range []string{e.SourceNamespace, e.OutputNamespace} {
		if len(validation.IsDNS1123Label(namespace)) != 0 {
			return errors.New("noncanonical namespace binding")
		}
	}
	for _, name := range []string{e.SourceName, e.OutputName} {
		if name == "" || len(validation.IsDNS1123Subdomain(name)) != 0 {
			return errors.New("noncanonical object binding")
		}
	}
	for _, digest := range []string{e.ApprovalDigestAtMinimum, e.PublicationDigestAtMinimum} {
		if digest != "" && !PinValid(digest) {
			return errors.New("invalid checkpoint digest")
		}
	}
	seen := map[string]bool{}
	if len(e.RootPins) == 0 || len(e.RootPins) > 4 {
		return errors.New("explicit bounded root pins required")
	}
	for _, pin := range e.RootPins {
		if !PinValid(pin) || seen[pin] {
			return errors.New("invalid root pins")
		}
		seen[pin] = true
	}
	return nil
}
func checkOutput(out *corev1.ConfigMap, e Install) error {
	if out == nil || out.Namespace != e.OutputNamespace || out.Name != e.OutputName || string(out.UID) != e.OutputUID || out.ResourceVersion == "" || out.DeletionTimestamp != nil || len(out.OwnerReferences) > 0 || len(out.BinaryData) > 0 || len(out.Data) != 1 || out.Labels[OutputLabel] != "true" || out.Immutable != nil && *out.Immutable || out.Annotations[InitializedAnnotation] != "true" {
		return errors.New("output metadata not the independently pinned initialized publication")
	}
	return nil
}

// A producer write between the reads of one observation makes that observation
// incoherent. It says nothing about the authority already delivered, which stays
// bounded by its own lease; callers may observe again instead of failing.
var (
	ErrSourceChanged = errors.New("source changed during API observation")
	ErrOutputChanged = errors.New("output changed during API observation")
)

func sameObject(a, b *corev1.ConfigMap) bool {
	return a != nil && b != nil && a.UID == b.UID && a.ResourceVersion == b.ResourceVersion && b.DeletionTimestamp == nil
}

// Projection is one coherent API observation projected for ztunnel.
type Projection struct {
	Body []byte
	// AcceptedSourceUID is the approval object whose material is the projected
	// generation. A caller that keeps floors binds it at that generation only.
	AcceptedSourceUID string
}

// ReadAndProject returns ReadProjection's ztunnel wire body.
func ReadAndProject(ctx context.Context, core typedcore.CoreV1Interface, e Install, clock func() time.Time) ([]byte, error) {
	projection, err := ReadProjection(ctx, core, e, clock)
	if err != nil {
		return nil, err
	}
	return projection.Body, nil
}

// ReadProjection uses the real CoreV1Interface implemented by Cilium's injected
// client.Clientset.CoreV1(). It neither caches nor watches resources. GETs are
// current API reads through that client's configured Kubernetes TLS/RBAC. Tests
// may inject the existing client-go fake. A hostile implementation is not an
// authenticated API client; this pure seam cannot attest its caller.
//
// The approval object is data in the pinned namespace, not installation scope.
// Approvals are immutable, so each new approval generation is a new object: a
// publication from a successor object is followed when its accepted generation
// is strictly greater than the floor, and the live successor is read by the
// name the publication gives and must have its UID.
//
// No callbacks to trust-policy/TLS code occur here. Any error must fence future
// runtime delivery; retaining the last good projection is NOT a permitted fallback.
func ReadProjection(ctx context.Context, core typedcore.CoreV1Interface, e Install, clock func() time.Time) (Projection, error) {
	body, accepted, err := readAndProject(ctx, core, e, clock)
	if err != nil {
		return Projection{}, err
	}
	return Projection{Body: body, AcceptedSourceUID: accepted}, nil
}

func readAndProject(ctx context.Context, core typedcore.CoreV1Interface, e Install, clock func() time.Time) ([]byte, string, error) {
	if err := e.validate(); err != nil {
		return nil, "", err
	}
	if core == nil || clock == nil {
		return nil, "", errors.New("explicit API client and clock required")
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	output, err := core.ConfigMaps(e.OutputNamespace).Get(ctx, e.OutputName, metav1.GetOptions{})
	if err != nil {
		return nil, "", err
	}
	if err = checkOutput(output, e); err != nil {
		return nil, "", err
	}
	p, err := DecodePublication([]byte(output.Data[DataKey]))
	if err != nil {
		return nil, "", err
	}
	if p.OutputUID != e.OutputUID || p.Source.Namespace != e.SourceNamespace || p.ProducerCluster != e.Cluster || p.Sequence < e.MinimumSequence || p.AcceptedGeneration < e.MinimumGeneration {
		return nil, "", errors.New("publication origin/floor mismatch")
	}
	// The configured and the accepted approval objects must be distinct from
	// the pinned output object.
	if len(validation.IsDNS1123Subdomain(p.Source.Name)) != 0 || p.Source.Name == e.OutputName || p.ExpectedSourceUID == e.OutputUID || p.AcceptedSourceUID == e.OutputUID {
		return nil, "", errors.New("publication approval source is not a distinct object in the pinned namespace")
	}
	if p.Sequence == e.MinimumSequence && e.PublicationDigestAtMinimum != "" && p.Digest != e.PublicationDigestAtMinimum {
		return nil, "", errors.New("same-sequence publication substitution")
	}
	if p.AcceptedGeneration == e.MinimumGeneration && e.ApprovalDigestAtMinimum != "" && p.AcceptedApprovalDigest != e.ApprovalDigestAtMinimum {
		return nil, "", errors.New("same-generation authority substitution")
	}
	// The floor object is the only source of the floor generation's material.
	// A successor object needs a strictly greater accepted generation.
	if p.AcceptedGeneration == e.MinimumGeneration && p.AcceptedSourceUID != e.SourceUID {
		return nil, "", errors.New("accepted history source mismatch")
	}
	// A tombstone clears all anchors. Missing/replaced source is deliberately
	// not an obstacle to withdrawal; it cannot be used as a published profile.
	if p.State == "published" {
		// DecodePublication binds Source.UID to ExpectedSourceUID and
		// AcceptedSourceUID for a published profile.
		source, readErr := core.ConfigMaps(e.SourceNamespace).Get(ctx, p.Source.Name, metav1.GetOptions{})
		if readErr != nil {
			return nil, "", readErr
		}
		if source.Namespace != e.SourceNamespace || source.Name != p.Source.Name || source.DeletionTimestamp != nil || string(source.UID) != p.Source.UID || source.ResourceVersion != p.Source.ResourceVersion || source.Immutable == nil || !*source.Immutable || len(source.Data) != 1 || len(source.BinaryData) > 0 || len(source.OwnerReferences) > 0 {
			return nil, "", errors.New("source not exact current immutable administrator approval")
		}
		valid, verifyErr := Validate([]byte(source.Data[ApprovalKey]), e.RootPins, e.Cluster, clock())
		if verifyErr != nil {
			return nil, "", verifyErr
		}
		if valid.Digest != p.ApprovalDigest {
			return nil, "", errors.New("live source differs from published approval")
		}
		latest, readErr := core.ConfigMaps(e.SourceNamespace).Get(ctx, p.Source.Name, metav1.GetOptions{})
		if readErr != nil {
			return nil, "", readErr
		}
		if !sameObject(source, latest) {
			return nil, "", ErrSourceChanged
		}
	}
	latest, err := core.ConfigMaps(e.OutputNamespace).Get(ctx, e.OutputName, metav1.GetOptions{})
	if err != nil {
		return nil, "", err
	}
	if !sameObject(output, latest) {
		return nil, "", ErrOutputChanged
	}
	if err = checkOutput(latest, e); err != nil {
		return nil, "", err
	}
	now := clock()
	if p.State == "published" {
		if _, err = VerifyCurrent([]byte(output.Data[DataKey]), e.Expected, now); err != nil {
			return nil, "", err
		}
	} else {
		at, _ := parseTime(p.PublishedAt)
		if now.Before(at) {
			return nil, "", errors.New("future withdrawal")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	body, err := project(p, e)
	if err != nil {
		return nil, "", err
	}
	return body, p.AcceptedSourceUID, nil
}

// These reasons describe unavailable approval/delivery state. They do not
// authorize irreversible issuer revocation. Key-set changes require a new
// validated published authority and its cumulative provider transition.
func checkDeliveryReason(p *Publication) error {
	if p.State == "published" && p.Reason == "Validated" {
		return nil
	}
	if p.State == "withdrawn" {
		switch p.Reason {
		case "SourceUnavailable", "SourceChanged", "SourceDeleted", "SourceUIDMismatch", "SourceInvalid", "SourceExpired", "GenerationRollback":
			return nil
		}
	}
	return errors.New("unknown or state-mismatched issuer-profile delivery reason")
}
func project(p *Publication, e Install) ([]byte, error) {
	if err := checkDeliveryReason(p); err != nil {
		return nil, err
	}
	at, err := parseTime(p.PublishedAt)
	if err != nil {
		return nil, err
	}
	until, err := parseTime(p.ValidUntil)
	if err != nil {
		return nil, err
	}
	if at.Unix() < 0 || until.Unix() < 0 {
		return nil, errors.New("negative protocol time")
	}
	if p.State == "withdrawn" && !until.Equal(at) {
		return nil, errors.New("tombstone cannot retain a lease")
	}
	// The wire names the producer's configured approval object. For a
	// published profile it is the accepted object; ztunnel binds it to the
	// material generation in its durable checkpoint.
	result := DERProfile{WireVersion: 1, Cluster: e.Cluster, Node: e.Node, SourceNamespace: e.SourceNamespace, SourceName: p.Source.Name, SourceUID: p.ExpectedSourceUID, OutputNamespace: e.OutputNamespace, OutputName: e.OutputName, OutputUID: e.OutputUID, Sequence: strconv.FormatUint(p.Sequence, 10), Generation: strconv.FormatUint(p.AcceptedGeneration, 10), ApprovalDigest: p.AcceptedApprovalDigest, PublicationDigest: p.Digest, State: p.State, Reason: p.Reason, PublishedUnix: strconv.FormatInt(at.Unix(), 10), ValidUntilUnix: strconv.FormatInt(until.Unix(), 10), Clusters: []DERCluster{}}
	if p.State == "published" {
		if p.Approval == nil || len(p.Approval.Roots) != 1 {
			return nil, errors.New("single-root profile required")
		}
		root, err := oneCertificate(p.Approval.Roots[0].CertificatePEM)
		if err != nil {
			return nil, err
		}
		if len(root.Raw) > 24576 {
			return nil, errors.New("root DER exceeds wire certificate bound")
		}
		result.RootDER = bytes.Clone(root.Raw)
		result.RootSHA256 = SHA(root.Raw)
		for _, cluster := range p.Approval.Clusters {
			item := DERCluster{ClusterID: cluster.ClusterID, TrustDomain: cluster.TrustDomain, Issuers: []DERIssuer{}}
			for _, issuer := range cluster.Issuers {
				cert, err := oneCertificate(issuer.CertificatePEM)
				if err != nil {
					return nil, err
				}
				if len(cert.Raw) > 24576 {
					return nil, errors.New("issuer DER exceeds wire certificate bound")
				}
				projected := DERIssuer{CertificateDER: bytes.Clone(cert.Raw), SPKISHA256: SHA(cert.RawSubjectPublicKeyInfo), SignsSPIRECA: issuer.SignsSPIRECA}
				if issuer.ChainPEM != "" {
					parent, err := oneCertificate(issuer.ChainPEM)
					if err != nil {
						return nil, err
					}
					if len(parent.Raw) > 24576 {
						return nil, errors.New("cluster CA DER exceeds wire certificate bound")
					}
					projected.LineageDER = [][]byte{bytes.Clone(parent.Raw)}
				}
				item.Issuers = append(item.Issuers, projected)
			}
			result.Clusters = append(result.Clusters, item)
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxPublicationBytes {
		return nil, fmt.Errorf("DER projection exceeds %d bytes", MaxPublicationBytes)
	}
	return body, nil
}
