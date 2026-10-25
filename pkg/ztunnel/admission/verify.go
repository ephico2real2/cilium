// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

// VerifyEndpoint confirms, without changing anything, that a captured Required
// endpoint is still the admitted incarnation: its live Namespace and Pod
// identity, enrollment intent, node and sandbox; its current registry capture
// generation and published membership; and an ADD acknowledged by the live
// ztunnel execution. It never quarantines, re-captures or sends an ADD. An
// error means the evidence is no longer current and the caller must run full
// admission (RevalidateEndpoint).
func (g *gate) VerifyEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
	if !g.enabled || g.membership == nil || g.core == nil || g.verifyCapture == nil {
		return fmt.Errorf("strict ztunnel admission verification is unavailable")
	}
	if ep == nil || !ep.IsAlive() {
		return fmt.Errorf("endpoint is unavailable")
	}
	namespace, name, uid, path := ep.GetK8sNamespace(), ep.GetK8sPodName(), ep.K8sUID, ep.GetContainerNetnsPath()
	if namespace == "" || name == "" || uid == "" || path == "" {
		return fmt.Errorf("endpoint has incomplete immutable identity")
	}
	ref, state, ok := g.membership.CurrentForPodUID(uid)
	if !ok || state.EndpointID != ep.GetID16() || state.NetnsPath != path || !state.ReadyForAddress() {
		return fmt.Errorf("registry membership is not this captured endpoint incarnation")
	}
	publication, ok := g.membership.Publication(ref)
	published, hasPublished := ep.GetZtunnelMembership()
	if !ok || !hasPublished || publication.State != membership.PublicationCaptured ||
		published.State != endpoint.ZtunnelMembershipCaptured || published.Version != publication.Version ||
		published.Revision != publication.Revision || published.Epoch != publication.Epoch ||
		published.Generation != publication.Generation || published.NamespaceUID != ref.Key.NamespaceUID {
		return fmt.Errorf("published membership is not the current captured publication")
	}

	ns, err := g.core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live namespace intent: %w", err)
	}
	if string(ns.UID) != ref.Key.NamespaceUID || ns.DeletionTimestamp != nil || ns.Labels["io.cilium/mtls-enabled"] != "true" {
		return fmt.Errorf("namespace incarnation or enrollment intent changed")
	}
	pod, err := g.core.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live Pod identity: %w", err)
	}
	if string(pod.UID) != uid || pod.DeletionTimestamp != nil || pod.Spec.ServiceAccountName == "" ||
		pod.Spec.NodeName == "" || pod.Spec.NodeName != g.nodeName() {
		return fmt.Errorf("live Pod does not match the admitted incarnation")
	}
	managed := ep.GetPod()
	if managed == nil || string(managed.UID) != uid || managed.Name != name || managed.Namespace != namespace ||
		published.ServiceAccount != pod.Spec.ServiceAccountName || published.NodeName != pod.Spec.NodeName {
		return fmt.Errorf("managed endpoint metadata does not match the admitted incarnation")
	}
	if err := g.validateNetns(path); err != nil {
		return fmt.Errorf("validating CNI network namespace: %w", err)
	}
	if err := g.verifyCapture(ep, ref, state.ZDSGeneration); err != nil {
		return fmt.Errorf("verifying live ztunnel capture: %w", err)
	}
	// The checks above ran outside the registry lock; the publication they
	// verified must still be the current one.
	if after, ok := g.membership.Publication(ref); !ok || after != publication {
		return fmt.Errorf("membership changed during verification")
	}
	return ctx.Err()
}
