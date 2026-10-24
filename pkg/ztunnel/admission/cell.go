// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package admission

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	k8sclient "github.com/cilium/cilium/pkg/k8s/client"
	slimcore "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned/typed/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

const (
	logStage              = "stage"
	logDeadline           = "deadline"
	logNamespaceUID       = "namespaceUID"
	logEnrollmentRequired = "enrollmentRequired"
)

var Cell = cell.Module("ztunnel-admission", "ztunnel new-pod startup admission", cell.Provide(newGate))

type params struct {
	cell.In
	Config      config.Config
	Clientset   k8sclient.Clientset
	Server      *zds.Server
	AgentConfig *option.DaemonConfig
	Logger      *slog.Logger
}

type out struct {
	cell.Out
	Gate endpointmanager.EndpointCreationGate `group:"endpoint-creation-gates"`
}

type gate struct {
	enabled        bool
	core           slimcore.CoreV1Interface
	enroll         func(context.Context, *endpoint.Endpoint) error
	validateNetns  func(string) error
	nodeName       func() string
	agentNamespace string
	logger         *slog.Logger
	budget         time.Duration
	attemptTimeout time.Duration
	initialBackoff time.Duration
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }
func permanent(format string, args ...any) error {
	return &permanentError{err: fmt.Errorf(format, args...)}
}

func newGate(p params) (out, error) {
	enabled := p.Config.EnableZTunnel && p.Config.RequireMTLS
	g := &gate{enabled: enabled, logger: p.Logger, nodeName: nodetypes.GetName,
		budget: 30 * time.Second, attemptTimeout: 5 * time.Second, initialBackoff: 100 * time.Millisecond,
		validateNetns: validateNetworkNamespace,
	}
	if p.AgentConfig != nil {
		g.agentNamespace = p.AgentConfig.K8sNamespace
	}
	if enabled {
		if p.Clientset == nil || !p.Clientset.IsEnabled() || p.Server == nil || g.agentNamespace == "" {
			return out{}, fmt.Errorf("strict ztunnel admission requires Kubernetes, ZDS and configured agent namespace")
		}
		g.core = p.Clientset.Slim().CoreV1()
		g.enroll = p.Server.EnrollEndpointContext
	}
	return out{Gate: g}, nil
}

func (g *gate) WaitForEndpoint(parent context.Context, ep *endpoint.Endpoint) (resultErr error) {
	if !g.enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, g.budget)
	defer cancel()
	started := time.Now()
	deadline, _ := ctx.Deadline()
	var namespaceUID types.UID
	var attempt int
	required := false // Never downgrade an observed enrolled request on retry.
	namespace, name, uid := "", "", ""
	var endpointID uint16
	if ep != nil {
		namespace, name, uid = ep.GetK8sNamespace(), ep.GetK8sPodName(), ep.K8sUID
		endpointID = ep.GetID16()
	}
	// Every exit, including cancellation before an attempt or during backoff,
	// records one terminal outcome. An admission ACK is not Protected status.
	defer func() {
		attrs := []any{logStage, "cni-startup-admission", logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started), logDeadline, deadline,
			logfields.EndpointID, endpointID, logfields.K8sUID, uid,
			logfields.Pod, name, logfields.K8sNamespace, namespace,
			logNamespaceUID, namespaceUID, logEnrollmentRequired, required}
		if resultErr != nil {
			g.logger.Error("Endpoint startup admission failed", append(attrs, logfields.Error, resultErr)...)
		} else {
			g.logger.Info("Endpoint startup admission completed", attrs...)
		}
	}()
	if ep == nil {
		return permanent("endpoint startup admission requires an endpoint")
	}
	if namespace == "" && name == "" && uid == "" {
		return nil // Internal/non-Kubernetes endpoint; no protection claim.
	}
	if namespace == "" || name == "" || uid == "" {
		return permanent("Kubernetes CNI endpoint has incomplete immutable identity")
	}
	backoff := g.initialBackoff
	var lastErr error
	for attempt = 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return errors.Join(err, lastErr)
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, g.attemptTimeout)
		err := g.once(attemptCtx, ep, &namespaceUID, &required)
		if err == nil {
			err = attemptCtx.Err()
		}
		if err == nil {
			err = ctx.Err()
		}
		lastErr = err
		cancelAttempt() // ZDS joins its cancellation callback before publishing success.
		if err == nil {
			return nil
		}
		var terminal *permanentError
		if errors.As(err, &terminal) || apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) || ctx.Err() != nil {
			return errors.Join(ctx.Err(), err)
		}
		g.logger.Warn("Endpoint startup admission retry",
			logStage, "cni-startup-admission",
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started),
			logfields.Backoff, backoff,
			logDeadline, deadline,
			logfields.EndpointID, endpointID,
			logfields.K8sUID, uid,
			logfields.Pod, name,
			logfields.K8sNamespace, namespace,
			logfields.Error, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ctx.Err(), err)
		case <-timer.C:
		}
		backoff = min(2*time.Second, 2*backoff)
	}
}

func (g *gate) once(ctx context.Context, ep *endpoint.Endpoint, pinnedUID *types.UID, required *bool) error {
	namespace, name := ep.GetK8sNamespace(), ep.GetK8sPodName()
	before, err := g.core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live namespace intent: %w", err)
	}
	if before.UID == "" || before.ResourceVersion == "" || before.DeletionTimestamp != nil {
		return permanent("namespace identity is empty or terminating")
	}
	if *pinnedUID == "" {
		*pinnedUID = before.UID
	}
	if before.UID != *pinnedUID {
		return permanent("namespace was recreated during CNI admission")
	}
	enrolled := before.Labels["io.cilium/mtls-enabled"] == "true"
	if *required && !enrolled {
		return permanent("enrollment intent changed during required CNI admission")
	}
	*required = *required || enrolled

	pod, err := g.core.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading live Pod identity: %w", err)
	}
	if string(pod.UID) != ep.K8sUID || pod.DeletionTimestamp != nil || pod.Name != name || pod.Namespace != namespace {
		return permanent("live Pod does not match immutable CNI identity")
	}
	if pod.Spec.ServiceAccountName == "" || pod.Spec.NodeName == "" || pod.Spec.NodeName != g.nodeName() {
		return permanent("live Pod service account or node binding is invalid")
	}
	// Current deletion still reads the managed endpoint's Pod pointer.
	// Do not create an ACK/cache state that this existing path cannot name.
	if enrolled {
		managedPod := ep.GetPod()
		if managedPod == nil || string(managedPod.UID) != ep.K8sUID ||
			managedPod.Name != name || managedPod.Namespace != namespace {
			return fmt.Errorf("managed endpoint metadata is not synchronized to immutable CNI identity")
		}
	}
	if enrolled && (pod.Spec.HostNetwork || namespace == g.agentNamespace) {
		return permanent("enrolled host-network or agent-namespace Pods are outside initial admission qualification")
	}
	if enrolled {
		path := ep.GetContainerNetnsPath()
		if path == "" {
			return permanent("enrolled CNI endpoint has no network namespace")
		}
		if err := g.validateNetns(path); err != nil {
			return fmt.Errorf("validating CNI network namespace: %w", err)
		}
		// This view is private to this attempt: background metadata updates
		// cannot alter the Pod UID/SA that the legacy converter sends.
		view := &endpoint.Endpoint{ID: ep.GetID16(), K8sUID: ep.K8sUID,
			K8sNamespace: namespace, K8sPodName: name}
		view.SetContainerNetnsPath(path)
		view.SetPod(pod.DeepCopy())
		if err := g.enroll(ctx, view); err != nil {
			return fmt.Errorf("capture/proxy enrollment: %w", err)
		}
		if err := g.validateNetns(path); err != nil {
			return permanent("CNI network namespace is invalid after enrollment: %w", err)
		}
	}
	currentPod, err := g.core.Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("rechecking live Pod: %w", err)
	}
	if string(currentPod.UID) != ep.K8sUID || currentPod.DeletionTimestamp != nil ||
		currentPod.Spec.ServiceAccountName != pod.Spec.ServiceAccountName || currentPod.Spec.NodeName != pod.Spec.NodeName {
		return permanent("Pod identity changed during CNI admission")
	}
	after, err := g.core.Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("rechecking live namespace intent: %w", err)
	}
	if after.UID != *pinnedUID || after.DeletionTimestamp != nil {
		return permanent("namespace changed generation during CNI admission")
	}
	if after.ResourceVersion != before.ResourceVersion || (after.Labels["io.cilium/mtls-enabled"] == "true") != enrolled {
		return fmt.Errorf("namespace intent changed during CNI admission")
	}
	return nil
}
