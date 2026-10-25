// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/table"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
)

const (
	logTransitionStage = "stage"
	logDesiredRevision = "desiredRevision"
)

type params struct {
	cell.In

	Config                      config.Config
	DB                          *statedb.DB
	EnrolledNamespaceTable      statedb.RWTable[*table.EnrolledNamespace]
	Logger                      *slog.Logger
	Lifecycle                   cell.Lifecycle
	EndpointManager             endpointmanager.EndpointManager
	EndpointEnroller            zds.EndpointEnroller
	EndpointDeletionCleaner     zds.EndpointDeletionCleaner
	RestorerPromise             promise.Promise[endpointstate.Restorer]
	EndpointEventChannel        chan *xds.EndpointEvent
	CiliumEndpointResource      resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSliceResource resource.Resource[*v2alpha1.CiliumEndpointSlice]
	EndpointRevalidators        []membership.EndpointRevalidator `group:"ztunnel-endpoint-revalidators"`
	Membership                  *membership.Registry
}

type EnrollmentReconciler struct {
	db                          *statedb.DB
	logger                      *slog.Logger
	enrolledNamespaceTable      statedb.RWTable[*table.EnrolledNamespace]
	endpointManager             endpointmanager.EndpointManager
	endpointEnroller            zds.EndpointEnroller
	endpointDeletionCleaner     zds.EndpointDeletionCleaner
	strictCreationAdmission     bool
	restorerPromise             promise.Promise[endpointstate.Restorer]
	endpointEventCh             chan *xds.EndpointEvent
	ciliumEndpointResource      resource.Resource[*types.CiliumEndpoint]
	ciliumEndpointSliceResource resource.Resource[*v2alpha1.CiliumEndpointSlice]
	endpointRevalidators        []membership.EndpointRevalidator
	membership                  *membership.Registry

	// Re-admission of restored Required endpoints runs after the initial ZDS
	// snapshot is seeded and stops with the reconciler.
	restoreCancel context.CancelFunc
	restoreWG     sync.WaitGroup
	// restoreBackoff is the first retry delay (restoredReadmissionInitialBackoff
	// when zero); it doubles up to restoredReadmissionMaxBackoff.
	restoreBackoff time.Duration
}

func NewEnrollmentReconciler(cfg params) (reconciler.Operations[*table.EnrolledNamespace], error) {
	if !cfg.Config.EnableZTunnel {
		return nil, nil
	}
	if cfg.Config.RequireMTLS && cfg.EndpointDeletionCleaner == nil {
		return nil, fmt.Errorf("strict ztunnel enrollment requires deleted-endpoint cleanup")
	}
	if cfg.Config.RequireMTLS && (cfg.Membership == nil || len(cfg.EndpointRevalidators) == 0) {
		return nil, fmt.Errorf("strict ztunnel enrollment requires membership registry and endpoint revalidator")
	}

	ops := &EnrollmentReconciler{
		logger:                      cfg.Logger,
		db:                          cfg.DB,
		enrolledNamespaceTable:      cfg.EnrolledNamespaceTable,
		endpointManager:             cfg.EndpointManager,
		endpointEnroller:            cfg.EndpointEnroller,
		endpointDeletionCleaner:     cfg.EndpointDeletionCleaner,
		strictCreationAdmission:     cfg.Config.RequireMTLS,
		restorerPromise:             cfg.RestorerPromise,
		endpointEventCh:             cfg.EndpointEventChannel,
		ciliumEndpointResource:      cfg.CiliumEndpointResource,
		ciliumEndpointSliceResource: cfg.CiliumEndpointSliceResource,
		endpointRevalidators:        cfg.EndpointRevalidators,
		membership:                  cfg.Membership,
	}
	cfg.Lifecycle.Append(ops)
	return ops, nil
}

// emitEndpointEvents sends endpoint events for all CiliumEndpoints/CiliumEndpointSlices
// in the given namespace to the xDS server with the specified event type.
func (ops *EnrollmentReconciler) emitEndpointEvents(ctx context.Context, namespace string, eventType xds.EndpointEventType) error {
	if option.Config.EnableCiliumEndpointSlice {
		cesStore, err := ops.ciliumEndpointSliceResource.Store(ctx)
		if err != nil {
			return fmt.Errorf("failed to get CiliumEndpointSlice store: %w", err)
		}
		slices, err := cesStore.ByIndex(k8s.NamespaceIndex, namespace)
		if err != nil {
			return fmt.Errorf("failed to get CiliumEndpointSlices by namespace index: %w", err)
		}

		for _, ces := range slices {
			for _, coreCep := range ces.Endpoints {
				cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&coreCep, ces.Namespace)
				select {
				case ops.endpointEventCh <- &xds.EndpointEvent{
					Type:           eventType,
					CiliumEndpoint: cep,
				}:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		return nil
	}

	cepStore, err := ops.ciliumEndpointResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoint store from K8sCiliumEndpointsWatcher: %w", err)
	}
	ceps, err := cepStore.ByIndex(k8s.NamespaceIndex, namespace)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoints by namespace index: %w", err)
	}
	for _, cep := range ceps {
		select {
		case ops.endpointEventCh <- &xds.EndpointEvent{
			Type:           eventType,
			CiliumEndpoint: cep,
		}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (ops *EnrollmentReconciler) Update(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	// Enroll all endpoints in this namespace
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	var strictErrs []error
	for _, ep := range endpoints {
		if ep.GetK8sPodUID() == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		if ops.strictCreationAdmission {
			// One endpoint that cannot be admitted stays quarantined; it does
			// not stop the others, and a retry re-admits only endpoints whose
			// admission no longer verifies.
			if err := ops.ensureEnrolledEndpoint(ctx, ep); err != nil {
				strictErrs = append(strictErrs, fmt.Errorf("revalidating enrolled endpoint %s/%s: %w", ep.GetK8sNamespace(), ep.GetK8sPodName(), err))
			}
			continue
		}
		err := ops.endpointEnroller.EnrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to enroll endpoint to ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
	}
	if err := errors.Join(strictErrs...); err != nil {
		return err
	}
	// Do not publish local xDS workload state until strict admission has
	// revalidated the endpoint and completed fresh capture plus ZDS ACK.
	if err := ops.emitEndpointEvents(ctx, ns.Name, xds.CREATE); err != nil {
		return err
	}
	ops.logger.Info("Enrolled all endpoints in namespace", logfields.K8sNamespace, ns.Name)
	return nil
}

func (ops *EnrollmentReconciler) Delete(ctx context.Context, txn statedb.ReadTxn, rev statedb.Revision, ns *table.EnrolledNamespace) error {
	if ops.strictCreationAdmission {
		endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
		if len(endpoints) != 0 {
			for _, ep := range endpoints {
				if ref, state, ok := ops.membership.CurrentForPodUID(ep.GetK8sPodUID()); ok &&
					state.EndpointID == ep.GetID16() && ref.Key.NamespaceUID == ns.UID {
					ops.membership.InvalidateCapture(ref)
					ops.publishRevokedMembership(ep, ref)
				}
			}
			ops.logger.Warn("Strict namespace unenrollment deferred until endpoints are recreated",
				logTransitionStage, "namespace-intent-transition",
				logfields.K8sNamespace, ns.Name,
				logDesiredRevision, rev,
				logfields.LenEndpoints, len(endpoints),
			)
			return zds.ErrStrictLiveUnenrollment
		}
		// Exact sandbox deletion owns retirement, never namespace-name release.
		return nil
	}
	endpoints := ops.endpointManager.GetEndpointsByNamespace(ns.Name)
	for _, ep := range endpoints {
		if ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		err := ops.endpointEnroller.DisenrollEndpoint(ep)
		if err != nil {
			ops.logger.Error("Failed to disenroll endpoint from ztunnel",
				logfields.K8sNamespace, ns.Name,
				logfields.Pod, ep.K8sPodName,
				logfields.Error, err,
			)
			return err
		}
	}

	if err := ops.emitEndpointEvents(ctx, ns.Name, xds.REMOVED); err != nil {
		return err
	}

	ops.logger.Info("Disenrolled all endpoints in namespace",
		logfields.K8sNamespace, ns.Name,
	)
	return nil
}

// Prune unexpected entries.
func (ops *EnrollmentReconciler) Prune(ctx context.Context, txn statedb.ReadTxn, objects iter.Seq2[*table.EnrolledNamespace, statedb.Revision]) error {
	return nil
}

var _ reconciler.Operations[*table.EnrolledNamespace] = &EnrollmentReconciler{}

// isZtunnelPod returns true if the endpoint is a ztunnel pod.
// This checks for the "app=ztunnel-cilium" label that is set on ztunnel pods.
func isZtunnelPod(ep *endpoint.Endpoint) bool {
	labels := ep.GetLabels()
	if label, ok := labels["k8s:app"]; ok {
		return label.Value == "ztunnel-cilium"
	}
	return false
}

func (ops *EnrollmentReconciler) Start(ctx cell.HookContext) error {
	_, initialized := ops.enrolledNamespaceTable.Initialized(ops.db.ReadTxn())
	select {
	case <-ctx.Done():
		ops.logger.Info("Stopping reconciler")
		return nil
	case <-initialized:
	}
	ops.logger.Info("EnrolledNamespace table initialized")

	restorer, err := ops.restorerPromise.Await(ctx)
	if err != nil {
		return fmt.Errorf("failed to await restorer: %w", err)
	}
	// Wait for endpoint restore to complete before getting endpoints.
	// This is to ensure that we don't miss any endpoints that are restored from disk.
	if err := restorer.WaitForEndpointRestore(ctx); err != nil {
		return fmt.Errorf("failed to wait for endpoint restore: %w", err)
	}

	ops.endpointManager.Subscribe(ops)
	// Get endpoints for initial snapshot
	endpoints := ops.endpointManager.GetEndpoints()
	endpointsToEnroll := make([]*endpoint.Endpoint, 0, len(endpoints))
	var restoredRequired []*endpoint.Endpoint
	for _, ep := range endpoints {
		epNamespace := ep.GetK8sNamespace()
		// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
		if epNamespace == "" || ep.GetK8sPodUID() == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
			continue
		}
		// Check if namespace is enrolled.
		txn := ops.db.ReadTxn()
		_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespaceByName(epNamespace))
		if ops.strictCreationAdmission {
			// Re-admission sends a ZDS ADD, and the ZDS consumer only starts
			// after the snapshot below is seeded. Quarantine now; re-admit after
			// seeding. A restored Required endpoint is never seeded: its earlier
			// ADD belongs to no live execution of this agent.
			needed, err := ops.restrictRestoredEndpoint(ctx, ep, found)
			if err != nil {
				return fmt.Errorf("restricting restored endpoint %s/%s: %w", ep.GetK8sNamespace(), ep.GetK8sPodName(), err)
			}
			if needed {
				restoredRequired = append(restoredRequired, ep)
			}
			continue
		}
		if !found {
			ops.logger.Info("Skipping enrollment of endpoint in unenrolled namespace",
				logfields.K8sNamespace, epNamespace,
				logfields.Pod, ep.K8sPodName,
			)
			continue
		}
		endpointsToEnroll = append(endpointsToEnroll, ep)
	}
	ops.endpointEnroller.SeedInitialSnapshot(endpointsToEnroll...)
	ops.readmitRestoredRequired(restoredRequired)
	ops.logger.Info("Enrollment reconciler initialized")
	return nil
}

func (ops *EnrollmentReconciler) Stop(cell.HookContext) error {
	ops.endpointManager.Unsubscribe(ops)
	if ops.restoreCancel != nil {
		ops.restoreCancel()
	}
	ops.restoreWG.Wait()
	ops.logger.Info("Stopping reconciler")
	return nil
}

func (ops *EnrollmentReconciler) restrictRestoredEndpoint(ctx context.Context, ep *endpoint.Endpoint, namespaceEnrolled bool) (bool, error) {
	needed := false
	for _, revalidator := range ops.endpointRevalidators {
		if revalidator == nil {
			return false, fmt.Errorf("endpoint revalidator is nil")
		}
		restricted, err := revalidator.RestrictRestoredEndpoint(ctx, ep, namespaceEnrolled)
		if err != nil {
			return false, err
		}
		needed = needed || restricted
	}
	return needed, nil
}

const (
	restoredReadmissionInitialBackoff = time.Second
	restoredReadmissionMaxBackoff     = 30 * time.Second
)

// readmitRestoredRequired re-admits each restored Required endpoint through
// the live ZDS connection. Each endpoint retries independently, so one that
// cannot be admitted never delays another; it stays quarantined until it is.
func (ops *EnrollmentReconciler) readmitRestoredRequired(endpoints []*endpoint.Endpoint) {
	if len(endpoints) == 0 {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	ops.restoreCancel = cancel
	for _, ep := range endpoints {
		ops.restoreWG.Go(func() { ops.readmitRestored(ctx, ep) })
	}
}

func (ops *EnrollmentReconciler) readmitRestored(ctx context.Context, ep *endpoint.Endpoint) {
	started := time.Now()
	backoff := ops.restoreBackoff
	if backoff == 0 {
		backoff = restoredReadmissionInitialBackoff
	}
	for attempt := 1; ; attempt++ {
		if ctx.Err() != nil || !ep.IsAlive() {
			return
		}
		err := ops.readmitOnce(ctx, ep)
		if err == nil {
			ops.logger.Info("Re-admitted restored Required endpoint",
				logTransitionStage, "restored-readmission",
				logfields.EndpointID, ep.GetID16(),
				logfields.K8sNamespace, ep.GetK8sNamespace(),
				logfields.Pod, ep.GetK8sPodName(),
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(started))
			return
		}
		ops.logger.Warn("Restored Required endpoint re-admission failed; endpoint stays quarantined",
			logTransitionStage, "restored-readmission",
			logfields.EndpointID, ep.GetID16(),
			logfields.K8sNamespace, ep.GetK8sNamespace(),
			logfields.Pod, ep.GetK8sPodName(),
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(started),
			logfields.Backoff, backoff,
			logfields.Error, err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(2*backoff, restoredReadmissionMaxBackoff)
	}
}

// readmitOnce makes sure a restored endpoint is admitted. When another path
// (namespace enrollment) admitted it first, this verifies and does nothing.
func (ops *EnrollmentReconciler) readmitOnce(ctx context.Context, ep *endpoint.Endpoint) error {
	for _, revalidator := range ops.endpointRevalidators {
		if revalidator == nil {
			return fmt.Errorf("endpoint revalidator is nil")
		}
		if err := revalidator.EnsureEndpoint(ctx, ep, membership.StageRestoredReadmission); err != nil {
			return err
		}
	}
	return nil
}

func (ops *EnrollmentReconciler) EndpointCreated(ep *endpoint.Endpoint) {
	if ops.strictCreationAdmission {
		// The synchronous Endpoint API gate owns new-pod admission. This void
		// callback cannot propagate errors and must not consume its time budget.
		return
	}
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespaceByName(epNamespace))
	if !found {
		ops.logger.Debug("Skipping enrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.EnrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to enroll endpoint to ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
	}
}

func (ops *EnrollmentReconciler) EndpointDeleted(ep *endpoint.Endpoint, _ endpoint.DeleteConfig) {
	if ops.strictCreationAdmission {
		if ep.K8sUID == "" && ep.GetK8sNamespace() == "" && ep.GetK8sPodName() == "" {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ref, state, ok := ops.membership.CurrentForPodUID(ep.GetK8sPodUID())
		if !ok || state.EndpointID != ep.GetID16() || state.NetnsPath != ep.GetContainerNetnsPath() {
			// Retire stale replay intent without granting membership retirement.
			// A generic cleanup ACK is never a native drain receipt.
			if err := ops.endpointDeletionCleaner.CleanupDeletedEndpointContext(ctx, ep); err != nil {
				ops.logger.Error("Unbound endpoint cleanup incomplete; membership retained", logfields.Error, err)
			}
			return
		}
		generation, began := ops.membership.BeginDrain(ref)
		if !began {
			return
		}
		ops.publishRevokedMembership(ep, ref)
		cleaner, ok := ops.endpointDeletionCleaner.(zds.EndpointDrainCleaner)
		if !ok {
			ops.logger.Error("Native typed drain cleaner unavailable; membership retained", logfields.EndpointID, ep.GetID16())
			// Compatibility cleanup may retire replay intent, but never state.
			if err := ops.endpointDeletionCleaner.CleanupDeletedEndpointContext(ctx, ep); err != nil {
				ops.logger.Error("Compatibility cleanup incomplete; membership retained", logfields.Error, err)
			}
			return
		}
		receipt, err := cleaner.DrainDeletedEndpointContext(ctx, ep, ref, generation)
		if err == nil {
			err = receipt.Retire(ops.membership, ref, generation)
		}
		if err != nil {
			ops.logger.Error("Native workload retirement incomplete; capture retained",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
		}

		return
	}
	epNamespace := ep.GetK8sNamespace()
	// If namespace is not enrolled or endpoint has no netns path or is ztunnel itself, skip
	if epNamespace == "" || ep.GetContainerNetnsPath() == "" || isZtunnelPod(ep) {
		return
	}
	// Check if namespace is enrolled
	txn := ops.db.ReadTxn()
	_, _, found := ops.enrolledNamespaceTable.Get(txn, table.EnrolledNamespaceByName(epNamespace))
	if !found {
		ops.logger.Debug("Skipping disenrollment of endpoint in unenrolled namespace",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
		)
		return
	}
	err := ops.endpointEnroller.DisenrollEndpoint(ep)
	if err != nil {
		ops.logger.Error("Failed to disenroll endpoint from ztunnel",
			logfields.K8sNamespace, epNamespace,
			logfields.Pod, ep.K8sPodName,
			logfields.Error, err,
		)
	}
}

func (ops *EnrollmentReconciler) publishRevokedMembership(ep *endpoint.Endpoint, ref membership.Reference) {
	previous, _ := ep.GetZtunnelMembership()
	state, ok := ops.membership.Publication(ref)
	if !ok {
		state = membership.Publication{Version: 1, Epoch: ref.Epoch, State: membership.PublicationRequired}
	}
	ep.SetZtunnelMembership(endpoint.ZtunnelMembership{
		Version:        state.Version,
		Revision:       state.Revision,
		Epoch:          state.Epoch,
		Generation:     state.Generation,
		State:          state.State,
		NamespaceUID:   ref.Key.NamespaceUID,
		NodeName:       previous.NodeName,
		ServiceAccount: previous.ServiceAccount,
	})
}

// ensureEnrolledEndpoint makes sure an endpoint of an enrolled namespace is
// admitted. It re-admits only when the current admission no longer verifies:
// re-admission quarantines the endpoint and starts a new capture generation.
func (ops *EnrollmentReconciler) ensureEnrolledEndpoint(ctx context.Context, ep *endpoint.Endpoint) error {
	for _, revalidator := range ops.endpointRevalidators {
		if revalidator == nil {
			return fmt.Errorf("endpoint revalidator is nil")
		}
		should, err := revalidator.ShouldRevalidate(ctx, ep, true)
		if err != nil {
			return err
		}
		if !should {
			continue
		}
		if err := revalidator.EnsureEndpoint(ctx, ep, membership.StageNamespaceEnrollment); err != nil {
			return err
		}
	}
	return nil
}

func (ops *EnrollmentReconciler) EndpointRestored(ep *endpoint.Endpoint) {}

var _ cell.HookInterface = &EnrollmentReconciler{}
var _ endpointmanager.Subscriber = &EnrollmentReconciler{}
