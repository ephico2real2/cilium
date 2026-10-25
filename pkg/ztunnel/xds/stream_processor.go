// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sort"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

const logStage = "stage"

const maxEndpointEventsPerBatch = 256

type StreamProcessorParams struct {
	// The backing gRPC bidi stream initiated by zTunnel
	Stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	// Channel where the StreamProcessor listens for new DeltaDiscoveryRequest.
	// this is fed directly from Stream.
	StreamRecv chan *v3.DeltaDiscoveryRequest
	// Channel where the StreamProcessor listens for Endpoint event.
	// this is fed by subscribing to EndpointManager.
	EndpointEventRecv chan *EndpointEvent
	// Reference to agent's CEP watcher and resource cache.
	// This will be the source of truth for serving WDS API.
	K8sCiliumEndpointsWatcher *watchers.K8sCiliumEndpointsWatcher
	DB                        *statedb.DB
	EnrolledNamespaceTable    statedb.RWTable[*table.EnrolledNamespace]
	Log                       *slog.Logger
	Metrics                   *Metrics
	Authorizations            *AuthorizationPolicies
	TrustDomain               string
	// ClusterName is the canonical local name expected by ztunnel's cluster inventory.
	ClusterName               string
	RequireMTLS               bool
	EffectivePolicyQuarantine bool
	IssuerProfile             *issuerProfileSource
	// NodeNames binds Kubernetes Node names from native node discovery.
	NodeNames nodeNameResolver
	// RemotePeers holds authenticated remote ClusterMesh workload snapshots
	// (nil: remote workloads are not projected). RemoteTrust binds each peer
	// to its trust domain from the validated issuer profile.
	RemotePeers *remote.PeerSnapshotStore
	RemoteTrust *remoteTrustAuthority
	// PolicyOwner publishes effective policy and releases quarantine from the
	// Address and Authorization acknowledgments of this stream.
	PolicyOwner *effectivePolicyOwner
}

// StreamProcessor implements the logic for handling xDS streams to zTunnel.
// It is abstracted away from the primary stream initialization handler to
// promote decoupling and the handling multiple streams without a shared set of
// channels being required on the Server object.
type StreamProcessor struct {
	stream                    v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	streamRecv                chan *v3.DeltaDiscoveryRequest
	endpointRecv              chan *EndpointEvent
	expectedNonce             map[string]struct{}
	log                       *slog.Logger
	endpointSource            EndpointEventSource
	db                        *statedb.DB
	enrolledNamespaceTable    statedb.RWTable[*table.EnrolledNamespace]
	metrics                   *Metrics
	authorizations            *AuthorizationPolicies
	trustDomain               string
	clusterName               string
	requireMTLS               bool
	effectivePolicyQuarantine bool
	quarantineResources       map[string]string
	issuerProfile             *issuerProfileSource
	nodeNames                 nodeNameResolver
	// Node bindings published on this stream (by Pod UID) and the native
	// table watch from the read that last verified all of them. The pending
	// pair is staged by bindNodeNames and committed after a successful send.
	boundNodeNames       map[string]nodeBinding
	nodeNameWatch        <-chan struct{}
	pendingNodeNames     map[string]nodeBinding
	pendingNodeNameWatch <-chan struct{}
	// Remote workload projection (one per stream) and the stream's index of
	// published local workload addresses.
	remotePeers        *remote.PeerSnapshotStore
	remoteTrust        *remoteTrustAuthority
	remote             *remoteStreamState
	remoteInitial      *remoteDelta
	remoteInitialTrust remoteTrustView
	localAddresses     map[netip.Addr]string
	// Effective policy evidence of this stream: its ADS generation, the
	// Address versions awaiting ACK by nonce, the last sent local workload
	// resources, and Authorization cache versions by nonce.
	policyOwner     *effectivePolicyOwner
	adsGeneration   uint64
	addressEvidence map[string][]addressEvidence
	localResources  map[string]*v3.Resource
	authMu          lock.Mutex
	authSent        map[string]uint64
	authAcked       uint64
}

type addressEvidence struct {
	ref     membership.Reference
	version uint64
}

// CiliumEndpointsWatcher defines the interface for watching CiliumEndpoints and CiliumEndpointSlices.
// This interface enables mocking for testing purposes.
type CiliumEndpointsWatcher interface {
	GetCiliumEndpointResource() resource.Resource[*types.CiliumEndpoint]
	GetCiliumEndpointSliceResource() resource.Resource[*v2alpha1.CiliumEndpointSlice]
}

// Ensure watchers.K8sCiliumEndpointsWatcher implements CiliumEndpointsWatcher.
var _ CiliumEndpointsWatcher = (*watchers.K8sCiliumEndpointsWatcher)(nil)

// EndpointSource provides data for XDS server from different data sources in the agent.
type EndpointSource struct {
	k8sCiliumEndpointsWatcher CiliumEndpointsWatcher
	sp                        *StreamProcessor
}

func NewEndpointSource(k *watchers.K8sCiliumEndpointsWatcher, sp *StreamProcessor) *EndpointSource {
	return &EndpointSource{
		k8sCiliumEndpointsWatcher: k,
		sp:                        sp,
	}
}

// isNamespaceEnrolled checks if the given namespace is enrolled for ztunnel processing.
func (es *EndpointSource) isNamespaceEnrolled(namespace string) bool {
	txn := es.sp.db.ReadTxn()
	_, _, found := es.sp.enrolledNamespaceTable.Get(txn, table.EnrolledNamespaceByName(namespace))
	return found
}

// Interface different data sources need to implement for usage with StreamProcessor.
type EndpointEventSource interface {
	// SubscribeToEndpointEvents subscribes to endpoint events.
	// Pre-Sync replay events are buffered and sent as an EndpointEventCollection
	// on syncCh. Post-Sync events are forwarded to endpointRecv individually.
	// syncCh is closed when the subscription ends.
	SubscribeToEndpointEvents(ctx context.Context, syncCh chan<- EndpointEventCollection)
}

func NewStreamProcessor(params *StreamProcessorParams) *StreamProcessor {
	metrics := params.Metrics
	if metrics == nil {
		metrics = NewMetrics()
	}
	authorizations := params.Authorizations
	if authorizations == nil {
		authorizations = NewAuthorizationPolicies(params.Log, metrics)
	}
	sp := &StreamProcessor{
		stream:                    params.Stream,
		streamRecv:                params.StreamRecv,
		endpointRecv:              params.EndpointEventRecv,
		log:                       params.Log,
		expectedNonce:             make(map[string]struct{}),
		db:                        params.DB,
		enrolledNamespaceTable:    params.EnrolledNamespaceTable,
		metrics:                   metrics,
		authorizations:            authorizations,
		trustDomain:               params.TrustDomain,
		clusterName:               params.ClusterName,
		requireMTLS:               params.RequireMTLS,
		effectivePolicyQuarantine: params.EffectivePolicyQuarantine,
		issuerProfile:             params.IssuerProfile,
		nodeNames:                 params.NodeNames,
		remotePeers:               params.RemotePeers,
		remoteTrust:               params.RemoteTrust,
		policyOwner:               params.PolicyOwner,
	}
	sp.endpointSource = NewEndpointSource(params.K8sCiliumEndpointsWatcher, sp)
	return sp
}

// convertCESToEndpointMap converts a CiliumEndpointSlice to a map of CiliumEndpoints
// keyed by namespace/name for easy lookup and comparison.
func convertCESToEndpointMap(ces *v2alpha1.CiliumEndpointSlice) map[string]*types.CiliumEndpoint {
	result := make(map[string]*types.CiliumEndpoint, len(ces.Endpoints))
	for _, coreCep := range ces.Endpoints {
		cep := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&coreCep, ces.Namespace)
		cepName := cep.Namespace + "/" + cep.Name
		result[cepName] = cep
	}
	return result
}

func validateStrictCESKeys(ces *v2alpha1.CiliumEndpointSlice) error {
	if ces == nil {
		return wrapValidationError(errInvalidWorkloadData, "missing CiliumEndpointSlice")
	}
	seen := make(map[string]struct{}, len(ces.Endpoints))
	for i := range ces.Endpoints {
		coreCEP := &ces.Endpoints[i]
		if coreCEP.Name == "" {
			return wrapValidationError(errInvalidWorkloadData, "CiliumEndpointSlice %q contains an unnamed endpoint", ces.Name)
		}
		if _, exists := seen[coreCEP.Name]; exists {
			return wrapValidationError(errInvalidWorkloadData, "CiliumEndpointSlice %q contains duplicate endpoint %q", ces.Name, coreCEP.Name)
		}
		seen[coreCEP.Name] = struct{}{}
	}
	return nil
}

// computeEndpointDiff compares old and new endpoint maps and returns lists of
// endpoints that were added, updated, or removed.
func computeEndpointDiff(oldCEPs, newCEPs map[string]*types.CiliumEndpoint) (added, updated, removed []*types.CiliumEndpoint) {
	// Find removed endpoints (in old but not in new)
	for cepName, oldCEP := range oldCEPs {
		if _, exists := newCEPs[cepName]; !exists {
			removed = append(removed, oldCEP)
		}
	}

	// Find new or updated endpoints
	for cepName, newCEP := range newCEPs {
		if oldCEP, exists := oldCEPs[cepName]; !exists {
			// New endpoint
			added = append(added, newCEP)
		} else if !oldCEP.DeepEqual(newCEP) {
			oldUID := (&EndpointEvent{CiliumEndpoint: oldCEP}).getPodUID()
			newUID := (&EndpointEvent{CiliumEndpoint: newCEP}).getPodUID()
			if oldUID != "" && newUID != "" && oldUID != newUID {
				// Delta resources are keyed by Pod UID, not CEP name. A Pod
				// recreated under the same CEP key must retire the old identity.
				removed = append(removed, oldCEP)
				added = append(added, newCEP)
			} else {
				// Updates with the same Pod UID are treated as CREATE.
				updated = append(updated, newCEP)
			}
		}
	}

	return added, updated, removed
}

// handleCESUpsert processes an upsert event for a CiliumEndpointSlice.
// Returns an EndpointEventCollection containing the diff events.
func (es *EndpointSource) handleCESUpsert(ces *v2alpha1.CiliumEndpointSlice, cesCache map[resource.Key]map[string]*types.CiliumEndpoint, key resource.Key) EndpointEventCollection {
	oldCEPs := cesCache[key]
	if oldCEPs == nil {
		oldCEPs = make(map[string]*types.CiliumEndpoint)
	}

	newCEPs := convertCESToEndpointMap(ces)
	added, updated, removed := computeEndpointDiff(oldCEPs, newCEPs)

	var events EndpointEventCollection
	events.AppendEndpoints(REMOVED, removed)
	events.AppendEndpoints(CREATE, added)
	events.AppendEndpoints(CREATE, updated) // Updates are treated as CREATE

	cesCache[key] = newCEPs
	return events
}

// handleCESDelete processes a delete event for a CiliumEndpointSlice.
// Returns an EndpointEventCollection containing REMOVED events for all endpoints.
func (es *EndpointSource) handleCESDelete(ces *v2alpha1.CiliumEndpointSlice, cesCache map[resource.Key]map[string]*types.CiliumEndpoint, key resource.Key) EndpointEventCollection {
	endpoints := cesCache[key]
	if endpoints == nil {
		endpoints = convertCESToEndpointMap(ces)
	}
	events := make(EndpointEventCollection, 0, len(endpoints))
	for _, ep := range endpoints {
		events = append(events, &EndpointEvent{Type: REMOVED, CiliumEndpoint: ep})
	}
	delete(cesCache, key)
	return events
}

func (es *EndpointSource) SubscribeToEndpointEvents(ctx context.Context, syncCh chan<- EndpointEventCollection) {
	defer close(syncCh)

	if option.Config.EnableCiliumEndpointSlice {
		newSliceEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointSliceResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
		// Keep track of CEPs in each CES to detect deletions on updates
		cesCache := make(map[resource.Key]map[string]*types.CiliumEndpoint)
		sourceErrors := make(map[resource.Key]error)
		var synced bool
		var initialBatch EndpointEventCollection

		for e := range newSliceEvents {
			if ctx.Err() != nil {
				e.Done(nil)
				return
			}
			if e.Kind == resource.Sync {
				if !synced {
					if es.sp.requireMTLS {
						initialBatch = make(EndpointEventCollection, 0)
						keys := make([]resource.Key, 0, len(cesCache))
						for key := range cesCache {
							keys = append(keys, key)
						}
						sort.Slice(keys, func(i, j int) bool {
							if keys[i].Namespace != keys[j].Namespace {
								return keys[i].Namespace < keys[j].Namespace
							}
							return keys[i].Name < keys[j].Name
						})
						for _, key := range keys {
							endpoints := cesCache[key]
							names := make([]string, 0, len(endpoints))
							for name := range endpoints {
								names = append(names, name)
							}
							sort.Strings(names)
							for _, name := range names {
								initialBatch = append(initialBatch, &EndpointEvent{Type: CREATE, CiliumEndpoint: endpoints[name]})
							}
						}
						errorKeys := make([]resource.Key, 0, len(sourceErrors))
						for key := range sourceErrors {
							errorKeys = append(errorKeys, key)
						}
						sort.Slice(errorKeys, func(i, j int) bool {
							if errorKeys[i].Namespace != errorKeys[j].Namespace {
								return errorKeys[i].Namespace < errorKeys[j].Namespace
							}
							return errorKeys[i].Name < errorKeys[j].Name
						})
						for _, key := range errorKeys {
							err := fmt.Errorf("invalid CiliumEndpointSlice %s/%s: %w", key.Namespace, key.Name, sourceErrors[key])
							initialBatch = append(initialBatch, strictEndpointSourceError(err))
						}
					}
					syncCh <- initialBatch
					synced = true
				}
				e.Done(nil)
				continue
			}
			if e.Object == nil {
				e.Done(nil)
				continue
			}

			if !synced && es.sp.requireMTLS {
				switch e.Kind {
				case resource.Upsert:
					if es.isNamespaceEnrolled(e.Object.Namespace) {
						if err := validateStrictCESKeys(e.Object); err != nil {
							delete(cesCache, e.Key)
							sourceErrors[e.Key] = err
							if es.sp.log != nil {
								es.sp.log.Error("Rejecting malformed strict CiliumEndpointSlice",
									logfields.K8sNamespace, e.Key.Namespace,
									logfields.Name, e.Key.Name,
									logfields.Error, err,
								)
							}
							e.Done(err)
							continue
						}
						cesCache[e.Key] = convertCESToEndpointMap(e.Object)
						delete(sourceErrors, e.Key)
					} else {
						delete(cesCache, e.Key)
						delete(sourceErrors, e.Key)
					}
				case resource.Delete:
					delete(cesCache, e.Key)
					delete(sourceErrors, e.Key)
				}
				e.Done(nil)
				continue
			}

			if synced && es.sp.requireMTLS {
				var events EndpointEventCollection
				var sourceErr error
				switch e.Kind {
				case resource.Upsert:
					if es.isNamespaceEnrolled(e.Object.Namespace) {
						if err := validateStrictCESKeys(e.Object); err != nil {
							sourceErr = err
							wrappedErr := fmt.Errorf("invalid CiliumEndpointSlice %s/%s: %w", e.Key.Namespace, e.Key.Name, err)
							events = append(events, strictEndpointSourceError(wrappedErr))
							if es.sp.log != nil {
								es.sp.log.Error("Rejecting malformed strict CiliumEndpointSlice",
									logfields.K8sNamespace, e.Key.Namespace,
									logfields.Name, e.Key.Name,
									logfields.Error, err,
								)
							}
						} else {
							events = es.handleCESUpsert(e.Object, cesCache, e.Key)
						}
					} else {
						for _, endpoint := range cesCache[e.Key] {
							events = append(events, &EndpointEvent{Type: REMOVED, CiliumEndpoint: endpoint})
						}
						delete(cesCache, e.Key)
					}
				case resource.Delete:
					events = es.handleCESDelete(e.Object, cesCache, e.Key)
				}
				events.EmitTo(ctx, es.sp.endpointRecv)
				e.Done(sourceErr)
				continue
			}

			if !es.isNamespaceEnrolled(e.Object.Namespace) {
				es.sp.log.Debug("Skipping processing of CiliumEndpointSlice in unenrolled namespace",
					logfields.K8sNamespace, e.Object.Namespace,
					logfields.Name, e.Object.GetName(),
				)
				e.Done(nil)
				continue
			}

			var events EndpointEventCollection
			switch e.Kind {
			case resource.Upsert:
				events = es.handleCESUpsert(e.Object, cesCache, e.Key)
			case resource.Delete:
				events = es.handleCESDelete(e.Object, cesCache, e.Key)
			}

			if !synced {
				initialBatch = append(initialBatch, events...)
			} else {
				events.EmitTo(ctx, es.sp.endpointRecv)
			}

			e.Done(nil)
		}
		return
	}

	// TODO(hemanthmalla): How should retries be configured here ?
	newEvents := es.k8sCiliumEndpointsWatcher.GetCiliumEndpointResource().Events(ctx, resource.WithErrorHandler(resource.AlwaysRetry))
	var synced bool
	var initialBatch EndpointEventCollection
	initialCEPs := make(map[resource.Key]*types.CiliumEndpoint)

	for e := range newEvents {
		if ctx.Err() != nil {
			e.Done(nil)
			return
		}
		if e.Kind == resource.Sync {
			if !synced {
				if es.sp.requireMTLS {
					keys := make([]resource.Key, 0, len(initialCEPs))
					for key := range initialCEPs {
						keys = append(keys, key)
					}
					sort.Slice(keys, func(i, j int) bool {
						if keys[i].Namespace != keys[j].Namespace {
							return keys[i].Namespace < keys[j].Namespace
						}
						return keys[i].Name < keys[j].Name
					})
					initialBatch = make(EndpointEventCollection, 0, len(keys))
					for _, key := range keys {
						initialBatch = append(initialBatch, &EndpointEvent{Type: CREATE, CiliumEndpoint: initialCEPs[key]})
					}
				}
				syncCh <- initialBatch
				synced = true
			}
			e.Done(nil)
			continue
		}
		if e.Object == nil {
			e.Done(nil)
			continue
		}

		if !synced && es.sp.requireMTLS {
			key := e.Key
			switch e.Kind {
			case resource.Upsert:
				if es.isNamespaceEnrolled(e.Object.GetNamespace()) {
					initialCEPs[key] = e.Object.DeepCopy()
				} else {
					delete(initialCEPs, key)
				}
			case resource.Delete:
				delete(initialCEPs, key)
			}
			e.Done(nil)
			continue
		}

		if synced && es.sp.requireMTLS {
			key := e.Key
			var events EndpointEventCollection
			switch e.Kind {
			case resource.Upsert:
				previous, found := initialCEPs[key]
				if !es.isNamespaceEnrolled(e.Object.GetNamespace()) {
					if found {
						events = append(events, &EndpointEvent{Type: REMOVED, CiliumEndpoint: previous})
						delete(initialCEPs, key)
					}
				} else {
					current := e.Object.DeepCopy()
					oldUID := ""
					if found {
						oldUID = (&EndpointEvent{CiliumEndpoint: previous}).getPodUID()
					}
					newUID := (&EndpointEvent{CiliumEndpoint: current}).getPodUID()
					if found && oldUID != "" && newUID != "" && oldUID != newUID {
						events = append(events, &EndpointEvent{Type: REMOVED, CiliumEndpoint: previous})
					}
					events = append(events, &EndpointEvent{Type: CREATE, CiliumEndpoint: current})
					initialCEPs[key] = current
				}
			case resource.Delete:
				previous, found := initialCEPs[key]
				if !found {
					previous = e.Object
				}
				if previous != nil {
					events = append(events, &EndpointEvent{Type: REMOVED, CiliumEndpoint: previous})
				}
				delete(initialCEPs, key)
			}
			events.EmitTo(ctx, es.sp.endpointRecv)
			e.Done(nil)
			continue
		}

		if !es.isNamespaceEnrolled(e.Object.GetNamespace()) {
			es.sp.log.Debug("Skipping processing of CiliumEndpoint in unenrolled namespace",
				logfields.K8sNamespace, e.Object.GetNamespace(),
				logfields.Name, e.Object.GetName(),
			)
			e.Done(nil)
			continue
		}

		var eventType EndpointEventType
		switch e.Kind {
		case resource.Upsert:
			eventType = CREATE
		case resource.Delete:
			eventType = REMOVED
		}

		event := &EndpointEvent{Type: eventType, CiliumEndpoint: e.Object}
		if !synced {
			initialBatch = append(initialBatch, event)
		} else {
			select {
			case es.sp.endpointRecv <- event:
			case <-ctx.Done():
				e.Done(nil)
				return
			}
		}
		e.Done(nil)
	}
}

// handleAddressTypeURL handles a subscription for xdsTypeURLAddress type URLs.
//
// On receipt of this request from zTunnel we subscribe our StreamProcessor to
// endpoint events and wait for the initial sync to complete. The subscription
// buffers all replayed events until Sync, then delivers them as a single
// atomic xDS response so ztunnel receives the full snapshot before becoming
// ready.
func (sp *StreamProcessor) handleAddressTypeURL(req *v3.DeltaDiscoveryRequest) error {
	// this must be a request to subscribe to all Address resources.
	//
	// in Istio an Address resource is either a Workload or a Service.
	// For now, we expect Cilium's socket-lb to be handling service translation,
	// so we will only send Workload events to support pod-to-pod proxying.
	if len(req.ResourceNamesSubscribe) != 0 && len(req.ResourceNamesUnsubscribe) != 0 {
		return wrapValidationError(errInvalidDiscoveryState, "unexpected resource names subscribe %v or unsubscribe %v for Address type URL",
			req.ResourceNamesSubscribe, req.ResourceNamesUnsubscribe)
	}

	ctx := sp.stream.Context()
	if sp.policyOwner != nil && sp.adsGeneration == 0 {
		sp.adsGeneration = sp.policyOwner.beginStream()
		sp.reportAuthorizationAck()
	}

	// Subscribe to endpoint events. The subscription buffers all replayed
	// events until the initial Sync, then sends the batch on syncCh.
	// Post-Sync events are forwarded to endpointRecv individually.
	syncCh := make(chan EndpointEventCollection, 1)
	go sp.endpointSource.SubscribeToEndpointEvents(ctx, syncCh)

	// Wait for the initial batch from the subscription replay so that
	// ztunnel receives all existing workloads atomically in one response.
	var collection EndpointEventCollection
	select {
	case batch, ok := <-syncCh:
		if !ok {
			if err := ctx.Err(); err != nil {
				return err
			}
			return wrapValidationError(errEndpointSourceClosed, "workload subscription ended before initial synchronization")
		}
		collection = batch
	case <-ctx.Done():
		return ctx.Err()
	}

	resp, err := sp.addressResponse(collection)
	if err != nil {
		sp.metrics.EnrollmentFailures.WithLabelValues("invalid_workload_snapshot").Inc()
		sp.log.Error("Rejecting incomplete strict workload Address snapshot",
			logStage, "xds-address-snapshot",
			logfields.Resource, xdsTypeURLAddress,
			logfields.Error, err,
		)
		return fmt.Errorf("failed to build workload Address response: %w", err)
	}
	if sp.remoteEnabled() {
		if _, err := sp.addInitialRemote(resp, time.Now()); err != nil {
			sp.log.Error("Rejecting merged local and remote workload Address snapshot",
				logStage, "xds-address-snapshot",
				logfields.Resource, xdsTypeURLAddress,
				logfields.Error, err,
			)
			return fmt.Errorf("failed to merge remote workloads: %w", err)
		}
	}
	if sp.requireMTLS {
		if err := addStrictInitialRemovals(resp, req); err != nil {
			return fmt.Errorf("failed to reconcile retained workload resources: %w", err)
		}
	}
	if err := sp.sendAddressResponse(resp, "xds-address-snapshot"); err != nil {
		return err
	}
	sp.recordAddressEvidence(resp)
	if sp.remoteEnabled() {
		if err := sp.updateLocalAddresses(resp); err != nil {
			return err
		}
		sp.commitInitialRemote(time.Now())
	}

	sp.log.Debug("initialized new stream for resource", logfields.Resource, xdsTypeURLAddress)

	return nil
}

func addStrictInitialRemovals(response *v3.DeltaDiscoveryResponse, request *v3.DeltaDiscoveryRequest) error {
	if response == nil {
		return wrapValidationError(errInvalidDiscoveryState, "missing initial workload response")
	}
	if request == nil {
		return wrapValidationError(errInvalidDiscoveryState, "missing initial workload request")
	}
	retained := make(map[string]struct{}, len(response.Resources))
	for _, resource := range response.Resources {
		if resource == nil || resource.Name == "" {
			return wrapValidationError(errInvalidDiscoveryState, "initial workload response contains an unnamed resource")
		}
		retained[resource.Name] = struct{}{}
	}
	removed := make(map[string]struct{}, len(response.RemovedResources)+len(request.InitialResourceVersions))
	for _, name := range response.RemovedResources {
		if name == "" {
			return wrapValidationError(errInvalidDiscoveryState, "initial workload response contains an empty removed name")
		}
		removed[name] = struct{}{}
	}
	for name := range request.InitialResourceVersions {
		if name == "" {
			return wrapValidationError(errInvalidDiscoveryState, "initial resource versions contain an empty workload name")
		}
		if _, exists := retained[name]; !exists {
			removed[name] = struct{}{}
		}
	}
	response.RemovedResources = response.RemovedResources[:0]
	for name := range removed {
		response.RemovedResources = append(response.RemovedResources, name)
	}
	sort.Strings(response.RemovedResources)
	return nil
}

func (sp *StreamProcessor) sendAddressResponse(response *v3.DeltaDiscoveryResponse, stage string) error {
	if response == nil || response.Nonce == "" {
		return wrapValidationError(errInvalidDiscoveryState, "cannot send an empty workload Address response or nonce")
	}
	if sp.stream == nil {
		return wrapValidationError(errInvalidDiscoveryState, "cannot send workload Address response without an xDS stream")
	}
	if err := sp.checkNodeNamesBeforeSend(); err != nil {
		if sp.log != nil {
			sp.log.Warn("Withholding workload Address response after a Kubernetes node binding changed",
				logStage, stage,
				logfields.Resource, xdsTypeURLAddress,
				logfields.Error, err,
			)
		}
		return fmt.Errorf("Kubernetes node binding changed before publication: %w", err)
	}
	if err := sp.sendAddressMessage(response, stage); err != nil {
		return err
	}
	sp.commitNodeNames()
	return nil
}

// sendAddressMessage sends one Address response on the serialized stream and
// registers its nonce. Local publications use sendAddressResponse, which also
// re-verifies and commits their Kubernetes node bindings; remote-only deltas
// carry no local node binding.
func (sp *StreamProcessor) sendAddressMessage(response *v3.DeltaDiscoveryResponse, stage string) error {
	if response == nil || response.Nonce == "" {
		return wrapValidationError(errInvalidDiscoveryState, "cannot send an empty workload Address response or nonce")
	}
	if sp.stream == nil {
		return wrapValidationError(errInvalidDiscoveryState, "cannot send workload Address response without an xDS stream")
	}
	if err := sp.stream.SendMsg(response); err != nil {
		if sp.metrics != nil {
			sp.metrics.EnrollmentFailures.WithLabelValues("send_failed").Inc()
		}
		if sp.log != nil {
			sp.log.Error("Failed to send workload Address response",
				logStage, stage,
				logfields.Resource, xdsTypeURLAddress,
				logfields.Error, err,
			)
		}
		return err
	}
	if sp.expectedNonce == nil {
		sp.expectedNonce = make(map[string]struct{})
	}
	sp.expectedNonce[response.Nonce] = struct{}{}
	return nil
}

func (sp *StreamProcessor) handleDeltaDiscoveryReq(req *v3.DeltaDiscoveryRequest) error {
	if req.TypeUrl != xdsTypeURLAddress {
		return wrapValidationError(errInvalidDiscoveryState, "unexpected type URL %q for Address handler", req.TypeUrl)
	}
	// if the delta discovery request has a nonce, this is a ack or nack.
	// In Observe mode, report a NACK and leave the stream alive for compatibility.
	// Strict mode closes the stream so ztunnel reconnects for a fresh full snapshot;
	// continuing would leave the two peers with different authorization state.
	if req.ResponseNonce != "" {
		// check if this is an expected nonce, if not, its an error
		if _, ok := sp.expectedNonce[req.ResponseNonce]; !ok {
			return wrapValidationError(errInvalidDiscoveryState, "unexpected nonce %q received", req.ResponseNonce)
		}

		// remove expected Nonce
		delete(sp.expectedNonce, req.ResponseNonce)

		if req.ErrorDetail == nil {
			sp.acknowledgeAddressEvidence(req.ResponseNonce)
		}
		if req.ErrorDetail != nil {
			sp.metrics.EnrollmentFailures.WithLabelValues("nack_received").Inc()
			sp.log.Error("Nack received from ztunnel",
				logfields.Error,
				req.ErrorDetail.Message,
				logfields.Code,
				req.ErrorDetail.Code)
			if sp.requireMTLS {
				return wrapValidationError(errInvalidDiscoveryState,
					"ztunnel rejected strict Address response with code %d", req.ErrorDetail.Code)
			}
			return nil
		}
		return nil
	}

	return sp.handleAddressTypeURL(req)
}

func (sp *StreamProcessor) handleEPEvent(epEvent *EndpointEvent) error {
	collection, err := sp.drainEndpointEvents(epEvent)
	if err != nil {
		return err
	}
	if sp.requireMTLS {
		collection, err = collection.coalesceStrictEndpointEvents()
		if err != nil {
			sp.metrics.EnrollmentFailures.WithLabelValues("invalid_workload_event").Inc()
			sp.log.Error("Rejecting malformed strict workload event batch",
				logStage, "xds-address-event",
				logfields.Resource, xdsTypeURLAddress,
				logfields.Error, err,
			)
			return fmt.Errorf("failed to coalesce workload Address events: %w", err)
		}
	}

	resp, err := sp.addressResponse(collection)
	if err != nil {
		sp.metrics.EnrollmentFailures.WithLabelValues("invalid_workload_event").Inc()
		sp.log.Error("Rejecting incomplete strict workload Address event",
			logStage, "xds-address-event",
			logfields.Resource, xdsTypeURLAddress,
			logfields.Error, err,
		)
		return fmt.Errorf("failed to build workload Address event response: %w", err)
	}
	if !sp.remoteEnabled() || sp.remote == nil {
		if err := sp.sendAddressResponse(resp, "xds-address-event"); err != nil {
			return err
		}
		sp.recordAddressEvidence(resp)
		return nil
	}
	// A new local address owned by a published remote workload withdraws
	// that peer in the same response.
	if err := sp.withdrawCollidingRemote(resp); err != nil {
		return err
	}
	if err := sp.sendAddressResponse(resp, "xds-address-event"); err != nil {
		return err
	}
	sp.recordAddressEvidence(resp)
	if err := sp.updateLocalAddresses(resp); err != nil {
		return err
	}
	return sp.syncRemote(time.Now())
}

func (sp *StreamProcessor) drainEndpointEvents(first *EndpointEvent) (EndpointEventCollection, error) {
	if first == nil {
		return nil, wrapValidationError(errInvalidWorkloadData, "cannot process a nil workload event")
	}
	collection := make(EndpointEventCollection, 0, maxEndpointEventsPerBatch)
	collection = append(collection, first)
	ctx := context.Background()
	if sp.stream != nil && sp.stream.Context() != nil {
		ctx = sp.stream.Context()
	}

	for len(collection) < maxEndpointEventsPerBatch {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case event, ok := <-sp.endpointRecv:
			if !ok {
				return nil, wrapValidationError(errEndpointSourceClosed, "workload endpoint event channel closed")
			}
			if event == nil {
				return nil, wrapValidationError(errInvalidWorkloadData, "workload endpoint event channel contains a nil event")
			}
			collection = append(collection, event)
		default:
			return collection, nil
		}
	}
	return collection, nil
}

func (sp *StreamProcessor) addressResponse(collection EndpointEventCollection) (*v3.DeltaDiscoveryResponse, error) {
	collection, err := sp.bindNodeNames(collection)
	if err != nil {
		return nil, err
	}
	if sp.requireMTLS {
		response, err := collection.toValidatedDeltaDiscoveryResponse(sp.trustDomain, sp.clusterName)
		if err != nil {
			return nil, err
		}
		if sp.effectivePolicyQuarantine {
			if err := sp.bindEffectiveQuarantine(response); err != nil {
				return nil, err
			}
		}
		return response, nil
	}
	return collection.toDeltaDiscoveryResponse(sp.trustDomain, sp.clusterName), nil
}

// Start multiplexes the legacy Address stream and the shared delta engine's
// Authorization stream. A protocol or send error terminates this connection;
// the next connection reconstructs its own subscription/nonce state, and the
// ADS generation this connection began ends with it.
func (sp *StreamProcessor) Start() error {
	ctx, cancel := context.WithCancel(sp.stream.Context())
	defer cancel()
	defer sp.endStream()
	if err := ctx.Err(); err != nil {
		return err
	}
	stream := &serializedDeltaStream{AggregatedDiscoveryService_DeltaAggregatedResourcesServer: sp.stream, ctx: ctx}
	sp.stream = stream
	recvError := make(chan error, 1)
	go func() {
		for {
			req, err := sp.stream.Recv()
			if err != nil {
				recvError <- err
				return
			}
			select {
			case sp.streamRecv <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	var evidenceTick <-chan time.Time
	if sp.policyOwner != nil {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		evidenceTick = ticker.C
	}
	var profileRequests chan *v3.DeltaDiscoveryRequest
	var profileError chan error
	var node *corev3.Node
	var authorizationRequests chan *v3.DeltaDiscoveryRequest
	var authorizationError chan error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvError:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case err := <-authorizationError:
			return err
		case err := <-profileError:
			return err
		case req, ok := <-sp.streamRecv:
			if !ok || req == nil {
				return wrapValidationError(errInvalidDiscoveryState, "xDS request channel closed or nil request")
			}
			if req.Node != nil {
				if node != nil && req.Node.Id != node.Id {
					return wrapValidationError(errInvalidDiscoveryState, "xDS node ID changed on stream")
				}
				if node == nil {
					node = proto.Clone(req.Node).(*corev3.Node)
				}
			}
			if req.TypeUrl == xdsTypeURLIssuerProfile {
				if sp.issuerProfile == nil {
					return wrapValidationError(errInvalidDiscoveryState, "issuer-profile probe is not configured")
				}
				if req.Node == nil && node != nil {
					req = proto.Clone(req).(*v3.DeltaDiscoveryRequest)
					req.Node = node
				}
				if profileRequests == nil {
					profileRequests = make(chan *v3.DeltaDiscoveryRequest)
					profileError = make(chan error, 1)
					go func() {
						profileError <- sp.issuerProfile.run(ctx, profileRequests, stream, sp.issuerProfile.protocolTiming())
					}()
				}
				select {
				case profileRequests <- req:
				case err := <-profileError:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}
			if req.TypeUrl == xdsTypeURLAuthorization {
				if req.Node == nil && node != nil {
					req = proto.Clone(req).(*v3.DeltaDiscoveryRequest)
					req.Node = node
				}
				sp.observeAuthorizationRequest(req)
				if authorizationRequests == nil {
					authorizationRequests = make(chan *v3.DeltaDiscoveryRequest)
					authorizationError = make(chan error, 1)
					adapter := &authorizationDeltaStream{ctx: ctx, requests: authorizationRequests, stream: stream, metrics: sp.metrics,
						onSend: sp.recordAuthorizationSend}
					go func() {
						authorizationError <- sp.authorizations.server.HandleDeltaRequestStream(ctx, adapter, xdsTypeURLAuthorization, "")
					}()
				}
				select {
				case authorizationRequests <- req:
				case err := <-authorizationError:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
				continue
			}
			if err := sp.handleDeltaDiscoveryReq(req); err != nil {
				return err
			}
		case <-sp.nodeNameWatch:
			if err := sp.revalidateNodeNames(); err != nil {
				return err
			}
		case <-sp.remoteViewWatch():
			if err := sp.syncRemote(time.Now()); err != nil {
				return err
			}
		case <-sp.remoteTrustWatch():
			if err := sp.syncRemote(time.Now()); err != nil {
				return err
			}
		case <-sp.remoteNodeWatch():
			if err := sp.syncRemote(time.Now()); err != nil {
				return err
			}
		case <-sp.remoteTimer():
			if err := sp.syncRemote(time.Now()); err != nil {
				return err
			}
		case <-evidenceTick:
			if err := sp.refreshAddressEvidence(); err != nil {
				return err
			}
		case ep, ok := <-sp.endpointRecv:
			if !ok || ep == nil {
				return wrapValidationError(errEndpointSourceClosed, "xDS endpoint channel closed or nil event")
			}
			if err := sp.handleEPEvent(ep); err != nil {
				return err
			}
		}
	}
}
