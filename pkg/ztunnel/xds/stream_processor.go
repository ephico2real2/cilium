// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

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
}

// StreamProcessor implements the logic for handling xDS streams to zTunnel.
// It is abstracted away from the primary stream initialization handler to
// promote decoupling and the handling multiple streams without a shared set of
// channels being required on the Server object.
type StreamProcessor struct {
	stream                 v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	streamRecv             chan *v3.DeltaDiscoveryRequest
	endpointRecv           chan *EndpointEvent
	expectedNonce          map[string]struct{}
	log                    *slog.Logger
	endpointSource         EndpointEventSource
	db                     *statedb.DB
	enrolledNamespaceTable statedb.RWTable[*table.EnrolledNamespace]
	metrics                *Metrics
	authorizations         *AuthorizationPolicies
	trustDomain            string
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
		stream:                 params.Stream,
		streamRecv:             params.StreamRecv,
		endpointRecv:           params.EndpointEventRecv,
		log:                    params.Log,
		expectedNonce:          make(map[string]struct{}),
		db:                     params.DB,
		enrolledNamespaceTable: params.EnrolledNamespaceTable,
		metrics:                metrics,
		authorizations:         authorizations,
		trustDomain:            params.TrustDomain,
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
			// Updated endpoint
			updated = append(updated, newCEP)
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
	endpoints := convertCESToEndpointMap(ces)
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
		var synced bool
		var initialBatch EndpointEventCollection

		for e := range newSliceEvents {
			if ctx.Err() != nil {
				e.Done(nil)
				return
			}
			if e.Kind == resource.Sync {
				if !synced {
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

	for e := range newEvents {
		if ctx.Err() != nil {
			e.Done(nil)
			return
		}
		if e.Kind == resource.Sync {
			if !synced {
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
		return fmt.Errorf("unexpected resource names subscribe %v or unsubscribe %v for Address type URL",
			req.ResourceNamesSubscribe, req.ResourceNamesUnsubscribe)
	}

	ctx := sp.stream.Context()

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
		if ok {
			collection = batch
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	resp := collection.toDeltaDiscoveryResponse(sp.trustDomain)
	sp.expectedNonce[resp.Nonce] = struct{}{}

	if err := sp.stream.SendMsg(resp); err != nil {
		sp.metrics.EnrollmentFailures.WithLabelValues("send_failed").Inc()
		return err
	}

	sp.log.Debug("initialized new stream for resource", logfields.Resource, xdsTypeURLAddress)

	return nil
}

func (sp *StreamProcessor) handleDeltaDiscoveryReq(req *v3.DeltaDiscoveryRequest) error {
	if req.TypeUrl != xdsTypeURLAddress {
		return fmt.Errorf("unexpected type URL %q for Address handler", req.TypeUrl)
	}
	// if the delta discovery request has a nonce, this is a ack or nack.
	// for now, if we have a Nack we'll log the errors, retrying a Nack'd
	// message would cause the same issue as previously encountered.
	if req.ResponseNonce != "" {
		// check if this is an expected nonce, if not, its an error
		if _, ok := sp.expectedNonce[req.ResponseNonce]; !ok {
			return fmt.Errorf("unexpected nonce %q received", req.ResponseNonce)
		}

		// remove expected Nonce
		delete(sp.expectedNonce, req.ResponseNonce)

		if req.ErrorDetail != nil {
			sp.metrics.EnrollmentFailures.WithLabelValues("nack_received").Inc()
			sp.log.Error("Nack received from ztunnel",
				logfields.Error,
				req.ErrorDetail.Message,
				logfields.Code,
				req.ErrorDetail.Code)
			// return nil here, we did not encounter a stream error,
			// instead we log the Nack to display an application level error.
			return nil
		}
		return nil
	}

	return sp.handleAddressTypeURL(req)
}

func (sp *StreamProcessor) handleEPEvent(epEvent *EndpointEvent) error {
	collection := EndpointEventCollection{epEvent}

drained:
	for {
		select {
		case ep := <-sp.endpointRecv:
			collection = append(collection, ep)
		default:
			break drained
		}
	}

	resp := collection.toDeltaDiscoveryResponse(sp.trustDomain)

	// record the generated Nonce so we can link up any Ack or Nack in our main
	// event loop.
	sp.expectedNonce[resp.Nonce] = struct{}{}

	err := sp.stream.SendMsg(resp)
	if err != nil {
		return err
	}
	return nil
}

// Start multiplexes the legacy Address stream and the shared delta engine's
// Authorization stream. A protocol or send error terminates this connection;
// the next connection reconstructs its own subscription/nonce state.
func (sp *StreamProcessor) Start() error {
	ctx, cancel := context.WithCancel(sp.stream.Context())
	defer cancel()
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
		case req, ok := <-sp.streamRecv:
			if !ok || req == nil {
				return fmt.Errorf("xDS request channel closed or nil request")
			}
			if req.Node != nil {
				if node != nil && req.Node.Id != node.Id {
					return fmt.Errorf("xDS node ID changed on stream")
				}
				if node == nil {
					node = proto.Clone(req.Node).(*corev3.Node)
				}
			}
			if req.TypeUrl == xdsTypeURLAuthorization {
				if req.Node == nil && node != nil {
					req = proto.Clone(req).(*v3.DeltaDiscoveryRequest)
					req.Node = node
				}
				if authorizationRequests == nil {
					authorizationRequests = make(chan *v3.DeltaDiscoveryRequest)
					authorizationError = make(chan error, 1)
					adapter := &authorizationDeltaStream{ctx: ctx, requests: authorizationRequests, stream: stream, metrics: sp.metrics}
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
		case ep, ok := <-sp.endpointRecv:
			if !ok || ep == nil {
				return fmt.Errorf("xDS endpoint channel closed or nil event")
			}
			if err := sp.handleEPEvent(ep); err != nil {
				return err
			}
		}
	}
}
