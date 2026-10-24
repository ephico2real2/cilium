# SPIRE workload credentials

This slice implements the credential-delivery prerequisite for CMTC-101. It does
not enable ClusterMesh compatibility, authorization production, persistent
packet admission, or a Protected status.

With `encryption.ztunnel.ca.type=spire`, enable
`authentication.mutual.spire.enabled`. The agent serves ADS using only its
bootstrap TLS server key/certificate chain and does not load or register the
internal workload CA. Missing ADS TLS credentials fail startup. Internal mode
retains its existing signer and requires all four Secret keys.

The proxy receives the SPIRE admin socket and node CRI socket for delegated
PID attestation. The bundled SPIRE installer registers an attested node alias
`/ztunnel` for operator-created workload entries, and a separate workload
identity `/ztunnel-proxy` for the proxy service account. Only that identity is
added to the existing delegated-identity allowlist. These are distinct from
application namespace/service-account identities.

The configured SPIFFE trust domain is carried in both initial and incremental
Address resources. Cilium ztunnel v1.0.0, commit
`5bb9cf256b10a209ae9bc0624ddfbf27dbc439de`, uses `SPIRE_ENABLED` to select its
SPIRE client exclusively. Its locked spire-api 0.3.9 client reads
`SPIRE_ADMIN_ENDPOINT_SOCKET`; the proxy selects its trust bundle using
`Config.cluster_domain`, so SPIRE mode sets `CLUSTER_DOMAIN` as well as
`TRUST_DOMAIN`. The chart keeps proxy DNS capture disabled. These settings do
not alter Kubernetes DNS configuration. Verify any future proxy pin against
these source contracts before changing them.

The CA choice does not configure a cert-manager issuer for SPIRE automatically.
CMTC-101's isolated runtime fixture supplies the cert-manager UpstreamAuthority
and namespace-scoped CertificateRequest RBAC. The organizational root key stays
outside the cluster, cluster issuer keys remain in cert-manager, and SPIRE holds
its own intermediate key. Agent nodes receive only the ADS TLS server key and
public chain. CA depth must allow root -> cluster issuer -> SPIRE intermediate
-> workload SVID. Issuer and peer restrictions for foreign-cluster identities
remain CMTC-105 acceptance work.

Local tests cover absence of the signing RPC/key loader in SPIRE mode, existing
internal signer behavior, unavailable-signer startup failure, invalid backend
and domain rejection, and issuer-domain propagation over actual initial and
incremental ADS streams. The CMTC fixture must additionally prove real SVID
issuance, peer identity, encrypted packets and negative cases before any runtime
mTLS acceptance is reported.

The operator's SPIRE initialization is a lifecycle-managed Hive job. It uses
Cilium's injected slog logger and standard logfields for attempt, elapsed time,
backoff, deadline, server address and underlying errors. Transient startup
failures use jittered exponential backoff capped at ten seconds within a
three-minute startup deadline; each connection attempt retains the configured
connection timeout. Shutdown cancels both an RPC and a pending retry. Explicit
authentication, permission and configuration rejections fail the job and its
Hive health report. Failed attempts release their X509 source and gRPC client;
successful resources remain alive until job shutdown.

Initialization is acknowledged only after an authenticated CountEntries RPC
responds. A lazy grpc.NewClient is not a connection acknowledgment. This ACK
does not establish application SVID delivery, policy installation or packet
protection. The broader dependency/registration/proxy recovery work is tracked
in [CMTC issue #7](https://github.com/ephico2real2/clustermesh-trust-controller/issues/7).

## Experimental authenticated-only inbound policy

`encryption.ztunnel.requireMtls=true` (`ztunnel-require-mtls`) publishes a native
ztunnel GLOBAL DENY rule matching the absence of an authenticated TLS principal.
It has no application-port predicates. The receiving plaintext listener passes
no peer identity to RBAC; HBONE uses the verified TLS peer. Cilium currently
supplies workload records only for enrolled namespaces, so this policy applies
to the workloads handled by the ztunnel, not arbitrary platform pods.

This option defaults to false while admission and platform compatibility are
being qualified. The desired policy is installed before ADS accepts connections,
but the pinned proxy can permit traffic while policy is absent. This is not a
persistent fail-closed gate, a complete Cilium authorization compiler, or a
`Protected` status. Startup/restart, policy loss, mandatory capture and legitimate
platform health probes must be checked independently. Incompatible Helm/agent
profiles reject the option instead of silently ignoring it. Do not substitute
port-80 (or enumerated-port) network-policy denies for workload authentication.
