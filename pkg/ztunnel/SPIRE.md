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
