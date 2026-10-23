# Independent authorization wire fixture

`allow-pos-v1.hex` is encoded directly from the pinned proxy schema's field numbers, independently of the generated Go serializer. It represents workload-scoped `shop/allow-pos`, one rule, one clause, one match: exact principal `cluster-a.example/ns/shop/sa/pos` AND application port 80. It is a protocol fixture, not a deployed policy or a selected production trust domain.

Encoding: Authorization name=1, namespace=2, scope=3 (WORKLOAD_SELECTOR=2), rules=5; Rule clauses=1; Clause matches=2; Match principals=3 and packed destination_ports=9; StringMatch exact=1. ALLOW=0 is omitted according to proto3 defaults.

The pinned Rust matcher strips `spiffe://` from the authenticated certificate identity before matching a principal. The policy's exact value therefore excludes that prefix; certificate SPIFFE URIs retain it. This convention must be preserved by the future policy compiler.
