# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [security/authorization_ztunnel.proto](#security_authorization_ztunnel-proto)
    - [Address](#istio-security-Address)
    - [Authorization](#istio-security-Authorization)
    - [Clause](#istio-security-Clause)
    - [Match](#istio-security-Match)
    - [Rule](#istio-security-Rule)
    - [ServiceAccountMatch](#istio-security-ServiceAccountMatch)
    - [StringMatch](#istio-security-StringMatch)

    - [Action](#istio-security-Action)
    - [Scope](#istio-security-Scope)

- [Scalar Value Types](#scalar-value-types)



<a name="security_authorization_ztunnel-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## security/authorization_ztunnel.proto
Cilium changes only go_package. Pinned source and wire contract: SOURCE.md.


<a name="istio-security-Address"></a>

### Address



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| address | [bytes](#bytes) |  |  |
| length | [uint32](#uint32) |  |  |






<a name="istio-security-Authorization"></a>

### Authorization



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| namespace | [string](#string) |  |  |
| scope | [Scope](#istio-security-Scope) |  | Determine the scope of this RBAC policy. If set to NAMESPACE, the &#39;namespace&#39; field value will be used. |
| action | [Action](#istio-security-Action) |  | The action to take if the request is matched with the rules. Default is ALLOW if not specified. |
| rules | [Rule](#istio-security-Rule) | repeated | Set of RBAC policy rules each containing its clauses (To, From, When). If at least one of the rules is matched the policy action will take place. Rules are OR-ed. |
| dry_run | [bool](#bool) |  | Whether or not this is a dry run policy. Dry run policies are not enforced, but their matches are logged |






<a name="istio-security-Clause"></a>

### Clause



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| matches | [Match](#istio-security-Match) | repeated | The logical behavior between the matches (if there are more than one) MatchBehavior match_behavior = 1; Matches are OR-ed Match is a generic form of the authz policy&#39;s expressions contained in To, From and When. |






<a name="istio-security-Match"></a>

### Match
Values of specific type are OR-ed
If multiple types are set, they are AND-ed


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [StringMatch](#istio-security-StringMatch) | repeated |  |
| not_namespaces | [StringMatch](#istio-security-StringMatch) | repeated |  |
| service_accounts | [ServiceAccountMatch](#istio-security-ServiceAccountMatch) | repeated |  |
| not_service_accounts | [ServiceAccountMatch](#istio-security-ServiceAccountMatch) | repeated |  |
| principals | [StringMatch](#istio-security-StringMatch) | repeated |  |
| not_principals | [StringMatch](#istio-security-StringMatch) | repeated |  |
| source_ips | [Address](#istio-security-Address) | repeated |  |
| not_source_ips | [Address](#istio-security-Address) | repeated |  |
| destination_ips | [Address](#istio-security-Address) | repeated |  |
| not_destination_ips | [Address](#istio-security-Address) | repeated |  |
| destination_ports | [uint32](#uint32) | repeated |  |
| not_destination_ports | [uint32](#uint32) | repeated |  |






<a name="istio-security-Rule"></a>

### Rule



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| clauses | [Clause](#istio-security-Clause) | repeated | Clauses are AND-ed This is a generic form of the authz policy&#39;s to, from and when |






<a name="istio-security-ServiceAccountMatch"></a>

### ServiceAccountMatch



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  |  |
| serviceAccount | [string](#string) |  |  |






<a name="istio-security-StringMatch"></a>

### StringMatch



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| exact | [string](#string) |  | exact string match |
| prefix | [string](#string) |  | prefix-based match |
| suffix | [string](#string) |  | suffix-based match |
| presence | [google.protobuf.Empty](#google-protobuf-Empty) |  |  |








<a name="istio-security-Action"></a>

### Action


| Name | Number | Description |
| ---- | ------ | ----------- |
| ALLOW | 0 | Allow the request if it matches with the rules. |
| DENY | 1 | Deny the request if it matches with the rules. |



<a name="istio-security-Scope"></a>

### Scope


| Name | Number | Description |
| ---- | ------ | ----------- |
| GLOBAL | 0 | ALL means that the authorization policy will be applied to all workloads in the mesh (any namespace). |
| NAMESPACE | 1 | NAMESPACE means that the policy will only be applied to workloads in a specific namespace. |
| WORKLOAD_SELECTOR | 2 | WORKLOAD_SELECTOR means that the policy will only be applied to specific workloads that were selected by their labels. |










## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |
