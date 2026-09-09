# A33.30 FireFlow direct bindings

`algosec_fireflow_role_member` and `algosec_fireflow_role_permission` select the
A33.30 public FireFlow contracts. Enable `experimental_fireflow_bindings=true`,
provide `fireflow_url` and an externally supplied `fireflow_session` (prefer
`ALGOSEC_FIREFLOW_URL` / `ALGOSEC_FIREFLOW_SESSION`). The client uses only the
[documented FireFlow_Session cookie](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/authenticating.htm).
It never logs in, guesses a token exchange, refreshes or logs out a session.
TLS verification is mandatory even when AFA `insecure=true`. Redirects and write
replay are refused; requests/responses are bounded. Sessions are provider inputs,
not resource state. No appliance acceptance or other-version compatibility is claimed.

## Direct membership

[GET members](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-members-get.htm)
explicitly requests `fetchIndirect=false`. The complete successful array requires
valid IDs, exact User/Role types and explicit `isDirectMember`; duplicates and
missing fields fail closed. Identity is `(role_id, member_type, member_id)`.
User and Role numeric ID domains are distinct. Only direct membership is owned;
indirect entries never confer ownership.

[POST members](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-members-post.htm)
sends one item in `addMembers` or `removeMembers`, with the other array explicitly
empty. Exact `Success`, empty messages and documented `data:null` acknowledge the
single operation. `PartiallySuccess`, mixed failure messages, malformed bodies,
timeout and HTTP errors do not establish create ownership. No confirming read can
rescue an unconfirmed create. Acknowledged tuples are retained before readback.

Known self-edges are rejected during planning, before replacement can remove the
owned binding. Other circular dependencies, disabled/missing users, missing roles
and permission failures remain errors. Role-member edges represent the inverse of
parent-role links; no duplicate parent-link resource or extra operation is counted.
No whole role/user CRUD is invented: role deletion is absent from this API family.

Import: `v1.<role_id>.<User|Role>.<member_id>`, using canonical positive decimal
int32 IDs. All changes replace, temporarily removing the direct assignment.

## Direct permission

[GET permissions](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-permissions-get.htm)
requires complete non-null `system`, `customField` and `requestTemplate` arrays,
with explicit `direct` and `inherited` flags. Identity is the role plus exact
permission name, object type and object ID. System object ID must be zero;
CustomField/RequestTemplate IDs must be positive int32 values.

[POST permissions](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/mf-roles-id-permissions-post.htm)
sends one typed tuple in `addPermissions` or `removePermissions`, with the other
array empty. Exact `Success`, empty messages and `data:{}` acknowledge the
operation. Readback must show the exact direct assignment. The resource changes
persistent authorization; a permission whose name refers to a workflow is not a
request to run that workflow. No unrelated grants or parent metadata are written.

Removing direct permission can leave inherited access, which is correct. A valid
complete read with `direct=false` means this resource's assignment is absent even
if `inherited=true`. Malformed or restricted reads retain state. Import accepts
`v1.<role_id>.<object_type>.<object_id>.<unpadded base64url UTF-8 permission_name>`;
round-trip canonical encoding is required. All changes replace. Known field errors
and serialized payload limits are checked before replacement destruction.

## Visibility, ownership and recovery

Use complete FireFlow Admin/SeeRole visibility. Member mutations require the
published AdminRole and AdminRoleMembership permissions or FireFlow Admin;
permission mutations require AdminRole and ShowConfigTab or FireFlow Admin.
The permission-catalog page's different ShowConfigTag spelling is not silently
promoted into an executable requirement. Parent-role/member APIs document all
results without pagination parameters; the provider does not invent pagination.
Large-role completeness remains unverified live.

Preexisting direct tuples require import. Preserve exclusive ownership and prohibit
concurrent writers: there is no documented conditional-create/CAS guarantee.
Inherited and unrelated entries remain untouched. Only successful complete reads
prove tuple absence. HTTP 404 is not generically treated as absence; inconsistent
parent-not-found descriptions, dependency failures and permission errors retain
state for operator recovery. No failed write is replayed automatically.
