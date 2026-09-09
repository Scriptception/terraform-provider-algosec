# A33.30 experimental ALGOSEC tag contract

`algosec_tag` requires `experimental_tags=true`. This is the selected A33.30
vendor Early Availability contract, not A32.60/A33.20 support or live acceptance.
Use a fully visible administrator inventory and exclusive writers.

The resource owns one ALGOSEC tag by its positive decimal int64 ID. DEVICE tags
cannot be imported. Canonical name/scope inputs reject surrounding whitespace and
control characters before replacement. Name changes rename the same ID; scope
changes replace. Import uses the canonical numeric ID, including after an external
rename. No guessed GET-by-ID endpoint is used.

The [create example](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-create-post.htm)
returns one object, although its response table says array. The provider selects
the explicit object example and requires HTTP 200, positive ID and exact
name/scope/type. Same-name preflight requires import; 409, timeout, malformed or
wrong-target create responses never acquire ownership from a later GET.

[Inventory](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-all-tags-get.htm)
uses unfiltered zero-based pages of 100, bounded to 1,000 pages, with duplicate-ID
rejection. **A short page terminates the list.** This is an explicit experimental
interpretation of the paginated-array contract: the vendor publishes no totals.
A permission-filtered inventory or concurrent changes can invalidate completeness;
neither is supported. Complete inventory resolves IDs independently of names.

Before DELETE, [detail](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-tag-details-get.htm)
is requested with the resolved name, explicit scope (including empty), and
`includeAssociations=true`. The selected response is one array, not the malformed
extra bracket in the example. It must contain the same immutable ID/type and a
loaded non-null relations array. Any association blocks DELETE; ordinary list
`relations=[]` is never proof of no associations. This is not an atomic guard:
no conditional delete/ETag is documented. Prohibit concurrent writers. Risk-profile
reference behavior under rename/delete is not established; no reference-preserving
claim is made.

[Rename](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-tagid-name-put.htm)
and [delete](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tags-tag-delete.htm)
select their operation-specific HTTP 200 empty-body acknowledgements. Other AFA
JSON operations remain strict. Rename refreshes the ID; deletion requires its
absence from complete inventory. Acknowledged IDs survive readback failures.

## Hostgroup association boundary

No association resource is delivered in this sub-batch. The
[relation DTO](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/tagrelationdto_type.htm)
identifies `deviceDataId`, `tagId` and canonized `hostgroup`, with optional
`deviceTreeName`. Writes need a tree name and hostgroup. The inspected
[device detail](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/device-details.htm)
has no response schema; device setup inventory provides names without numeric ID.
[Allowed devices](https://techdocs.algosec.com/en/horizon/a33.30/horizon-help/content/api-guide/alloweddevices-list.htm)
shows `id` plus `treeName`, but does not establish that ID's equivalence to
`deviceDataId` or canonical hostgroup resolution for an absent assignment.
Reopen on an exact documented ID-domain mapping and authoritative canonical
hostgroup lookup. Matching only an optional display/tree string is insufficient.
This narrow association gap does not block the tag metadata lifecycle.
