# Experimental singleton URL/IP assignment

`algosec_url_ip_membership` selects the A33.20 public Panorama contract and requires
`experimental_url_ip_memberships=true`. A32.60 has no documented IP removal
counterpart. A33.30 documentation also exposes the pair, but this implementation
mapping does not infer tested newer-version compatibility. All fixtures are
synthetic; no appliance acceptance has occurred.

The category and URL must already exist. Own exactly one `(category, URL, IP)`
tuple, preserving spelling and all unrelated entries. Never combine this resource
with `algosec_url_category` ownership of the parent category, duplicate tuple
ownership or concurrent writers. Administrator visibility and the same appliance
URL-category override-file prerequisite as whole-category management apply.

[PUT](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/url-categories_put_ip.htm)
and [DELETE](https://techdocs.algosec.com/en/asms/a33.20/asms-help/content/api-guide/url-categories_delete_ip.htm)
send a JSON array containing only the owned IP. The explicit cURL route spelling
`/afa/api/v1/plugins/panorama/URLCategory/{category}/URL/{url}/IP/` is selected;
the table's different capitalization and malformed example IPs are not copied.
Acknowledgement must be the valid category map with the exact category/URL still
present and the expected IP membership. An empty map, wrong target, null body or
HTTP failure never confirms a mutation. Full category readback follows.

A preexisting assignment requires import. An unconfirmed write does not acquire
ownership through later reads. A positively acknowledged create retains its exact
tuple if refresh fails. Read errors retain state; only valid full inventory proves
absence. All changes replace, temporarily removing the assignment; known invalid
IP and identifier inputs are rejected before destruction.

Import is `v1.<category>.<URL>.<IP>`, where each token is unpadded base64url of the
exact UTF-8 value. Decoding and re-encoding must reproduce the identifier exactly;
IP spelling is not silently normalized. IPv4/IPv6 addresses are supported; scoped
addresses and CIDR prefixes are rejected.
