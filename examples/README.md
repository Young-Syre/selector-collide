# Example inputs

Fabricated ABIs. None of these is any real project's artefact; the ERC-20 and
EIP-2535 member names are from public standards, and the vault is invented.

| File | What it demonstrates |
| --- | --- |
| `proxy.json`, `implementation.json` | A proxy and implementation that clash on three selectors: `upgradeTo(address)` and `setFeeRecipient(address)` are state-changing and guarded by different modifiers, and `owner()` is a view. |
| `clean-proxy.json`, `clean-implementation.json` | The same shape with disjoint selectors, so `check` reports nothing and exits 0. |
| `diamond-facet-ownership.json`, `diamond-facet-token.json`, `diamond-facet-legacy.json` | Three EIP-2535 facets, one clash: the legacy facet's `collate_propagate_storage(bytes16)` and the token facet's `burn(uint256)` are both `0x42966c68`. That pair is the published demonstration of the bug class, and `tests/test_known.py` recomputes it rather than trusting it. |
| `allowlist.txt` | A selector-keyed allowlist, the input to `selector-collide allowlist`. |
| `router-surface.txt` | A signature list rather than JSON, with modifier annotations that a Solidity ABI cannot carry. |

`proxy.json`, `clean-proxy.json` and the facets carry a non-standard
`"modifiers"` key. solc does not emit it; it is accepted because without it no
ABI can express the access control that rule SC002 compares. Entries without
it are read normally and SC002 simply cannot fire for them.
