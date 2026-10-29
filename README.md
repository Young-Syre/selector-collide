# selector-collide

[![tests](https://github.com/Young-Syre/selector-collide/actions/workflows/tests.yml/badge.svg)](https://github.com/Young-Syre/selector-collide/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-green)](LICENSE)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

An EVM function-selector collision and proxy-shadowing analyser. It reads local
ABIs and reports where two different functions share one 4-byte selector:
across a proxy and its implementation, across the facets of a diamond, inside a
single ABI, or inside an allowlist that is keyed on selectors.

Python 3.11+, standard library only, no network access.

## The EVM has no notion of a function

A call is a blob of calldata, and Solidity's convention is that the first four
bytes identify which function the caller meant. Those four bytes are the
leading four of `keccak256("name(type,type,...)")`, and the compiler emits a
dispatcher at the top of the contract that compares them against each public
function in turn, jumping to the first match. If nothing matches, control
falls through to the `fallback` function, or the call reverts.

Four bytes is 4,294,967,296 possibilities. That is a large number for a human
and a small one for a computer, and three consequences follow.

**A proxy answers before its implementation does.** A `delegatecall` proxy has
its own dispatcher. Its own functions are matched first; only when none matches
does the fallback forward the call to the implementation. So if the proxy and
the implementation both export a selector, the implementation's function behind
it can never be reached through the proxy. It is not overridden — it is
unreachable, while still looking perfectly live in the implementation's ABI, in
the generated bindings, and in every integration written against them. The
severity depends on what was displaced. A displaced view returns the proxy's
answer. A displaced state-changing function means a transaction that looks like
it worked did something else entirely. And when the two sides carry different
access control — the proxy's copy `onlyAdmin`, the implementation's copy
`onlyOwner`, or public — the guard that actually runs is not the guard the
implementation's author wrote. This is the clash that OpenZeppelin's transparent
proxy addresses by refusing admin-looking calls from non-admins, and that
upgrade tooling checks for by name. It is still found in audits, because the two
ABIs usually live in different files and nobody compared them.

**A selector is not a signature, so a different function can satisfy a check on
it.** Guards are routinely written against four bytes: a module allowlist in a
Safe-style wallet, a `bytes4 => address` router table, a "this module may only
call `transfer`" policy. Four bytes do not say *which* `transfer`. Anyone who
controls a function name can search for a different signature that hashes to the
same selector, and the search space is small enough that the answers for popular
selectors are already published. `transfer(address,uint256)`,
`many_msg_babbage(bytes1)` and `func_2093253501(bytes)` are all `0xa9059cbb`;
`transferFrom(address,address,uint256)` and `gasprice_bit_ether(int128)` are
both `0x23b872dd`; `burn(uint256)` and `collate_propagate_storage(bytes16)` are
both `0x42966c68`. Every one of those is recomputed by this repository's test
suite rather than quoted on trust. A policy keyed on the selector permits the
alternative as readily as the original — and the alternative's parameters are
decoded differently, so the calldata the guard inspected is not the calldata the
callee reads.

**Collisions that the compiler would catch are not always presented to the
compiler.** Two functions with one selector in a single contract is a
compile-time error, so it does not survive. But an EIP-2535 diamond spreads its
functions over facets compiled separately, and the clash only appears when
`diamondCut` tries to register a selector another facet already owns: a failed
upgrade at best, and at worst a cut that silently keeps whichever facet was
registered first. A fallback-based router dispatches by hand, so nothing is
checked at all. And an ABI assembled from several sources — a merged interface,
a hand-edited artefact — can contain a pair that no compiler ever saw.

All three are the same fact seen from three angles: the selector namespace is 32
bits wide, shared, and unenforced across compilation units.

## Install

```
git clone https://github.com/Young-Syre/selector-collide
cd selector-collide
python -m pip install -e .
```

There are no dependencies to install. Without installing, `python -m
selector_collide` works from the repository root.

## Usage

### A proxy against its implementation

```
$ selector-collide --proxy examples/proxy.json --implementation examples/implementation.json
selector-collide: proxy shadowing
  input: proxy proxy.json (abi-json)
  input: implementation implementation.json (abi-json)

  HIGH    SC001 proxy-shadow
          selector 0x3659cfe6  proxy.json shadows upgradeTo(address)
          upgradeTo(address) in proxy.json and upgradeTo(address) in
          implementation.json share selector 0x3659cfe6. The proxy matches it
          first, so the implementation's function is unreachable through the
          proxy. It is state-changing, so a call that was meant to mutate the
          implementation's state runs the proxy's function instead.

  HIGH    SC001 proxy-shadow
          selector 0xe74b981b  proxy.json shadows setFeeRecipient(address)
          setFeeRecipient(address) in proxy.json and setFeeRecipient(address)
          in implementation.json share selector 0xe74b981b. The proxy matches
          it first, so the implementation's function is unreachable through
          the proxy. It is state-changing, so a call that was meant to mutate
          the implementation's state runs the proxy's function instead.

  HIGH    SC002 shadow-modifier-divergence
          selector 0x3659cfe6  access control differs on 0x3659cfe6
          The shadowing pair declares different modifiers: proxy.json has
          onlyAdmin and implementation.json has onlyOwner. Whichever guard the
          implementation's function relied on is no longer the guard that
          runs.

  HIGH    SC002 shadow-modifier-divergence
          selector 0xe74b981b  access control differs on 0xe74b981b
          The shadowing pair declares different modifiers: proxy.json has
          onlyAdmin and implementation.json has onlyOwner. Whichever guard the
          implementation's function relied on is no longer the guard that
          runs.

  MEDIUM  SC001 proxy-shadow
          selector 0x8da5cb5b  proxy.json shadows owner()
          owner() in proxy.json and owner() in implementation.json share
          selector 0x8da5cb5b. The proxy matches it first, so the
          implementation's function is unreachable through the proxy. It is a
          read, so callers get the proxy's answer rather than the
          implementation's.

  MEDIUM  SC003 shadow-mutability-divergence
          selector 0xe74b981b  state mutability differs on 0xe74b981b
          proxy.json declares setFeeRecipient(address) as nonpayable while
          implementation.json declares setFeeRecipient(address) as payable.
          Callers compiled against the implementation's ABI will send calls
          the proxy's function handles differently.

  6 findings: 4 high, 2 medium
```

Exit code 1. A pair with no shared selectors says so and exits 0:

```
$ selector-collide --proxy examples/clean-proxy.json --implementation examples/clean-implementation.json
selector-collide: proxy shadowing
  input: proxy clean-proxy.json (abi-json)
  input: implementation clean-implementation.json (abi-json)

  no collisions found
```

### Diamond facets

```
$ selector-collide --diamond examples/diamond-facet-ownership.json \
    examples/diamond-facet-token.json examples/diamond-facet-legacy.json
selector-collide: diamond facet clash
  input: facet diamond-facet-ownership.json (abi-json)
  input: facet diamond-facet-token.json (abi-json)
  input: facet diamond-facet-legacy.json (abi-json)

  HIGH    SC004 facet-clash
          selector 0x42966c68  0x42966c68 claimed by 2 facets
          Selector 0x42966c68 is exported by diamond-facet-legacy.json,
          diamond-facet-token.json. A diamond holds one selector-to-facet
          mapping, so registering the second facet reverts in diamondCut, and
          any cut that works leaves one of these functions unroutable:
          diamond-facet-legacy.json:collate_propagate_storage(bytes16)
          [nonpayable onlyMigrator]; diamond-facet-token.json:burn(uint256)
          [nonpayable]

  1 finding: 1 high
```

### Listing selectors

```
$ selector-collide selectors examples/proxy.json
0x3659cfe6  upgradeTo(address)        function nonpayable onlyAdmin
0x5c60da1b  implementation()          function view onlyAdmin
0x8da5cb5b  owner()                   function view
0x8f283970  changeAdmin(address)      function nonpayable onlyAdmin
0xe74b981b  setFeeRecipient(address)  function nonpayable onlyAdmin
0xf851a440  admin()                   function view onlyAdmin
```

### An allowlist keyed on selectors

```
$ selector-collide allowlist examples/allowlist.txt --rate 9371
selector-collide: allowlist
  input: allowlist.txt (5 entries)

  HIGH    SC008 allowlist-selector-keyed
          selector 0x42966c68  0x42966c68 has a published colliding signature
          allowlist.txt allows burn(uint256).
          collate_propagate_storage(bytes16) also hashes to 0x42966c68, so a
          caller can satisfy this allowlist with a function this allowlist was
          never meant to permit. Key the check on the full signature, or on a
          hash wider than four bytes, or on the target address as well.

  HIGH    SC008 allowlist-selector-keyed
          selector 0xa9059cbb  0xa9059cbb has a published colliding signature
          allowlist.txt allows transfer(address,uint256).
          many_msg_babbage(bytes1), func_2093253501(bytes) also hash to
          0xa9059cbb, so a caller can satisfy this allowlist with a function
          this allowlist was never meant to permit. Key the check on the full
          signature, or on a hash wider than four bytes, or on the target
          address as well.

  MEDIUM  SC008 allowlist-selector-keyed
          selector 0x095ea7b3  0x095ea7b3 is allowed by selector, not by signature
          allowlist.txt allows approve(address,uint256). No colliding
          signature for 0x095ea7b3 is known to this tool, but the selector
          space is 32 bits wide: a uniform search expects 2**32 candidates and
          has a median of 2,977,044,471 before one appears. At 9,371 candidate
          signatures per second, the median search is about 3.7 days on one
          core. The check admits any signature that lands on these four bytes,
          not only this one.
...
```

### JSON

Every mode takes `--json`. Keys are sorted and the output is byte-identical
across runs on the same input.

```
$ selector-collide --diamond examples/diamond-facet-token.json \
    examples/diamond-facet-legacy.json --json
{
  "counts": {
    "high": 1,
    "info": 0,
    "low": 0,
    "medium": 0
  },
  "findings": [
    {
      "detail": "Selector 0x42966c68 is exported by diamond-facet-legacy.json, diamond-facet-token.json. A diamond holds one selector-to-facet mapping, so registering the second facet reverts in diamondCut, and any cut that works leaves one of these functions unroutable: diamond-facet-legacy.json:collate_propagate_storage(bytes16) [nonpayable onlyMigrator]; diamond-facet-token.json:burn(uint256) [nonpayable]",
      "name": "facet-clash",
      "rule": "SC004",
      "selector": "0x42966c68",
      "severity": "high",
      "signatures": [
        "burn(uint256)",
        "collate_propagate_storage(bytes16)"
      ],
      "sources": [
        "diamond-facet-legacy.json",
        "diamond-facet-token.json"
      ],
      "title": "0x42966c68 claimed by 2 facets"
    }
  ],
  "inputs": [
    "facet diamond-facet-token.json (abi-json)",
    "facet diamond-facet-legacy.json (abi-json)"
  ],
  "mode": "diamond facet clash",
  "tool": "selector-collide"
}
```

## Modes and rules

| Mode | Invocation |
| --- | --- |
| Proxy shadowing | `--proxy <abi> --implementation <abi>` |
| Diamond facet clash | `--diamond <abi> <abi> [<abi> ...]` |
| Single ABI | `--abi <abi> [<abi> ...]` |
| Selector listing | `selectors <abi> [<abi> ...]` |
| Allowlist assessment | `allowlist <file>` |
| Preimage search | `find <selector>` |
| Birthday search | `collide` |
| Hash-rate measurement | `benchmark` |
| Keccak self-test | `selftest` |

| Rule | Name | Severity | Fires when |
| --- | --- | --- | --- |
| SC001 | `proxy-shadow` | high / medium | A selector is exported by both the proxy and the implementation, so the implementation's function is unreachable through the proxy. High when the displaced function is state-changing, medium when it is `view` or `pure`. |
| SC002 | `shadow-modifier-divergence` | high | A shadowing pair whose declared modifiers differ, so the access control that runs is not the access control the implementation declared. Needs modifier annotations (see below). |
| SC003 | `shadow-mutability-divergence` | medium | A shadowing pair whose `stateMutability` differs, e.g. a `nonpayable` proxy function displacing a `payable` one. |
| SC004 | `facet-clash` | high | Two or more diamond facets export the same selector. |
| SC005 | `abi-duplicate-selector` | high / medium | One ABI contains two distinct signatures with the same selector. High between two functions, medium between a function and a custom error, where dispatch is unaffected but revert decoding is ambiguous. |
| SC006 | `proxy-without-fallback` | info | A proxy ABI declares no fallback, so it cannot forward anything: either the ABI is partial or the contract is not a forwarding proxy. |
| SC007 | `open-fallback` | info | An ABI declares a fallback, so selectors it does not declare are not rejected. Any check treating that ABI as the complete call surface is incomplete. |
| SC008 | `allowlist-selector-keyed` | high / medium | An allowlist entry is a 4-byte key. High when a colliding signature is already published, medium otherwise. |

`--fail-on {high,medium,low,info,never}` sets the lowest severity that makes the
command exit 1. The default is `low`, so `info` findings are reported but do not
fail. `never` always exits 0 when the run completed.

### Modifier annotations

A Solidity JSON ABI does not record modifiers. solc emits names, types,
`stateMutability` and outputs, and nothing about `onlyOwner`. SC002 therefore
needs the information from somewhere else, and there are two ways to supply it:

- a non-standard `"modifiers": ["onlyAdmin"]` key on an ABI entry, which this
  tool reads and solc never writes (see `examples/proxy.json`);
- a signature list, where any trailing identifier that is not a Solidity
  keyword is read as a modifier: `withdraw(uint256) external onlyAdmin`.

Without annotations the other rules work normally and SC002 simply cannot fire.
It is not inferred from anything, and nothing is guessed from a function's name.

## Searching for a colliding signature

`find` brute-forces a short synthetic signature with a given selector, so that a
reviewer can demonstrate a collision rather than argue about one. Be clear-eyed
about the cost. A selector is 32 bits. A uniform search expects 2³² ≈ 4.29e9
candidates, with a median of 2,977,044,471 — the trial count is geometric, so the
median is ln 2 ≈ 69% of the mean.

The hash rate is the whole story, and it is measured, not estimated:

```
$ selector-collide benchmark --count 200000
hashed 200,000 candidate signatures in 21.34s (9,371/s)
  median 32-bit search: 2,977,044,471 candidates, about 3.7 days on one core
```

That is CPython 3.14.4 on one core of an Intel Core i9-13900KS. `benchmark`
measures the code path the searches use, including candidate construction, not a
permutation microbenchmark. Keccak-f[1600] is 24 rounds of 64-bit mixing over a
25-lane state; in pure Python that is roughly two thousand big-integer
operations per hash. Almost all of that time is the permutation itself, so
there is no meaningful headroom left in the sponge wrapper around it:

```
$ python -c "
import time
from selector_collide.keccak import _permute, selector_int_of_bytes
lanes = [i * 0x0123456789ABCDEF & ((1 << 64) - 1) for i in range(25)]
n = 20000
t = time.perf_counter()
for _ in range(n): _permute(lanes)
perm = n / (time.perf_counter() - t)
msgs = [('f%d()' % i).encode() for i in range(n)]
t = time.perf_counter()
for m in msgs: selector_int_of_bytes(m)
full = n / (time.perf_counter() - t)
print(f'permutation {perm:,.0f}/s, whole hash {full:,.0f}/s -> permutation is {full/perm:.1%} of the cost')
"
permutation 10,225/s, whole hash 9,498/s -> permutation is 92.9% of the cost
```

**So: a full 32-bit preimage search was not run to completion here, and this
repository does not claim one.** At 9,371 candidates per second the median
search is about 3.7 days of single-core work. `find` therefore takes a budget,
reports what it did, exits 4 when the budget is exhausted, and extrapolates from
the rate it actually achieved:

```
$ selector-collide find 0xa9059cbb --max 1e6
no match after 1,000,000 candidates in 106.0s (9,435/s)
  target     0xa9059cbb
  template   f{}()
  at this rate the median 32-bit search (2,977,044,471 candidates) would take about 3.7 days on one core
```

What *was* run, twice over, is everything that is affordable.

**A partial match, for calibration.** `--bits N` compares only the top N bits,
which costs 2^(32-N) times less. This is not a collision and the tool says so,
but it demonstrates the search is wired up correctly and lets you check the
extrapolation against a real measurement:

```
$ selector-collide find 0xa9059cbb --bits 24 --max 1e7
found partial match after 4,085,477 candidates in 453.4s (9,010/s)
  signature  fbotmp()
  selector   0xa9059ca1
  target     0xa9059cbb
  NOTE: only the top 24 bits were compared, so this is not a collision. A full 32-bit match needs about 256 times more work.
```

**A real collision, by birthday search.** If you need *a* collision rather than
a collision with a *chosen* selector, the cost collapses. Among n candidates the
expected number of colliding pairs is about n²/2³³, so a 50% chance needs about
√(2 ln 2 · 2³²) ≈ 77,000 candidates — seconds, not days:

```
$ selector-collide collide --max 400000
found a colliding pair after 46,940 candidates in 5.1s (9,227/s)
  selector   0x7e2b73ab
  signature  fzom()
  signature  f9g4()
```

Both of those really do hash to `0x7e2b73ab`; the CI workflow recomputes the
pair it finds and fails if they do not. That is the asymmetry worth taking away:
*any* collision is seconds of work, and a collision with the selector *you*
choose is days. A guard that assumes four bytes pin down a function is relying
on the wrong one of those two numbers.

If you want a real 32-bit preimage, the search is embarrassingly parallel —
split the candidate space by prefix, or port the loop to a compiled language.
This repository stays in the standard library and states the measured rate
instead of pretending otherwise.

## Canonicalisation

A selector is `keccak256(canonical_signature)[:4]`, and "canonical" is exact:
the name, the parameter types in parentheses, single commas, no spaces, no
parameter names, no return types, no data locations, every type in canonical
form. Get it wrong and you compute a different number with full confidence.

| Input | Canonical form | Supported |
| --- | --- | --- |
| `address`, `bool`, `string`, `bytes`, `function` | unchanged | yes |
| `uint8` … `uint256`, `int8` … `int256` (multiples of 8) | unchanged | yes |
| `bytes1` … `bytes32` | unchanged | yes |
| `uint`, `int` | `uint256`, `int256` | yes |
| `byte` (removed in Solidity 0.8) | `bytes1` | yes |
| `fixed`, `ufixed` | `fixed128x18`, `ufixed128x18` | parsed per the ABI spec; solc does not implement fixed-point types, so you are unlikely to meet one |
| `uint[]`, `uint[3]`, `uint[2][]` | `uint256[]`, `uint256[3]`, `uint256[2][]` | yes, to any depth |
| `(address,uint256)`, `(address,(bool,uint))[2]` | expanded recursively | yes |
| ABI JSON `"type": "tuple"` with `components` | `(uint256,address,uint64)` | yes, nested and arrayed |
| `struct Vault.RedeemRequest` in a signature list | — | no: rejected with a message pointing at the ABI JSON, where solc has already expanded it |
| ABI JSON `"internalType": "struct …"` | from `components` | yes |
| `contract IERC20`, `interface IVault` | `address` | yes |
| `enum Vault.Mode` | `uint8` | yes |
| `address payable` | `address` | yes |
| `uint256[] memory amounts`, `bytes calldata data` | `uint256[]`, `bytes` | yes: names and data locations are dropped |
| `function transfer(address to, uint256 amount) external returns (bool)` | `transfer(address,uint256)` | yes: keywords and the `returns` clause are dropped |
| `error InsufficientBalance(uint256,uint256)` | kept as an `error` entry with a selector | yes |
| `event Transfer(address,address,uint256)` | no selector | by design: an event is identified by a 32-byte topic, not four bytes |
| `constructor(...)` | no selector | by design: a constructor is never dispatched |
| `fallback()`, `receive()` | no selector | by design: reached by the *absence* of a match |
| user-defined value types (`type MyInt is uint256`) | underlying type | only through ABI JSON, where solc has already resolved it; an unknown bare identifier in a signature list is rejected rather than guessed |

Anything it cannot canonicalise is an error naming the offending type, never a
silent guess. `uint7`, `bytes33`, `uint256[0]`, a qualified name it cannot
resolve and a stray second identifier are all rejected.

## Input formats

Detected by content, not by file extension:

1. **Standard Solidity JSON ABI** — a top-level JSON array of entry objects.
2. **Build artefact** — a JSON object with an `"abi"` key. Foundry's `forge
   build` artefacts, `forge inspect <contract> abi` and Hardhat artefacts all
   match.
3. **Signature list** — one signature per line, `#` starts a comment. Canonical
   signatures, Solidity declarations and modifier annotations are all accepted.
   This is how you analyse a fallback-based router, which has no ABI of its own.

Pre-0.5 ABIs that use `"constant": true` and `"payable": true` instead of
`stateMutability` are read correctly. An entry with no `"type"` is a function,
as the ABI specification requires.

## Keccak-256

`hashlib` cannot do this. SHA3-256 and Keccak-256 share the Keccak-f[1600]
permutation, the sponge construction and the 136-byte rate, and differ in one
byte: Keccak appends the `pad10*1` multi-rate padding directly, so the first
padding byte is `0x01`, while FIPS 202 first appends the domain separator `01`,
making it `0x06`. Ethereum froze on Keccak before FIPS 202 was published.
`hashlib.sha3_256(b"")` is
`a7ffc6f8…`; `keccak256(b"")` is `c5d24601…`. Different function, same shape,
and the padding byte is the single most likely place to get this wrong.

So `selector_collide/keccak.py` implements it from scratch, and the test suite
attacks it from four directions:

- **Published vectors.** The empty string, `"abc"`, `"testing"`, the pangram,
  one million `a` characters (a multi-block input), and the ERC-20 `Transfer`
  and `Approval` event topics, which appear in every token transfer log on every
  EVM chain.
- **Both EIP-1967 storage slots**, which that EIP defines as
  `keccak256(label) - 1` and states as literals:
  `0x360894a1…` for the implementation slot and `0xb5312768…` for the admin slot.
- **Eight selectors** anyone can check against a deployed contract:
  `transfer(address,uint256)` → `0xa9059cbb`, `approve(address,uint256)` →
  `0x095ea7b3`, `balanceOf(address)` → `0x70a08231`, `owner()` → `0x8da5cb5b`,
  plus `totalSupply()`, `transferFrom(…)`, ERC-165's `supportsInterface(bytes4)`
  → `0x01ffc9a7` and UUPS's `upgradeTo(address)` → `0x3659cfe6`.
- **An independent implementation.** `tests/reference_keccak.py` is a second,
  spec-literal Keccak written in the obvious loop-over-indices style. The
  production module unrolls the 25 lanes into local variables for speed, so a
  transcription error there would not reproduce itself in the reference. The two
  are compared on every input length from 0 to 400 bytes, on the exact rate
  boundaries (134, 135, 136, 137, 271, 272, 273 …) and on 60 seeded random
  inputs.
- **Separation from SHA3**, asserted directly, so an accidental swap to
  `hashlib` would fail rather than quietly change every selector.

`selector-collide selftest` runs the committed vectors from the installed
package:

```
$ selector-collide selftest
  ok    keccak256 empty string
  ok    keccak256 "abc"
  ok    keccak256 "testing"
  ok    keccak256 pangram
  ok    keccak256 one million 'a' (multi-block)
  ok    keccak256 ERC-20 Transfer event topic
  ok    keccak256 ERC-20 Approval event topic
  ok    keccak256 135 bytes (one byte of padding, so 0x01 and 0x80 merge into 0x81)
  ok    keccak256 136 bytes (a full rate, so padding occupies a whole second block)
  ok    slot EIP-1967 implementation slot
  ok    slot EIP-1967 admin slot
  ok    selector transfer(address,uint256)
  ok    selector approve(address,uint256)
  ok    selector balanceOf(address)
  ok    selector owner()
  ok    selector totalSupply()
  ok    selector transferFrom(address,address,uint256)
  ok    selector supportsInterface(bytes4)
  ok    selector upgradeTo(address)
  ok    known collision transferFrom(address,address,uint256)
  ok    known collision gasprice_bit_ether(int128)
  ok    known collision burn(uint256)
  ok    known collision collate_propagate_storage(bytes16)
  ok    known collision transfer(address,uint256)
  ok    known collision many_msg_babbage(bytes1)
  ok    known collision func_2093253501(bytes)

  26 checks, 0 failed
```

The two boundary vectors at 135 and 136 bytes are this implementation's own
output rather than published values, and the self-test labels nothing as
published that is not. They earn their place by being cross-checked against the
reference implementation; they guard against regression, not against a shared
mistake.

## What this tool does not do

- **No network access.** It never fetches an ABI from Etherscan, an RPC node or
  anywhere else. It reads the local files you give it. There is no API key, no
  cache and no telemetry.
- **It does not read bytecode.** Everything is derived from ABIs and signature
  lists. A function that exists in the bytecode but not in the ABI you supplied
  is invisible, which matters most for hand-written assembly dispatchers — for
  those, write the surface out as a signature list.
- **It does not know your modifiers unless you tell it.** A standard ABI has no
  modifier information, so SC002 depends on annotations and nothing is inferred
  from names.
- **It does not confirm that a proxy is a proxy.** It compares the two ABIs you
  name. If the "proxy" ABI has no fallback it says so (SC006), but it cannot
  tell a `delegatecall` forwarder from a contract that merely looks like one.
  For checking a *deployed* proxy's EIP-1967 slots against live state, that is a
  different job and a different tool.
- **It does not resolve structs from Solidity source.** It is not a compiler.
  Give it the ABI solc produced, or write the tuple out.
- **It will probably not find you a 32-bit preimage.** See the measured rate
  above. Birthday collisions are cheap; chosen-target collisions are not.
- **It does not score exploitability.** Severities reflect what the ABIs say —
  state-changing against view, diverging modifiers — not whether a path is
  reachable in your deployment. That judgement is yours.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Ran to completion with nothing at or above the fail threshold |
| 1 | At least one finding at or above the fail threshold (see `--fail-on`) |
| 2 | Usage error |
| 3 | Input error: a file was missing, unreadable, or not a usable ABI |
| 4 | A search ran its whole budget without finding a collision |

`selftest` exits 1 if any vector fails.

## Development

```
$ python -m unittest discover -s tests -t . -v
...
Ran 246 tests in 13.783s

OK
```

246 tests holding 439 assertion statements, many of them inside loops over
tables. The suite is deterministic: random inputs use fixed seeds, and the
searches enumerate candidates in a fixed order, so the same arguments always
give the same result. It takes about fourteen seconds, most of which is the one
birthday search that has to hash ~47,000 candidates to find a real collision.

CI runs the suite on Python 3.11, 3.12 and 3.13, and then asserts from the
command line that the Keccak vectors pass, the example proxy pair reports
exactly the documented findings, the clean pair reports nothing, the diamond
reports its one clash, a birthday collision is found and verified, and all five
exit codes are what this README says they are.

## Licence

MIT. See [LICENSE](LICENSE).
