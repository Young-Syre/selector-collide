"""Reading ABIs and signature lists from local files.

Three input shapes are accepted, distinguished by content rather than by file
extension:

1. A standard Solidity JSON ABI: a top-level JSON array of entry objects.
2. A build artefact: a JSON object with an ``"abi"`` key holding that array.
   Foundry's ``forge build`` artefacts and Hardhat's artefacts both match, as
   does ``forge inspect <contract> abi``.
3. A plain signature list: one signature per line, ``#`` starting a comment.

Nothing here opens a network connection. The tool reads the files it is given
and nothing else; there is no Etherscan lookup, no RPC call and no cache.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .signature import Entry, SignatureError, canonical_type, parse_signature

__all__ = ["AbiError", "Source", "load_source", "load_selector_list", "parse_selector"]


class AbiError(ValueError):
    """An input file could not be read as an ABI or a signature list."""


@dataclass(frozen=True)
class Source:
    """The canonicalised entries of one input file."""

    label: str
    entries: tuple[Entry, ...]
    fmt: str  # "abi-json" | "artefact-json" | "signatures"

    @property
    def functions(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.entries if e.kind == "function")

    @property
    def errors(self) -> tuple[Entry, ...]:
        return tuple(e for e in self.entries if e.kind == "error")

    @property
    def has_fallback(self) -> bool:
        return any(e.kind == "fallback" for e in self.entries)

    @property
    def has_receive(self) -> bool:
        return any(e.kind == "receive" for e in self.entries)

    def selector_map(self, include_errors: bool = False) -> dict[str, list[Entry]]:
        """Map selector to the entries carrying it, in file order."""
        kinds = ("function", "error") if include_errors else ("function",)
        out: dict[str, list[Entry]] = {}
        for entry in self.entries:
            if entry.kind in kinds and entry.selector is not None:
                out.setdefault(entry.selector, []).append(entry)
        return out


def _entry_from_abi_object(obj: object, label: str, index: int) -> Entry | None:
    """Convert one ABI JSON entry. Returns None for entries with no selector role."""
    if not isinstance(obj, dict):
        raise AbiError(f"{label}: ABI entry {index} is not a JSON object")

    # The ABI specification makes "type" default to "function" when absent.
    kind = obj.get("type", "function")
    if not isinstance(kind, str):
        raise AbiError(f"{label}: ABI entry {index} has a non-string 'type'")
    if kind in ("event", "constructor"):
        return None
    if kind in ("fallback", "receive"):
        mutability = obj.get("stateMutability", "payable" if kind == "receive" else "nonpayable")
        return Entry("", (), kind, str(mutability), (), label, kind)
    if kind not in ("function", "error"):
        raise AbiError(f"{label}: ABI entry {index} has unknown type {kind!r}")

    name = obj.get("name")
    if not isinstance(name, str) or not name:
        raise AbiError(f"{label}: ABI entry {index} ({kind}) has no name")

    raw_inputs = obj.get("inputs", [])
    if not isinstance(raw_inputs, list):
        raise AbiError(f"{label}: 'inputs' of {name} is not a list")

    types: list[str] = []
    for position, param in enumerate(raw_inputs):
        if not isinstance(param, dict):
            raise AbiError(f"{label}: input {position} of {name} is not an object")
        declared = param.get("type")
        if not isinstance(declared, str) or not declared:
            raise AbiError(f"{label}: input {position} of {name} has no 'type'")
        components = param.get("components")
        if components is not None and not isinstance(components, list):
            raise AbiError(f"{label}: 'components' of {name} input {position} is not a list")
        try:
            types.append(canonical_type(declared, components))
        except SignatureError as exc:
            raise AbiError(f"{label}: input {position} of {name}: {exc}") from exc

    mutability = obj.get("stateMutability")
    if mutability is None:
        # Pre-0.5 ABIs used the booleans instead.
        if obj.get("payable") is True:
            mutability = "payable"
        elif obj.get("constant") is True:
            mutability = "view"
        else:
            mutability = "nonpayable"
    if not isinstance(mutability, str):
        raise AbiError(f"{label}: 'stateMutability' of {name} is not a string")

    # Non-standard, and the only way to express access control: solc does not
    # record modifiers in the ABI, so a "modifiers" key is accepted if one has
    # been added by hand or by a generator. Absent, rule SC002 cannot fire.
    raw_modifiers = obj.get("modifiers", [])
    if not isinstance(raw_modifiers, list) or not all(isinstance(m, str) for m in raw_modifiers):
        raise AbiError(f"{label}: 'modifiers' of {name} is not a list of strings")

    return Entry(
        name=name,
        types=tuple(types),
        kind=kind,
        state_mutability=mutability,
        modifiers=tuple(raw_modifiers),
        source=label,
        raw=json.dumps(obj, sort_keys=True),
    )


def _entries_from_abi_list(items: list, label: str) -> tuple[Entry, ...]:
    entries: list[Entry] = []
    for index, obj in enumerate(items):
        entry = _entry_from_abi_object(obj, label, index)
        if entry is not None:
            entries.append(entry)
    return tuple(entries)


def _entries_from_signature_text(text: str, label: str) -> tuple[Entry, ...]:
    entries: list[Entry] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        try:
            entries.append(parse_signature(stripped, label))
        except SignatureError as exc:
            raise AbiError(f"{label}:{number}: {exc}") from exc
    return tuple(entries)


def load_source(path: str | Path, label: str | None = None) -> Source:
    """Load one ABI or signature list from a local file.

    ``label`` defaults to the file's basename, so reports never carry the
    directory the file happened to live in.
    """
    file_path = Path(path)
    name = label if label is not None else file_path.name
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AbiError(f"cannot read {name}: {exc.strerror or exc}") from exc

    stripped = text.lstrip()
    if stripped[:1] in ("[", "{"):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AbiError(f"{name}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
        if isinstance(document, list):
            return Source(name, _entries_from_abi_list(document, name), "abi-json")
        if isinstance(document, dict):
            inner = document.get("abi")
            if isinstance(inner, list):
                return Source(name, _entries_from_abi_list(inner, name), "artefact-json")
            raise AbiError(
                f"{name}: JSON object has no 'abi' array; a build artefact must "
                f"carry its ABI under the 'abi' key"
            )
        raise AbiError(f"{name}: JSON is neither an ABI array nor an object with an 'abi' key")

    if not stripped:
        raise AbiError(f"{name}: file is empty")
    return Source(name, _entries_from_signature_text(text, name), "signatures")


def parse_selector(text: str) -> str:
    """Normalise a 4-byte selector to lowercase ``0x`` + 8 hex digits."""
    candidate = text.strip().lower()
    if candidate.startswith("0x"):
        candidate = candidate[2:]
    if len(candidate) != 8 or any(c not in "0123456789abcdef" for c in candidate):
        raise AbiError(
            f"{text!r} is not a 4-byte selector; expected 8 hex digits, "
            f"optionally prefixed with 0x"
        )
    return "0x" + candidate


def load_selector_list(path: str | Path, label: str | None = None) -> tuple[str, list[tuple[str, str]]]:
    """Load an allowlist of selectors or signatures from a local file.

    Each non-comment line is either a 4-byte selector or a signature, which is
    canonicalised and hashed. Returns the label and a list of
    ``(selector, origin)`` pairs in file order, where ``origin`` is the
    signature when one was given and the literal selector otherwise.
    """
    file_path = Path(path)
    name = label if label is not None else file_path.name
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AbiError(f"cannot read {name}: {exc.strerror or exc}") from exc

    found: list[tuple[str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        try:
            found.append((parse_selector(stripped), stripped))
            continue
        except AbiError:
            pass
        try:
            entry = parse_signature(stripped, name)
        except SignatureError as exc:
            raise AbiError(
                f"{name}:{number}: not a selector and not a signature: {exc}"
            ) from exc
        if entry.selector is None:
            raise AbiError(f"{name}:{number}: {stripped!r} has no selector")
        found.append((entry.selector, entry.signature))
    if not found:
        raise AbiError(f"{name}: no selectors or signatures found")
    return name, found
