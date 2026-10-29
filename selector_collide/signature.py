"""Canonicalisation of Solidity function signatures.

A selector is ``keccak256(canonical_signature)[:4]``, and "canonical" is a
precise thing: the function name, then the parameter types in parentheses,
separated by single commas, with no spaces, no parameter names, no data
location keywords, no return types, and every type written in its canonical
form. ``uint`` is an alias for ``uint256``; a struct parameter is written as a
parenthesised tuple of its members; an enum is its underlying ``uint8``; a
contract type is ``address``.

Getting this wrong produces a selector that is simply a different number, so
the work here is as load-bearing as the hash itself. What is and is not
supported is listed in the README's canonicalisation matrix and pinned by
``tests/test_signature.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .keccak import selector_hex

__all__ = [
    "SignatureError",
    "Entry",
    "canonical_type",
    "canonical_signature",
    "parse_signature",
    "split_top_level",
]


class SignatureError(ValueError):
    """A signature or type could not be canonicalised."""


# Aliases the ABI specification defines. ``byte`` was removed in Solidity 0.8
# but still turns up in older ABIs and hand-written signature lists.
_TYPE_ALIASES = {
    "uint": "uint256",
    "int": "int256",
    "byte": "bytes1",
    "fixed": "fixed128x18",
    "ufixed": "ufixed128x18",
}

# Keywords that may precede a type in human-readable Solidity, and what the
# type becomes. A contract reference is an address; an enum is its smallest
# underlying integer type, which Solidity caps at 256 members, hence uint8.
_TYPE_PREFIXES = {
    "contract": "address",
    "enum": "uint8",
    "interface": "address",
}

# Dropped wherever they appear in a parameter: data locations and the
# payability marker on an address are not part of the canonical type.
_DROPPED_WORDS = frozenset({"calldata", "memory", "storage", "payable"})

# Function-level keywords that are not modifiers and carry no selector meaning.
_NON_MODIFIER_KEYWORDS = frozenset({
    "public", "external", "internal", "private",
    "pure", "view", "payable", "nonpayable",
    "virtual", "override", "returns", "function",
})

_MUTABILITY_KEYWORDS = frozenset({"pure", "view", "payable"})

_SIMPLE_TYPES = frozenset({"address", "bool", "string", "bytes", "function", "tuple"})


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside parentheses or brackets.

    ``"uint256,(address,bool)[2],bytes"`` splits into three parts, not five.
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth < 0:
                raise SignatureError(f"unbalanced brackets in {text!r}")
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if depth != 0:
        raise SignatureError(f"unbalanced brackets in {text!r}")
    tail = "".join(current)
    if parts or tail.strip():
        parts.append(tail)
    return [p.strip() for p in parts]


def _split_array_suffix(type_text: str) -> tuple[str, str]:
    """Split a type into its base and its array suffixes.

    ``"uint[2][]"`` becomes ``("uint", "[2][]")``. Only trailing bracket groups
    are treated as suffixes, so a tuple's own parentheses are left alone.
    """
    suffix: list[str] = []
    rest = type_text.rstrip()
    while rest.endswith("]"):
        start = rest.rfind("[")
        if start == -1:
            raise SignatureError(f"unbalanced brackets in type {type_text!r}")
        inner = rest[start + 1:-1].strip()
        if inner:
            if not inner.isdigit() or inner != str(int(inner)) or int(inner) < 1:
                raise SignatureError(
                    f"fixed array length must be a positive integer without "
                    f"leading zeros, got {inner!r} in {type_text!r}"
                )
            suffix.append(f"[{inner}]")
        else:
            suffix.append("[]")
        rest = rest[:start].rstrip()
    suffix.reverse()
    return rest, "".join(suffix)


def _check_elementary(base: str, original: str) -> str:
    """Validate an elementary type name, returning it unchanged."""
    if base in _SIMPLE_TYPES:
        return base

    if base.startswith("uint") or base.startswith("int"):
        digits = base[4:] if base.startswith("uint") else base[3:]
        if digits.isdigit():
            bits = int(digits)
            if digits == str(bits) and 8 <= bits <= 256 and bits % 8 == 0:
                return base
        raise SignatureError(
            f"integer width must be a multiple of 8 between 8 and 256, "
            f"got {base!r} in {original!r}"
        )

    if base.startswith("bytes"):
        digits = base[5:]
        if digits.isdigit():
            size = int(digits)
            if digits == str(size) and 1 <= size <= 32:
                return base
        raise SignatureError(
            f"bytesN size must be between 1 and 32, got {base!r} in {original!r}"
        )

    if base.startswith("fixed") or base.startswith("ufixed"):
        body = base[5:] if base.startswith("fixed") else base[6:]
        m, sep, n = body.partition("x")
        if sep and m.isdigit() and n.isdigit():
            bits, decimals = int(m), int(n)
            if (m == str(bits) and n == str(decimals)
                    and 8 <= bits <= 256 and bits % 8 == 0 and 0 < decimals <= 80):
                return base
        raise SignatureError(
            f"fixed-point type must be fixedMxN with M a multiple of 8 in "
            f"8..256 and N in 1..80, got {base!r} in {original!r}"
        )

    raise SignatureError(
        f"unknown type {base!r} in {original!r}; struct and user-defined types "
        f"must be given as an expanded tuple, or supplied through an ABI JSON "
        f"file where solc has already resolved them"
    )


def _match_parens(text: str) -> tuple[str, str]:
    """Split ``"(a,b)[2] memory x"`` into ``("(a,b)", "[2] memory x")``."""
    depth = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[:i + 1], text[i + 1:].strip()
    raise SignatureError(f"unbalanced parentheses in type {text!r}")


def _take_suffixes(text: str) -> tuple[str, str]:
    """Take leading array suffixes off ``text``, returning them and the rest."""
    rest = text.strip()
    suffix: list[str] = []
    while rest.startswith("["):
        close = rest.find("]")
        if close == -1:
            raise SignatureError(f"unbalanced brackets in type {text!r}")
        inner = rest[1:close].strip()
        if inner:
            if not inner.isdigit() or inner != str(int(inner)) or int(inner) < 1:
                raise SignatureError(
                    f"fixed array length must be a positive integer without "
                    f"leading zeros, got {inner!r} in {text!r}"
                )
            suffix.append(f"[{inner}]")
        else:
            suffix.append("[]")
        rest = rest[close + 1:].strip()
    return "".join(suffix), rest


def _check_trailing(trailing: str, original: str) -> None:
    """Allow only data-location keywords and a single parameter name."""
    names = 0
    for word in trailing.split():
        if word in _DROPPED_WORDS:
            continue
        if word in _TYPE_PREFIXES or word == "struct":
            raise SignatureError(
                f"cannot read {original!r}: the type keyword {word!r} follows the type"
            )
        if not (word[0].isalpha() or word[0] in "_$"):
            raise SignatureError(f"cannot read {original!r}: unexpected {word!r}")
        names += 1
        if names > 1:
            raise SignatureError(
                f"cannot read {original!r}: more than one name after the type"
            )


def canonical_type(type_text: str, components: list[dict] | None = None) -> str:
    """Return the canonical ABI form of a single parameter type.

    Accepts the canonical form itself and the looser forms that appear in
    Solidity source: a parameter name, a data location, ``address payable``, or
    a ``contract``/``enum``/``interface`` keyword. ``components`` is the ABI
    JSON member list that accompanies a ``tuple`` type; when present the tuple
    is expanded to ``(member,member,...)``.
    """
    text = " ".join(type_text.split())
    if not text:
        raise SignatureError("empty parameter type")

    for keyword, replacement in _TYPE_PREFIXES.items():
        if text.startswith(keyword + " "):
            # "contract IERC20 token" -> address. The named type and any
            # parameter name that follows carry no selector information.
            return replacement
    if text.startswith("struct ") or text == "struct":
        raise SignatureError(
            f"struct type {type_text!r} must be expanded to a tuple; an ABI "
            f"JSON file carries the members in its 'components' key"
        )

    if text.startswith("("):
        base, rest = _match_parens(text)
        suffix, trailing = _take_suffixes(rest)
        _check_trailing(trailing, type_text)
        inner = base[1:-1].strip()
        if not inner:
            return "()" + suffix
        members = [canonical_type(part) for part in split_top_level(inner)]
        return "(" + ",".join(members) + ")" + suffix

    words = text.split()
    _check_trailing(" ".join(words[1:]), type_text)
    base, suffix = _split_array_suffix(words[0])
    base = _TYPE_ALIASES.get(base, base)

    if base == "tuple":
        if components is None:
            raise SignatureError(
                "a 'tuple' type needs its 'components' members to be canonicalised"
            )
        members = [
            canonical_type(c.get("type", ""), c.get("components"))
            for c in components
        ]
        return "(" + ",".join(members) + ")" + suffix

    if "." in base:
        raise SignatureError(
            f"qualified type name {base!r} in {type_text!r} cannot be resolved "
            f"from a signature alone; use an ABI JSON file"
        )

    return _check_elementary(base, type_text) + suffix


def canonical_signature(name: str, types: list[str] | tuple[str, ...]) -> str:
    """Join an already-canonical name and type list into a signature."""
    return f"{name}({','.join(types)})"


def _check_name(name: str, original: str) -> str:
    if not name:
        raise SignatureError(f"missing function name in {original!r}")
    if not (name[0].isalpha() or name[0] in "_$"):
        raise SignatureError(
            f"function name {name!r} in {original!r} does not start with a "
            f"letter, underscore or dollar sign"
        )
    for ch in name[1:]:
        if not (ch.isalnum() or ch in "_$"):
            raise SignatureError(f"illegal character {ch!r} in name {name!r}")
    return name


@dataclass(frozen=True)
class Entry:
    """One dispatchable (or decodable) ABI entry, canonicalised.

    ``kind`` follows the ABI JSON ``type`` field: ``function``, ``error``,
    ``event``, ``constructor``, ``fallback`` or ``receive``. Only ``function``
    entries take part in selector dispatch; ``error`` entries share the 4-byte
    space but are matched when decoding a revert, not when routing a call.
    """

    name: str
    types: tuple[str, ...]
    kind: str = "function"
    state_mutability: str = "nonpayable"
    modifiers: tuple[str, ...] = ()
    source: str = ""
    raw: str = ""
    outputs: tuple[str, ...] = field(default=(), compare=False)

    @property
    def signature(self) -> str:
        if self.kind in ("fallback", "receive"):
            return f"{self.kind}()"
        return canonical_signature(self.name, self.types)

    @property
    def has_selector(self) -> bool:
        """Whether a 4-byte selector exists for this entry.

        Functions and custom errors are identified by one. A constructor is
        not dispatched at all, an event is identified by a full 32-byte topic
        hash, and ``fallback``/``receive`` are reached by the absence of a
        matching selector rather than by one of their own.
        """
        return self.kind in ("function", "error")

    @property
    def selector(self) -> str | None:
        return selector_hex(self.signature) if self.has_selector else None

    @property
    def is_state_changing(self) -> bool:
        return self.state_mutability in ("nonpayable", "payable")

    @property
    def dispatchable(self) -> bool:
        """Whether a caller can route a call to this entry by its selector.

        Custom errors have selectors but are never dispatched to, so they are
        excluded: they matter for decoding a revert, not for routing a call.
        """
        return self.kind == "function"

    def describe(self) -> str:
        bits = [self.state_mutability] if self.state_mutability else []
        bits += list(self.modifiers)
        suffix = f" [{' '.join(bits)}]" if bits else ""
        return f"{self.signature}{suffix}"


def parse_signature(text: str, source: str = "") -> Entry:
    """Parse one human-readable signature line into an :class:`Entry`.

    Accepts a canonical signature, and also the looser forms people paste from
    Solidity source or from ``cast``::

        transfer(address,uint256)
        function transfer(address to, uint256 amount) external returns (bool)
        error InsufficientBalance(uint256 available, uint256 required)
        withdraw(uint256) onlyAdmin

    Trailing identifiers that are not Solidity keywords are recorded as
    modifiers. They are not part of the selector -- they exist so that a
    signature list can state the access control that a standard ABI omits.
    """
    line = " ".join(text.split())
    if not line:
        raise SignatureError("empty signature")

    kind = "function"
    for keyword in ("function", "error", "event", "constructor"):
        if line == keyword or line.startswith(keyword + " ") or line.startswith(keyword + "("):
            if keyword != "function":
                kind = keyword
            line = line[len(keyword):].strip()
            break

    if line in ("fallback()", "fallback"):
        return Entry("", (), "fallback", "nonpayable", (), source, text)
    if line in ("receive()", "receive"):
        return Entry("", (), "receive", "payable", (), source, text)

    open_paren = line.find("(")
    if open_paren == -1:
        raise SignatureError(f"no parameter list in {text!r}")

    # Match the closing parenthesis of the parameter list.
    depth = 0
    close_paren = -1
    for i, ch in enumerate(line[open_paren:], start=open_paren):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_paren = i
                break
    if close_paren == -1:
        raise SignatureError(f"unbalanced parentheses in {text!r}")

    name = _check_name(line[:open_paren].strip(), text) if kind != "constructor" else ""
    params = line[open_paren + 1:close_paren].strip()
    types = tuple(canonical_type(part) for part in split_top_level(params)) if params else ()

    trailer = line[close_paren + 1:].strip()
    mutability = "nonpayable"
    modifiers: list[str] = []
    outputs: tuple[str, ...] = ()

    if trailer:
        # Pull a returns(...) clause out before looking at bare words.
        lowered = trailer.replace("returns (", "returns(")
        idx = lowered.find("returns(")
        if idx != -1:
            rest = lowered[idx + len("returns("):]
            depth = 1
            end = -1
            for i, ch in enumerate(rest):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end == -1:
                raise SignatureError(f"unbalanced returns clause in {text!r}")
            inner = rest[:end].strip()
            if inner:
                outputs = tuple(canonical_type(p) for p in split_top_level(inner))
            lowered = lowered[:idx] + rest[end + 1:]
        for word in lowered.replace(",", " ").split():
            word = word.strip()
            if not word:
                continue
            if word in _MUTABILITY_KEYWORDS:
                mutability = word
            elif word in _NON_MODIFIER_KEYWORDS:
                continue
            else:
                modifiers.append(word.split("(")[0])

    return Entry(name, types, kind, mutability, tuple(modifiers), source, text, outputs)
