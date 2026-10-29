"""selector-collide: an EVM function-selector collision and proxy-shadowing analyser.

Standard library only, no network access. The entry points most callers want:

    from selector_collide import keccak256, selector_hex, load_source
    from selector_collide.analyse import analyse_shadowing
"""

from __future__ import annotations

__version__ = "0.1.0"

from .abi import AbiError, Source, load_selector_list, load_source, parse_selector
from .keccak import keccak256, keccak256_hex, selector_bytes, selector_hex, selector_int
from .signature import Entry, SignatureError, canonical_signature, canonical_type, parse_signature

__all__ = [
    "__version__",
    "AbiError",
    "Entry",
    "SignatureError",
    "Source",
    "canonical_signature",
    "canonical_type",
    "keccak256",
    "keccak256_hex",
    "load_selector_list",
    "load_source",
    "parse_selector",
    "parse_signature",
    "selector_bytes",
    "selector_hex",
    "selector_int",
]
