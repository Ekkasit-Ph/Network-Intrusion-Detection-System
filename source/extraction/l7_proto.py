"""Translate nDPI protocol *names* (what NFStream reports) into the numeric
`L7_PROTO` encoding the NF-ToN-IoT-v2 training data stores.

The training column holds nProbe's `master.app` encoding, written as a
decimal number: the master protocol id before the point, the application
protocol id after it. Verified against the 16.9M-row training CSV:

    7.0    -> HTTP (7), no sub-protocol        [dominant port 80]
    91.0   -> TLS (91)                          [port 443]
    5.0    -> DNS (5)                           [port 53]
    7.178  -> HTTP (7) carrying app 178         [port 80]
    89.7   -> VNC (89) carrying HTTP (7)        [port 5800 = VNC-over-HTTP]

NFStream exposes the protocol *name* (`flow.application_name`, e.g. "HTTP",
"TLS.Google") and not the id, so this module rebuilds the name -> id table
from the `NDPI_PROTOCOL_*` constants the compiled engine exports. Reading
them from the live library rather than transcribing a table means the
mapping always matches the nDPI build that actually did the dissecting;
a transcribed table silently rots the moment nfstream is upgraded and
protocol ids shift.

Anything unmapped resolves to 0.0 (nDPI's own UNKNOWN id), which is also
the most common value in the training data (60.75%), so the model is on
familiar ground rather than seeing a value it never trained against.
"""

from __future__ import annotations

import logging
from functools import lru_cache

log = logging.getLogger(__name__)

UNKNOWN_L7_PROTO = 0.0

# nDPI's display names don't always match its constant names. These are the
# systematic differences: the network-layer protocols are declared as
# NDPI_PROTOCOL_IP_* but reported without that prefix.
_PREFIX_ALIASES = ("IP_",)

# Cases where the reported name differs from the constant in a way no rule
# derives. Kept explicit and small; anything added here should come from an
# observed mismatch, not a guess.
_EXPLICIT_ALIASES = {
    "MAIL_IMAPS": "IMAPS",
    "MAIL_POPS": "POPS",
    "MAIL_SMTPS": "SMTPS",
}


def _build_name_to_id() -> dict[str, int]:
    """name (upper-cased) -> nDPI protocol id, read from the loaded engine."""
    try:
        from nfstream.engine import engine
    except ImportError:  # nfstream absent: callers fall back to UNKNOWN
        log.warning("nfstream is not installed; every L7_PROTO will resolve to UNKNOWN")
        return {}

    lib = engine.lib
    table: dict[str, int] = {}
    for const in dir(lib):
        if not const.startswith("NDPI_PROTOCOL_"):
            continue
        value = getattr(lib, const)
        if not isinstance(value, int):
            continue
        name = const[len("NDPI_PROTOCOL_") :]
        # Skip the category/QOE enums that share the prefix but aren't
        # protocols -- they'd collide with real protocol names.
        if name.startswith(("CATEGORY_", "QOE_CATEGORY_", "NUM_CATEGORIES")):
            continue

        table.setdefault(name, value)
        for prefix in _PREFIX_ALIASES:
            if name.startswith(prefix):
                table.setdefault(name[len(prefix) :], value)
        if name in _EXPLICIT_ALIASES:
            table.setdefault(_EXPLICIT_ALIASES[name], value)
    return table


NAME_TO_ID: dict[str, int] = _build_name_to_id()


@lru_cache(maxsize=4096)
def encode(application_name: str | None) -> float:
    """NFStream's `application_name` -> the training data's L7_PROTO value.

    Handles both plain names ("HTTP") and nDPI's dotted master.app form
    ("TLS.Google"), which becomes the corresponding numeric master.app.
    """
    if not application_name:
        return UNKNOWN_L7_PROTO

    parts = application_name.upper().split(".")
    master = NAME_TO_ID.get(parts[0])
    if master is None:
        return UNKNOWN_L7_PROTO

    app = NAME_TO_ID.get(parts[1]) if len(parts) > 1 else None
    if not app:  # no sub-protocol, or one we can't resolve
        return float(master)

    # nProbe writes the two ids either side of a decimal point, so the
    # digits after it are the app id verbatim -- not a fraction.
    return float(f"{master}.{app}")


def coverage_report(names: list[str]) -> dict[str, object]:
    """How many of `names` this module can resolve. Used by the tests, and
    worth running against a real capture before trusting live scoring."""
    resolved = [n for n in names if encode(n) != UNKNOWN_L7_PROTO]
    unresolved = sorted({n for n in names if encode(n) == UNKNOWN_L7_PROTO})
    return {
        "total": len(names),
        "resolved": len(resolved),
        "unresolved_names": unresolved,
        "table_size": len(NAME_TO_ID),
    }
