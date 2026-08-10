from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from .payload_inspector import inspect_payload


MIN_CANDIDATE_LENGTH = 16
MIN_FRAGMENT_LENGTH = 8
MIN_DECODED_LENGTH = 8

MAX_INPUT_LENGTH = 4 * 1024 * 1024
MAX_DECODED_LENGTH = 8 * 1024 * 1024

MAX_RECURSION_DEPTH = 3


# ---------------------------------------------------------
# Wrappers
# ---------------------------------------------------------

_DATA_URI_RE = re.compile(
    r"^data:[^,\r\n]{0,512};base64,",
    re.IGNORECASE,
)

_PEM_ARMOR_RE = re.compile(
    r"^[ \t]*-----"
    r"(?:BEGIN|END)"
    r" [-A-Z0-9 ._/:]+"
    r"-----[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------
# Base64 patterns
# ---------------------------------------------------------

_B64_STANDARD_RE = re.compile(
    r"^[A-Za-z0-9+/]*={0,2}$"
)

_B64_URLSAFE_RE = re.compile(
    r"^[A-Za-z0-9_-]*={0,2}$"
)


# Used for finding embedded/split Base64.
#
# Start at 8 chars because fragments may have been split.
_B64_FRAGMENT_RE = re.compile(
    rf"[A-Za-z0-9+/_-]"
    rf"{{{MIN_FRAGMENT_LENGTH},}}"
    rf"={{0,2}}"
)


# Characters allowed between intentionally split fragments.
#
# Limited to tiny gaps to prevent expensive reconstruction
# across normal sentences.
_SPLIT_SEPARATOR_RE = re.compile(
    r"^[\s,;|:.\u200b\u200c\u200d\ufeff]{1,4}$"
)


_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\ufeff]"
)


# ---------------------------------------------------------
# Base64 validation / decoding
# ---------------------------------------------------------

def _normalize_padding(
    value: str,
) -> Optional[str]:

    if not value:
        return None

    core = value.rstrip("=")

    supplied_padding = (
        len(value) - len(core)
    )

    if supplied_padding > 2:
        return None

    remainder = len(core) % 4

    # Base64 cannot have a single leftover symbol.
    if remainder == 1:
        return None

    required_padding = (
        -len(core)
    ) % 4

    # Accept:
    #
    #   TQ==
    #   TQ
    #
    # Reject malformed:
    #
    #   TQ=
    #   TWFu=
    if supplied_padding not in (
        0,
        required_padding,
    ):
        return None

    return (
        core
        + ("=" * required_padding)
    )


def _decode_base64(
    value: str,
) -> Optional[bytes]:

    if len(value) < MIN_CANDIDATE_LENGTH:
        return None

    # Fast character validation before attempting decode.
    standard = (
        _B64_STANDARD_RE.fullmatch(value)
        is not None
    )

    urlsafe = (
        _B64_URLSAFE_RE.fullmatch(value)
        is not None
    )

    if not standard and not urlsafe:
        return None

    padded = _normalize_padding(value)

    if padded is None:
        return None

    try:

        if standard:

            decoded = base64.b64decode(
                padded,
                validate=True,
            )

        else:

            decoded = base64.b64decode(
                padded,
                altchars=b"-_",
                validate=True,
            )

    except (binascii.Error, ValueError):
        return None

    if len(decoded) < MIN_DECODED_LENGTH:
        return None

    return decoded


# ---------------------------------------------------------
# Candidate analysis
# ---------------------------------------------------------

def _analyze_candidate(
    candidate: str,
    depth: int,
) -> tuple[bool, bool]:
    """
    Returns:

        (
            recognized_as_base64,
            suspicious
        )
    """

    decoded = _decode_base64(
        candidate
    )

    if decoded is None:
        return False, False

    if len(decoded) > MAX_DECODED_LENGTH:
        # Fail closed for unexpectedly huge decoded content.
        return True, True

    suspicious, text = inspect_payload(
        decoded
    )

    if suspicious:
        return True, True

    if (
        text is None
        or depth >= MAX_RECURSION_DEPTH
    ):
        return True, False

    # Nested Base64.
    if _scan_embedded(
        text,
        depth + 1,
    ):
        return True, True

    return True, False


# ---------------------------------------------------------
# Embedded / split scanning
# ---------------------------------------------------------

def _scan_embedded(
    text: str,
    depth: int,
) -> bool:

    previous_end: Optional[int] = None

    fragments: list[str] = []

    def flush() -> bool:
        nonlocal fragments

        if len(fragments) < 2:
            fragments = []
            return False

        candidate = "".join(
            fragments
        )

        fragments = []

        if len(candidate) < MIN_CANDIDATE_LENGTH:
            return False

        _, suspicious = _analyze_candidate(
            candidate,
            depth,
        )

        return suspicious

    for match in _B64_FRAGMENT_RE.finditer(
        text
    ):

        fragment = match.group(0)

        # -------------------------------------------------
        # Direct embedded candidate
        # -------------------------------------------------

        if len(fragment) >= MIN_CANDIDATE_LENGTH:

            _, suspicious = _analyze_candidate(
                fragment,
                depth,
            )

            if suspicious:
                return True

        # -------------------------------------------------
        # Reconstruct intentionally split Base64:
        #
        #   abcdefgh ijklmnop
        #   abcdefgh;ijklmnop
        #   abcdefgh<ZWSP>ijklmnop
        #
        # We append fragment strings themselves rather than
        # slicing the original text, avoiding the old bug
        # where separators remained inside the candidate.
        # -------------------------------------------------

        if previous_end is None:

            fragments = [
                fragment
            ]

            previous_end = match.end()

            continue

        gap = text[
            previous_end:match.start()
        ]

        if (
            gap
            and _SPLIT_SEPARATOR_RE.fullmatch(
                gap
            )
        ):

            fragments.append(
                fragment
            )

        else:

            if flush():
                return True

            fragments = [
                fragment
            ]

        previous_end = match.end()

    return flush()


# ---------------------------------------------------------
# Wrapper handling
# ---------------------------------------------------------

def _strip_wrapper(
    value: str,
) -> tuple[str, bool]:

    value = value.strip()

    wrapped = False

    # Data URI.
    new_value, count = (
        _DATA_URI_RE.subn(
            "",
            value,
            count=1,
        )
    )

    if count:

        value = new_value

        wrapped = True

    # PEM headers MUST be removed before whitespace
    # normalization.
    if "-----" in value:

        new_value, count = (
            _PEM_ARMOR_RE.subn(
                "",
                value,
            )
        )

        if count:

            value = new_value

            wrapped = True

    return value.strip(), wrapped


def _compact_wrapped_base64(
    value: str,
) -> str:

    # PEM/Data URI content may legitimately contain line
    # wrapping.
    #
    # Zero-width chars are also stripped because they can be
    # used to split encoded content.
    value = _ZERO_WIDTH_RE.sub(
        "",
        value,
    )

    return "".join(
        value.split()
    )


# ---------------------------------------------------------
# Public API
# ---------------------------------------------------------

def looks_encoded_payload(
    value: str,
) -> bool:

    if not isinstance(value, str):
        return False

    if not value:
        return False

    # Prevent CPU/memory abuse.
    if len(value) > MAX_INPUT_LENGTH:
        return True

    value, wrapped = _strip_wrapper(
        value
    )

    if not value:
        return False

    # -----------------------------------------------------
    # Cheapest and most accurate path:
    #
    # the entire input itself is Base64.
    # -----------------------------------------------------

    if not any(
        char.isspace()
        for char in value
    ):

        recognized, suspicious = (
            _analyze_candidate(
                value,
                0,
            )
        )

        if suspicious:
            return True

        # Important:
        #
        # If the complete input is valid benign Base64,
        # don't waste CPU scanning arbitrary substrings
        # inside the encoded representation.
        if recognized:
            return False

    # -----------------------------------------------------
    # PEM / Data URI
    # -----------------------------------------------------

    if wrapped:

        compact = (
            _compact_wrapped_base64(
                value
            )
        )

        recognized, suspicious = (
            _analyze_candidate(
                compact,
                0,
            )
        )

        if suspicious:
            return True

        if recognized:
            return False

    # -----------------------------------------------------
    # Mixed text / embedded / split Base64
    # -----------------------------------------------------

    return _scan_embedded(
        value,
        0,
    )


def reject_encoded_string(
    value: str,
) -> str:

    if looks_encoded_payload(value):
        return ""

    return value
