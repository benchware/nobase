from __future__ import annotations

import base64
import binascii
import re
from typing import Optional

from payload_inspector import inspect_payload


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
# Base32 patterns
# ---------------------------------------------------------

# RFC 4648 Base32 alphabet:
#   A-Z 2-7
#
# Base32 can use up to six "=" padding characters.
_B32_RE = re.compile(
    r"^[A-Z2-7]*={0,6}$",
    re.IGNORECASE,
)

# Used for finding embedded/split Base32.
_B32_FRAGMENT_RE = re.compile(
    rf"[A-Z2-7]"
    rf"{{{MIN_FRAGMENT_LENGTH},}}"
    rf"={{0,6}}",
    re.IGNORECASE,
)

# Characters allowed between intentionally split fragments.
_SPLIT_SEPARATOR_RE = re.compile(
    r"^[\s,;|:.\u200b\u200c\u200d\ufeff]{1,4}$"
)

_ZERO_WIDTH_RE = re.compile(
    r"[\u200b\u200c\u200d\ufeff]"
)
# ---------------------------------------------------------
# Base32 validation / decoding
# ---------------------------------------------------------

def _normalize_base32_padding(
    value: str,
) -> Optional[str]:

    if not value:
        return None

    core = value.rstrip("=")

    supplied_padding = (
        len(value) - len(core)
    )

    if supplied_padding > 6:
        return None

    remainder = len(core) % 8

    # RFC 4648 Base32 has no valid encodings with these
    # numbers of unpadded characters in the final block.
    if remainder in (1, 3, 6):
        return None

    required_padding = (
        -len(core)
    ) % 8

    if supplied_padding not in (
        0,
        required_padding,
    ):
        return None

    return (
        core
        + ("=" * required_padding)
    )


def _decode_base32(
    value: str,
) -> Optional[bytes]:

    if len(value) < MIN_CANDIDATE_LENGTH:
        return None

    if _B32_RE.fullmatch(value) is None:
        return None

    padded = _normalize_base32_padding(value)

    if padded is None:
        return None

    try:
        decoded = base64.b32decode(
            padded,
            casefold=True,
        )
    except (binascii.Error, ValueError):
        return None

    if len(decoded) < MIN_DECODED_LENGTH:
        return None

    return decoded


# ---------------------------------------------------------
# Base32 confidence
# ---------------------------------------------------------

def _base32_confidence(
    candidate: str,
    decoded: bytes,
    suspicious: bool,
    text: Optional[str],
) -> int:
    """
    Return a confidence score from 0-100 that candidate is
    intentionally Base32-encoded content.

    The score is deliberately conservative because ordinary
    uppercase text can belong to the Base32 alphabet.
    """

    score = 0

    core = candidate.rstrip("=")

    # Strongest signal: the decoded payload itself is suspicious.
    if suspicious:
        score += 70

    # Valid Base32 padding is a useful signal.
    if "=" in candidate:
        if candidate.endswith("="):
            score += 10

    # A correctly sized Base32 block is more convincing than
    # arbitrary uppercase text.
    if len(core) % 8 == 0:
        score += 10

    # Longer candidates provide more evidence.
    if len(core) >= 24:
        score += 10
    elif len(core) >= 16:
        score += 5

    # Successfully decoded printable/text payload is useful,
    # but not sufficient on its own.
    if text is not None:
        score += 5

    # Reduce confidence for candidates consisting entirely of
    # ordinary alphabetic uppercase text. This is where Base32
    # has particularly bad false-positive behavior.
    if (
        core
        and all(
            "A" <= char.upper() <= "Z"
            for char in core
        )
    ):
        score -= 25

    return max(0, min(100, score))


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
            recognized_as_base32,
            suspicious
        )
    """

    decoded = _decode_base32(
        candidate
    )

    if decoded is None:
        return False, False

    if len(decoded) > MAX_DECODED_LENGTH:
        return True, True

    suspicious, text = inspect_payload(
        decoded
    )

    # Directly suspicious decoded payload.
    if suspicious:
        return True, True

    if (
        text is None
        or depth >= MAX_RECURSION_DEPTH
    ):
        return True, False

    text = text.strip()

    # ---------------------------------------------------------
    # Nested Base32
    #
    # outer Base32
    #       ↓
    # inner Base32
    #       ↓
    # actual payload
    # ---------------------------------------------------------

    nested_decoded = _decode_base32(text)

    if nested_decoded is not None:

        _, nested_suspicious = _analyze_candidate(
            text,
            depth + 1,
        )

        if nested_suspicious:
            return True, True

        # It was valid Base32, even if the decoded payload
        # wasn't suspicious.
        return True, False

    # ---------------------------------------------------------
    # Embedded Base32
    # ---------------------------------------------------------

    if _scan_embedded(
        text,
        depth + 1,
    ):
        return True, True

    # ---------------------------------------------------------
    # The candidate itself was valid Base32.
    # ---------------------------------------------------------

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

    for match in _B32_FRAGMENT_RE.finditer(
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
        # Reconstruct intentionally split Base32:
        #
        #   ABCDEFGH IJKLMNPQ
        #   ABCDEFGH;IJKLMNPQ
        #   ABCDEFGH<ZWSP>IJKLMNPQ
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


def _compact_wrapped_base32(
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
    # the entire input itself is Base32.
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
        # If the complete input is valid benign Base32,
        # don't waste CPU scanning arbitrary substrings
        # inside the encoded representation.
        if recognized:
            return False

    # -----------------------------------------------------
    # PEM / Data URI
    # -----------------------------------------------------

    if wrapped:

        compact = (
            _compact_wrapped_base32(
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
    # Mixed text / embedded / split Base32
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
