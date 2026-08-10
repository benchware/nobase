from __future__ import annotations

import base64
import binascii
import re
from typing import Optional


MIN_CANDIDATE_LENGTH = 16
MIN_DECODED_LENGTH = 8

MAX_INPUT_LENGTH = 4 * 1024 * 1024
MAX_DECODED_LENGTH = 8 * 1024 * 1024
MAX_TEXT_SCAN_LENGTH = 1_000_000
MAX_RECURSION_DEPTH = 3


_DATA_URI_RE = re.compile(
    r"^data:[A-Za-z0-9.+/-]+;base64,",
    re.IGNORECASE,
)

_PEM_RE = re.compile(
    r"^-{5}(?:BEGIN|END)[^-]*-{5}$",
    re.IGNORECASE | re.MULTILINE,
)

_B64_RUN_RE = re.compile(
    r"[A-Za-z0-9+/_-]{16,}={0,2}"
)

_B32_RUN_RE = re.compile(
    r"[A-Z2-7]{16,}={0,6}",
    re.IGNORECASE,
)

_B64_STANDARD_RE = re.compile(
    r"^[A-Za-z0-9+/]*={0,2}$"
)

_B64_URLSAFE_RE = re.compile(
    r"^[A-Za-z0-9_-]*={0,2}$"
)

_B32_RE = re.compile(
    r"^[A-Z2-7]*={0,6}$",
    re.IGNORECASE,
)

_CODE_PATTERNS = (
    # Python / generic scripting
    re.compile(r"\bprint\s*\(", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"\b__import__\s*\(", re.I),
    re.compile(r"\bsubprocess\s*\.", re.I),
    re.compile(r"\bos\s*\.\s*system\s*\(", re.I),

    # JavaScript / HTML
    re.compile(r"<\s*script\b", re.I),
    re.compile(r"javascript\s*:", re.I),

    # Shell
    re.compile(r"#!\s*/(?:usr/)?bin/(?:ba)?sh\b", re.I),
    re.compile(r"\bcurl\s+https?://", re.I),
    re.compile(r"\bwget\s+https?://", re.I),

    # Windows CMD / BAT
    re.compile(r"@echo\s+(?:off|on)\b", re.I),
    re.compile(r"\bcmd(?:\.exe)?\s+/[a-z]+\b", re.I),
    re.compile(r"\b(?:set|if|for|goto|call)\s+[^ \r\n]+", re.I),

    # PowerShell
    re.compile(r"\bpowershell(?:\.exe)?\b", re.I),
    re.compile(r"\bpwsh(?:\.exe)?\b", re.I),
    re.compile(r"\bInvoke-(?:Expression|Command|WebRequest)\b", re.I),
    re.compile(r"\bStart-Process\b", re.I),
    re.compile(r"\bIEX\s*\(", re.I),
    re.compile(r"\bSet-ExecutionPolicy\b", re.I),
)


_MAGIC_PREFIXES = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\x00asm",
    b"\xca\xfe\xba\xbe",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"MSCF",
    b"Rar!\x1a\x07",
)


def _fix_padding(value: str) -> str:
    value = value.rstrip("=")
    return value + "=" * (-len(value) % 4)


def _decode_base64(value: str) -> Optional[bytes]:
    if len(value) < MIN_CANDIDATE_LENGTH:
        return None

    value = _fix_padding(value)

    if _B64_STANDARD_RE.fullmatch(value):
        try:
            decoded = base64.b64decode(
                value,
                validate=True,
            )

            if len(decoded) >= MIN_DECODED_LENGTH:
                return decoded

        except (binascii.Error, ValueError):
            pass

    if _B64_URLSAFE_RE.fullmatch(value):
        try:
            decoded = base64.urlsafe_b64decode(value)

            if len(decoded) >= MIN_DECODED_LENGTH:
                return decoded

        except (binascii.Error, ValueError):
            pass

    return None


def _decode_base32(value: str) -> Optional[bytes]:
    if len(value) < MIN_CANDIDATE_LENGTH:
        return None

    if not _B32_RE.fullmatch(value):
        return None

    try:
        decoded = base64.b32decode(
            _fix_padding(value.upper()),
            casefold=True,
        )

        if len(decoded) >= MIN_DECODED_LENGTH:
            return decoded

    except (binascii.Error, ValueError):
        pass

    return None


def _looks_executable(data: bytes) -> bool:
    return any(
        data.startswith(prefix)
        for prefix in _MAGIC_PREFIXES
    )


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False

    sample = data[:4096]

    if b"\x00" in sample:
        return False

    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _looks_like_code(data: bytes) -> bool:
    if not _looks_like_text(data):
        return False

    text = data[:MAX_TEXT_SCAN_LENGTH].decode(
        "utf-8",
        errors="strict",
    )

    return any(
        pattern.search(text)
        for pattern in _CODE_PATTERNS
    )


def _analyze_decoded(
    data: bytes,
    depth: int,
) -> bool:

    if not data:
        return False

    if len(data) > MAX_DECODED_LENGTH:
        return True

    if _looks_executable(data):
        return True

    if _looks_like_code(data):
        return True

    if depth >= MAX_RECURSION_DEPTH:
        return False

    if not _looks_like_text(data):
        return False

    text = data[:MAX_TEXT_SCAN_LENGTH].decode(
        "utf-8",
        errors="strict",
    )

    for match in _B64_RUN_RE.finditer(text):
        decoded = _decode_base64(match.group(0))

        if decoded is not None:
            if _analyze_decoded(
                decoded,
                depth + 1,
            ):
                return True

    return False


def _check_base64(
    candidate: str,
    depth: int,
) -> bool:

    decoded = _decode_base64(candidate)

    if decoded is None:
        return False

    return _analyze_decoded(
        decoded,
        depth,
    )


def _check_base32(
    candidate: str,
    depth: int,
) -> bool:

    decoded = _decode_base32(candidate)

    if decoded is None:
        return False

    return _analyze_decoded(
        decoded,
        depth,
    )


def _normalize(value: str) -> str:
    if any(
        c in value
        for c in (
            " ",
            "\t",
            "\r",
            "\n",
            "\u200b",
            "\u200c",
            "\u200d",
            "\ufeff",
        )
    ):
        value = re.sub(
            r"[\s\u200b\u200c\u200d\ufeff]+",
            "",
            value,
        )

    value = _DATA_URI_RE.sub(
        "",
        value,
        count=1,
    )

    value = _PEM_RE.sub(
        "",
        value,
    )

    return value.strip()


def looks_encoded_payload(value: str) -> bool:
    if not isinstance(value, str):
        return False

    if not value:
        return False

    if len(value) > MAX_INPUT_LENGTH:
        return True

    value = _normalize(value)

    if not value:
        return False

    # Whole-string checks are the cheapest useful path.
    if _check_base64(value, 0):
        return True

    if _check_base32(value, 0):
        return True

    # Embedded Base64/Base64URL.
    runs = list(_B64_RUN_RE.finditer(value))

    for match in runs:
        if _check_base64(
            match.group(0),
            0,
        ):
            return True

    # Reconstruct only adjacent/split Base64 fragments.
    if len(runs) >= 2:
        start = runs[0].start()
        end = runs[0].end()

        for match in runs[1:]:
            gap = value[end:match.start()]

            if not gap or all(
                c in ",;|:/._-"
                for c in gap
            ):
                end = match.end()
                continue

            candidate = value[start:end]

            if len(candidate) >= MIN_CANDIDATE_LENGTH:
                if _check_base64(
                    candidate,
                    0,
                ):
                    return True

            start = match.start()
            end = match.end()

        candidate = value[start:end]

        if len(candidate) >= MIN_CANDIDATE_LENGTH:
            if _check_base64(
                candidate,
                0,
            ):
                return True

    # Embedded Base32.
    for match in _B32_RUN_RE.finditer(value):
        if _check_base32(
            match.group(0),
            0,
        ):
            return True

    return False


def reject_encoded_string(value: str) -> str:
    if looks_encoded_payload(value):
        return ""

    return value