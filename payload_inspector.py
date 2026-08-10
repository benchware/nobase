from __future__ import annotations

from typing import Optional

from signatures import CODE_RE, MAGIC_PREFIXES


MAX_TEXT_SCAN_LENGTH = 2 * 1024 * 1024


def decode_text(data: bytes) -> Optional[str]:
    """
    Decode text conservatively.

    Supports:
      - UTF-8
      - UTF-16 LE/BE with BOM
      - likely UTF-16 LE/BE without BOM

    UTF-16 support is important for PowerShell EncodedCommand.
    """

    if not data:
        return None

    sample = data[:MAX_TEXT_SCAN_LENGTH]

    # -----------------------------------------------------
    # Explicit UTF-16 BOM
    # -----------------------------------------------------

    if sample.startswith(
        (
            b"\xff\xfe",
            b"\xfe\xff",
        )
    ):
        try:
            return sample.decode("utf-16")
        except UnicodeDecodeError:
            return None

    # -----------------------------------------------------
    # UTF-16 without BOM
    #
    # ASCII-heavy UTF-16LE:
    #
    #   I \0 E \0 X \0 ...
    #
    # UTF-8 decoding would technically accept those NULs,
    # so UTF-16 detection must happen first.
    # -----------------------------------------------------

    if len(sample) >= 8:

        even = sample[0::2]
        odd = sample[1::2]

        if even and odd:

            even_nul_ratio = (
                even.count(0) / len(even)
            )

            odd_nul_ratio = (
                odd.count(0) / len(odd)
            )

            # UTF-16LE
            if (
                odd_nul_ratio >= 0.20
                and even_nul_ratio <= 0.05
            ):
                try:
                    return sample.decode(
                        "utf-16-le"
                    )
                except UnicodeDecodeError:
                    pass

            # UTF-16BE
            if (
                even_nul_ratio >= 0.20
                and odd_nul_ratio <= 0.05
            ):
                try:
                    return sample.decode(
                        "utf-16-be"
                    )
                except UnicodeDecodeError:
                    pass

    # -----------------------------------------------------
    # UTF-8
    # -----------------------------------------------------

    if b"\x00" in sample:
        return None

    try:
        return sample.decode("utf-8")

    except UnicodeDecodeError:
        return None


def inspect_payload(
    data: bytes,
) -> tuple[bool, Optional[str]]:
    """
    Returns:

        (
            suspicious,
            decoded_text
        )

    decoded_text is returned so the Base64 detector can
    recursively inspect nested encoding without decoding
    the same bytes twice.
    """

    if not data:
        return False, None

    # Fast binary signature check.
    if data.startswith(MAGIC_PREFIXES):
        return True, None

    text = decode_text(data)

    if text is None:
        return False, None

    if CODE_RE.search(text):
        return True, text

    return False, text
