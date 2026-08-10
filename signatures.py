from __future__ import annotations

import re


MAGIC_PREFIXES = (
    # Windows PE
    b"MZ",

    # ELF
    b"\x7fELF",

    # Mach-O
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",

    # WebAssembly
    b"\x00asm",

    # Java class
    b"\xca\xfe\xba\xbe",

    # ZIP / JAR / Office Open XML
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",

    # gzip
    b"\x1f\x8b",

    # CAB
    b"MSCF",

    # RAR
    b"Rar!\x1a\x07",
)


# Keep these intentionally strong.
#
# We do NOT flag generic things such as:
#   print(
#   if
#   for
#   set
#
# because they produce unnecessary false positives.
CODE_RE = re.compile(
    r"""
    (?:
        # Python
        \b(?:eval|exec|__import__)\s*\(
      | \bsubprocess\s*\.
      | \bos\s*\.\s*system\s*\(
      | ^[ \t]*from\s+[A-Za-z_][\w.]*\s+import\s+
      | ^[ \t]*import\s+[A-Za-z_][\w.]*
      | ^[ \t]*def\s+[A-Za-z_]\w*\s*\(

        # JavaScript / HTML
      | <\s*script\b
      | javascript\s*:

        # Shell
      | \#\!\s*/(?:usr/)?bin/(?:ba|z|k)?sh\b
      | \b(?:bash|zsh|ksh|sh)\s+-c\b
      | \b(?:curl|wget)\b[^\r\n]{0,160}\bhttps?://

        # Windows CMD
      | @echo\s+(?:off|on)\b
      | \bcmd(?:\.exe)?\s+/(?:c|k)\b

        # PowerShell
      | \b(?:powershell|pwsh)(?:\.exe)?\b
      | \bInvoke-(?:Expression|Command|WebRequest|RestMethod)\b
      | \bStart-Process\b
      | \bSet-ExecutionPolicy\b
      | \bIEX\s*(?:\(|\s)
    )
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
