from __future__ import annotations

import base64
import unittest

from base64_detector import (
    looks_encoded_payload,
    reject_encoded_string,
)


def b64(data: bytes) -> str:
    return base64.b64encode(
        data
    ).decode("ascii")


class Base64DetectorTests(unittest.TestCase):

    def test_normal_text(self):
        self.assertFalse(
            looks_encoded_payload(
                "hello this is normal text"
            )
        )

    def test_benign_base64(self):
        value = b64(
            b"hello world"
        )

        self.assertFalse(
            looks_encoded_payload(value)
        )

    def test_python_os_system(self):
        value = b64(
            b"os.system('whoami')"
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_python_subprocess(self):
        value = b64(
            b"subprocess.run(['whoami'])"
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_powershell_utf16le(self):

        script = (
            "IEX('Write-Host hello')"
        ).encode("utf-16-le")

        value = b64(script)

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_windows_executable(self):

        value = b64(
            b"MZ"
            + (b"\x00" * 64)
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_elf(self):

        value = b64(
            b"\x7fELF"
            + (b"\x00" * 64)
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_nested_base64(self):

        payload = b64(
            b"os.system('whoami')"
        )

        outer = b64(
            payload.encode("ascii")
        )

        self.assertTrue(
            looks_encoded_payload(
                outer
            )
        )

    def test_three_levels(self):

        value = b64(
            b"os.system('whoami')"
        )

        value = b64(
            value.encode("ascii")
        )

        value = b64(
            value.encode("ascii")
        )

        self.assertTrue(
            looks_encoded_payload(
                value
            )
        )

    def test_embedded_base64(self):

        payload = b64(
            b"subprocess.run(['id'])"
        )

        value = (
            f"hello:{payload}:world"
        )

        self.assertTrue(
            looks_encoded_payload(
                value
            )
        )

    def test_split_base64(self):

        payload = b64(
            b"os.system('whoami')"
        )

        pieces = [
            payload[i:i + 8]
            for i in range(
                0,
                len(payload),
                8,
            )
        ]

        value = " ".join(pieces)

        self.assertTrue(
            looks_encoded_payload(
                value
            )
        )

    def test_zero_width_split(self):

        payload = b64(
            b"os.system('whoami')"
        )

        pieces = [
            payload[i:i + 8]
            for i in range(
                0,
                len(payload),
                8,
            )
        ]

        value = "\u200b".join(
            pieces
        )

        self.assertTrue(
            looks_encoded_payload(
                value
            )
        )

    def test_data_uri(self):

        payload = b64(
            b"<script>alert(1)</script>"
        )

        value = (
            "data:text/plain;base64,"
            + payload
        )

        self.assertTrue(
            looks_encoded_payload(
                value
            )
        )

    def test_reject(self):

        value = b64(
            b"os.system('whoami')"
        )

        self.assertEqual(
            reject_encoded_string(
                value
            ),
            "",
        )

    def test_keep_benign(self):

        value = "normal message"

        self.assertEqual(
            reject_encoded_string(
                value
            ),
            value,
        )


if __name__ == "__main__":
    unittest.main()
