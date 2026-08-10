import base64
import unittest

from base32_detector import (
    looks_encoded_payload,
    reject_encoded_string,
)


def b32(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii")


class Base32DetectorTests(unittest.TestCase):

    def test_normal_text(self):
        self.assertFalse(
            looks_encoded_payload(
                "hello this is normal text"
            )
        )

    def test_benign_base32(self):
        value = b32(b"hello world")

        self.assertFalse(
            looks_encoded_payload(value)
        )

    def test_python_os_system(self):
        value = b32(
            b"os.system('whoami')"
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_python_subprocess(self):
        value = b32(
            b"subprocess.run(['whoami'])"
        )

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_nested_base32(self):
        inner = b32(
            b"os.system('whoami')"
        )

        outer = b32(
            inner.encode("ascii")
        )

        self.assertTrue(
            looks_encoded_payload(outer)
        )

    def test_split_base32(self):
        payload = b32(
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
            looks_encoded_payload(value)
        )

    def test_zero_width_split(self):
        payload = b32(
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

        value = "\u200b".join(pieces)

        self.assertTrue(
            looks_encoded_payload(value)
        )

    def test_reject(self):
        value = b32(
            b"os.system('whoami')"
        )

        self.assertEqual(
            reject_encoded_string(value),
            "",
        )

    def test_keep_benign(self):
        value = "normal message"

        self.assertEqual(
            reject_encoded_string(value),
            value,
        )


if __name__ == "__main__":
    unittest.main()