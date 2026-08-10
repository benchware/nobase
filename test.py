from detect_base64 import (
    looks_encoded_payload,
    reject_encoded_string
)

value = "QWl6byBBaXpvIFdobyBJcyBOYW5kYXJlPw==" # Translates to "Aizo Aizo Who Is Nandare?" because it rejects only code-like content and not basic text

if looks_encoded_payload(value):
    print("Rejected: encoded payload detected")
else:
    print("Allowed")