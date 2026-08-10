# NoBase
This is a library that rejects Base64, Base32 and some encoding types.

This supports detecting encoded data that decodes into malicious executables, scripts, and code-like payloads.

## Installation

Clone the repository and import the library into your project.
```
git clone https://github.com/benchware/nobase
cd nobase
```
**Requirements**: Python. No external dependencies are required.

## Features
`detect-base64.py`: Decodes Base64 and Base32.
## API
`looks_encoded_payload(value)`

Returns **`True`** when the input is suspected to be an encoded string/script. Otherwise, it returns **`False`**.

Example:
```py
from detect_base64 import looks_encoded_payload

if looks_encoded_payload(value): 
    return ""
else:
    return value
```
- Value must be `str` and returns `bool`.
