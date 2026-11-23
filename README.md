<p align="center">
  <a href="https://github.com/lupaxa-security-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/security-toolbox/readme-logo.png" alt="Security Toolbox" />
  </a>
</p>

<h1 align="center">Token Decoder</h1>

Token Decoder inspects a JWT or another common token and prints a JSON report. It does not verify signatures and it does not decrypt JWE payloads.

The library import is `lupaxa.token_decoder`. The command is `token-decoder`.

## Install

Python 3.11 or newer. There are no runtime dependencies.

```bash
pip install lupaxa-token-decoder
```

## Quick Start

Pass a token, or pipe one line on stdin:

```bash
token-decoder "$TOKEN"
printf '%s\n' "$TOKEN" | token-decoder
```

With no argument, a terminal prompts on stderr. The JSON report is written to stdout.

> **Note:** A token passed as an argument can be stored in your shell history. Pipe it on stdin when that matters. `signature_verified` is always false. This tool never checks a signature and never decrypts a JWE.

## Library

```python
from lupaxa.token_decoder import decode_token

print(decode_token(token)["type"])
```

`lupaxa` is a namespace package. There is no `lupaxa/__init__.py`.

## What it Decodes

| Type               | When                                                                                                                     |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| JWT                | Three segments whose header is JSON and contains `alg`. `exp`, `iat`, and `nbf` gain a UTC reading beside the raw value. |
| JWE                | Five segments whose header is JSON and contains `enc`. The ciphertext is reported, not decrypted.                        |
| JSON               | The token itself is a JSON document.                                                                                     |
| Hexadecimal        | An even-length hex string. UTF-8 text is included when the bytes decode.                                                 |
| Base64 / Base64URL | Standard or URL-safe Base64 that decodes to UTF-8. JSON text is parsed.                                                  |
| Opaque / Unknown   | None of the formats above.                                                                                               |

A leading `Bearer` prefix is ignored. Line wrapping is removed except inside a JSON document.

## Command Line Options

| Option         | Meaning                             |
| -------------- | ----------------------------------- |
| `TOKEN`        | Token to decode.                    |
| `-`            | Read one line from stdin.           |
| `--help`, `-h` | Print the command summary and exit. |
| `--version`    | Print the version and exit.         |

<a href="https://github.com/the-lupaxa-project">
  <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
