"""Detect and decode JWTs and other common token formats.

Signatures are never verified. Compact JWE tokens are recognised and are
not decrypted.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from contextlib import suppress
from datetime import UTC, datetime
from typing import Literal, TypeAlias, TypedDict, cast

Json: TypeAlias = dict[str, "Json"] | list["Json"] | str | int | float | bool | None


class JwtReport(TypedDict):
    """Decoded compact JWT. The signature is not verified."""

    type: Literal["JWT"]
    header: dict[str, Json]
    payload: Json | str
    signature: str
    signature_verified: Literal[False]


class JweReport(TypedDict):
    """Recognised compact JWE. The payload is not decrypted."""

    type: Literal["JWE"]
    header: dict[str, Json]
    encrypted_key: str
    initialization_vector: str
    ciphertext: str
    authentication_tag: str
    decrypted: Literal[False]


class JsonReport(TypedDict):
    """A token that is itself a JSON document."""

    type: Literal["JSON"]
    data: Json


class HexReport(TypedDict):
    """An even-length hexadecimal token."""

    type: Literal["Hexadecimal"]
    decoded: str | None
    bytes: int


class Base64Report(TypedDict):
    """Standard or URL-safe Base64 that decodes as UTF-8."""

    type: Literal["Base64 / Base64URL"]
    decoded: Json


class EmptyReport(TypedDict):
    """A blank token."""

    type: Literal["Empty token"]


class OpaqueReport(TypedDict):
    """A token that matched none of the known formats."""

    type: Literal["Opaque / Unknown"]
    length: int
    note: str


Report = JwtReport | JweReport | JsonReport | HexReport | Base64Report | EmptyReport | OpaqueReport

_TIMESTAMP_CLAIMS = ("exp", "iat", "nbf")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")
_B64 = re.compile(r"[A-Za-z0-9_+/=-]+\Z")


def decode_base64(value: str) -> bytes:
    """Decode standard or URL-safe Base64, adding padding when it is missing.

    ``altchars`` translates ``-`` and ``_`` to ``+`` and ``/`` before
    validation, so one call accepts both alphabets.

    Parameters
    ----------
    value:
        A Base64 or Base64url string, with or without padding.

    Returns
    -------
    bytes
        The decoded bytes.
    """
    padded = value + ("=" * (-len(value) % 4))
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def format_timestamp(value: Json) -> Json:
    """Convert a Unix timestamp to an ISO-8601 UTC string.

    Booleans are returned unchanged. ``bool`` is a subclass of ``int``,
    so a claim such as ``true`` must not be treated as a timestamp.
    Values that are not numbers, or that cannot be converted, are also
    returned unchanged.

    Parameters
    ----------
    value:
        A claim value that might be a Unix timestamp in seconds.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return value
    try:
        moment = datetime.fromtimestamp(value, tz=UTC)
    except (ValueError, OverflowError, OSError):
        return value
    return moment.isoformat()


def _as_json(value: object) -> Json:
    """Return ``value`` as a JSON document.

    Parameters
    ----------
    value:
        An object produced by ``json.loads``.

    Raises
    ------
    ValueError
        If ``value`` is not a JSON object, array, string, number, boolean,
        or null.
    """
    if isinstance(value, dict):
        pairs = cast("dict[object, object]", value)
        document: dict[str, Json] = {}
        for key, item in pairs.items():
            document[str(key)] = _as_json(item)
        return document
    if isinstance(value, list):
        items = cast("list[object]", value)
        return [_as_json(item) for item in items]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    message = "JSON value is not a document"
    raise ValueError(message)


def _json_value(raw: str | bytes) -> Json:
    return _as_json(cast("object", json.loads(raw)))


def decode_jwt(token: str) -> Report | None:
    """Decode a compact JWT without verifying its signature.

    Parameters
    ----------
    token:
        A candidate compact JWT (``header.payload.signature``).

    Returns
    -------
    dict or None
        A report when the header is a JSON object that contains ``alg``.
        ``None`` when ``token`` is not a JWT.
    """
    parts = token.split(".")
    if len(parts) != 3 or parts[0] == "" or parts[1] == "":
        return None
    try:
        header = _json_value(decode_base64(parts[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or "alg" not in header:
        return None

    try:
        payload: Json | str = _json_value(decode_base64(parts[1]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        payload = "<Non-JSON or encrypted payload>"

    if isinstance(payload, dict):
        stamped: dict[str, Json] = dict(payload)
        for key in _TIMESTAMP_CLAIMS:
            if key in stamped:
                raw_value = stamped[key]
                stamped[key] = {"raw": raw_value, "utc": format_timestamp(raw_value)}
        payload = stamped

    return {
        "type": "JWT",
        "header": header,
        "payload": payload,
        "signature": parts[2],
        "signature_verified": False,
    }


def decode_jwe(token: str) -> Report | None:
    """Recognise a compact JWE without decrypting it.

    Parameters
    ----------
    token:
        A candidate compact JWE of five dot-separated segments.

    Returns
    -------
    dict or None
        A report when the header is a JSON object that contains ``enc``.
        ``None`` when ``token`` is not a compact JWE.
    """
    parts = token.split(".")
    if len(parts) != 5 or parts[0] == "":
        return None
    try:
        header = _json_value(decode_base64(parts[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or "enc" not in header:
        return None
    return {
        "type": "JWE",
        "header": header,
        "encrypted_key": parts[1],
        "initialization_vector": parts[2],
        "ciphertext": parts[3],
        "authentication_tag": parts[4],
        "decrypted": False,
    }


def _without_bearer(token: str) -> str:
    stripped = token.strip()
    match = re.match(r"bearer(?:\s+|$)", stripped, flags=re.IGNORECASE)
    if match is None:
        return stripped
    return stripped[match.end() :].strip()


def _unwrap(token: str) -> str:
    """Drop wrapping whitespace without flattening a JSON document."""
    if any(character.isspace() for character in token) and not token.startswith(("{", "[", '"')):
        return "".join(token.split())
    return token


def decode_token(token: str) -> Report:
    """Detect and decode one token.

    A leading ``Bearer`` prefix is removed. Signatures are not checked.

    Parameters
    ----------
    token:
        A JWT, compact JWE, JSON document, hexadecimal string, Base64
        string, or an unrecognised token.

    Returns
    -------
    dict
        A JSON-ready report. The ``type`` field names the format.
    """
    token = _unwrap(_without_bearer(token))
    if not token:
        return {"type": "Empty token"}

    jwt = decode_jwt(token)
    if jwt is not None:
        return jwt

    jwe = decode_jwe(token)
    if jwe is not None:
        return jwe

    # A bare number is left for the hex and Base64 checks. Digit strings are
    # common tokens; a JSON number is not.
    if token[:1] in '{["' or token in {"true", "false", "null"}:
        try:
            return {"type": "JSON", "data": _json_value(token)}
        except ValueError:
            pass

    if len(token) % 2 == 0 and _HEX.fullmatch(token):
        raw = bytes.fromhex(token)
        try:
            decoded: str | None = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = None
        return {"type": "Hexadecimal", "decoded": decoded, "bytes": len(raw)}

    if _B64.fullmatch(token):
        try:
            text = decode_base64(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
        else:
            decoded_value: Json = text
            with suppress(ValueError):
                decoded_value = _json_value(text)
            return {"type": "Base64 / Base64URL", "decoded": decoded_value}

    return {
        "type": "Opaque / Unknown",
        "length": len(token),
        "note": "Token cannot be decoded using known formats.",
    }
