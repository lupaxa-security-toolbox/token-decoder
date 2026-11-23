"""Decoder coverage for the formats the library recognises."""

import base64
import json
from datetime import UTC, datetime

from lupaxa.token_decoder import decode_token
from lupaxa.token_decoder.decode import format_timestamp


def _segment(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(payload: object, header: dict[str, object] | None = None) -> str:
    return f"{_segment(header or {'alg': 'none', 'typ': 'JWT'})}.{_segment(payload)}.c2ln"


def test_jwt_rewrites_timestamps_and_does_not_verify() -> None:
    token = _jwt({"sub": "user", "exp": 1710000000, "iat": 1700000000, "nbf": 1700000000})
    report = decode_token(token)

    assert report["type"] == "JWT"
    assert report["header"]["alg"] == "none"
    assert report["payload"]["sub"] == "user"
    assert report["signature"] == "c2ln"
    assert report["signature_verified"] is False
    assert report["payload"]["exp"] == {
        "raw": 1710000000,
        "utc": datetime.fromtimestamp(1710000000, tz=UTC).isoformat(),
    }


def test_boolean_timestamp_claim_is_not_a_unix_time() -> None:
    report = decode_token(_jwt({"exp": True}))
    assert report["payload"]["exp"] == {"raw": True, "utc": True}


def test_bearer_prefix_and_wrapped_jwt() -> None:
    token = _jwt({"sub": "user"})
    wrapped = "Bearer " + token[:8] + "\n" + token[8:]
    assert decode_token(wrapped)["type"] == "JWT"


def test_non_json_jwt_payload_is_marked() -> None:
    header = _segment({"alg": "dir"})
    payload = base64.urlsafe_b64encode(b"\xff\xfe").decode().rstrip("=")
    report = decode_token(f"{header}.{payload}.sig")
    assert report["payload"] == "<Non-JSON or encrypted payload>"
    assert report["signature_verified"] is False


def test_three_segments_without_alg_are_not_a_jwt() -> None:
    token = f"{_segment({'typ': 'JWT'})}.{_segment({'sub': 'user'})}.sig"
    report = decode_token(token)
    assert report["type"] == "Opaque / Unknown"


def test_compact_jwe_is_not_decrypted() -> None:
    header = _segment({"alg": "dir", "enc": "A256GCM"})
    token = f"{header}.ek.iv.ciphertext.tag"
    report = decode_token(token)
    assert report["type"] == "JWE"
    assert report["decrypted"] is False
    assert report["header"]["enc"] == "A256GCM"
    assert report["ciphertext"] == "ciphertext"


def test_json_document() -> None:
    report = decode_token('{"hello": "world"}')
    assert report == {"type": "JSON", "data": {"hello": "world"}}
    assert decode_token("true") == {"type": "JSON", "data": True}
    assert decode_token("null") == {"type": "JSON", "data": None}


def test_hexadecimal_text_and_binary() -> None:
    text = decode_token("68656c6c6f")
    assert text == {"type": "Hexadecimal", "decoded": "hello", "bytes": 5}

    binary = decode_token("00ff")
    assert binary["type"] == "Hexadecimal"
    assert binary["decoded"] is None
    assert binary["bytes"] == 2


def test_base64_and_base64url() -> None:
    standard = base64.b64encode(b'{"ok":true}').decode()
    url = base64.urlsafe_b64encode(b"hello world").decode().rstrip("=")
    assert decode_token(standard)["decoded"] == {"ok": True}
    assert decode_token(url)["decoded"] == "hello world"


def test_empty_and_opaque() -> None:
    assert decode_token("   ") == {"type": "Empty token"}
    assert decode_token("Bearer ") == {"type": "Empty token"}
    opaque = decode_token("not a token!!!")
    assert opaque["type"] == "Opaque / Unknown"
    assert opaque["length"] == len("notatoken!!!")


def test_format_timestamp_rejects_out_of_range_values() -> None:
    assert format_timestamp("later") == "later"
    assert format_timestamp(10**30) == 10**30
