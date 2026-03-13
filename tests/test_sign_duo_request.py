"""
Tests for sign_duo_request(method, host, path, params, skey, ikey).

The function builds an HMAC-SHA1 signature over a canonical string comprising
the date, HTTP method, host, path, and sorted URL-encoded params, then returns
a Basic-auth header and the date string.
"""

import base64
import hmac
import hashlib
import urllib.parse
from unittest.mock import patch

from main import sign_duo_request


# --- Helpers ----------------------------------------------------------------

IKEY = "DITEST00000000000000"
SKEY = "test_secret_key_for_signing_only"
HOST = "api-test.duosecurity.com"
PATH = "/admin/v1/users"
FIXED_DATE = "Thu, 01 Jan 2026 00:00:00 GMT"


def _expected_sig(method, host, path, params, skey, ikey, date):
    """Mirror the canonical-string construction to produce the expected sig."""
    sorted_items = sorted(params.items())
    canon_params = "&".join(
        f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}"
        for k, v in sorted_items
    )
    canonical = "\n".join([date, method.upper(), host.lower(), path, canon_params])
    sig = hmac.new(skey.encode(), canonical.encode(), hashlib.sha1).hexdigest()
    auth = f"Basic {base64.b64encode(f'{ikey}:{sig}'.encode()).decode()}"
    return auth


# --- Tests ------------------------------------------------------------------


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_known_test_vector(mock_time):
    """Given fixed inputs, the HMAC-SHA1 signature matches a pre-computed value."""
    params = {"username": "alice"}
    auth, dt = sign_duo_request("GET", HOST, PATH, params, SKEY, IKEY)

    expected = _expected_sig("GET", HOST, PATH, params, SKEY, IKEY, FIXED_DATE)
    assert auth == expected
    assert dt == FIXED_DATE


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_get_with_no_params(mock_time):
    """GET with empty params produces a valid signature string."""
    auth, dt = sign_duo_request("GET", HOST, PATH, {}, SKEY, IKEY)

    expected = _expected_sig("GET", HOST, PATH, {}, SKEY, IKEY, FIXED_DATE)
    assert auth == expected
    assert auth.startswith("Basic ")


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_post_with_params_sorted(mock_time):
    """POST with params includes them sorted in the canonical string."""
    params = {"zebra": "1", "apple": "2", "mango": "3"}
    auth, dt = sign_duo_request("POST", HOST, PATH, params, SKEY, IKEY)

    expected = _expected_sig("POST", HOST, PATH, params, SKEY, IKEY, FIXED_DATE)
    assert auth == expected


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_params_sorted_alphabetically(mock_time):
    """Params are sorted alphabetically regardless of insertion order."""
    params_a = {"b": "2", "a": "1", "c": "3"}
    params_b = {"c": "3", "a": "1", "b": "2"}

    auth_a, _ = sign_duo_request("GET", HOST, PATH, params_a, SKEY, IKEY)
    auth_b, _ = sign_duo_request("GET", HOST, PATH, params_b, SKEY, IKEY)
    assert auth_a == auth_b


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_sig_starts_with_ikey(mock_time):
    """The Base64-decoded auth header contains ikey: prefix."""
    auth, _ = sign_duo_request("GET", HOST, PATH, {}, SKEY, IKEY)

    # Decode the Basic auth value
    b64_part = auth.split(" ", 1)[1]
    decoded = base64.b64decode(b64_part).decode()
    assert decoded.startswith(f"{IKEY}:")


def test_dt_is_nonempty_string():
    """The returned date header is a non-empty string."""
    _, dt = sign_duo_request("GET", HOST, PATH, {}, SKEY, IKEY)
    assert isinstance(dt, str)
    assert len(dt) > 0
    # Should look like an RFC 7231 date
    assert "GMT" in dt


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_special_characters_percent_encoded(mock_time):
    """Special characters in param values are percent-encoded correctly."""
    params = {"msg": "hello world&foo=bar", "key": "a+b=c"}
    auth, _ = sign_duo_request("POST", HOST, PATH, params, SKEY, IKEY)

    expected = _expected_sig("POST", HOST, PATH, params, SKEY, IKEY, FIXED_DATE)
    assert auth == expected


@patch("main.time.strftime", return_value=FIXED_DATE)
def test_empty_params_dict(mock_time):
    """Empty params dict works without error."""
    auth, dt = sign_duo_request("GET", HOST, PATH, {}, SKEY, IKEY)
    assert auth is not None
    assert dt == FIXED_DATE
