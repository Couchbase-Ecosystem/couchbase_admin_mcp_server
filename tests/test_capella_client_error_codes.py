"""Reading Capella's domain error code, which is not the HTTP status.

A park/resume decision turns on this. Capella answers 422 for several different
situations, and the domain `code` in the body is what distinguishes "the cluster
is already in that state" -- benign, proceed -- from a real refusal. Getting it
wrong in the benign direction leaves a cluster running and billing.

Two traps are encoded in the function and tested here:

  * `.code` means something DIFFERENT on urllib.error.HTTPError, where it is the
    HTTP status. Reading it off an arbitrary exception would report a 404 as
    Capella domain code 404.
  * `True` is an instance of `int` in Python. A body carrying `"code": true`
    must not be read as code 1.

The message-parsing path exists because the attribute was not always set, and it
has its own trap: the message may carry a Python repr rather than JSON, so the
scan has to keep looking past a brace that does not open valid JSON rather than
giving up at the first one.
"""

from __future__ import annotations

import urllib.error

import pytest

from handlers.capella.client import CapellaError, _domain_code_of, capella_error_code

# ── the attribute, which is the reliable path ────────────────────────────────


def test_the_attached_code_is_preferred_over_anything_in_the_message():
    """It is set where the body is parsed, so no round-trip through the rendered
    message is needed."""
    error = CapellaError("something failed", status=422)
    error.code = 4002
    assert capella_error_code(error) == 4002


def test_a_boolean_attribute_is_not_a_code():
    """True is an instance of int in Python, and reading it as code 1 would make
    a nonsense comparison succeed."""
    error = CapellaError("x", status=422)
    error.code = True
    assert capella_error_code(error) is None


def test_the_http_status_of_an_unrelated_exception_is_never_read_as_a_code():
    """`.code` on urllib.error.HTTPError is the HTTP status. Reading it here
    would report a 404 as Capella domain code 404 and silently change a
    park/resume decision."""
    http = urllib.error.HTTPError("https://x", 404, "not found", {}, None)
    assert capella_error_code(http) is None


# ── the message-parsing fallback ─────────────────────────────────────────────


def test_a_json_body_in_the_message_yields_its_code():
    assert capella_error_code(RuntimeError('failed: {"code": 4002}')) == 4002


def test_a_string_code_that_is_all_digits_is_accepted():
    """Capella has rendered this field both ways."""
    assert capella_error_code(RuntimeError('{"code": "11006"}')) == 11006


def test_the_scan_keeps_looking_past_a_brace_that_opens_nothing():
    """The message carried a Python repr rather than JSON, so the string path
    never matched and callers silently took the re-raise branch. Giving up at the
    first brace is how that happened."""
    message = "context {'not': 'json'} then the real body {\"code\": 4002}"
    assert capella_error_code(RuntimeError(message)) == 4002


@pytest.mark.parametrize(
    "message",
    [
        "no braces at all",
        "{not json",
        '{"code": "not-a-number"}',
        '{"code": true}',
        '{"message": "no code here"}',
        "[1, 2, 3]",
    ],
)
def test_an_unparseable_or_absent_code_is_none(message):
    """Every caller must treat None as "not the outcome I was hoping for" and
    re-raise, so None has to be returned rather than a guess."""
    assert capella_error_code(RuntimeError(message)) is None


# ── the parsed-body helper the client uses directly ──────────────────────────


@pytest.mark.parametrize(
    ("detail", "expected"),
    [
        ({"code": 4002}, 4002),
        ({"code": "4002"}, 4002),
        ({"code": " 4002 "}, 4002),
        ({"code": True}, None),
        ({"code": "not-a-number"}, None),
        ({"code": None}, None),
        ({}, None),
        ("not a dict", None),
        (None, None),
    ],
)
def test_the_domain_code_of_a_parsed_body(detail, expected):
    assert _domain_code_of(detail) == expected
