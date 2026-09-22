"""Three small pieces of handlers/shared with outsized consequences.

REDACTION runs over every string leaf of every payload, so a rule written for
error text now sees ordinary prose. "Basic authentication required" became
"Basic ***REDACTED*** required" once the rule was applied everywhere -- a proxy's
text/plain 401 page passes through admin_request into ok(), so this is reachable
from a cluster nobody controls. The fix distinguishes a credential from the next
English word; the cases below pin that distinction in both directions, because a
rule that stops redacting is a leak and a rule that over-redacts destroys the
message an operator needs.

RETRY gates on the METHOD, not on the status. A status of 0 -- a timeout, a
connection reset -- is in neither the unprocessed set nor the 5xx set, so the
status-based predicate returned False for every method and the retry this branch
exists to provide was dead code. A timeout leaves the outcome UNKNOWN, so only
idempotent methods may repeat: a POST that timed out may already have been
applied.

THE REFUSAL DISCRIMINATOR is stripped from success payloads. Both dispatchers
classify a payload carrying it as a refusal, so a handler echoing a
caller-controlled top-level key could otherwise produce a successful mutating call
that the audit trail records as denied -- a write that happened, filed as a write
that was refused.
"""

from __future__ import annotations

import pytest

from handlers import shared
from handlers.shared import ERROR_MARKER

# ── redaction: a credential, not the next English word ───────────────────────


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "authorization: bearer abcdef0123456789abcdef",
        "Basic YWRtaW46cGFzc3dvcmQxMjM0NTY3ODkw",
    ],
)
def test_a_real_credential_is_redacted(text):
    redacted = shared.redact_text(text)
    assert shared.REDACTED in redacted
    assert "eyJhbGci" not in redacted
    assert "YWRtaW46" not in redacted


@pytest.mark.parametrize(
    "text",
    [
        "Basic authentication required",
        "Bearer token missing",
        "Digest authentication is not supported",
    ],
)
def test_ordinary_prose_after_a_scheme_word_is_left_alone(text):
    """A proxy's text/plain 401 page passes through admin_request into ok(), so
    this is reachable from infrastructure nobody in this project controls."""
    assert shared.redact_text(text) == text


def test_a_mixed_token_of_at_least_eight_characters_is_a_credential():
    """The predicate is "long OR not purely alphabetic". Requiring both would let
    a short base64 secret through; the 8-character floor is in the pattern."""
    assert shared._looks_like_credential("abc12345") is True
    assert shared._looks_like_credential("authentication") is False
    assert shared._looks_like_credential("a" * 20) is True
    assert shared.REDACTED in shared.redact_text("Bearer abc12345def")


def test_both_auth_scheme_rules_agree_about_what_a_credential_is():
    """There are two byte-identical (Bearer|Basic|Digest) regexes in this module.
    Until 2026-09-22 only one carried the credential test, so redact_text -- which
    runs FIRST on every string leaf -- redacted unconditionally and the guarded
    rule never saw the text. The fix was inert for exactly the case its own
    comment cites.

    This asserts the two cannot drift apart again: whatever one does to a token,
    the other does.
    """
    import re

    for token in ("authentication", "abc12345def", "a" * 25, "YWRtaW46cGFzcw=="):
        by_redact_text = shared.REDACTED in shared.redact_text(f"Bearer {token}")
        by_predicate = shared._looks_like_credential(token) and re.fullmatch(
            r"[A-Za-z0-9._~+/=-]{8,}", token
        )
        assert by_redact_text == bool(by_predicate), token


def test_redaction_leaves_text_with_no_credential_untouched():
    assert shared.redact_text("nothing to see") == "nothing to see"


# ── the refusal discriminator never rides along on a success ─────────────────


def test_the_error_marker_is_stripped_from_a_success_payload():
    """A write that happened, filed by the audit trail as a write that was
    refused, is the failure this guards."""
    cleaned = shared._without_error_marker({"result": "ok", ERROR_MARKER: True})
    assert ERROR_MARKER not in cleaned
    assert cleaned["result"] == "ok"


def test_a_payload_without_the_marker_is_returned_unchanged():
    original = {"result": "ok"}
    assert shared._without_error_marker(original) is original


@pytest.mark.parametrize("value", ["a string", ["a", "list"], 7, None])
def test_a_non_object_payload_passes_through(value):
    assert shared._without_error_marker(value) == value


def test_ok_does_not_emit_a_payload_that_reads_as_a_refusal():
    """The end-to-end version of the same property, through the function every
    handler actually calls."""
    import json

    body = json.loads(shared.ok({"echoed": "value", ERROR_MARKER: True})[0].text)
    assert ERROR_MARKER not in body


# ── retry gates on the method, because a timeout leaves the outcome unknown ──


def test_only_idempotent_methods_are_retried_after_a_transport_failure(monkeypatch):
    """Status 0 is in neither the unprocessed set nor the 5xx set, so a
    status-based predicate returned False for every method and this retry was
    dead code.

    The caught set is (TimeoutError, ssl.SSLError, http.client.HTTPException) --
    deliberately NOT bare OSError, which would swallow programming errors from
    inside the `with` block along with transport failures.
    """
    attempts: list[str] = []
    slept: list[float] = []

    def explode(*args, **kwargs):
        attempts.append("call")
        raise TimeoutError("read timed out")

    monkeypatch.setattr(shared.urllib.request, "urlopen", explode)
    monkeypatch.setattr(shared.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")

    with pytest.raises(RuntimeError):
        shared.admin_request("GET", "/pools")
    get_attempts = len(attempts)
    assert get_attempts == shared._MAX_ATTEMPTS, "GET is idempotent, so it repeats"
    assert slept, "the backoff must actually be applied between attempts"

    attempts.clear()
    with pytest.raises(RuntimeError):
        shared.admin_request("POST", "/pools/default", data={"x": 1})
    assert len(attempts) == 1, (
        "a POST that timed out may already have been applied, so it must not repeat"
    )


def test_the_backoff_doubles(monkeypatch):
    slept: list[float] = []
    monkeypatch.setattr(
        shared.urllib.request,
        "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(TimeoutError("read timed out")),
    )
    monkeypatch.setattr(shared.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://localhost")
    monkeypatch.setenv("CB_USERNAME", "u")
    monkeypatch.setenv("CB_PASSWORD", "p")
    with pytest.raises(RuntimeError):
        shared.admin_request("GET", "/pools")
    assert slept == [shared._BASE_BACKOFF * (2**n) for n in range(len(slept))], slept
