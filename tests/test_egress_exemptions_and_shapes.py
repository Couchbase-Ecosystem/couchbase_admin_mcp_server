"""The egress guard's exempt path and its destination heuristic.

An operator may reasonably relax the ALLOWLIST for a particular field. They may
not relax the metadata, loopback and link-local denials, and the module says so
twice in its own hints -- so the exempt path honours the second without honouring
the first. That split is what these cover.

The heuristic below it decides whether a value is destination-SHAPED at all, and
its history is a warning about where a length cap belongs. The cap used to test
the whole value, so padding defeated the guard outright:

    "s3://169.254.169.254/loot/" + "a" * 2100   ->  not destination-shaped

which on the forced path SKIPS every check -- padding converted a DENY into a
silent ALLOW, strictly worse than the bug it replaced. An over-long value now
returns TRUE and is handed to assert_egress_allowed, which refuses it as an
implausible host. The cap bounds RESOLUTION work without ever deciding the
verdict in the permissive direction.
"""

from __future__ import annotations

import pytest

from handlers import egress
from handlers.egress import EgressDeniedError

# ── the exempt path still refuses what is never acceptable ───────────────────


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "metadata",
        "metadata.google.internal",
        "LOCALHOST.",
        "metadata.goog",
    ],
)
def test_a_metadata_or_loopback_name_is_refused_even_on_an_exempt_field(host):
    """The allowlist is a policy an operator may relax per field. These are not."""
    with pytest.raises(EgressDeniedError) as caught:
        egress._assert_not_absolutely_denied(host, field="uploadHost", tool="t")
    message = str(caught.value)
    assert "never an acceptable destination" in message
    assert "CB_ADMIN_EGRESS_EXEMPT_FIELDS" in message


def test_an_ordinary_host_passes_the_absolute_check(host="uploads.example.com"):
    assert egress._assert_not_absolutely_denied(host, field="f", tool="t") is None


def test_a_value_with_no_extractable_host_is_not_absolutely_denied():
    """There is nothing to deny. The allowlist check still runs separately."""
    assert egress._assert_not_absolutely_denied("", field="f", tool="t") is None


def test_an_operator_can_add_an_exempt_field(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", "uploadHost, otherField")
    exempt = egress._host_like_exempt()
    assert "uploadhost" in {e.lower() for e in exempt}
    assert "otherfield" in {e.lower() for e in exempt}


def test_the_exempt_list_is_empty_by_default(monkeypatch):
    monkeypatch.delenv("CB_ADMIN_EGRESS_EXEMPT_FIELDS", raising=False)
    assert isinstance(egress._host_like_exempt(), frozenset)


# ── what counts as destination-shaped ────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/path",
        "example.com",
        "host:8091",
        "169.254.169.254",
        # No dot at all, and these are exactly the forms that slipped through a
        # dot-based test.
        "metadata",
        "localhost",
        "0xa9fea9fe",
        "2130706433",
    ],
)
def test_these_are_destination_shaped(value):
    assert egress._looks_like_a_destination(value) is True


@pytest.mark.parametrize("value", ["", "   ", "plainword", "a name"])
def test_these_are_not_destination_shaped(value):
    assert egress._looks_like_a_destination(value) is False


def test_padding_cannot_turn_a_denial_into_a_skip():
    """MEASURED: "s3://169.254.169.254/loot/" + "a"*2100 returned False and went
    unchecked, while split_host still extracted 169.254.169.254 from it. An
    over-long value must return TRUE so the real check gets to refuse it."""
    padded = "s3://169.254.169.254/loot/" + "a" * 2100
    assert egress._looks_like_a_destination(padded) is True

    also_padded = "169.254.169.254," + "b" * 600
    assert egress._looks_like_a_destination(also_padded) is True


def test_an_over_long_value_with_no_host_is_still_handed_on():
    """The cap bounds RESOLUTION work; it never decides the verdict in the
    permissive direction."""
    assert egress._looks_like_a_destination("x" * 3000) is True


# ── resolution failures are not silent allows ────────────────────────────────


def test_a_name_that_cannot_be_resolved_yields_no_addresses(monkeypatch):
    """An empty list means "nothing to compare", and the caller must not read
    that as "nothing objectionable"."""

    def boom(*args, **kwargs):
        raise OSError("Name or service not known")

    monkeypatch.setattr("socket.getaddrinfo", boom)
    assert egress._resolve_all("nowhere.invalid") == []


def test_a_unicode_error_during_resolution_is_handled(monkeypatch):
    """A label that idna cannot encode raises UnicodeError rather than OSError,
    and an unhandled one would crash the guard instead of refusing."""

    def boom(*args, **kwargs):
        raise UnicodeError("label too long")

    monkeypatch.setattr("socket.getaddrinfo", boom)
    assert egress._resolve_all("x" * 300) == []


def test_resolved_addresses_are_parsed_and_scope_ids_dropped(monkeypatch):
    """A link-local IPv6 address arrives as fe80::1%eth0, and the scope id is not
    part of the address being compared."""

    def resolve(host, port):
        return [(None, None, None, None, ("fe80::1%eth0", 0))]

    monkeypatch.setattr("socket.getaddrinfo", resolve)
    found = egress._resolve_all("linklocal.invalid")
    assert [str(a) for a in found] == ["fe80::1"]
