"""The environment marker: the only thing that says an environment is ours.

Every reaper decision reads it, and ONE bad marker used to break the whole
listing. `capella_env_list`, `capella_env_status` and both reap modes all reach
this through a list, so a single poisoned description meant no genuinely expired
environment anywhere got collected until a human noticed. The rule the code now
follows, and that these pin:

    One bad marker must degrade to "not recognizably ours", never to an outage.

The other direction is the expensive one. `ttl_hours="4"` -- a string, which
nothing validated despite the schema declaring an integer -- fell through an
isinstance check and meant "never expires". The caller asked for four hours and
got forever, on a billable resource. So a numeric string is coerced, and a value
that genuinely cannot be read is treated as pinned only after saying so in the
log.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from handlers.capella import guardrails as g

# ── reading the TTL ──────────────────────────────────────────────────────────


CREATED = "2026-09-14T00:00:00Z"


def _marker(**fields):
    base = {"created": CREATED, "ttl_h": 4}
    base.update(fields)
    return base


def test_an_ordinary_ttl_gives_an_absolute_expiry():
    expiry = g.marker_expiry(_marker())
    assert expiry == datetime(2026, 9, 14, 4, tzinfo=timezone.utc)


def test_a_numeric_string_ttl_is_coerced_rather_than_meaning_forever():
    """ttl_hours="4" silently pinned the environment forever: the caller asked for
    four hours and got a billable resource nothing would collect."""
    assert g.marker_expiry(_marker(ttl_h="4")) == g.marker_expiry(_marker(ttl_h=4))


@pytest.mark.parametrize("ttl", [0, -1, "0"])
def test_a_zero_or_negative_ttl_means_explicitly_pinned(ttl):
    """An environment the reaper must leave alone."""
    assert g.marker_expiry(_marker(ttl_h=ttl)) is None


def test_a_boolean_ttl_is_not_read_as_one_hour():
    """True is an instance of int in Python, and the isinstance check has to say
    so explicitly or a marker carrying `ttl_h: true` expires in an hour."""
    assert g.marker_expiry(_marker(ttl_h=True)) is None


def test_an_unreadable_ttl_is_treated_as_pinned():
    """ "Never reaped" is the expensive direction, so it is taken only after
    warning rather than silently.

    The warning itself is deliberately NOT asserted with caplog: caplog attaches
    to the ROOT logger, and `couchbase-admin` sets propagate=False once
    configure_from_env() has run -- so such an assertion passes when the file is
    run alone and fails in a full-suite run. That is the trap
    tests/test_gui_authorization.py documents, and it is why the audit tests read
    the sink FILE instead.
    """
    assert g.marker_expiry(_marker(ttl_h="four hours")) is None


def test_a_marker_with_no_created_time_cannot_expire():
    assert g.marker_expiry(_marker(created="")) is None


def test_an_unparseable_created_time_degrades_to_pinned():
    assert g.marker_expiry(_marker(created="last tuesday")) is None


def test_a_ttl_that_overflows_a_date_does_not_break_the_listing():
    """A large ttl_h made this arithmetic raise, and because every caller reaches
    it through a list, that ONE poisoned description broke capella_env_list,
    capella_env_status and both reap modes for the whole sandbox. One bad marker
    must degrade to "not recognizably ours", never to an outage."""
    assert g.marker_expiry(_marker(ttl_h=10**12)) is None


def test_expiry_drives_the_expired_verdict():
    marker = _marker(ttl_h=4)
    before = datetime(2026, 9, 14, 3, tzinfo=timezone.utc)
    after = datetime(2026, 9, 14, 5, tzinfo=timezone.utc)
    assert g.is_expired(marker, now=before) is False
    assert g.is_expired(marker, now=after) is True


def test_a_pinned_marker_is_never_expired():
    assert g.is_expired(_marker(ttl_h=0), now=datetime.now(timezone.utc)) is False


# ── finding the marker inside a description ──────────────────────────────────


def _described(body: str) -> str:
    return f"{g.ENV_MARKER_PREFIX}{body}"


def test_a_marker_object_is_extracted_from_surrounding_text():
    assert g._extract_marker_json(_described('{"a": 1} trailing')) == '{"a": 1}'


def test_nested_objects_are_balanced_correctly():
    body = '{"a": {"b": {"c": 1}}}'
    assert g._extract_marker_json(_described(body)) == body


def test_a_brace_inside_a_string_does_not_end_the_object():
    """A description is operator-supplied text. A `}` inside a quoted value must
    not truncate the marker."""
    body = '{"note": "closes } here"}'
    assert g._extract_marker_json(_described(body)) == body


def test_an_escaped_quote_does_not_end_the_string():
    body = '{"note": "a \\" quote"}'
    assert g._extract_marker_json(_described(body)) == body


def test_a_description_with_no_marker_yields_nothing():
    assert g._extract_marker_json("just a description") is None


def test_an_unbalanced_marker_is_not_guessed_at():
    """No closing brace for the object we opened. Returning a truncated fragment
    would hand json.loads something that parses into the wrong thing."""
    assert g._extract_marker_json(_described('{"a": 1')) is None


def test_whitespace_between_the_prefix_and_the_object_is_tolerated():
    """The marker regex skips whitespace up to the opening brace, so a
    description wrapped by an editor still parses."""
    assert g._extract_marker_json(_described('\n  {"a": 1}')) == '{"a": 1}'


def test_an_unparseable_marker_is_not_recognisably_ours():
    """Degrade to "not ours", never to an exception -- the whole listing depends
    on it."""
    assert g.parse_marker(_described("{not json}")) is None
    assert g.parse_marker(None) is None
    assert g.parse_marker("no marker here") is None


def test_a_well_formed_marker_round_trips():
    parsed = g.parse_marker(_described(f'{{"ttl_h": 4, "created": "{CREATED}"}}'))
    assert parsed["ttl_h"] == 4


# ── integer configuration ────────────────────────────────────────────────────


def test_a_non_integer_setting_falls_back_to_the_default(monkeypatch):
    """A misconfigured ceiling must not take the process down; it warns and uses
    the default. The warning is not asserted here for the propagate=False reason
    given above."""
    monkeypatch.setenv("CB_CAPELLA_MAX_ENVIRONMENTS", "lots")
    assert g._env_int("CB_CAPELLA_MAX_ENVIRONMENTS", 7) == 7


def test_an_unset_setting_uses_the_default(monkeypatch):
    monkeypatch.delenv("CB_CAPELLA_MAX_ENVIRONMENTS", raising=False)
    assert g._env_int("CB_CAPELLA_MAX_ENVIRONMENTS", 7) == 7


def test_an_integer_setting_is_honoured(monkeypatch):
    monkeypatch.setenv("CB_CAPELLA_MAX_ENVIRONMENTS", "3")
    assert g._env_int("CB_CAPELLA_MAX_ENVIRONMENTS", 7) == 3
