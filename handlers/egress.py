"""
handlers/egress.py — allowlist for destinations the CLUSTER is asked to contact.

THE PROBLEM
===========
Several admin operations take a hostname from the caller and make Couchbase
itself open the connection. The agent supplies the destination; the cluster —
inside the trust boundary, often holding a cloud instance role — does the
dialling. That inverts the usual direction of control:

  admin_logs_collect_start(uploadHost=...)
      Couchbase gathers a diagnostic bundle from every node and uploads it to the
      named host. Bundles contain query text, document keys, configuration and
      sometimes credentials. One call is "send me all your logs."

  admin_xdcr_reference_create(hostname=...)   + admin_xdcr_replication_create
      Streams an entire bucket, continuously, to a remote cluster.

  admin_node_add(hostname=, user=, password=)
      The cluster dials out, and a node that successfully joins receives replica
      data.

  admin_kmip_set(kmipHost=...)
      Repoints where the cluster fetches its master encryption key. Aimed
      elsewhere, the cluster cannot decrypt its own data after a restart.

  admin_alerts_set(emailHost=...) + admin_alerts_test_email
      Arbitrary outbound TCP from a cluster node, on demand, with caller-chosen
      content.

There is a second direction to it. These destinations can be internal addresses
the agent itself cannot reach: 169.254.169.254 returns cloud instance-role
credentials on AWS and GCP, and RFC1918 ranges become reachable. The cluster
becomes a proxy into the customer's network, and the error text returned to the
model turns it into a scanner.

THE CONTROL
===========
One allowlist, checked before any of those calls is issued.

  CB_ADMIN_EGRESS_ALLOWED_HOSTS   Comma-separated hosts, IPs or CIDRs the cluster
                                  may be pointed at. Supports a leading-dot
                                  suffix match for a domain, e.g.
                                  ".couchbase.com,10.20.0.0/16,smtp.corp.example".

  CB_ADMIN_EGRESS_ALLOW_ANY       Escape hatch for PUBLIC destinations only. It
                                  does NOT admit private/RFC1918 ranges or the
                                  metadata/loopback denials below — so reaching
                                  for it out of convenience cannot turn the
                                  cluster into a reverse proxy into the internal
                                  network. Named to be conspicuous.

Unset behaves as follows, deliberately asymmetric:

  * Loopback, link-local and cloud metadata addresses are ALWAYS refused, even
    with CB_ADMIN_EGRESS_ALLOW_ANY. There is no legitimate reason to ask a
    Couchbase node to upload its logs to 169.254.169.254, and the cost of being
    wrong is IAM credentials.
  * Everything else is refused with a message naming the variable to set. Fail
    closed: the operator states where the cluster may talk to, once, at deploy
    time.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

# Addresses that are never an acceptable destination for a cluster-originated
# request, regardless of configuration. Cloud instance-metadata services are the
# reason this list is absolute.
_ALWAYS_DENIED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # link-local, incl. 169.254.169.254
    ipaddress.ip_network("127.0.0.0/8"),  # loopback
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    # 0.0.0.0/8 as a whole, not just /32: 0.0.0.1 routes to the local host on
    # Linux, so a /32 denial was trivially sidestepped.
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    # The EC2 IPv6 instance-metadata address specifically. The whole of fd00::/8
    # deliberately is NOT here: that is the entire assigned ULA space, and a
    # customer's IPv6 KMIP appliance or SMTP relay legitimately lives there. It is
    # covered by _PRIVATE_NETWORKS below, which requires an explicit entry.
    ipaddress.ip_network("fd00:ec2::254/128"),
)

#: Private / internal ranges. NOT absolutely denied — a customer's backup target,
#: SMTP relay and KMIP appliance are all normally on RFC1918 — but reachable ONLY
#: when an operator names them explicitly. CB_ADMIN_EGRESS_ALLOW_ANY deliberately
#: does NOT admit these: "allow any" means any PUBLIC destination, so lifting the
#: allowlist for convenience cannot silently turn the cluster into a reverse proxy
#: into the internal network.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT / k8s overlays
    ipaddress.ip_network("fc00::/7"),
)

#: Hostnames that resolve to a metadata service by convention.
_ALWAYS_DENIED_NAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "localhost",
        "localhost.localdomain",
    }
)


class EgressDeniedError(RuntimeError):
    """A cluster-originated destination refused by policy. Nothing was sent.

    The hint is folded into the message text so that a handler's generic
    ``except Exception`` still surfaces the remediation guidance — the guidance is
    the useful half of a refusal, and requiring every call site to catch this
    specific type would guarantee some of them didn't.
    """

    def __init__(self, message: str, *, hint: str = ""):
        super().__init__(f"{message} {hint}".strip() if hint else message)
        self.hint = hint


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def _allow_any() -> bool:
    return _env("CB_ADMIN_EGRESS_ALLOW_ANY").lower() in ("1", "true", "yes", "on")


def _allowed_entries() -> tuple[str, ...]:
    raw = _env("CB_ADMIN_EGRESS_ALLOWED_HOSTS")
    if not raw:
        return ()
    return tuple(e.strip().lower() for e in raw.split(",") if e.strip())


def split_host(value: str) -> str:
    """Extract the host a value will actually be dialled at.

    The order of operations is the security property. Previously the port was
    stripped first and userinfo was never handled, so
    ``smtp.corp.example:25@169.254.169.254`` yielded the host
    ``smtp.corp.example`` — an allowlisted name — while the real destination was the
    metadata service, because everything before ``@`` in a URL is userinfo. Likewise
    ``https://evil.tld?x=.corp.example`` matched a ``.corp.example`` suffix entry.

    So: scheme, then query/fragment, then userinfo, then port. Anything left that
    cannot be a hostname is refused rather than guessed at.
    """
    host = (value or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    # Query and fragment first: their contents must never influence the decision.
    for sep in ("?", "#"):
        host = host.split(sep, 1)[0]
    host = host.split("/", 1)[0]
    # Userinfo. Everything before the LAST '@' is credentials, not the destination.
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    if host.startswith("["):  # [::1]:8091
        end = host.find("]")
        if end > 0:
            return host[1:end].strip().lower()
    # Only strip a trailing :port when unambiguous (one colon = not bare IPv6).
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host.strip().rstrip(".").lower()


def _is_plausible_host(host: str) -> bool:
    """Reject anything that cannot be a hostname or IP literal.

    A value that survives parsing but is not a valid host is refused rather than
    compared against the allowlist, because the comparison would be meaningless and
    the downstream consumer may parse it differently than we did.
    """
    if not host or len(host) > 253:
        return False
    if _as_ip(host) is not None:
        return True
    # LDH (letters/digits/hyphen) plus dots, which is what a hostname may contain.
    return all(
        part
        and len(part) <= 63
        and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", part)
        for part in host.split(".")
    )


def _as_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse a host as an IP, normalising the forms that hide a denied address.

    Three normalisations, each of which was a live bypass:

      IPv4-MAPPED IPv6   ``::ffff:169.254.169.254`` is dialled as IPv4 by every OS
                         stack, but is an IPv6Address that matches none of the IPv4
                         denial networks. The metadata service was reachable through
                         it even with the allowlist lifted.
      LEGACY NUMERIC     ``2130706433``, ``0x7f000001`` and ``0177.0.0.1`` are all
                         rejected by ``ipaddress`` but accepted by ``inet_aton`` and
                         by libcurl, so they fell through as "hostnames" and matched
                         no denial.
      TRAILING DOT       ``169.254.169.254.`` is a legal FQDN form that defeated both
                         the name list and the IP parse.
    """
    text = (host or "").strip().rstrip(".")
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        parsed = None
        # inet_aton accepts dotted-octal, dotted-hex, bare-integer and short forms.
        try:
            import socket

            parsed = ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(text)))
        except (OSError, ValueError):
            return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


def _matches_entry(host: str, ip: object | None, entry: str) -> bool:
    if entry == host:
        return True
    # ".example.com" matches any subdomain, and example.com itself.
    if entry.startswith(".") and (host.endswith(entry) or host == entry[1:]):
        return True
    if ip is not None:
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False


def _resolve_check_enabled() -> bool:
    """Whether to resolve names before deciding.

    On by default. Disable with CB_ADMIN_EGRESS_SKIP_DNS=true only where DNS is
    unavailable or resolution is too slow in-path; the string-level denials still
    apply, but a name pointing at the metadata service would then be accepted.
    """
    return _env("CB_ADMIN_EGRESS_SKIP_DNS").lower() not in ("1", "true", "yes", "on")


def _resolve_all(host: str) -> list:
    """Every address a name maps to. Empty on failure — resolution problems must
    not become a way to bypass the check, so a name that cannot be resolved is
    still subject to the allowlist below."""
    import socket

    found = []
    try:
        for info in socket.getaddrinfo(host, None):
            addr = info[4][0]
            parsed = _as_ip(str(addr).split("%")[0])
            if parsed is not None:
                found.append(parsed)
    except (OSError, UnicodeError):
        return []
    return found


def assert_egress_allowed(value: str, *, field: str, tool: str) -> str:
    """Authorize a destination the CLUSTER will be asked to contact.

    Returns the extracted host on success. Raises EgressDenied otherwise —
    nothing has been sent at that point.
    """
    host = split_host(value)
    if not host:
        raise EgressDeniedError(
            f"{tool}: `{field}` is empty or could not be parsed as a host.",
            hint="Supply a hostname or IP address.",
        )

    if not _is_plausible_host(host):
        raise EgressDeniedError(
            f"{tool}: `{field}`={host!r} is not a valid hostname or IP address.",
            hint=(
                "Values containing credentials, query strings or other URL "
                "components are refused: the destination must be unambiguous, "
                "because anything this server parses differently from the cluster "
                "is a way to smuggle a different target past the allowlist."
            ),
        )

    ip = _as_ip(host)

    # Absolute denials first: these hold even under CB_ADMIN_EGRESS_ALLOW_ANY.
    if host in _ALWAYS_DENIED_NAMES:
        raise EgressDeniedError(
            f"{tool}: `{field}`={host!r} is a loopback or metadata hostname and is "
            "never an acceptable destination for a cluster-originated request.",
            hint=(
                "Cloud instance-metadata services return IAM credentials to "
                "anything that can reach them. This denial cannot be configured "
                "away."
            ),
        )
    if ip is not None:
        for net in _ALWAYS_DENIED_NETWORKS:
            # No version gate: `in` already handles a mismatch, and gating on it was
            # what let an IPv4-mapped IPv6 address skip the IPv4 denial networks.
            if ip in net:
                raise EgressDeniedError(
                    f"{tool}: `{field}`={host!r} falls in {net}, which is a "
                    "loopback/link-local/metadata range and is never an acceptable "
                    "destination for a cluster-originated request.",
                    hint=(
                        "169.254.169.254 in particular returns cloud instance-role "
                        "credentials. This denial cannot be configured away."
                    ),
                )

    entries = _allowed_entries()
    explicitly_listed = any(_matches_entry(host, ip, e) for e in entries)

    # A private address needs an EXPLICIT entry. _allow_any() does not cover it.
    if ip is not None and not explicitly_listed:
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                raise EgressDeniedError(
                    f"{tool}: `{field}`={host!r} is inside the private range {net} "
                    "and is not explicitly listed in CB_ADMIN_EGRESS_ALLOWED_HOSTS.",
                    hint=(
                        "Internal destinations must be named individually so the "
                        "cluster cannot be used to reach arbitrary hosts inside the "
                        "network. CB_ADMIN_EGRESS_ALLOW_ANY covers public "
                        "destinations only and deliberately does not admit private "
                        f"ranges — add {host} (or a tighter CIDR) to the allowlist "
                        "if this destination is intended."
                    ),
                )

    # H11: a name that RESOLVES to a denied address must be refused. Checking only
    # the string meant DNS decided the destination — `imds.attacker.example` with an
    # A record of 169.254.169.254 sailed through, and the module's "cannot be
    # configured away" promise held only for literal IPs. Full rebinding cannot be
    # closed from here (the cluster re-resolves independently), but the static case
    # can, and is.
    resolution_failed = False
    if ip is None and _resolve_check_enabled():
        resolved_addresses = _resolve_all(host)
        resolution_failed = not resolved_addresses
        for resolved in resolved_addresses:
            for net in _ALWAYS_DENIED_NETWORKS:
                if resolved in net:
                    raise EgressDeniedError(
                        f"{tool}: `{field}`={host!r} resolves to {resolved}, which is "
                        f"in the always-denied range {net}.",
                        hint=(
                            "The name is refused because of where it points, not "
                            "because of how it is spelled. Note that a cluster "
                            "re-resolves independently, so DNS rebinding cannot be "
                            "fully prevented here — prefer an IP literal or a CIDR "
                            "entry for anything sensitive."
                        ),
                    )
            if not explicitly_listed:
                for net in _PRIVATE_NETWORKS:
                    if resolved in net:
                        raise EgressDeniedError(
                            f"{tool}: `{field}`={host!r} resolves to {resolved} in the "
                            f"private range {net}, and is not explicitly allowlisted.",
                            hint=(
                                "Add the name or its CIDR to "
                                "CB_ADMIN_EGRESS_ALLOWED_HOSTS if this internal "
                                "destination is intended."
                            ),
                        )

    if explicitly_listed:
        # The operator named this destination deliberately, so an unresolvable name is
        # their decision to make (a name that only resolves inside the cluster's
        # network is a normal case).
        return host

    if _allow_any():
        # ALLOW_ANY is documented as "lifts the allowlist, KEEPS the metadata and
        # loopback denial". For a name, that promise rests entirely on resolution
        # having succeeded: with an empty result the denial loop above ran zero times
        # and the name was admitted unchecked. The cluster then resolves it
        # independently — possibly to 169.254.169.254 — so accepting it would make the
        # one guarantee this mode still offers untrue precisely when it matters.
        if resolution_failed:
            raise EgressDeniedError(
                f"{tool}: `{field}`={host!r} could not be resolved, so it cannot be "
                "checked against the metadata and loopback denials that "
                "CB_ADMIN_EGRESS_ALLOW_ANY still enforces.",
                hint=(
                    "CB_ADMIN_EGRESS_ALLOW_ANY lifts the allowlist but never the "
                    "metadata/loopback denial, and that denial can only be applied to "
                    "a name this server can resolve — the cluster resolves it "
                    "separately, so an unresolvable name here may be a metadata "
                    f"address there. Add {host} to CB_ADMIN_EGRESS_ALLOWED_HOSTS to "
                    "state it explicitly, or use an IP literal."
                ),
            )
        return host

    if not entries:
        raise EgressDeniedError(
            f"{tool}: no egress allowlist is configured, so `{field}`={host!r} is "
            "refused.",
            hint=(
                "This operation makes the CLUSTER connect to a destination the "
                "caller chose — which is how a log bundle, a bucket's contents or "
                "the master encryption key source can be redirected. Set "
                "CB_ADMIN_EGRESS_ALLOWED_HOSTS to the destinations the cluster may "
                "contact (hosts, IPs, CIDRs, or '.domain.example' for a suffix "
                "match). CB_ADMIN_EGRESS_ALLOW_ANY=true lifts the allowlist but "
                "keeps the metadata/loopback denial."
            ),
        )

    raise EgressDeniedError(
        f"{tool}: `{field}`={host!r} is not in CB_ADMIN_EGRESS_ALLOWED_HOSTS.",
        hint=(
            f"Permitted: {', '.join(entries)}. Add the destination there if it is "
            "genuinely intended — it is a deploy-time decision, not one a tool "
            "argument can make."
        ),
    )


#: Key-name fragments (case-insensitive) that mark a value as a DESTINATION the
#: cluster will be asked to contact. Matched as substrings so `kmipHost`,
#: `KMIP_HOSTNAME`, `emailHost`, `targetUri` and `ldapServer` all match.
_HOST_LIKE_FRAGMENTS: tuple[str, ...] = (
    "host",
    "url",
    "uri",
    "server",
    "endpoint",
    "address",
    "addr",
)

#: Keys that CONTAIN a host fragment but are not destinations. Kept tiny and
#: explicit — anything not listed here is guarded.
_HOST_LIKE_EXEMPT: frozenset[str] = frozenset(
    {
        "hostformat",  # display/format options, not a destination
        "urlencoded",
        # These CONTAIN "address" but never name a destination the cluster dials.
        # Without them a legitimate emailAddress or macAddress inside an eventing
        # definition was routed through the allowlist and refused — over-guarding in
        # the safe direction, but an operator-facing outage with no way out.
        "emailaddress",
        "macaddress",
        "ipaddresstype",
        "addressfamily",
    }
)


def _host_like_exempt() -> frozenset[str]:
    """Exemptions, plus any the operator adds via CB_ADMIN_EGRESS_EXEMPT_FIELDS.

    The hard-coded set cannot anticipate every field name across the whole Couchbase
    admin surface, and with no override a false positive is an outage the operator
    cannot resolve without editing the source.
    """
    raw = (os.environ.get("CB_ADMIN_EGRESS_EXEMPT_FIELDS") or "").strip()
    extra = {e.strip().lower() for e in raw.split(",") if e.strip()}
    return _HOST_LIKE_EXEMPT | frozenset(extra)


def _assert_not_absolutely_denied(value: str, *, field: str, tool: str) -> None:
    """Apply ONLY the denials that no configuration may lift.

    Used where an operator exemption suppresses the allowlist. The allowlist is a
    policy an operator may reasonably relax per field; the metadata, loopback and
    link-local denials are not, and this module says so twice in its own hints. Split
    out so the exempt path can honour the second without honouring the first.
    """
    host = split_host(value)
    if not host:
        return
    lowered = host.lower().rstrip(".")
    if lowered in _ALWAYS_DENIED_NAMES:
        raise EgressDeniedError(
            f"{tool}: `{field}`={host!r} is a loopback or metadata hostname and is "
            "never an acceptable destination, including for a field listed in "
            "CB_ADMIN_EGRESS_EXEMPT_FIELDS.",
            hint=(
                "An exemption suppresses the allowlist so a legitimate non-host "
                "field stops being refused. It does not — and must not — lift the "
                "instance-metadata denial, which returns IAM credentials to anything "
                "that can reach it."
            ),
        )
    ip = _as_ip(host)
    if ip is None:
        return
    for net in _ALWAYS_DENIED_NETWORKS:
        if ip in net:
            raise EgressDeniedError(
                f"{tool}: `{field}`={host!r} falls in {net}, a "
                "loopback/link-local/metadata range that is never an acceptable "
                "destination, including for an exempted field.",
                hint=(
                    "169.254.169.254 in particular returns cloud instance-role "
                    "credentials. This denial cannot be configured away, and an "
                    "exemption does not reach it."
                ),
            )


def guard_host_like_fields(data: dict, *, tool: str) -> None:
    """Apply the egress allowlist to every value in `data` that names a destination.

    Replaces a two-entry denylist. The KMIP guard tested exactly ``kmipHost`` and
    ``kmiphost``, so ``KmipHost`` — or any other host-bearing field the endpoint
    accepts — reached the cluster unchecked. Since these tools merge a free-form
    ``additional_fields`` dict into the request body, the set of key spellings that
    can arrive is not bounded by the schema, and an enumeration of accepted spellings
    is therefore the wrong shape for the check.

    Scanning by key SHAPE is the right shape: a new host-bearing field is guarded the
    day the endpoint gains it, rather than the day someone remembers to add it here.
    Over-guarding is the safe direction — the cost is an operator adding a legitimate
    destination to the allowlist.
    """
    for key, value in data.items():
        lowered = str(key).lower()
        if value is None or value is True or value is False or value == "":
            continue
        exempt = lowered in _host_like_exempt()
        host_like = any(fragment in lowered for fragment in _HOST_LIKE_FRAGMENTS)
        if not host_like and not exempt:
            continue
        if exempt:
            # An EXEMPTION suppresses the allowlist, never the absolute denials.
            #
            # It was consulted before every check, so CB_ADMIN_EGRESS_EXEMPT_FIELDS
            # =kmiphost -- added to clear one false positive -- silently re-opened the
            # instance-metadata path for that field, against a denial this module
            # twice promises "cannot be configured away".
            _assert_not_absolutely_denied(str(value), field=str(key), tool=tool)
            continue
        assert_egress_allowed(str(value), field=str(key), tool=tool)


#: Depth cap for the recursive walk. A caller-supplied object nested a few hundred
#: levels deep would otherwise raise RecursionError — which, in a guard, means the
#: request is refused with a confusing error at best and the guard is skipped by an
#: exception handler at worst. Eventing definitions are a handful of levels deep.
_MAX_WALK_DEPTH = 24

#: Cap on leaves examined in one payload. Depth alone was not enough: nothing bounded
#: BREADTH, and assert_egress_allowed resolves every name-valued leaf, so a single
#: tool call with 5,000 leaves made 5,000 blocking getaddrinfo round trips on one
#: worker thread (measured). With a slow or blackholed resolver that is minutes of a
#: held thread from a small pool. It is also a DNS exfiltration channel wherever the
#: documented suffix form (".corp.example") is configured, since every attacker-chosen
#: label under it resolves.
_MAX_WALK_LEAVES = 256


def _looks_like_a_destination(value: str) -> bool:
    """Whether a scalar could name a host at all.

    Used only for the forced (scalar-root) path, so that a numeric or obviously
    non-host value is not run through the allowlist and refused for no reason. A value
    containing a scheme, a dot, or a colon is treated as possibly-a-destination.

    The dot-colon-scheme test alone made the guard's verdict depend on the attacker's
    SPELLING. `169.254.169.254` was denied; the same address as `2852039166` or
    `0xa9fea9fe` has no dot and passed, as did the bare names `metadata` and
    `localhost`. So the two forms this module already knows how to recognise are
    consulted directly: anything `_as_ip` can parse (which normalises legacy numeric,
    hex, octal and IPv4-mapped forms) and anything in the always-denied name list.
    """
    text = value.strip()
    if not text:
        return False
    # The length cap must bound RESOLUTION work, not decide the verdict. Testing the
    # whole value meant padding defeated the guard outright:
    # "s3://169.254.169.254/loot/" + "a"*2100 returned False and went unchecked, while
    # split_host still extracted 169.254.169.254 from it. Cap the extracted HOST
    # instead, which is the only part that reaches a DNS lookup.
    # An over-long value returns TRUE, not False.
    #
    # Returning False here meant "not destination-shaped", which on the forced path
    # SKIPS every check -- so padding converted a DENY into a silent ALLOW, strictly
    # worse than the 2048-char bug it replaced:
    # "169.254.169.254," + "b"*600 was allowed while the unpadded value was denied.
    # Returning True hands it to assert_egress_allowed, which refuses it as an
    # implausible host. The cap therefore bounds RESOLUTION work without ever
    # deciding the verdict in the permissive direction.
    host = split_host(text)
    if (host and len(host) > 512) or (not host and len(text) > 2048):
        return True
    if "://" in text or "." in text or ":" in text:
        return True
    if text.lower() in _ALWAYS_DENIED_NAMES:
        return True
    return _as_ip(text) is not None


def guard_nested_host_fields(
    obj: Any,
    *,
    tool: str,
    path: str = "",
    _depth: int = 0,
    _budget: list[int] | None = None,
) -> None:
    """Guard every destination-shaped value anywhere inside a nested payload.

    The guard this replaces read exactly ``definition["depcfg"]["curl"][i]["hostname"]``
    and returned silently whenever the shape differed — so it failed OPEN in four
    separate ways: a top-level ARRAY of definitions (which the Eventing endpoint
    accepts), a non-dict ``depcfg``, ``curl`` as a single object rather than a list,
    and any other spelling of the host key.

    The first version of this walk still failed open on one shape: a LIST OF SCALARS.
    ``{"hostname": ["169.254.169.254"]}`` recursed into the list, and a ``str`` item
    matched neither the dict nor the container branch, so it fell out unchecked — and
    the key name had already been lost, so no host-shape test could be applied
    either. Sequence items are now guarded against the ENCLOSING key's name, which is
    the only sensible interpretation of ``hostname: [...]``.
    """
    if _budget is None:
        _budget = [_MAX_WALK_LEAVES]

    if _depth > _MAX_WALK_DEPTH:
        raise EgressDeniedError(
            f"{tool}: payload nests deeper than {_MAX_WALK_DEPTH} levels at "
            f"{path or '<root>'}, so its destinations cannot be checked.",
            hint=(
                "Refusing rather than walking further: a guard that gives up quietly "
                "on an awkward shape is not a guard. Flatten the payload."
            ),
        )

    def _check_leaf(
        key_name: str, value: Any, where: str, *, force: bool = False
    ) -> None:
        """Apply the allowlist to one scalar, judged by the key that introduced it."""
        # Identity, not equality: `1 in (True,)` is True in Python, so integer and
        # float leaves 0, 1, 0.0 and 1.0 were skipped here while the FLAT guard denied
        # them -- {"hostname": 1} is 0.0.0.1, inside the 0.0.0.0/8 denial this module
        # widened precisely because 0.0.0.1 routes to the local host on Linux. The two
        # guards therefore disagreed in both directions for the same field.
        if value is None or value is True or value is False or value == "":
            return
        lowered = str(key_name).lower()
        if not force:
            if lowered in _host_like_exempt():
                # Exemption suppresses the ALLOWLIST only, never the absolute
                # denials -- same rule as the flat guard, so the two agree.
                _assert_not_absolutely_denied(
                    str(value) if not isinstance(value, str) else value,
                    field=where,
                    tool=tool,
                )
                return
            if not any(fragment in lowered for fragment in _HOST_LIKE_FRAGMENTS):
                return
        # Stringify rather than skip. A non-str leaf under a host-like key was
        # dropped entirely, so `{"hostname": 2852039166}` was unchecked while
        # `{"hostname": "169.254.169.254"}` was denied -- the same address, decided by
        # its JSON type.
        text = value if isinstance(value, str) else str(value)
        # The heuristic applies ONLY on the forced path now. On the non-forced path
        # the KEY has already declared this a destination (it matched
        # _HOST_LIKE_FRAGMENTS and is not exempt), so second-guessing that with a
        # shape test is what let `hostname: "metadata"` through -- while
        # guard_host_like_fields, the flat guard over the same keys, applied no such
        # test and denied it. Three guards over one payload disagreed in the unsafe
        # direction; now the nested walk matches the flat one by construction.
        if force and not _looks_like_a_destination(text):
            return
        value = text
        _budget[0] -= 1
        if _budget[0] < 0:
            raise EgressDeniedError(
                f"{tool}: payload contains more than {_MAX_WALK_LEAVES} "
                "destination-shaped values, which cannot all be checked in one call.",
                hint=(
                    "Each one requires a DNS resolution, so an unbounded count is "
                    "both a denial-of-service against this server and a way to use "
                    "it as a DNS side channel. Split the request."
                ),
            )
        assert_egress_allowed(str(value), field=where, tool=tool)

    if not isinstance(obj, (dict, list, tuple, set)):
        # A SCALAR ROOT. This branch silently returned, and handlers/backup.py passes
        # args["target"] straight in with no type validation anywhere in the dispatch —
        # so `target="s3://169.254.169.254/loot"` reached the Backup Service having been
        # checked by nothing at all, while the same value inside an object was denied.
        # A guard whose coverage depends on the caller's choice of JSON type is not a
        # guard, so the scalar is checked against the name it arrived under.
        # `force=True`: a scalar handed to this guard IS the destination-bearing value
        # by construction (backup's `target`, eventing's `definition`), so it is checked
        # regardless of whether its name happens to look host-like.
        _check_leaf(path or "value", obj, path or "<root>", force=True)
        return

    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            if isinstance(value, (dict, list, tuple, set)):
                guard_nested_host_fields(
                    value, tool=tool, path=child, _depth=_depth + 1, _budget=_budget
                )
            else:
                _check_leaf(key, value, child)
    elif isinstance(obj, (list, tuple, set)):
        # The key that introduced this sequence is the last path segment; a scalar
        # inside `hostname: [...]` is a hostname.
        enclosing = path.rsplit(".", 1)[-1].split("[")[0]
        for index, item in enumerate(obj):
            child = f"{path}[{index}]"
            if isinstance(item, (dict, list, tuple, set)):
                guard_nested_host_fields(
                    item, tool=tool, path=child, _depth=_depth + 1, _budget=_budget
                )
            else:
                # A string directly inside the ROOT payload is checked regardless of
                # the enclosing name, for the same reason a scalar root is: the caller
                # chose the JSON type, and `definition=["http://169.254.169.254/"]`
                # otherwise reached the endpoint unchecked while the dict spelling of
                # the same thing was denied. Deeper strings are judged by their key,
                # because forcing everywhere would run an Eventing function's appcode
                # through the allowlist and refuse ordinary JavaScript.
                _check_leaf(enclosing, item, child, force=_depth == 0)


def describe_policy() -> dict:
    """Egress posture, for the status tool and the startup banner."""
    entries = _allowed_entries()
    return {
        "allowed_hosts": list(entries),
        "allow_any": _allow_any(),
        "posture": (
            "unrestricted (metadata/loopback still denied)"
            if _allow_any()
            else (
                "allowlisted" if entries else "fail-closed — no destinations permitted"
            )
        ),
    }
