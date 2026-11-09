# The egress allowlist: where the cluster may be told to connect

**Source:** `handlers/egress.py`. Called from `handlers/cluster.py`, `handlers/backup.py`,
`handlers/encryption.py`, `handlers/eventing.py`, `handlers/search_admin.py` and
`handlers/xdcr.py`.
**Spec:** `docs/spec.md` S10 (egress allowlist) and S3 step 8 (`denied_egress`).
**Configuration:** `CB_ADMIN_EGRESS_ALLOWED_HOSTS`, `CB_ADMIN_EGRESS_ALLOW_ANY`,
`CB_ADMIN_EGRESS_SKIP_DNS`, `CB_ADMIN_EGRESS_EXEMPT_FIELDS`.

## What it decides

Several admin tools take a hostname from the caller and make **Couchbase itself** open the
connection. The caller names the destination and the cluster dials it, from inside the trust
boundary and sometimes holding a cloud instance role. The allowlist decides whether a named
destination is acceptable, before the call is made. It answers with a host, or with an
`EgressDeniedError` after which nothing has been sent.

The destinations it guards are the log upload host (`admin_logs_collect_start`), XDCR
reference hostnames, the node to add (`admin_node_add`), the KMIP host (`admin_kmip_set`), the
alert mail host (`admin_alerts_set`), and any destination-shaped value inside a nested payload
such as an Eventing definition's `curl` bindings.

## The rules, in the order they are applied

1. **Parse the host first** (`split_host`). Scheme, then query and fragment, then everything
   before the last `@` (userinfo), then the port. Anything that cannot be a hostname is
   refused, not guessed at (`_is_plausible_host`).
2. **Always refuse** loopback, link-local (including `169.254.169.254`), `0.0.0.0/8`, the EC2
   IPv6 metadata address and the names `metadata`, `metadata.google.internal`, `localhost` and
   a few others. No setting lifts this, including `CB_ADMIN_EGRESS_ALLOW_ANY` and an explicit
   allowlist entry.
3. **Private ranges need an explicit entry.** RFC1918, `100.64.0.0/10` and `fc00::/7` are
   refused unless the operator named the address or a CIDR that covers it.
   `CB_ADMIN_EGRESS_ALLOW_ANY` does not admit them. "Any" means any public destination.
4. **Resolve a name and judge its addresses by rules 2 and 3.** A name that points at a denied
   address is refused for where it points. `CB_ADMIN_EGRESS_SKIP_DNS=true` turns this off for
   hosts where DNS is unavailable.
5. **Then the allowlist.** An entry is an exact host, a CIDR, or a leading-dot suffix such as
   `.corp.example`, which matches subdomains and the bare domain. An entry the operator wrote
   admits an unresolvable name, because a name that only resolves inside the cluster's network
   is normal.
6. **With no entries and no allow-any, everything is refused.** The message names the variable
   to set. Fail closed: the operator says once, at deploy time, where the cluster may talk to.

The posture is deliberately asymmetric. The things that cost the most when wrong (cloud
credentials, the master encryption key) have no override. The things that are only convenient
have one that is named conspicuously.

## Why it is built this way

**The caller can make the cluster a proxy and a scanner.** A caller who can name a destination
can reach internal addresses the caller cannot reach itself, and the error text returned to
the model turns the cluster into a port scanner. Pointing `admin_kmip_set` elsewhere means the
cluster cannot decrypt its own data after a restart. `admin_logs_collect_start` sends query
text, document keys and sometimes credentials to the named host.

**The order of parsing is the security property.** The first version stripped the port before
handling userinfo, so `smtp.corp.example:25@169.254.169.254` was judged as
`smtp.corp.example` while the real destination was the metadata service. A suffix entry could
be matched by `https://evil.tld?x=.corp.example`. The parse order above, and the refusal of
any value that still holds credentials or a query, close both. The reason given in the code:
anything this server parses differently from the cluster is a way to smuggle a different
target past the allowlist.

**The same address has many spellings, and the OS accepts all of them.** `_as_ip` normalizes
three that each bypassed a denial in the past: IPv4-mapped IPv6 (`::ffff:169.254.169.254`), the
legacy numeric forms `inet_aton` and libcurl accept (`2130706433`, `0x7f000001`, `0177.0.0.1`),
and a trailing dot (`169.254.169.254.`). The denial network for `0.0.0.0/8` is the whole block
because `0.0.0.1` reaches the local host on Linux.

**An unresolvable name must not become a way through.** With `CB_ADMIN_EGRESS_ALLOW_ANY` on and
resolution failing, the metadata check would run zero times and the name would be admitted
unchecked, while the cluster resolves it separately and may get `169.254.169.254`. So an
unresolvable, unlisted name is refused under allow-any.

**A destination is recognized by the key that introduced it.** `guard_host_like_fields` and
`guard_nested_host_fields` treat a value as a destination when its key contains `host`, `url`,
`uri`, `server`, `endpoint`, `address` or `addr`. A short, explicit exempt list
(`hostformat`, `emailaddress`, `macaddress`, and a few more) covers keys that contain a
fragment but name nothing the cluster dials. The operator can add more with
`CB_ADMIN_EGRESS_EXEMPT_FIELDS`, because a false positive with no way out is an outage. An
exemption suppresses the allowlist and never the absolute denials in rule 2.

**A walk over a payload is bounded.** Depth is capped at 24 and leaves at 256. Resolution is
blocking, so 5,000 leaves made 5,000 `getaddrinfo` calls on one worker thread (measured). With
a suffix entry configured, every attacker-chosen label under it resolves, which is also a DNS
exfiltration channel. An over-long value is handed to `assert_egress_allowed`, which refuses it
as an implausible host. Returning "not destination-shaped" for it skipped every check, so
padding turned a denial into an allow.

## What it cannot do

DNS rebinding is not closed. The cluster re-resolves a name on its own, so a name can resolve to
a safe address here and a denied one there. The code says so and recommends an IP literal or a
CIDR entry for anything sensitive. The check applies only to the tools that call it. A new tool
that makes the cluster dial a caller-named host must call it, and nothing finds the omission
except the sweep test below.

## Where it is tested

| Property | Test |
| --- | --- |
| Metadata and loopback always denied, even when listed, with a port, or as a URL | `tests/test_egress_and_statement_guards.py::test_metadata_and_loopback_are_always_denied` and the three after it |
| No entries means no destination | `test_no_allowlist_means_no_destination_permitted`, `test_describe_policy_reports_fail_closed` |
| Exact, suffix and CIDR entries; a lookalike domain does not match | the same file, `test_exact_host_allowlist` to `test_cidr_allowlist` |
| Private ranges need an explicit entry and allow-any does not admit them | `test_private_ranges_are_not_admitted_by_allow_any`, `test_private_host_is_permitted_when_explicitly_named` |
| Unresolvable names under allow-any, and the skip-DNS escape | `test_allow_any_refuses_a_name_it_cannot_resolve`, `test_skip_dns_remains_an_escape_hatch` |
| Each of the five flat sinks refuses an unlisted destination through the real handler | `test_each_sink_refuses_an_unallowlisted_destination` (guarded against an empty list by `test_the_sink_inventory_is_not_empty`) |
| Exemptions never lift the absolute denials; padding cannot turn a denial into a skip | `tests/test_egress_exemptions_and_shapes.py` |
| The nested and flat guards agree | `tests/test_scan_20260817_regressions.py::test_sec5_nested_and_flat_guards_agree` |

The sweep test replaced a structural test that searched for the string `assert_egress_allowed`.
That test passed with the guard deleted from three of four sinks, because the string was still
present elsewhere in the file. Mutation testing found it. The sweep calls each real handler.

## Before you change it

- A new tool whose argument becomes a destination the cluster dials must call
  `assert_egress_allowed` or `guard_host_like_fields`, and must be added to `SINK_CALLS` in
  `tests/test_egress_and_statement_guards.py`. Then update the count in
  `test_the_sink_inventory_is_not_empty`.
- Do not add a setting that lifts rule 2. Do not return "skip" from a length or shape test.
- Parse order is part of the contract. If you touch `split_host`, add the spelling that broke
  before the one you are fixing, and keep the ones in `tests/` passing.
- Four guards in `handlers/egress.py` are covered by the mutation rounds
  (`scripts/mutation_*.py --list`, counted 2026-11-09). Add one for any guard you add.
- Chris Ahrendt decides the defaults. Record a change in `docs/design-decisions.md`.
