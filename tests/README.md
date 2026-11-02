# tests/

The regression suite. It needs no cluster. CI runs it in random order, in file order, and with a
coverage floor (`.github/workflows/ci.yml`). Commands are in `docs/BUILD_GUIDE.md`.

Files that apply across the whole code base:

| File | What it guards |
| --- | --- |
| `test_handler_contract.py` | Every tool group meets the same contract: honest annotations, every tool routed, no duplicate names, no handler that raises |
| `test_no_vacuous_coverage.py` | A test may not pass because it checked nothing |
| `test_tool_group_examples.py` | One tested, runnable example for each of the 17 tool groups, run against stubs. The gate fails when a group has none |
| `test_documentation_gate.py` | The documentation standard (D1 to D15). Each rule is in `report` or `fail` mode |
| `test_docs_are_not_stale.py` | A count quoted in a document carries a date |
| `test_tool_inventory_is_current.py`, `test_diagrams_match_the_code.py` | Documents that list tools or draw the design match the code |
| `test_packaging.py` | The wheel and the image include every module the server imports |
| `test_dispatch_parity.py` | The server and the console decide the same way |

Two rules that matter most (`AGENTS.md` section 3 and `CONTRIBUTING.md`):

1. A test must fail when the control it guards is removed. The mutation harnesses in
   `scripts/` prove it for the security controls.
2. A test may not pass vacuously. A loop over an empty list proves nothing.

Test files are grouped by area in their names (`test_capella_*`, `test_ee_fixture_*`,
`test_gui_*`, `test_http_*`). Every file opens with a header that says what it guards and why.
