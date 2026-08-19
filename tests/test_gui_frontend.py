"""
The console must actually render, and must not reach the internet to do it.

THE FINDING
===========
`gui/static/index.html` was 567 lines of JSX — 67 `className=` attributes, `{/* ... */}`
comments, JSX return values — served in a plain `<script>` tag with React loaded from
cdnjs and NO transpiler anywhere on the page. The browser threw
`SyntaxError: Unexpected token '<'` on the first tag and React never mounted. The
console rendered a blank page; it had never worked.

Nothing caught it because there was no frontend test at all, and every backend test
drives Flask directly and never loads the page.

Two independent problems were fixed, so both are asserted:

  1. No transpiler. Babel standalone is now vendored and the app script is
     `type="text/babel"`.
  2. Third-party runtime dependencies. React and Babel came from cdnjs and the fonts
     from Google, so the console could not load inside an air-gapped or
     egress-restricted network — and an administration tool for a production database
     took its JavaScript from a CDN at request time.

The compile-and-render test needs Node, which is not a dependency of this project, so it
skips cleanly where Node is unavailable. The static assertions do not need it and always
run.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess

import pytest

STATIC = pathlib.Path(__file__).resolve().parent.parent / "gui" / "static"
INDEX = STATIC / "index.html"
VENDOR = STATIC / "vendor"


@pytest.fixture(scope="module")
def html() -> str:
    return INDEX.read_text(encoding="utf-8")


# ── Static guarantees (no Node required) ─────────────────────────────────────


def test_the_page_exists_and_is_not_trivial(html):
    """Premise for everything below."""
    assert len(html) > 10_000


def test_the_app_script_is_marked_for_the_transpiler(html):
    """The exact defect: JSX in a plain <script>.

    Without type="text/babel" the browser parses it as JavaScript, hits the first `<`,
    and throws — so React never mounts and the page is blank.
    """
    assert re.search(r'<script type="text/babel"', html), (
        "the application script is not marked text/babel; if it contains JSX the "
        "browser will throw SyntaxError and the console will render nothing"
    )


def test_the_jsx_premise_still_holds(html):
    """Guards the test above from becoming vacuous.

    If someone converts the source to React.createElement, text/babel is no longer
    required and this whole file should be revisited rather than silently passing.
    """
    app = re.search(r'<script type="text/babel"[^>]*>(.*?)</script>', html, re.S)
    assert app, "no text/babel script found"
    assert app.group(1).count("className=") > 10, (
        "the app no longer looks like JSX; if it was converted to createElement, the "
        "Babel requirement (and its 2.9 MB vendored bundle) can be dropped"
    )


def test_babel_is_available_to_the_page(html):
    assert re.search(r'<script src="vendor/babel[^"]*\.js"', html), (
        "type=text/babel is set but no Babel is loaded, so nothing compiles the JSX"
    )
    assert (VENDOR / "babel.min.js").is_file()


def test_react_is_vendored_not_fetched(html):
    for name in ("react.production.min.js", "react-dom.production.min.js"):
        assert (VENDOR / name).is_file(), f"vendor/{name} is missing"
        assert f'src="vendor/{name}"' in html, f"{name} is not loaded from vendor/"


def test_the_page_has_no_external_runtime_dependency(html):
    """An air-gapped network cannot reach cdnjs or Google Fonts, and an admin
    console should not take its JavaScript from a third party at request time."""
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    assert not external, f"the console still loads from external origins: {external}"


def test_no_font_service_dependency(html):
    """The webfont <link> failed closed to invisible text in some browsers and was a
    third-party request from an admin tool."""
    assert "fonts.googleapis.com" not in html
    assert "fonts.gstatic.com" not in html


def test_font_stacks_degrade_to_system_fonts(html):
    """Dropping the webfont must not leave the console unstyled: the intended faces stay
    first in the stack, with real fallbacks behind them."""
    assert re.search(r"--font-ui:\s*'Syne',[^;]*sans-serif", html)
    assert re.search(r"--font-mono:\s*'DM Mono',[^;]*monospace", html)


def test_vendored_licences_are_present():
    """Both bundles are MIT, and redistributing them means shipping their licences."""
    licences = list(VENDOR.glob("*.LICENSE"))
    assert licences, "vendored third-party code with no licence files"
    for path in licences:
        assert "MIT" in path.read_text(encoding="utf-8", errors="ignore")


def test_the_vendor_directory_ships_in_the_image():
    """The console is COPYed into the container; its vendored runtime has to come too,
    or the page loads and then fails to find React."""
    dockerfile = (STATIC.parent.parent / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^COPY[^\n]*\bgui\b", dockerfile, re.MULTILINE), (
        "gui/ is not copied into the image"
    )


# ── The real thing: compile and render (needs Node) ─────────────────────────


def _node() -> str | None:
    return shutil.which("node")


@pytest.mark.skipif(_node() is None, reason="node is not available")
def test_the_vendored_babel_compiles_the_app(tmp_path):
    """Compile the actual JSX with the actual vendored Babel.

    A version of Babel that cannot parse this source would leave the console just as
    blank as having no Babel at all, so the pairing is what matters, not the presence of
    the file.
    """
    script = tmp_path / "compile.js"
    script.write_text(
        f"""
        const fs = require("fs");
        const html = fs.readFileSync({json.dumps(str(INDEX))}, "utf8");
        const m = html.match(/<script type="text\\/babel"[^>]*>([\\s\\S]*?)<\\/script>/);
        if (!m) {{ console.log("NO_APP_SCRIPT"); process.exit(1); }}
        global.self = global;
        const Babel = require({json.dumps(str(VENDOR / "babel.min.js"))}) || global.Babel;
        const out = Babel.transform(m[1], {{ presets: ["react"] }}).code;
        console.log("OK " + Babel.version + " " + out.length);
        """,
        encoding="utf-8",
    )
    result = subprocess.run(
        [_node(), str(script)], check=False, capture_output=True, text=True, timeout=300
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("OK "), result.stdout
    _, version, size = result.stdout.split()
    assert int(size) > 5000, "compiled output is implausibly small"


@pytest.mark.skipif(_node() is None, reason="node is not available")
def test_the_compiled_app_renders_markup(tmp_path):
    """Execute the compiled component tree and assert markup comes out.

    This is the assertion that would have failed on the broken version: not "the file
    parses" but "the App component evaluates and produces DOM".

    Uses react-dom/server if React is resolvable; otherwise falls back to asserting the
    App component is at least defined, which still catches a syntax or reference error.
    """
    script = tmp_path / "render.js"
    script.write_text(
        f"""
        const fs = require("fs"), vm = require("vm");
        const html = fs.readFileSync({json.dumps(str(INDEX))}, "utf8");
        const m = html.match(/<script type="text\\/babel"[^>]*>([\\s\\S]*?)<\\/script>/);
        global.self = global;
        const Babel = require({json.dumps(str(VENDOR / "babel.min.js"))}) || global.Babel;
        const code = Babel.transform(m[1], {{ presets: ["react"] }}).code;

        let React, Server;
        try {{ React = require("react"); Server = require("react-dom/server"); }} catch {{}}

        const sandbox = {{
          React: React || {{ createElement: () => ({{}}), useState: () => [null, () => {{}}] }},
          console,
          window: {{ location: {{ origin: "http://127.0.0.1:5173" }}, addEventListener() {{}} }},
          document: {{ getElementById: () => ({{}}) }},
          fetch: () => Promise.resolve({{ ok: true, json: () => Promise.resolve([]) }}),
          setTimeout, clearTimeout,
          ReactDOM: {{ createRoot: () => ({{ render() {{}} }}) }},
        }};
        vm.createContext(sandbox);
        vm.runInContext(code + "\\n;globalThis.__App = typeof App !== 'undefined' ? App : null;", sandbox);
        if (typeof sandbox.__App !== "function") {{ console.log("NO_APP"); process.exit(1); }}
        if (!Server) {{ console.log("DEFINED_ONLY"); process.exit(0); }}
        const markup = Server.renderToStaticMarkup(React.createElement(sandbox.__App));
        console.log("RENDERED " + markup.length + " " + (/<div/.test(markup) ? "hasdiv" : "nodiv"));
        """,
        encoding="utf-8",
    )
    env = {"NODE_PATH": "/tmp/node_modules"}
    import os

    result = subprocess.run(
        [_node(), str(script)],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, **env},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout.strip()
    if out == "DEFINED_ONLY":
        # HARD FAILURE IN CI, skip only on a developer machine.
        #
        # This skip was permanent EVERYWHERE, including CI: the node script does
        # `try { require("react") } catch {}` with NODE_PATH=/tmp/node_modules, and
        # nothing -- not this test, not conftest, not the workflow -- ever installed
        # react. The repo vendors browser UMD bundles, which cannot satisfy
        # `require("react-dom/server")`. So the assertions below, which the docstring
        # calls "the assertion that would have failed on the broken version", never ran
        # anywhere, and the CI comment "a skipped frontend test is how the console came
        # to render a blank page unnoticed -- so CI installs Node" was true in letter
        # only: Node was installed, React was not.
        #
        # CI now runs `npm install --prefix /tmp react react-dom`, so in CI a
        # DEFINED_ONLY result means that install broke and the render is genuinely
        # unverified -- which must fail rather than skip.
        if os.environ.get("CI"):
            pytest.fail(
                "react is not resolvable in CI, so the console render was NOT "
                "verified. The workflow installs react/react-dom into /tmp; check "
                "that step. A skipped frontend test is how the console came to render "
                "a blank page unnoticed."
            )
        pytest.skip(
            "react not resolvable locally; compile + App definition verified. "
            "Run `npm install --prefix /tmp react react-dom` to exercise the render "
            "assertions, which CI does."
        )
    assert out.startswith("RENDERED "), out
    _, size, hasdiv = out.split()
    assert int(size) > 500, f"render produced only {size} bytes"
    assert hasdiv == "hasdiv"
