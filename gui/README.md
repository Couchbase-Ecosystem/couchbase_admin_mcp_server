# gui/

The operator console: a Flask backend (`gui_server.py`) and a front end (`static/`). It
lets a person list the tools and call them. It is a separate process from the MCP server.

- It asks the same `authz.py` module for every decision, so the console and the server
  cannot drift apart. Every console call writes an audit record.
- With `OAUTH_ENABLED=false` (the default) there is no authentication, and it is for
  localhost only. The enterprise profile refuses `CB_GUI_INSECURE_NO_AUTH`
  (`profile_config.py`).

Start it:

```bash
uv run python gui/gui_server.py                # local
gunicorn "gui.gui_server:create_app()"         # served
```

Install the extras first (`uv sync --extra gui`, or `--extra oauth` for login). Read the
`gui_server.py` header for the environment variables.

Tests: `tests/test_gui_*.py`.
