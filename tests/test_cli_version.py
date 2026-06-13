"""``mcp-warden --version`` flag coverage.

The version flag is a shipped support contract: ``SECURITY.md`` and the
bug-report issue template instruct users to run ``mcp-warden --version`` to
report their installed version, and ``RELEASING.md`` uses it in the post-release
verify step. These tests assert the flag prints the package version and exits 0,
and that adding the eager root callback did not break the subcommands.
"""

from __future__ import annotations

import re

import typer
from typer.testing import CliRunner

from mcp_warden import __version__
from mcp_warden.cli import app

runner = CliRunner()

#: ANSI/CSI escape-sequence stripper (rich emits color + cursor codes).
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _plain(text: str) -> str:
    """De-ANSI a rich-rendered string and collapse all whitespace."""
    return re.sub(r"\s+", " ", _ANSI.sub("", text))


def test_version_flag_prints_version_and_exits_zero() -> None:
    """``--version`` prints ``mcp-warden <version>`` and exits 0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    plain = _plain(result.output)
    assert __version__ in plain
    assert "mcp-warden" in plain


def test_version_flag_registered_on_root() -> None:
    """``--version`` is a registered root option.

    Introspect the click command rather than scraping the rendered help text:
    rich line-wraps the help table differently across terminal widths (a narrow
    CI terminal can split the ``--version`` token across box cells), so a
    rendered-string substring search is geometry-dependent and flaky. The
    registered param list is render-independent and is what actually matters.
    """
    click_cmd = typer.main.get_command(app)
    root_opts = [opt for p in click_cmd.params for opt in getattr(p, "opts", [])]
    assert "--version" in root_opts


def test_root_callback_does_not_break_subcommands() -> None:
    """The eager root callback must not shadow or break the subcommands.

    A bare unknown subcommand still errors as before (non-zero), proving the
    callback did not turn the app into a no-arg command.
    """
    result = runner.invoke(app, ["definitely-not-a-command"])
    assert result.exit_code != 0
