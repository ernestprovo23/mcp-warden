"""Tests for ``warden diff`` — the offline, redacted lock comparison (#20).

``diff`` is a RENDERER over ``compute_drift``; these tests exercise the four
output behaviors (human / ``--json`` / ``--sarif`` / exit code) and — most
importantly — the redaction guarantee: a secret planted in ``server.args`` must
never appear in ANY output mode (M1/M2 leak test).
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from mcp_warden.cli import app
from mcp_warden.lockfile import build_lock, write_lock
from mcp_warden.models import CapturedSurface, CapturedTool

runner = CliRunner()

# Rich soft-wraps to 80 cols when stdout is a pipe (CliRunner). A wide terminal
# keeps each JSONL record on one line so the parsing assertions are stable —
# this mirrors how `--json` is consumed in a real (wide) CI terminal/redirect.
_WIDE = {"COLUMNS": "1000"}


def _surface(tools=None, command="python", args=None):
    return CapturedSurface(
        command=command,
        args=args if args is not None else ["server.py"],
        protocol_version="2025-06-18",
        tools=tools or [],
        resources=[],
        prompts=[],
    )


def _write(tmp_path, name, surface, **build_kwargs):
    """Build a lock from a surface and write it to ``tmp_path/name``."""
    lock = build_lock(surface, [], **build_kwargs)
    path = tmp_path / name
    write_lock(lock, path)
    return path


def test_identical_locks_no_differences(tmp_path):
    s = _surface([CapturedTool(name="read_file", input_schema={"properties": {"path": {}}})])
    a = _write(tmp_path, "a.lock", s)
    b = _write(tmp_path, "b.lock", s)
    result = runner.invoke(app, ["diff", str(a), str(b)])
    assert result.exit_code == 0
    assert "no differences" in result.stdout
    assert "a.lock" in result.stdout and "b.lock" in result.stdout  # M5 basenames


def test_tool_added_removed_and_schema_change_render(tmp_path):
    base = _surface(
        [
            CapturedTool(name="keep", input_schema={"properties": {"a": {"type": "string", "maxLength": 64}}}),
            CapturedTool(name="gone", input_schema={}),
        ]
    )
    cur = _surface(
        [
            CapturedTool(name="keep", input_schema={"properties": {"a": {"type": "string", "maxLength": 4096}}}),
            CapturedTool(name="fresh", input_schema={}),
        ]
    )
    a = _write(tmp_path, "a.lock", base)
    b = _write(tmp_path, "b.lock", cur)
    result = runner.invoke(app, ["diff", str(a), str(b)], env=_WIDE)
    assert result.exit_code == 0  # viewer: default exit 0 even with drift
    out = result.stdout
    assert "tool-added" in out and "tools/fresh" in out
    assert "tool-removed" in out and "tools/gone" in out
    assert "schema-constraint-relaxed" in out  # the maxLength relaxation


def test_diff_redaction_leak(tmp_path):
    """M1/M2: a secret planted in server.args must NEVER appear in any output.

    Two locks with different launch argv (one carrying ``sk-PLANTEDSECRET123``)
    produce a server-identity drift. We diff in all three modes and assert the
    secret leaks into NONE of them, while the "launch changed" row IS present —
    proving the change is visible without the secret. We also PARSE the JSONL and
    assert every record's ``detail`` field is clean.
    """
    secret = "sk-PLANTEDSECRET123"
    base = _surface(
        [CapturedTool(name="t", input_schema={})],
        command="node",
        args=["server.js", "--api-key", secret],
    )
    cur = _surface(
        [CapturedTool(name="t", input_schema={})],
        command="node",
        args=["server.js", "--api-key", "sk-DIFFERENTKEY456"],
    )
    a = _write(tmp_path, "a.lock", base)
    b = _write(tmp_path, "b.lock", cur)
    sarif_path = tmp_path / "out.sarif"

    human = runner.invoke(app, ["diff", str(a), str(b)], env=_WIDE)
    js = runner.invoke(app, ["diff", str(a), str(b), "--json"], env=_WIDE)
    sa = runner.invoke(app, ["diff", str(a), str(b), "--sarif", str(sarif_path)], env=_WIDE)

    assert human.exit_code == 0 and js.exit_code == 0 and sa.exit_code == 0
    sarif_text = sarif_path.read_text(encoding="utf-8")

    for blob in (human.stdout, js.stdout, sarif_text):
        assert secret not in blob
        assert "PLANTEDSECRET" not in blob

    # The change must still be VISIBLE: hardcoded "launch changed" message row.
    assert "server-identity" in human.stdout
    assert "launch" in human.stdout.lower()

    # Parse the JSONL and assert each record's detail field is clean (M2).
    records = [json.loads(line) for line in js.stdout.splitlines() if line.strip()]
    assert any(r.get("drift_class") == "server-identity" for r in records)
    for rec in records:
        detail = rec.get("detail")
        if detail is not None:
            assert "PLANTEDSECRET" not in detail and secret not in detail


def test_provenance_only_difference_no_integrity_drift(tmp_path):
    """Provenance-only change: integrity drift empty, provenance section shown.

    Build identical surfaces, then mutate ONLY out-of-digest provenance on B
    (rotation_count + approver). ``overall_digest`` is unchanged, so
    ``compute_drift`` returns empty; ``--exit-code`` returns 0.
    """
    s = _surface([CapturedTool(name="t", input_schema={})])
    a_lock = build_lock(s, [])
    b_lock = a_lock.model_copy(deep=True)
    # Mutate only out-of-digest pin provenance.
    b_lock.pin.rotation_count = 3
    b_lock.pin.approved = True
    b_lock.pin.approver = "alice@example.com"
    b_lock.pin.approved_digest = b_lock.overall_digest

    a = tmp_path / "a.lock"
    b = tmp_path / "b.lock"
    write_lock(a_lock, a)
    write_lock(b_lock, b)

    result = runner.invoke(app, ["diff", str(a), str(b), "--exit-code"])
    assert result.exit_code == 0  # provenance-only does NOT trip --exit-code
    out = result.stdout
    assert "Provenance" in out
    assert "rotation_count" in out
    assert "approver" in out
    assert "alice@example.com" in out


def test_exit_code_trips_on_integrity_drift(tmp_path):
    base = _surface([CapturedTool(name="a", input_schema={})])
    cur = _surface([CapturedTool(name="a", input_schema={}), CapturedTool(name="b", input_schema={})])
    a = _write(tmp_path, "a.lock", base)
    b = _write(tmp_path, "b.lock", cur)
    result = runner.invoke(app, ["diff", str(a), str(b), "--exit-code"])
    assert result.exit_code == 1


def test_json_output_parses(tmp_path):
    base = _surface([CapturedTool(name="a", input_schema={})])
    cur = _surface([CapturedTool(name="a", input_schema={}), CapturedTool(name="b", input_schema={})])
    a = _write(tmp_path, "a.lock", base)
    b = _write(tmp_path, "b.lock", cur)
    result = runner.invoke(app, ["diff", str(a), str(b), "--json"], env=_WIDE)
    assert result.exit_code == 0
    records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert records
    assert all(r["kind"] == "drift" for r in records)
    assert any(r["drift_class"] == "tool-added" for r in records)


def test_sarif_output_is_valid(tmp_path):
    base = _surface([CapturedTool(name="a", input_schema={})])
    cur = _surface([CapturedTool(name="a", input_schema={}), CapturedTool(name="b", input_schema={})])
    a = _write(tmp_path, "a.lock", base)
    b = _write(tmp_path, "b.lock", cur)
    sarif_path = tmp_path / "out.sarif"
    result = runner.invoke(app, ["diff", str(a), str(b), "--sarif", str(sarif_path)])
    assert result.exit_code == 0
    doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "mcp-warden"
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert any(rid.startswith("WRD-DRIFT-") for rid in rule_ids)


def test_missing_lock_fails_closed(tmp_path):
    s = _surface([CapturedTool(name="a", input_schema={})])
    a = _write(tmp_path, "a.lock", s)
    missing = tmp_path / "does-not-exist.lock"
    result = runner.invoke(app, ["diff", str(a), str(missing)])
    assert result.exit_code == 2


def test_invalid_lock_fails_closed(tmp_path):
    s = _surface([CapturedTool(name="a", input_schema={})])
    a = _write(tmp_path, "a.lock", s)
    bad = tmp_path / "bad.lock"
    bad.write_text("{ not valid json", encoding="utf-8")
    result = runner.invoke(app, ["diff", str(a), str(bad)])
    assert result.exit_code == 2


def test_no_provenance_suppresses_section_and_emits_m6_message(tmp_path):
    """M6: --no-provenance hides a real provenance diff -> the M6 message, not bare 'no differences'."""
    s = _surface([CapturedTool(name="t", input_schema={})])
    a_lock = build_lock(s, [])
    b_lock = a_lock.model_copy(deep=True)
    b_lock.pin.rotation_count = 5  # out-of-digest provenance-only change
    a = tmp_path / "a.lock"
    b = tmp_path / "b.lock"
    write_lock(a_lock, a)
    write_lock(b_lock, b)

    result = runner.invoke(app, ["diff", str(a), str(b), "--no-provenance"])
    assert result.exit_code == 0
    out = result.stdout
    assert "Provenance" not in out  # section suppressed
    assert "no integrity drift" in out
    assert "hidden by --no-provenance" in out


def test_no_provenance_with_identical_locks_says_no_differences(tmp_path):
    s = _surface([CapturedTool(name="t", input_schema={})])
    a = _write(tmp_path, "a.lock", s)
    b = _write(tmp_path, "b.lock", s)
    result = runner.invoke(app, ["diff", str(a), str(b), "--no-provenance"])
    assert result.exit_code == 0
    assert "no differences" in result.stdout
