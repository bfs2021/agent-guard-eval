"""Tests for AgentGuard CLI commands."""

from click.testing import CliRunner

from agentguard.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "agentguard" in result.output


def test_cli_evaluate_valid(tmp_path):
    trace_path = tmp_path / "valid.json"
    trace_path.write_text(
        """{
        "session_id": "test-valid",
        "agent_name": "agent",
        "tool_calls": [
            {"step_id": 1, "tool_name": "read", "arguments": {"file": "doc.txt"}}
        ]
    }""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["evaluate", str(trace_path)])
    assert result.exit_code == 0
    assert "PASSED" in result.output


def test_cli_evaluate_failure_and_junit_output(tmp_path):
    trace_path = tmp_path / "vuln.json"
    junit_path = tmp_path / "results.xml"
    trace_path.write_text(
        """{
        "session_id": "test-vuln",
        "agent_name": "agent",
        "tool_calls": [
            {"step_id": 1, "tool_name": "exec", "arguments": {"cmd": "rm -rf /"}}
        ]
    }""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "evaluate",
            str(trace_path),
            "--format",
            "junit",
            "-o",
            str(junit_path),
            "--fail-on",
            "CRITICAL",
        ],
    )
    assert result.exit_code == 1
    assert junit_path.exists()
    assert "<testsuite" in junit_path.read_text(encoding="utf-8")


def test_cli_evaluate_html_output(tmp_path):
    trace_path = tmp_path / "trace.json"
    html_path = tmp_path / "report.html"
    trace_path.write_text(
        """{
        "session_id": "test-html-cli",
        "agent_name": "agent",
        "tool_calls": [
            {"step_id": 1, "tool_name": "read", "arguments": {"file": "doc.txt"}}
        ]
    }""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["evaluate", str(trace_path), "--format", "html", "-o", str(html_path)],
    )
    assert result.exit_code == 0
    assert html_path.exists()
    assert "<!DOCTYPE html>" in html_path.read_text(encoding="utf-8")


def test_cli_fuzz(tmp_path):
    out_path = tmp_path / "attacks.json"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["fuzz", "Translate this text to Spanish", "-o", str(out_path)],
    )
    assert result.exit_code == 0
    assert out_path.exists()
    assert "System Override" in out_path.read_text(encoding="utf-8")


def test_cli_sanitize(tmp_path):
    trace_path = tmp_path / "raw.json"
    clean_path = tmp_path / "sanitized.json"
    trace_path.write_text(
        """{
        "session_id": "test-raw",
        "user_prompt": "My key is AKIA1234567890ABCDEF",
        "tool_calls": []
    }""",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["sanitize", str(trace_path), "-o", str(clean_path)],
    )
    assert result.exit_code == 0
    assert clean_path.exists()
    assert "[REDACTED:AWS_ACCESS_KEY]" in clean_path.read_text(encoding="utf-8")


FETCH_TRACE = """{
    "session_id": "test-schema",
    "agent_name": "agent",
    "tool_calls": [
        {"step_id": 1, "tool_name": "fetch", "arguments": {"url": "https://example.com"}}
    ]
}"""


def test_cli_evaluate_rejects_non_object_schema_map(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_text('["fetch"]', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 2
    assert "Invalid schema file" in result.output
    assert "JSON object" in result.output
    assert "Traceback" not in result.output


def test_cli_evaluate_rejects_scalar_schema_map(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_text('"fetch"', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 2
    assert "Invalid schema file" in result.output
    assert "Traceback" not in result.output


def test_cli_evaluate_rejects_non_object_tool_schema(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_text('{"fetch": 42}', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 2
    assert "Invalid schema file" in result.output
    assert "'fetch'" in result.output
    assert "Traceback" not in result.output


def test_cli_evaluate_rejects_invalid_tool_schema(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_text('{"fetch": {"type": 123}}', encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 2
    assert "Invalid schema file" in result.output
    assert "'fetch'" in result.output
    assert "not a valid JSON Schema" in result.output


def test_cli_evaluate_reports_undecodable_schema_file(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_bytes(b'{"fetch": "\xff\xfe"}')

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 2
    assert "Error reading schema file" in result.output
    assert str(schema_path) in result.output
    assert "Traceback" not in result.output


def test_cli_evaluate_accepts_valid_schema_map(tmp_path):
    trace_path = tmp_path / "trace.json"
    schema_path = tmp_path / "schemas.json"
    trace_path.write_text(FETCH_TRACE, encoding="utf-8")
    schema_path.write_text(
        '{"fetch": {"type": "object", "properties": {"url": {"type": "string"}}}}',
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        cli, ["evaluate", str(trace_path), "--schema", str(schema_path)]
    )
    assert result.exit_code == 0
    assert "PASSED" in result.output
