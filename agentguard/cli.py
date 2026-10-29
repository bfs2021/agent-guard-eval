"""Command line interface for AgentGuard."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from agentguard.diff import (
    TraceDiffEngine,
    render_diff_console,
    render_diff_markdown,
)
from agentguard.engine import evaluate_trace, get_default_evaluators
from agentguard.evaluators.schema_validator import SchemaValidator
from agentguard.models import AgentTrace, Severity
from agentguard.redteam.fuzzer import AgentRedTeamFuzzer
from agentguard.reporters.console import render_console_report
from agentguard.reporters.html import render_html_report
from agentguard.reporters.junit import render_junit_report
from agentguard.reporters.sarif import render_sarif_report
from agentguard.sanitizer import AgentTraceSanitizer


@click.group()
@click.version_option(version="0.2.0", prog_name="agentguard")
def cli():
    """AgentGuard: Deterministic Security & Reliability Evaluation Framework for AI Agents."""


@cli.command("evaluate")
@click.argument(
    "trace_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["console", "junit", "sarif", "html"], case_sensitive=False),
    default="console",
    help="Output report format (default: console).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional file path to write the output report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["ANY", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
    default="ANY",
    help="Severity threshold to trigger non-zero exit code (default: ANY).",
)
@click.option(
    "--schema",
    "-s",
    "schema_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to JSON file with tool JSON schemas.",
)
def evaluate_cmd(
    trace_file: Path, report_format: str, output: Path, fail_on: str, schema_file: Path
):
    """Evaluate an agent execution trace against security and reliability rules."""
    try:
        with open(trace_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        trace = AgentTrace.model_validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        click.secho(f"Error parsing trace file '{trace_file}': {e}", fg="red", err=True)
        sys.exit(2)

    evaluators = get_default_evaluators()

    if schema_file:
        try:
            with open(schema_file, "r", encoding="utf-8") as f:
                schemas = json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeError) as e:
            click.secho(
                f"Error reading schema file '{schema_file}': {e}", fg="red", err=True
            )
            sys.exit(2)

        try:
            SchemaValidator.validate_tool_schemas(schemas)
        except (TypeError, ValueError) as e:
            click.secho(
                f"Invalid schema file '{schema_file}': {e}", fg="red", err=True
            )
            sys.exit(2)

        # Find and configure schema validator
        for ev in evaluators:
            if isinstance(ev, SchemaValidator):
                ev.tool_schemas = schemas

    result = evaluate_trace(trace, evaluators)

    # Format output
    if report_format == "console":
        if output:
            txt = render_console_report(result)
            output.write_text(txt, encoding="utf-8")
            click.echo(f"Report written to {output}")
        else:
            render_console_report(result, console=Console())
    elif report_format == "junit":
        xml_content = render_junit_report(result)
        if output:
            output.write_text(xml_content, encoding="utf-8")
            click.echo(f"JUnit XML written to {output}")
        else:
            click.echo(xml_content)
    elif report_format == "sarif":
        sarif_content = render_sarif_report(result)
        if output:
            output.write_text(sarif_content, encoding="utf-8")
            click.echo(f"SARIF JSON written to {output}")
        else:
            click.echo(sarif_content)
    elif report_format == "html":
        html_content = render_html_report(result, trace=trace)
        if output:
            output.write_text(html_content, encoding="utf-8")
            click.echo(f"Interactive HTML report written to {output}")
        else:
            click.echo(html_content)

    # Determine exit code based on --fail-on
    severity_order = {
        "ANY": [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
        "MEDIUM": [Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL],
        "HIGH": [Severity.HIGH, Severity.CRITICAL],
        "CRITICAL": [Severity.CRITICAL],
    }
    target_severities = set(severity_order.get(fail_on.upper(), severity_order["ANY"]))

    should_fail = any(f.severity in target_severities for f in result.findings)
    if should_fail:
        sys.exit(1)


@cli.command("fuzz")
@click.argument("prompt", type=str)
@click.option(
    "--tool", default="bash_execute", help="Target tool name hint for attacks."
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional file path to save generated adversarial test cases.",
)
def fuzz_cmd(prompt: str, tool: str, output: Path):
    """Generate red-team adversarial prompt injection and jailbreak test cases."""
    fuzzer = AgentRedTeamFuzzer()
    test_cases = fuzzer.generate_adversarial_prompts(prompt, tool_hint=tool)

    console = Console()
    console.print(
        f"[bold cyan]Generated {len(test_cases)} Adversarial Attack Test Cases[/bold cyan]\n"
    )

    for idx, tc in enumerate(test_cases, 1):
        console.print(
            f"[bold yellow]#{idx} [{tc.attack_category}] {tc.attack_name}[/bold yellow]"
        )
        console.print(f"  [dim]{tc.description}[/dim]")
        console.print(f"  [magenta]Payload:[/magenta] {tc.payload[:80]!r}...\n")

    if output:
        output.write_text(
            json.dumps([tc.model_dump() for tc in test_cases], indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Saved attack test suite to {output}[/green]")


@cli.command("sanitize")
@click.argument(
    "trace_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    required=True,
    help="Target file path to write the sanitized trace.",
)
@click.option(
    "--max-string-len",
    default=10000,
    type=int,
    help="Maximum byte length for strings before pruning.",
)
def sanitize_cmd(trace_file: Path, output: Path, max_string_len: int):
    """Sanitize an agent trace by redacting secrets and pruning bloated payloads."""
    try:
        with open(trace_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        trace = AgentTrace.model_validate(data)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        click.secho(f"Error parsing trace file '{trace_file}': {e}", fg="red", err=True)
        sys.exit(2)

    sanitizer = AgentTraceSanitizer(max_string_length=max_string_len)
    clean_trace, count = sanitizer.sanitize(trace)

    output.write_text(clean_trace.model_dump_json(indent=2), encoding="utf-8")

    console = Console()
    console.print(f"[bold green]✔ Sanitized trace written to {output}[/bold green]")
    console.print(f"  [cyan]Total Redactions Applied:[/cyan] [bold]{count}[/bold]")


@cli.command("diff")
@click.argument(
    "baseline_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.argument(
    "candidate_file", type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["console", "markdown"], case_sensitive=False),
    default="console",
    help="Output format (console or markdown).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Optional file path to write the diff report.",
)
def diff_cmd(
    baseline_file: Path, candidate_file: Path, report_format: str, output: Path | None
):
    """Compare baseline vs candidate traces for behavioral & security regressions."""
    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            base_data = json.load(f)
        baseline = AgentTrace.model_validate(base_data)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        click.secho(
            f"Error parsing baseline trace '{baseline_file}': {e}", fg="red", err=True
        )
        sys.exit(2)

    try:
        with open(candidate_file, "r", encoding="utf-8") as f:
            cand_data = json.load(f)
        candidate = AgentTrace.model_validate(cand_data)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        click.secho(
            f"Error parsing candidate trace '{candidate_file}': {e}", fg="red", err=True
        )
        sys.exit(2)

    engine = TraceDiffEngine()
    diff = engine.compare(baseline, candidate)

    if report_format == "markdown":
        md = render_diff_markdown(diff)
        if output:
            output.write_text(md, encoding="utf-8")
            click.echo(f"Saved diff report to {output}")
        else:
            click.echo(md)
    else:
        render_diff_console(diff)
        if output:
            # Also save markdown to file if output is specified
            output.write_text(render_diff_markdown(diff), encoding="utf-8")
            click.echo(f"Saved markdown diff report to {output}")

    if diff.verdict == "REGRESSED":
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
