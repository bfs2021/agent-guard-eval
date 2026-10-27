"""Regression tests for SSRF URL authority classification."""

import pytest

from agentguard.evaluators.ssrf_guard import SSRFAndExfiltrationGuard
from agentguard.models import AgentTrace, Severity, ToolCall


def evaluate_url(url):
    trace = AgentTrace(
        session_id="ssrf-host-regression",
        tool_calls=[ToolCall(step_id=1, tool_name="fetch", arguments={"url": url})],
    )
    return SSRFAndExfiltrationGuard().evaluate(trace)


@pytest.mark.parametrize("url", [
    "https://example.com/docs/169.254.169.254",
    "https://example.com/?target=169.254.169.254",
    "https://example.com/#169.254.169.254",
    "http://169.254.169.254@example.com/",
    "https://169.254.169.254.example.com/",
    "https://metadata.google.internal.example.com/",
])
def test_metadata_text_outside_target_host_is_not_a_probe(url):
    assert evaluate_url(url) == []


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254./latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://METADATA.GOOGLE.INTERNAL.:80/computeMetadata/v1/",
    "http://metadata.platform.internal./",
    "http://example.com@169.254.169.254/",
])
def test_metadata_target_host_is_critical(url):
    findings = evaluate_url(url)
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-004-B"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].details["url"] == url


def test_absolute_localhost_name_is_still_flagged():
    findings = evaluate_url("http://LOCALHOST.:8080/admin")
    assert len(findings) == 1
    assert findings[0].rule_id == "AG-004-C"
