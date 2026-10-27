"""SSRF and internal cloud metadata probe evaluator for AI agent network calls."""

import ipaddress
import re
from typing import Any, ClassVar
from urllib.parse import urlparse

from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class SSRFAndExfiltrationGuard(BaseEvaluator):
    """Detects Server-Side Request Forgery (SSRF) and metadata service exfiltration attempts."""

    rule_id = "AG-004"
    rule_name = "SSRF & Cloud Metadata Exfiltration Guard"

    # Cloud Metadata endpoints (AWS IMDS, GCP metadata, Azure instance metadata)
    METADATA_HOSTS: ClassVar[set[str]] = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.platform.internal",
    }

    URL_REGEX: ClassVar[re.Pattern] = re.compile(
        r"(https?://[^\s\"'>]+|file://[^\s\"'>]+)",
        re.IGNORECASE,
    )

    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        findings: list[Finding] = []

        for call in trace.tool_calls:
            self._scan_for_ssrf(call.arguments, call.step_id, call.tool_name, findings)

        return findings

    def _scan_for_ssrf(
        self,
        obj: Any,
        step_id: int,
        tool_name: str,
        findings: list[Finding],
    ) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                self._scan_for_ssrf(v, step_id, tool_name, findings)
        elif isinstance(obj, list):
            for item in obj:
                self._scan_for_ssrf(item, step_id, tool_name, findings)
        elif isinstance(obj, str):
            matches = self.URL_REGEX.findall(obj)
            for raw_url in matches:
                self._check_url(raw_url, step_id, tool_name, findings)

    def _check_url(
        self,
        raw_url: str,
        step_id: int,
        tool_name: str,
        findings: list[Finding],
    ) -> None:
        try:
            parsed = urlparse(raw_url)
        except (ValueError, AttributeError):
            return

        scheme = (parsed.scheme or "").lower()
        # A final dot denotes an absolute DNS name and does not change its target.
        hostname = (parsed.hostname or "").lower().removesuffix(".")

        # 1. Local file URI exfiltration
        if scheme == "file":
            findings.append(
                Finding(
                    rule_id="AG-004-A",
                    rule_name=f"{self.rule_name}: File Protocol Exfiltration",
                    severity=Severity.HIGH,
                    message=f"Detected 'file://' scheme probing local system files: '{raw_url[:60]}'",
                    step_id=step_id,
                    tool_name=tool_name,
                    details={"url": raw_url},
                )
            )
            return

        # 2. Cloud Instance Metadata Service (IMDS) probes (AWS / GCP / Azure)
        if hostname in self.METADATA_HOSTS:
            findings.append(
                Finding(
                    rule_id="AG-004-B",
                    rule_name=f"{self.rule_name}: Cloud Metadata Probe (IMDS)",
                    severity=Severity.CRITICAL,
                    message=f"Detected SSRF probe targeting Cloud Instance Metadata (IMDS): '{raw_url}'",
                    step_id=step_id,
                    tool_name=tool_name,
                    details={"target_host": hostname, "url": raw_url},
                )
            )
            return

        # 3. Private / Loopback IP address check
        if hostname:
            if hostname in ("localhost", "0.0.0.0", "127.0.0.1", "::1"):
                findings.append(
                    Finding(
                        rule_id="AG-004-C",
                        rule_name=f"{self.rule_name}: Loopback SSRF Vector",
                        severity=Severity.HIGH,
                        message=f"Detected request targeting localhost/loopback interface: '{raw_url[:60]}'",
                        step_id=step_id,
                        tool_name=tool_name,
                        details={"hostname": hostname, "url": raw_url},
                    )
                )
                return

            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    findings.append(
                        Finding(
                            rule_id="AG-004-C",
                            rule_name=f"{self.rule_name}: Private Network SSRF Vector",
                            severity=Severity.HIGH,
                            message=f"Detected request targeting private/internal IP address '{hostname}': '{raw_url[:60]}'",
                            step_id=step_id,
                            tool_name=tool_name,
                            details={"ip": str(ip), "url": raw_url},
                        )
                    )
            except ValueError:
                # Not a literal IP, valid domain name
                pass
