"""Schema adherence and hallucinated tool validator."""

from typing import Any

import jsonschema

from agentguard.evaluators.base import BaseEvaluator
from agentguard.models import AgentTrace, Finding, Severity


class SchemaValidator(BaseEvaluator):
    """Detects schema non-conformance, undeclared tools, and hallucinated arguments."""

    rule_id = "AG-001"
    rule_name = "Tool Schema Adherence"

    def __init__(self, tool_schemas: dict[str, dict[str, Any]] | None = None):
        """
        Args:
            tool_schemas: Dictionary mapping tool names to their JSON Schema definitions.
        """
        self.tool_schemas = tool_schemas or {}

    @staticmethod
    def validate_tool_schemas(tool_schemas: Any) -> None:
        """Reject schema maps that cannot be evaluated.

        Args:
            tool_schemas: The decoded contents of a schema file.

        Raises:
            TypeError: When the map is not a JSON object or a tool's definition
                is neither a JSON object nor a boolean.
            ValueError: When a tool name is empty, or when a tool's definition
                is not a valid JSON Schema.
        """
        if not isinstance(tool_schemas, dict):
            raise TypeError(
                "expected a JSON object mapping tool names to JSON Schemas, "
                f"got {type(tool_schemas).__name__}"
            )
        for tool_name, schema in tool_schemas.items():
            if not isinstance(tool_name, str) or not tool_name:
                raise ValueError(f"tool name {tool_name!r} is not a non-empty string")
            if not isinstance(schema, (dict, bool)):
                raise TypeError(
                    f"schema for tool '{tool_name}' must be a JSON object, "
                    f"got {type(schema).__name__}"
                )
            try:
                jsonschema.Draft7Validator.check_schema(schema)
            except jsonschema.exceptions.SchemaError as exc:
                raise ValueError(
                    f"schema for tool '{tool_name}' is not a valid JSON Schema: "
                    f"{exc.message}"
                ) from exc

    def register_schema(self, tool_name: str, schema: dict[str, Any]) -> None:
        """Register a JSON schema definition for a tool."""
        self.tool_schemas[tool_name] = schema

    def evaluate(self, trace: AgentTrace) -> list[Finding]:
        findings: list[Finding] = []

        if not self.tool_schemas:
            # If no schemas are configured, skip strict schema checks
            return findings

        for call in trace.tool_calls:
            # 1. Check if tool is known/declared
            if call.tool_name not in self.tool_schemas:
                findings.append(
                    Finding(
                        rule_id="AG-001-A",
                        rule_name=f"{self.rule_name}: Undeclared Tool",
                        severity=Severity.HIGH,
                        message=f"Agent invoked undeclared/hallucinated tool: '{call.tool_name}'",
                        step_id=call.step_id,
                        tool_name=call.tool_name,
                        details={"tool_name": call.tool_name},
                    )
                )
                continue

            schema = self.tool_schemas[call.tool_name]
            validator = jsonschema.Draft7Validator(schema)

            # 2. Check schema conformance
            errors = list(validator.iter_errors(call.arguments))
            for err in errors:
                findings.append(
                    Finding(
                        rule_id="AG-001-B",
                        rule_name=f"{self.rule_name}: Schema Drift",
                        severity=Severity.HIGH
                        if err.validator == "required"
                        else Severity.MEDIUM,
                        message=f"Tool '{call.tool_name}' argument error: {err.message}",
                        step_id=call.step_id,
                        tool_name=call.tool_name,
                        details={
                            "validator": err.validator,
                            "path": list(err.path),
                            "schema_path": list(err.schema_path),
                        },
                    )
                )

        return findings
