"""Pre-call safety guardrails and deterministic prompt hashing for the Control Plane."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Literal

from platform_common import ChatCompletionRequest, ChatMessage, PolicyBundle, SafetyRule


@dataclass(frozen=True, slots=True)
class GuardrailDecision:
    """Outcome of pre-call safety guardrail evaluation for a chat completion request."""

    policy_action: Literal["allow", "redact", "deny"]
    triggered_rules: list[str]
    redacted_entity_types: list[str]
    sanitized_payload: ChatCompletionRequest
    prompt_sha256: str
    denied_rule_id: str | None = None


class GuardrailDeniedError(Exception):
    """Raised when a pre-call safety rule with action 'deny' rejects a prompt."""

    def __init__(self, decision: GuardrailDecision) -> None:
        rule_id = decision.denied_rule_id or (
            decision.triggered_rules[0] if decision.triggered_rules else "policy_violation"
        )
        super().__init__(f"Request denied by safety policy rule '{rule_id}'")
        self.decision = decision
        self.rule_id = rule_id
        self.message = f"Request denied by safety policy rule '{rule_id}'"
        self.error_type = "policy_violation"
        self.code = "prompt_denied"
        self.param = "messages"


@lru_cache(maxsize=256)
def _compile_rule_pattern(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _normalize_message(message: ChatMessage | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(message, ChatMessage):
        return message.model_dump(mode="json", exclude_none=True)
    return dict(message)


def compute_prompt_sha256(messages: Sequence[ChatMessage | Mapping[str, Any]]) -> str:
    """Compute a deterministic SHA-256 hex digest over canonical JSON of incoming messages."""
    normalized = [_normalize_message(message) for message in messages]
    canonical_json = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _append_unique(target: list[str], value: str | None) -> None:
    if value and value not in target:
        target.append(value)


def _apply_redact_rule(
    rule: SafetyRule,
    compiled: re.Pattern[str],
    contents: list[str],
) -> tuple[bool, str]:
    entity_type = rule.entity_type or "PII"
    replacement = rule.replacement or f"[REDACTED_{entity_type}]"
    matched = False
    for idx, text in enumerate(contents):
        updated, count = compiled.subn(lambda _match, repl=replacement: repl, text)
        if count > 0:
            contents[idx] = updated
            matched = True
    return matched, entity_type


def evaluate_guardrails(
    payload: ChatCompletionRequest,
    policy: PolicyBundle,
) -> GuardrailDecision:
    """Evaluate pre-call safety rules in Policy Bundle order across incoming messages."""
    prompt_sha256 = compute_prompt_sha256(payload.messages)
    original_contents = [message.content for message in payload.messages]
    working_contents = list(original_contents)

    deny_rules: list[str] = []
    deny_entity_types: list[str] = []
    redact_rules: list[str] = []
    redact_entity_types: list[str] = []

    for rule in policy.safety_rules:
        compiled = _compile_rule_pattern(rule.pattern)
        if rule.action == "deny":
            if any(compiled.search(content) for content in original_contents):
                _append_unique(deny_rules, rule.id)
                _append_unique(deny_entity_types, rule.entity_type)
            continue

        if deny_rules:
            continue

        matched, entity_type = _apply_redact_rule(rule, compiled, working_contents)
        if matched:
            _append_unique(redact_rules, rule.id)
            _append_unique(redact_entity_types, entity_type)

    if deny_rules:
        return GuardrailDecision(
            policy_action="deny",
            triggered_rules=deny_rules,
            redacted_entity_types=deny_entity_types,
            sanitized_payload=payload,
            prompt_sha256=prompt_sha256,
            denied_rule_id=deny_rules[0],
        )

    if redact_rules:
        sanitized_messages = [
            message.model_copy(update={"content": updated_content})
            for message, updated_content in zip(payload.messages, working_contents, strict=True)
        ]
        sanitized_payload = payload.model_copy(update={"messages": sanitized_messages})
        return GuardrailDecision(
            policy_action="redact",
            triggered_rules=redact_rules,
            redacted_entity_types=redact_entity_types,
            sanitized_payload=sanitized_payload,
            prompt_sha256=prompt_sha256,
        )

    return GuardrailDecision(
        policy_action="allow",
        triggered_rules=[],
        redacted_entity_types=[],
        sanitized_payload=payload,
        prompt_sha256=prompt_sha256,
    )
