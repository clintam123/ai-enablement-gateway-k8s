"""Shared privacy-safe JSON Audit Event emitter."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from typing import Any

from platform_common.models import AuditEvent

AuditSink = Callable[[AuditEvent], Any] | list[AuditEvent]


class AuditEmitter:
    """Structured 1-line JSON logger and optional injectable Audit Event sink."""

    def __init__(
        self,
        audit_sink: AuditSink | None = None,
        *,
        logger_name: str = "platform_common.audit",
    ) -> None:
        self._audit_sink = audit_sink
        self._logger = logging.getLogger(logger_name)

    async def emit(self, event: AuditEvent) -> None:
        """Emit one privacy-safe JSON Audit Event to the audit logger and optional sink."""
        self._logger.info(event.model_dump_json())
        if self._audit_sink is None:
            return
        if isinstance(self._audit_sink, list):
            self._audit_sink.append(event)
            return
        result = self._audit_sink(event)
        if inspect.isawaitable(result):
            await result
