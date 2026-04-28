"""Shared data models and response helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

RiskLevel = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True)
class RiskAssessment:
    """Risk metadata for a GDB operation."""

    level: RiskLevel = "low"
    warning: str | None = None
    matched_rule: str | None = None

    @property
    def requires_confirmation(self) -> bool:
        return self.level in {"medium", "high", "critical"}

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_result(
    *,
    ok: bool,
    tool: str,
    action: str | None = None,
    risk_level: RiskLevel = "low",
    need_confirm: bool = False,
    executed_with_risk: bool = False,
    warning: str | None = None,
    data: dict[str, Any] | None = None,
    stdout: str = "",
    stderr: str = "",
    raw: Any | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Create the uniform JSON-serializable response used by every tool."""

    return {
        "ok": ok,
        "tool": tool,
        "action": action,
        "risk_level": risk_level,
        "need_confirm": need_confirm,
        "executed_with_risk": executed_with_risk,
        "warning": warning,
        "data": data or {},
        "stdout": stdout,
        "stderr": stderr,
        "raw": raw if raw is not None else {},
        "error": error,
    }


def confirmation_required_result(
    *,
    tool: str,
    action: str | None,
    command: str,
    assessment: RiskAssessment,
    suggested_extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a standard warning response for risky operations."""

    suggested_retry: dict[str, Any] = {"confirm": True}
    if command:
        suggested_retry["command"] = command
    if suggested_extra:
        suggested_retry.update(suggested_extra)

    return make_result(
        ok=False,
        tool=tool,
        action=action,
        risk_level=assessment.level,
        need_confirm=True,
        warning=assessment.warning,
        data={"suggested_retry": suggested_retry, "matched_rule": assessment.matched_rule},
    )

