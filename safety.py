"""Risk classification for high-permission GDB operations.

The policy is intentionally not a hard-deny policy. Risky operations return a
warning and may be executed when the caller explicitly retries with
``confirm=true``.
"""

from __future__ import annotations

import re

from config import MAX_MEMORY_DUMP_WITHOUT_CONFIRM, MAX_MEMORY_READ, MAX_MEMORY_WRITE, MAX_STEP_COUNT
from models import RiskAssessment, RiskLevel

Rule = tuple[re.Pattern[str], str]
_SPACE_RE = re.compile(r"\s+")
_MI_CONSOLE_RE = re.compile(r"^-interpreter-exec\s+console\s+(.+)$", re.IGNORECASE)


def _compile_rules(rules: tuple[tuple[str, str], ...]) -> tuple[Rule, ...]:
    """Compile risk rule regexes once at import time."""

    return tuple((re.compile(pattern), reason) for pattern, reason in rules)


_GDB_CRITICAL_RULES = _compile_rules(
    (
        (r"^shell\s+.*\brm\b", "shell rm can delete local files"),
        (r"^shell\s+.*\bdel\b", "shell del can delete local files"),
        (r"^shell\s+.*\bcurl\b", "shell curl can transfer data or fetch code"),
        (r"^shell\s+.*\bwget\b", "shell wget can transfer data or fetch code"),
        (r"^shell\s+.*\bpowershell\b", "shell powershell can execute arbitrary host commands"),
        (r"^shell\s+.*\bcmd\b", "shell cmd can execute arbitrary host commands"),
        (r"^shell\s+.*\bbash\s+-c\b", "shell bash -c can execute arbitrary host commands"),
        (r"^shell\s+.*\bsh\s+-c\b", "shell sh -c can execute arbitrary host commands"),
        (r"^(python|py|pi)\b.*\bimport\s+os\b", "GDB Python importing os can execute host-side operations"),
        (r"^(python|py|pi)\b.*\bimport\s+subprocess\b", "GDB Python importing subprocess can spawn processes"),
        (r"^(python|py|pi)\b.*\bexec\s*\(", "GDB Python exec can run arbitrary code"),
        (r"^(python|py|pi)\b.*\beval\s*\(", "GDB Python eval can run arbitrary code"),
        (r"^call\s+system\s*\(", "calling system() executes inferior-side shell commands"),
        (r"^call\s+execve\s*\(", "calling execve() can replace the inferior process image"),
        (r"^call\s+execl\s*\(", "calling execl() can replace the inferior process image"),
        (r"^call\s+popen\s*\(", "calling popen() can execute shell commands"),
    )
)

_GDB_HIGH_RULES = _compile_rules(
    (
        (
            r"^target\s+remote\b",
            "target remote will connect this GDB session to a remote gdbserver. "
            "Only use this for systems you own or are authorized to debug",
        ),
        (
            r"^target\s+extended-remote\b",
            "target extended-remote will connect this GDB session to a remote gdbserver "
            "and may run programs on the remote target",
        ),
        (r"^disconnect\b", "disconnect detaches this GDB session from the current remote target"),
        (r"^detach\b", "detach releases the current inferior and may leave it running"),
        (
            r"^set\s+remote\s+exec-file\b",
            "set remote exec-file controls what program extended-remote will run on the target",
        ),
        (r"^set\s+sysroot\b", "set sysroot changes where GDB loads remote target libraries and symbols from"),
        (r"^set\s+solib-search-path\b", "set solib-search-path changes shared-library symbol resolution"),
        (r"^shell\b", "GDB shell executes local host commands"),
        (r"^source\b", "source executes commands from a local file"),
        (r"^(python|py|pi)\b", "GDB Python can execute arbitrary debugger-side code"),
        (r"^dump\s+memory\b", "dump memory writes inferior memory to disk"),
        (r"^restore\b", "restore writes file contents into inferior memory"),
        (r"^set\s+logging\s+file\b", "set logging file writes debugger output to a selected path"),
        (r"^set\s+follow-fork-mode\b", "follow-fork-mode changes process control behavior"),
        (r"\bcall\s+system\s*\(", "calling system() executes inferior-side shell commands"),
        (r"^maintenance\b", "maintenance commands can alter internal GDB behavior"),
    )
)

_GDB_MEDIUM_RULES = _compile_rules(
    (
        (r"^set\s+\$[a-z0-9_]+\s*=", "writing registers changes inferior execution state"),
        (r"^set\s+\{[^}]+\}", "writing memory changes inferior execution state"),
        (r"^set\s+args\b", "changing inferior argv affects future runs"),
        (r"^set\s+environment\b", "changing inferior environment affects future runs"),
        (
            r"^set\s+architecture\b",
            "changing architecture affects disassembly, register layout, and target interpretation",
        ),
        (r"^file\b", "loading a new local symbol file changes the active debugging target"),
        (r"^symbol-file\b", "loading a new symbol file changes symbol resolution"),
        (r"^add-symbol-file\b", "adding symbols at an address changes symbol resolution"),
        (r"^call\b", "calling inferior functions can mutate program state"),
        (r"^(watch|rwatch|awatch)\b", "watchpoints can alter execution timing and stop behavior"),
        (r"^kill\b", "kill terminates the current inferior process"),
    )
)

_MI_CRITICAL_RULES = _compile_rules(
    (
        (
            r"^-interpreter-exec\b.*\bcall\s+(system|execve|execl|popen)\b",
            "calling process-spawning libc functions can execute commands",
        ),
        (r"^-interpreter-exec\b.*\bcall\s+system\b", "calling system() executes shell commands"),
    )
)

_MI_HIGH_RULES = _compile_rules(
    (
        (r"^-target-select\b", "target selection can attach to external or remote targets"),
        (r"^-target-download\b", "target download writes program data to a target"),
        (r"^-gdb-set\s+logging\s+file\b", "set logging file writes debugger output to disk"),
        (r"^-gdb-set\s+sysroot\b", "set sysroot changes where GDB loads remote target libraries and symbols from"),
        (r"^-gdb-set\s+solib-search-path\b", "set solib-search-path changes shared-library symbol resolution"),
        (
            r"^-gdb-set\s+remote\s+exec-file\b",
            "set remote exec-file controls what program extended-remote will run on the target",
        ),
        (
            r"^-interpreter-exec\b.*\b(shell|python|source|maintenance)\b",
            "interpreter-exec can run high-risk GDB commands",
        ),
    )
)

_MI_MEDIUM_RULES = _compile_rules(
    (
        (r"^-data-write-memory", "writing memory changes inferior execution state"),
        (r"^-data-write-register-values", "writing registers changes inferior execution state"),
        (r"^-gdb-set\b", "changing GDB settings may alter future execution"),
        (r"^-file-exec-and-symbols\b", "loading a local symbol file changes the active debugging target"),
        (r"^-file-symbol-file\b", "loading a symbol file changes symbol resolution"),
        (r"^-exec-abort\b", "aborting execution terminates inferior state"),
    )
)


def _norm(command: str) -> str:
    return _SPACE_RE.sub(" ", command.strip()).lower()


def _match_rule(command: str, rules: tuple[Rule, ...]) -> tuple[str, str] | None:
    """Return the first matching rule pattern and reason."""

    for pattern, reason in rules:
        if pattern.search(command):
            return pattern.pattern, reason
    return None


def _assessment_from_rules(
    *,
    normalized_command: str,
    original_command: str,
    level: RiskLevel,
    rules: tuple[Rule, ...],
) -> RiskAssessment | None:
    """Build a risk assessment if any rule at a level matches."""

    matched = _match_rule(normalized_command, rules)
    if not matched:
        return None
    pattern, reason = matched
    return RiskAssessment(level, build_warning(original_command, level, reason), pattern)


def build_warning(command: str, risk_level: str, reason: str) -> str:
    """Build a consistent warning for commands that require confirmation."""

    return f"{command} is {risk_level} risk: {reason}. Retry with confirm=true to execute."


def assess_gdb_command(command: str) -> RiskAssessment:
    """Classify a GDB CLI command by risk level without blocking it."""

    cmd = _norm(command)
    if not cmd:
        return RiskAssessment("low")

    for level, rules in (
        ("critical", _GDB_CRITICAL_RULES),
        ("high", _GDB_HIGH_RULES),
        ("medium", _GDB_MEDIUM_RULES),
    ):
        assessment = _assessment_from_rules(
            normalized_command=cmd,
            original_command=command,
            level=level,
            rules=rules,
        )
        if assessment:
            return assessment

    return RiskAssessment("low")


def assess_mi_command(mi_command: str) -> RiskAssessment:
    """Classify a raw GDB/MI command by risk level."""

    cmd = _norm(mi_command)
    if not cmd:
        return RiskAssessment("low")

    match = _MI_CONSOLE_RE.match(mi_command.strip())
    if match:
        embedded = match.group(1).strip()
        if len(embedded) >= 2 and embedded[0] == embedded[-1] and embedded[0] in {"'", '"'}:
            embedded = embedded[1:-1]
        return assess_gdb_command(embedded)

    for level, rules in (
        ("critical", _MI_CRITICAL_RULES),
        ("high", _MI_HIGH_RULES),
        ("medium", _MI_MEDIUM_RULES),
    ):
        assessment = _assessment_from_rules(
            normalized_command=cmd,
            original_command=mi_command,
            level=level,
            rules=rules,
        )
        if assessment:
            return assessment

    return RiskAssessment("low")


def assess_memory_action(action: str, size: int = 0) -> RiskAssessment:
    """Classify memory helper operations."""

    action_l = action.lower()
    if action_l == "write":
        reason = "writing memory changes inferior execution state"
        return RiskAssessment("medium", build_warning("memory write", "medium", reason), "memory.write")
    if action_l == "dump":
        level: RiskLevel = "high" if size > MAX_MEMORY_DUMP_WITHOUT_CONFIRM else "medium"
        reason = "dumping memory writes inferior memory to disk"
        return RiskAssessment(level, build_warning("memory dump", level, reason), "memory.dump")
    if action_l == "read" and size > MAX_MEMORY_READ:
        reason = f"reading more than {MAX_MEMORY_READ} bytes may be expensive"
        return RiskAssessment("medium", build_warning("memory read", "medium", reason), "memory.large_read")
    if action_l == "search" and size > MAX_MEMORY_READ:
        reason = f"searching more than {MAX_MEMORY_READ} bytes may be expensive"
        return RiskAssessment("medium", build_warning("memory search", "medium", reason), "memory.large_search")
    return RiskAssessment("low")


def assess_register_action(action: str) -> RiskAssessment:
    """Classify register helper operations."""

    if action.lower() == "write":
        reason = "writing registers changes inferior execution state"
        return RiskAssessment("medium", build_warning("register write", "medium", reason), "register.write")
    return RiskAssessment("low")


def assess_run_control(action: str, count: int) -> RiskAssessment:
    """Classify run-control operations."""

    action_l = action.lower()
    if count > MAX_STEP_COUNT:
        reason = f"count exceeds MAX_STEP_COUNT={MAX_STEP_COUNT}"
        return RiskAssessment(
            "medium",
            build_warning(f"run_control {action}", "medium", reason),
            "run_control.large_count",
        )
    if action_l in {"kill", "restart"}:
        reason = "this action terminates or restarts the inferior process"
        return RiskAssessment(
            "medium",
            build_warning(f"run_control {action_l}", "medium", reason),
            f"run_control.{action_l}",
        )
    return RiskAssessment("low")


def assess_elf_action(action: str) -> RiskAssessment:
    """ELF inspection actions are read-only by default."""

    return RiskAssessment("low")


def max_write_size_exceeded(size: int) -> bool:
    """Return whether a requested memory write exceeds the configured limit."""

    return size > MAX_MEMORY_WRITE
