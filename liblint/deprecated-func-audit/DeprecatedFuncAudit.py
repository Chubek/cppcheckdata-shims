#!/usr/bin/env python3
"""
DeprecatedFuncAudit.py — Cppcheck addon for auditing deprecated/unsafe C functions.

Detects use of functions with known security or correctness issues:
  - gets            : always unsafe (no bounds checking) [CWE-242]
  - strcpy          : unsafe string copy [CWE-120]
  - strcat          : unsafe string concatenation [CWE-120]
  - sprintf         : unsafe formatted output [CWE-120]
  - vsprintf        : unsafe formatted output [CWE-120]
  - scanf           : unsafe input without field width limit [CWE-120]
  - atoi            : no error detection, prefer strtol [CWE-190]
  - rand            : not suitable for cryptographic use [CWE-338]
  - system          : shell injection risk [CWE-78]
  - memcpy          : no overlap/bounds validation [CWE-120]

Usage:
  cppcheck --addon=DeprecatedFuncAudit path/to/src/
  cppcheck --dump file.c && python3 DeprecatedFuncAudit.py file.c.dump
"""

from __future__ import annotations

import sys
from typing import Any, ClassVar, Dict, FrozenSet, List, Optional

import cppcheckdata

from cppcheckdata_shims.checkers import (
    Checker,
    CheckerContext,
    CheckerRegistry,
    Diagnostic,
    DiagnosticSeverity,
    SourceLocation,
    SuppressionManager,
    _tok_str,
    _tok_file,
    _tok_line,
    _tok_col,
    _iter_tokens,
)

# ─────────────────────────────────────────────────────────────────────────
#  Helper: resolve a call-expression token to its function name
# ─────────────────────────────────────────────────────────────────────────

def _call_name(tok: Any) -> Optional[str]:
    """
    Given a '(' token that represents a function call, return the
    name of the called function, or None if it cannot be determined.
    """
    prev = getattr(tok, "previous", None)
    if prev is None:
        return None
    return _tok_str(prev) or None


def _is_call_token(tok: Any) -> bool:
    """Return True if tok is a '(' that opens a function call."""
    if _tok_str(tok) != "(":
        return True  # checked below
    # cppcheckdata marks function-call '(' with isExpandedMacro or we
    # inspect the AST: a call '(' has astOperand1 = function name token.
    op1 = getattr(tok, "astOperand1", None)
    if op1 is not None:
        return True
    return False


def _get_call_args(tok: Any) -> List[Any]:
    """
    Return a list of top-level argument tokens for a call '(' token.
    Walks the comma-separated astOperand2 chain.
    """
    args: List[Any] = []
    node = getattr(tok, "astOperand2", None)
    while node is not None:
        if _tok_str(node) == ",":
            # left child of comma is the next (or only) arg
            left = getattr(node, "astOperand1", None)
            if left is not None:
                args.append(left)
            node = getattr(node, "astOperand2", None)
        else:
            args.append(node)
            break
    return args


# ─────────────────────────────────────────────────────────────────────────
#  Base class for function-call checkers
# ─────────────────────────────────────────────────────────────────────────

class FuncCallChecker(Checker):
    """
    Abstract checker that fires once per call site of a target function.

    Subclasses set `target_functions` and override `check_call()`.
    """

    target_functions: ClassVar[FrozenSet[str]] = frozenset()

    def collect_evidence(self, ctx: CheckerContext) -> None:
        """Scan token list for calls to target functions."""
        for tok in _iter_tokens(ctx.cfg):
            if _tok_str(tok) != "(":
                continue
            name = _call_name(tok)
            if name and name in self.target_functions:
                self.check_call(tok, name, ctx)

    def diagnose(self, ctx: CheckerContext) -> None:
        # diagnostics already appended inside check_call → collect_evidence
        pass

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        """Called for every detected call site. Override in subclasses."""
        raise NotImplementedError


# ─────────────────────────────────────────────────────────────────────────
#  1. gets — always unsafe (CWE-242)
# ─────────────────────────────────────────────────────────────────────────

class GetsChecker(FuncCallChecker):
    """
    Detects calls to gets().

    gets() reads an unlimited number of bytes into the buffer, making
    buffer overflow unavoidable. It has been removed from C11.

    CWE-242: Use of Inherently Dangerous Function
    """

    name = "deprecated-gets"
    description = "Detects use of gets(), which is inherently unsafe"
    error_ids = frozenset({"getsUsed"})
    default_severity = DiagnosticSeverity.ERROR
    cwe_ids = {"getsUsed": 242}
    target_functions = frozenset({"gets"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="getsUsed",
            message=(
                "Call to 'gets' is always unsafe: no bounds checking is "
                "possible. Replace with fgets(buf, sizeof(buf), stdin)."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
            severity=DiagnosticSeverity.ERROR,
        )


# ─────────────────────────────────────────────────────────────────────────
#  2. strcpy — unsafe string copy (CWE-120)
# ─────────────────────────────────────────────────────────────────────────

class StrcpyChecker(FuncCallChecker):
    """
    Detects calls to strcpy().

    strcpy() does not check whether the destination buffer is large
    enough to hold the source string. Prefer strncpy() or strlcpy().

    CWE-120: Buffer Copy without Checking Size of Input
    """

    name = "deprecated-strcpy"
    description = "Detects unsafe use of strcpy()"
    error_ids = frozenset({"strcpyUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"strcpyUsed": 120}
    target_functions = frozenset({"strcpy"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="strcpyUsed",
            message=(
                "Call to 'strcpy' may overflow the destination buffer. "
                "Replace with strncpy(dst, src, sizeof(dst)-1) or strlcpy()."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  3. strcat — unsafe string concatenation (CWE-120)
# ─────────────────────────────────────────────────────────────────────────

class StrcatChecker(FuncCallChecker):
    """
    Detects calls to strcat().

    strcat() appends without bounds checking. Prefer strncat() or
    strlcat().

    CWE-120: Buffer Copy without Checking Size of Input
    """

    name = "deprecated-strcat"
    description = "Detects unsafe use of strcat()"
    error_ids = frozenset({"strcatUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"strcatUsed": 120}
    target_functions = frozenset({"strcat"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="strcatUsed",
            message=(
                "Call to 'strcat' may overflow the destination buffer. "
                "Replace with strncat(dst, src, sizeof(dst)-strlen(dst)-1) "
                "or strlcat()."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  4 & 5. sprintf / vsprintf — unsafe formatted output (CWE-120)
# ─────────────────────────────────────────────────────────────────────────

class SprintfChecker(FuncCallChecker):
    """
    Detects calls to sprintf() and vsprintf().

    Neither function limits the number of bytes written to the buffer.
    Prefer snprintf() / vsnprintf().

    CWE-120: Buffer Copy without Checking Size of Input
    """

    name = "deprecated-sprintf"
    description = "Detects unsafe use of sprintf() and vsprintf()"
    error_ids = frozenset({"sprintfUsed", "vsprintfUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"sprintfUsed": 120, "vsprintfUsed": 120}
    target_functions = frozenset({"sprintf", "vsprintf"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        eid = "sprintfUsed" if func_name == "sprintf" else "vsprintfUsed"
        safe = "snprintf" if func_name == "sprintf" else "vsnprintf"
        self._emit(
            error_id=eid,
            message=(
                f"Call to '{func_name}' does not limit output size. "
                f"Replace with {safe}(buf, sizeof(buf), ...)."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  6. scanf without field-width limit (CWE-120)
# ─────────────────────────────────────────────────────────────────────────

class ScanfChecker(FuncCallChecker):
    """
    Detects calls to scanf-family functions with a bare %s or %c
    format specifier (no field-width limit).

    When the format string is a literal, we inspect it; when it is
    dynamic we always warn (conservative).

    CWE-120: Buffer Copy without Checking Size of Input
    """

    name = "deprecated-scanf"
    description = "Detects scanf() calls with unbounded string format"
    error_ids = frozenset({"scanfNoLimit"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"scanfNoLimit": 120}
    target_functions = frozenset({
        "scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf",
    })

    # Index of the format string argument for each function
    _FORMAT_ARG_INDEX: ClassVar[Dict[str, int]] = {
        "scanf": 0, "vscanf": 0,
        "fscanf": 1, "vfscanf": 1,
        "sscanf": 1, "vsscanf": 1,
    }

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        args = _get_call_args(call_tok)
        fmt_idx = self._FORMAT_ARG_INDEX.get(func_name, 0)

        if fmt_idx >= len(args):
            # Cannot determine format argument; warn conservatively
            self._emit_warning(call_tok, func_name,
                               "format argument not found")
            return

        fmt_tok = args[fmt_idx]
        fmt_str = getattr(fmt_tok, "str", "") or ""

        # Strip surrounding quotes from string literal token
        if fmt_str.startswith('"') and fmt_str.endswith('"'):
            fmt_str = fmt_str[1:-1]
            # Check for bare %s or %c (no digit between % and s/c)
            import re
            if re.search(r'%[^0-9*][sc]|%[sc]', fmt_str):
                self._emit_warning(call_tok, func_name,
                                   "format string contains unbounded %s or %c")
        else:
            # Dynamic format string → always warn
            self._emit_warning(call_tok, func_name,
                               "dynamic or non-literal format string")

    def _emit_warning(self, call_tok: Any, func_name: str,
                      detail: str) -> None:
        self._emit(
            error_id="scanfNoLimit",
            message=(
                f"Call to '{func_name}' may overflow buffer: {detail}. "
                "Use a field-width specifier (e.g., %63s) or fgets()."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  7. atoi — no error detection (CWE-190)
# ─────────────────────────────────────────────────────────────────────────

class AtoiChecker(FuncCallChecker):
    """
    Detects calls to atoi(), atol(), and atoll().

    These functions provide no mechanism to detect overflow or invalid
    input. Prefer strtol() / strtoll() with errno checking.

    CWE-190: Integer Overflow or Wraparound
    """

    name = "deprecated-atoi"
    description = "Detects use of atoi/atol/atoll without error checking"
    error_ids = frozenset({"atoiUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"atoiUsed": 190}
    target_functions = frozenset({"atoi", "atol", "atoll"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="atoiUsed",
            message=(
                f"Call to '{func_name}' provides no overflow or error "
                "detection. Replace with strtol(str, &end, 10) and check "
                "errno and 'end'."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  8. rand — not suitable for cryptography (CWE-338)
# ─────────────────────────────────────────────────────────────────────────

class RandChecker(FuncCallChecker):
    """
    Detects calls to rand() and srand().

    The standard rand() PRNG is not cryptographically secure.
    Use /dev/urandom, getrandom(), or a CSPRNG for security-sensitive
    random values.

    CWE-338: Use of Cryptographically Weak PRNG
    """

    name = "deprecated-rand"
    description = "Detects use of non-cryptographic rand()"
    error_ids = frozenset({"randUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"randUsed": 338}
    target_functions = frozenset({"rand", "srand"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="randUsed",
            message=(
                f"Call to '{func_name}': the standard PRNG is not "
                "cryptographically secure. For security-sensitive use, "
                "replace with getrandom(), /dev/urandom, or a CSPRNG."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  9. system — shell injection (CWE-78)
# ─────────────────────────────────────────────────────────────────────────

class SystemChecker(FuncCallChecker):
    """
    Detects calls to system().

    system() passes its argument to the shell, creating a command
    injection risk if any part of the string is attacker-controlled.
    Prefer execv() / posix_spawn() with explicit argument lists.

    CWE-78: Improper Neutralization of Special Elements used in an
            OS Command ('OS Command Injection')
    """

    name = "deprecated-system"
    description = "Detects potentially unsafe use of system()"
    error_ids = frozenset({"systemUsed"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"systemUsed": 78}
    target_functions = frozenset({"system"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        self._emit(
            error_id="systemUsed",
            message=(
                "Call to 'system()' is susceptible to shell injection if the "
                "command string includes attacker-controlled data. Consider "
                "execv() or posix_spawn() with an explicit argument list."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  10. memcpy — no overlap/bounds validation (CWE-120)
# ─────────────────────────────────────────────────────────────────────────

class MemcpyChecker(FuncCallChecker):
    """
    Detects calls to memcpy() where the size argument cannot be
    statically verified to be within bounds.

    When the size argument is a literal constant we do not warn (the
    developer has chosen an explicit size). When it is dynamic (a
    variable or expression) we flag it for manual review.

    CWE-120: Buffer Copy without Checking Size of Input
    """

    name = "deprecated-memcpy"
    description = "Detects memcpy() calls with unvalidated size argument"
    error_ids = frozenset({"memcpyUnvalidated"})
    default_severity = DiagnosticSeverity.WARNING
    cwe_ids = {"memcpyUnvalidated": 120}
    target_functions = frozenset({"memcpy", "memmove"})

    def check_call(self, call_tok: Any, func_name: str,
                   ctx: CheckerContext) -> None:
        args = _get_call_args(call_tok)
        # memcpy(dst, src, size) — size is the third argument (index 2)
        if len(args) < 3:
            # Malformed call or macro; warn conservatively
            self._emit_warning(call_tok, func_name,
                               "could not determine size argument")
            return

        size_tok = args[2]
        # If the size token is an integer literal, assume the developer
        # has made an explicit choice and skip.
        if getattr(size_tok, "isNumber", False):
            return

        # Check ValueFlow: known constant value → skip
        for v in (getattr(size_tok, "values", None) or []):
            if getattr(v, "valueKind", "") == "known":
                return

        self._emit_warning(call_tok, func_name,
                           "size argument is not a compile-time constant")

    def _emit_warning(self, call_tok: Any, func_name: str,
                      detail: str) -> None:
        self._emit(
            error_id="memcpyUnvalidated",
            message=(
                f"Call to '{func_name}': {detail}. Ensure the size argument "
                "is validated against both source and destination buffer "
                "sizes before calling."
            ),
            file=_tok_file(call_tok),
            line=_tok_line(call_tok),
            column=_tok_col(call_tok),
        )


# ─────────────────────────────────────────────────────────────────────────
#  Registry
# ─────────────────────────────────────────────────────────────────────────

def _build_registry() -> CheckerRegistry:
    """Register and return all deprecated-function checkers."""
    registry = CheckerRegistry()
    for cls in (
        GetsChecker,
        StrcpyChecker,
        StrcatChecker,
        SprintfChecker,
        ScanfChecker,
        AtoiChecker,
        RandChecker,
        SystemChecker,
        MemcpyChecker,
    ):
        registry.register(cls)
    return registry


_REGISTRY = _build_registry()


# ─────────────────────────────────────────────────────────────────────────
#  Output helper
# ─────────────────────────────────────────────────────────────────────────

def _print_diagnostic(diag: Diagnostic) -> None:
    """
    Emit a Diagnostic in the standard Cppcheck addon format.

    - With --cli : JSON object to stdout (parsed by Cppcheck GUI/runner)
    - Without    : [file:line]: (severity) message [addon-errorId] to stderr
    """
    if "--cli" in sys.argv:
        import json
        msg: Dict[str, Any] = {
            "file": diag.location.file,
            "linenr": diag.location.line,
            "column": diag.location.column,
            "severity": diag.severity.value,
            "message": diag.message,
            "addon": diag.addon,
            "errorId": diag.error_id,
            "extra": diag.extra,
        }
        if diag.cwe:
            msg["cwe"] = diag.cwe
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()
    else:
        loc = f"[{diag.location.file}:{diag.location.line}]"
        sev = diag.severity.value
        text = diag.message
        if diag.extra:
            text += f" ({diag.extra})"
        eid = f"{diag.addon}-{diag.error_id}"
        sys.stderr.write(f"{loc}: ({sev}) {text} [{eid}]\n")
        sys.stderr.flush()


# ─────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────

def main() -> None:
    """Parse dump files and run all deprecated-function checkers."""
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()

    if not args.dumpfile:
        if not args.quiet:
            print("DeprecatedFuncAudit: no input files.", file=sys.stderr)
        sys.exit(0)

    checkers = [cls() for cls in _REGISTRY.get_enabled()]

    for dumpfile in args.dumpfile:
        if not args.quiet:
            print(f"Checking {dumpfile}...", file=sys.stderr)

        data = cppcheckdata.CppcheckData(dumpfile)

        for cfg in data.iterconfigurations():
            if not args.quiet:
                print(f"  Configuration: {cfg.name}", file=sys.stderr)

            # Build context
            sm = SuppressionManager()
            sm.load_inline_suppressions(cfg)
            ctx = CheckerContext(cfg=cfg, suppressions=sm)

            for checker in checkers:
                checker._diagnostics.clear()
                checker.configure(ctx)
                checker.collect_evidence(ctx)
                checker.diagnose(ctx)
                for diag in checker.report(ctx):
                    _print_diagnostic(diag)


if __name__ == "__main__":
    main()
