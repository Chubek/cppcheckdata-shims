#!/usr/bin/env python3
"""
FormatStringValidator.py

A Cppcheck addon that validates printf-style format strings by using the
cppcheckdata-shims infrastructure.  The checker inspects calls to
well-known printf-family functions, parses the format literal, and
verifies both argument count and (when type information is available)
argument categories.

Key shims integrations:
    • Checker framework (cppcheckdata_shims.checkers)
    • CFG construction (cppcheckdata_shims.ctrlflow_graph.CFGBuilder)
    • Optional type queries (cppcheckdata_shims.type_analysis.TypeAnalyzer)

The module also exposes helper functions consumed by the companion CASL
specification (FormatStringValidator.casl) so that both front-ends share
the same core logic.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

import cppcheckdata

from cppcheckdata_shims.checkers import (
    Checker,
    CheckerResult,
    CheckerRunner,
    Finding,
    Severity,
    register_checker,
)
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder
from cppcheckdata_shims.type_analysis import TypeAnalyzer

# ---------------------------------------------------------------------------
# Metadata describing printf-like functions we know how to handle.
# Each entry specifies the zero-based index of the format argument.
# ---------------------------------------------------------------------------

PRINTF_FAMILY: Dict[str, int] = {
    "printf": 0,
    "fprintf": 1,
    "sprintf": 1,
    "snprintf": 2,
    "dprintf": 1,
    "asprintf": 1,
    "sprintf_s": 1,
    "snprintf_s": 2,
    "fprintf_s": 1,
    "printf_s": 0,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "vdprintf": 1,
    "vasprintf": 1,
}

# ---------------------------------------------------------------------------
# Regular expression for parsing conversion specifiers.
# Groups:
#   flags, width, precision, length, conv
# ---------------------------------------------------------------------------

FORMAT_SPEC_RE = re.compile(
    r"""
    %
    (?P<percent>%)|
    %
    (?P<flags>[-+#0\ ']*)
    (?P<width>\*|\d+)?
    (?P<precision>\.(?:\*|\d+))?
    (?P<length>hh|h|ll|l|L|j|z|t)?
    (?P<conv>[diouxXfFeEgGaAcspn])
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Helper data structures shared by the Python checker and CASL front-end.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExpectedArgument:
    """Describes one abstract argument requirement derived from the format."""
    category: str            # e.g., "int", "unsigned", "double", "string", "pointer", ...
    description: str         # human readable description
    specifier: str           # the raw printf specifier that triggered this expectation
    position: int            # positional index among the format-driven arguments
    length_modifier: Optional[str] = None


@dataclass(frozen=True)
class CallArgument:
    """Wraps a call-site argument, pairing the original object with its primary token."""
    original: object
    token: Optional[cppcheckdata.Token]
    index: int


@dataclass
class FormatAnalysisIssue:
    """Represents a diagnostic discovered while checking a specific call."""
    kind: str                     # e.g., "count", "type", "format", "nonliteral"
    severity: Severity
    message: str
    error_id: str
    primary: Optional[cppcheckdata.Token] = None
    related: Sequence[Tuple[str, cppcheckdata.Token]] = ()


@dataclass
class FormatAnalysisReport:
    """Aggregate report for a call-site."""
    issues: List[FormatAnalysisIssue]


@dataclass
class CallInfo:
    """Canonical representation of a call-site for downstream analysis."""
    callee_name: str
    arguments: List[CallArgument]
    format_index: int
    call_token: Optional[cppcheckdata.Token]


# ---------------------------------------------------------------------------
# Core utilities (shared with CASL) -----------------------------------------
# ---------------------------------------------------------------------------


def is_printf_like_name(name: Optional[str]) -> bool:
    """Return True if the function name belongs to the printf family."""
    if not name:
        return False
    return name in PRINTF_FAMILY


def _guess_callee_name(call: object) -> Optional[str]:
    """Best-effort attempt to extract a callee name from various call-site representations."""
    if call is None:
        return None

    # Common shims CallSite structure
    if hasattr(call, "callee_name"):
        return getattr(call, "callee_name")
    if hasattr(call, "function") and getattr(call.function, "name", None):
        return call.function.name
    if hasattr(call, "callee") and getattr(call.callee, "name", None):
        return call.callee.name

    # Fallback: look at token
    token = getattr(call, "token", None)
    if token is not None:
        if getattr(token, "function", None) and getattr(token.function, "name", None):
            return token.function.name
        if token.str:
            return token.str

    return None


def _primary_token(obj: object) -> Optional[cppcheckdata.Token]:
    """Return a representative token for an argument/expression."""
    if isinstance(obj, cppcheckdata.Token):
        return obj

    # AST nodes often expose .token
    if hasattr(obj, "token") and isinstance(obj.token, cppcheckdata.Token):
        return obj.token

    # FunctionCallArgument wrapper?
    if hasattr(obj, "argument_token") and isinstance(obj.argument_token, cppcheckdata.Token):
        return obj.argument_token

    if hasattr(obj, "astToken") and isinstance(obj.astToken, cppcheckdata.Token):
        return obj.astToken

    return None


def extract_call_info(call: object) -> Optional[CallInfo]:
    """
    Convert an arbitrary call-site representation (token-level, AST node,
    or shims CallSite instance) into a CallInfo structure.
    """
    name = _guess_callee_name(call)
    if not is_printf_like_name(name):
        return None

    format_index = PRINTF_FAMILY[name]

    # Obtain argument collection in a broadly compatible way.
    raw_args: Iterable = ()
    if hasattr(call, "arguments"):
        raw_args = getattr(call, "arguments")
    elif hasattr(call, "args"):
        raw_args = getattr(call, "args")
    elif hasattr(call, "argumentTokens"):
        raw_args = getattr(call, "argumentTokens")
    elif hasattr(call, "call_arguments"):
        raw_args = getattr(call, "call_arguments")
    elif hasattr(call, "astArguments"):
        raw_args = getattr(call, "astArguments")
    else:
        # Some call representations attach arguments on the underlying token.
        token = getattr(call, "token", None)
        if token is not None and getattr(token, "astArguments", None):
            raw_args = token.astArguments

    args_list: List[CallArgument] = []
    for idx, arg in enumerate(list(raw_args)):
        args_list.append(CallArgument(original=arg, token=_primary_token(arg), index=idx))

    call_token = getattr(call, "token", None)
    if call_token is None and args_list:
        call_token = args_list[0].token

    if format_index >= len(args_list):
        # Degenerate call (insufficient arguments) — still return a CallInfo so that
        # the checker can warn about it.
        return CallInfo(
            callee_name=name,
            arguments=args_list,
            format_index=format_index,
            call_token=call_token,
        )

    return CallInfo(
        callee_name=name,
        arguments=args_list,
        format_index=format_index,
        call_token=call_token,
    )


def _unescape_c_string(literal: str) -> str:
    """Convert a C string literal (with quotes) to its runtime value."""
    body = literal
    if body.startswith('"') and body.endswith('"'):
        body = body[1:-1]
    try:
        return bytes(body, "utf-8").decode("unicode_escape")
    except Exception:
        # Fallback: return raw body if decoding fails.
        return body


def _string_literal_from_token(token: Optional[cppcheckdata.Token]) -> Optional[str]:
    """Extract literal contents from a token if it represents a string constant."""
    if token is None or token.str is None:
        return None
    text = token.str
    if text.startswith('"'):
        return _unescape_c_string(text)
    # In some dumps string literal tokens are aggregated across multiple tokens;
    # best effort detection.
    if getattr(token, "isString", False):
        return _unescape_c_string(text)
    return None


SPEC_KIND_MAP: Dict[str, str] = {
    "d": "int",
    "i": "int",
    "u": "unsigned",
    "o": "unsigned",
    "x": "unsigned",
    "X": "unsigned",
    "f": "double",
    "F": "double",
    "e": "double",
    "E": "double",
    "g": "double",
    "G": "double",
    "a": "double",
    "A": "double",
    "c": "char",
    "s": "string",
    "p": "pointer",
    "n": "pointer-int",
}


def expectations_from_format(fmt: str) -> List[ExpectedArgument]:
    """Parse a format string into a list of argument expectations."""
    expectations: List[ExpectedArgument] = []
    position = 0
    for match in FORMAT_SPEC_RE.finditer(fmt):
        if match.group("percent"):
            # Escaped percent "%%" — consumes no arguments.
            continue

        raw_spec = match.group(0)
        conv = match.group("conv")
        length = match.group("length")

        # Width "*" consumes an int.
        if match.group("width") == "*":
            expectations.append(
                ExpectedArgument(
                    category="int",
                    description=f"field width for {raw_spec}",
                    specifier="*",
                    position=position,
                )
            )
            position += 1

        precision = match.group("precision")
        if precision and "*" in precision:
            expectations.append(
                ExpectedArgument(
                    category="int",
                    description=f"precision for {raw_spec}",
                    specifier="*",
                    position=position,
                )
            )
            position += 1

        category = SPEC_KIND_MAP.get(conv, "unknown")
        if category != "unknown":
            expectations.append(
                ExpectedArgument(
                    category=category,
                    description=f"argument for {raw_spec}",
                    specifier=raw_spec,
                    position=position,
                    length_modifier=length,
                )
            )
        else:
            expectations.append(
                ExpectedArgument(
                    category="invalid",
                    description=f"unsupported format specifier {raw_spec}",
                    specifier=raw_spec,
                    position=position,
                )
            )
        position += 1

    return expectations


def classify_argument(arg: CallArgument, type_env: Optional[TypeAnalyzer]) -> str:
    """
    Attempt to classify an argument into coarse categories used for matching
    against format expectations.  This function integrates with the shims type
    analysis when available and falls back to syntactic heuristics otherwise.
    """
    expr = arg.original
    token = arg.token

    # Use shims type analysis if we can.
    if type_env is not None:
        try:
            tp = type_env.get_expr_type(expr if expr is not None else token)
        except Exception:
            tp = None
        if tp is not None:
            if hasattr(tp, "is_pointer") and tp.is_pointer():
                pointee = None
                if hasattr(tp, "pointee"):
                    try:
                        pointee = tp.pointee()
                    except Exception:
                        pointee = None
                if pointee is not None:
                    if hasattr(pointee, "is_char") and pointee.is_char():
                        return "string-pointer"
                return "pointer"
            if hasattr(tp, "is_floating") and tp.is_floating():
                return "floating"
            if hasattr(tp, "is_integral") and tp.is_integral():
                if hasattr(tp, "is_signed") and not tp.is_signed():
                    return "unsigned"
                return "integral"
            if hasattr(tp, "is_bool") and tp.is_bool():
                return "integral"
            if hasattr(tp, "is_char") and tp.is_char():
                return "char"
            if hasattr(tp, "is_enum") and tp.is_enum():
                return "integral"
            if hasattr(tp, "is_nullptr") and tp.is_nullptr():
                return "pointer"

    # Fallback heuristic based on token spelling.
    if token is not None and token.str:
        text = token.str
        if text.startswith('"'):
            return "string-literal"
        if text.startswith("'"):
            return "char-literal"
        if text.endswith("f") or "." in text or "e" in text.lower():
            try:
                float(text.rstrip("f"))
                return "floating"
            except ValueError:
                pass
        if text.isdigit() or (
            text.startswith(("-", "+")) and text[1:].isdigit()
        ):
            return "integral"
        if text.endswith("ull") or text.endswith("u") or text.endswith("UL"):
            return "unsigned"
        if text == "NULL" or text == "nullptr":
            return "pointer"

    return "unknown"


def argument_matches(expectation: ExpectedArgument, category: str) -> bool:
    """Decide whether an argument classification satisfies a format expectation."""
    if expectation.category == "int":
        return category in {"integral", "unsigned"}
    if expectation.category == "unsigned":
        return category in {"unsigned", "integral"}
    if expectation.category == "double":
        return category == "floating"
    if expectation.category == "string":
        return category in {"string-pointer", "pointer", "string-literal"}
    if expectation.category == "char":
        return category in {"char", "integral", "char-literal"}
    if expectation.category == "pointer":
        return category in {"pointer", "string-pointer"}
    if expectation.category == "pointer-int":
        return category in {"pointer"}
    if expectation.category == "invalid":
        # This represents a malformed specifier rather than a type mismatch.
        return False
    if expectation.category == "unknown":
        # Conservatively allow anything.
        return True
    return False


def analyze_format_call(
    call_info: CallInfo,
    type_env: Optional[TypeAnalyzer],
) -> FormatAnalysisReport:
    """
    Given a CallInfo, analyze the associated format string and arguments,
    producing a list of issues.
    """
    issues: List[FormatAnalysisIssue] = []
    args = call_info.arguments
    fmt_arg = args[call_info.format_index] if call_info.format_index < len(args) else None
    fmt_literal = _string_literal_from_token(fmt_arg.token if fmt_arg else None)

    if fmt_arg is None:
        issues.append(
            FormatAnalysisIssue(
                kind="count",
                severity=Severity.ERROR,
                message="Missing format argument",
                error_id="FormatStringMissingFormat",
                primary=call_info.call_token,
            )
        )
        return FormatAnalysisReport(issues=issues)

    if fmt_literal is None:
        issues.append(
            FormatAnalysisIssue(
                kind="nonliteral",
                severity=Severity.WARNING,
                message="Format string is not a compile-time literal; unable to validate arguments",
                error_id="FormatStringNonLiteral",
                primary=fmt_arg.token,
            )
        )
        return FormatAnalysisReport(issues=issues)

    expectations = expectations_from_format(fmt_literal)
    format_driven_args: List[CallArgument] = []
    for arg in args[call_info.format_index + 1 :]:
        format_driven_args.append(arg)

    if len(format_driven_args) < sum(1 for exp in expectations if exp.category != "invalid"):
        issues.append(
            FormatAnalysisIssue(
                kind="count",
                severity=Severity.ERROR,
                message=(
                    f"Format string expects at least {len(expectations)} argument(s) "
                    f"but {len(format_driven_args)} provided"
                ),
                error_id="FormatStringArgumentCount",
                primary=call_info.call_token,
                related=[("Format string here", fmt_arg.token)] if fmt_arg.token else (),
            )
        )
        return FormatAnalysisReport(issues=issues)

    if len(format_driven_args) > len(expectations):
        issues.append(
            FormatAnalysisIssue(
                kind="count",
                severity=Severity.WARNING,
                message=(
                    f"Format string uses {len(expectations)} placeholder(s) "
                    f"but {len(format_driven_args)} argument(s) supplied"
                ),
                error_id="FormatStringExtraArguments",
                primary=format_driven_args[len(expectations)].token
                if len(format_driven_args) > len(expectations)
                else call_info.call_token,
            )
        )

    for idx, expectation in enumerate(expectations):
        if idx >= len(format_driven_args):
            break
        arg = format_driven_args[idx]
        if expectation.category == "invalid":
            issues.append(
                FormatAnalysisIssue(
                    kind="format",
                    severity=Severity.ERROR,
                    message=f"Unsupported or invalid conversion specifier '{expectation.specifier}'",
                    error_id="FormatStringInvalidSpecifier",
                    primary=fmt_arg.token,
                )
            )
            continue

        category = classify_argument(arg, type_env)
        if category == "unknown":
            issues.append(
                FormatAnalysisIssue(
                    kind="type",
                    severity=Severity.INCONCLUSIVE,
                    message=(
                        f"Unable to prove that argument #{idx + 1} matches specifier "
                        f"{expectation.specifier}"
                    ),
                    error_id="FormatStringUnknownType",
                    primary=arg.token,
                )
            )
            continue

        if not argument_matches(expectation, category):
            issues.append(
                FormatAnalysisIssue(
                    kind="type",
                    severity=Severity.ERROR,
                    message=(
                        f"Format specifier {expectation.specifier} expects {expectation.category} "
                        f"argument, but argument #{idx + 1} looks like {category}"
                    ),
                    error_id="FormatStringTypeMismatch",
                    primary=arg.token,
                    related=[
                        ("Format string", fmt_arg.token),
                    ]
                    if fmt_arg.token
                    else (),
                )
            )

    return FormatAnalysisReport(issues=issues)


# ---------------------------------------------------------------------------
# Checker implementation ----------------------------------------------------
# ---------------------------------------------------------------------------


class FormatStringChecker(Checker):
    """Checker entry point registered with cppcheckdata_shims.checkers."""

    name = "format-string-validator"
    description = "Validate printf-style format strings"
    severity = Severity.ERROR

    def __init__(self) -> None:
        super().__init__()
        self._type_analyzer = TypeAnalyzer()

    # Exposed for CASL usage to share logic.
    analyze_format_call = staticmethod(analyze_format_call)
    extract_call_info = staticmethod(extract_call_info)

    def check(self, cfg, cfg_data) -> CheckerResult:
        """
        Called by the CheckerRunner once per function CFG.
        Iterates over call-sites, filters printf-family, and emits findings.
        """
        findings: List[Finding] = []

        # Analyze types once per CFG; shims TypeAnalyzer caches internally.
        try:
            type_env = self._type_analyzer.analyze(cfg)
        except Exception:
            type_env = None

        for call in self._iter_call_sites(cfg):
            call_info = extract_call_info(call)
            if not call_info:
                continue

            report = analyze_format_call(call_info, type_env)

            for issue in report.issues:
                finding = Finding(
                    token=issue.primary or call_info.call_token,
                    severity=issue.severity,
                    message=issue.message,
                    error_id=issue.error_id,
                    addon=self.name,
                    related=[{"message": msg, "token": tok} for msg, tok in issue.related],
                )
                findings.append(finding)

        return CheckerResult(findings=findings)

    # ------------------------------------------------------------------

    def _iter_call_sites(self, cfg) -> Iterable[object]:
        """
        Yield the call-site representations embedded in the CFG.  Different
        cfg implementations expose slightly different attributes; this helper
        normalizes them.
        """
        if hasattr(cfg, "call_sites"):
            yield from cfg.call_sites
            return
        if hasattr(cfg, "calls"):
            yield from cfg.calls
            return
        if hasattr(cfg, "blocks"):
            for block in cfg.blocks:
                if hasattr(block, "calls"):
                    yield from block.calls
        # Last resort: inspect tokens associated with the CFG.
        if hasattr(cfg, "tokens"):
            for token in cfg.tokens:
                if getattr(token, "functionCall", None):
                    yield token.functionCall


# ---------------------------------------------------------------------------
# CASL helper namespace -----------------------------------------------------
# ---------------------------------------------------------------------------


class CASLHelpers:
    """
    A minimal helper namespace that CASL rules can reference via ($$ "...").
    All functions are thin wrappers over the shared analysis routines.
    """

    @staticmethod
    def argument_count_ok(call: object) -> bool:
        info = extract_call_info(call)
        if not info:
            return True
        report = analyze_format_call(info, type_env=None)
        return not any(issue.kind == "count" for issue in report.issues)

    @staticmethod
    def has_type_mismatch(call: object) -> bool:
        info = extract_call_info(call)
        if not info:
            return False
        report = analyze_format_call(info, type_env=None)
        return any(issue.kind == "type" and issue.severity == Severity.ERROR for issue in report.issues)

    @staticmethod
    def uses_invalid_specifier(call: object) -> bool:
        info = extract_call_info(call)
        if not info:
            return False
        report = analyze_format_call(info, type_env=None)
        return any(issue.kind == "format" for issue in report.issues)

    @staticmethod
    def format_is_nonliteral(call: object) -> bool:
        info = extract_call_info(call)
        if not info:
            return False
        fmt_arg = (
            info.arguments[info.format_index]
            if info.format_index < len(info.arguments)
            else None
        )
        if fmt_arg is None:
            return True
        literal = _string_literal_from_token(fmt_arg.token)
        return literal is None


# ---------------------------------------------------------------------------
# Checker registration + addon entry point ---------------------------------
# ---------------------------------------------------------------------------


register_checker(FormatStringChecker)


def check(data: cppcheckdata.CppcheckData) -> None:
    """
    Entry point invoked by Cppcheck.  Builds CFGs once and dispatches to the
    CheckerRunner with our checker enabled.
    """
    builder = CFGBuilder()
    runner = CheckerRunner(
        checkers=[FormatStringChecker.name],
        cli_mode=("--cli" in sys.argv),
    )

    for cfg_data in data.configurations:
        cfgs = builder.build_all(cfg_data)
        runner.run_with_cfgs(cfg_data, cfgs)


if __name__ == "__main__":
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()
    data = cppcheckdata.parsedump(args.dumpfile)
    check(data)
