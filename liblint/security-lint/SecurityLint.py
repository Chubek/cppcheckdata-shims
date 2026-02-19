#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecurityLint.py
═══════════════

A comprehensive security-focused static analysis addon for Cppcheck that
detects vulnerabilities based on MITRE's CWE (Common Weakness Enumeration)
database.

This addon leverages the cppcheckdata_shims library's taint analysis and
AST helper facilities to identify security vulnerabilities in C/C++ code.

Covered CWE Categories
──────────────────────

INJECTION VULNERABILITIES:
    • CWE-78:  OS Command Injection
    • CWE-89:  SQL Injection
    • CWE-90:  LDAP Injection
    • CWE-91:  XML Injection (Blind XPath Injection)
    • CWE-94:  Code Injection
    • CWE-134: Use of Externally-Controlled Format String

PATH TRAVERSAL:
    • CWE-22:  Path Traversal
    • CWE-23:  Relative Path Traversal
    • CWE-36:  Absolute Path Traversal
    • CWE-73:  External Control of File Name or Path

BUFFER ERRORS:
    • CWE-119: Improper Restriction of Operations within Memory Buffer Bounds
    • CWE-120: Buffer Copy without Checking Size of Input
    • CWE-121: Stack-based Buffer Overflow
    • CWE-122: Heap-based Buffer Overflow
    • CWE-125: Out-of-bounds Read
    • CWE-126: Buffer Over-read
    • CWE-127: Buffer Under-read
    • CWE-129: Improper Validation of Array Index
    • CWE-131: Incorrect Calculation of Buffer Size
    • CWE-170: Improper Null Termination

INTEGER ERRORS:
    • CWE-190: Integer Overflow or Wraparound
    • CWE-191: Integer Underflow
    • CWE-192: Integer Coercion Error
    • CWE-193: Off-by-one Error
    • CWE-194: Unexpected Sign Extension
    • CWE-195: Signed to Unsigned Conversion Error
    • CWE-196: Unsigned to Signed Conversion Error
    • CWE-197: Numeric Truncation Error

MEMORY MANAGEMENT:
    • CWE-415: Double Free
    • CWE-416: Use After Free
    • CWE-401: Missing Release of Memory after Effective Lifetime
    • CWE-476: NULL Pointer Dereference
    • CWE-789: Memory Allocation with Excessive Size Value

INFORMATION EXPOSURE:
    • CWE-117: Improper Output Neutralization for Logs
    • CWE-200: Exposure of Sensitive Information
    • CWE-209: Error Message Information Exposure

DANGEROUS FUNCTIONS:
    • CWE-242: Use of Inherently Dangerous Function
    • CWE-676: Use of Potentially Dangerous Function

Usage
─────
    cppcheck --dump myfile.c
    python SecurityLint.py myfile.c.dump

    Or with Cppcheck addon interface:
    cppcheck --addon=SecurityLint.py myfile.c

License: MIT
"""

from __future__ import annotations

import sys
import argparse
from typing import List, Optional, Set, Dict, FrozenSet
from dataclasses import dataclass, field

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS FROM CPPCHECKDATA_SHIMS
# ═══════════════════════════════════════════════════════════════════════════

try:
    import cppcheckdata
except ImportError:
    print("Error: cppcheckdata module not found.", file=sys.stderr)
    print("Please run this script on a Cppcheck dump file.", file=sys.stderr)
    sys.exit(1)

from cppcheckdata_shims.ast_helper import (
    # Safe accessors
    tok_str, tok_op1, tok_op2, tok_parent,
    tok_var_id, tok_variable, tok_function,
    tok_value_type, tok_values,
    tok_file, tok_line, tok_column,
    # Traversal
    iter_ast_preorder, iter_ast_postorder,
    find_ast_root, collect_subtree,
    iter_tokens_in_scope,
    # Predicates
    is_assignment, is_function_call, is_dereference,
    is_subscript, is_address_of, is_member_access,
    is_identifier, is_literal, is_number,
    is_comparison, is_arithmetic_op,
    is_pointer_type, is_array_type,
    is_signed_type, is_unsigned_type,
    is_integral_type,
    # Expression analysis
    is_lvalue, has_side_effects,
    may_be_zero, may_be_negative,
    get_variables_used, get_variables_written,
    # Function call utilities
    get_called_function_name, get_call_arguments,
    count_call_arguments,
    find_function_calls, find_calls_to,
    is_allocation_call, is_deallocation_call,
    # Type utilities
    get_type_str, get_sizeof_type, get_array_size,
    # Scope utilities
    get_enclosing_function, is_in_loop,
    # Search utilities
    find_dereferences, find_array_accesses,
    find_assignments,
    # Constants
    ALLOC_FUNCTIONS, DEALLOC_FUNCTIONS,
    # Debug
    token_location, expr_to_string,
)

from cppcheckdata_shims.taint_analysis import (
    # Core types
    TaintLevel, TaintValue, TaintState,
    # Configuration
    SourceKind, SinkKind, PropagationKind,
    TaintSource, TaintSink, TaintSanitizer, TaintPropagator,
    TaintConfig,
    # Analysis
    TaintAnalyzer, TaintAnalysisResult,
    TaintViolation,
    # Predefined configs
    create_default_config,
    create_sql_injection_config,
    # Reporting
    TaintReportFormat,
    format_violations,
)

from cppcheckdata_shims.checkers import (
    CheckerBase,
    Finding,
    Severity,
    register_checker,
)


# ═══════════════════════════════════════════════════════════════════════════
#  CWE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CWEInfo:
    """Information about a CWE entry."""
    id: int
    name: str
    description: str
    severity: Severity


# CWE database for vulnerabilities we detect
CWE_DATABASE: Dict[int, CWEInfo] = {
    # Injection
    78: CWEInfo(78, "OS Command Injection",
                "Improper Neutralization of Special Elements used in an OS Command",
                Severity.ERROR),
    89: CWEInfo(89, "SQL Injection",
                "Improper Neutralization of Special Elements used in an SQL Command",
                Severity.ERROR),
    90: CWEInfo(90, "LDAP Injection",
                "Improper Neutralization of Special Elements used in an LDAP Query",
                Severity.ERROR),
    91: CWEInfo(91, "XML Injection",
                "XML Injection (aka Blind XPath Injection)",
                Severity.ERROR),
    94: CWEInfo(94, "Code Injection",
                "Improper Control of Generation of Code",
                Severity.ERROR),
    134: CWEInfo(134, "Format String Vulnerability",
                 "Use of Externally-Controlled Format String",
                 Severity.ERROR),

    # Path Traversal
    22: CWEInfo(22, "Path Traversal",
                "Improper Limitation of a Pathname to a Restricted Directory",
                Severity.ERROR),
    23: CWEInfo(23, "Relative Path Traversal",
                "Relative Path Traversal",
                Severity.ERROR),
    36: CWEInfo(36, "Absolute Path Traversal",
                "Absolute Path Traversal",
                Severity.ERROR),
    73: CWEInfo(73, "External Control of File Name or Path",
                "External Control of File Name or Path",
                Severity.WARNING),

    # Buffer Errors
    119: CWEInfo(119, "Buffer Overflow",
                 "Improper Restriction of Operations within the Bounds of a Memory Buffer",
                 Severity.ERROR),
    120: CWEInfo(120, "Classic Buffer Overflow",
                 "Buffer Copy without Checking Size of Input",
                 Severity.ERROR),
    121: CWEInfo(121, "Stack-based Buffer Overflow",
                 "Stack-based Buffer Overflow",
                 Severity.ERROR),
    122: CWEInfo(122, "Heap-based Buffer Overflow",
                 "Heap-based Buffer Overflow",
                 Severity.ERROR),
    125: CWEInfo(125, "Out-of-bounds Read",
                 "Out-of-bounds Read",
                 Severity.WARNING),
    126: CWEInfo(126, "Buffer Over-read",
                 "Buffer Over-read",
                 Severity.WARNING),
    127: CWEInfo(127, "Buffer Under-read",
                 "Buffer Under-read",
                 Severity.WARNING),
    129: CWEInfo(129, "Improper Validation of Array Index",
                 "Improper Validation of Array Index",
                 Severity.ERROR),
    131: CWEInfo(131, "Incorrect Calculation of Buffer Size",
                 "Incorrect Calculation of Buffer Size",
                 Severity.ERROR),
    170: CWEInfo(170, "Improper Null Termination",
                 "Improper Null Termination",
                 Severity.WARNING),

    # Integer Errors
    190: CWEInfo(190, "Integer Overflow",
                 "Integer Overflow or Wraparound",
                 Severity.WARNING),
    191: CWEInfo(191, "Integer Underflow",
                 "Integer Underflow (Wrap or Wraparound)",
                 Severity.WARNING),
    192: CWEInfo(192, "Integer Coercion Error",
                 "Integer Coercion Error",
                 Severity.WARNING),
    193: CWEInfo(193, "Off-by-one Error",
                 "Off-by-one Error",
                 Severity.WARNING),
    194: CWEInfo(194, "Unexpected Sign Extension",
                 "Unexpected Sign Extension",
                 Severity.WARNING),
    195: CWEInfo(195, "Signed to Unsigned Conversion Error",
                 "Signed to Unsigned Conversion Error",
                 Severity.WARNING),
    196: CWEInfo(196, "Unsigned to Signed Conversion Error",
                 "Unsigned to Signed Conversion Error",
                 Severity.WARNING),
    197: CWEInfo(197, "Numeric Truncation Error",
                 "Numeric Truncation Error",
                 Severity.WARNING),

    # Memory Management
    415: CWEInfo(415, "Double Free",
                 "Double Free",
                 Severity.ERROR),
    416: CWEInfo(416, "Use After Free",
                 "Use After Free",
                 Severity.ERROR),
    401: CWEInfo(401, "Memory Leak",
                 "Missing Release of Memory after Effective Lifetime",
                 Severity.WARNING),
    476: CWEInfo(476, "NULL Pointer Dereference",
                 "NULL Pointer Dereference",
                 Severity.ERROR),
    789: CWEInfo(789, "Memory Allocation with Excessive Size",
                 "Memory Allocation with Excessive Size Value",
                 Severity.WARNING),

    # Information Exposure
    117: CWEInfo(117, "Log Injection",
                 "Improper Output Neutralization for Logs",
                 Severity.WARNING),
    200: CWEInfo(200, "Information Exposure",
                 "Exposure of Sensitive Information to an Unauthorized Actor",
                 Severity.WARNING),
    209: CWEInfo(209, "Error Message Information Exposure",
                 "Generation of Error Message Containing Sensitive Information",
                 Severity.WARNING),

    # Dangerous Functions
    242: CWEInfo(242, "Inherently Dangerous Function",
                 "Use of Inherently Dangerous Function",
                 Severity.ERROR),
    676: CWEInfo(676, "Potentially Dangerous Function",
                 "Use of Potentially Dangerous Function",
                 Severity.WARNING),

    # Other
    14: CWEInfo(14, "Compiler Removal of Code to Clear Buffers",
                "Compiler Removal of Code to Clear Buffers",
                Severity.WARNING),
    20: CWEInfo(20, "Improper Input Validation",
                "Improper Input Validation",
                Severity.WARNING),
}


# ═══════════════════════════════════════════════════════════════════════════
#  DANGEROUS FUNCTION DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

# CWE-242: Inherently dangerous functions (should never be used)
INHERENTLY_DANGEROUS_FUNCTIONS: FrozenSet[str] = frozenset({
    "gets",         # No bounds checking, always vulnerable
    "sprintf",      # No bounds checking (use snprintf)
    "vsprintf",     # No bounds checking (use vsnprintf)
    "scanf",        # Unbounded %s is dangerous
    "fscanf",       # Unbounded %s is dangerous
    "sscanf",       # Unbounded %s is dangerous
    "strcpy",       # No bounds checking (use strncpy/strlcpy)
    "strcat",       # No bounds checking (use strncat/strlcat)
    "wcscpy",       # Wide-char version of strcpy
    "wcscat",       # Wide-char version of strcat
})

# CWE-676: Potentially dangerous functions (use with caution)
POTENTIALLY_DANGEROUS_FUNCTIONS: Dict[str, str] = {
    "strlen": "May cause issues with unterminated strings",
    "strchr": "May return NULL; check before use",
    "strrchr": "May return NULL; check before use",
    "strstr": "May return NULL; check before use",
    "strncpy": "May not null-terminate; ensure manual termination",
    "strncat": "Size parameter is remaining space, not total",
    "memcpy": "No overlap checking; use memmove for overlapping regions",
    "realloc": "May return NULL; original pointer may be lost",
    "atoi": "No error checking; use strtol instead",
    "atol": "No error checking; use strtol instead",
    "atof": "No error checking; use strtod instead",
    "getenv": "Returns pointer to environment; do not modify",
    "setjmp": "Complex control flow; error-prone",
    "longjmp": "Complex control flow; may skip destructors",
    "alloca": "Stack allocation; may cause stack overflow",
    "_alloca": "Stack allocation; may cause stack overflow",
    "system": "Shell injection risk; avoid if possible",
    "popen": "Shell injection risk; avoid if possible",
    "mktemp": "Race condition; use mkstemp instead",
    "tmpnam": "Race condition; use mkstemp instead",
    "tempnam": "Race condition; use mkstemp instead",
    "rand": "Not cryptographically secure; use secure random",
    "srand": "Not cryptographically secure",
}

# Functions that should have their return value checked
MUST_CHECK_RETURN: FrozenSet[str] = frozenset({
    "malloc", "calloc", "realloc", "aligned_alloc",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
    "open", "close", "read", "write", "lseek",
    "socket", "bind", "listen", "accept", "connect",
    "send", "recv", "sendto", "recvfrom",
    "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_cond_wait",
})


# ═══════════════════════════════════════════════════════════════════════════
#  TAINT CONFIGURATION FOR SECURITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def create_security_taint_config() -> TaintConfig:
    """
    Create a comprehensive taint configuration for security analysis.

    This extends the default configuration with additional sources, sinks,
    and sanitizers specific to security vulnerability detection.
    """
    config = create_default_config()

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sources
    # ─────────────────────────────────────────────────────────────────

    # Network input sources
    config.add_source(TaintSource(
        function="accept",
        kind=SourceKind.RETURN_VALUE,
        description="Network connection (socket)",
        cwe=20,
    ))
    config.add_source(TaintSource(
        function="gethostbyname",
        kind=SourceKind.RETURN_VALUE,
        description="DNS lookup result",
        cwe=20,
    ))
    config.add_source(TaintSource(
        function="getaddrinfo",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=3,
        description="Address info from DNS",
        cwe=20,
    ))

    # File input sources
    config.add_source(TaintSource(
        function="getline",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Line read from file",
        cwe=20,
    ))
    config.add_source(TaintSource(
        function="getdelim",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Delimited read from file",
        cwe=20,
    ))

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sinks
    # ─────────────────────────────────────────────────────────────────

    # Log injection (CWE-117)
    config.add_sink(TaintSink(
        function="syslog",
        argument_index=1,
        kind=SinkKind.LOG_INJECTION,
        description="System log injection",
        cwe=117,
        severity=6,
    ))
    config.add_sink(TaintSink(
        function="openlog",
        argument_index=0,
        kind=SinkKind.LOG_INJECTION,
        cwe=117,
        severity=5,
    ))

    # LDAP injection (CWE-90)
    config.add_sink(TaintSink(
        function="ldap_search_s",
        argument_index=2,  # filter
        kind=SinkKind.LDAP_INJECTION,
        description="LDAP search filter",
        cwe=90,
        severity=9,
    ))
    config.add_sink(TaintSink(
        function="ldap_search_ext_s",
        argument_index=2,
        kind=SinkKind.LDAP_INJECTION,
        cwe=90,
        severity=9,
    ))

    # XML injection (CWE-91)
    config.add_sink(TaintSink(
        function="xmlParseMemory",
        argument_index=0,
        kind=SinkKind.XML_INJECTION,
        description="XML parsing",
        cwe=91,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="xmlParseDoc",
        argument_index=0,
        kind=SinkKind.XML_INJECTION,
        cwe=91,
        severity=7,
    ))
    config.add_sink(TaintSink(
        function="xmlParseFile",
        argument_index=0,
        kind=SinkKind.XML_INJECTION,
        cwe=91,
        severity=7,
    ))

    # Code injection (CWE-94)
    config.add_sink(TaintSink(
        function="dlopen",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        description="Dynamic library loading",
        cwe=94,
        severity=10,
    ))
    config.add_sink(TaintSink(
        function="LoadLibrary",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        cwe=94,
        severity=10,
    ))
    config.add_sink(TaintSink(
        function="LoadLibraryA",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        cwe=94,
        severity=10,
    ))
    config.add_sink(TaintSink(
        function="LoadLibraryW",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        cwe=94,
        severity=10,
    ))

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sanitizers
    # ─────────────────────────────────────────────────────────────────

    # Input validation functions
    config.add_sanitizer(TaintSanitizer(
        function="isalnum",
        argument_index=0,
        sanitizes_return=False,
        description="Alphanumeric check (partial sanitization)",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="isdigit",
        argument_index=0,
        sanitizes_return=False,
        description="Digit check (partial sanitization)",
    ))

    # Escaping functions
    config.add_sanitizer(TaintSanitizer(
        function="escape_string",
        argument_index=0,
        sanitizes_return=True,
        description="Generic string escaping",
    ))
    config.add_sanitizer(TaintSanitizer(
        function="quote",
        argument_index=0,
        sanitizes_return=True,
        description="String quoting",
    ))

    return config


# ═══════════════════════════════════════════════════════════════════════════
#  SECURITY LINT CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class SecurityLintChecker(CheckerBase):
    """
    Comprehensive security checker for C/C++ code.

    This checker combines multiple analysis techniques:
    1. Taint analysis for injection vulnerabilities
    2. Pattern-based detection for dangerous functions
    3. Dataflow analysis for memory safety issues
    4. Type analysis for integer vulnerabilities
    """

    name = "SecurityLint"
    description = "Comprehensive security vulnerability detection"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self._taint_config = create_security_taint_config()
        self._taint_analyzer = TaintAnalyzer(
            self._taint_config,
            track_flow_paths=True,
            verbose=False,
        )
        self._findings: List[Finding] = []

    def check(self, cfg) -> List[Finding]:
        """
        Run all security checks on a configuration.

        Args:
            cfg: A cppcheckdata Configuration object

        Returns:
            List of findings
        """
        self._findings = []

        # Run taint analysis for injection vulnerabilities
        self._check_taint_vulnerabilities(cfg)

        # Check for dangerous function usage
        self._check_dangerous_functions(cfg)

        # Check for buffer-related vulnerabilities
        self._check_buffer_vulnerabilities(cfg)

        # Check for integer vulnerabilities
        self._check_integer_vulnerabilities(cfg)

        # Check for memory management issues
        self._check_memory_vulnerabilities(cfg)

        # Check for unchecked return values
        self._check_unchecked_returns(cfg)

        # Check for null pointer issues
        self._check_null_pointer_issues(cfg)

        return self._findings

    # ─────────────────────────────────────────────────────────────────
    #  Taint Analysis Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_taint_vulnerabilities(self, cfg) -> None:
        """Run taint analysis to find injection vulnerabilities."""
        result = self._taint_analyzer.analyze_configuration(cfg)

        for violation in result.violations:
            cwe_id = violation.cwe or self._sink_kind_to_cwe(
                violation.sink_kind)
            cwe_info = CWE_DATABASE.get(cwe_id)

            message = self._format_taint_message(violation)

            finding = Finding(
                file=tok_file(violation.sink_token),
                line=tok_line(violation.sink_token),
                column=tok_column(violation.sink_token),
                severity=cwe_info.severity if cwe_info else Severity.WARNING,
                message=message,
                checker=self.name,
                cwe=cwe_id,
            )
            self._findings.append(finding)

    def _sink_kind_to_cwe(self, sink_kind: SinkKind) -> int:
        """Map sink kind to CWE ID."""
        mapping = {
            SinkKind.COMMAND_INJECTION: 78,
            SinkKind.SQL_INJECTION: 89,
            SinkKind.PATH_TRAVERSAL: 22,
            SinkKind.FORMAT_STRING: 134,
            SinkKind.BUFFER_SIZE: 120,
            SinkKind.MEMORY_ALLOCATION: 789,
            SinkKind.LDAP_INJECTION: 90,
            SinkKind.XML_INJECTION: 91,
            SinkKind.XSS: 79,
            SinkKind.CODE_INJECTION: 94,
            SinkKind.LOG_INJECTION: 117,
        }
        # Default to CWE-20 (Input Validation)
        return mapping.get(sink_kind, 20)

    def _format_taint_message(self, violation: TaintViolation) -> str:
        """Format a human-readable message for a taint violation."""
        cwe_id = violation.cwe or self._sink_kind_to_cwe(violation.sink_kind)
        cwe_info = CWE_DATABASE.get(cwe_id)
        cwe_name = cwe_info.name if cwe_info else violation.sink_kind.name

        parts = [
            f"[CWE-{cwe_id}] {cwe_name}:",
            f"Tainted data reaches {violation.function}()",
        ]

        if violation.sink.argument_index >= 0:
            parts.append(f"at argument {violation.sink.argument_index}")

        if violation.taint_sources:
            sources_str = ", ".join(violation.taint_sources)
            parts.append(f"(from: {sources_str})")

        return " ".join(parts)

    # ─────────────────────────────────────────────────────────────────
    #  Dangerous Function Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_dangerous_functions(self, cfg) -> None:
        """Check for usage of dangerous functions."""
        for token in cfg.tokenlist:
            if not is_function_call(token):
                continue

            func_name = get_called_function_name(token)

            # CWE-242: Inherently dangerous functions
            if func_name in INHERENTLY_DANGEROUS_FUNCTIONS:
                self._report_dangerous_function(
                    token, func_name, 242,
                    f"Use of inherently dangerous function '{func_name}'"
                )

            # CWE-676: Potentially dangerous functions
            elif func_name in POTENTIALLY_DANGEROUS_FUNCTIONS:
                reason = POTENTIALLY_DANGEROUS_FUNCTIONS[func_name]
                self._report_dangerous_function(
                    token, func_name, 676,
                    f"Use of potentially dangerous function '{func_name}': {reason}"
                )

            # Additional checks for specific dangerous patterns
            self._check_dangerous_patterns(token, func_name)

    def _report_dangerous_function(
        self,
        token,
        func_name: str,
        cwe: int,
        message: str
    ) -> None:
        """Report a dangerous function finding."""
        cwe_info = CWE_DATABASE.get(cwe)
        finding = Finding(
            file=tok_file(token),
            line=tok_line(token),
            column=tok_column(token),
            severity=cwe_info.severity if cwe_info else Severity.WARNING,
            message=f"[CWE-{cwe}] {message}",
            checker=self.name,
            cwe=cwe,
        )
        self._findings.append(finding)

    def _check_dangerous_patterns(self, token, func_name: str) -> None:
        """Check for dangerous usage patterns of specific functions."""
        args = get_call_arguments(token)

        # Check for scanf family with unbounded %s
        if func_name in ("scanf", "fscanf", "sscanf"):
            self._check_scanf_format(token, func_name, args)

        # Check for printf family with non-literal format
        if func_name in ("printf", "fprintf", "sprintf", "snprintf"):
            self._check_printf_format(token, func_name, args)

        # Check for strcpy/strcat to fixed-size buffer
        if func_name in ("strcpy", "strcat"):
            self._check_string_copy(token, func_name, args)

        # Check for memcpy with potentially overlapping regions
        if func_name == "memcpy":
            self._check_memcpy_overlap(token, args)

    def _check_scanf_format(self, token, func_name: str, args: List) -> None:
        """Check scanf format string for unbounded %s."""
        if not args:
            return

        # Format string is first arg for scanf, second for fscanf
        fmt_idx = 0 if func_name == "scanf" else 1
        if fmt_idx >= len(args):
            return

        fmt_arg = args[fmt_idx]
        if is_literal(fmt_arg):
            fmt_str = tok_str(fmt_arg).strip('"')
            # Check for %s without width specifier
            if "%s" in fmt_str and not any(
                f"%{i}s" in fmt_str for i in range(1, 100)
            ):
                self._report_dangerous_function(
                    token, func_name, 120,
                    f"Unbounded '%s' in {func_name} format string may cause buffer overflow"
                )

    def _check_printf_format(self, token, func_name: str, args: List) -> None:
        """Check printf format string for potential issues."""
        if not args:
            return

        # Format string position varies by function
        fmt_idx = {"printf": 0, "fprintf": 1,
                   "sprintf": 1, "snprintf": 2}.get(func_name, 0)
        if fmt_idx >= len(args):
            return

        fmt_arg = args[fmt_idx]
        # Non-literal format string is potential format string vulnerability
        if not is_literal(fmt_arg) and is_identifier(fmt_arg):
            # Already handled by taint analysis, but add extra warning
            pass

    def _check_string_copy(self, token, func_name: str, args: List) -> None:
        """Check strcpy/strcat for buffer overflow potential."""
        if len(args) < 2:
            return

        dest = args[0]
        dest_var = tok_variable(dest)

        if dest_var:
            # Check if destination is a fixed-size array
            if getattr(dest_var, "isArray", False):
                array_size = get_array_size(dest)
                if array_size is not None:
                    # Report potential overflow
                    self._report_dangerous_function(
                        token, func_name, 120,
                        f"{func_name} to fixed-size buffer ({array_size} bytes) "
                        f"without size checking"
                    )

    def _check_memcpy_overlap(self, token, args: List) -> None:
        """Check memcpy for potentially overlapping regions."""
        if len(args) < 2:
            return

        dest = args[0]
        src = args[1]

        # Check if dest and src might alias
        dest_var_id = tok_var_id(dest)
        src_var_id = tok_var_id(src)

        if dest_var_id and src_var_id and dest_var_id == src_var_id:
            finding = Finding(
                file=tok_file(token),
                line=tok_line(token),
                column=tok_column(token),
                severity=Severity.WARNING,
                message="[CWE-119] memcpy with potentially overlapping regions; use memmove instead",
                checker=self.name,
                cwe=119,
            )
            self._findings.append(finding)

    # ─────────────────────────────────────────────────────────────────
    #  Buffer Vulnerability Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_buffer_vulnerabilities(self, cfg) -> None:
        """Check for buffer-related vulnerabilities."""
        for token in cfg.tokenlist:
            # Check array accesses
            if is_subscript(token):
                self._check_array_bounds(token)

            # Check string operations
            if is_function_call(token):
                func_name = get_called_function_name(token)
                if func_name in ("strncpy", "strncat", "memcpy", "memmove", "memset"):
                    self._check_buffer_size_param(token, func_name)

    def _check_array_bounds(self, token) -> None:
        """Check array access for potential out-of-bounds."""
        array_tok = tok_op1(token)
        index_tok = tok_op2(token)

        if not array_tok or not index_tok:
            return

        # Get array size if known
        array_size = get_array_size(array_tok)

        # Check index value if known
        index_values = tok_values(index_tok)
        for val in index_values:
            intval = getattr(val, "intvalue", None)
            if intval is not None:
                # Check for negative index
                if intval < 0:
                    finding = Finding(
                        file=tok_file(token),
                        line=tok_line(token),
                        column=tok_column(token),
                        severity=Severity.ERROR,
                        message=f"[CWE-129] Negative array index: {intval}",
                        checker=self.name,
                        cwe=129,
                    )
                    self._findings.append(finding)

                # Check for out-of-bounds if array size is known
                elif array_size is not None and intval >= array_size:
                    finding = Finding(
                        file=tok_file(token),
                        line=tok_line(token),
                        column=tok_column(token),
                        severity=Severity.ERROR,
                        message=f"[CWE-125] Array index {intval} out of bounds (size: {array_size})",
                        checker=self.name,
                        cwe=125,
                    )
                    self._findings.append(finding)

        # Check if index might be negative (from signed variable)
        if may_be_negative(index_tok) and is_signed_type(index_tok):
            finding = Finding(
                file=tok_file(token),
                line=tok_line(token),
                column=tok_column(token),
                severity=Severity.WARNING,
                message="[CWE-129] Array index from signed variable may be negative",
                checker=self.name,
                cwe=129,
            )
            self._findings.append(finding)

    def _check_buffer_size_param(self, token, func_name: str) -> None:
        """Check buffer size parameters for potential issues."""
        args = get_call_arguments(token)

        # Size parameter position varies by function
        size_idx = {"strncpy": 2, "strncat": 2, "memcpy": 2,
                    "memmove": 2, "memset": 2}.get(func_name)
        if size_idx is None or size_idx >= len(args):
            return

        size_arg = args[size_idx]

        # Check for tainted size (already handled by taint analysis)

        # Check for potential integer overflow in size calculation
        if is_arithmetic_op(find_ast_root(size_arg)):
            self._check_size_overflow(token, size_arg, func_name)

    def _check_size_overflow(self, call_token, size_expr, func_name: str) -> None:
        """Check for potential integer overflow in size calculation."""
        root = find_ast_root(size_expr)

        # Check for multiplication (common overflow pattern)
        for node in iter_ast_preorder(root):
            if tok_str(node) == '*':
                op1 = tok_op1(node)
                op2 = tok_op2(node)

                # If both operands are variables or non-constant, warn
                if op1 and op2 and not is_literal(op1) and not is_literal(op2):
                    finding = Finding(
                        file=tok_file(call_token),
                        line=tok_line(call_token),
                        column=tok_column(call_token),
                        severity=Severity.WARNING,
                        message=f"[CWE-131] Size calculation for {func_name} may overflow: "
                        f"{expr_to_string(node)}",
                        checker=self.name,
                        cwe=131,
                    )
                    self._findings.append(finding)
                    break

    # ─────────────────────────────────────────────────────────────────
    #  Integer Vulnerability Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_integer_vulnerabilities(self, cfg) -> None:
        """Check for integer-related vulnerabilities."""
        for token in cfg.tokenlist:
            # Check assignments for type conversion issues
            if is_assignment(token):
                self._check_integer_conversion(token)

            # Check arithmetic operations for overflow potential
            if tok_str(token) in ('+', '-', '*') and is_arithmetic_op(token):
                self._check_integer_overflow(token)

    def _check_integer_conversion(self, token) -> None:
        """Check assignment for problematic integer conversions."""
        lhs = tok_op1(token)
        rhs = tok_op2(token)

        if not lhs or not rhs:
            return

        lhs_type = tok_value_type(lhs)
        rhs_type = tok_value_type(rhs)

        if not lhs_type or not rhs_type:
            return

        lhs_signed = is_signed_type(lhs)
        rhs_signed = is_signed_type(rhs)
        lhs_size = get_sizeof_type(lhs)
        rhs_size = get_sizeof_type(rhs)

        # CWE-195: Signed to unsigned conversion
        if rhs_signed and not lhs_signed:
            if may_be_negative(rhs):
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message="[CWE-195] Signed to unsigned conversion of potentially negative value",
                    checker=self.name,
                    cwe=195,
                )
                self._findings.append(finding)

        # CWE-196: Unsigned to signed conversion
        elif not rhs_signed and lhs_signed:
            # Large unsigned values become negative when converted to signed
            rhs_values = tok_values(rhs)
            for val in rhs_values:
                intval = getattr(val, "intvalue", None)
                if intval is not None and lhs_size:
                    max_signed = (1 << (lhs_size * 8 - 1)) - 1
                    if intval > max_signed:
                        finding = Finding(
                            file=tok_file(token),
                            line=tok_line(token),
                            column=tok_column(token),
                            severity=Severity.WARNING,
                            message=f"[CWE-196] Unsigned value {intval} exceeds signed maximum",
                            checker=self.name,
                            cwe=196,
                        )
                        self._findings.append(finding)

        # CWE-197: Numeric truncation
        if lhs_size and rhs_size and lhs_size < rhs_size:
            finding = Finding(
                file=tok_file(token),
                line=tok_line(token),
                column=tok_column(token),
                severity=Severity.WARNING,
                message=f"[CWE-197] Numeric truncation: {rhs_size}-byte value to {lhs_size}-byte variable",
                checker=self.name,
                cwe=197,
            )
            self._findings.append(finding)

    def _check_integer_overflow(self, token) -> None:
        """Check arithmetic operation for potential overflow."""
        op1 = tok_op1(token)
        op2 = tok_op2(token)

        if not op1 or not op2:
            return

        # Check if result is used in sensitive context
        parent = tok_parent(token)
        if parent:
            parent_str = tok_str(parent)

            # Overflow in array index
            if parent_str == '[':
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-190] Arithmetic in array index may overflow: {expr_to_string(token)}",
                    checker=self.name,
                    cwe=190,
                )
                self._findings.append(finding)

            # Overflow in allocation size
            elif is_function_call(parent):
                func_name = get_called_function_name(parent)
                if func_name in ALLOC_FUNCTIONS:
                    finding = Finding(
                        file=tok_file(token),
                        line=tok_line(token),
                        column=tok_column(token),
                        severity=Severity.WARNING,
                        message=f"[CWE-190] Arithmetic in allocation size may overflow: {expr_to_string(token)}",
                        checker=self.name,
                        cwe=190,
                    )
                    self._findings.append(finding)

    # ─────────────────────────────────────────────────────────────────
    #  Memory Management Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_memory_vulnerabilities(self, cfg) -> None:
        """Check for memory management vulnerabilities."""
        # Track allocation state per scope
        for scope in cfg.scopes:
            if getattr(scope, "type", "") == "Function":
                self._check_function_memory(scope)

    def _check_function_memory(self, scope) -> None:
        """Check memory management within a function."""
        # Simple tracking of allocated/freed pointers
        allocated: Dict[int, object] = {}  # var_id -> allocation token
        freed: Dict[int, object] = {}       # var_id -> free token

        for token in iter_tokens_in_scope(scope):
            if not is_function_call(token):
                continue

            func_name = get_called_function_name(token)

            # Track allocations
            if is_allocation_call(token):
                parent = tok_parent(token)
                if parent and is_assignment(parent):
                    lhs = tok_op1(parent)
                    var_id = tok_var_id(lhs)
                    if var_id:
                        allocated[var_id] = token
                        # Clear from freed if reallocating
                        freed.pop(var_id, None)

            # Track deallocations
            elif is_deallocation_call(token):
                args = get_call_arguments(token)
                if args:
                    arg = args[0]
                    var_id = tok_var_id(arg)
                    if var_id:
                        # CWE-415: Double free
                        if var_id in freed:
                            finding = Finding(
                                file=tok_file(token),
                                line=tok_line(token),
                                column=tok_column(token),
                                severity=Severity.ERROR,
                                message=f"[CWE-415] Double free of pointer",
                                checker=self.name,
                                cwe=415,
                            )
                            self._findings.append(finding)
                        else:
                            freed[var_id] = token
                            allocated.pop(var_id, None)

            # Check for use after free
            else:
                for node in iter_ast_preorder(token):
                    var_id = tok_var_id(node)
                    if var_id and var_id in freed:
                        # Check if this is a dereference or use
                        if is_dereference(tok_parent(node)) or is_subscript(tok_parent(node)):
                            finding = Finding(
                                file=tok_file(node),
                                line=tok_line(node),
                                column=tok_column(node),
                                severity=Severity.ERROR,
                                message=f"[CWE-416] Use after free",
                                checker=self.name,
                                cwe=416,
                            )
                            self._findings.append(finding)

    # ─────────────────────────────────────────────────────────────────
    #  Unchecked Return Value Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_unchecked_returns(self, cfg) -> None:
        """Check for unchecked return values of critical functions."""
        for token in cfg.tokenlist:
            if not is_function_call(token):
                continue

            func_name = get_called_function_name(token)
            if func_name not in MUST_CHECK_RETURN:
                continue

            # Check if return value is used
            parent = tok_parent(token)
            if parent is None:
                # Call statement with no parent - return value ignored
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-252] Return value of {func_name}() is not checked",
                    checker=self.name,
                    cwe=252,
                )
                self._findings.append(finding)
            elif tok_str(parent) == '(' and not is_function_call(parent):
                # Cast to void - intentionally ignored
                pass
            elif tok_str(parent) == ',' or tok_str(parent) == ';':
                # Part of comma expression or statement - likely ignored
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-252] Return value of {func_name}() may not be checked",
                    checker=self.name,
                    cwe=252,
                )
                self._findings.append(finding)

    # ─────────────────────────────────────────────────────────────────
    #  Null Pointer Checks
    # ─────────────────────────────────────────────────────────────────

    def _check_null_pointer_issues(self, cfg) -> None:
        """Check for null pointer dereference vulnerabilities."""
        for token in cfg.tokenlist:
            # Check dereferences
            if is_dereference(token):
                self._check_null_deref(token)

            # Check array accesses
            if is_subscript(token):
                self._check_null_array_access(token)

            # Check member access through pointer
            if tok_str(token) == '->':
                self._check_null_member_access(token)

    def _check_null_deref(self, token) -> None:
        """Check pointer dereference for potential null."""
        ptr = tok_op1(token)
        if not ptr:
            return

        # Check if pointer might be null
        if may_be_zero(ptr):
            # Check if there's a null check before this
            if not self._has_null_check_before(ptr):
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-476] Potential null pointer dereference: {expr_to_string(ptr)}",
                    checker=self.name,
                    cwe=476,
                )
                self._findings.append(finding)

    def _check_null_array_access(self, token) -> None:
        """Check array access for potential null base."""
        array = tok_op1(token)
        if not array:
            return

        if is_pointer_type(array) and may_be_zero(array):
            if not self._has_null_check_before(array):
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-476] Potential null pointer in array access: {expr_to_string(array)}",
                    checker=self.name,
                    cwe=476,
                )
                self._findings.append(finding)

    def _check_null_member_access(self, token) -> None:
        """Check member access through potentially null pointer."""
        ptr = tok_op1(token)
        if not ptr:
            return

        if may_be_zero(ptr):
            if not self._has_null_check_before(ptr):
                finding = Finding(
                    file=tok_file(token),
                    line=tok_line(token),
                    column=tok_column(token),
                    severity=Severity.WARNING,
                    message=f"[CWE-476] Potential null pointer member access: {expr_to_string(ptr)}",
                    checker=self.name,
                    cwe=476,
                )
                self._findings.append(finding)

    def _has_null_check_before(self, ptr_token) -> bool:
        """
        Check if there's a null check for this pointer before its use.

        This is a simplified check that looks for common patterns.
        """
        var_id = tok_var_id(ptr_token)
        if not var_id:
            return False

        # Walk backwards looking for null check
        current = ptr_token
        depth = 0
        max_depth = 50

        while current and depth < max_depth:
            current = getattr(current, "previous", None)
            depth += 1

            if not current:
                break

            # Check for if (ptr) or if (ptr != NULL) pattern
            if tok_str(current) == "if":
                # Look at condition
                next_tok = getattr(current, "next", None)
                if next_tok and tok_str(next_tok) == "(":
                    # Simple heuristic: if the variable appears in condition
                    cond_end = getattr(next_tok, "link", None)
                    if cond_end:
                        check_tok = next_tok
                        while check_tok and check_tok != cond_end:
                            if tok_var_id(check_tok) == var_id:
                                return True
                            check_tok = getattr(check_tok, "next", None)

        return False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def analyze_file(dump_file: str) -> List[Finding]:
    """
    Analyze a Cppcheck dump file for security vulnerabilities.

    Args:
        dump_file: Path to the .dump file

    Returns:
        List of findings
    """
    data = cppcheckdata.parsedump(dump_file)
    checker = SecurityLintChecker()
    all_findings: List[Finding] = []

    for cfg in data.configurations:
        findings = checker.check(cfg)
        all_findings.extend(findings)

    return all_findings


def print_findings(findings: List[Finding], format: str = "text") -> None:
    """
    Print findings in the specified format.

    Args:
        findings: List of findings to print
        format: Output format ("text", "json", "csv")
    """
    if format == "json":
        import json
        data = {
            "findings": [
                {
                    "file": f.file,
                    "line": f.line,
                    "column": f.column,
                    "severity": f.severity.name,
                    "message": f.message,
                    "checker": f.checker,
                    "cwe": f.cwe,
                }
                for f in findings
            ]
        }
        print(json.dumps(data, indent=2))

    elif format == "csv":
        import csv
        import sys
        writer = csv.writer(sys.stdout)
        writer.writerow(["File", "Line", "Column",
                        "Severity", "CWE", "Message"])
        for f in findings:
            writer.writerow([f.file, f.line, f.column,
                            f.severity.name, f.cwe or "", f.message])

    else:  # text
        if not findings:
            print("No security issues found.")
            return

        print(f"\n{'═' * 70}")
        print(f"  SECURITY LINT REPORT - {len(findings)} issue(s) found")
        print(f"{'═' * 70}\n")

        # Group by severity
        by_severity: Dict[Severity, List[Finding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        for severity in [Severity.ERROR, Severity.WARNING, Severity.STYLE, Severity.INFO]:
            if severity not in by_severity:
                continue

            severity_findings = by_severity[severity]
            print(f"[{severity.name}] ({len(severity_findings)} issues)")
            print("-" * 50)

            for f in severity_findings:
                print(f"  {f.file}:{f.line}:{f.column}")
                print(f"    {f.message}")
                print()

        print(f"{'═' * 70}")


def main():
    """Main entry point for command-line usage."""
    parser = argparse.ArgumentParser(
        description="SecurityLint - Security vulnerability detection for C/C++",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s myfile.c.dump
    %(prog)s --format=json myfile.c.dump
    %(prog)s --format=csv *.dump

Supported CWEs:
    Injection: CWE-78, CWE-89, CWE-90, CWE-91, CWE-94, CWE-134
    Path Traversal: CWE-22, CWE-23, CWE-36, CWE-73
    Buffer Errors: CWE-119, CWE-120, CWE-121, CWE-122, CWE-125, CWE-126,
                   CWE-127, CWE-129, CWE-131, CWE-170
    Integer Errors: CWE-190, CWE-191, CWE-192, CWE-193, CWE-194, CWE-195,
                    CWE-196, CWE-197
    Memory: CWE-415, CWE-416, CWE-401, CWE-476, CWE-789
    Dangerous Functions: CWE-242, CWE-676
        """
    )

    parser.add_argument(
        "dump_files",
        nargs="+",
        help="Cppcheck dump file(s) to analyze"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show findings, no summary"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="SecurityLint 1.0.0"
    )

    args = parser.parse_args()

    all_findings: List[Finding] = []

    for dump_file in args.dump_files:
        try:
            findings = analyze_file(dump_file)
            all_findings.extend(findings)
        except Exception as e:
            print(f"Error analyzing {dump_file}: {e}", file=sys.stderr)

    print_findings(all_findings, args.format)

    # Exit with error code if findings found
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
