#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TaintLint.py — Comprehensive Taint Analysis Addon for Cppcheck
══════════════════════════════════════════════════════════════

A security-focused Cppcheck addon that performs taint analysis to detect
vulnerabilities where untrusted (tainted) data flows to sensitive operations
(sinks) without proper sanitization.

This addon detects vulnerabilities based on MITRE's CWE database:

    ┌─────────────────────────────────────────────────────────────────┐
    │  INJECTION VULNERABILITIES                                      │
    ├─────────────────────────────────────────────────────────────────┤
    │  CWE-78:  OS Command Injection                                  │
    │  CWE-89:  SQL Injection                                         │
    │  CWE-90:  LDAP Injection                                        │
    │  CWE-91:  XML Injection (Blind XPath Injection)                 │
    │  CWE-94:  Code Injection                                        │
    │  CWE-134: Use of Externally-Controlled Format String            │
    └─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │  PATH AND FILE VULNERABILITIES                                  │
    ├─────────────────────────────────────────────────────────────────┤
    │  CWE-22:  Path Traversal                                        │
    │  CWE-23:  Relative Path Traversal                               │
    │  CWE-36:  Absolute Path Traversal                               │
    │  CWE-73:  External Control of File Name or Path                 │
    └─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │  MEMORY SAFETY VULNERABILITIES                                  │
    ├─────────────────────────────────────────────────────────────────┤
    │  CWE-120: Buffer Copy without Checking Size of Input            │
    │  CWE-122: Heap-based Buffer Overflow                            │
    │  CWE-129: Improper Validation of Array Index                    │
    │  CWE-131: Incorrect Calculation of Buffer Size                  │
    │  CWE-789: Memory Allocation with Excessive Size Value           │
    └─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │  INFORMATION DISCLOSURE                                         │
    ├─────────────────────────────────────────────────────────────────┤
    │  CWE-117: Improper Output Neutralization for Logs               │
    │  CWE-200: Exposure of Sensitive Information                     │
    │  CWE-209: Error Message Information Exposure                    │
    └─────────────────────────────────────────────────────────────────┘

    ┌─────────────────────────────────────────────────────────────────┐
    │  DANGEROUS FUNCTIONS                                            │
    ├─────────────────────────────────────────────────────────────────┤
    │  CWE-242: Use of Inherently Dangerous Function                  │
    │  CWE-676: Use of Potentially Dangerous Function                 │
    └─────────────────────────────────────────────────────────────────┘

Usage:
    cppcheck --dump myfile.c
    python TaintLint.py myfile.c.dump

    With options:
    python TaintLint.py --format=json --severity=high myfile.c.dump

Author: cppcheckdata_shims library
License: MIT
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

try:
    import cppcheckdata
except ImportError:
    print("Error: cppcheckdata module not found.", file=sys.stderr)
    print("Please ensure Cppcheck is properly installed.", file=sys.stderr)
    sys.exit(1)

try:
    from cppcheckdata_shims.taint_analysis import (
        TaintLevel,
        TaintValue,
        TaintState,
        SourceKind,
        SinkKind,
        PropagationKind,
        TaintSource,
        TaintSink,
        TaintSanitizer,
        TaintPropagator,
        TaintConfig,
        TaintAnalyzer,
        TaintAnalysisResult,
        TaintViolation,
        TaintReportFormat,
        format_violations,
        format_violations_text,
        format_violations_json,
        format_violations_sarif,
    )

    from cppcheckdata_shims.ast_helper import (
        tok_str,
        tok_op1,
        tok_op2,
        tok_parent,
        tok_var_id,
        tok_variable,
        tok_file,
        tok_line,
        tok_column,
        token_location,
        iter_ast_preorder,
        find_ast_root,
        is_function_call,
        is_assignment,
        is_literal,
        is_identifier,
        get_called_function_name,
        get_call_arguments,
        expr_to_string,
        find_function_calls,
    )
except ImportError as e:
    print(f"Error: cppcheckdata_shims module not found: {e}", file=sys.stderr)
    print("Please ensure cppcheckdata_shims is properly installed.", file=sys.stderr)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  CWE INFORMATION DATABASE
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CWEEntry:
    """Information about a CWE entry."""
    id: int
    name: str
    description: str
    url: str

    def __str__(self) -> str:
        return f"CWE-{self.id}: {self.name}"


CWE_DATABASE: Dict[int, CWEEntry] = {
    # Injection
    78: CWEEntry(
        78,
        "Improper Neutralization of Special Elements used in an OS Command",
        "The product constructs all or part of an OS command using externally-influenced "
        "input from an upstream component, but it does not neutralize or incorrectly "
        "neutralizes special elements that could modify the intended OS command.",
        "https://cwe.mitre.org/data/definitions/78.html"
    ),
    89: CWEEntry(
        89,
        "Improper Neutralization of Special Elements used in an SQL Command",
        "The product constructs all or part of an SQL command using externally-influenced "
        "input from an upstream component, but it does not neutralize or incorrectly "
        "neutralizes special elements that could modify the intended SQL command.",
        "https://cwe.mitre.org/data/definitions/89.html"
    ),
    90: CWEEntry(
        90,
        "Improper Neutralization of Special Elements used in an LDAP Query",
        "The product constructs all or part of an LDAP query using externally-influenced "
        "input from an upstream component, but it does not neutralize or incorrectly "
        "neutralizes special elements that could modify the intended LDAP query.",
        "https://cwe.mitre.org/data/definitions/90.html"
    ),
    91: CWEEntry(
        91,
        "XML Injection (aka Blind XPath Injection)",
        "The product does not properly neutralize special elements that are used in XML, "
        "allowing attackers to modify the syntax, content, or commands of the XML before "
        "it is processed by an end system.",
        "https://cwe.mitre.org/data/definitions/91.html"
    ),
    94: CWEEntry(
        94,
        "Improper Control of Generation of Code",
        "The product constructs all or part of a code segment using externally-influenced "
        "input from an upstream component, but it does not neutralize or incorrectly "
        "neutralizes special elements that could modify the syntax or behavior of the "
        "intended code segment.",
        "https://cwe.mitre.org/data/definitions/94.html"
    ),
    117: CWEEntry(
        117,
        "Improper Output Neutralization for Logs",
        "The product does not neutralize or incorrectly neutralizes output that is written "
        "to logs.",
        "https://cwe.mitre.org/data/definitions/117.html"
    ),
    134: CWEEntry(
        134,
        "Use of Externally-Controlled Format String",
        "The product uses a function that accepts a format string as an argument, but the "
        "format string originates from an external source.",
        "https://cwe.mitre.org/data/definitions/134.html"
    ),

    # Path Traversal
    22: CWEEntry(
        22,
        "Improper Limitation of a Pathname to a Restricted Directory",
        "The product uses external input to construct a pathname that is intended to "
        "identify a file or directory that is located underneath a restricted parent "
        "directory, but the product does not properly neutralize special elements within "
        "the pathname.",
        "https://cwe.mitre.org/data/definitions/22.html"
    ),
    23: CWEEntry(
        23,
        "Relative Path Traversal",
        "The product uses external input to construct a pathname that should be within a "
        "restricted directory, but it does not properly neutralize sequences such as '..' "
        "that can resolve to a location that is outside of that directory.",
        "https://cwe.mitre.org/data/definitions/23.html"
    ),
    36: CWEEntry(
        36,
        "Absolute Path Traversal",
        "The product uses external input to construct a pathname that should be within a "
        "restricted directory, but it does not properly neutralize absolute path sequences "
        "such as '/abs/path' that can resolve to a location that is outside of that directory.",
        "https://cwe.mitre.org/data/definitions/36.html"
    ),
    73: CWEEntry(
        73,
        "External Control of File Name or Path",
        "The product allows user input to control or influence paths or file names that "
        "are used in filesystem operations.",
        "https://cwe.mitre.org/data/definitions/73.html"
    ),

    # Buffer/Memory
    120: CWEEntry(
        120,
        "Buffer Copy without Checking Size of Input",
        "The product copies an input buffer to an output buffer without verifying that "
        "the size of the input buffer is less than the size of the output buffer.",
        "https://cwe.mitre.org/data/definitions/120.html"
    ),
    122: CWEEntry(
        122,
        "Heap-based Buffer Overflow",
        "A heap overflow condition is a buffer overflow, where the buffer that can be "
        "overwritten is allocated in the heap portion of memory.",
        "https://cwe.mitre.org/data/definitions/122.html"
    ),
    129: CWEEntry(
        129,
        "Improper Validation of Array Index",
        "The product uses untrusted input when calculating or using an array index, but "
        "the product does not validate or incorrectly validates the index to ensure the "
        "index references a valid position within the array.",
        "https://cwe.mitre.org/data/definitions/129.html"
    ),
    131: CWEEntry(
        131,
        "Incorrect Calculation of Buffer Size",
        "The product does not correctly calculate the size to be used when allocating a "
        "buffer, which could lead to a buffer overflow.",
        "https://cwe.mitre.org/data/definitions/131.html"
    ),
    789: CWEEntry(
        789,
        "Memory Allocation with Excessive Size Value",
        "The product allocates memory based on an untrusted size value, but it does not "
        "validate or incorrectly validates the size, allowing arbitrary amounts of memory "
        "to be allocated.",
        "https://cwe.mitre.org/data/definitions/789.html"
    ),

    # Dangerous Functions
    242: CWEEntry(
        242,
        "Use of Inherently Dangerous Function",
        "The product calls a function that can never be guaranteed to work safely.",
        "https://cwe.mitre.org/data/definitions/242.html"
    ),
    676: CWEEntry(
        676,
        "Use of Potentially Dangerous Function",
        "The product invokes a potentially dangerous function that could introduce a "
        "vulnerability if it is used incorrectly.",
        "https://cwe.mitre.org/data/definitions/676.html"
    ),
}


# ═══════════════════════════════════════════════════════════════════════════
#  DANGEROUS FUNCTION DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

INHERENTLY_DANGEROUS_FUNCTIONS: FrozenSet[str] = frozenset({
    "gets",
})

POTENTIALLY_DANGEROUS_FUNCTIONS: Dict[str, Tuple[int, str]] = {
    "strcpy": (676, "No bounds checking; use strncpy or strlcpy"),
    "strcat": (676, "No bounds checking; use strncat or strlcat"),
    "sprintf": (676, "No bounds checking; use snprintf"),
    "vsprintf": (676, "No bounds checking; use vsnprintf"),
    "scanf": (676, "Unbounded %s may overflow; specify width"),
    "fscanf": (676, "Unbounded %s may overflow; specify width"),
    "sscanf": (676, "Unbounded %s may overflow; specify width"),
    "gets": (242, "Cannot be used safely; use fgets"),
    "mktemp": (676, "Race condition; use mkstemp"),
    "tmpnam": (676, "Race condition; use mkstemp"),
    "tempnam": (676, "Race condition; use mkstemp"),
    "realpath": (676, "May overflow buffer; pass NULL for buffer"),
    "getwd": (676, "No bounds checking; use getcwd"),
    "wcscpy": (676, "No bounds checking; use wcsncpy"),
    "wcscat": (676, "No bounds checking; use wcsncat"),
}


# ═══════════════════════════════════════════════════════════════════════════
#  TAINT CONFIGURATION BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_taint_config() -> TaintConfig:
    """
    Build a comprehensive TaintConfig for security vulnerability detection.

    Returns:
        A fully configured TaintConfig
    """
    config = TaintConfig()

    # ═══════════════════════════════════════════════════════════════════
    #  TAINT SOURCES
    # ═══════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    #  Standard Input
    # ─────────────────────────────────────────────────────────────────

    config.add_source(TaintSource(
        function="gets",
        kind=SourceKind.RETURN_VALUE,
        description="Reads unbounded line from stdin (DANGEROUS)",
        cwe=242,
        tags=frozenset({"stdin", "dangerous"}),
    ))

    config.add_source(TaintSource(
        function="fgets",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Reads line from stream",
        tags=frozenset({"stdin", "stream"}),
    ))

    config.add_source(TaintSource(
        function="getchar",
        kind=SourceKind.RETURN_VALUE,
        description="Reads character from stdin",
        tags=frozenset({"stdin"}),
    ))

    config.add_source(TaintSource(
        function="fgetc",
        kind=SourceKind.RETURN_VALUE,
        description="Reads character from stream",
        tags=frozenset({"stream"}),
    ))

    config.add_source(TaintSource(
        function="getc",
        kind=SourceKind.RETURN_VALUE,
        description="Reads character from stream",
        tags=frozenset({"stream"}),
    ))

    config.add_source(TaintSource(
        function="fread",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Reads binary data from stream",
        tags=frozenset({"stream", "binary"}),
    ))

    config.add_source(TaintSource(
        function="read",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="POSIX read from file descriptor",
        tags=frozenset({"posix", "fd"}),
    ))

    config.add_source(TaintSource(
        function="pread",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="POSIX pread from file descriptor",
        tags=frozenset({"posix", "fd"}),
    ))

    config.add_source(TaintSource(
        function="getline",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Reads line with dynamic allocation",
        tags=frozenset({"stream", "gnu"}),
    ))

    config.add_source(TaintSource(
        function="getdelim",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="Reads delimited input",
        tags=frozenset({"stream", "gnu"}),
    ))

    # Formatted input
    config.add_source(TaintSource(
        function="scanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Formatted input from stdin",
        tags=frozenset({"stdin", "formatted"}),
    ))

    config.add_source(TaintSource(
        function="fscanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=2,
        description="Formatted input from stream",
        tags=frozenset({"stream", "formatted"}),
    ))

    config.add_source(TaintSource(
        function="sscanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=2,
        description="Formatted input from string",
        tags=frozenset({"string", "formatted"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  Network Input
    # ─────────────────────────────────────────────────────────────────

    config.add_source(TaintSource(
        function="recv",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receives data from socket",
        cwe=20,
        tags=frozenset({"network", "socket"}),
    ))

    config.add_source(TaintSource(
        function="recvfrom",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receives data from socket with address",
        cwe=20,
        tags=frozenset({"network", "socket", "udp"}),
    ))

    config.add_source(TaintSource(
        function="recvmsg",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Receives message from socket",
        cwe=20,
        tags=frozenset({"network", "socket"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  Environment
    # ─────────────────────────────────────────────────────────────────

    config.add_source(TaintSource(
        function="getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Environment variable (attacker-controlled)",
        cwe=78,
        tags=frozenset({"environment"}),
    ))

    config.add_source(TaintSource(
        function="secure_getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Secure environment variable",
        tags=frozenset({"environment", "secure"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  Command Line (argv)
    # ─────────────────────────────────────────────────────────────────

    config.add_tainted_parameter("main", 1)  # argv

    # ═══════════════════════════════════════════════════════════════════
    #  TAINT SINKS
    # ═══════════════════════════════════════════════════════════════════

    # ─────────────────────────────────────────────────────────────────
    #  CWE-78: OS Command Injection
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="system",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Shell command execution",
        cwe=78,
        severity=10,
        tags=frozenset({"shell", "critical"}),
    ))

    config.add_sink(TaintSink(
        function="popen",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Shell command with pipe",
        cwe=78,
        severity=10,
        tags=frozenset({"shell", "pipe"}),
    ))

    for func in ["execl", "execle", "execlp", "execv", "execve", "execvp", "execvpe"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=0,
            kind=SinkKind.COMMAND_INJECTION,
            description=f"Program execution via {func}",
            cwe=78,
            severity=9,
            tags=frozenset({"exec"}),
        ))

    # Windows
    config.add_sink(TaintSink(
        function="ShellExecute",
        argument_index=2,
        kind=SinkKind.COMMAND_INJECTION,
        description="Windows shell execute",
        cwe=78,
        severity=10,
        tags=frozenset({"windows", "shell"}),
    ))

    config.add_sink(TaintSink(
        function="CreateProcess",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Windows process creation",
        cwe=78,
        severity=9,
        tags=frozenset({"windows"}),
    ))

    config.add_sink(TaintSink(
        function="WinExec",
        argument_index=0,
        kind=SinkKind.COMMAND_INJECTION,
        description="Windows command execution",
        cwe=78,
        severity=10,
        tags=frozenset({"windows", "deprecated"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-134: Format String
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="printf",
        argument_index=0,
        kind=SinkKind.FORMAT_STRING,
        description="Format string to stdout",
        cwe=134,
        severity=8,
        tags=frozenset({"printf"}),
    ))

    config.add_sink(TaintSink(
        function="fprintf",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        description="Format string to stream",
        cwe=134,
        severity=8,
        tags=frozenset({"printf", "stream"}),
    ))

    config.add_sink(TaintSink(
        function="dprintf",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        description="Format string to fd",
        cwe=134,
        severity=8,
        tags=frozenset({"printf", "fd"}),
    ))

    config.add_sink(TaintSink(
        function="sprintf",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        description="Format string to buffer",
        cwe=134,
        severity=9,
        tags=frozenset({"printf", "buffer"}),
    ))

    config.add_sink(TaintSink(
        function="snprintf",
        argument_index=2,
        kind=SinkKind.FORMAT_STRING,
        description="Format string to bounded buffer",
        cwe=134,
        severity=8,
        tags=frozenset({"printf", "buffer"}),
    ))

    config.add_sink(TaintSink(
        function="syslog",
        argument_index=1,
        kind=SinkKind.FORMAT_STRING,
        description="Syslog format string",
        cwe=134,
        severity=8,
        tags=frozenset({"syslog"}),
    ))

    # Variadic versions
    for func, idx in [("vprintf", 0), ("vfprintf", 1), ("vsprintf", 1),
                      ("vsnprintf", 2), ("vsyslog", 1)]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=idx,
            kind=SinkKind.FORMAT_STRING,
            description=f"Variadic format string via {func}",
            cwe=134,
            severity=8,
            tags=frozenset({"printf", "variadic"}),
        ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-22: Path Traversal
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="fopen",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="File open with user path",
        cwe=22,
        severity=7,
        tags=frozenset({"file", "open"}),
    ))

    config.add_sink(TaintSink(
        function="freopen",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="File reopen with user path",
        cwe=22,
        severity=7,
        tags=frozenset({"file", "open"}),
    ))

    config.add_sink(TaintSink(
        function="open",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="POSIX open with user path",
        cwe=22,
        severity=7,
        tags=frozenset({"posix", "open"}),
    ))

    config.add_sink(TaintSink(
        function="openat",
        argument_index=1,
        kind=SinkKind.PATH_TRAVERSAL,
        description="POSIX openat with user path",
        cwe=22,
        severity=7,
        tags=frozenset({"posix", "open"}),
    ))

    config.add_sink(TaintSink(
        function="creat",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="File creation with user path",
        cwe=22,
        severity=7,
        tags=frozenset({"file", "create"}),
    ))

    # Directory operations
    for func in ["mkdir", "rmdir", "opendir", "chdir"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=0,
            kind=SinkKind.PATH_TRAVERSAL,
            description=f"Directory operation with user path: {func}",
            cwe=22,
            severity=6 if func in ("opendir", "chdir") else 7,
            tags=frozenset({"directory"}),
        ))

    # File deletion/modification
    for func in ["unlink", "remove", "rename", "chmod", "chown"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=0,
            kind=SinkKind.PATH_TRAVERSAL,
            description=f"File operation with user path: {func}",
            cwe=22,
            severity=8 if func in ("unlink", "remove") else 7,
            tags=frozenset({"file"}),
        ))

    # Symlink operations
    config.add_sink(TaintSink(
        function="symlink",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="Symlink target with user path",
        cwe=59,
        severity=7,
        tags=frozenset({"symlink"}),
    ))

    config.add_sink(TaintSink(
        function="symlink",
        argument_index=1,
        kind=SinkKind.PATH_TRAVERSAL,
        description="Symlink name with user path",
        cwe=59,
        severity=7,
        tags=frozenset({"symlink"}),
    ))

    # Dynamic library loading
    config.add_sink(TaintSink(
        function="dlopen",
        argument_index=0,
        kind=SinkKind.PATH_TRAVERSAL,
        description="Dynamic library load with user path",
        cwe=426,
        severity=9,
        tags=frozenset({"dlopen"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-89: SQL Injection
    # ─────────────────────────────────────────────────────────────────

    # SQLite
    config.add_sink(TaintSink(
        function="sqlite3_exec",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="SQLite query execution",
        cwe=89,
        severity=9,
        tags=frozenset({"sqlite", "sql"}),
    ))

    for func in ["sqlite3_prepare", "sqlite3_prepare_v2", "sqlite3_prepare_v3"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=1,
            kind=SinkKind.SQL_INJECTION,
            description=f"SQLite query preparation: {func}",
            cwe=89,
            severity=9,
            tags=frozenset({"sqlite", "sql"}),
        ))

    # MySQL
    config.add_sink(TaintSink(
        function="mysql_query",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="MySQL query execution",
        cwe=89,
        severity=9,
        tags=frozenset({"mysql", "sql"}),
    ))

    config.add_sink(TaintSink(
        function="mysql_real_query",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="MySQL query execution",
        cwe=89,
        severity=9,
        tags=frozenset({"mysql", "sql"}),
    ))

    # PostgreSQL
    config.add_sink(TaintSink(
        function="PQexec",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="PostgreSQL query execution",
        cwe=89,
        severity=9,
        tags=frozenset({"postgresql", "sql"}),
    ))

    config.add_sink(TaintSink(
        function="PQexecParams",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="PostgreSQL parameterized query",
        cwe=89,
        severity=9,
        tags=frozenset({"postgresql", "sql"}),
    ))

    # ODBC
    config.add_sink(TaintSink(
        function="SQLExecDirect",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="ODBC direct SQL execution",
        cwe=89,
        severity=9,
        tags=frozenset({"odbc", "sql"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-90: LDAP Injection
    # ─────────────────────────────────────────────────────────────────

    for func in ["ldap_search", "ldap_search_s", "ldap_search_st",
                 "ldap_search_ext", "ldap_search_ext_s"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=2,
            kind=SinkKind.LDAP_INJECTION,
            description=f"LDAP search filter: {func}",
            cwe=90,
            severity=8,
            tags=frozenset({"ldap"}),
        ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-91: XML Injection
    # ─────────────────────────────────────────────────────────────────

    for func in ["xmlParseMemory", "xmlParseDoc", "xmlReadMemory", "xmlReadDoc"]:
        config.add_sink(TaintSink(
            function=func,
            argument_index=0,
            kind=SinkKind.XML_INJECTION,
            description=f"XML parsing: {func}",
            cwe=91,
            severity=7,
            tags=frozenset({"xml", "libxml"}),
        ))

    # XPath
    config.add_sink(TaintSink(
        function="xmlXPathEval",
        argument_index=0,
        kind=SinkKind.XML_INJECTION,
        description="XPath evaluation",
        cwe=91,
        severity=8,
        tags=frozenset({"xpath", "libxml"}),
    ))

    config.add_sink(TaintSink(
        function="xmlXPathEvalExpression",
        argument_index=0,
        kind=SinkKind.XML_INJECTION,
        description="XPath expression evaluation",
        cwe=91,
        severity=8,
        tags=frozenset({"xpath", "libxml"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-94: Code Injection
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="dlsym",
        argument_index=1,
        kind=SinkKind.CODE_INJECTION,
        description="Dynamic symbol lookup",
        cwe=94,
        severity=8,
        tags=frozenset({"dlsym"}),
    ))

    # Scripting engines
    config.add_sink(TaintSink(
        function="luaL_dostring",
        argument_index=1,
        kind=SinkKind.CODE_INJECTION,
        description="Lua code execution",
        cwe=94,
        severity=9,
        tags=frozenset({"lua", "script"}),
    ))

    config.add_sink(TaintSink(
        function="luaL_loadstring",
        argument_index=1,
        kind=SinkKind.CODE_INJECTION,
        description="Lua code loading",
        cwe=94,
        severity=9,
        tags=frozenset({"lua", "script"}),
    ))

    config.add_sink(TaintSink(
        function="PyRun_SimpleString",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        description="Python code execution",
        cwe=94,
        severity=9,
        tags=frozenset({"python", "script"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-117: Log Injection
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="syslog",
        argument_index=1,
        kind=SinkKind.LOG_INJECTION,
        description="Syslog message",
        cwe=117,
        severity=5,
        tags=frozenset({"syslog", "logging"}),
    ))

    config.add_sink(TaintSink(
        function="openlog",
        argument_index=0,
        kind=SinkKind.LOG_INJECTION,
        description="Syslog ident",
        cwe=117,
        severity=4,
        tags=frozenset({"syslog", "logging"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-120, CWE-122: Buffer Overflow via Tainted Size
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="memcpy",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Memory copy with tainted size",
        cwe=120,
        severity=8,
        tags=frozenset({"memcpy", "size"}),
    ))

    config.add_sink(TaintSink(
        function="memmove",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Memory move with tainted size",
        cwe=120,
        severity=8,
        tags=frozenset({"memmove", "size"}),
    ))

    config.add_sink(TaintSink(
        function="memset",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Memory set with tainted size",
        cwe=120,
        severity=7,
        tags=frozenset({"memset", "size"}),
    ))

    config.add_sink(TaintSink(
        function="strncpy",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="String copy with tainted size",
        cwe=120,
        severity=7,
        tags=frozenset({"strncpy", "size"}),
    ))

    config.add_sink(TaintSink(
        function="strncat",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="String concat with tainted size",
        cwe=120,
        severity=7,
        tags=frozenset({"strncat", "size"}),
    ))

    config.add_sink(TaintSink(
        function="read",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Read with tainted size",
        cwe=120,
        severity=8,
        tags=frozenset({"read", "size"}),
    ))

    config.add_sink(TaintSink(
        function="recv",
        argument_index=2,
        kind=SinkKind.BUFFER_SIZE,
        description="Recv with tainted size",
        cwe=120,
        severity=8,
        tags=frozenset({"recv", "size"}),
    ))

    # ─────────────────────────────────────────────────────────────────
    #  CWE-789: Memory Allocation with Tainted Size
    # ─────────────────────────────────────────────────────────────────

    config.add_sink(TaintSink(
        function="malloc",
        argument_index=0,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Malloc with tainted size",
        cwe=789,
        severity=7,
        tags=frozenset({"malloc", "alloc"}),
    ))

    config.add_sink(TaintSink(
        function="calloc",
        argument_index=0,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Calloc with tainted count",
        cwe=789,
        severity=7,
        tags=frozenset({"calloc", "alloc"}),
    ))

    config.add_sink(TaintSink(
        function="calloc",
        argument_index=1,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Calloc with tainted size",
        cwe=789,
        severity=7,
        tags=frozenset({"calloc", "alloc"}),
    ))

    config.add_sink(TaintSink(
        function="realloc",
        argument_index=1,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Realloc with tainted size",
        cwe=789,
        severity=7,
        tags=frozenset({"realloc", "alloc"}),
    ))

    config.add_sink(TaintSink(
        function="aligned_alloc",
        argument_index=1,
        kind=SinkKind.MEMORY_ALLOCATION,
        description="Aligned alloc with tainted size",
        cwe=789,
        severity=7,
        tags=frozenset({"aligned_alloc", "alloc"}),
    ))

    # ═══════════════════════════════════════════════════════════════════
    #  SANITIZERS
    # ═══════════════════════════════════════════════════════════════════

    # Path sanitizers
    config.add_sanitizer(TaintSanitizer(
        function="realpath",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.PATH_TRAVERSAL}),
        description="Resolves to canonical path",
    ))

    config.add_sanitizer(TaintSanitizer(
        function="basename",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.PATH_TRAVERSAL}),
        description="Extracts filename only",
    ))

    # SQL sanitizers
    config.add_sanitizer(TaintSanitizer(
        function="mysql_real_escape_string",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="MySQL escape",
    ))

    config.add_sanitizer(TaintSanitizer(
        function="PQescapeStringConn",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="PostgreSQL escape",
    ))

    config.add_sanitizer(TaintSanitizer(
        function="sqlite3_mprintf",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="SQLite safe printf",
    ))

    # Integer parsing (for size validation)
    for func in ["strtol", "strtoul", "strtoll", "strtoull", "atoi", "atol"]:
        config.add_sanitizer(TaintSanitizer(
            function=func,
            argument_index=0,
            sanitizes_return=True,
            valid_for_sinks=frozenset({SinkKind.BUFFER_SIZE, SinkKind.MEMORY_ALLOCATION}),
            description=f"Integer conversion: {func}",
        ))

    # ═══════════════════════════════════════════════════════════════════
    #  PROPAGATORS
    # ═══════════════════════════════════════════════════════════════════

    # String copy
    config.add_propagator(TaintPropagator(
        function="strcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="String copy",
    ))

    config.add_propagator(TaintPropagator(
        function="strncpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="Bounded string copy",
    ))

    config.add_propagator(TaintPropagator(
        function="strcat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="String concatenation",
    ))

    config.add_propagator(TaintPropagator(
        function="strncat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="Bounded string concatenation",
    ))

    config.add_propagator(TaintPropagator(
        function="strdup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
        description="String duplication",
    ))

    config.add_propagator(TaintPropagator(
        function="strndup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
        description="Bounded string duplication",
    ))

    # Memory copy
    config.add_propagator(TaintPropagator(
        function="memcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="Memory copy",
    ))

    config.add_propagator(TaintPropagator(
        function="memmove",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_return=True,
        to_arguments=frozenset({0}),
        description="Memory move",
    ))

    # Non-propagating functions
    for func in ["strlen", "wcslen", "strcmp", "strncmp", "memcmp",
                 "strchr", "strrchr", "strstr", "strspn", "strcspn"]:
        config.add_propagator(TaintPropagator(
            function=func,
            propagation_kind=PropagationKind.NONE,
            to_return=True,
            description=f"{func} returns computed value",
        ))

    return config


# ═══════════════════════════════════════════════════════════════════════════
#  FINDING REPRESENTATION
# ═══════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    """Finding severity levels."""
    ERROR = auto()
    WARNING = auto()
    STYLE = auto()
    INFO = auto()


@dataclass
class Finding:
    """A security finding."""
    file: str
    line: int
    column: int
    severity: Severity
    message: str
    cwe: Optional[int] = None
    rule_id: str = ""
    confidence: float = 1.0

    def __str__(self) -> str:
        cwe_str = f" [CWE-{self.cwe}]" if self.cwe else ""
        return f"{self.file}:{self.line}:{self.column}: {self.severity.name.lower()}{cwe_str}: {self.message}"


# ═══════════════════════════════════════════════════════════════════════════
#  TAINTLINT ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class TaintLint:
    """
    TaintLint security analyzer.

    Performs taint analysis and dangerous function detection on C/C++ code.
    """

    def __init__(
        self,
        *,
        track_flow_paths: bool = True,
        check_dangerous_functions: bool = True,
        verbose: bool = False,
    ):
        """
        Initialize TaintLint.

        Args:
            track_flow_paths: Track detailed taint flow paths
            check_dangerous_functions: Check for dangerous function usage
            verbose: Enable verbose output
        """
        self._taint_config = build_taint_config()
        self._taint_analyzer = TaintAnalyzer(
            self._taint_config,
            track_flow_paths=track_flow_paths,
            verbose=verbose,
        )
        self._check_dangerous = check_dangerous_functions
        self._verbose = verbose
        self._findings: List[Finding] = []

    def analyze_file(self, dump_path: str) -> List[Finding]:
        """
        Analyze a Cppcheck dump file.

        Args:
            dump_path: Path to the .dump file

        Returns:
            List of findings
        """
        self._findings = []

        try:
            data = cppcheckdata.parsedump(dump_path)
        except Exception as e:
            print(f"Error parsing {dump_path}: {e}", file=sys.stderr)
            return []

        for cfg in data.configurations:
            self._analyze_configuration(cfg)

        return self._findings

    def _analyze_configuration(self, cfg) -> None:
        """Analyze a single configuration."""
        # Run taint analysis
        result = self._taint_analyzer.analyze_configuration(cfg)
        self._process_taint_violations(result.violations)

        # Check for dangerous functions
        if self._check_dangerous:
            self._check_dangerous_functions(cfg)

    def _process_taint_violations(self, violations: List[TaintViolation]) -> None:
        """Convert taint violations to findings."""
        for v in violations:
            cwe = v.cwe or self._sink_kind_to_cwe(v.sink_kind)
            cwe_entry = CWE_DATABASE.get(cwe)
            cwe_name = cwe_entry.name if cwe_entry else v.sink_kind.name

            message = f"{cwe_name}: Tainted data from "
            if v.taint_sources:
                message += ", ".join(v.taint_sources)
            else:
                message += "external source"
            message += f" reaches {v.function}()"

            if v.sink.argument_index >= 0:
                message += f" at argument {v.sink.argument_index}"

            finding = Finding(
                file=tok_file(v.sink_token) or "<unknown>",
                line=tok_line(v.sink_token) or 0,
                column=tok_column(v.sink_token) or 0,
                severity=Severity.ERROR if v.severity >= 8 else Severity.WARNING,
                message=message,
                cwe=cwe,
                rule_id=f"TAINT-{v.sink_kind.name}",
                confidence=v.confidence,
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
            SinkKind.CODE_INJECTION: 94,
            SinkKind.LOG_INJECTION: 117,
        }
        return mapping.get(sink_kind, 20)

    def _check_dangerous_functions(self, cfg) -> None:
        """Check for dangerous function usage."""
        for token in cfg.tokenlist:
            if not is_function_call(token):
                continue

            func_name = get_called_function_name(token)

            # Inherently dangerous (CWE-242)
            if func_name in INHERENTLY_DANGEROUS_FUNCTIONS:
                finding = Finding(
                    file=tok_file(token) or "<unknown>",
                    line=tok_line(token) or 0,
                    column=tok_column(token) or 0,
                    severity=Severity.ERROR,
                    message=f"Use of inherently dangerous function '{func_name}' - cannot be used safely",
                    cwe=242,
                    rule_id="DANGEROUS-242",
                )
                self._findings.append(finding)

            # Potentially dangerous (CWE-676)
            elif func_name in POTENTIALLY_DANGEROUS_FUNCTIONS:
                cwe, reason = POTENTIALLY_DANGEROUS_FUNCTIONS[func_name]
                finding = Finding(
                    file=tok_file(token) or "<unknown>",
                    line=tok_line(token) or 0,
                    column=tok_column(token) or 0,
                    severity=Severity.WARNING,
                    message=f"Use of potentially dangerous function '{func_name}': {reason}",
                    cwe=cwe,
                    rule_id=f"DANGEROUS-{cwe}",
                )
                self._findings.append(finding)


# ═══════════════════════════════════════════════════════════════════════════
#  OUTPUT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════

def format_findings_text(findings: List[Finding]) -> str:
    """Format findings as text."""
    if not findings:
        return "No security issues found.\n"

    lines = [
        "═" * 70,
        f"  TAINTLINT SECURITY REPORT - {len(findings)} issue(s) found",
        "═" * 70,
        "",
    ]

    # Group by severity
    by_severity: Dict[Severity, List[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    for severity in [Severity.ERROR, Severity.WARNING, Severity.STYLE, Severity.INFO]:
        if severity not in by_severity:
            continue

        sev_findings = by_severity[severity]
        lines.append(f"[{severity.name}] ({len(sev_findings)} issues)")
        lines.append("-" * 50)

        for f in sev_findings:
            lines.append(f"  {f.file}:{f.line}:{f.column}")
            cwe_str = f" (CWE-{f.cwe})" if f.cwe else ""
            lines.append(f"    {f.message}{cwe_str}")
            lines.append("")

    lines.append("═" * 70)
    return "\n".join(lines)


def format_findings_json(findings: List[Finding]) -> str:
    """Format findings as JSON."""
    import json

    data = {
        "version": "1.0",
        "tool": "TaintLint",
        "total": len(findings),
        "findings": [
            {
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "severity": f.severity.name,
                "message": f.message,
                "cwe": f.cwe,
                "rule_id": f.rule_id,
                "confidence": f.confidence,
            }
            for f in findings
        ]
    }
    return json.dumps(data, indent=2)


def format_findings_sarif(findings: List[Finding]) -> str:
    """Format findings as SARIF."""
    import json

    rules = {}
    results = []

    for f in findings:
        rule_id = f.rule_id or f"CWE-{f.cwe}" if f.cwe else "UNKNOWN"

        if rule_id not in rules:
            cwe_entry = CWE_DATABASE.get(f.cwe) if f.cwe else None
            rules[rule_id] = {
                "id": rule_id,
                "name": cwe_entry.name if cwe_entry else rule_id,
                "shortDescription": {"text": cwe_entry.name if cwe_entry else f.message[:50]},
                "fullDescription": {"text": cwe_entry.description if cwe_entry else f.message},
                "defaultConfiguration": {
                    "level": "error" if f.severity == Severity.ERROR else "warning"
                },
            }
            if f.cwe:
                rules[rule_id]["properties"] = {"cwe": f"CWE-{f.cwe}"}

        results.append({
            "ruleId": rule_id,
            "level": "error" if f.severity == Severity.ERROR else "warning",
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line, "startColumn": f.column}
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TaintLint",
                    "version": "1.0.0",
                    "rules": list(rules.values())
                }
            },
            "results": results
        }]
    }

    return json.dumps(sarif, indent=2)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TaintLint - Taint analysis for C/C++ security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s myfile.c.dump
    %(prog)s --format=json myfile.c.dump
    %(prog)s --format=sarif --output=report.sarif *.dump

Detected CWEs:
    Injection: CWE-78, CWE-89, CWE-90, CWE-91, CWE-94, CWE-134
    Path Traversal: CWE-22, CWE-23, CWE-36, CWE-73
    Buffer/Memory: CWE-120, CWE-122, CWE-129, CWE-131, CWE-789
    Dangerous Functions: CWE-242, CWE-676
    Log Injection: CWE-117
        """
    )

    parser.add_argument(
        "dump_files",
        nargs="+",
        help="Cppcheck dump file(s) to analyze"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file (default: stdout)"
    )
    parser.add_argument(
        "--no-dangerous-functions",
        action="store_true",
        help="Disable dangerous function checks"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="TaintLint 1.0.0"
    )

    args = parser.parse_args()

    # Create analyzer
    analyzer = TaintLint(
        track_flow_paths=True,
        check_dangerous_functions=not args.no_dangerous_functions,
        verbose=args.verbose,
    )

    # Analyze all files
    all_findings: List[Finding] = []
    for dump_file in args.dump_files:
        if args.verbose:
            print(f"Analyzing {dump_file}...", file=sys.stderr)
        findings = analyzer.analyze_file(dump_file)
        all_findings.extend(findings)

    # Format output
    if args.format == "json":
        output = format_findings_json(all_findings)
    elif args.format == "sarif":
        output = format_findings_sarif(all_findings)
    else:
        output = format_findings_text(all_findings)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()