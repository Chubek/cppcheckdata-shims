#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InputValidationLint.py
══════════════════════

A Cppcheck addon for detecting input validation vulnerabilities using
both pattern-based checks and taint analysis.

Detects:
    • CWE-20:  Improper Input Validation
    • CWE-22:  Path Traversal
    • CWE-78:  OS Command Injection
    • CWE-89:  SQL Injection
    • CWE-120: Buffer Copy without Checking Size
    • CWE-134: Format String Vulnerability
    • CWE-242: Use of Inherently Dangerous Function
    • CWE-377: Insecure Temporary File
    • CWE-676: Use of Potentially Dangerous Function
    • CWE-789: Memory Allocation with Excessive Size

Usage:
    # Generate dump file
    cppcheck --dump myfile.c

    # Run addon
    python3 InputValidationLint.py myfile.c.dump

    # JSON output
    python3 InputValidationLint.py --json myfile.c.dump

    # SARIF output (for CI integration)
    python3 InputValidationLint.py --sarif myfile.c.dump

License: MIT
"""

from __future__ import annotations

import sys
import os

# ═══════════════════════════════════════════════════════════════════════════
#  ADDON METADATA
# ═══════════════════════════════════════════════════════════════════════════

__addon_name__ = "InputValidationLint"
__version__ = "1.0.0"
__description__ = "Detects input validation and injection vulnerabilities"
__cwe_coverage__ = [20, 22, 78, 89, 120, 134, 242, 377, 676, 789]

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

# Add parent directory to path for imports if running as standalone
_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_script_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

try:
    import cppcheckdata
except ImportError:
    sys.stderr.write("Error: cppcheckdata module not found.\n")
    sys.stderr.write("Ensure cppcheckdata.py is in the Python path.\n")
    sys.exit(1)

try:
    from cppcheckdata_shims.taint_analysis import (
        TaintAnalyzer,
        TaintConfig,
        TaintSource,
        TaintSink,
        TaintSanitizer,
        TaintPropagator,
        SourceKind,
        SinkKind,
        PropagationKind,
        create_default_config,
        create_sql_injection_config,
        create_xss_config,
        format_violations_text,
        format_violations_json,
        format_violations_sarif,
    )
    TAINT_AVAILABLE = True
except ImportError as e:
    TAINT_AVAILABLE = False
    _taint_import_error = str(e)

# ═══════════════════════════════════════════════════════════════════════════
#  DANGEROUS FUNCTION DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════

# Format: function_name -> (cwe, message, safe_alternative)

INHERENTLY_DANGEROUS = {
    # CWE-242: Use of Inherently Dangerous Function
    "gets": (
        242,
        "gets() cannot limit input length, always causes buffer overflow risk",
        "fgets()",
    ),
}

POTENTIALLY_DANGEROUS = {
    # CWE-676: Use of Potentially Dangerous Function
    "strcpy": (
        676,
        "strcpy() does not check buffer bounds",
        "strncpy() or strlcpy()",
    ),
    "strcat": (
        676,
        "strcat() does not check buffer bounds",
        "strncat() or strlcat()",
    ),
    "sprintf": (
        676,
        "sprintf() does not check buffer bounds",
        "snprintf()",
    ),
    "vsprintf": (
        676,
        "vsprintf() does not check buffer bounds",
        "vsnprintf()",
    ),
    "scanf": (
        676,
        "scanf() can overflow buffers without width specifiers",
        "fgets() + sscanf() with width limits",
    ),
    "sscanf": (
        676,
        "sscanf() can overflow buffers without width specifiers",
        "use width specifiers (e.g., %63s)",
    ),
    "fscanf": (
        676,
        "fscanf() can overflow buffers without width specifiers",
        "use width specifiers",
    ),
    "strtok": (
        676,
        "strtok() is not thread-safe and modifies input",
        "strtok_r()",
    ),
    "getwd": (
        676,
        "getwd() does not check buffer size",
        "getcwd()",
    ),
    "realpath": (
        676,
        "realpath() with NULL second argument may have portability issues",
        "realpath() with explicit buffer",
    ),

    # CWE-377: Insecure Temporary File
    "tmpnam": (
        377,
        "tmpnam() creates predictable file names (race condition)",
        "mkstemp()",
    ),
    "tempnam": (
        377,
        "tempnam() creates predictable file names (race condition)",
        "mkstemp()",
    ),
    "mktemp": (
        377,
        "mktemp() creates predictable file names (race condition)",
        "mkstemp()",
    ),
}

# ═══════════════════════════════════════════════════════════════════════════
#  PATTERN-BASED CHECKER
# ═══════════════════════════════════════════════════════════════════════════

def check_dangerous_functions(cfg):
    """
    Scan the token stream for calls to dangerous C library functions.

    This is a simple pattern-based check that doesn't require taint analysis.

    Args:
        cfg: A cppcheckdata.Configuration object

    Returns:
        List of finding dicts with keys:
            file, line, severity, id, cwe, message
    """
    findings = []

    for token in cfg.tokenlist:
        # Skip non-name tokens
        if not token.isName:
            continue

        # Check if next token is '(' (function call)
        if token.next is None or token.next.str != '(':
            continue

        func_name = token.str

        # Check inherently dangerous functions
        if func_name in INHERENTLY_DANGEROUS:
            cwe, msg, alt = INHERENTLY_DANGEROUS[func_name]
            findings.append({
                "file":     token.file,
                "line":     token.linenr,
                "severity": "error",
                "id":       f"dangerousFunction_{func_name}",
                "cwe":      cwe,
                "message":  f"{msg}. Use {alt} instead." if alt else msg,
            })

        # Check potentially dangerous functions
        elif func_name in POTENTIALLY_DANGEROUS:
            cwe, msg, alt = POTENTIALLY_DANGEROUS[func_name]
            findings.append({
                "file":     token.file,
                "line":     token.linenr,
                "severity": "warning",
                "id":       f"potentiallyDangerousFunction_{func_name}",
                "cwe":      cwe,
                "message":  f"{msg}. Consider using {alt} instead." if alt else msg,
            })

    return findings

# ═══════════════════════════════════════════════════════════════════════════
#  TAINT CONFIGURATION BUILDER
# ═══════════════════════════════════════════════════════════════════════════

def build_input_validation_config():
    """
    Build a comprehensive taint configuration for input validation checking.

    Starts with the default config and adds additional sources, sinks,
    and sanitizers specific to input validation vulnerabilities.

    Returns:
        TaintConfig configured for input validation analysis
    """
    if not TAINT_AVAILABLE:
        return None

    # Start with default config (includes common sources/sinks)
    config = create_default_config()

    # Merge in SQL injection config
    sql_config = create_sql_injection_config()
    config.merge(sql_config)

    # Merge in XSS config
    xss_config = create_xss_config()
    config.merge(xss_config)

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sources
    # ─────────────────────────────────────────────────────────────────

    # Windows-specific input functions
    windows_sources = [
        ("GetCommandLineA", SourceKind.RETURN_VALUE, "Windows command line"),
        ("GetCommandLineW", SourceKind.RETURN_VALUE, "Windows command line (wide)"),
        ("GetEnvironmentVariableA", SourceKind.ARGUMENT_OUT, "Windows environment variable"),
        ("GetEnvironmentVariableW", SourceKind.ARGUMENT_OUT, "Windows environment variable (wide)"),
    ]

    for func, kind, desc in windows_sources:
        config.add_source(TaintSource(
            function=func,
            kind=kind,
            argument_index=1 if kind == SourceKind.ARGUMENT_OUT else -1,
            description=desc,
        ))

    # POSIX extended input
    posix_sources = [
        ("getline", SourceKind.ARGUMENT_OUT, 0, "Dynamic line input"),
        ("getdelim", SourceKind.ARGUMENT_OUT, 0, "Dynamic delimited input"),
        ("pread", SourceKind.ARGUMENT_OUT, 1, "Positional read"),
        ("readv", SourceKind.ARGUMENT_OUT, 1, "Scatter read"),
        ("recvmmsg", SourceKind.ARGUMENT_OUT, 1, "Multiple message receive"),
    ]

    for func, kind, arg_idx, desc in posix_sources:
        config.add_source(TaintSource(
            function=func,
            kind=kind,
            argument_index=arg_idx,
            description=desc,
        ))

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sanitizers
    # ─────────────────────────────────────────────────────────────────

    # Common validation function patterns (application-specific)
    custom_sanitizers = [
        ("validate_input", 0, True, frozenset(), "Generic input validation"),
        ("sanitize_string", 0, True, frozenset(), "String sanitization"),
        ("escape_shell", 0, True, frozenset({SinkKind.COMMAND_INJECTION}), "Shell escaping"),
        ("escape_sql", 0, True, frozenset({SinkKind.SQL_INJECTION}), "SQL escaping"),
        ("sanitize_path", 0, True, frozenset({SinkKind.PATH_TRAVERSAL}), "Path sanitization"),
        ("validate_path", 0, True, frozenset({SinkKind.PATH_TRAVERSAL}), "Path validation"),
        ("html_escape", 0, True, frozenset({SinkKind.XSS}), "HTML escaping"),
        ("url_encode", 0, True, frozenset({SinkKind.XSS, SinkKind.HEADER_INJECTION}), "URL encoding"),
    ]

    for func, arg_idx, sanitizes_ret, valid_for, desc in custom_sanitizers:
        config.add_sanitizer(TaintSanitizer(
            function=func,
            argument_index=arg_idx,
            sanitizes_return=sanitizes_ret,
            valid_for_sinks=valid_for,
            description=desc,
        ))

    # ─────────────────────────────────────────────────────────────────
    #  Additional Sinks (defense in depth)
    # ─────────────────────────────────────────────────────────────────

    # Dynamic library loading
    config.add_sink(TaintSink(
        function="dlopen",
        argument_index=0,
        kind=SinkKind.CODE_INJECTION,
        description="Dynamic library path",
        cwe=427,
        severity=9,
    ))

    # Logging (potential log injection)
    log_functions = ["syslog", "openlog", "LOG", "log_message"]
    for func in log_functions:
        if not config.is_sink(func):  # Don't duplicate
            config.add_sink(TaintSink(
                function=func,
                argument_index=-1,  # Any argument
                kind=SinkKind.LOG_INJECTION,
                description="Log output",
                cwe=117,
                severity=4,
            ))

    return config

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ANALYSIS RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_input_validation_lint(dumpfile, json_output=False, sarif=False):
    """
    Main entry point: load a Cppcheck .dump file and run all checks.

    Args:
        dumpfile:    Path to the .dump file produced by ``cppcheck --dump``
        json_output: If True, print results as JSON
        sarif:       If True, print results as SARIF 2.1.0
    """
    # ── 1. Load the dump file ───────────────────────────────────────
    if not os.path.exists(dumpfile):
        sys.stderr.write(f"Error: Dump file not found: {dumpfile}\n")
        sys.exit(1)

    data = cppcheckdata.parsedump(dumpfile)

    all_pattern_findings = []
    all_taint_violations = []

    # ── 2. Iterate over every configuration in the dump ─────────────
    for cfg in data.configurations:

        # ── 2a. Pattern-based dangerous-function check ──────────────
        pattern_findings = check_dangerous_functions(cfg)
        all_pattern_findings.extend(pattern_findings)

        # ── 2b. Taint analysis (if available) ───────────────────────
        if TAINT_AVAILABLE:
            taint_config = build_input_validation_config()
            if taint_config:
                analyzer = TaintAnalyzer(taint_config, track_flow_paths=True)
                result = analyzer.analyze_configuration(cfg)
                all_taint_violations.extend(result.violations)

    # ── 3. Output results ───────────────────────────────────────────
    if sarif:
        _output_sarif(all_pattern_findings, all_taint_violations)
    elif json_output:
        _output_json(all_pattern_findings, all_taint_violations)
    else:
        _output_text(all_pattern_findings, all_taint_violations)

# ═══════════════════════════════════════════════════════════════════════════
#  OUTPUT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════

def _output_text(pattern_findings, taint_violations):
    """Output results as human-readable text."""
    if pattern_findings:
        print("=" * 70)
        print("  DANGEROUS FUNCTION USAGE (Pattern Checker)")
        print("=" * 70)
        for f in pattern_findings:
            cwe_tag = f"CWE-{f['cwe']}" if f['cwe'] else ""
            severity = f['severity'].upper()
            print(f"[{severity}] {f['file']}:{f['line']}  {f['id']}  {cwe_tag}")
            print(f"    {f['message']}")
        print()

    if taint_violations and TAINT_AVAILABLE:
        print(format_violations_text(taint_violations))

    if not pattern_findings and not taint_violations:
        print("No issues found.")

    # Summary
    total = len(pattern_findings) + len(taint_violations)
    if total > 0:
        print("-" * 70)
        print(f"Total: {total} issue(s) found")
        print(f"  - Pattern-based:  {len(pattern_findings)}")
        print(f"  - Taint analysis: {len(taint_violations)}")


def _output_json(pattern_findings, taint_violations):
    """Output results as JSON."""
    import json

    report = {
        "tool": __addon_name__,
        "version": __version__,
        "pattern_findings": [
            {
                "file":     f["file"],
                "line":     f["line"],
                "severity": f["severity"],
                "id":       f["id"],
                "cwe":      f["cwe"],
                "message":  f["message"],
            }
            for f in pattern_findings
        ],
        "taint_violations": [],
    }

    if taint_violations and TAINT_AVAILABLE:
        # Parse the JSON from format_violations_json
        import json as json_module
        taint_json_str = format_violations_json(taint_violations)
        taint_data = json_module.loads(taint_json_str)
        report["taint_violations"] = taint_data.get("violations", [])

    print(json.dumps(report, indent=2))


def _output_sarif(pattern_findings, taint_violations):
    """Output results as SARIF 2.1.0."""
    import json

    # Convert pattern findings to pseudo-violations for SARIF
    runs = []

    # Pattern checker results
    if pattern_findings:
        pattern_rules = {}
        pattern_results = []

        for f in pattern_findings:
            rule_id = f["id"]
            if rule_id not in pattern_rules:
                pattern_rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f["message"].split(".")[0]},
                    "defaultConfiguration": {
                        "level": "error" if f["severity"] == "error" else "warning"
                    },
                    "properties": {}
                }
                if f["cwe"]:
                    pattern_rules[rule_id]["properties"]["cwe"] = f"CWE-{f['cwe']}"

            pattern_results.append({
                "ruleId": rule_id,
                "level": "error" if f["severity"] == "error" else "warning",
                "message": {"text": f["message"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["line"]}
                    }
                }]
            })

        runs.append({
            "tool": {
                "driver": {
                    "name": f"{__addon_name__} (Pattern Checker)",
                    "version": __version__,
                    "rules": list(pattern_rules.values())
                }
            },
            "results": pattern_results
        })

    # Taint analysis results
    if taint_violations and TAINT_AVAILABLE:
        taint_sarif = format_violations_sarif(
            taint_violations,
            tool_name=f"{__addon_name__} (Taint Analysis)",
            tool_version=__version__,
        )
        taint_data = json.loads(taint_sarif)
        runs.extend(taint_data.get("runs", []))

    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    }

    print(json.dumps(sarif_output, indent=2))

# ═══════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def _main():
    """Command-line entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description=f"{__addon_name__} v{__version__} — {__description__}",
        epilog="Generate dump files with: cppcheck --dump <source.c>",
    )
    parser.add_argument(
        "dumpfile",
        help="Cppcheck .dump file to analyze"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Output results in SARIF 2.1.0 format"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__addon_name__} {__version__}"
    )

    args = parser.parse_args()

    # Warn if taint analysis is not available
    if not TAINT_AVAILABLE:
        sys.stderr.write(f"Warning: Taint analysis unavailable: {_taint_import_error}\n")
        sys.stderr.write("Only pattern-based checks will be performed.\n\n")

    run_input_validation_lint(
        args.dumpfile,
        json_output=args.json,
        sarif=args.sarif,
    )


if __name__ == "__main__":
    _main()
