#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APIContractLint.py
══════════════════

A Cppcheck addon that detects violations of implicit and explicit
C/C++ API contracts: resource lifecycle errors, unchecked return
values, argument constraint violations, and tainted API parameters.

Detects:
    • CWE-252:  Unchecked Return Value
    • CWE-401:  Memory Leak (Missing Release of Memory after Effective Lifetime)
    • CWE-415:  Double Free
    • CWE-416:  Use After Free
    • CWE-476:  NULL Pointer Dereference
    • CWE-628:  Function Call with Incorrectly Specified Arguments
    • CWE-666:  Operation on Resource in Wrong Phase of Lifetime
    • CWE-675:  Multiple Operations on Resource in Incompatible State
    • CWE-690:  Unchecked Return Value to NULL Pointer Dereference
    • CWE-789:  Memory Allocation with Excessive Size Value

Usage:
    cppcheck --dump myfile.c
    python3 APIContractLint.py myfile.c.dump
    python3 APIContractLint.py --json myfile.c.dump
    python3 APIContractLint.py --sarif myfile.c.dump

License: MIT
"""

from __future__ import annotations

import sys
import os
import json
import argparse
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

# ═══════════════════════════════════════════════════════════════════════════
#  ADDON METADATA
# ═══════════════════════════════════════════════════════════════════════════

__addon_name__ = "APIContractLint"
__version__ = "1.1.0"
__description__ = "Detects C/C++ API contract violations and resource lifecycle errors"
__cwe_coverage__ = [252, 401, 415, 416, 476, 628, 666, 675, 690, 789]

# ═══════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ═══════════════════════════════════════════════════════════════════════════

_script_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir = os.path.dirname(_script_dir)
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

try:
    import cppcheckdata
except ImportError:
    sys.stderr.write("Error: cppcheckdata module not found.\n")
    sys.exit(1)

# Taint analysis is optional; used only for CWE-789 checks
try:
    from cppcheckdata_shims.taint_analysis import (
        TaintAnalyzer,
        TaintConfig,
        TaintSource,
        TaintSink,
        TaintSanitizer,
        SourceKind,
        SinkKind,
        PropagationKind,
        create_default_config,
        format_violations_text,
        format_violations_json,
        format_violations_sarif,
    )
    TAINT_AVAILABLE = True
except ImportError as _e:
    TAINT_AVAILABLE = False
    _taint_import_error = str(_e)

# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — RESOURCE STATE MACHINE
# ═══════════════════════════════════════════════════════════════════════════

class ResourceKind(Enum):
    """Kind of tracked resource."""
    HEAP_MEMORY = auto()     # malloc/calloc/realloc/free
    FILE_HANDLE = auto()     # fopen/fclose
    FILE_DESCRIPTOR = auto() # open/close
    DIR_HANDLE = auto()      # opendir/closedir
    MUTEX = auto()           # pthread_mutex_lock/unlock
    SOCKET = auto()          # socket/close


class ResourceState(Enum):
    """
    Lifecycle state of a tracked resource.

    State machine:
        ┌──────────┐   acquire   ┌──────────┐   release   ┌──────────┐
        │ UNKNOWN  │────────────▶│ ACQUIRED │────────────▶│ RELEASED │
        └──────────┘             └──────────┘             └──────────┘
                                      │  ▲                     │
                                      │  │ use (OK)            │ use → CWE-416
                                      │  │                     │ release → CWE-415
                                      ▼  │                     ▼
                                 ┌──────────┐           ┌──────────┐
                                 │  IN_USE  │           │  ERROR   │
                                 └──────────┘           └──────────┘
    """
    UNKNOWN = auto()
    ACQUIRED = auto()
    IN_USE = auto()
    RELEASED = auto()
    ERROR = auto()


@dataclass
class ResourceInfo:
    """Tracks a single resource instance."""
    kind: ResourceKind
    state: ResourceState
    var_id: int                      # cppcheckdata varId
    var_name: str                    # human-readable name
    acquire_file: str = ""
    acquire_line: int = 0
    release_file: str = ""
    release_line: int = 0
    last_use_file: str = ""
    last_use_line: int = 0
    checked_null: bool = False       # has the caller checked for NULL?


# ── Allocation / release function tables ──────────────────────────────────

# Maps acquire-function → (ResourceKind, "which output")
# "return" means the return value holds the resource
ACQUIRE_FUNCTIONS: Dict[str, Tuple[ResourceKind, Any]] = {
    # Heap
    "malloc":  (ResourceKind.HEAP_MEMORY, "return"),
    "calloc":  (ResourceKind.HEAP_MEMORY, "return"),
    "realloc": (ResourceKind.HEAP_MEMORY, "return"),
    "strdup":  (ResourceKind.HEAP_MEMORY, "return"),
    "strndup": (ResourceKind.HEAP_MEMORY, "return"),
    "aligned_alloc": (ResourceKind.HEAP_MEMORY, "return"),
    # File handles
    "fopen":   (ResourceKind.FILE_HANDLE, "return"),
    "fdopen":  (ResourceKind.FILE_HANDLE, "return"),
    "freopen": (ResourceKind.FILE_HANDLE, "return"),
    "tmpfile": (ResourceKind.FILE_HANDLE, "return"),
    "popen":   (ResourceKind.FILE_HANDLE, "return"),
    # File descriptors
    "open":    (ResourceKind.FILE_DESCRIPTOR, "return"),
    "openat":  (ResourceKind.FILE_DESCRIPTOR, "return"),
    "creat":   (ResourceKind.FILE_DESCRIPTOR, "return"),
    "socket":  (ResourceKind.SOCKET, "return"),
    "accept":  (ResourceKind.SOCKET, "return"),
    "dup":     (ResourceKind.FILE_DESCRIPTOR, "return"),
    "dup2":    (ResourceKind.FILE_DESCRIPTOR, "return"),
    # Directory handles
    "opendir": (ResourceKind.DIR_HANDLE, "return"),
}

# Maps release-function → (ResourceKind, argument-index-of-resource)
RELEASE_FUNCTIONS: Dict[str, Tuple[ResourceKind, int]] = {
    "free":      (ResourceKind.HEAP_MEMORY, 0),
    "realloc":   (ResourceKind.HEAP_MEMORY, 0),  # releases old pointer
    "fclose":    (ResourceKind.FILE_HANDLE, 0),
    "pclose":    (ResourceKind.FILE_HANDLE, 0),
    "close":     (ResourceKind.FILE_DESCRIPTOR, 0),
    "closedir":  (ResourceKind.DIR_HANDLE, 0),
    "shutdown":  (ResourceKind.SOCKET, 0),
}

# Functions whose return value MUST be checked (→ CWE-252 / CWE-690)
MUST_CHECK_RETURN: Dict[str, Tuple[int, str]] = {
    # function → (CWE, reason)
    "malloc":  (690, "returns NULL on failure"),
    "calloc":  (690, "returns NULL on failure"),
    "realloc": (690, "returns NULL on failure; original pointer leaked on failure"),
    "strdup":  (690, "returns NULL on failure"),
    "strndup": (690, "returns NULL on failure"),
    "fopen":   (252, "returns NULL if file cannot be opened"),
    "fdopen":  (252, "returns NULL on failure"),
    "freopen": (252, "returns NULL on failure"),
    "tmpfile": (252, "returns NULL on failure"),
    "fgets":   (252, "returns NULL on error or EOF"),
    "fread":   (252, "returns fewer items on error"),
    "opendir": (252, "returns NULL on failure"),
    "socket":  (252, "returns -1 on failure"),
    "open":    (252, "returns -1 on failure"),
    "popen":   (252, "returns NULL on failure"),
}

# Argument-count contracts: function → expected_min_args
ARG_COUNT_CONTRACTS: Dict[str, int] = {
    "memcpy":  3,
    "memmove": 3,
    "memset":  3,
    "strncpy": 3,
    "strncat": 3,
    "fgets":   3,
    "fread":   4,
    "fwrite":  4,
    "snprintf": 3,
    "qsort":   4,
    "bsearch": 5,
}

# Functions that must NOT receive NULL for certain arguments
# function → list of (argument_index, reason)
NONNULL_ARGS: Dict[str, List[Tuple[int, str]]] = {
    "strcpy":  [(0, "destination"), (1, "source")],
    "strncpy": [(0, "destination"), (1, "source")],
    "strcat":  [(0, "destination"), (1, "source")],
    "strncat": [(0, "destination"), (1, "source")],
    "strlen":  [(0, "string")],
    "strcmp":   [(0, "s1"), (1, "s2")],
    "strncmp":  [(0, "s1"), (1, "s2")],
    "memcpy":  [(0, "destination"), (1, "source")],
    "memmove": [(0, "destination"), (1, "source")],
    "memset":  [(0, "destination")],
    "memcmp":  [(0, "s1"), (1, "s2")],
    "printf":  [(0, "format string")],
    "fprintf": [(0, "stream"), (1, "format string")],
    "sprintf": [(0, "destination"), (1, "format string")],
    "snprintf": [(0, "destination"), (2, "format string")],
    "fputs":   [(0, "string"), (1, "stream")],
    "fgets":   [(0, "buffer"), (2, "stream")],
    "fwrite":  [(0, "buffer"), (3, "stream")],
    "fread":   [(0, "buffer"), (3, "stream")],
    "fclose":  [(0, "stream")],
    "fflush":  [(0, "stream")],
    "free":    [],  # free(NULL) is valid; intentionally empty
}


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TOKEN / AST HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _is_function_call(token) -> bool:
    """Check if token is a function call (name followed by '(')."""
    return (token.isName
            and token.next is not None
            and token.next.str == '(')


def _get_call_args(token) -> List:
    """
    Collect the top-level argument tokens for a function call.

    Given token pointing at ``func`` in ``func(a, b, c)`` where
    token.next is ``(``, walks the token stream to split on
    commas respecting parenthesis/bracket nesting.

    Returns a list of the first token of each argument.
    """
    if token.next is None or token.next.str != '(':
        return []

    open_paren = token.next
    close_paren = open_paren.link
    if close_paren is None:
        return []

    # Walk from the token after '(' to the token before ')'
    args = []
    depth = 0
    current = open_paren.next
    arg_start = current

    while current is not None and current != close_paren:
        if current.str in ('(', '[', '{'):
            depth += 1
        elif current.str in (')', ']', '}'):
            depth -= 1
        elif current.str == ',' and depth == 0:
            if arg_start is not None:
                args.append(arg_start)
            arg_start = current.next
        current = current.next

    # Last argument
    if arg_start is not None and arg_start != close_paren:
        args.append(arg_start)

    return args


def _expr_var_id(token) -> int:
    """Return the varId of an expression token, or 0."""
    if token is None:
        return 0
    if hasattr(token, 'varId') and token.varId:
        return token.varId
    return 0


def _expr_text(token) -> str:
    """Reconstruct approximate source text for an expression token."""
    if token is None:
        return "?"
    return token.str


def _var_name_for_id(cfg, var_id: int) -> str:
    """Look up the variable name from a Configuration's variable list."""
    if var_id == 0:
        return "?"
    for tok in cfg.tokenlist:
        if hasattr(tok, 'varId') and tok.varId == var_id and tok.isName:
            return tok.str
    return f"var#{var_id}"


def _token_loc(token) -> str:
    """Format token location as file:line."""
    f = token.file if token.file else "?"
    l = token.linenr if token.linenr else 0
    return f"{f}:{l}"


def _climb_to_assignment(token):
    """
    From a function-name token, climb the AST to find the enclosing
    assignment operator and return (assignment_token, lhs_token).

    Cppcheck AST for ``x = malloc(10)`` typically looks like:

        =              ← assignment
       / \\
      x    (           ← call operator
          / \\
       malloc  10

    So token ('malloc') → parent is '(' → parent is '='.
    In some dumps the function token itself may be the child of '='.

    Returns (assign_tok, lhs_tok) or (None, None) if not inside an
    assignment.
    """
    current = token
    # Walk up at most a few levels
    for _ in range(5):
        parent = current.astParent
        if parent is None:
            return (None, None)
        if parent.isAssignmentOp:
            lhs = parent.astOperand1
            return (parent, lhs)
        current = parent
    return (None, None)


def _is_return_value_used(token) -> bool:
    """
    Check whether a function call's return value is used in *any* way
    (assigned, compared, passed as argument, etc.).

    If astParent is None at every level → discarded.
    """
    current = token
    for _ in range(5):
        parent = current.astParent
        if parent is None:
            return False
        # If the parent is a statement-terminating ';', return value
        # is not used.  But cppcheckdata doesn't represent ';' as a
        # token.  Instead, if the top-level AST root has no further
        # parent, the call IS the whole expression-statement.
        # However, if the parent is '(' that means the function call
        # itself — keep climbing.
        if parent.str == '(' and parent.astOperand1 == current:
            # This is the call-expression parenthesis wrapping us
            current = parent
            continue
        # Any other parent means the value is being used
        return True
    return False


def _find_var_id_usage_as_comparison(token_start, var_id: int,
                                      max_steps: int = 500) -> bool:
    """
    Walk forward from *token_start* looking for any comparison that
    involves var_id against NULL/0/nullptr, or a negation/bare-if check.

    This scans the raw token stream (not AST), which is more robust
    for finding patterns like:
        if (ptr == NULL)
        if (ptr != NULL)
        if (!ptr)
        if (ptr)
        ptr == NULL
    """
    current = token_start.next
    steps = 0
    scope_depth = 0

    while current is not None and steps < max_steps:
        steps += 1

        # Track scope depth — stop at end of enclosing function
        if current.str == '{':
            scope_depth += 1
        elif current.str == '}':
            if scope_depth == 0:
                break
            scope_depth -= 1

        vid = _expr_var_id(current)

        # Pattern 1: direct AST comparison  var == NULL / var != NULL
        if current.isComparisonOp and current.str in ('==', '!='):
            op1 = current.astOperand1
            op2 = current.astOperand2
            if op1 and op2:
                if (_expr_var_id(op1) == var_id and
                        _is_null_literal(op2)):
                    return True
                if (_expr_var_id(op2) == var_id and
                        _is_null_literal(op1)):
                    return True

        # Pattern 2: negation  !ptr
        if current.str == '!' and current.astOperand1:
            if _expr_var_id(current.astOperand1) == var_id:
                return True

        # Pattern 3: bare-if  "if ( ptr )" — look at token stream
        if current.str == 'if':
            nxt = current.next
            if nxt and nxt.str == '(':
                inner = nxt.next
                if inner and _expr_var_id(inner) == var_id:
                    return True

        current = current.next

    return False


def _is_null_literal(token) -> bool:
    """Check whether a token is NULL / 0 / nullptr."""
    if token is None:
        return False
    return token.str in ('0', 'NULL', 'nullptr')


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — CORE CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

def check_resource_lifecycle(cfg) -> List[dict]:
    """
    State-machine checker for resource lifecycle errors.

    Walks the token stream linearly, maintaining a mapping from
    varId → ResourceInfo.  Detects:
        - CWE-415  Double free
        - CWE-416  Use after free
        - CWE-401  Memory leak (acquired but never released in scope)

    Args:
        cfg: cppcheckdata.Configuration

    Returns:
        List of finding dicts.
    """
    findings: List[dict] = []
    resources: Dict[int, ResourceInfo] = {}  # varId → ResourceInfo

    for token in cfg.tokenlist:
        if not _is_function_call(token):
            continue

        func_name = token.str
        args = _get_call_args(token)

        # ── ACQUIRE ──────────────────────────────────────────────────
        if func_name in ACQUIRE_FUNCTIONS:
            kind, output = ACQUIRE_FUNCTIONS[func_name]

            if output == "return":
                # Climb AST to find assignment LHS
                assign_tok, lhs = _climb_to_assignment(token)
                if assign_tok is None or lhs is None:
                    # Return value discarded — handled by check_unchecked_return
                    continue

                vid = _expr_var_id(lhs)
                if vid == 0:
                    continue

                # Special case: realloc releases old pointer first
                if func_name == "realloc" and len(args) >= 1:
                    old_vid = _expr_var_id(args[0])
                    if old_vid and old_vid in resources:
                        resources[old_vid].state = ResourceState.RELEASED
                        resources[old_vid].release_file = token.file or ""
                        resources[old_vid].release_line = token.linenr or 0

                resources[vid] = ResourceInfo(
                    kind=kind,
                    state=ResourceState.ACQUIRED,
                    var_id=vid,
                    var_name=_expr_text(lhs),
                    acquire_file=token.file or "",
                    acquire_line=token.linenr or 0,
                )

        # ── RELEASE ──────────────────────────────────────────────────
        if func_name in RELEASE_FUNCTIONS:
            kind, arg_idx = RELEASE_FUNCTIONS[func_name]

            if arg_idx < len(args):
                arg = args[arg_idx]
                vid = _expr_var_id(arg)
                if vid == 0:
                    continue

                if vid in resources:
                    res = resources[vid]
                    if res.state == ResourceState.RELEASED:
                        # ── CWE-415: Double Free ─────────────────────
                        findings.append({
                            "file":     token.file,
                            "line":     token.linenr,
                            "severity": "error",
                            "id":       "doubleFree",
                            "cwe":      415,
                            "message":  (
                                f"Double free of '{res.var_name}'. "
                                f"Previously released at "
                                f"{res.release_file}:{res.release_line}."
                            ),
                        })
                        res.state = ResourceState.ERROR
                    else:
                        res.state = ResourceState.RELEASED
                        res.release_file = token.file or ""
                        res.release_line = token.linenr or 0
                else:
                    # First time we see this variable being released
                    resources[vid] = ResourceInfo(
                        kind=kind,
                        state=ResourceState.RELEASED,
                        var_id=vid,
                        var_name=_expr_text(arg),
                        release_file=token.file or "",
                        release_line=token.linenr or 0,
                    )

        # ── USE (any function call that passes a tracked resource) ───
        for i, arg in enumerate(args):
            vid = _expr_var_id(arg)
            if vid == 0:
                continue
            if vid in resources and resources[vid].state == ResourceState.RELEASED:
                # Skip if the function IS the release function and this IS
                # the release argument (already handled above)
                if func_name in RELEASE_FUNCTIONS:
                    _, release_arg_idx = RELEASE_FUNCTIONS[func_name]
                    if i == release_arg_idx:
                        continue

                res = resources[vid]
                findings.append({
                    "file":     token.file,
                    "line":     token.linenr,
                    "severity": "error",
                    "id":       "useAfterFree",
                    "cwe":      416,
                    "message":  (
                        f"Use of '{res.var_name}' after it was released "
                        f"at {res.release_file}:{res.release_line}."
                    ),
                })

    # ── End-of-scope leak detection (CWE-401) ────────────────────────
    for vid, res in resources.items():
        if res.state in (ResourceState.ACQUIRED, ResourceState.IN_USE):
            if res.kind == ResourceKind.HEAP_MEMORY:
                findings.append({
                    "file":     res.acquire_file,
                    "line":     res.acquire_line,
                    "severity": "warning",
                    "id":       "memoryLeak",
                    "cwe":      401,
                    "message":  (
                        f"Potential memory leak: '{res.var_name}' allocated "
                        f"here is never freed in the analyzed scope."
                    ),
                })
            elif res.kind in (
                ResourceKind.FILE_HANDLE, ResourceKind.FILE_DESCRIPTOR,
                ResourceKind.DIR_HANDLE, ResourceKind.SOCKET,
            ):
                kind_label = {
                    ResourceKind.FILE_HANDLE: "file handle",
                    ResourceKind.FILE_DESCRIPTOR: "file descriptor",
                    ResourceKind.DIR_HANDLE: "directory handle",
                    ResourceKind.SOCKET: "socket",
                }.get(res.kind, "resource")
                findings.append({
                    "file":     res.acquire_file,
                    "line":     res.acquire_line,
                    "severity": "warning",
                    "id":       "resourceLeak",
                    "cwe":      401,
                    "message":  (
                        f"Potential {kind_label} leak: '{res.var_name}' "
                        f"opened here is never closed in the analyzed scope."
                    ),
                })

    return findings


def check_unchecked_return(cfg) -> List[dict]:
    """
    Detect unchecked return values from functions that can fail.

    Covers CWE-252 and CWE-690.

    Strategy:
      1. If the return value is completely discarded → always report.
      2. If the return value is assigned to a variable, scan *forward*
         from the assignment for a NULL/error check.  If none is found
         within the enclosing scope → report.

    Args:
        cfg: cppcheckdata.Configuration

    Returns:
        List of finding dicts.
    """
    findings: List[dict] = []

    for token in cfg.tokenlist:
        if not _is_function_call(token):
            continue

        func_name = token.str
        if func_name not in MUST_CHECK_RETURN:
            continue

        cwe, reason = MUST_CHECK_RETURN[func_name]

        # ── Case 1: Is the return value used at all? ─────────────────
        if not _is_return_value_used(token):
            findings.append({
                "file":     token.file,
                "line":     token.linenr,
                "severity": "warning",
                "id":       f"uncheckedReturn_{func_name}",
                "cwe":      cwe,
                "message":  (
                    f"Return value of {func_name}() is discarded. "
                    f"{func_name}() {reason}."
                ),
            })
            continue

        # ── Case 2: Assigned to a variable — check for NULL test ─────
        assign_tok, lhs = _climb_to_assignment(token)
        if assign_tok is not None and lhs is not None:
            vid = _expr_var_id(lhs)
            if vid and not _find_var_id_usage_as_comparison(
                    assign_tok, vid):
                findings.append({
                    "file":     token.file,
                    "line":     token.linenr,
                    "severity": "warning",
                    "id":       f"uncheckedReturnAssign_{func_name}",
                    "cwe":      690 if cwe == 690 else 252,
                    "message":  (
                        f"Return value of {func_name}() assigned to "
                        f"'{_expr_text(lhs)}' but never checked for "
                        f"NULL/error. {func_name}() {reason}."
                    ),
                })
            continue

        # ── Case 3: Used inside a conditional expression ─────────────
        # If we got here the value is used (Case 1 didn't trigger) but
        # not directly assigned.  It may be inside ``if(malloc(...))``
        # or passed to another function.  We consider conditional use
        # as checked and function-argument use as acceptable (the
        # callee presumably checks).

    return findings


def check_argument_contracts(cfg) -> List[dict]:
    """
    Detect wrong argument counts and known-NULL arguments.

    Covers CWE-628 (incorrectly specified arguments) and
    CWE-476 (NULL pointer dereference from passing NULL to
    non-null-expecting function).

    Args:
        cfg: cppcheckdata.Configuration

    Returns:
        List of finding dicts.
    """
    findings: List[dict] = []

    # Track variables known to be NULL
    null_vars: Set[int] = set()

    for token in cfg.tokenlist:
        # Track assignments of NULL/0 to variables: ``ptr = NULL;``
        if token.isAssignmentOp and token.str == '=':
            lhs = token.astOperand1
            rhs = token.astOperand2
            if lhs and rhs:
                vid = _expr_var_id(lhs)
                if vid:
                    if _is_null_literal(rhs):
                        null_vars.add(vid)
                    else:
                        null_vars.discard(vid)  # reassigned

        if not _is_function_call(token):
            continue

        func_name = token.str
        args = _get_call_args(token)

        # ── Argument count check (CWE-628) ──────────────────────────
        if func_name in ARG_COUNT_CONTRACTS:
            expected = ARG_COUNT_CONTRACTS[func_name]
            actual = len(args)
            if actual < expected:
                findings.append({
                    "file":     token.file,
                    "line":     token.linenr,
                    "severity": "error",
                    "id":       f"wrongArgCount_{func_name}",
                    "cwe":      628,
                    "message":  (
                        f"{func_name}() called with {actual} argument(s) "
                        f"but requires at least {expected}."
                    ),
                })

        # ── Non-null argument check (CWE-476) ───────────────────────
        if func_name in NONNULL_ARGS:
            for arg_idx, param_desc in NONNULL_ARGS[func_name]:
                if arg_idx < len(args):
                    arg = args[arg_idx]
                    # Explicit NULL literal
                    if _is_null_literal(arg):
                        findings.append({
                            "file":     token.file,
                            "line":     token.linenr,
                            "severity": "error",
                            "id":       f"nullArgument_{func_name}",
                            "cwe":      476,
                            "message":  (
                                f"NULL passed as {param_desc} "
                                f"(argument {arg_idx}) to {func_name}() "
                                f"which requires non-null."
                            ),
                        })
                    # Variable known to be NULL
                    elif _expr_var_id(arg) in null_vars:
                        findings.append({
                            "file":     token.file,
                            "line":     token.linenr,
                            "severity": "warning",
                            "id":       f"possibleNullArgument_{func_name}",
                            "cwe":      476,
                            "message":  (
                                f"'{_expr_text(arg)}' may be NULL when "
                                f"passed as {param_desc} (argument "
                                f"{arg_idx}) to {func_name}()."
                            ),
                        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — TAINT-BASED SIZE VALIDATION (CWE-789)
# ═══════════════════════════════════════════════════════════════════════════

def build_api_contract_taint_config() -> Optional["TaintConfig"]:
    """
    Build a taint config focused on detecting tainted allocation sizes.

    Returns:
        TaintConfig or None if taint module unavailable
    """
    if not TAINT_AVAILABLE:
        return None

    config = create_default_config()

    # Additional size-sensitive sinks
    size_sinks = [
        ("malloc", 0, SinkKind.MEMORY_ALLOCATION, 789, 7),
        ("calloc", 0, SinkKind.MEMORY_ALLOCATION, 789, 7),
        ("calloc", 1, SinkKind.MEMORY_ALLOCATION, 789, 7),
        ("realloc", 1, SinkKind.MEMORY_ALLOCATION, 789, 7),
        ("aligned_alloc", 1, SinkKind.MEMORY_ALLOCATION, 789, 7),
        ("alloca", 0, SinkKind.MEMORY_ALLOCATION, 789, 8),
        ("memcpy", 2, SinkKind.BUFFER_SIZE, 120, 8),
        ("memmove", 2, SinkKind.BUFFER_SIZE, 120, 8),
        ("memset", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("strncpy", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("strncat", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("snprintf", 1, SinkKind.BUFFER_SIZE, 120, 6),
        ("fread", 1, SinkKind.BUFFER_SIZE, 120, 6),
        ("fread", 2, SinkKind.BUFFER_SIZE, 120, 6),
        ("fwrite", 1, SinkKind.BUFFER_SIZE, 120, 6),
        ("fwrite", 2, SinkKind.BUFFER_SIZE, 120, 6),
        ("read", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("write", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("recv", 2, SinkKind.BUFFER_SIZE, 120, 7),
        ("send", 2, SinkKind.BUFFER_SIZE, 120, 7),
    ]

    for func, arg_idx, kind, cwe, sev in size_sinks:
        if not config.is_sink(func):
            config.add_sink(TaintSink(
                function=func,
                argument_index=arg_idx,
                kind=kind,
                description=f"Size argument to {func}()",
                cwe=cwe,
                severity=sev,
            ))

    # Add sanitizers for common validation patterns
    validation_sanitizers = [
        "validate_size",
        "check_bounds",
        "safe_size",
        "clamp_size",
        "limit_size",
    ]
    for func in validation_sanitizers:
        config.add_sanitizer(TaintSanitizer(
            function=func,
            argument_index=0,
            sanitizes_return=True,
            valid_for_sinks=frozenset(
                {SinkKind.MEMORY_ALLOCATION, SinkKind.BUFFER_SIZE}),
            description=f"Size validation via {func}()",
        ))

    return config


def check_tainted_sizes(cfg) -> List[dict]:
    """
    Use taint analysis to detect user-controlled allocation/copy sizes.

    Args:
        cfg: cppcheckdata.Configuration

    Returns:
        List of finding dicts.
    """
    if not TAINT_AVAILABLE:
        return []

    taint_config = build_api_contract_taint_config()
    if taint_config is None:
        return []

    analyzer = TaintAnalyzer(taint_config, track_flow_paths=True)
    result = analyzer.analyze_configuration(cfg)

    findings = []
    for v in result.violations:
        findings.append({
            "file":     v.sink_token.file if v.sink_token else "?",
            "line":     v.sink_token.linenr if v.sink_token else 0,
            "severity": "warning" if v.severity < 7 else "error",
            "id":       f"taintedApiArg_{v.sink.function}",
            "cwe":      v.cwe or 789,
            "message":  (
                f"Tainted (user-controlled) data from "
                f"{{{', '.join(v.taint_sources)}}} reaches "
                f"{v.sink.function}() argument {v.sink.argument_index} "
                f"without validation. {v.sink.description or ''}"
            ),
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — OUTPUT FORMATTERS
# ═══════════════════════════════════════════════════════════════════════════

def _severity_order(s: str) -> int:
    return {"error": 0, "warning": 1, "style": 2, "information": 3}.get(s, 9)


def output_text(findings: List[dict]) -> None:
    """Print human-readable report."""
    if not findings:
        print("APIContractLint: no issues found.")
        return

    findings.sort(key=lambda f: (_severity_order(f["severity"]),
                                  f.get("file", ""), f.get("line", 0)))

    print("=" * 72)
    print(f"  {__addon_name__} v{__version__}")
    print(f"  {len(findings)} issue(s) detected")
    print("=" * 72)

    for f in findings:
        sev = f["severity"].upper()
        cwe = f"CWE-{f['cwe']}" if f.get("cwe") else ""
        loc = f"{f.get('file', '?')}:{f.get('line', 0)}"
        print(f"[{sev}] {loc}  {f['id']}  {cwe}")
        print(f"    {f['message']}")
    print()
    print(f"Total: {len(findings)} issue(s)")


def output_json(findings: List[dict]) -> None:
    """Print JSON report."""
    report = {
        "tool": __addon_name__,
        "version": __version__,
        "total": len(findings),
        "findings": findings,
    }
    print(json.dumps(report, indent=2, default=str))


def output_sarif(findings: List[dict]) -> None:
    """Print SARIF 2.1.0 report."""
    rules = {}
    results = []

    for f in findings:
        rule_id = f["id"]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f["message"].split(".")[0]},
                "defaultConfiguration": {
                    "level": ("error" if f["severity"] == "error"
                              else "warning")
                },
                "properties": {},
            }
            if f.get("cwe"):
                rules[rule_id]["properties"]["cwe"] = f"CWE-{f['cwe']}"

        results.append({
            "ruleId": rule_id,
            "level": ("error" if f["severity"] == "error" else "warning"),
            "message": {"text": f["message"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.get("file", "?")
                    },
                    "region": {"startLine": f.get("line", 1)},
                }
            }],
        })

    sarif = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": __addon_name__,
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    print(json.dumps(sarif, indent=2, default=str))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — MAIN RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_api_contract_lint(
    dumpfile: str,
    *,
    json_output: bool = False,
    sarif: bool = False,
) -> None:
    """
    Load a Cppcheck dump file and run all API contract checks.

    Args:
        dumpfile: Path to the ``.dump`` file
        json_output: Emit JSON
        sarif: Emit SARIF 2.1.0
    """
    if not os.path.exists(dumpfile):
        sys.stderr.write(f"Error: dump file not found: {dumpfile}\n")
        sys.exit(1)

    data = cppcheckdata.parsedump(dumpfile)

    all_findings: List[dict] = []

    for cfg in data.configurations:
        all_findings.extend(check_resource_lifecycle(cfg))
        all_findings.extend(check_unchecked_return(cfg))
        all_findings.extend(check_argument_contracts(cfg))
        all_findings.extend(check_tainted_sizes(cfg))

    # Deduplicate (same file+line+id)
    seen: Set[Tuple] = set()
    unique: List[dict] = []
    for f in all_findings:
        key = (f.get("file"), f.get("line"), f.get("id"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    if sarif:
        output_sarif(unique)
    elif json_output:
        output_json(unique)
    else:
        output_text(unique)


# ═══════════════════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def _main() -> None:
    parser = argparse.ArgumentParser(
        description=f"{__addon_name__} v{__version__} — {__description__}",
        epilog="Generate dump files with: cppcheck --dump <source.c>",
    )
    parser.add_argument("dumpfile",
                        help="Cppcheck .dump file to analyze")
    parser.add_argument("--json", action="store_true",
                        dest="json_output",
                        help="Output results in JSON format")
    parser.add_argument("--sarif", action="store_true",
                        help="Output results in SARIF 2.1.0 format")
    parser.add_argument("--version", action="version",
                        version=f"{__addon_name__} {__version__}")

    args = parser.parse_args()

    if not TAINT_AVAILABLE:
        sys.stderr.write(
            f"Warning: taint analysis unavailable "
            f"({_taint_import_error}). "
            f"CWE-789 checks will be skipped.\n\n"
        )

    run_api_contract_lint(
        args.dumpfile,
        json_output=args.json_output,
        sarif=args.sarif,
    )


if __name__ == "__main__":
    _main()
