#!/usr/bin/env python3
"""
AtomicCorrectnessLint.py
════════════════════════════════════════════════════════════════════════════

Cppcheck addon: atomic-correctness-lint
Tier 2 | CWE-252, CWE-362, CWE-366, CWE-479, CWE-667, CWE-764

Detects incorrect use of C11 <stdatomic.h> primitives and POSIX
sig_atomic_t in C source code.

Background
──────────
C11 atomics provide sequential consistency by default, but their
correct use requires discipline that the C type system cannot enforce:

  - The programmer must choose memory-order arguments that actually
    provide the required synchronisation guarantees.
  - Every atomic_flag used as a spinlock must be released on every
    code path.
  - atomic_compare_exchange_* communicates success/failure through its
    return value; discarding that value silently ignores failure.
  - Copying a struct containing _Atomic members to a local variable
    breaks the atomicity guarantee for subsequent accesses.
  - A memory fence is vacuous if no atomic operation is visible in the
    same scope.
  - sig_atomic_t is only safe in a signal handler when declared volatile;
    the volatile qualifier prevents the compiler from caching the value
    in a register across signal delivery.

Checkers
────────
  ACL-01  atomicLoadStoreMismatch       CWE-362  Plain atomic_store where
                                                  a RMW (fetch_add/CAS) is
                                                  required: TOCTOU window
  ACL-02  nonAtomicAccessOnAtomic       CWE-366  Direct assignment (=) or
                                                  arithmetic (++/--/+=) on
                                                  _Atomic-qualified variable
  ACL-03  relaxedOrderOnSeqCst          CWE-362  memory_order_relaxed used
                                                  on a variable that is also
                                                  accessed with a stronger
                                                  order in the same TU
  ACL-04  doubleLockAtomic              CWE-667  Atomic flag acquired twice
                                                  without intervening clear
  ACL-05  atomicFlagWithoutClear        CWE-764  atomic_flag_test_and_set
                                                  site with no reachable
                                                  atomic_flag_clear
  ACL-06  sigAtomicNonVolatile          CWE-366  sig_atomic_t variable
                                                  lacks volatile qualifier
  ACL-07  atomicCmpXchgIgnored          CWE-252  Return value of
                                                  atomic_compare_exchange_
                                                  strong/weak not checked
  ACL-08  atomicOnStackStructCopy       CWE-362  _Atomic struct member
                                                  accessed via a local
                                                  (non-atomic) copy
  ACL-09  fenceWithoutAtomicOp          CWE-362  atomic_thread_fence /
                                                  atomic_signal_fence with
                                                  no atomic load/store
                                                  visible in the same scope
  ACL-10  atomicInSignalHandler         CWE-479  Non-sig_atomic_t atomic
                                                  operation inside a
                                                  signal-handler function

CONTRACT — Safe Variable-ID Access
───────────────────────────────────
ALL variable-ID access MUST use _safe_vid() or _safe_vid_tok().
Direct int(tok.varId) calls are FORBIDDEN.

Rationale: cppcheckdata returns varId as decimal strings, hex address
strings ("560e31248150" — ValueError), None, or sentinel 0 (meaning
"no variable").  _safe_vid() normalises all cases to Optional[int],
returning None for the sentinel and non-decimal strings.

Usage
─────
    cppcheck --dump myfile.c
    python AtomicCorrectnessLint.py myfile.c.dump

License: MIT
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
)

try:
    import cppcheckdata
except ImportError:
    sys.stderr.write("ERROR: cppcheckdata module not found.\n")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — SAFE VARIABLE-ID HELPERS  (hardening mandate)
# ═══════════════════════════════════════════════════════════════════════════

def _safe_vid(vid: Any) -> Optional[int]:
    """
    Safely convert a raw varId value to int.

    Returns None for:
      - None input
      - non-decimal strings (hex address strings like '560e31248150')
      - cppcheck sentinel value 0  ("no variable")

    NEVER call int(tok.varId) directly anywhere in this addon.
    """
    if vid is None:
        return None
    try:
        v = int(vid)
        return v if v != 0 else None
    except (ValueError, TypeError):
        return None


def _safe_vid_tok(tok: Any) -> Optional[int]:
    """Return the safe variable-ID for a token, or None."""
    return _safe_vid(getattr(tok, "varId", None))


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — TOKEN / SCOPE UTILITIES
# ═══════════════════════════════════════════════════════════════════════════

def _tok_str(tok: Any) -> str:
    return getattr(tok, "str", "") or ""

def _tok_file(tok: Any) -> str:
    return getattr(tok, "file", "") or ""

def _tok_line(tok: Any) -> int:
    return int(getattr(tok, "linenr", 0) or 0)

def _tok_col(tok: Any) -> int:
    return int(getattr(tok, "column", 0) or 0)

def _tok_next(tok: Any) -> Optional[Any]:
    return getattr(tok, "next", None)

def _tok_prev(tok: Any) -> Optional[Any]:
    return getattr(tok, "previous", None)

def _tok_scope(tok: Any) -> Optional[Any]:
    return getattr(tok, "scope", None)

def _scope_type(scope: Any) -> str:
    return getattr(scope, "type", "") or ""

def _tok_order(tok: Any) -> Tuple[str, int, int]:
    """Sortable (file, line, col) key for a token."""
    return (_tok_file(tok), _tok_line(tok), _tok_col(tok))

def _tok_before(a: Any, b: Any) -> bool:
    return _tok_order(a) < _tok_order(b)

def _is_function_call(tok: Any) -> bool:
    """Return True if tok is the name token of a function call."""
    if not getattr(tok, "isName", False):
        return False
    nxt = _tok_next(tok)
    return nxt is not None and _tok_str(nxt) == "("


def _enclosing_scope_of_type(tok: Any, *types: str) -> Optional[Any]:
    """Walk the scope chain and return the first scope with type in types."""
    s = _tok_scope(tok)
    while s is not None:
        if _scope_type(s) in types:
            return s
        s = getattr(s, "nestedIn", None)
    return None


def _enclosing_function_scope(tok: Any) -> Optional[Any]:
    return _enclosing_scope_of_type(tok, "Function")


def _same_function(a: Any, b: Any) -> bool:
    sa = _enclosing_function_scope(a)
    sb = _enclosing_function_scope(b)
    return sa is not None and sa is sb


def _call_arg_tokens(call_name_tok: Any) -> List[Any]:
    """
    Return the positional argument tokens for a function call.

    Uses the AST: open-paren's astOperand2 is the first arg (or a comma
    tree for multiple args).  Returns [] if no arguments.
    """
    nxt = _tok_next(call_name_tok)
    if nxt is None or _tok_str(nxt) != "(":
        return []
    first = getattr(nxt, "astOperand2", None)
    if first is None:
        return []

    args: List[Any] = []

    def _collect(node: Any) -> None:
        if node is None:
            return
        if _tok_str(node) == ",":
            _collect(getattr(node, "astOperand1", None))
            _collect(getattr(node, "astOperand2", None))
        else:
            args.append(node)

    _collect(first)
    return args


def _tokens_in_scope(cfg: Any, scope: Any) -> List[Any]:
    """Return all tokens whose immediate scope is `scope`."""
    return [
        tok for tok in getattr(cfg, "tokenlist", [])
        if _tok_scope(tok) is scope
    ]


def _tokens_in_function(cfg: Any, fn_scope: Any) -> List[Any]:
    """
    Return all tokens that are lexically inside the function body,
    including nested scopes (if/while/for blocks inside the function).
    """
    result: List[Any] = []
    for tok in getattr(cfg, "tokenlist", []):
        s = _tok_scope(tok)
        while s is not None:
            if s is fn_scope:
                result.append(tok)
                break
            if _scope_type(s) == "Function":
                # A different function — stop walking
                break
            s = getattr(s, "nestedIn", None)
    return result


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — DOMAIN CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

# ── C11 atomic load/store/RMW functions ─────────────────────────────────

_ATOMIC_LOAD_FNS: FrozenSet[str] = frozenset({
    "atomic_load",
    "atomic_load_explicit",
})

_ATOMIC_STORE_FNS: FrozenSet[str] = frozenset({
    "atomic_store",
    "atomic_store_explicit",
})

_ATOMIC_RMW_FNS: FrozenSet[str] = frozenset({
    "atomic_exchange",
    "atomic_exchange_explicit",
    "atomic_fetch_add",
    "atomic_fetch_add_explicit",
    "atomic_fetch_sub",
    "atomic_fetch_sub_explicit",
    "atomic_fetch_and",
    "atomic_fetch_and_explicit",
    "atomic_fetch_or",
    "atomic_fetch_or_explicit",
    "atomic_fetch_xor",
    "atomic_fetch_xor_explicit",
})

_ATOMIC_CAS_FNS: FrozenSet[str] = frozenset({
    "atomic_compare_exchange_strong",
    "atomic_compare_exchange_strong_explicit",
    "atomic_compare_exchange_weak",
    "atomic_compare_exchange_weak_explicit",
})

_ATOMIC_FLAG_ACQUIRE_FNS: FrozenSet[str] = frozenset({
    "atomic_flag_test_and_set",
    "atomic_flag_test_and_set_explicit",
})

_ATOMIC_FLAG_RELEASE_FNS: FrozenSet[str] = frozenset({
    "atomic_flag_clear",
    "atomic_flag_clear_explicit",
})

_ATOMIC_FLAG_FNS: FrozenSet[str] = (
    _ATOMIC_FLAG_ACQUIRE_FNS | _ATOMIC_FLAG_RELEASE_FNS
)

_FENCE_FNS: FrozenSet[str] = frozenset({
    "atomic_thread_fence",
    "atomic_signal_fence",
})

# All C11 atomic operation functions (load + store + RMW + CAS + flag)
_ALL_ATOMIC_OPS: FrozenSet[str] = (
    _ATOMIC_LOAD_FNS
    | _ATOMIC_STORE_FNS
    | _ATOMIC_RMW_FNS
    | _ATOMIC_CAS_FNS
    | _ATOMIC_FLAG_FNS
    | _FENCE_FNS
)

# ── memory_order tokens ──────────────────────────────────────────────────

_RELAXED = "memory_order_relaxed"
_ACQUIRE = "memory_order_acquire"
_RELEASE = "memory_order_release"
_ACQ_REL = "memory_order_acq_rel"
_SEQ_CST = "memory_order_seq_cst"
_CONSUME = "memory_order_consume"

_STRONG_ORDERS: FrozenSet[str] = frozenset({
    _ACQUIRE, _RELEASE, _ACQ_REL, _SEQ_CST, _CONSUME,
})

# ── signal() registration ────────────────────────────────────────────────

_SIGNAL_REGISTRATION_FNS: FrozenSet[str] = frozenset({
    "signal",
    "sigaction",   # struct sigaction.sa_handler / sa_sigaction
    "bsd_signal",
})

# ── Non-signal-safe atomic types ────────────────────────────────────────
# These are fine in normal code but not in signal handlers
# (only sig_atomic_t and volatile sig_atomic_t are signal-safe).

_NON_SIGNAL_SAFE_ATOMIC_OPS: FrozenSet[str] = (
    _ATOMIC_LOAD_FNS
    | _ATOMIC_STORE_FNS
    | _ATOMIC_RMW_FNS
    | _ATOMIC_CAS_FNS
    | _ATOMIC_FLAG_FNS
)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 4 — VARIABLE CLASSIFICATION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _var_type_str(tok: Any) -> str:
    """
    Best-effort: return the type string of the variable referenced by tok.

    Tries:
      1. tok.variable.type.str
      2. tok.valueType.originalTypeName
      3. tok.valueType.type
    Returns "" if nothing is available.
    """
    var = getattr(tok, "variable", None)
    if var is not None:
        vt = getattr(var, "type", None)
        if vt is not None:
            s = getattr(vt, "str", None) or ""
            if s:
                return s

    vt2 = getattr(tok, "valueType", None)
    if vt2 is not None:
        s = getattr(vt2, "originalTypeName", None) or ""
        if s:
            return s
        s = str(getattr(vt2, "type", "") or "")
        if s:
            return s

    return ""


def _is_atomic_qualified(tok: Any) -> bool:
    """
    Return True if the token references a variable with _Atomic type
    qualification.

    Checks:
      - type string contains "_Atomic" or "atomic_" prefix
      - Variable.isAtomic (cppcheck >= 2.10 sets this for C11 atomics)
    """
    var = getattr(tok, "variable", None)
    if var is not None:
        if getattr(var, "isAtomic", False):
            return True

    ts = _var_type_str(tok)
    if "_Atomic" in ts or ts.startswith("atomic_"):
        return True

    # Check the valueType
    vt = getattr(tok, "valueType", None)
    if vt is not None:
        if getattr(vt, "isAtomic", False):
            return True
        orig = getattr(vt, "originalTypeName", "") or ""
        if "_Atomic" in orig or orig.startswith("atomic_"):
            return True

    return False


def _is_sig_atomic_t(tok: Any) -> bool:
    """Return True if tok's variable has type sig_atomic_t."""
    ts = _var_type_str(tok)
    return "sig_atomic_t" in ts


def _is_volatile(tok: Any) -> bool:
    """Return True if tok's variable is declared volatile."""
    var = getattr(tok, "variable", None)
    if var is not None:
        if getattr(var, "isVolatile", False):
            return True
    ts = _var_type_str(tok)
    return "volatile" in ts


def _is_global_or_static(tok: Any) -> bool:
    var = getattr(tok, "variable", None)
    if var is None:
        return False
    return (
        getattr(var, "isGlobal", False)
        or getattr(var, "isStatic", False)
    )


def _is_local_non_atomic(tok: Any) -> bool:
    var = getattr(tok, "variable", None)
    if var is None:
        return False
    return (
        getattr(var, "isLocal", False)
        and not getattr(var, "isStatic", False)
        and not _is_atomic_qualified(tok)
    )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 5 — MEMORY-ORDER ARGUMENT EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def _memory_order_arg(call_tok: Any, arg_index: int) -> Optional[str]:
    """
    Return the memory_order constant string for the given argument index
    of a call, or None if the argument is not a memory_order constant or
    does not exist.

    arg_index is 0-based from the start of the argument list.
    """
    args = _call_arg_tokens(call_tok)
    if arg_index >= len(args):
        return None
    arg = args[arg_index]
    s = _tok_str(arg)
    if s.startswith("memory_order_"):
        return s
    return None


def _any_memory_order_arg(call_tok: Any) -> Optional[str]:
    """Return the first memory_order_* token in the argument list."""
    args = _call_arg_tokens(call_tok)
    for arg in args:
        s = _tok_str(arg)
        if s.startswith("memory_order_"):
            return s
    return None


def _first_arg_vid(call_tok: Any) -> Optional[int]:
    """Return _safe_vid of the first argument of a call, or None."""
    args = _call_arg_tokens(call_tok)
    if not args:
        return None
    # First arg is often a pointer: &counter — strip address-of operator
    first = args[0]
    if _tok_str(first) == "&":
        operand = getattr(first, "astOperand1", None)
        if operand is None:
            operand = getattr(first, "astOperand2", None)
        if operand is not None:
            return _safe_vid_tok(operand)
    return _safe_vid_tok(first)


def _first_arg_tok(call_tok: Any) -> Optional[Any]:
    """Return the first argument token (stripping &)."""
    args = _call_arg_tokens(call_tok)
    if not args:
        return None
    first = args[0]
    if _tok_str(first) == "&":
        op = getattr(first, "astOperand1", None) or \
             getattr(first, "astOperand2", None)
        return op
    return first


# ═══════════════════════════════════════════════════════════════════════════
#  PART 6 — RETURN-VALUE-CHECKED HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _return_value_checked(call_name_tok: Any) -> bool:
    """
    Return True if the return value of the function call starting at
    call_name_tok is consumed (assigned, compared, or passed as argument).

    We check the AST parent of the open-paren token.
    """
    open_paren = _tok_next(call_name_tok)
    if open_paren is None or _tok_str(open_paren) != "(":
        return False

    # Try the parent of the open-paren node first
    parent = getattr(open_paren, "astParent", None)

    # Also try the parent of the call-name token itself
    if parent is None:
        parent = getattr(call_name_tok, "astParent", None)

    if parent is None:
        return False  # bare statement — return value discarded

    ps = _tok_str(parent)

    # Assignment
    if getattr(parent, "isAssignmentOp", False):
        return True
    # Comparison operator
    if ps in {"==", "!=", "<", ">", "<=", ">="}:
        return True
    # Logical operators (used in conditions)
    if ps in {"&&", "||", "!"}:
        return True
    # Ternary / conditional
    if ps == "?":
        return True
    # Comma in argument list — passed to another function
    if ps == ",":
        return True
    # Used as a condition directly (if/while/for)
    if ps in {"if", "while", "for"}:
        return True
    # Explicit cast
    if ps == "(":
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 7 — SIGNAL HANDLER REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

def _collect_signal_handler_names(cfg: Any) -> Set[str]:
    """
    Return the set of function names registered as signal handlers via
    signal() or sigaction() calls in this translation unit.

    Handles:
      signal(SIGINT, my_handler)       → "my_handler"
      sigaction(SIGINT, &act, NULL)    → not directly traceable here;
                                         we only cover the direct signal()
                                         pattern for the addon's scope.
    """
    handlers: Set[str] = set()
    for tok in getattr(cfg, "tokenlist", []):
        if _tok_str(tok) != "signal":
            continue
        if not _is_function_call(tok):
            continue
        args = _call_arg_tokens(tok)
        if len(args) < 2:
            continue
        handler_arg = args[1]
        # Common form: signal(SIG, handler_name)
        if getattr(handler_arg, "isName", False):
            handlers.add(_tok_str(handler_arg))
        # Also handle: signal(SIG, &handler_name)
        elif _tok_str(handler_arg) == "&":
            op = getattr(handler_arg, "astOperand1", None) or \
                 getattr(handler_arg, "astOperand2", None)
            if op and getattr(op, "isName", False):
                handlers.add(_tok_str(op))
    return handlers


def _function_name_from_scope(fn_scope: Any) -> Optional[str]:
    """Return the name of the function owning a Function scope."""
    fn_obj = getattr(fn_scope, "function", None)
    if fn_obj is not None:
        name = getattr(fn_obj, "name", None)
        if name:
            return name
    # Fallback: className attribute used on some cppcheck versions
    return getattr(fn_scope, "className", None)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 8 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════

ADDON_NAME = "AtomicCorrectnessLint"


@dataclass(frozen=True)
class _Finding:
    error_id: str
    message:  str
    cwe:      int
    file:     str
    line:     int
    column:   int = 0
    severity: str = "warning"
    extra:    str = ""

    def emit(self) -> None:
        obj = {
            "file":     self.file,
            "linenr":   self.line,
            "column":   self.column,
            "severity": self.severity,
            "message":  self.message,
            "addon":    ADDON_NAME,
            "errorId":  self.error_id,
            "cwe":      self.cwe,
            "extra":    self.extra,
        }
        sys.stdout.write(json.dumps(obj) + "\n")


# ═══════════════════════════════════════════════════════════════════════════
#  PART 9 — BASE CHECKER
# ═══════════════════════════════════════════════════════════════════════════

class _BaseChecker:
    """Abstract base.  All varId access via _safe_vid / _safe_vid_tok."""
    error_id: str = ""
    cwe:      int  = 0
    severity: str  = "warning"

    def __init__(self) -> None:
        self._findings: List[_Finding] = []

    def check(self, cfg: Any) -> None:
        raise NotImplementedError

    def _emit(
        self,
        tok:      Any,
        message:  str,
        error_id: Optional[str] = None,
        cwe:      Optional[int] = None,
        severity: Optional[str] = None,
        extra:    str = "",
    ) -> None:
        self._findings.append(_Finding(
            error_id = error_id  or self.error_id,
            message  = message,
            cwe      = cwe       or self.cwe,
            file     = _tok_file(tok),
            line     = _tok_line(tok),
            column   = _tok_col(tok),
            severity = severity  or self.severity,
            extra    = extra,
        ))

    @property
    def findings(self) -> List[_Finding]:
        return list(self._findings)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 10 — INDIVIDUAL CHECKERS
# ═══════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────
#  ACL-01  atomicLoadStoreMismatch  (CWE-362)
#
#  Detects the classic atomic TOCTOU pattern:
#
#    val = atomic_load(&counter);   ← load
#    if (val < LIMIT)
#        atomic_store(&counter, val + 1);  ← store based on loaded value
#
#  This is NOT atomic.  The correct idiom is atomic_fetch_add or a CAS
#  loop.  We flag atomic_store calls whose stored value is derived (in
#  the same function) from a preceding atomic_load of the SAME variable.
#
#  Detection:
#    For each function, collect (varId → list of load-site tokens) and
#    (varId → list of store-site tokens where stored value references a
#    variable that was assigned from a load).
#    Flag stores whose value token's varId was loaded from the same
#    atomic object.
#
#  Conservative: we only flag when the load-derived variable is used
#  directly as the stored value (one assignment step).
# ─────────────────────────────────────────────────────────────────────────

class _ACL01_AtomicLoadStoreMismatch(_BaseChecker):
    error_id = "atomicLoadStoreMismatch"
    cwe      = 362
    severity = "warning"

    def check(self, cfg: Any) -> None:
        tlist = list(getattr(cfg, "tokenlist", []))
        seen: Set[Tuple[str, int]] = set()

        # Map: result_varId → (atomic_obj_varId, load_tok)
        # Populated when we see: result = atomic_load(&obj)
        load_results: Dict[int, Tuple[int, Any]] = {}

        for tok in tlist:
            ts = _tok_str(tok)

            # ── Track load results ────────────────────────────────────
            if ts in _ATOMIC_LOAD_FNS and _is_function_call(tok):
                obj_vid = _first_arg_vid(tok)
                if obj_vid is None:
                    continue
                # The call is the RHS of an assignment?
                open_p = _tok_next(tok)
                if open_p is None:
                    continue
                parent = getattr(open_p, "astParent", None)
                if parent is None:
                    parent = getattr(tok, "astParent", None)
                if parent is not None and getattr(parent,
                                                   "isAssignmentOp",
                                                   False):
                    lhs = getattr(parent, "astOperand1", None)
                    if lhs is not None:
                        result_vid = _safe_vid_tok(lhs)
                        if result_vid is not None:
                            load_results[result_vid] = (obj_vid, tok)

            # ── Check stores whose value came from a load ─────────────
            elif ts in _ATOMIC_STORE_FNS and _is_function_call(tok):
                args = _call_arg_tokens(tok)
                if len(args) < 2:
                    continue
                obj_vid  = _first_arg_vid(tok)
                val_arg  = args[1]

                # Walk the value token's AST to find the leaf variable
                val_vid  = _safe_vid_tok(val_arg)

                # Also check simple binary expressions: val + 1, val - delta
                # by inspecting the AST operands one level deep
                if val_vid is None:
                    op1 = getattr(val_arg, "astOperand1", None)
                    op2 = getattr(val_arg, "astOperand2", None)
                    if op1 is not None:
                        val_vid = _safe_vid_tok(op1)
                    if val_vid is None and op2 is not None:
                        val_vid = _safe_vid_tok(op2)

                if val_vid is None or obj_vid is None:
                    continue

                if val_vid not in load_results:
                    continue

                src_obj_vid, load_tok = load_results[val_vid]
                if src_obj_vid != obj_vid:
                    continue  # different atomic object
                if not _same_function(tok, load_tok):
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                load_line = _tok_line(load_tok)
                self._emit(
                    tok,
                    f"'atomic_store()' stores a value derived from a "
                    f"preceding 'atomic_load()' at line {load_line} on "
                    f"the same atomic object (varId={obj_vid}); this is a "
                    f"load-store TOCTOU race — use 'atomic_fetch_add()', "
                    f"'atomic_fetch_sub()', or a CAS loop instead (CWE-362).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-02  nonAtomicAccessOnAtomic  (CWE-366)
#
#  A variable declared with _Atomic qualification is accessed via a
#  plain assignment operator (=), pre/post increment (++/--), or
#  compound assignment (+=, -=, &=, |=, ^=) rather than the designated
#  atomic_store / atomic_fetch_* functions.
#
#  Plain assignment on _Atomic types is technically defined behaviour in
#  C11 (it uses seq_cst), BUT:
#    - It bypasses the explicit memory-order parameter, making the
#      ordering invisible in code review.
#    - Many older compilers and MSVC do NOT implement C11 atomic
#      assignment correctly — they generate non-atomic LD/ST pairs for
#      structs.
#    - Mixing atomic_ function calls with plain assignment on the same
#      variable makes auditing impossible.
#
#  We flag plain = and compound-assignment on _Atomic-qualified tokens.
#
#  Detection:
#    For every assignment/increment token whose LHS (or operand) is
#    _Atomic-qualified, flag if NOT inside an atomic_* call's argument
#    list.
# ─────────────────────────────────────────────────────────────────────────

class _ACL02_NonAtomicAccessOnAtomic(_BaseChecker):
    error_id = "nonAtomicAccessOnAtomic"
    cwe      = 366
    severity = "warning"

    # Operators that represent non-atomic access patterns
    _BAD_OPS: FrozenSet[str] = frozenset({
        "=", "+=", "-=", "*=", "/=", "%=",
        "&=", "|=", "^=", "<<=", ">>=",
        "++", "--",
    })

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            ts = _tok_str(tok)
            if ts not in self._BAD_OPS:
                continue

            # Find the variable being written
            lhs = getattr(tok, "astOperand1", None)
            if lhs is None:
                # Prefix ++/-- have operand in astOperand1 on some versions
                lhs = getattr(tok, "astOperand2", None)
            if lhs is None:
                continue

            if not _is_atomic_qualified(lhs):
                continue

            # Suppress if inside an atomic_ call's args (e.g., CAS second arg)
            if self._inside_atomic_call_args(tok):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            var_name = _tok_str(lhs)
            self._emit(
                tok,
                f"Plain '{ts}' operator used on _Atomic-qualified variable "
                f"'{var_name}'; use atomic_store() / atomic_fetch_*() / "
                f"atomic_exchange() explicitly to make memory ordering "
                f"visible and portable (CWE-366).",
            )

    @staticmethod
    def _inside_atomic_call_args(tok: Any) -> bool:
        """Return True if tok is lexically inside an atomic_* function call."""
        # Walk AST parents upward looking for a call to an atomic function
        node = getattr(tok, "astParent", None)
        depth = 0
        while node is not None and depth < 12:
            ps = _tok_str(node)
            if ps == "(" :
                op1 = getattr(node, "astOperand1", None)
                if op1 is not None and _tok_str(op1) in _ALL_ATOMIC_OPS:
                    return True
            node = getattr(node, "astParent", None)
            depth += 1
        return False


# ─────────────────────────────────────────────────────────────────────────
#  ACL-03  relaxedOrderOnSeqCst  (CWE-362)
#
#  A variable is accessed with memory_order_relaxed in one place and
#  with a stronger order (acquire/release/seq_cst) in another place in
#  the same translation unit.
#
#  This mixed-order pattern is almost always a bug: the programmer
#  intended the strong-ordered accesses to establish happens-before but
#  inadvertently inserted a relaxed access that breaks the chain.
#
#  Detection:
#    1. For every *_explicit() call, record (varId → set of orders used).
#    2. After scanning the whole cfg, flag any varId that appears with
#       BOTH memory_order_relaxed AND at least one strong order.
#
#  The flag site is the relaxed-access token.
# ─────────────────────────────────────────────────────────────────────────

class _ACL03_RelaxedOrderOnSeqCst(_BaseChecker):
    error_id = "relaxedOrderOnSeqCst"
    cwe      = 362
    severity = "warning"

    # Explicit-order functions: the memory_order argument position varies.
    # atomic_load_explicit(ptr, order)       → arg 1
    # atomic_store_explicit(ptr, val, order) → arg 2
    # atomic_fetch_*_explicit(ptr, val, order) → arg 2
    # atomic_exchange_explicit(ptr, val, order) → arg 2
    # atomic_compare_exchange_*_explicit(ptr, exp, des, succ, fail) → arg 3,4
    # atomic_flag_test_and_set_explicit(ptr, order) → arg 1
    # atomic_flag_clear_explicit(ptr, order) → arg 1

    _EXPLICIT_FNS: FrozenSet[str] = frozenset({
        "atomic_load_explicit",
        "atomic_store_explicit",
        "atomic_exchange_explicit",
        "atomic_fetch_add_explicit",
        "atomic_fetch_sub_explicit",
        "atomic_fetch_and_explicit",
        "atomic_fetch_or_explicit",
        "atomic_fetch_xor_explicit",
        "atomic_compare_exchange_strong_explicit",
        "atomic_compare_exchange_weak_explicit",
        "atomic_flag_test_and_set_explicit",
        "atomic_flag_clear_explicit",
    })

    def check(self, cfg: Any) -> None:
        # vid → {order_str → [call_tok]}
        order_sites: Dict[int, Dict[str, List[Any]]] = {}

        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in self._EXPLICIT_FNS:
                continue
            if not _is_function_call(tok):
                continue

            vid = _first_arg_vid(tok)
            if vid is None:
                continue

            order = _any_memory_order_arg(tok)
            if order is None:
                continue

            order_sites.setdefault(vid, {}).setdefault(order, []).append(tok)

        # Now flag variables with mixed relaxed + strong orders
        seen: Set[Tuple[str, int]] = set()
        for vid, orders in order_sites.items():
            if _RELAXED not in orders:
                continue
            strong_present = any(o in _STRONG_ORDERS for o in orders)
            if not strong_present:
                continue

            # Flag each relaxed site
            for relax_tok in orders[_RELAXED]:
                key = (_tok_file(relax_tok), _tok_line(relax_tok))
                if key in seen:
                    continue
                seen.add(key)

                strong_orders_used = sorted(
                    o for o in orders if o in _STRONG_ORDERS
                )
                self._emit(
                    relax_tok,
                    f"Atomic variable (varId={vid}) is accessed with "
                    f"'memory_order_relaxed' here but also with stronger "
                    f"order(s) {strong_orders_used} elsewhere in this "
                    f"translation unit; the relaxed access breaks the "
                    f"happens-before chain you may have intended (CWE-362).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-04  doubleLockAtomic  (CWE-667)
#
#  An atomic_flag is used as a spinlock (test-and-set to acquire,
#  clear to release) but atomic_flag_test_and_set is called twice on
#  the same flag without an intervening atomic_flag_clear.
#
#  Detection:
#    Per function, per atomic_flag varId, track:
#      - ACQUIRE events (test_and_set)
#      - RELEASE events (clear)
#    If two ACQUIRE events appear without an intervening RELEASE,
#    flag the second ACQUIRE.
#
#  Note: this is a sequential/lexical analysis.  It does not model
#  loop back-edges.  A flag acquired in a loop body without a clear
#  inside the loop body will be caught on the second iteration token.
# ─────────────────────────────────────────────────────────────────────────

class _ACL04_DoubleLockAtomic(_BaseChecker):
    error_id = "doubleLockAtomic"
    cwe      = 667
    severity = "error"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = list(getattr(cfg, "tokenlist", []))

        # Per vid: list of ("acquire"|"release", tok) sorted by source order
        events: Dict[int, List[Tuple[str, Any]]] = {}

        for tok in tlist:
            ts = _tok_str(tok)
            if ts in _ATOMIC_FLAG_ACQUIRE_FNS and _is_function_call(tok):
                vid = _first_arg_vid(tok)
                if vid is not None:
                    events.setdefault(vid, []).append(("acquire", tok))
            elif ts in _ATOMIC_FLAG_RELEASE_FNS and _is_function_call(tok):
                vid = _first_arg_vid(tok)
                if vid is not None:
                    events.setdefault(vid, []).append(("release", tok))

        for vid, ev_list in events.items():
            ev_list.sort(key=lambda x: _tok_order(x[1]))
            pending_acquire: Optional[Any] = None

            for kind, tok in ev_list:
                if kind == "acquire":
                    if pending_acquire is not None:
                        # Second acquire without intervening release
                        key = (_tok_file(tok), _tok_line(tok))
                        if key not in seen:
                            seen.add(key)
                            first_line = _tok_line(pending_acquire)
                            self._emit(
                                tok,
                                f"'atomic_flag_test_and_set()' called on "
                                f"atomic_flag (varId={vid}) at line "
                                f"{_tok_line(tok)} without a preceding "
                                f"'atomic_flag_clear()'; first acquisition "
                                f"at line {first_line} — double-lock / "
                                f"lock order violation (CWE-667).",
                                severity="error",
                            )
                    else:
                        pending_acquire = tok
                elif kind == "release":
                    pending_acquire = None


# ─────────────────────────────────────────────────────────────────────────
#  ACL-05  atomicFlagWithoutClear  (CWE-764)
#
#  An atomic_flag_test_and_set() call site has no reachable
#  atomic_flag_clear() call for the same flag in the same function.
#
#  This is weaker than ACL-04: it flags ANY function that acquires a
#  flag but never releases it — a lock that is never unlocked.
#
#  Detection:
#    Per function scope, collect the set of varIds acquired and the set
#    of varIds released.  Flag acquired varIds that are not released.
#
#  False-positive guard:
#    - If the flag is a global/static and the function is clearly a
#      "lock" half of a lock/unlock pair (e.g., named "lock_*"),
#      suppress.  We implement the name-based suppression.
# ─────────────────────────────────────────────────────────────────────────

class _ACL05_AtomicFlagWithoutClear(_BaseChecker):
    error_id = "atomicFlagWithoutClear"
    cwe      = 764
    severity = "warning"

    _LOCK_NAME_RE = re.compile(
        r"\b(lock|acquire|spin_lock|take|grab)\b", re.IGNORECASE
    )

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        # Collect per-function: acquired_vids, released_vids, first_acquire_tok
        fn_acquired:     Dict[Any, Dict[int, Any]]  = {}   # scope → {vid → tok}
        fn_released:     Dict[Any, Set[int]]         = {}   # scope → {vid}

        for tok in getattr(cfg, "tokenlist", []):
            ts = _tok_str(tok)
            fn_scope = _enclosing_function_scope(tok)
            if fn_scope is None:
                continue

            if ts in _ATOMIC_FLAG_ACQUIRE_FNS and _is_function_call(tok):
                vid = _first_arg_vid(tok)
                if vid is not None:
                    fn_acquired.setdefault(fn_scope, {}).setdefault(vid, tok)
            elif ts in _ATOMIC_FLAG_RELEASE_FNS and _is_function_call(tok):
                vid = _first_arg_vid(tok)
                if vid is not None:
                    fn_released.setdefault(fn_scope, set()).add(vid)

        for fn_scope, acq_map in fn_acquired.items():
            released = fn_released.get(fn_scope, set())

            # Name-based suppression: if the function is named *lock*
            fn_name = _function_name_from_scope(fn_scope) or ""
            if self._LOCK_NAME_RE.search(fn_name):
                continue  # Deliberate lock-half pattern

            for vid, acquire_tok in acq_map.items():
                if vid in released:
                    continue

                key = (_tok_file(acquire_tok), _tok_line(acquire_tok))
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    acquire_tok,
                    f"'atomic_flag_test_and_set()' acquires atomic_flag "
                    f"(varId={vid}) but no 'atomic_flag_clear()' call is "
                    f"present in the same function — the flag is never "
                    f"released (CWE-764).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-06  sigAtomicNonVolatile  (CWE-366)
#
#  A variable declared as sig_atomic_t is NOT declared volatile.
#
#  C99 §7.14.1.1p5: a signal handler may only refer to objects with
#  static storage duration that are of type "volatile sig_atomic_t".
#  Without the volatile qualifier, the compiler may cache the variable
#  in a register and the signal handler's write will not be visible to
#  the main thread (or vice versa).
#
#  Detection:
#    Scan all Variable objects; flag those with type sig_atomic_t that
#    are not marked volatile.
# ─────────────────────────────────────────────────────────────────────────

class _ACL06_SigAtomicNonVolatile(_BaseChecker):
    error_id = "sigAtomicNonVolatile"
    cwe      = 366
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[int] = set()   # varIds already reported

        for tok in getattr(cfg, "tokenlist", []):
            if not _is_sig_atomic_t(tok):
                continue

            vid = _safe_vid_tok(tok)
            if vid is None or vid in seen:
                continue

            if _is_volatile(tok):
                continue

            var = getattr(tok, "variable", None)
            if var is None:
                continue

            # Only flag global/static variables — local sig_atomic_t is
            # unusual but not a signal-safety problem per se (signal
            # handlers cannot access stack locals anyway).
            if not (getattr(var, "isGlobal", False) or
                    getattr(var, "isStatic", False)):
                continue

            # Only flag at the declaration site (isName + isDecl or first use)
            # We use a pragmatic check: flag only when this is the nameToken
            # (variable.nameToken is this tok)
            name_tok = getattr(var, "nameToken", None)
            if name_tok is not tok:
                continue

            seen.add(vid)
            var_name = _tok_str(tok)
            self._emit(
                tok,
                f"'sig_atomic_t' variable '{var_name}' (varId={vid}) is not "
                f"declared 'volatile'; per C99 §7.14.1.1 only "
                f"'volatile sig_atomic_t' is safe to access from both a "
                f"signal handler and the main program (CWE-366).  "
                f"Declare as: 'volatile sig_atomic_t {var_name};'",
            )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-07  atomicCmpXchgIgnored  (CWE-252)
#
#  The return value of atomic_compare_exchange_strong() or
#  atomic_compare_exchange_weak() is not checked.
#
#  These functions return a _Bool / bool: true on success (the exchange
#  happened), false on failure (the expected value did not match).
#  Ignoring the return value means the program proceeds as if the CAS
#  succeeded even when it did not — a silent data-race loss.
#
#  Detection:
#    Same pattern as VarargsSafetyChecker VSC-10: check the AST parent
#    of the call to see if the result is consumed.
# ─────────────────────────────────────────────────────────────────────────

class _ACL07_AtomicCmpXchgIgnored(_BaseChecker):
    error_id = "atomicCmpXchgIgnored"
    cwe      = 252
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        for tok in getattr(cfg, "tokenlist", []):
            if _tok_str(tok) not in _ATOMIC_CAS_FNS:
                continue
            if not _is_function_call(tok):
                continue
            if _return_value_checked(tok):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            fn = _tok_str(tok)
            self._emit(
                tok,
                f"Return value of '{fn}()' (bool: true=success, "
                f"false=failure) is not checked; if the CAS fails the "
                f"program continues silently with a stale value — "
                f"wrap in a retry loop or check the bool result (CWE-252).",
            )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-08  atomicOnStackStructCopy  (CWE-362)
#
#  A struct that contains an _Atomic member is copied to a local
#  (stack, non-atomic) variable and the local copy is then accessed.
#  The copy operation itself is NOT atomic — it is a non-atomic bulk
#  memcpy from the perspective of other threads — and subsequent reads
#  of the copy operate on potentially torn data.
#
#  Pattern detected:
#    struct S { _Atomic int counter; char name[32]; };
#    extern struct S shared;
#
#    void foo(void) {
#        struct S local = shared;        ← ACL-08: non-atomic struct copy
#        int v = atomic_load(&local.counter); // operates on a torn copy
#    }
#
#  Detection:
#    1. Find assignment tokens (=) where the RHS is a global/static
#       variable and the LHS is a local variable.
#    2. Check if the type of the RHS variable has any _Atomic member.
#       (We use a type-name heuristic: if the struct type has been seen
#       to contain _Atomic members via token scan.)
#    3. Flag the assignment.
#
#  Because cppcheckdata does not expose struct member information
#  reliably across all versions, we implement a two-step approach:
#    Step A: Scan all tokens to find struct/type names that have
#            _Atomic members declared inside their body.
#    Step B: For each non-atomic copy of a variable whose type name is
#            in the set from Step A, flag.
# ─────────────────────────────────────────────────────────────────────────

class _ACL08_AtomicOnStackStructCopy(_BaseChecker):
    error_id = "atomicOnStackStructCopy"
    cwe      = 362
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        tlist = list(getattr(cfg, "tokenlist", []))

        # Step A: Find struct type names that contain _Atomic members
        atomic_struct_types = self._find_atomic_struct_types(cfg)
        if not atomic_struct_types:
            return

        # Step B: Find local = global assignments where the type is atomic
        for tok in tlist:
            if not getattr(tok, "isAssignmentOp", False):
                continue
            if _tok_str(tok) != "=":
                continue

            lhs = getattr(tok, "astOperand1", None)
            rhs = getattr(tok, "astOperand2", None)
            if lhs is None or rhs is None:
                continue

            # LHS must be a local non-atomic variable
            if not _is_local_non_atomic(lhs):
                continue

            # RHS must be a global or static variable
            if not _is_global_or_static(rhs):
                continue

            # The type of the RHS must be in our atomic-struct set
            rhs_type = _var_type_str(rhs)
            if not any(at in rhs_type for at in atomic_struct_types):
                continue

            key = (_tok_file(tok), _tok_line(tok))
            if key in seen:
                continue
            seen.add(key)

            lhs_name = _tok_str(lhs)
            rhs_name = _tok_str(rhs)
            self._emit(
                tok,
                f"Non-atomic copy of struct '{rhs_name}' (which contains "
                f"_Atomic member(s)) into local variable '{lhs_name}'; "
                f"the copy is not atomic — other threads may observe a "
                f"torn intermediate state.  Pass a pointer or use a lock "
                f"for whole-struct access (CWE-362).",
            )

    @staticmethod
    def _find_atomic_struct_types(cfg: Any) -> Set[str]:
        """
        Return the set of struct/type names that declare at least one
        _Atomic member.

        Heuristic: look for the pattern
            struct <Name> { ... _Atomic ... }
        by scanning Struct scopes and their member tokens.
        """
        atomic_types: Set[str] = set()
        for scope in getattr(cfg, "scopes", []) or []:
            if _scope_type(scope) != "Struct":
                continue
            # Check member tokens inside this struct scope
            for tok in getattr(cfg, "tokenlist", []):
                if _tok_scope(tok) is not scope:
                    continue
                if "_Atomic" in _tok_str(tok):
                    # Name of the struct scope
                    sname = getattr(scope, "className", None) or ""
                    if sname:
                        atomic_types.add(sname)
                    break
        return atomic_types


# ─────────────────────────────────────────────────────────────────────────
#  ACL-09  fenceWithoutAtomicOp  (CWE-362)
#
#  atomic_thread_fence() or atomic_signal_fence() is present in a
#  function scope that contains NO atomic load, store, or RMW
#  operations.  A fence without any atomic operation in the same
#  scope is vacuous — it provides no synchronisation guarantee because
#  there is nothing to synchronise.
#
#  Common cause: a developer moves atomic operations to a helper
#  function but forgets to move the fence, or adds a fence "just in
#  case" without understanding the memory model.
#
#  Detection:
#    For each function scope, check if it contains a fence call.
#    If yes, check if it also contains at least one atomic load/store/RMW.
#    If no atomic ops are found, flag the fence.
# ─────────────────────────────────────────────────────────────────────────

class _ACL09_FenceWithoutAtomicOp(_BaseChecker):
    error_id = "fenceWithoutAtomicOp"
    cwe      = 362
    severity = "warning"

    _ATOMIC_OPS_NO_FENCE: FrozenSet[str] = (
        _ATOMIC_LOAD_FNS | _ATOMIC_STORE_FNS | _ATOMIC_RMW_FNS | _ATOMIC_CAS_FNS
    )

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()

        # Per function scope: fence tokens and atomic-op tokens
        fn_fences:     Dict[Any, List[Any]] = {}
        fn_atomic_ops: Dict[Any, bool]      = {}

        for tok in getattr(cfg, "tokenlist", []):
            ts = _tok_str(tok)
            fn_scope = _enclosing_function_scope(tok)
            if fn_scope is None:
                continue

            if ts in _FENCE_FNS and _is_function_call(tok):
                fn_fences.setdefault(fn_scope, []).append(tok)
            elif ts in self._ATOMIC_OPS_NO_FENCE and _is_function_call(tok):
                fn_atomic_ops[fn_scope] = True

        for fn_scope, fence_toks in fn_fences.items():
            if fn_atomic_ops.get(fn_scope, False):
                continue  # Fence paired with atomic ops — ok

            for fence_tok in fence_toks:
                key = (_tok_file(fence_tok), _tok_line(fence_tok))
                if key in seen:
                    continue
                seen.add(key)

                fn_name = _function_name_from_scope(fn_scope) or "<unknown>"
                fence_fn = _tok_str(fence_tok)
                self._emit(
                    fence_tok,
                    f"'{fence_fn}()' in function '{fn_name}' has no "
                    f"atomic load/store/RMW in the same function scope; "
                    f"a fence without adjacent atomic operations is "
                    f"vacuous and provides no synchronisation (CWE-362).",
                )


# ─────────────────────────────────────────────────────────────────────────
#  ACL-10  atomicInSignalHandler  (CWE-479)
#
#  A non-sig_atomic_t atomic operation (atomic_load, atomic_store,
#  atomic_fetch_*, atomic_compare_exchange_*, atomic_flag_*) is used
#  inside a function registered as a signal handler.
#
#  Background: POSIX.1-2017 §2.4.3 defines the set of async-signal-safe
#  functions.  C11 atomic operations (other than volatile sig_atomic_t
#  reads/writes) are NOT in that list.  On most platforms they involve
#  lock-prefix instructions or LL/SC loops that interact with the
#  kernel's scheduler state — calling them in a signal handler that
#  interrupts a thread already holding a CPU lock can deadlock.
#
#  Detection:
#    1. Collect signal handler function names from signal() calls.
#    2. For each handler, scan its body for any atomic_ function calls
#       that are NOT operating on a sig_atomic_t / volatile sig_atomic_t.
#    3. Flag those calls.
# ─────────────────────────────────────────────────────────────────────────

class _ACL10_AtomicInSignalHandler(_BaseChecker):
    error_id = "atomicInSignalHandler"
    cwe      = 479
    severity = "warning"

    def check(self, cfg: Any) -> None:
        seen: Set[Tuple[str, int]] = set()
        handler_names = _collect_signal_handler_names(cfg)
        if not handler_names:
            return

        # Map function name → its Function scope
        fn_scopes: Dict[str, Any] = {}
        for scope in getattr(cfg, "scopes", []) or []:
            if _scope_type(scope) != "Function":
                continue
            name = _function_name_from_scope(scope)
            if name and name in handler_names:
                fn_scopes[name] = scope

        if not fn_scopes:
            return

        for fn_name, fn_scope in fn_scopes.items():
            for tok in _tokens_in_function(cfg, fn_scope):
                ts = _tok_str(tok)
                if ts not in _NON_SIGNAL_SAFE_ATOMIC_OPS:
                    continue
                if not _is_function_call(tok):
                    continue

                # Is the operand a sig_atomic_t variable? If so, it is
                # the safe pattern — suppress.
                first_arg = _first_arg_tok(tok)
                if first_arg is not None and _is_sig_atomic_t(first_arg):
                    continue

                key = (_tok_file(tok), _tok_line(tok))
                if key in seen:
                    continue
                seen.add(key)

                self._emit(
                    tok,
                    f"'{ts}()' called inside signal handler '{fn_name}'; "
                    f"C11 atomic operations are not async-signal-safe per "
                    f"POSIX.1-2017 §2.4.3 — use 'volatile sig_atomic_t' "
                    f"with plain reads/writes instead (CWE-479).",
                )


# ═══════════════════════════════════════════════════════════════════════════
#  PART 11 — ADDON ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

_ALL_CHECKERS: List[type] = [
    _ACL01_AtomicLoadStoreMismatch,
    _ACL02_NonAtomicAccessOnAtomic,
    _ACL03_RelaxedOrderOnSeqCst,
    _ACL04_DoubleLockAtomic,
    _ACL05_AtomicFlagWithoutClear,
    _ACL06_SigAtomicNonVolatile,
    _ACL07_AtomicCmpXchgIgnored,
    _ACL08_AtomicOnStackStructCopy,
    _ACL09_FenceWithoutAtomicOp,
    _ACL10_AtomicInSignalHandler,
]


def _run_on_dump(dump_file: str) -> int:
    data  = cppcheckdata.parsedump(dump_file)
    total = 0

    for cfg in data.configurations:
        for checker_cls in _ALL_CHECKERS:
            checker = checker_cls()
            try:
                checker.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"[ACL] {checker_cls.__name__} raised "
                    f"{type(exc).__name__}: {exc}\n"
                )
                continue
            for finding in checker.findings:
                finding.emit()
                total += 1

    return 1 if total > 0 else 0


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python AtomicCorrectnessLint.py <file.c.dump>\n"
        )
        sys.exit(1)
    dump_file = sys.argv[1]
    if not os.path.isfile(dump_file):
        sys.stderr.write(f"ERROR: dump file not found: {dump_file}\n")
        sys.exit(1)
    sys.exit(_run_on_dump(dump_file))


if __name__ == "__main__":
    main()
