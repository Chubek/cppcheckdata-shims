#!/usr/bin/env python3
"""
MisraSubsetLint.py — Cppcheck addon
====================================
Checks a high-value, mechanically decidable subset of MISRA-C:2012 rules.

Checked rules
─────────────
MSL-01  MISRA 14.4  Non-boolean controlling expression           CWE-1040
MSL-02  MISRA 15.5  Function has multiple return statements      CWE-1041
MSL-03  MISRA 16.4  switch statement missing 'default' clause    CWE-478
MSL-04  MISRA 16.5  'default' is not last clause in switch       CWE-1075
MSL-05  MISRA 12.1  Mixed arithmetic and bitwise without parens  CWE-783
MSL-06  MISRA 13.3  Increment/decrement in boolean sub-expr      CWE-398
MSL-07  MISRA 17.7  Return value of non-void function discarded  CWE-252
MSL-08  MISRA 20.4  #define redefines a language keyword         CWE-1041
MSL-09  MISRA 21.3  Use of banned dynamic-memory function        CWE-676
MSL-10  MISRA 15.4  Multiple breaks inside a single loop body    CWE-1041

Usage
─────
  cppcheck --dump myfile.c
  python3 MisraSubsetLint.py myfile.c.dump
"""

from __future__ import annotations

import sys
import re
import os
from collections import defaultdict

# ---------------------------------------------------------------------------
# Shim-safe import
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    sys.path.insert(0, os.path.dirname(__file__))
    import cppcheckdata

ADDON_NAME = "MisraSubsetLint"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def emit(tok, severity: str, message: str, error_id: str) -> None:
    """
    Call the shim-compatible reportError signature:
        reportError(token, severity, message, addon, errorId)
    """
    cppcheckdata.reportError(tok, severity, message, ADDON_NAME, error_id)


def tok_str(tok) -> str:
    """Return token string value, '' if None."""
    return tok.str if tok else ""


def tok_next(tok, skip: int = 1):
    """Advance tok by `skip` steps, returning None on exhaustion."""
    t = tok
    for _ in range(skip):
        if t is None:
            return None
        t = t.next
    return t


def tokens_in_range(start_tok, end_tok):
    """Yield tokens from start_tok up to (but not including) end_tok."""
    t = start_tok
    while t and t != end_tok:
        yield t
        t = t.next


def find_matching_brace(open_brace_tok):
    """Given a '{' token, return the matching '}' token or None."""
    if tok_str(open_brace_tok) != '{':
        return None
    depth = 0
    t = open_brace_tok
    while t:
        if t.str == '{':
            depth += 1
        elif t.str == '}':
            depth -= 1
            if depth == 0:
                return t
        t = t.next
    return None


def find_matching_paren(open_paren_tok):
    """Given a '(' token, return the matching ')' token or None."""
    if tok_str(open_paren_tok) != '(':
        return None
    depth = 0
    t = open_paren_tok
    while t:
        if t.str == '(':
            depth += 1
        elif t.str == ')':
            depth -= 1
            if depth == 0:
                return t
        t = t.next
    return None


# ---------------------------------------------------------------------------
# C language keywords (for MSL-08)
# ---------------------------------------------------------------------------
C_KEYWORDS: frozenset[str] = frozenset({
    "auto", "break", "case", "char", "const", "continue", "default",
    "do", "double", "else", "enum", "extern", "float", "for", "goto",
    "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
    "union", "unsigned", "void", "volatile", "while",
    "_Bool", "_Complex", "_Imaginary",
    # C11 extras
    "_Alignas", "_Alignof", "_Atomic", "_Generic",
    "_Noreturn", "_Static_assert", "_Thread_local",
})

# ---------------------------------------------------------------------------
# Banned memory functions (MISRA 21.3)
# ---------------------------------------------------------------------------
BANNED_MEM_FUNCS: frozenset[str] = frozenset({
    "malloc", "calloc", "realloc", "free",
    "alloca", "valloc", "pvalloc", "aligned_alloc",
})

# ---------------------------------------------------------------------------
# Functions whose return value must NOT be ignored (MISRA 17.7 subset)
# These are well-known C stdlib functions with error-bearing return values.
# ---------------------------------------------------------------------------
CHECKED_RETURN_FUNCS: frozenset[str] = frozenset({
    # I/O
    "fopen", "fclose", "fread", "fwrite", "fseek", "fflush",
    "fprintf", "fscanf", "scanf", "sscanf", "vfscanf",
    "puts", "fputs", "fputc",
    # Memory / string
    "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsnprintf",
    # POSIX / system
    "open", "close", "read", "write", "lseek",
    "send", "recv", "connect", "bind", "listen", "accept",
    "pthread_create", "pthread_join", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_cond_wait",
    "sem_wait", "sem_post", "sem_init",
    "mmap", "munmap", "shm_open",
    # Crypto / security
    "RAND_bytes", "RAND_priv_bytes",
    "EVP_EncryptInit_ex", "EVP_EncryptUpdate", "EVP_EncryptFinal_ex",
    "EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex",
    "EVP_DigestInit_ex", "EVP_DigestUpdate", "EVP_DigestFinal_ex",
    # Allocation (when used — separate from MISRA 21.3 which bans them)
    "malloc", "calloc", "realloc",
})

# Bitwise operators
BITWISE_OPS: frozenset[str] = frozenset({"&", "|", "^", "~", "<<", ">>"})
# Arithmetic operators
ARITH_OPS:   frozenset[str] = frozenset({"+", "-", "*", "/", "%"})
# Boolean/logical operators
BOOL_OPS:    frozenset[str] = frozenset({"&&", "||"})
# Increment/decrement
INC_DEC_OPS: frozenset[str] = frozenset({"++", "--"})

# Controlling-expression keywords
CONTROL_KW:  frozenset[str] = frozenset({"if", "while", "for"})

# ---------------------------------------------------------------------------
# MSL-08 — #define redefines keyword
# ---------------------------------------------------------------------------

def check_msl08_define_keyword(cfg) -> None:
    """
    Walk directives looking for:  #define <keyword>  ...
    """
    if not hasattr(cfg, 'directives'):
        return
    define_re = re.compile(r'^\s*#\s*define\s+(\w+)')
    for directive in cfg.directives:
        m = define_re.match(directive.str)
        if m:
            name = m.group(1)
            if name in C_KEYWORDS:
                emit(
                    directive,
                    "error",
                    f"MISRA 20.4: #define redefines C keyword '{name}' "
                    f"(CWE-1041)",
                    "MSL-08",
                )


# ---------------------------------------------------------------------------
# MSL-09 — banned dynamic memory functions
# ---------------------------------------------------------------------------

def check_msl09_banned_memory(tok) -> None:
    """
    Detect calls to banned dynamic-memory management functions.
    Token pattern:  <name> '('  where name in BANNED_MEM_FUNCS
    """
    if (tok.str in BANNED_MEM_FUNCS
            and tok_str(tok.next) == '('
            and (tok.previous is None
                 or tok_str(tok.previous) not in (".", "->"))):
        emit(
            tok,
            "warning",
            f"MISRA 21.3: use of banned dynamic-memory function "
            f"'{tok.str}' (CWE-676)",
            "MSL-09",
        )


# ---------------------------------------------------------------------------
# MSL-03 / MSL-04 — switch: missing default / default not last
# ---------------------------------------------------------------------------

def check_msl03_msl04_switch(tok) -> None:
    """
    Detect:
      MSL-03: switch body has no 'default:' label.
      MSL-04: 'default:' label is not the last clause.
    """
    if tok.str != 'switch':
        return

    # Find the opening '{' of the switch body
    t = tok.next
    # skip the controlling expression '( … )'
    if tok_str(t) == '(':
        t = find_matching_paren(t)
        if t:
            t = t.next

    if tok_str(t) != '{':
        return

    body_open  = t
    body_close = find_matching_brace(body_open)
    if body_close is None:
        return

    # Collect positions of 'case' and 'default' labels (depth == 1)
    depth         = 0
    has_default   = False
    default_tok   = None
    last_label    = None   # last 'case' or 'default' token seen
    inner         = body_open
    while inner and inner != body_close:
        if inner.str == '{':
            depth += 1
        elif inner.str == '}':
            depth -= 1
        elif depth == 1:
            if inner.str == 'default':
                has_default = True
                default_tok = inner
                last_label  = ('default', inner)
            elif inner.str == 'case':
                last_label  = ('case', inner)
        inner = inner.next

    if not has_default:
        emit(
            tok,
            "warning",
            "MISRA 16.4: switch statement has no 'default' clause "
            "(CWE-478)",
            "MSL-03",
        )
    elif last_label and last_label[0] != 'default':
        emit(
            default_tok,
            "style",
            "MISRA 16.5: 'default' clause is not the last clause in "
            "switch (CWE-1075)",
            "MSL-04",
        )


# ---------------------------------------------------------------------------
# MSL-02 — single exit point (multiple returns)
# ---------------------------------------------------------------------------

def check_msl02_multiple_returns(func, body_start_tok, body_end_tok) -> None:
    """
    Count 'return' tokens at the outermost depth of the function body.
    More than one → violation.
    """
    return_toks = []
    depth = 0
    t = body_start_tok
    while t and t != body_end_tok:
        if t.str == '{':
            depth += 1
        elif t.str == '}':
            depth -= 1
        elif t.str == 'return' and depth == 1:
            return_toks.append(t)
        t = t.next

    if len(return_toks) > 1:
        # Report at the second (unexpected) return
        emit(
            return_toks[1],
            "style",
            f"MISRA 15.5: function '{func.name}' has multiple return "
            f"statements (CWE-1041)",
            "MSL-02",
        )


# ---------------------------------------------------------------------------
# MSL-10 — multiple break in a single loop body
# ---------------------------------------------------------------------------

def check_msl10_multiple_break(func, body_start_tok, body_end_tok) -> None:
    """
    Detect more than one 'break' directly inside a single loop body.
    Nested loops each get their own break-count.
    """
    LOOP_KW   = frozenset({"for", "while", "do"})
    # Stack of (opening_brace_tok, break_count)
    loop_stack: list[list] = []

    t = body_start_tok
    while t and t != body_end_tok:
        if t.str in LOOP_KW:
            # Push a frame when we enter a loop
            # Find the '{' that opens the loop body
            tmp = t.next
            if tok_str(tmp) == '(':
                tmp = find_matching_paren(tmp)
                if tmp:
                    tmp = tmp.next
            # for do…while the '{' comes right after 'do'
            if tok_str(tmp) == '{':
                loop_stack.append([tmp, 0])   # [open_brace, break_count]
        elif t.str == '{' and loop_stack:
            # Inner brace not the loop opener → push sentinel to avoid
            # miscounting breaks in nested non-loop blocks
            pass
        elif t.str == 'break' and loop_stack:
            loop_stack[-1][1] += 1
            if loop_stack[-1][1] == 2:
                emit(
                    t,
                    "style",
                    f"MISRA 15.4: loop in function '{func.name}' has "
                    f"more than one 'break' statement (CWE-1041)",
                    "MSL-10",
                )
        elif t.str == '}' and loop_stack:
            # Check whether this brace closes the topmost loop frame
            open_brace = loop_stack[-1][0]
            close_brace = find_matching_brace(open_brace)
            if close_brace == t:
                loop_stack.pop()
        t = t.next


# ---------------------------------------------------------------------------
# MSL-01 — non-boolean controlling expression
# ---------------------------------------------------------------------------

def _is_comparison_or_bool(tok) -> bool:
    """
    Heuristic: decide whether the controlling-expression token sequence
    'looks like' a proper boolean expression.

    We scan the parenthesised expression for at least one comparison or
    logical operator.  If none is found, it is a plain integer / pointer
    expression used as a boolean (MISRA 14.4 violation).
    """
    COMPARE_OPS = frozenset({"==", "!=", "<", ">", "<=", ">=", "!", "&&", "||"})
    # tok should be the '(' that opens the controlling expression
    t = tok.next
    depth = 1
    while t:
        if t.str == '(':
            depth += 1
        elif t.str == ')':
            depth -= 1
            if depth == 0:
                break
        elif t.str in COMPARE_OPS:
            return True
        t = t.next
    return False


def check_msl01_non_bool_control(tok) -> None:
    """
    MSL-01: if / while / for with a non-boolean controlling expression.
    Only fires when the expression is a single identifier or constant
    (no comparison/logical operator found inside the parens).
    """
    if tok.str not in CONTROL_KW:
        return
    # for 'for', skip: the controlling part is complex and often valid
    if tok.str == 'for':
        return

    paren_open = tok.next
    if tok_str(paren_open) != '(':
        return

    if not _is_comparison_or_bool(paren_open):
        emit(
            tok,
            "warning",
            f"MISRA 14.4: controlling expression of '{tok.str}' is not "
            f"essentially Boolean (CWE-1040)",
            "MSL-01",
        )


# ---------------------------------------------------------------------------
# MSL-05 — mixed arithmetic and bitwise without explicit parentheses
# ---------------------------------------------------------------------------

def check_msl05_mixed_ops(tok) -> None:
    """
    Detect token sequences of the form:
        <expr> <arith_op> <expr> <bitwise_op>  (or vice-versa)
    without an intervening '(' that would make precedence explicit.

    Simplified heuristic: flag any bitwise operator that has an arithmetic
    operator as its immediate left-hand sibling at the same paren depth.
    """
    if tok.str not in BITWISE_OPS:
        return
    # Look back for an arithmetic operator at the same level
    prev = tok.previous
    if prev is None:
        return
    # Skip over a right-hand identifier/number/closing paren
    if tok_str(prev) in (')', '}') or prev.isName or prev.isNumber:
        prev = prev.previous
    if prev and prev.str in ARITH_OPS:
        emit(
            tok,
            "warning",
            f"MISRA 12.1: bitwise operator '{tok.str}' mixed with "
            f"arithmetic operator '{prev.str}' without explicit "
            f"parentheses (CWE-783)",
            "MSL-05",
        )


# ---------------------------------------------------------------------------
# MSL-06 — increment/decrement inside boolean sub-expression
# ---------------------------------------------------------------------------

def check_msl06_inc_dec_in_bool(tok) -> None:
    """
    Detect  ++ / --  appearing as a direct operand of  &&  or  ||.
    Token patterns:
        <expr>++  &&   or   &&  ++<expr>
        <expr>--  ||   or   ||  --<expr>
    """
    if tok.str not in INC_DEC_OPS:
        return
    nxt = tok.next
    prv = tok.previous
    if tok_str(nxt) in BOOL_OPS or tok_str(prv) in BOOL_OPS:
        emit(
            tok,
            "warning",
            f"MISRA 13.3: increment/decrement operator '{tok.str}' used "
            f"as operand of boolean operator (CWE-398)",
            "MSL-06",
        )


# ---------------------------------------------------------------------------
# MSL-07 — ignored return value of non-void function
# ---------------------------------------------------------------------------

# Simple pattern:  statement starts with  <func_name> '('  (no assignment LHS)
# We exclude common void-return idioms: assert, free, exit, abort, etc.
_VOID_IDIOMS: frozenset[str] = frozenset({
    "assert", "free", "exit", "_exit", "abort", "longjmp",
    "perror", "printf", "fprintf", "vprintf", "vfprintf",
    "puts", "putchar", "putc", "fputc", "fputs",
    "srand", "srandom",
    "va_start", "va_end", "va_copy",
    "pthread_exit",
})

def check_msl07_ignored_return(tok) -> None:
    """
    Detect call statements where the return value is discarded.
    Heuristic: token is a function name in CHECKED_RETURN_FUNCS,
    the next token is '(', and the previous token is ';' or '{' or '}'
    (i.e., this is the start of a statement, not an expression).
    """
    if tok.str not in CHECKED_RETURN_FUNCS:
        return
    if tok.str in _VOID_IDIOMS:
        return
    if tok_str(tok.next) != '(':
        return
    # Check previous token to confirm statement-start position
    prev_str = tok_str(tok.previous)
    if prev_str not in (';', '{', '}', ''):
        return
    emit(
        tok,
        "warning",
        f"MISRA 17.7: return value of '{tok.str}' is discarded "
        f"(CWE-252)",
        "MSL-07",
    )


# ---------------------------------------------------------------------------
# Per-function body analysis dispatcher
# ---------------------------------------------------------------------------

def analyse_function(func) -> None:
    """
    Walk the token stream of a single function body and dispatch per-rule
    checks.
    """
    # Locate the opening brace of the function body via the token stream
    body_start = None
    t = func.tokenDef if hasattr(func, 'tokenDef') else None
    if t is None:
        return

    # Advance to '{' that opens the body (skip declaration tokens)
    scan = t
    depth = 0
    while scan:
        if scan.str == '{':
            depth += 1
            if depth == 1:
                body_start = scan
                break
        scan = scan.next

    if body_start is None:
        return

    body_end = find_matching_brace(body_start)
    if body_end is None:
        return

    # Rule MSL-02 and MSL-10 need the full range
    check_msl02_multiple_returns(func, body_start, body_end)
    check_msl10_multiple_break(func, body_start, body_end)

    # Token-by-token checks
    t = body_start
    while t and t != body_end:
        check_msl01_non_bool_control(t)
        check_msl05_mixed_ops(t)
        check_msl06_inc_dec_in_bool(t)
        check_msl07_ignored_return(t)
        check_msl03_msl04_switch(t)
        check_msl09_banned_memory(t)
        t = t.next


# ---------------------------------------------------------------------------
# Global token-level checks (outside function bodies)
# ---------------------------------------------------------------------------

def analyse_global_tokens(cfg) -> None:
    """
    Checks that apply to tokens regardless of function context:
      MSL-03/04  (switch at file scope — rare but possible)
      MSL-09     (banned memory anywhere)
    """
    for tok in cfg.tokenlist:
        check_msl03_msl04_switch(tok)
        check_msl09_banned_memory(tok)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: python3 {os.path.basename(__file__)} <file.c.dump>",
              file=sys.stderr)
        sys.exit(1)

    dump_file = sys.argv[1]

    try:
        data = cppcheckdata.parsedump(dump_file)
    except Exception as exc:
        print(f"[{ADDON_NAME}] Failed to parse dump: {exc}", file=sys.stderr)
        sys.exit(1)

    for cfg in data.configurations:
        # ── Directive-level checks ──────────────────────────────────────────
        check_msl08_define_keyword(cfg)

        # ── Function-level analysis ─────────────────────────────────────────
        if hasattr(cfg, 'functions'):
            for func in cfg.functions:
                try:
                    analyse_function(func)
                except Exception as exc:
                    # Soft failure: never crash the entire addon on one function
                    print(
                        f"[{ADDON_NAME}] Warning: exception in function "
                        f"'{getattr(func, 'name', '?')}': {exc}",
                        file=sys.stderr,
                    )


if __name__ == '__main__':
    main()
