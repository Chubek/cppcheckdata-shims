"""
OwnershipFlowTracker.py — Cppcheck addon
========================================
Tracks heap pointer ownership, transfer, and aliasing errors.

Checkers
--------
OFT-01  double_free_on_same_path          CWE-415
OFT-02  use_after_free_deref              CWE-416
OFT-03  mismatched_alloc_free             CWE-762
OFT-04  free_of_stack_address             CWE-590
OFT-05  ownership_escaped_without_nulling CWE-416
OFT-06  conditional_free_then_use         CWE-416
OFT-07  realloc_original_lost             CWE-401
OFT-08  alloc_in_loop_no_free             CWE-401

Shim contract
-------------
Variable IDs are accessed ONLY via _safe_vid() / _safe_vid_tok().
All .variable, .valueType, .astParent, .astOperand1/2 accesses are
guarded for None before use.

Author : Generated for the OwnershipFlowTracker addon suite
"""

import sys
import re

# ---------------------------------------------------------------------------
# Shim: attempt to import cppcheckdata; fall back to a minimal stub so that
# the module can be syntax-checked without the Cppcheck runtime present.
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:  # pragma: no cover
    cppcheckdata = None  # type: ignore


# ===========================================================================
# Safe-access helpers  (SHIMS_VADE_MECUM contract)
# ===========================================================================

def _safe_vid(var):
    """Return var.Id as a string key, or None if var is None / Id missing."""
    if var is None:
        return None
    try:
        vid = var.Id
        return str(vid) if vid is not None else None
    except AttributeError:
        return None


def _safe_vid_tok(tok):
    """Return the variable-Id of tok.variable, or None."""
    if tok is None:
        return None
    try:
        var = tok.variable
    except AttributeError:
        return None
    return _safe_vid(var)


# ===========================================================================
# AST / token utility helpers
# ===========================================================================

def _get_call_name(tok):
    """
    Given a token that is a '(' (function call), return the function name
    string, or None.

    cppcheckdata represents  foo(...)  as:
        tok  = '('
        tok.astOperand1 = name token  (or  tok.previous for older builds)
    """
    if tok is None:
        return None
    # Primary: astOperand1 holds the function name token
    try:
        op1 = tok.astOperand1
        if op1 is not None and op1.str:
            return op1.str
    except AttributeError:
        pass
    # Fallback: previous token (non-AST path)
    try:
        prev = tok.previous
        if prev is not None and prev.str and prev.str.isidentifier():
            return prev.str
    except AttributeError:
        pass
    return None


def _get_call_arg(tok, n):
    """
    Return the token representing the N-th argument (0-based) of a call
    whose '(' token is *tok*.

    The argument list is encoded in the AST as a right-leaning tree of
    ',' nodes:
        arg0  ,  (arg1 , (arg2 , ...))
    astOperand2 of '(' is the root of that tree.
    """
    if tok is None:
        return None
    try:
        arg_root = tok.astOperand2  # first arg or root of comma tree
    except AttributeError:
        return None

    if arg_root is None:
        return None

    current = arg_root
    idx = 0
    while current is not None:
        # If current is a ',' node, descend left for the current argument
        try:
            is_comma = current.str == ','
        except AttributeError:
            is_comma = False

        if is_comma:
            if idx == n:
                try:
                    return current.astOperand1
                except AttributeError:
                    return None
            idx += 1
            try:
                current = current.astOperand2
            except AttributeError:
                return None
        else:
            # Leaf: this is the final (or only) argument
            if idx == n:
                return current
            return None

    return None


# ---------------------------------------------------------------------------
# Allocator / freer classification
# ---------------------------------------------------------------------------

_ALLOC_FUNCS = {
    'malloc':   'malloc_family',
    'calloc':   'malloc_family',
    'strdup':   'malloc_family',
    'strndup':  'malloc_family',
    'realloc':  'malloc_family',   # treated separately in OFT-07
    'aligned_alloc': 'malloc_family',
    'posix_memalign': 'malloc_family',
    'new':      'new_family',      # operator new (name-token fallback)
}

_FREE_FUNCS = {
    'free':     'malloc_family',
    'delete':   'new_family',      # operator delete (name-token fallback)
}


def _is_alloc_call(tok):
    """
    If tok is a '(' whose callee is an allocator, return the family string.
    Otherwise return None.
    tok is expected to be a '(' token.
    """
    name = _get_call_name(tok)
    if name is None:
        return None
    return _ALLOC_FUNCS.get(name)


def _is_free_call(tok):
    """
    If tok is a '(' whose callee is a freer, return the family string.
    Otherwise return None.
    """
    name = _get_call_name(tok)
    if name is None:
        return None
    return _FREE_FUNCS.get(name)


# Transfer-semantic name prefixes for OFT-05
_TRANSFER_PREFIXES = (
    'take_', 'move_', 'give_', 'transfer_',
    'consume_', 'adopt_', 'release_', 'pass_',
)


def _is_transfer_call(call_name):
    """Return True if the callee name implies ownership transfer."""
    if call_name is None:
        return False
    lower = call_name.lower()
    return any(lower.startswith(p) for p in _TRANSFER_PREFIXES)


# ===========================================================================
# Scope / type helpers
# ===========================================================================

def _scope_type(tok):
    """Return tok.scope.type string, or '' if unavailable."""
    try:
        s = tok.scope
        if s is None:
            return ''
        return s.type or ''
    except AttributeError:
        return ''


def _var_is_local(var):
    """
    Return True when var is a local (stack) or global variable —
    i.e. NOT dynamically allocated.  We check the scope type.
    """
    if var is None:
        return False
    try:
        sc = var.nameToken.scope if var.nameToken else None
    except AttributeError:
        sc = None
    if sc is None:
        try:
            sc = var.scope
        except AttributeError:
            return False
    if sc is None:
        return False
    try:
        return sc.type in ('Function', 'Global', 'Namespace', 'Class')
    except AttributeError:
        return False


def _var_is_array_or_address(var):
    """
    Return True if the variable is a plain array (not a pointer-to-heap).
    Heuristic: variable token is not a pointer dereference.
    """
    if var is None:
        return False
    try:
        return var.isArray
    except AttributeError:
        return False


def _is_in_loop(tok):
    """
    Return True if tok resides inside a For or While scope.
    Walk the scope chain upward.
    """
    try:
        sc = tok.scope
    except AttributeError:
        return False
    while sc is not None:
        try:
            t = sc.type
        except AttributeError:
            break
        if t in ('For', 'While', 'Do'):
            return True
        try:
            sc = sc.nestedIn
        except AttributeError:
            break
    return False


def _scope_id(tok):
    """Return a stable id for tok's scope (for loop-body grouping)."""
    try:
        s = tok.scope
        if s is None:
            return None
        return id(s)
    except AttributeError:
        return None


# ===========================================================================
# Argument extraction helpers
# ===========================================================================

def _arg0_vid(call_paren_tok):
    """Return the variable-Id of the first argument to a call, or None."""
    arg = _get_call_arg(call_paren_tok, 0)
    if arg is None:
        return None
    # The arg may itself be a dereference or address-of — try to resolve
    # the base variable.
    return _resolve_base_vid(arg)


def _resolve_base_vid(tok):
    """
    Walk down a simple expression to find the variable token.
    Handles:  p,  *p,  &p,  p->x  (return vid of p in all cases).
    """
    if tok is None:
        return None
    try:
        s = tok.str
    except AttributeError:
        return None

    if s in ('*', '&', '->'):
        try:
            return _resolve_base_vid(tok.astOperand1)
        except AttributeError:
            return None

    return _safe_vid_tok(tok)


# ===========================================================================
# OFT-01 / OFT-02 — double free & use-after-free
# ===========================================================================

def _check_oft01_oft02(cfg, data):
    """
    OFT-01  double_free_on_same_path
    OFT-02  use_after_free_deref

    Strategy: single linear pass over token list per function scope.
    Maintain freed_set  (set of variable Ids known to be freed).
    On free(p)  → if p in freed_set: OFT-01 else add to freed_set.
    On reassign  p = ...  → remove p from freed_set.
    On deref/read of p where p in freed_set → OFT-02.
    """
    errors = []

    for func in cfg.functions:
        freed_set = {}   # vid -> tok_of_free (for error location)

        tokens = list(cfg.tokenlist)
        # Restrict to tokens inside this function's scope
        # (simple: filter by scope chain membership)
        func_scope_id = id(func.token.scope) if func.token and func.token.scope else None

        for tok in tokens:
            # ------------------------------------------------------------------
            # Detect free(p) calls
            # ------------------------------------------------------------------
            if tok.str == '(' and _is_free_call(tok):
                vid = _arg0_vid(tok)
                if vid is None:
                    continue

                if vid in freed_set:
                    # OFT-01 — double free
                    errors.append({
                        'tok': tok,
                        'id': 'OFT-01',
                        'msg': (
                            "double_free_on_same_path: "
                            "pointer freed here was already freed at line "
                            f"{freed_set[vid].linenr}. "
                            "[CWE-415]"
                        ),
                        'severity': 'error',
                    })
                else:
                    freed_set[vid] = tok
                continue

            # ------------------------------------------------------------------
            # Detect assignment  p = <something>  — clears freed state
            # ------------------------------------------------------------------
            if tok.str == '=' and tok.isAssignmentOp:
                lhs = tok.astOperand1 if tok.astOperand1 is not None else None
                lhs_vid = _safe_vid_tok(lhs) if lhs else None
                if lhs_vid and lhs_vid in freed_set:
                    # Pointer has been reassigned — no longer freed
                    del freed_set[lhs_vid]
                continue

            # ------------------------------------------------------------------
            # Detect dereference of freed pointer  (OFT-02)
            # ------------------------------------------------------------------
            if tok.str in ('*', '->', '['):
                # Find the base variable being dereferenced
                try:
                    base = tok.astOperand1
                except AttributeError:
                    base = None

                base_vid = _resolve_base_vid(base)
                if base_vid and base_vid in freed_set:
                    errors.append({
                        'tok': tok,
                        'id': 'OFT-02',
                        'msg': (
                            "use_after_free_deref: "
                            f"dereference of pointer freed at line "
                            f"{freed_set[base_vid].linenr}. "
                            "[CWE-416]"
                        ),
                        'severity': 'error',
                    })
                continue

    return errors


# ===========================================================================
# OFT-03 — mismatched alloc / free
# ===========================================================================

def _check_oft03(cfg, data):
    """
    OFT-03  mismatched_alloc_free

    Track: alloc_map  vid -> (family, tok).
    On free(p): if alloc_map[p].family != free_family → flag.
    """
    errors = []

    for func in cfg.functions:
        alloc_map = {}  # vid -> {'family': str, 'tok': tok}

        for tok in cfg.tokenlist:
            if tok.str != '(':
                continue

            alloc_family = _is_alloc_call(tok)
            free_family  = _is_free_call(tok)

            if alloc_family and _get_call_name(tok) != 'realloc':
                # Track what vid this result is assigned to
                # Pattern: vid = malloc(...)  → parent of '(' is '='
                try:
                    assign = tok.astParent
                    if assign is None or assign.str != '=':
                        continue
                    lhs = assign.astOperand1
                    vid = _safe_vid_tok(lhs)
                    if vid:
                        alloc_map[vid] = {'family': alloc_family, 'tok': tok}
                except AttributeError:
                    continue

            elif free_family:
                vid = _arg0_vid(tok)
                if vid is None:
                    continue
                if vid in alloc_map:
                    expected = alloc_map[vid]['family']
                    if expected != free_family:
                        alloc_tok = alloc_map[vid]['tok']
                        alloc_name = _get_call_name(alloc_tok) or '?'
                        free_name  = _get_call_name(tok) or '?'
                        errors.append({
                            'tok': tok,
                            'id': 'OFT-03',
                            'msg': (
                                "mismatched_alloc_free: "
                                f"pointer allocated with '{alloc_name}' "
                                f"(line {alloc_tok.linenr}) "
                                f"is freed with '{free_name}'. "
                                "Mismatched memory management routines. "
                                "[CWE-762]"
                            ),
                            'severity': 'error',
                        })
                # Remove from map regardless — after free, ownership is done
                alloc_map.pop(vid, None)

    return errors


# ===========================================================================
# OFT-04 — free of stack address
# ===========================================================================

def _check_oft04(cfg, data):
    """
    OFT-04  free_of_stack_address

    Detect:
      free(&local_var)   — address-of a non-pointer local
      free(array_name)   — array decayed to pointer passed to free
    """
    errors = []

    for tok in cfg.tokenlist:
        if tok.str != '(' or not _is_free_call(tok):
            continue

        arg = _get_call_arg(tok, 0)
        if arg is None:
            continue

        # Case 1: free(&x)
        try:
            is_addr_of = arg.str == '&'
        except AttributeError:
            is_addr_of = False

        if is_addr_of:
            try:
                inner = arg.astOperand1
            except AttributeError:
                inner = None
            inner_var = inner.variable if inner else None
            if inner_var is not None and _var_is_local(inner_var):
                errors.append({
                    'tok': tok,
                    'id': 'OFT-04',
                    'msg': (
                        "free_of_stack_address: "
                        f"'free' called on address of local variable "
                        f"'{getattr(inner, 'str', '?')}'. "
                        "Freeing stack memory is undefined behaviour. "
                        "[CWE-590]"
                    ),
                    'severity': 'error',
                })
            continue

        # Case 2: free(array_name) — arg is directly a variable token
        try:
            arg_var = arg.variable
        except AttributeError:
            arg_var = None

        if arg_var is not None and _var_is_array_or_address(arg_var):
            if _var_is_local(arg_var):
                errors.append({
                    'tok': tok,
                    'id': 'OFT-04',
                    'msg': (
                        "free_of_stack_address: "
                        f"'free' called on local array "
                        f"'{getattr(arg, 'str', '?')}'. "
                        "Freeing a stack array is undefined behaviour. "
                        "[CWE-590]"
                    ),
                    'severity': 'error',
                })

    return errors


# ===========================================================================
# OFT-05 — ownership escaped without nulling
# ===========================================================================

def _check_oft05(cfg, data):
    """
    OFT-05  ownership_escaped_without_nulling

    When a pointer is passed to a transfer-semantic function, mark it
    ESCAPED.  Any subsequent dereference or use (other than assignment)
    in the calling function is flagged.
    """
    errors = []

    for func in cfg.functions:
        escaped = {}  # vid -> escape_tok

        for tok in cfg.tokenlist:
            if tok.str != '(':
                continue

            call_name = _get_call_name(tok)
            if call_name is None:
                continue

            # --- Escape event ---
            if _is_transfer_call(call_name):
                # Check every argument for pointer variables
                for n in range(8):   # inspect up to 8 args
                    arg = _get_call_arg(tok, n)
                    if arg is None:
                        break
                    vid = _resolve_base_vid(arg)
                    if vid and vid not in escaped:
                        escaped[vid] = tok
                continue

            # --- Not a transfer call — check for dereference of escaped ptr ---
            # (handled in token loop below)

        # Second pass: look for dereferences of escaped vids
        for tok in cfg.tokenlist:
            if tok.str in ('*', '->', '['):
                try:
                    base_vid = _resolve_base_vid(tok.astOperand1)
                except AttributeError:
                    base_vid = None
                if base_vid and base_vid in escaped:
                    escape_tok = escaped[base_vid]
                    call_name  = _get_call_name(escape_tok) or '?'
                    errors.append({
                        'tok': tok,
                        'id': 'OFT-05',
                        'msg': (
                            "ownership_escaped_without_nulling: "
                            f"pointer passed to '{call_name}' "
                            f"(line {escape_tok.linenr}) suggests ownership "
                            "transfer; subsequent dereference may be invalid. "
                            "Set pointer to NULL after transfer. "
                            "[CWE-416]"
                        ),
                        'severity': 'warning',
                    })
            # Clear escaped state on reassignment
            if tok.str == '=' and getattr(tok, 'isAssignmentOp', False):
                lhs_vid = _safe_vid_tok(getattr(tok, 'astOperand1', None))
                if lhs_vid:
                    escaped.pop(lhs_vid, None)

    return errors


# ===========================================================================
# OFT-06 — conditional free then use
# ===========================================================================

def _check_oft06(cfg, data):
    """
    OFT-06  conditional_free_then_use

    Linear heuristic:
    When free(p) appears and its immediate enclosing scope has type 'If',
    record p as conditionally_freed.  If p is later used (dereferenced
    or passed to a call that is NOT free/NULL-check) without reassignment
    → flag.
    """
    errors = []

    for func in cfg.functions:
        cond_freed = {}  # vid -> (tok, if_scope_id)

        for tok in cfg.tokenlist:
            # --- Detect free(p) inside an If scope ---
            if tok.str == '(' and _is_free_call(tok):
                vid = _arg0_vid(tok)
                if vid is None:
                    continue
                s_type = _scope_type(tok)
                if s_type == 'If':
                    cond_freed[vid] = (tok, _scope_id(tok))
                elif vid in cond_freed:
                    # Unconditional free — remove from conditional tracking
                    del cond_freed[vid]
                continue

            # --- Reassignment clears the conditional-free state ---
            if tok.str == '=' and getattr(tok, 'isAssignmentOp', False):
                lhs_vid = _safe_vid_tok(getattr(tok, 'astOperand1', None))
                if lhs_vid and lhs_vid in cond_freed:
                    del cond_freed[lhs_vid]
                continue

            # --- NULL comparison clears the state (safe guard) ---
            if tok.str in ('==', '!='):
                try:
                    op1 = tok.astOperand1
                    op2 = tok.astOperand2
                except AttributeError:
                    continue
                for side in (op1, op2):
                    if side and getattr(side, 'str', '') in ('NULL', '0', 'nullptr'):
                        other = op2 if side is op1 else op1
                        vid = _safe_vid_tok(other)
                        if vid:
                            cond_freed.pop(vid, None)
                continue

            # --- Detect dereference of conditionally-freed pointer ---
            if tok.str in ('*', '->', '['):
                try:
                    base_vid = _resolve_base_vid(tok.astOperand1)
                except AttributeError:
                    base_vid = None
                if base_vid and base_vid in cond_freed:
                    free_tok, _ = cond_freed[base_vid]
                    errors.append({
                        'tok': tok,
                        'id': 'OFT-06',
                        'msg': (
                            "conditional_free_then_use: "
                            f"pointer was freed inside an 'if' branch "
                            f"(line {free_tok.linenr}) and is dereferenced "
                            "here without a NULL check or reassignment. "
                            "[CWE-416]"
                        ),
                        'severity': 'error',
                    })

    return errors


# ===========================================================================
# OFT-07 — realloc original lost
# ===========================================================================

def _check_oft07(cfg, data):
    """
    OFT-07  realloc_original_lost

    Detect:   p = realloc(p, n);
    where the same variable appears as both the LHS of the assignment
    and the first argument of realloc().

    If realloc returns NULL, the original pointer is overwritten and the
    old memory is leaked.
    """
    errors = []

    for tok in cfg.tokenlist:
        if tok.str != '(':
            continue
        if _get_call_name(tok) != 'realloc':
            continue

        # Check: assignment parent  p = realloc(p, n)
        try:
            assign = tok.astParent
        except AttributeError:
            continue
        if assign is None or assign.str != '=':
            continue

        lhs     = getattr(assign, 'astOperand1', None)
        lhs_vid = _safe_vid_tok(lhs)
        if lhs_vid is None:
            continue

        # First argument of realloc
        arg0_vid = _arg0_vid(tok)
        if arg0_vid is None:
            continue

        if lhs_vid == arg0_vid:
            errors.append({
                'tok': tok,
                'id': 'OFT-07',
                'msg': (
                    "realloc_original_lost: "
                    f"result of 'realloc' assigned back to the same pointer "
                    f"'{getattr(lhs, 'str', '?')}'. "
                    "If realloc returns NULL the original allocation is leaked. "
                    "Use a temporary: tmp = realloc(p, n); if (tmp) p = tmp; "
                    "[CWE-401]"
                ),
                'severity': 'warning',
            })

    return errors


# ===========================================================================
# OFT-08 — alloc in loop no free
# ===========================================================================

def _check_oft08(cfg, data):
    """
    OFT-08  alloc_in_loop_no_free

    For each malloc/calloc call inside a loop scope:
    - Record the assigned variable vid and the loop scope id.
    - Scan the same loop body for a free() of that vid.
    - If no free() found → flag.

    We also suppress if the variable is returned or passed to a
    transfer-semantic call inside the loop (escape = intentional).
    """
    errors = []

    # Collect all alloc sites in loops
    alloc_sites = []   # list of {'vid': ..., 'tok': ..., 'loop_sid': ...}

    for tok in cfg.tokenlist:
        if tok.str != '(':
            continue
        alloc_family = _is_alloc_call(tok)
        if alloc_family is None:
            continue
        if _get_call_name(tok) == 'realloc':
            continue
        if not _is_in_loop(tok):
            continue

        # Get the variable the result is assigned to
        try:
            assign = tok.astParent
        except AttributeError:
            continue
        if assign is None or assign.str != '=':
            continue

        lhs_vid = _safe_vid_tok(getattr(assign, 'astOperand1', None))
        if lhs_vid is None:
            continue

        loop_sid = _innermost_loop_scope_id(tok)
        alloc_sites.append({
            'vid':      lhs_vid,
            'tok':      tok,
            'loop_sid': loop_sid,
        })

    # For each alloc site, look for a matching free or escape in the same loop
    for site in alloc_sites:
        vid      = site['vid']
        alloc_tok = site['tok']
        loop_sid = site['loop_sid']

        found_free   = False
        found_escape = False

        for tok in cfg.tokenlist:
            if _innermost_loop_scope_id(tok) != loop_sid:
                continue

            # Free?
            if tok.str == '(' and _is_free_call(tok):
                if _arg0_vid(tok) == vid:
                    found_free = True
                    break

            # Transfer escape?
            if tok.str == '(':
                cname = _get_call_name(tok)
                if cname and _is_transfer_call(cname):
                    for n in range(8):
                        arg = _get_call_arg(tok, n)
                        if arg is None:
                            break
                        if _resolve_base_vid(arg) == vid:
                            found_escape = True
                            break
                if found_escape:
                    break

            # Return of pointer — escape
            if tok.str == 'return':
                try:
                    ret_op = tok.astOperand1
                except AttributeError:
                    ret_op = None
                if ret_op and _resolve_base_vid(ret_op) == vid:
                    found_escape = True
                    break

        if not found_free and not found_escape:
            alloc_name = _get_call_name(alloc_tok) or 'malloc'
            errors.append({
                'tok': alloc_tok,
                'id': 'OFT-08',
                'msg': (
                    "alloc_in_loop_no_free: "
                    f"'{alloc_name}' inside loop allocates a new buffer "
                    "each iteration but no 'free' is visible in the same "
                    "loop body. The previous allocation is leaked on each "
                    "iteration. [CWE-401]"
                ),
                'severity': 'warning',
            })

    return errors


def _innermost_loop_scope_id(tok):
    """Return the id() of the innermost For/While/Do scope of tok, or None."""
    try:
        sc = tok.scope
    except AttributeError:
        return None
    while sc is not None:
        try:
            t = sc.type
        except AttributeError:
            break
        if t in ('For', 'While', 'Do'):
            return id(sc)
        try:
            sc = sc.nestedIn
        except AttributeError:
            break
    return None


# ===========================================================================
# Error emission
# ===========================================================================

# Severity → Cppcheck severity string mapping
_SEVERITY_MAP = {
    'error':       'error',
    'warning':     'warning',
    'style':       'style',
    'performance': 'performance',
}

# Checker → CWE number
_CWE_MAP = {
    'OFT-01': 415,
    'OFT-02': 416,
    'OFT-03': 762,
    'OFT-04': 590,
    'OFT-05': 416,
    'OFT-06': 416,
    'OFT-07': 401,
    'OFT-08': 401,
}


def _emit(errors, checker_id_filter=None):
    """
    Emit all collected errors through cppcheckdata.reportError().
    If cppcheckdata is not available, print to stderr.
    """
    for e in errors:
        tok      = e['tok']
        msg      = e['msg']
        checker  = e['id']
        severity = _SEVERITY_MAP.get(e.get('severity', 'warning'), 'warning')
        cwe      = _CWE_MAP.get(checker, 0)

        if checker_id_filter and checker not in checker_id_filter:
            continue

        if cppcheckdata is not None:
            try:
                cppcheckdata.reportError(tok, severity, msg, 'OwnershipFlowTracker', checker)
            except TypeError:
                # Older cppcheckdata API without addon/checker args
                cppcheckdata.reportError(tok, severity, msg)
        else:
            loc = f"{getattr(tok, 'file', '?')}:{getattr(tok, 'linenr', '?')}"
            print(f"[{checker}] {loc}: {msg}", file=sys.stderr)


# ===========================================================================
# Entry point
# ===========================================================================

def analyse(filename, checker_id_filter=None):
    """
    Main entry point called by Cppcheck.
    Parses the dump file and runs all checkers.
    """
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not found.", file=sys.stderr)
        sys.exit(1)

    data = cppcheckdata.parsedump(filename)

    all_errors = []

    for cfg in data.configurations:
        all_errors += _check_oft01_oft02(cfg, data)
        all_errors += _check_oft03(cfg, data)
        all_errors += _check_oft04(cfg, data)
        all_errors += _check_oft05(cfg, data)
        all_errors += _check_oft06(cfg, data)
        all_errors += _check_oft07(cfg, data)
        all_errors += _check_oft08(cfg, data)

    _emit(all_errors, checker_id_filter)


# ---------------------------------------------------------------------------
# Cppcheck addon protocol: called as   python3 OwnershipFlowTracker.py file.c.dump
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 OwnershipFlowTracker.py <file.c.dump>", file=sys.stderr)
        sys.exit(1)

    dump_file = sys.argv[1]
    analyse(dump_file)
