"""
StackBufferHardenLint.py — Cppcheck addon
==========================================
Detects stack-based buffer overflow patterns: dangerous string/memory
functions, fixed-size arrays with unchecked inputs, alloca misuse,
VLA risks, off-by-one patterns, stack address returns, and more.

Checkers
--------
SBH-01  unsafe_string_function      Use of strcpy/strcat/gets/sprintf
SBH-02  bounded_func_size_mismatch  strncpy/strncat n > dest size literal
SBH-03  alloca_unchecked            alloca() without size guard
SBH-04  vla_unbounded               VLA declared with non-const/unchecked size
SBH-05  stack_address_returned      Function returns pointer to local variable
SBH-06  fixed_array_index_unchecked Array indexed with non-literal, unbounded index
SBH-07  gets_usage                  gets() used (removed in C11, always unsafe)
SBH-08  off_by_one_size_arg         Size arg to str/mem function = sizeof(buf) + constant

CWE mapping
-----------
SBH-01, SBH-07  →  CWE-120  (Buffer Copy without Checking Size of Input)
SBH-02          →  CWE-193  (Off-by-One Error)
SBH-03          →  CWE-770  (Allocation without Limits)
SBH-04          →  CWE-770  (Allocation without Limits)
SBH-05          →  CWE-562  (Return of Stack Variable Address)
SBH-06          →  CWE-129  (Improper Validation of Array Index)
SBH-08          →  CWE-193  (Off-by-One Error)

Shim contract
-------------
All .variable, .valueType, .astParent, .astOperand1/2 accesses guarded.
"""

import sys
import re
from collections import defaultdict

try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore


# ===========================================================================
# §1  Safe field accessors
# ===========================================================================

def _safe_vid(var):
    if var is None:
        return None
    try:
        vid = var.Id
        return str(vid) if vid is not None else None
    except AttributeError:
        return None


def _safe_vid_tok(tok):
    if tok is None:
        return None
    try:
        var = tok.variable
    except AttributeError:
        return None
    return _safe_vid(var)


def _tok_str(tok):
    if tok is None:
        return ''
    try:
        return tok.str or ''
    except AttributeError:
        return ''


def _tok_linenr(tok):
    if tok is None:
        return 0
    try:
        return int(tok.linenr) if tok.linenr is not None else 0
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_file(tok):
    if tok is None:
        return ''
    try:
        return tok.file or ''
    except AttributeError:
        return ''


def _tok_is_string(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isString)
    except AttributeError:
        return _tok_str(tok).startswith('"')


def _tok_is_number(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isNumber)
    except AttributeError:
        return False


def _tok_is_name(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isName)
    except AttributeError:
        s = _tok_str(tok)
        return bool(s) and (s[0].isalpha() or s[0] == '_')


def _is_expanded_macro(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isExpandedMacro)
    except AttributeError:
        return False


def _ast_op1(tok):
    if tok is None:
        return None
    try:
        return tok.astOperand1
    except AttributeError:
        return None


def _ast_op2(tok):
    if tok is None:
        return None
    try:
        return tok.astOperand2
    except AttributeError:
        return None


def _ast_parent(tok):
    if tok is None:
        return None
    try:
        return tok.astParent
    except AttributeError:
        return None


def _tok_next(tok):
    if tok is None:
        return None
    try:
        return tok.next
    except AttributeError:
        return None


def _tok_variable(tok):
    if tok is None:
        return None
    try:
        return tok.variable
    except AttributeError:
        return None


def _var_is_local(var):
    """Return True if var is a local (function-scope) variable."""
    if var is None:
        return False
    try:
        return bool(var.isLocal)
    except AttributeError:
        return False


def _var_is_array(var):
    if var is None:
        return False
    try:
        return bool(var.isArray)
    except AttributeError:
        return False


def _var_is_pointer(var):
    if var is None:
        return False
    try:
        return bool(var.isPointer)
    except AttributeError:
        return False


def _var_dimensions(var):
    """Return list of dimension sizes (int or None if unknown)."""
    if var is None:
        return []
    try:
        dims = var.dimensions
        result = []
        for d in dims:
            try:
                result.append(int(d.num))
            except (AttributeError, TypeError, ValueError):
                result.append(None)
        return result
    except AttributeError:
        return []


def _valuetype_type(tok):
    if tok is None:
        return ''
    try:
        vt = tok.valueType
        if vt is None:
            return ''
        return vt.type or ''
    except AttributeError:
        return ''


def _valuetype_pointer(tok):
    if tok is None:
        return 0
    try:
        vt = tok.valueType
        if vt is None:
            return 0
        return int(vt.pointer or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


def _tok_scope(tok):
    if tok is None:
        return None
    try:
        return tok.scope
    except AttributeError:
        return None


def _scope_type(scope):
    if scope is None:
        return ''
    try:
        return scope.type or ''
    except AttributeError:
        return ''


# ===========================================================================
# §2  Call-site helpers
# ===========================================================================

def _call_name_from_paren(tok):
    """Given a '(' call token, return the function name or None."""
    if tok is None or _tok_str(tok) != '(':
        return None
    op1 = _ast_op1(tok)
    if op1 is None:
        return None
    name = _tok_str(op1)
    if name and (name[0].isalpha() or name[0] == '_'):
        return name
    return None


def _collect_args(call_paren_tok):
    """Collect argument AST root tokens from a '(' call token."""
    args = []
    if call_paren_tok is None:
        return args
    arg_root = _ast_op2(call_paren_tok)
    if arg_root is None:
        return args
    node = arg_root
    while node is not None:
        if _tok_str(node) == ',':
            left = _ast_op1(node)
            if left is not None:
                args.append(left)
            node = _ast_op2(node)
        else:
            args.append(node)
            break
    return args


def _try_parse_int(tok):
    """Try to extract an integer value from a number token or simple expression."""
    if tok is None:
        return None
    s = _tok_str(tok)
    if _tok_is_number(tok):
        try:
            return int(s, 0)
        except ValueError:
            return None
    # Handle simple sizeof(type) — not fully evaluated, skip
    return None


# ===========================================================================
# §3  Function registries
# ===========================================================================

# Unsafe string functions: name → (dst_arg_idx, src_arg_idx or None)
_UNSAFE_STRING_FUNCS = {
    'strcpy':   (0, 1),
    'strcat':   (0, 1),
    'wcscpy':   (0, 1),
    'wcscat':   (0, 1),
    'sprintf':  (0, None),   # format string may overflow dst
    'vsprintf': (0, None),
}

# gets() — always dangerous, removed from C11
_GETS_FUNCS = frozenset({'gets', '_getts'})

# Bounded variants where we can check n vs dest size
# name → (dst_arg_idx, size_arg_idx)
_BOUNDED_STRING_FUNCS = {
    'strncpy':  (0, 2),
    'strncat':  (0, 2),
    'wcsncpy':  (0, 2),
    'wcsncat':  (0, 2),
    'snprintf': (0, 1),   # dst at 0, size at 1
    'vsnprintf':(0, 1),
    'memcpy':   (0, 2),
    'memmove':  (0, 2),
    'memset':   (0, 2),
}

# alloca
_ALLOCA_FUNCS = frozenset({'alloca', '__builtin_alloca', '_alloca'})


# ===========================================================================
# §4  Array / local variable dimension lookup
# ===========================================================================

def _get_array_size_from_arg(arg_tok):
    """
    Given an AST node that is a buffer argument, try to determine the
    declared size of the underlying array (if it is a local fixed-size array).
    Returns (var, first_dimension_size) or (None, None).
    """
    if arg_tok is None:
        return None, None

    # Dereference & or array-decay: the arg may be bare name or &name
    tok = arg_tok
    s = _tok_str(tok)

    # Strip address-of
    if s == '&':
        tok = _ast_op1(tok)
        s = _tok_str(tok)

    var = _tok_variable(tok)
    if var is None:
        return None, None

    if not _var_is_array(var) and not _var_is_pointer(var):
        return None, None

    dims = _var_dimensions(var)
    if dims:
        return var, dims[0]
    return var, None


# ===========================================================================
# §5  Checker implementations
# ===========================================================================

def _check_sbh01(call_name, paren_tok, errors):
    """SBH-01: Unsafe string/format functions (strcpy, strcat, sprintf, etc.)."""
    if call_name not in _UNSAFE_STRING_FUNCS:
        return
    errors.append(_mk(
        'SBH-01', paren_tok,
        f"unsafe_string_function: "
        f"'{call_name}' does not check destination buffer size and can "
        f"overflow the stack. "
        f"Replace with the bounded equivalent "
        f"(e.g., strncpy/strncat/snprintf) and verify size arguments. "
        f"[CWE-120]",
        'warning',
    ))


def _check_sbh02(call_name, paren_tok, errors):
    """SBH-02: Bounded func size arg > declared dest buffer size."""
    spec = _BOUNDED_STRING_FUNCS.get(call_name)
    if spec is None:
        return

    dst_idx, size_idx = spec
    args = _collect_args(paren_tok)

    if len(args) <= max(dst_idx, size_idx):
        return

    dst_tok  = args[dst_idx]
    size_tok = args[size_idx]

    _var, arr_size = _get_array_size_from_arg(dst_tok)
    if arr_size is None:
        return

    n = _try_parse_int(size_tok)
    if n is None:
        return

    if n > arr_size:
        errors.append(_mk(
            'SBH-02', paren_tok,
            f"bounded_func_size_mismatch: "
            f"'{call_name}' size argument ({n}) exceeds declared destination "
            f"buffer size ({arr_size}). "
            f"This will write beyond the stack array boundary. "
            f"Ensure size argument ≤ sizeof(dest). "
            f"[CWE-193]",
            'error',
        ))
    elif n == arr_size and call_name in ('strncat', 'wcsncat'):
        # strncat(dst, src, sizeof(dst)) is wrong — it should be
        # sizeof(dst) - strlen(dst) - 1
        errors.append(_mk(
            'SBH-02', paren_tok,
            f"bounded_func_size_mismatch: "
            f"'{call_name}' with n = full buffer size ({n}) ignores existing "
            f"content in dst; correct n should be sizeof(dst)-strlen(dst)-1. "
            f"[CWE-193]",
            'warning',
        ))


def _check_sbh03(call_name, paren_tok, errors):
    """SBH-03: alloca() without an obvious size guard."""
    if call_name not in _ALLOCA_FUNCS:
        return

    args = _collect_args(paren_tok)
    if not args:
        errors.append(_mk(
            'SBH-03', paren_tok,
            f"alloca_unchecked: "
            f"'{call_name}' called with no arguments. "
            f"[CWE-770]",
            'error',
        ))
        return

    size_tok = args[0]
    size_str = _tok_str(size_tok)

    # If the size is a literal integer, only flag if it's suspiciously large
    if _tok_is_number(size_tok):
        try:
            n = int(size_str, 0)
            if n > 65536:
                errors.append(_mk(
                    'SBH-03', paren_tok,
                    f"alloca_unchecked: "
                    f"'{call_name}' allocates {n} bytes on the stack. "
                    f"Large stack allocations risk stack overflow. "
                    f"Use heap allocation for sizes > 64 KiB. "
                    f"[CWE-770]",
                    'warning',
                ))
        except ValueError:
            pass
        return

    # Non-literal size — flag as potentially unbounded
    errors.append(_mk(
        'SBH-03', paren_tok,
        f"alloca_unchecked: "
        f"'{call_name}' called with a non-constant size ('{size_str}'). "
        f"If the size is attacker-controlled or unbounded, this will "
        f"silently overflow the stack (alloca does not return NULL on failure). "
        f"Validate the size before calling alloca or use malloc/free instead. "
        f"[CWE-770]",
        'warning',
    ))


def _check_sbh07(call_name, paren_tok, errors):
    """SBH-07: gets() usage."""
    if call_name not in _GETS_FUNCS:
        return
    errors.append(_mk(
        'SBH-07', paren_tok,
        f"gets_usage: "
        f"'{call_name}' reads an unbounded line from stdin into a fixed buffer "
        f"and was removed from the C standard in C11 due to inherent unsafety. "
        f"Replace with fgets(buf, sizeof(buf), stdin) and strip the trailing "
        f"newline if needed. "
        f"[CWE-120]",
        'error',
    ))


def _check_sbh08(call_name, paren_tok, errors):
    """SBH-08: Size arg = sizeof(buf) + or - small constant (off-by-one risk)."""
    spec = _BOUNDED_STRING_FUNCS.get(call_name)
    if spec is None:
        return

    dst_idx, size_idx = spec
    args = _collect_args(paren_tok)
    if len(args) <= max(dst_idx, size_idx):
        return

    size_tok = args[size_idx]

    # We are looking for patterns like:  sizeof(x) + 1  or  sizeof(x) - 0
    # represented in AST as  (+  sizeof(x)  1) or (- sizeof(x) 0)
    s = _tok_str(size_tok)

    if s not in ('+', '-'):
        return

    op1 = _ast_op1(size_tok)
    op2 = _ast_op2(size_tok)

    # Check if op1 is sizeof(...)
    if _tok_str(op1) != 'sizeof':
        return

    adjustment = _try_parse_int(op2)
    if adjustment is None:
        return

    if s == '+' and adjustment >= 1:
        errors.append(_mk(
            'SBH-08', paren_tok,
            f"off_by_one_size_arg: "
            f"'{call_name}' size argument is sizeof(buf)+{adjustment}. "
            f"Passing sizeof(buf)+N writes beyond the buffer boundary. "
            f"The correct size limit is sizeof(buf) or sizeof(buf)-1 "
            f"(to leave room for a NUL terminator). "
            f"[CWE-193]",
            'error',
        ))
    elif s == '-' and adjustment == 0:
        errors.append(_mk(
            'SBH-08', paren_tok,
            f"off_by_one_size_arg: "
            f"'{call_name}' size argument is sizeof(buf)-0 (subtracting zero). "
            f"For string functions this does not leave room for the NUL "
            f"terminator; use sizeof(buf)-1. "
            f"[CWE-193]",
            'warning',
        ))


# ===========================================================================
# §6  Statement-level checkers (non-call-site)
# ===========================================================================

def _check_sbh04_vla(tok, errors):
    """
    SBH-04: Variable-length array declared with non-constant size.
    In cppcheckdata, VLAs are Variables where isArray=True and the
    dimension has num=0 (unknown at compile time).  We detect them by
    looking for array declarators whose dimension size is 0/unknown and
    the variable is local.
    """
    var = _tok_variable(tok)
    if var is None:
        return
    if not _var_is_array(var):
        return
    if not _var_is_local(var):
        return

    dims = _var_dimensions(var)
    if not dims:
        return

    first_dim = dims[0]
    if first_dim is not None and first_dim != 0:
        return  # constant-size array — fine

    # Dimension is 0 or unknown → VLA
    errors.append(_mk(
        'SBH-04', tok,
        f"vla_unbounded: "
        f"Local array '{_tok_str(tok)}' appears to be a variable-length array "
        f"(VLA). If the size is derived from user input or an external source "
        f"without validation, this can exhaust the stack. "
        f"Validate the size against a reasonable maximum before declaration, "
        f"or use heap allocation (malloc/calloc). "
        f"[CWE-770]",
        'warning',
    ))


def _check_sbh05_return_local(tok, scope_locals, errors):
    """
    SBH-05: Return of pointer/address of local variable.
    We look for 'return' tokens whose AST operand resolves to a local
    variable (or &local_var) that is a stack-allocated non-static object.
    """
    if _tok_str(tok) != 'return':
        return

    ret_val = _ast_op1(tok)
    if ret_val is None:
        return

    # Strip address-of
    inner = ret_val
    s = _tok_str(inner)
    if s == '&':
        inner = _ast_op1(inner)

    var = _tok_variable(inner)
    if var is None:
        return

    vid = _safe_vid(var)
    if vid not in scope_locals:
        return

    # Make sure the return type is a pointer (returning address of local)
    if _valuetype_pointer(ret_val) < 1 and _tok_str(ret_val) != '&':
        # If the token itself is not address-of and not a pointer, skip
        return

    try:
        is_static = var.isStatic
    except AttributeError:
        is_static = False
    if is_static:
        return

    errors.append(_mk(
        'SBH-05', tok,
        f"stack_address_returned: "
        f"Function returns a pointer to local variable "
        f"'{_tok_str(inner)}'. "
        f"The local's lifetime ends when the function returns; "
        f"the caller receives a dangling pointer into freed stack space. "
        f"Return a heap-allocated object or use an output parameter instead. "
        f"[CWE-562]",
        'error',
    ))


def _check_sbh06_unchecked_index(tok, errors):
    """
    SBH-06: Array subscript with a non-literal, potentially unchecked index.
    We detect '[' tokens where the index operand is a non-constant variable
    with no obvious bounds check in the surrounding expression.
    """
    if _tok_str(tok) != '[':
        return

    # op1 = array, op2 = index
    index_tok = _ast_op2(tok)
    if index_tok is None:
        return

    # Literal index is fine
    if _tok_is_number(index_tok):
        return

    # Check the array operand is a fixed-size local array
    arr_tok = _ast_op1(tok)
    arr_var = _tok_variable(arr_tok) if arr_tok is not None else None
    if arr_var is None:
        return
    if not _var_is_array(arr_var):
        return
    if not _var_is_local(arr_var):
        return

    dims = _var_dimensions(arr_var)
    arr_size = dims[0] if dims else None
    if arr_size is None or arr_size == 0:
        return  # Unknown-size or VLA — SBH-04 covers VLAs

    # Index is a variable or expression — emit advisory
    idx_str = _tok_str(index_tok)
    errors.append(_mk(
        'SBH-06', tok,
        f"fixed_array_index_unchecked: "
        f"Array '{_tok_str(arr_tok)}' (size {arr_size}) is indexed with "
        f"a non-literal expression ('{idx_str}'). "
        f"If '{idx_str}' is not validated to be in [0, {arr_size - 1}], "
        f"this is an out-of-bounds access on the stack. "
        f"Add a bounds check before the access. "
        f"[CWE-129]",
        'warning',
    ))


# ===========================================================================
# §7  Local variable collector (for SBH-05)
# ===========================================================================

def _collect_scope_locals(cfg):
    """
    Build a set of variable IDs that are local, non-static, non-argument,
    stack-allocated variables within the current cfg.
    """
    local_ids = set()
    for var in cfg.variables:
        try:
            if not var.isLocal:
                continue
            try:
                if var.isStatic:
                    continue
            except AttributeError:
                pass
            try:
                if var.isArgument:
                    continue
            except AttributeError:
                pass
            vid = _safe_vid(var)
            if vid is not None:
                local_ids.add(vid)
        except AttributeError:
            continue
    return local_ids


# ===========================================================================
# §8  Per-cfg scanner
# ===========================================================================

def _scan_cfg(cfg):
    errors = []
    scope_locals = _collect_scope_locals(cfg)

    seen_vla_vids = set()  # Avoid duplicate VLA reports per variable

    for tok in cfg.tokenlist:
        if _is_expanded_macro(tok):
            continue

        s = _tok_str(tok)

        # --- Call-site checkers ---
        if s == '(':
            call_name = _call_name_from_paren(tok)
            if call_name:
                _check_sbh01(call_name, tok, errors)
                _check_sbh02(call_name, tok, errors)
                _check_sbh03(call_name, tok, errors)
                _check_sbh07(call_name, tok, errors)
                _check_sbh08(call_name, tok, errors)

        # --- return statement ---
        elif s == 'return':
            _check_sbh05_return_local(tok, scope_locals, errors)

        # --- Array subscript ---
        elif s == '[':
            _check_sbh06_unchecked_index(tok, errors)

        # --- VLA detection: identifier tokens that are local arrays ---
        elif _tok_is_name(tok):
            var = _tok_variable(tok)
            if var is not None:
                vid = _safe_vid(var)
                if vid is not None and vid not in seen_vla_vids:
                    _check_sbh04_vla(tok, errors)
                    seen_vla_vids.add(vid)

    return errors


# ===========================================================================
# §9  Error construction and emission
# ===========================================================================

def _mk(checker_id, tok, msg, severity='warning'):
    return {
        'id':       checker_id,
        'tok':      tok,
        'msg':      msg,
        'severity': severity,
    }


_CWE_FROM_ID = {
    'SBH-01': 120,
    'SBH-02': 193,
    'SBH-03': 770,
    'SBH-04': 770,
    'SBH-05': 562,
    'SBH-06': 129,
    'SBH-07': 120,
    'SBH-08': 193,
}

_SEV_MAP = {
    'error':   'error',
    'warning': 'warning',
    'style':   'style',
}


def _emit(errors, filter_ids=None):
    for e in errors:
        tok      = e['tok']
        msg      = e['msg']
        checker  = e['id']
        severity = _SEV_MAP.get(e.get('severity', 'warning'), 'warning')

        if filter_ids and checker not in filter_ids:
            continue

        if cppcheckdata is not None:
            try:
                cppcheckdata.reportError(
                    tok, severity, msg, 'StackBufferHardenLint', checker
                )
            except TypeError:
                try:
                    cppcheckdata.reportError(tok, severity, msg)
                except Exception:
                    pass
        else:
            loc = f"{_tok_file(tok)}:{_tok_linenr(tok)}"
            print(f"[{checker}] {loc}: {msg}", file=sys.stderr)


# ===========================================================================
# §10  Public entry point
# ===========================================================================

def analyse(filename, filter_ids=None):
    """Main entry point called by Cppcheck's addon runner."""
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not found.", file=sys.stderr)
        sys.exit(1)

    data = cppcheckdata.parsedump(filename)

    all_errors = []
    for cfg in data.configurations:
        all_errors.extend(_scan_cfg(cfg))

    _emit(all_errors, filter_ids)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Usage: python3 StackBufferHardenLint.py <file.c.dump>",
            file=sys.stderr,
        )
        sys.exit(1)

    analyse(sys.argv[1])
