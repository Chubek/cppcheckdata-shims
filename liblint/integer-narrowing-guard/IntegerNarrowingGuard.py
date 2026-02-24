"""
IntegerNarrowingGuard.py — Cppcheck addon
==========================================
Detects implicit integer truncation, sign-conversion hazards, and
related numeric type misuse.

Checkers
--------
ING-01  implicit_truncation_assignment     CWE-197
ING-02  signed_to_unsigned_comparison      CWE-195
ING-03  loop_counter_overflow              CWE-190
ING-04  return_truncation                  CWE-197
ING-05  size_t_downcast                    CWE-681
ING-06  shift_width_exceeds_type           CWE-190
ING-07  negation_of_unsigned               CWE-190
ING-08  multiplication_before_widening     CWE-190

Shim contract
-------------
Variable IDs are accessed ONLY via _safe_vid() / _safe_vid_tok().
All .variable, .valueType, .astParent, .astOperand1/2 accesses are
guarded for None before use.
"""

import sys
import re

# ---------------------------------------------------------------------------
# Import cppcheckdata or provide a stub for offline syntax checking.
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:  # pragma: no cover
    cppcheckdata = None  # type: ignore


# ===========================================================================
# Shim: safe variable-ID accessors   (SHIMS_VADE_MECUM contract)
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
# Safe valueType accessors
# ===========================================================================

def _vt(tok):
    """Return tok.valueType, or None. Never raises."""
    if tok is None:
        return None
    try:
        return tok.valueType
    except AttributeError:
        return None


def _vt_type(vt):
    """Return vt.type string, or '' if unavailable."""
    if vt is None:
        return ''
    try:
        return vt.type or ''
    except AttributeError:
        return ''


def _vt_sign(vt):
    """Return vt.sign string ('signed'|'unsigned'), or None."""
    if vt is None:
        return None
    try:
        return vt.sign
    except AttributeError:
        return None


def _vt_bits(vt):
    """Return vt.bits (explicit stdint width), or 0."""
    if vt is None:
        return 0
    try:
        b = vt.bits
        return int(b) if b else 0
    except (AttributeError, TypeError, ValueError):
        return 0


def _vt_pointer(vt):
    """Return vt.pointer depth, or 0."""
    if vt is None:
        return 0
    try:
        p = vt.pointer
        return int(p) if p else 0
    except (AttributeError, TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Canonical type width table
# ---------------------------------------------------------------------------

# Maps valueType.type → bit width.
# For stdint types, vt.bits overrides this table.
_TYPE_WIDTH_TABLE = {
    'bool':      1,
    'char':      8,
    'short':     16,
    'int':       32,
    'long':      64,   # conservative LP64; ILP32 would be 32
    'longlong':  64,
    'float':     32,
    'double':    64,
    'longdouble':80,
    'unknown':   0,
}

# Types that are "integer" (not float, not pointer)
_INTEGER_TYPES = frozenset({
    'bool', 'char', 'short', 'int', 'long', 'longlong',
})

# Types that are "numeric" (integer or float)
_NUMERIC_TYPES = _INTEGER_TYPES | frozenset({'float', 'double', 'longdouble'})


def _type_width(vt):
    """
    Return the canonical bit-width of a valueType, or 0 if unknown.
    Explicit stdint bits (vt.bits) take priority over the type name.
    Pointer types return 64 (pointer-sized).
    """
    if vt is None:
        return 0

    # Pointer — treat as 64-bit address
    if _vt_pointer(vt) > 0:
        return 64

    # Explicit stdint width (uint8_t, int32_t, etc.)
    bits = _vt_bits(vt)
    if bits > 0:
        return bits

    t = _vt_type(vt)
    return _TYPE_WIDTH_TABLE.get(t, 0)


def _is_integer_vt(vt):
    """Return True if valueType represents an integer (non-pointer, non-float)."""
    if vt is None:
        return False
    if _vt_pointer(vt) > 0:
        return False
    t = _vt_type(vt)
    return t in _INTEGER_TYPES


def _is_numeric_vt(vt):
    """Return True if valueType represents any numeric type."""
    if vt is None:
        return False
    if _vt_pointer(vt) > 0:
        return False
    return _vt_type(vt) in _NUMERIC_TYPES


# ===========================================================================
# AST helpers
# ===========================================================================

def _ast_op1(tok):
    """Return tok.astOperand1 safely."""
    if tok is None:
        return None
    try:
        return tok.astOperand1
    except AttributeError:
        return None


def _ast_op2(tok):
    """Return tok.astOperand2 safely."""
    if tok is None:
        return None
    try:
        return tok.astOperand2
    except AttributeError:
        return None


def _ast_parent(tok):
    """Return tok.astParent safely."""
    if tok is None:
        return None
    try:
        return tok.astParent
    except AttributeError:
        return None


def _tok_str(tok):
    """Return tok.str safely."""
    if tok is None:
        return ''
    try:
        return tok.str or ''
    except AttributeError:
        return ''


def _is_explicit_cast(tok):
    """
    Return True if tok is wrapped in an explicit cast expression.
    In cppcheckdata, a C-style cast (type)expr is represented as a
    token with isCast=True, or the parent token has str that looks
    like a type keyword / closing paren of a cast.

    We use the heuristic: if tok.astParent.isCast is True, the
    expression is explicitly cast.
    """
    if tok is None:
        return False
    # Direct isCast flag on the token itself
    try:
        if tok.isCast:
            return True
    except AttributeError:
        pass
    # Parent is a cast node
    parent = _ast_parent(tok)
    if parent is not None:
        try:
            if parent.isCast:
                return True
        except AttributeError:
            pass
    return False


def _is_numeric_literal(tok):
    """Return True if tok is a numeric literal token."""
    if tok is None:
        return False
    try:
        return bool(tok.isNumber)
    except AttributeError:
        # Fallback: check if the string looks like a number
        s = _tok_str(tok)
        return bool(re.match(r'^-?\d+[\w.]*$', s))


def _literal_int_value(tok):
    """
    Return the integer value of a numeric literal token, or None.
    Handles suffixes: u, l, ul, ull, etc.
    """
    if tok is None:
        return None
    s = _tok_str(tok)
    # Strip suffixes
    s_clean = re.sub(r'[uUlLfF]+$', '', s)
    # Handle hex / octal
    try:
        if s_clean.startswith('0x') or s_clean.startswith('0X'):
            return int(s_clean, 16)
        if s_clean.startswith('0') and len(s_clean) > 1:
            return int(s_clean, 8)
        return int(s_clean)
    except (ValueError, TypeError):
        return None


# ===========================================================================
# Scope / function helpers
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


def _is_in_loop(tok):
    """Return True if tok resides inside a For / While / Do scope."""
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


def _enclosing_function(tok, cfg):
    """
    Return the Function object whose scope contains tok, or None.
    We walk tok.scope upward until we reach a Function scope, then
    match against cfg.functions by scope identity.
    """
    try:
        sc = tok.scope
    except AttributeError:
        return None

    while sc is not None:
        if getattr(sc, 'type', '') == 'Function':
            # Match against known functions
            for func in cfg.functions:
                try:
                    if func.token and func.token.scope is sc:
                        return func
                except AttributeError:
                    continue
            # Also try matching by scope object directly
            for func in cfg.functions:
                try:
                    if id(func.functionScope) == id(sc):
                        return func
                except AttributeError:
                    continue
            break
        try:
            sc = sc.nestedIn
        except AttributeError:
            break
    return None


def _func_return_type_width(func):
    """
    Return the bit-width of the function's declared return type, or 0.
    We inspect the token before the function name for type keywords.
    """
    if func is None:
        return 0

    # Try retType from the function object if available
    try:
        ret_vt = func.retType
        if ret_vt is not None:
            w = _type_width(ret_vt)
            if w > 0:
                return w
    except AttributeError:
        pass

    # Fallback: walk tokens before the function's definition token
    try:
        def_tok = func.tokenDef or func.token
    except AttributeError:
        return 0

    if def_tok is None:
        return 0

    # Walk backwards up to 6 tokens looking for a type keyword
    cur = def_tok
    for _ in range(6):
        try:
            cur = cur.previous
        except AttributeError:
            break
        if cur is None:
            break
        s = _tok_str(cur)
        if s in _TYPE_WIDTH_TABLE:
            return _TYPE_WIDTH_TABLE[s]

    return 0


# ===========================================================================
# Size-returning function detection (for ING-05)
# ===========================================================================

_SIZE_FUNCS = frozenset({
    'strlen', 'strnlen', 'wcslen',
    'fread', 'fwrite',
    'read', 'write', 'recv', 'send',
    'sprintf', 'snprintf',
    'mbstowcs', 'wcstombs',
    'strspn', 'strcspn',
})


def _get_call_name(tok):
    """
    Given a '(' function-call token, return the function name, or None.
    """
    if tok is None:
        return None
    try:
        op1 = tok.astOperand1
        if op1 is not None:
            s = _tok_str(op1)
            if s:
                return s
    except AttributeError:
        pass
    try:
        prev = tok.previous
        if prev is not None:
            s = _tok_str(prev)
            if s and (s.isidentifier() or s.replace('_', '').isalnum()):
                return s
    except AttributeError:
        pass
    return None


def _is_size_func_call(tok):
    """Return True if tok is a '(' for a size-returning function call."""
    if _tok_str(tok) != '(':
        return False
    name = _get_call_name(tok)
    return name in _SIZE_FUNCS


def _is_sizeof_expr(tok):
    """Return True if tok or its subtree is a sizeof expression."""
    if tok is None:
        return False
    if _tok_str(tok) == 'sizeof':
        return True
    # sizeof might be the operand1 parent
    op1 = _ast_op1(tok)
    if op1 is not None and _tok_str(op1) == 'sizeof':
        return True
    return False


# ===========================================================================
# Checker implementations
# ===========================================================================

# ---------------------------------------------------------------------------
# ING-01 — implicit_truncation_assignment
# ---------------------------------------------------------------------------

def _check_ing01(cfg, data):
    """
    ING-01  implicit_truncation_assignment

    Flag assignment  dst = expr  where:
      - dst type width < expr type width
      - both are integer types (not pointer, not float)
      - expr is NOT wrapped in an explicit cast
    """
    errors = []

    for tok in cfg.tokenlist:
        # We look for simple assignment '='
        if _tok_str(tok) != '=':
            continue
        try:
            is_assign = tok.isAssignmentOp
        except AttributeError:
            is_assign = False
        if not is_assign:
            continue

        lhs = _ast_op1(tok)
        rhs = _ast_op2(tok)
        if lhs is None or rhs is None:
            continue

        lhs_vt = _vt(lhs)
        rhs_vt = _vt(rhs)

        # Both must be integer types, not pointers
        if not _is_integer_vt(lhs_vt) or not _is_integer_vt(rhs_vt):
            continue

        w_lhs = _type_width(lhs_vt)
        w_rhs = _type_width(rhs_vt)

        # Only flag genuine narrowing
        if w_lhs == 0 or w_rhs == 0 or w_rhs <= w_lhs:
            continue

        # Suppress if RHS is an explicit cast
        if _is_explicit_cast(rhs):
            continue

        # Suppress if RHS is a small non-negative literal that fits
        if _is_numeric_literal(rhs):
            val = _literal_int_value(rhs)
            if val is not None and 0 <= val < (1 << w_lhs):
                continue

        lhs_type_str = _vt_type(lhs_vt)
        rhs_type_str = _vt_type(rhs_vt)
        lhs_bits_str = (
            f"{_vt_bits(lhs_vt)}-bit" if _vt_bits(lhs_vt) > 0
            else f"{w_lhs}-bit"
        )
        rhs_bits_str = (
            f"{_vt_bits(rhs_vt)}-bit" if _vt_bits(rhs_vt) > 0
            else f"{w_rhs}-bit"
        )

        errors.append({
            'tok': tok,
            'id': 'ING-01',
            'msg': (
                "implicit_truncation_assignment: "
                f"assigning {rhs_bits_str} '{rhs_type_str}' expression "
                f"to {lhs_bits_str} '{lhs_type_str}' variable without "
                f"an explicit cast. High bits will be silently discarded. "
                "[CWE-197]"
            ),
            'severity': 'warning',
        })

    return errors


# ---------------------------------------------------------------------------
# ING-02 — signed_to_unsigned_comparison
# ---------------------------------------------------------------------------

_COMPARISON_OPS = frozenset({'<', '>', '<=', '>=', '==', '!='})


def _check_ing02(cfg, data):
    """
    ING-02  signed_to_unsigned_comparison

    Flag comparisons between a signed and an unsigned integer operand.
    Suppress if the signed operand is a non-negative integer literal.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) not in _COMPARISON_OPS:
            continue

        op1 = _ast_op1(tok)
        op2 = _ast_op2(tok)
        if op1 is None or op2 is None:
            continue

        vt1 = _vt(op1)
        vt2 = _vt(op2)

        if not _is_integer_vt(vt1) or not _is_integer_vt(vt2):
            continue

        sign1 = _vt_sign(vt1)
        sign2 = _vt_sign(vt2)

        # We need one signed and one unsigned
        if sign1 == sign2:
            continue
        if sign1 is None or sign2 is None:
            continue

        # Identify which side is signed
        signed_tok   = op1 if sign1 == 'signed'   else op2
        unsigned_tok = op1 if sign1 == 'unsigned' else op2

        # Suppress: signed operand is a non-negative literal
        if _is_numeric_literal(signed_tok):
            val = _literal_int_value(signed_tok)
            if val is not None and val >= 0:
                continue

        s_type = _vt_type(_vt(signed_tok))
        u_type = _vt_type(_vt(unsigned_tok))

        errors.append({
            'tok': tok,
            'id': 'ING-02',
            'msg': (
                "signed_to_unsigned_comparison: "
                f"comparing signed '{s_type}' with unsigned '{u_type}'. "
                "If the signed value is negative it will be converted to a "
                "large unsigned value, making the comparison result wrong. "
                "[CWE-195]"
            ),
            'severity': 'warning',
        })

    return errors


# ---------------------------------------------------------------------------
# ING-03 — loop_counter_overflow
# ---------------------------------------------------------------------------

def _check_ing03(cfg, data):
    """
    ING-03  loop_counter_overflow

    Flag:  for (...; counter < LIMIT; ...) or counter <= LIMIT
    where counter's type width is w bits and LIMIT >= 2^w.
    This creates an infinite loop because the counter wraps to 0.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) not in ('<', '<='):
            continue

        # Must be inside a loop
        if not _is_in_loop(tok):
            continue

        op1 = _ast_op1(tok)   # loop counter
        op2 = _ast_op2(tok)   # limit

        if op1 is None or op2 is None:
            continue

        vt1 = _vt(op1)
        if not _is_integer_vt(vt1):
            continue

        # Sign must be unsigned for wrap-to-zero behaviour
        if _vt_sign(vt1) != 'unsigned':
            continue

        w = _type_width(vt1)
        if w == 0 or w >= 64:
            continue

        # RHS must be a literal we can evaluate
        if not _is_numeric_literal(op2):
            continue

        limit = _literal_int_value(op2)
        if limit is None:
            continue

        max_val = (1 << w)   # 2^w

        # For '<': flag if limit >= max_val (counter can never reach limit)
        # For '<=': flag if limit >= max_val - 1 ... but limit == max_val-1 is
        #   the last valid unsigned value; limit >= max_val wraps.
        op_str = _tok_str(tok)
        if op_str == '<' and limit >= max_val:
            errors.append({
                'tok': tok,
                'id': 'ING-03',
                'msg': (
                    "loop_counter_overflow: "
                    f"loop counter of type width {w}-bit unsigned is compared "
                    f"with {limit} which is >= {max_val} (2^{w}). "
                    "The counter wraps to 0 before reaching the limit, "
                    "creating an infinite loop. [CWE-190]"
                ),
                'severity': 'error',
            })
        elif op_str == '<=' and limit >= max_val:
            errors.append({
                'tok': tok,
                'id': 'ING-03',
                'msg': (
                    "loop_counter_overflow: "
                    f"loop counter of type width {w}-bit unsigned is compared "
                    f"with {limit} (using <=) which exceeds the type's maximum "
                    f"value {max_val - 1}. "
                    "The counter wraps before the condition is ever false. "
                    "[CWE-190]"
                ),
                'severity': 'error',
            })

    return errors


# ---------------------------------------------------------------------------
# ING-04 — return_truncation
# ---------------------------------------------------------------------------

def _check_ing04(cfg, data):
    """
    ING-04  return_truncation

    Flag:  return <expr>  where expr type width > function return type width.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) != 'return':
            continue

        expr = _ast_op1(tok)
        if expr is None:
            continue

        expr_vt = _vt(expr)
        if not _is_integer_vt(expr_vt):
            continue

        w_expr = _type_width(expr_vt)
        if w_expr == 0:
            continue

        # Suppress if expression is an explicit cast (intentional)
        if _is_explicit_cast(expr):
            continue

        # Find enclosing function
        func = _enclosing_function(tok, cfg)
        w_ret = _func_return_type_width(func)

        if w_ret == 0 or w_expr <= w_ret:
            continue

        ret_type = _vt_type(expr_vt)
        errors.append({
            'tok': tok,
            'id': 'ING-04',
            'msg': (
                "return_truncation: "
                f"returning {w_expr}-bit '{ret_type}' expression from a "
                f"function declared to return {w_ret}-bit type. "
                "Upper bits will be silently discarded at the call site. "
                "[CWE-197]"
            ),
            'severity': 'warning',
        })

    return errors


# ---------------------------------------------------------------------------
# ING-05 — size_t_downcast
# ---------------------------------------------------------------------------

def _check_ing05(cfg, data):
    """
    ING-05  size_t_downcast

    Flag casts of size_t-returning expressions (sizeof, strlen, fread, …)
    to signed 32-bit int.

    Pattern: the cast token's inner expression is a sizeof or a size-func call,
    and the cast's own valueType is 32-bit signed.
    """
    errors = []

    for tok in cfg.tokenlist:
        # Look for tokens that represent a cast operation
        try:
            is_cast = tok.isCast
        except AttributeError:
            is_cast = False

        if not is_cast:
            continue

        # The cast result type
        cast_vt = _vt(tok)
        if cast_vt is None:
            continue

        w_cast = _type_width(cast_vt)
        sign   = _vt_sign(cast_vt)

        # We care about casts TO signed types of ≤ 32 bits
        if sign != 'signed' or w_cast > 32 or w_cast == 0:
            continue

        # The inner expression
        inner = _ast_op1(tok)
        if inner is None:
            inner = _ast_op2(tok)

        if inner is None:
            continue

        # Is the inner expression a sizeof or size-returning call?
        flagged = False
        inner_name = ''

        if _is_sizeof_expr(inner):
            flagged = True
            inner_name = 'sizeof'
        elif _tok_str(inner) == '(' and _is_size_func_call(inner):
            flagged = True
            inner_name = _get_call_name(inner) or 'size-returning function'
        elif _tok_str(inner) == '(':
            # Check if it's a call to a size func
            name = _get_call_name(inner)
            if name and name in _SIZE_FUNCS:
                flagged = True
                inner_name = name

        if not flagged:
            continue

        dst_type = _vt_type(cast_vt)
        errors.append({
            'tok': tok,
            'id': 'ING-05',
            'msg': (
                "size_t_downcast: "
                f"result of '{inner_name}' (returns size_t / unsigned 64-bit) "
                f"is cast to signed {w_cast}-bit '{dst_type}'. "
                "For large buffers this cast overflows, producing a negative "
                "value. Use size_t or ssize_t for size variables. [CWE-681]"
            ),
            'severity': 'warning',
        })

    return errors


# ---------------------------------------------------------------------------
# ING-06 — shift_width_exceeds_type
# ---------------------------------------------------------------------------

def _check_ing06(cfg, data):
    """
    ING-06  shift_width_exceeds_type

    Flag  expr << N  or  expr >> N  where N >= bit-width of expr's type.
    Shifting by >= the type width is undefined behaviour in C.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) not in ('<<', '>>'):
            continue

        op1 = _ast_op1(tok)   # value being shifted
        op2 = _ast_op2(tok)   # shift count

        if op1 is None or op2 is None:
            continue

        vt1 = _vt(op1)
        if not _is_integer_vt(vt1):
            continue

        w = _type_width(vt1)
        if w == 0:
            continue

        # Shift count must be a literal for static analysis
        if not _is_numeric_literal(op2):
            continue

        count = _literal_int_value(op2)
        if count is None:
            continue

        if count < 0:
            errors.append({
                'tok': tok,
                'id': 'ING-06',
                'msg': (
                    "shift_width_exceeds_type: "
                    f"shift count {count} is negative. "
                    "Shifting by a negative count is undefined behaviour in C. "
                    "[CWE-190]"
                ),
                'severity': 'error',
            })
        elif count >= w:
            op_str = _tok_str(tok)
            type_str = _vt_type(vt1)
            errors.append({
                'tok': tok,
                'id': 'ING-06',
                'msg': (
                    "shift_width_exceeds_type: "
                    f"shift '{op_str}' by {count} bits applied to "
                    f"{w}-bit type '{type_str}'. "
                    f"Shift count must be < {w} for this type. "
                    "This is undefined behaviour in C. [CWE-190]"
                ),
                'severity': 'error',
            })

    return errors


# ---------------------------------------------------------------------------
# ING-07 — negation_of_unsigned
# ---------------------------------------------------------------------------

def _check_ing07(cfg, data):
    """
    ING-07  negation_of_unsigned

    Flag  -expr  (unary minus) when expr has an unsigned integer type.
    The result wraps to a large positive value silently.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) != '-':
            continue

        # Distinguish unary from binary minus:
        # unary: astOperand1 is None, operand is in astOperand2
        op1 = _ast_op1(tok)
        op2 = _ast_op2(tok)

        # Binary minus — skip
        if op1 is not None and op2 is not None:
            continue

        # Unary minus: op1 is None, op2 holds the operand
        # (some cppcheckdata versions put the operand in op1 for unary)
        operand = op2 if op2 is not None else op1
        if operand is None:
            continue

        vt = _vt(operand)
        if not _is_integer_vt(vt):
            continue

        if _vt_sign(vt) != 'unsigned':
            continue

        type_str = _vt_type(vt)
        w        = _type_width(vt)
        errors.append({
            'tok': tok,
            'id': 'ING-07',
            'msg': (
                "negation_of_unsigned: "
                f"unary minus applied to unsigned {w}-bit '{type_str}' "
                "expression. The result wraps modulo 2^N, yielding a large "
                "positive value — likely not the intended behaviour. [CWE-190]"
            ),
            'severity': 'warning',
        })

    return errors


# ---------------------------------------------------------------------------
# ING-08 — multiplication_before_widening
# ---------------------------------------------------------------------------

def _check_ing08(cfg, data):
    """
    ING-08  multiplication_before_widening

    Flag:  int64_t result = a * b
    where both a and b are 32-bit integers and neither is explicitly
    cast to a 64-bit type before the multiplication.

    The multiplication occurs at 32-bit width, overflows, and THEN the
    garbage result is widened — the widening assignment does not help.

    Pattern:
      '=' with LHS width >= 64 and RHS is '*' with both operands at 32-bit.
    """
    errors = []

    for tok in cfg.tokenlist:
        if _tok_str(tok) != '=':
            continue
        try:
            is_assign = tok.isAssignmentOp
        except AttributeError:
            is_assign = False
        if not is_assign:
            continue

        lhs = _ast_op1(tok)
        rhs = _ast_op2(tok)
        if lhs is None or rhs is None:
            continue

        # LHS must be a wide integer (>= 64 bits)
        lhs_vt = _vt(lhs)
        if not _is_integer_vt(lhs_vt):
            continue
        w_lhs = _type_width(lhs_vt)
        if w_lhs < 64:
            continue

        # RHS must be a '*' multiplication node
        if _tok_str(rhs) != '*':
            continue

        mul_op1 = _ast_op1(rhs)
        mul_op2 = _ast_op2(rhs)
        if mul_op1 is None or mul_op2 is None:
            continue

        vt_m1 = _vt(mul_op1)
        vt_m2 = _vt(mul_op2)

        if not _is_integer_vt(vt_m1) or not _is_integer_vt(vt_m2):
            continue

        w_m1 = _type_width(vt_m1)
        w_m2 = _type_width(vt_m2)

        # Both operands must be narrow (32-bit or less)
        if w_m1 > 32 or w_m2 > 32:
            continue
        if w_m1 == 0 or w_m2 == 0:
            continue

        # Suppress if either operand is an explicit cast to a wide type
        if _is_explicit_cast(mul_op1) or _is_explicit_cast(mul_op2):
            # Check cast destination width
            cast_vt1 = _vt(mul_op1)
            cast_vt2 = _vt(mul_op2)
            if _type_width(cast_vt1) >= 64 or _type_width(cast_vt2) >= 64:
                continue

        # Suppress if either operand is a literal small enough to not overflow
        # (product of two literals fits in 32 bits)
        if _is_numeric_literal(mul_op1) and _is_numeric_literal(mul_op2):
            v1 = _literal_int_value(mul_op1)
            v2 = _literal_int_value(mul_op2)
            if v1 is not None and v2 is not None:
                if abs(v1 * v2) < (1 << 31):
                    continue

        t1 = _vt_type(vt_m1)
        t2 = _vt_type(vt_m2)
        t_lhs = _vt_type(lhs_vt)

        errors.append({
            'tok': rhs,   # point at the '*' operator
            'id': 'ING-08',
            'msg': (
                "multiplication_before_widening: "
                f"product of {w_m1}-bit '{t1}' and {w_m2}-bit '{t2}' "
                f"is computed at {max(w_m1, w_m2)}-bit width before being "
                f"assigned to {w_lhs}-bit '{t_lhs}'. "
                "Overflow occurs before widening. "
                f"Cast one operand first: (({t_lhs})a) * b. [CWE-190]"
            ),
            'severity': 'warning',
        })

    return errors


# ===========================================================================
# Error emission
# ===========================================================================

_SEVERITY_MAP = {
    'error':       'error',
    'warning':     'warning',
    'style':       'style',
    'performance': 'performance',
}

_CWE_MAP = {
    'ING-01': 197,
    'ING-02': 195,
    'ING-03': 190,
    'ING-04': 197,
    'ING-05': 681,
    'ING-06': 190,
    'ING-07': 190,
    'ING-08': 190,
}


def _emit(errors, checker_id_filter=None):
    """Emit all collected errors through cppcheckdata.reportError()."""
    for e in errors:
        tok      = e['tok']
        msg      = e['msg']
        checker  = e['id']
        severity = _SEVERITY_MAP.get(e.get('severity', 'warning'), 'warning')

        if checker_id_filter and checker not in checker_id_filter:
            continue

        if cppcheckdata is not None:
            try:
                cppcheckdata.reportError(
                    tok, severity, msg, 'IntegerNarrowingGuard', checker
                )
            except TypeError:
                cppcheckdata.reportError(tok, severity, msg)
        else:
            loc = (
                f"{getattr(tok, 'file', '?')}"
                f":{getattr(tok, 'linenr', '?')}"
            )
            print(f"[{checker}] {loc}: {msg}", file=sys.stderr)


# ===========================================================================
# Entry point
# ===========================================================================

def analyse(filename, checker_id_filter=None):
    """Main entry point called by Cppcheck."""
    if cppcheckdata is None:
        print("ERROR: cppcheckdata module not found.", file=sys.stderr)
        sys.exit(1)

    data = cppcheckdata.parsedump(filename)

    all_errors = []
    for cfg in data.configurations:
        all_errors += _check_ing01(cfg, data)
        all_errors += _check_ing02(cfg, data)
        all_errors += _check_ing03(cfg, data)
        all_errors += _check_ing04(cfg, data)
        all_errors += _check_ing05(cfg, data)
        all_errors += _check_ing06(cfg, data)
        all_errors += _check_ing07(cfg, data)
        all_errors += _check_ing08(cfg, data)

    _emit(all_errors, checker_id_filter)


# ---------------------------------------------------------------------------
# Cppcheck addon protocol
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Usage: python3 IntegerNarrowingGuard.py <file.c.dump>",
            file=sys.stderr,
        )
        sys.exit(1)

    analyse(sys.argv[1])
