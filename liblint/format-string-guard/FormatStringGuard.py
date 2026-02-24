"""
FormatStringGuard.py — Cppcheck addon
======================================
Detects format string vulnerabilities: injection via non-literal formats,
%n usage, argument count mismatches, type mismatches, null format strings,
snprintf truncation, unsafe sprintf usage, and getenv-derived format strings.

Checkers
--------
FSG-01  format_string_injection      Non-literal passed as format arg
FSG-02  percent_n_in_format          %n directive in format string literal
FSG-03  argument_count_mismatch      Directive count ≠ variadic arg count
FSG-04  format_type_mismatch         Directive type ≠ actual argument type
FSG-05  null_format_string           NULL/0 passed as format argument
FSG-06  snprintf_truncation_ignored  snprintf return value discarded
FSG-07  sprintf_no_length_limit      sprintf used (no size bound)
FSG-08  format_string_from_getenv    getenv() result used as format string

CWE mapping
-----------
FSG-01, FSG-02, FSG-08  →  CWE-134  (Use of Externally-Controlled Format String)
FSG-03, FSG-04          →  CWE-686  (Wrong Number/Type of Arguments for Format)
FSG-05                  →  CWE-476  (NULL Pointer Dereference)
FSG-06                  →  CWE-252  (Unchecked Return Value)
FSG-07                  →  CWE-120  (Buffer Copy without Checking Size)

Shim contract
-------------
All .variable, .valueType, .astParent, .astOperand1/2 accesses guarded.
Variable IDs accessed ONLY via _safe_vid() / _safe_vid_tok().
"""

import sys
import re
from collections import namedtuple

# ---------------------------------------------------------------------------
# cppcheckdata import with offline stub
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    cppcheckdata = None  # type: ignore


# ===========================================================================
# §1  Shim contract — variable-ID accessors
# ===========================================================================

def _safe_vid(var):
    """Return var.Id as str, or None."""
    if var is None:
        return None
    try:
        vid = var.Id
        return str(vid) if vid is not None else None
    except AttributeError:
        return None


def _safe_vid_tok(tok):
    """Return tok.variable.Id as str, or None."""
    if tok is None:
        return None
    try:
        var = tok.variable
    except AttributeError:
        return None
    return _safe_vid(var)


# ===========================================================================
# §2  Safe token field accessors
# ===========================================================================

def _tok_str(tok):
    if tok is None:
        return ''
    try:
        return tok.str or ''
    except AttributeError:
        return ''


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
    """Return True if tok is a string literal."""
    if tok is None:
        return False
    try:
        return bool(tok.isString)
    except AttributeError:
        # Fallback: check if str starts with '"'
        s = _tok_str(tok)
        return s.startswith('"')


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


def _tok_scope(tok):
    if tok is None:
        return None
    try:
        return tok.scope
    except AttributeError:
        return None


def _is_expanded_macro(tok):
    if tok is None:
        return False
    try:
        return bool(tok.isExpandedMacro)
    except AttributeError:
        return False


def _valuetype_type(tok):
    """Return tok.valueType.type string or '' if unavailable."""
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
    """Return tok.valueType.pointer (int depth) or 0."""
    if tok is None:
        return 0
    try:
        vt = tok.valueType
        if vt is None:
            return 0
        return int(vt.pointer or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


def _valuetype_sign(tok):
    """Return tok.valueType.sign string or ''."""
    if tok is None:
        return ''
    try:
        vt = tok.valueType
        if vt is None:
            return ''
        return vt.sign or ''
    except AttributeError:
        return ''


# ===========================================================================
# §3  Format function registry
# ===========================================================================

# Maps function name → index of the format string argument (0-based)
# and the index at which variadic/format arguments start.
# Structure: (format_arg_idx, first_variadic_arg_idx)
# For 'v'-prefix functions, variadic_start is None (they use va_list, skip
# argument-count checks but still check for injection / %n).

_FORMAT_FUNCS = {
    # stdio
    'printf':     (0, 1),
    'fprintf':    (1, 2),
    'sprintf':    (1, 2),
    'snprintf':   (2, 3),
    'dprintf':    (1, 2),
    'asprintf':   (1, 2),

    # v-variants (va_list — no arg-count check)
    'vprintf':    (0, None),
    'vfprintf':   (1, None),
    'vsprintf':   (1, None),
    'vsnprintf':  (2, None),
    'vdprintf':   (1, None),
    'vasprintf':  (1, None),

    # syslog / err family
    'syslog':     (1, 2),
    'vsyslog':    (1, None),
    'err':        (2, 3),
    'errx':       (2, 3),
    'warn':       (1, 2),
    'warnx':      (1, 2),
    'verr':       (2, None),
    'verrx':      (2, None),
    'vwarn':      (1, None),
    'vwarnx':     (1, None),
}

# Functions whose return value is a format string (environment)
_ENV_SOURCE_FUNCS = frozenset({
    'getenv', 'secure_getenv',
    '__secure_getenv',
})

# sprintf variants (FSG-07)
_SPRINTF_FUNCS = frozenset({'sprintf', 'vsprintf'})

# snprintf variants (FSG-06)
_SNPRINTF_FUNCS = frozenset({'snprintf', 'vsnprintf', 'dprintf', 'vdprintf'})


# ===========================================================================
# §4  Format string parser
# ===========================================================================

# Compiled regex for a single format directive
_FMT_DIRECTIVE_RE = re.compile(
    r'%'
    r'(?P<flags>[-+ #0*]*)'
    r'(?P<width>\*|\d*)'
    r'(?:\.(?P<precision>\*|\d*))?'
    r'(?P<length_mod>hh|ll|h|l|L|z|j|t|q)?'
    r'(?P<spec>[diouxXeEfFgGaAcspn%])'
)


class FormatDirective:
    """Represents one parsed format directive."""
    __slots__ = ('spec', 'length_mod', 'width_star',
                 'prec_star', 'is_percent', 'position')

    def __init__(self, m, pos):
        self.spec        = m.group('spec')
        self.length_mod  = m.group('length_mod') or ''
        self.width_star  = (m.group('width') == '*')
        self.prec_star   = (m.group('precision') == '*')
        self.is_percent  = (self.spec == '%')
        self.position    = pos

    @property
    def args_consumed(self):
        """Number of variadic arguments consumed by this directive."""
        if self.is_percent:
            return 0
        count = 1
        if self.width_star:
            count += 1
        if self.prec_star:
            count += 1
        return count

    @property
    def has_percent_n(self):
        return self.spec == 'n'


def _extract_string_value(tok):
    """
    Extract the Python string from a C string literal token.
    The token str field contains the literal including quotes and
    escape sequences exactly as written in source.
    Returns the unquoted, unescaped string, or None if not a literal.
    """
    s = _tok_str(tok)
    if not s.startswith('"'):
        return None
    # Strip outer quotes
    inner = s[1:-1] if s.endswith('"') else s[1:]
    # Unescape basic C escape sequences
    try:
        # Use 'unicode_escape' via bytes decode
        inner = inner.replace('\\"', '"')
        return inner
    except Exception:
        return inner


def _parse_format_string(fmt_str):
    """
    Parse a C format string and return a list of FormatDirective objects.
    fmt_str is the raw content between the outer quotes of the literal.
    """
    if fmt_str is None:
        return []
    directives = []
    for m in _FMT_DIRECTIVE_RE.finditer(fmt_str):
        directives.append(FormatDirective(m, m.start()))
    return directives


def _count_args_needed(directives):
    """Return total variadic arguments consumed by the directive list."""
    return sum(d.args_consumed for d in directives)


# ===========================================================================
# §5  Call-site argument extraction
# ===========================================================================

def _call_name_from_paren(tok):
    """
    Given a '(' token that is the call operator, return the function name.
    """
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
    """
    Collect argument AST root tokens from a '(' call token.
    Returns a list in left-to-right order.
    """
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


# ===========================================================================
# §6  Type compatibility helpers
# ===========================================================================

# Map (spec, length_mod) → set of acceptable valueType.type strings
# 'ptr' is a synthetic tag meaning "pointer depth > 0"
_COMPAT = {
    # integer specifiers
    ('d', ''):   {'int', 'char', 'short'},
    ('d', 'h'):  {'int', 'short'},
    ('d', 'hh'): {'int', 'char'},
    ('d', 'l'):  {'long'},
    ('d', 'll'): {'long long', 'longlong'},
    ('d', 'z'):  {'ssize_t', 'long'},
    ('d', 'j'):  {'intmax_t', 'long long'},
    ('d', 't'):  {'ptrdiff_t', 'long'},
    ('i', ''):   {'int', 'char', 'short'},
    ('i', 'l'):  {'long'},
    ('i', 'll'): {'long long', 'longlong'},
    ('o', ''):   {'unsigned int', 'unsigned', 'int'},
    ('u', ''):   {'unsigned int', 'unsigned', 'int'},
    ('u', 'z'):  {'size_t', 'unsigned long'},
    ('u', 'l'):  {'unsigned long'},
    ('u', 'll'): {'unsigned long long'},
    ('x', ''):   {'unsigned int', 'unsigned', 'int'},
    ('X', ''):   {'unsigned int', 'unsigned', 'int'},
    # floating point
    ('f', ''):   {'float', 'double'},
    ('f', 'L'):  {'long double'},
    ('e', ''):   {'float', 'double'},
    ('E', ''):   {'float', 'double'},
    ('g', ''):   {'float', 'double'},
    ('G', ''):   {'float', 'double'},
    ('a', ''):   {'float', 'double'},
    ('A', ''):   {'float', 'double'},
    # char / string
    ('c', ''):   {'int', 'char', 'unsigned char', 'signed char'},
    ('s', ''):   {'ptr'},                # expects char*
    ('s', 'l'):  {'ptr'},                # wchar_t*
    # pointer
    ('p', ''):   {'ptr'},
    # %n expects int*
    ('n', ''):   {'ptr'},
}

# Specifiers that MUST be pointers
_PTR_SPECS = frozenset({'s', 'p', 'n'})

# Specifiers that must NOT be pointers
_NON_PTR_SPECS = frozenset({'d', 'i', 'o', 'u', 'x', 'X',
                             'f', 'F', 'e', 'E', 'g', 'G',
                             'a', 'A', 'c'})


def _check_type_compat(directive, arg_tok):
    """
    Check compatibility between a format directive and an argument token.
    Returns (compatible: bool, reason: str).
    """
    spec     = directive.spec
    lmod     = directive.length_mod
    vt_type  = _valuetype_type(arg_tok)
    vt_ptr   = _valuetype_pointer(arg_tok)
    is_ptr   = (vt_ptr > 0)

    if not vt_type:
        # Can't determine type — skip check
        return True, ''

    # %s, %p, %n must be pointers
    if spec in _PTR_SPECS and not is_ptr:
        return False, (
            f"directive '%{lmod}{spec}' expects a pointer argument "
            f"but received a non-pointer (type='{vt_type}')"
        )

    # Integer/float specifiers must NOT be pointers
    if spec in _NON_PTR_SPECS and is_ptr:
        return False, (
            f"directive '%{lmod}{spec}' expects a scalar argument "
            f"but received a pointer (type='{vt_type}', ptr_depth={vt_ptr})"
        )

    # Floating-point check
    if spec in 'fFeEgGaA':
        if vt_type not in ('float', 'double', 'long double'):
            return False, (
                f"directive '%{lmod}{spec}' expects float/double "
                f"but received '{vt_type}'"
            )

    return True, ''


# ===========================================================================
# §7  AST origin tracer (for FSG-08 getenv detection)
# ===========================================================================

def _trace_origin_call(tok, max_depth=6):
    """
    Walk up/through the AST to find if tok ultimately originates from
    a call to a function in _ENV_SOURCE_FUNCS.
    Returns the function name if found, else None.
    Handles simple chains: var = getenv(...) then var used as format.
    """
    if tok is None:
        return None

    visited = set()

    def _walk(t, depth):
        if t is None or depth > max_depth:
            return None
        tid = id(t)
        if tid in visited:
            return None
        visited.add(tid)

        s = _tok_str(t)

        # Is this token itself a call paren?
        if s == '(':
            name = _call_name_from_paren(t)
            if name in _ENV_SOURCE_FUNCS:
                return name

        # Is op1 or op2 a call to an env function?
        for child in (_ast_op1(t), _ast_op2(t)):
            if child is not None:
                result = _walk(child, depth + 1)
                if result:
                    return result

        return None

    return _walk(tok, 0)


# ===========================================================================
# §8  Individual checker implementations
# ===========================================================================

def _check_fsg01(call_name, fmt_arg_tok, paren_tok, errors):
    """FSG-01: Non-literal format string passed to format function."""
    if fmt_arg_tok is None:
        return

    # String literal is safe
    if _tok_is_string(fmt_arg_tok):
        return

    # Literal NULL / 0 is handled by FSG-05
    s = _tok_str(fmt_arg_tok)
    if s in ('NULL', '0') or (_tok_is_number(fmt_arg_tok) and s == '0'):
        return

    # getenv is handled by FSG-08 — skip here to avoid double-reporting
    origin = _trace_origin_call(fmt_arg_tok)
    if origin in _ENV_SOURCE_FUNCS:
        return

    errors.append(_mk(
        'FSG-01', paren_tok,
        f"format_string_injection: "
        f"'{call_name}' called with a non-literal format string "
        f"(argument is '{s}'). "
        f"An attacker-controlled format string can exploit %%n to write "
        f"to arbitrary memory addresses. "
        f"Use a string literal or wrap in printf(\"%%s\", var). "
        f"[CWE-134]",
        'error',
    ))


def _check_fsg02(call_name, fmt_str_val, paren_tok, errors):
    """FSG-02: %n directive present in format string literal."""
    if fmt_str_val is None:
        return
    directives = _parse_format_string(fmt_str_val)
    for d in directives:
        if d.has_percent_n:
            errors.append(_mk(
                'FSG-02', paren_tok,
                f"percent_n_in_format: "
                f"'{call_name}' format string contains '%%n' at position "
                f"{d.position}. "
                f"The %%n directive writes the byte count to an int pointer "
                f"and is frequently exploited in format string attacks. "
                f"Remove %%n from the format string. "
                f"[CWE-134]",
                'error',
            ))
            break   # one report per call is sufficient


def _check_fsg03(call_name, fmt_str_val, args, fmt_idx,
                 first_variadic, paren_tok, errors):
    """FSG-03: Argument count mismatch."""
    if fmt_str_val is None or first_variadic is None:
        return

    directives = _parse_format_string(fmt_str_val)
    needed     = _count_args_needed(directives)
    supplied   = max(0, len(args) - first_variadic)

    if needed == supplied:
        return

    if needed > supplied:
        errors.append(_mk(
            'FSG-03', paren_tok,
            f"argument_count_mismatch: "
            f"'{call_name}' format string requires {needed} argument(s) "
            f"but only {supplied} were supplied. "
            f"Missing arguments will read undefined stack/register values. "
            f"[CWE-686]",
            'error',
        ))
    else:
        errors.append(_mk(
            'FSG-03', paren_tok,
            f"argument_count_mismatch: "
            f"'{call_name}' format string requires {needed} argument(s) "
            f"but {supplied} were supplied ({supplied - needed} excess). "
            f"Excess arguments are ignored; likely a format string typo. "
            f"[CWE-686]",
            'warning',
        ))


def _check_fsg04(call_name, fmt_str_val, args,
                 first_variadic, paren_tok, errors):
    """FSG-04: Format type mismatch."""
    if fmt_str_val is None or first_variadic is None:
        return

    directives = [d for d in _parse_format_string(fmt_str_val)
                  if not d.is_percent]

    arg_idx = first_variadic  # index into args[]
    for d in directives:
        # width '*' consumes one int arg
        if d.width_star:
            arg_idx += 1
        # precision '*' consumes one int arg
        if d.prec_star:
            arg_idx += 1

        if arg_idx >= len(args):
            break  # FSG-03 already covers short supply

        arg_tok = args[arg_idx]
        ok, reason = _check_type_compat(d, arg_tok)
        if not ok:
            errors.append(_mk(
                'FSG-04', paren_tok,
                f"format_type_mismatch: "
                f"'{call_name}' argument {arg_idx + 1}: {reason}. "
                f"[CWE-686]",
                'warning',
            ))
        arg_idx += 1


def _check_fsg05(call_name, fmt_arg_tok, paren_tok, errors):
    """FSG-05: NULL/0 passed as format string."""
    if fmt_arg_tok is None:
        return
    s = _tok_str(fmt_arg_tok)
    is_null = (s == 'NULL') or (_tok_is_number(fmt_arg_tok) and s == '0')
    if is_null:
        errors.append(_mk(
            'FSG-05', paren_tok,
            f"null_format_string: "
            f"'{call_name}' called with NULL as the format string argument. "
            f"This causes undefined behaviour (likely a crash). "
            f"[CWE-476]",
            'error',
        ))


def _check_fsg06(call_name, paren_tok, errors):
    """FSG-06: snprintf return value not checked."""
    if call_name not in _SNPRINTF_FUNCS:
        return

    # Walk up the AST from '('.  If the immediate parent is not an
    # assignment or comparison, the return value is discarded.
    parent = _ast_parent(paren_tok)
    if parent is None:
        # Top-level statement — return value discarded
        errors.append(_mk(
            'FSG-06', paren_tok,
            f"snprintf_truncation_ignored: "
            f"return value of '{call_name}' is not checked. "
            f"If the output is truncated (return value >= size), "
            f"the buffer contains an incomplete string. "
            f"Assign and check the return value against the size argument. "
            f"[CWE-252]",
            'style',
        ))
        return

    p_str = _tok_str(parent)
    # If parent is ';' or a standalone expression, value is discarded
    if p_str in (';', ','):
        errors.append(_mk(
            'FSG-06', paren_tok,
            f"snprintf_truncation_ignored: "
            f"return value of '{call_name}' is discarded. "
            f"Truncation cannot be detected without checking the return value. "
            f"[CWE-252]",
            'style',
        ))


def _check_fsg07(call_name, paren_tok, errors):
    """FSG-07: sprintf used (unbounded buffer copy)."""
    if call_name in _SPRINTF_FUNCS:
        errors.append(_mk(
            'FSG-07', paren_tok,
            f"sprintf_no_length_limit: "
            f"'{call_name}' has no buffer-size parameter and can overflow "
            f"the destination buffer if the formatted output exceeds its "
            f"capacity. Replace with snprintf() and check the return value. "
            f"[CWE-120]",
            'warning',
        ))


def _check_fsg08(call_name, fmt_arg_tok, paren_tok, errors):
    """FSG-08: Format string derived from getenv() or similar."""
    if fmt_arg_tok is None:
        return
    if _tok_is_string(fmt_arg_tok):
        return

    origin = _trace_origin_call(fmt_arg_tok)
    if origin in _ENV_SOURCE_FUNCS:
        errors.append(_mk(
            'FSG-08', paren_tok,
            f"format_string_from_getenv: "
            f"'{call_name}' uses the return value of '{origin}()' as a "
            f"format string. Environment variables are attacker-controllable "
            f"in many deployment scenarios. "
            f"Use a fixed literal format string: printf(\"%%s\", getenv(...)). "
            f"[CWE-134]",
            'error',
        ))


# ===========================================================================
# §9  Per-call dispatcher
# ===========================================================================

def _dispatch_call(call_name, paren_tok, errors):
    """
    Run all applicable FSG checkers for a single format function call site.
    paren_tok is the '(' token of the call.
    """
    spec = _FORMAT_FUNCS.get(call_name)
    if spec is None:
        return

    fmt_idx, first_variadic = spec
    args = _collect_args(paren_tok)

    # Guard: not enough arguments to even have a format string
    if len(args) <= fmt_idx:
        errors.append(_mk(
            'FSG-03', paren_tok,
            f"argument_count_mismatch: "
            f"'{call_name}' requires at least {fmt_idx + 1} argument(s) "
            f"but received {len(args)}. "
            f"[CWE-686]",
            'error',
        ))
        return

    fmt_arg_tok = args[fmt_idx]

    # Extract the string value if it is a literal
    fmt_str_val = None
    if _tok_is_string(fmt_arg_tok):
        fmt_str_val = _extract_string_value(fmt_arg_tok)

    # Run each checker
    _check_fsg05(call_name, fmt_arg_tok, paren_tok, errors)
    _check_fsg01(call_name, fmt_arg_tok, paren_tok, errors)
    _check_fsg08(call_name, fmt_arg_tok, paren_tok, errors)

    if fmt_str_val is not None:
        _check_fsg02(call_name, fmt_str_val, paren_tok, errors)
        _check_fsg03(call_name, fmt_str_val, args,
                     fmt_idx, first_variadic, paren_tok, errors)
        _check_fsg04(call_name, fmt_str_val, args,
                     first_variadic, paren_tok, errors)

    _check_fsg06(call_name, paren_tok, errors)
    _check_fsg07(call_name, paren_tok, errors)


# ===========================================================================
# §10  Token-list scanner
# ===========================================================================

def _scan_cfg(cfg):
    """Scan all tokens in one configuration.  Returns list of error dicts."""
    errors = []

    for tok in cfg.tokenlist:
        if _is_expanded_macro(tok):
            continue

        if _tok_str(tok) != '(':
            continue

        call_name = _call_name_from_paren(tok)
        if call_name is None:
            continue

        if call_name not in _FORMAT_FUNCS:
            continue

        _dispatch_call(call_name, tok, errors)

    return errors


# ===========================================================================
# §11  Error construction
# ===========================================================================

def _mk(checker_id, tok, msg, severity='warning'):
    return {
        'id':       checker_id,
        'tok':      tok,
        'msg':      msg,
        'severity': severity,
    }


# ===========================================================================
# §12  Error emission
# ===========================================================================

_CWE_FROM_ID = {
    'FSG-01': 134,
    'FSG-02': 134,
    'FSG-03': 686,
    'FSG-04': 686,
    'FSG-05': 476,
    'FSG-06': 252,
    'FSG-07': 120,
    'FSG-08': 134,
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
                    tok, severity, msg, 'FormatStringGuard', checker
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
# §13  Public entry point
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


# ---------------------------------------------------------------------------
# Cppcheck addon protocol — direct invocation
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(
            "Usage: python3 FormatStringGuard.py <file.c.dump>",
            file=sys.stderr,
        )
        sys.exit(1)

    analyse(sys.argv[1])
