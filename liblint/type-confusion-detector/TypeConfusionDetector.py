#!/usr/bin/env python3
"""
TypeConfusionDetector.py — Cppcheck addon
=========================================
Domain  : Type confusion, illegal casts, sign/width mismatch in C
Checkers: TCD-01 … TCD-10
CWEs    : 190, 195, 196, 197, 467, 681, 704, 843

Hardening contract
------------------
* NEVER call int(tok.varId) directly.
* ALWAYS use _safe_vid() / _safe_vid_tok().
* All findings are emitted as single-line JSON objects on stdout.
"""

from __future__ import annotations

import sys
import json
import re
from collections import defaultdict
from typing import Optional, List, Dict, Set, Tuple, Iterator

# ---------------------------------------------------------------------------
# Bootstrap: locate cppcheckdata
# ---------------------------------------------------------------------------
try:
    import cppcheckdata
except ImportError:
    import os, sys
    _addon_dir = os.path.dirname(os.path.abspath(__file__))
    for _candidate in [
        os.path.join(_addon_dir, "cppcheckdata.py"),
        os.path.join(_addon_dir, "..", "cppcheckdata.py"),
        "/usr/share/cppcheck/addons/cppcheckdata.py",
        "/usr/lib/cppcheck/addons/cppcheckdata.py",
    ]:
        if os.path.isfile(_candidate):
            import importlib.util as _ilu
            _spec = _ilu.spec_from_file_location("cppcheckdata", _candidate)
            cppcheckdata = _ilu.module_from_spec(_spec)  # type: ignore[assignment]
            _spec.loader.exec_module(cppcheckdata)  # type: ignore[union-attr]
            break
    else:
        sys.exit("TypeConfusionDetector: cannot locate cppcheckdata.py")


# ---------------------------------------------------------------------------
# Hardened variable-ID helpers  (hardening contract §1)
# ---------------------------------------------------------------------------

def _safe_vid(tok) -> int:
    """Return tok.varId as int, or 0 on any failure."""
    try:
        raw = tok.varId
        if raw is None:
            return 0
        return int(raw)
    except (TypeError, ValueError, AttributeError):
        return 0


def _safe_vid_tok(tok) -> int:
    """Alias kept for symmetry with other addons in the suite."""
    return _safe_vid(tok)


# ---------------------------------------------------------------------------
# Token / type helpers
# ---------------------------------------------------------------------------

def _tok_str(tok) -> str:
    try:
        return tok.str or ""
    except AttributeError:
        return ""


def _tok_type_str(tok) -> str:
    """Best-effort: return the string representation of a token's type."""
    try:
        if tok.variable and tok.variable.typeStartToken:
            parts: List[str] = []
            t = tok.variable.typeStartToken
            end = tok.variable.typeEndToken
            while t is not None:
                parts.append(_tok_str(t))
                if t == end:
                    break
                t = t.next
            return " ".join(parts)
    except AttributeError:
        pass
    try:
        return tok.type or ""
    except AttributeError:
        return ""


def _is_pointer(tok) -> bool:
    try:
        return bool(tok.variable and tok.variable.isPointer)
    except AttributeError:
        return False


def _is_array(tok) -> bool:
    try:
        return bool(tok.variable and tok.variable.isArray)
    except AttributeError:
        return False


def _base_type(tok) -> str:
    """Return the base type string stripped of const/volatile/pointer stars."""
    s = _tok_type_str(tok)
    s = re.sub(r'\b(const|volatile|restrict|unsigned|signed)\b', '', s)
    s = re.sub(r'\*+', '', s)
    return s.strip()


# Signed integer base types (C standard)
_SIGNED_INT_TYPES: frozenset = frozenset({
    "char", "signed char", "short", "short int", "signed short",
    "int", "signed int", "long", "long int", "signed long",
    "long long", "long long int", "signed long long",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "intptr_t", "intmax_t", "ptrdiff_t", "ssize_t",
})

_UNSIGNED_INT_TYPES: frozenset = frozenset({
    "unsigned char", "unsigned short", "unsigned short int",
    "unsigned int", "unsigned", "unsigned long", "unsigned long int",
    "unsigned long long", "unsigned long long int",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "uintptr_t", "uintmax_t", "size_t",
})

_ALL_INT_TYPES: frozenset = _SIGNED_INT_TYPES | _UNSIGNED_INT_TYPES

# Width (in bytes) for common types — used by TCD-03 / TCD-10
_TYPE_WIDTH: Dict[str, int] = {
    "char": 1, "signed char": 1, "unsigned char": 1,
    "int8_t": 1, "uint8_t": 1,
    "short": 2, "short int": 2, "signed short": 2, "unsigned short": 2,
    "int16_t": 2, "uint16_t": 2,
    "int": 4, "signed int": 4, "unsigned int": 4, "unsigned": 4,
    "int32_t": 4, "uint32_t": 4,
    "long": 4, "long int": 4, "signed long": 4, "unsigned long": 4,
    "long long": 8, "long long int": 8, "unsigned long long": 8,
    "int64_t": 8, "uint64_t": 8,
    "float": 4, "double": 8, "long double": 16,
}

_CHAR_TYPES: frozenset = frozenset({"char", "signed char", "unsigned char", "char8_t"})
_WCHAR_TYPES: frozenset = frozenset({"wchar_t", "char16_t", "char32_t"})

# Struct/union keywords
_COMPOSITE_KW: frozenset = frozenset({"struct", "union"})

# Known wide-string functions (accept wchar_t*)
_WIDE_STRING_FUNCS: frozenset = frozenset({
    "wprintf", "fwprintf", "swprintf", "vwprintf", "vfwprintf", "vswprintf",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcscmp", "wcsncmp",
    "wcslen", "wcschr", "wcsrchr", "wcsstr", "wcstok",
    "fputws", "fgetws", "putwchar", "getwchar", "wcsftime",
    "mbstowcs", "wcstombs",
})

# Known narrow-string functions (accept char*)
_NARROW_STRING_FUNCS: frozenset = frozenset({
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp",
    "strlen", "strchr", "strrchr", "strstr", "strtok",
    "fputs", "fgets", "putchar", "getchar", "strftime",
    "puts", "gets",
})


# ---------------------------------------------------------------------------
# Emission helper
# ---------------------------------------------------------------------------

def _emit(checker_id: str, cwe: int, severity: str, msg: str, tok) -> None:
    """Emit a single-line JSON finding in Cppcheck addon protocol format."""
    try:
        filename = tok.file or ""
        linenr   = int(tok.linenr) if tok.linenr is not None else 0
        col      = int(tok.column) if tok.column is not None else 0
    except (AttributeError, TypeError, ValueError):
        filename, linenr, col = "", 0, 0

    record = {
        "file":    filename,
        "linenr":  linenr,
        "column":  col,
        "severity": severity,
        "message":  msg,
        "addon":   "TypeConfusionDetector",
        "errorId": checker_id,
        "cwe":     cwe,
    }
    sys.stdout.write(json.dumps(record) + "\n")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Token iteration helpers
# ---------------------------------------------------------------------------

def _tokens(cfg) -> Iterator:
    """Yield all tokens in all scopes."""
    try:
        for tok in cfg.tokenlist:
            yield tok
    except (AttributeError, TypeError):
        pass


def _scope_tokens(scope) -> Iterator:
    """Yield tokens that belong to a given scope."""
    try:
        tok = scope.bodyStart
        end = scope.bodyEnd
        while tok is not None and tok != end:
            yield tok
            tok = tok.next
    except (AttributeError, TypeError):
        pass


# ===========================================================================
#  Checker base class
# ===========================================================================

class _BaseChecker:
    checker_id: str = "TCD-00"
    cwe: int        = 0
    severity: str   = "style"

    def check(self, cfg) -> None:
        raise NotImplementedError


# ===========================================================================
#  TCD-01  pointer_type_pun
#  CWE-843  Access of Resource Using Incompatible Type
#
#  Flags: (SomeType*)ptr  where ptr's declared base type != SomeType,
#         neither type is void, and the cast is not part of a memcpy/
#         union context.
# ===========================================================================

class _TCD01_PointerTypePun(_BaseChecker):
    checker_id = "TCD-01"
    cwe        = 843
    severity   = "error"

    # Patterns that legitimise a reinterpret cast
    _SAFE_CONTEXTS: frozenset = frozenset({
        "memcpy", "memmove", "memset", "memcmp",
    })

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            # Look for a C-style cast: '(' TypeName '*' ')'
            if _tok_str(tok) != '(':
                continue
            cast_type, stars, close = self._parse_cast(tok)
            if not cast_type or stars == 0 or not close:
                continue
            # The token after ')' is the operand
            operand = close.next
            if operand is None:
                continue
            # Skip void* casts — they are universally used as generics
            if cast_type == "void":
                continue
            # Get operand's declared base type
            op_base = self._operand_base_type(operand)
            if not op_base or op_base == "void":
                continue
            # Skip compatible casts
            if self._compatible(cast_type, op_base):
                continue
            # Skip if inside safe context
            if self._in_safe_context(tok):
                continue
            # Both are composite types (struct/union) → handled by TCD-07
            if self._is_composite(cast_type) and self._is_composite(op_base):
                continue
            msg = (
                f"Pointer type pun: casting '{op_base}*' to '{cast_type}*' "
                f"violates strict aliasing (CWE-843). "
                f"Use memcpy or a union for type-safe reinterpretation."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    # ------------------------------------------------------------------

    def _parse_cast(self, open_paren) -> Tuple[str, int, object]:
        """
        From '(' try to parse: TypeName {'*'} ')'
        Returns (type_name, star_count, close_paren_tok) or ('', 0, None).
        """
        parts: List[str] = []
        stars = 0
        t = open_paren.next
        while t is not None:
            s = _tok_str(t)
            if s in ('const', 'volatile', 'restrict'):
                t = t.next
                continue
            if s == '*':
                stars += 1
                t = t.next
                continue
            if s == ')':
                return " ".join(parts), stars, t
            if s == '(':
                # Nested paren — not a simple cast
                return "", 0, None
            if re.match(r'^[A-Za-z_]\w*$', s) or s in _COMPOSITE_KW:
                parts.append(s)
                t = t.next
                continue
            # Unexpected token
            return "", 0, None
        return "", 0, None

    def _operand_base_type(self, tok) -> str:
        try:
            if tok.variable and tok.variable.isPointer:
                ts = tok.variable.typeStartToken
                te = tok.variable.typeEndToken
                if ts:
                    parts = []
                    t = ts
                    while t is not None:
                        s = _tok_str(t)
                        if s not in ('*', 'const', 'volatile', 'restrict'):
                            parts.append(s)
                        if t == te:
                            break
                        t = t.next
                    return " ".join(parts).strip()
        except AttributeError:
            pass
        return ""

    def _compatible(self, a: str, b: str) -> bool:
        """True if the two type strings refer to the same underlying type."""
        def _norm(s):
            s = re.sub(r'\b(struct|union|enum)\s+', '', s)
            s = re.sub(r'\s+', ' ', s).strip()
            return s
        an, bn = _norm(a), _norm(b)
        if an == bn:
            return True
        # char <-> unsigned char <-> signed char are commonly aliased (§6.5 exception)
        if {an, bn} <= {"char", "unsigned char", "signed char"}:
            return True
        return False

    def _is_composite(self, t: str) -> bool:
        return bool(re.search(r'\b(struct|union)\b', t))

    def _in_safe_context(self, tok) -> bool:
        """Check if tok is an argument of a known safe function."""
        try:
            t = tok
            # Walk backwards to find a function name before the '('
            prev = t.previous
            if prev is None:
                return False
            # e.g.  memcpy( (char*) ... )
            func_tok = prev
            if _tok_str(func_tok) == '(':
                func_tok = func_tok.previous
            return _tok_str(func_tok) in self._SAFE_CONTEXTS
        except AttributeError:
            return False


# ===========================================================================
#  TCD-02  signed_unsigned_compare
#  CWE-195 / CWE-196
#
#  Flags comparisons (< <= > >= == !=) between a signed and unsigned token
#  where no explicit cast is present.
# ===========================================================================

class _TCD02_SignedUnsignedCompare(_BaseChecker):
    checker_id = "TCD-02"
    cwe        = 195
    severity   = "warning"

    _COMPARE_OPS: frozenset = frozenset({'<', '<=', '>', '>=', '==', '!='})

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _tok_str(tok) not in self._COMPARE_OPS:
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue
            l_signed = self._is_signed(lhs)
            r_signed = self._is_signed(rhs)
            l_unsigned = self._is_unsigned(lhs)
            r_unsigned = self._is_unsigned(rhs)
            if (l_signed and r_unsigned) or (l_unsigned and r_signed):
                msg = (
                    f"Comparing signed and unsigned types without explicit cast "
                    f"around operator '{_tok_str(tok)}' may produce unexpected results "
                    f"when the signed operand is negative (CWE-195/196)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _is_signed(self, tok) -> bool:
        try:
            if tok.variable:
                ts = _tok_str(tok.variable.typeStartToken) if tok.variable.typeStartToken else ""
                te = _tok_str(tok.variable.typeEndToken)   if tok.variable.typeEndToken   else ""
                type_s = (ts + " " + te).lower().strip()
                # Explicitly unsigned → not signed
                if "unsigned" in type_s:
                    return False
                for st in _SIGNED_INT_TYPES:
                    if st in type_s:
                        return True
        except AttributeError:
            pass
        return False

    def _is_unsigned(self, tok) -> bool:
        try:
            if tok.variable:
                ts = _tok_str(tok.variable.typeStartToken) if tok.variable.typeStartToken else ""
                te = _tok_str(tok.variable.typeEndToken)   if tok.variable.typeEndToken   else ""
                type_s = (ts + " " + te).lower().strip()
                if "unsigned" in type_s:
                    return True
                for ut in _UNSIGNED_INT_TYPES:
                    if ut in type_s:
                        return True
        except AttributeError:
            pass
        return False


# ===========================================================================
#  TCD-03  truncating_cast
#  CWE-197  Numeric Truncation Error
#
#  Flags: (NarrowType)wide_var  where NarrowType is narrower than wide_var's
#         declared type.
# ===========================================================================

class _TCD03_TruncatingCast(_BaseChecker):
    checker_id = "TCD-03"
    cwe        = 197
    severity   = "warning"

    # Map tokens to width; if unknown, skip
    _WIDTH = _TYPE_WIDTH

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _tok_str(tok) != '(':
                continue
            cast_type, close = self._parse_scalar_cast(tok)
            if not cast_type or not close:
                continue
            cast_width = self._width(cast_type)
            if cast_width == 0:
                continue
            operand = close.next
            if operand is None:
                continue
            op_width = self._operand_width(operand)
            if op_width == 0:
                continue
            if cast_width < op_width:
                msg = (
                    f"Truncating cast: value of width {op_width} bytes "
                    f"cast to '{cast_type}' ({cast_width} bytes). "
                    f"High-order bits will be silently discarded (CWE-197)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _parse_scalar_cast(self, open_paren) -> Tuple[str, object]:
        """Parse '(' ScalarType ')' — no pointer stars allowed."""
        parts: List[str] = []
        t = open_paren.next
        while t is not None:
            s = _tok_str(t)
            if s in ('const', 'volatile'):
                t = t.next
                continue
            if s == '*':
                return "", None  # pointer cast, not a scalar cast
            if s == ')':
                return " ".join(parts), t
            if re.match(r'^[A-Za-z_]\w*$', s):
                parts.append(s)
                t = t.next
                continue
            return "", None
        return "", None

    def _width(self, type_str: str) -> int:
        # Normalise
        s = re.sub(r'\s+', ' ', type_str.strip().lower())
        return self._WIDTH.get(s, 0)

    def _operand_width(self, tok) -> int:
        try:
            if tok.variable:
                ts = tok.variable.typeStartToken
                te = tok.variable.typeEndToken
                if ts:
                    parts = []
                    t = ts
                    while t is not None:
                        s = _tok_str(t)
                        if s not in ('*', 'const', 'volatile', 'restrict'):
                            parts.append(s)
                        if t == te:
                            break
                        t = t.next
                    type_s = " ".join(parts).strip().lower()
                    w = self._WIDTH.get(type_s, 0)
                    if w:
                        return w
        except AttributeError:
            pass
        return 0


# ===========================================================================
#  TCD-04  sizeof_pointer
#  CWE-467  Use of sizeof() on a Pointer Type
#
#  Flags: sizeof(ptr) where ptr is a pointer variable.
#  The developer likely intended sizeof(*ptr) or sizeof(PointedToType).
# ===========================================================================

class _TCD04_SizeofPointer(_BaseChecker):
    checker_id = "TCD-04"
    cwe        = 467
    severity   = "warning"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _tok_str(tok) != 'sizeof':
                continue
            # sizeof can be: sizeof(expr) or sizeof expr
            nxt = tok.next
            if nxt is None:
                continue
            if _tok_str(nxt) == '(':
                inner = nxt.next
            else:
                inner = nxt
            if inner is None:
                continue
            # If inner token is a variable that is a pointer, flag it
            if _safe_vid(inner) == 0:
                continue
            try:
                var = inner.variable
                if var is None:
                    continue
                if var.isPointer and not var.isArray:
                    type_str = _tok_type_str(inner)
                    msg = (
                        f"sizeof applied to pointer variable '{_tok_str(inner)}' "
                        f"(type: '{type_str}*') yields the pointer size, not the "
                        f"size of the pointed-to object. "
                        f"Did you mean sizeof(*{_tok_str(inner)}) or sizeof({type_str})? "
                        f"(CWE-467)"
                    )
                    _emit(self.checker_id, self.cwe, self.severity, msg, tok)
            except AttributeError:
                pass


# ===========================================================================
#  TCD-05  void_ptr_function_cast
#  CWE-704  Incorrect Type Conversion or Cast
#
#  Flags: calling through (void*) cast of a function pointer, or storing
#  a typed function pointer as void* and calling it.
#  Pattern: ((void*)fn)(args)  or  void *fp = fn; ... (*fp)(args)
# ===========================================================================

class _TCD05_VoidPtrFunctionCast(_BaseChecker):
    checker_id = "TCD-05"
    cwe        = 704
    severity   = "error"

    def check(self, cfg) -> None:
        # Pattern 1: assignment void *fp = some_function_ptr
        void_ptr_vars: Set[int] = set()
        for tok in _tokens(cfg):
            if _tok_str(tok) != '=':
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue
            # LHS must be a void* variable
            if not self._is_void_ptr(lhs):
                continue
            # RHS must be a function pointer
            if self._is_function_ptr(rhs):
                vid = _safe_vid(lhs)
                if vid:
                    void_ptr_vars.add(vid)
                msg = (
                    f"Function pointer assigned to 'void*' variable "
                    f"'{_tok_str(lhs)}'; calling through void* discards "
                    f"prototype information (CWE-704)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

        # Pattern 2: (void*)func_expr used in a call context
        for tok in _tokens(cfg):
            if _tok_str(tok) != '(':
                continue
            # Check if immediately inside is 'void' '*' ')'
            cast_type, stars, close = self._parse_cast_simple(tok)
            if cast_type != "void" or stars != 1 or close is None:
                continue
            # Check what comes after
            after = close.next
            if after is None:
                continue
            if self._is_function_ptr(after) or self._could_be_fn(after):
                msg = (
                    f"Casting function pointer to 'void*' at call site "
                    f"loses type information and causes undefined behaviour "
                    f"if prototype does not match (CWE-704)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _is_void_ptr(self, tok) -> bool:
        try:
            v = tok.variable
            if v and v.isPointer:
                ts = _tok_str(v.typeStartToken) if v.typeStartToken else ""
                return ts.strip() == "void"
        except AttributeError:
            pass
        return False

    def _is_function_ptr(self, tok) -> bool:
        try:
            v = tok.variable
            if v and v.isPointer:
                # typeStartToken points to a function type indicator
                ts = v.typeStartToken
                if ts and _tok_str(ts) in ("void", "int", "char", "long",
                                            "unsigned", "float", "double"):
                    # Heuristic: declared with (*) notation
                    return getattr(v, 'isFunction', False)
        except AttributeError:
            pass
        return False

    def _could_be_fn(self, tok) -> bool:
        """Heuristic: tok looks like a function name used as a value."""
        s = _tok_str(tok)
        return bool(re.match(r'^[A-Za-z_]\w*$', s))

    def _parse_cast_simple(self, open_paren) -> Tuple[str, int, object]:
        parts: List[str] = []
        stars = 0
        t = open_paren.next
        while t is not None:
            s = _tok_str(t)
            if s in ('const', 'volatile'):
                t = t.next
                continue
            if s == '*':
                stars += 1
                t = t.next
                continue
            if s == ')':
                return " ".join(parts), stars, t
            if re.match(r'^[A-Za-z_]\w*$', s):
                parts.append(s)
                t = t.next
                continue
            return "", 0, None
        return "", 0, None


# ===========================================================================
#  TCD-06  enum_out_of_range
#  CWE-704  Incorrect Type Conversion or Cast
#
#  Flags: assigning an integer literal to an enum-typed variable where the
#  literal is not among the declared enumerator values.
# ===========================================================================

class _TCD06_EnumOutOfRange(_BaseChecker):
    checker_id = "TCD-06"
    cwe        = 704
    severity   = "style"

    def check(self, cfg) -> None:
        # Build map: enum type name → set of valid integer values
        enum_values: Dict[str, Set[int]] = {}
        try:
            for enum in cfg.enumlist:
                try:
                    name = enum.name or ""
                    vals: Set[int] = set()
                    for item in enum.items:
                        try:
                            vals.add(int(item.value))
                        except (TypeError, ValueError, AttributeError):
                            pass
                    if name:
                        enum_values[name] = vals
                except AttributeError:
                    pass
        except AttributeError:
            pass

        if not enum_values:
            return

        for tok in _tokens(cfg):
            if _tok_str(tok) != '=':
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue
            # LHS must be an enum-typed variable
            enum_name = self._get_enum_type(lhs)
            if not enum_name or enum_name not in enum_values:
                continue
            # RHS must be a plain integer literal
            try:
                lit_val = int(_tok_str(rhs))
            except (ValueError, TypeError):
                continue
            valid = enum_values[enum_name]
            if lit_val not in valid:
                msg = (
                    f"Integer literal {lit_val} assigned to enum '{enum_name}' "
                    f"variable '{_tok_str(lhs)}' is outside the declared "
                    f"enumerator range {sorted(valid)}. "
                    f"This may indicate a type confusion (CWE-704)."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _get_enum_type(self, tok) -> str:
        try:
            v = tok.variable
            if v and v.typeStartToken:
                ts = _tok_str(v.typeStartToken)
                te = _tok_str(v.typeEndToken) if v.typeEndToken else ""
                # enum Foo → "Foo"
                if ts == "enum":
                    return te
                return ts
        except AttributeError:
            pass
        return ""


# ===========================================================================
#  TCD-07  struct_reinterpret_cast
#  CWE-843  Access of Resource Using Incompatible Type
#
#  Flags: (struct B*)ptr  where ptr is declared as struct A*  (A ≠ B).
#  Different from TCD-01 which handles scalar types.
# ===========================================================================

class _TCD07_StructReinterpretCast(_BaseChecker):
    checker_id = "TCD-07"
    cwe        = 843
    severity   = "error"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _tok_str(tok) != '(':
                continue
            cast_struct, stars, close = self._parse_struct_ptr_cast(tok)
            if not cast_struct or stars == 0 or not close:
                continue
            operand = close.next
            if operand is None:
                continue
            src_struct = self._operand_struct_type(operand)
            if not src_struct:
                continue
            if cast_struct != src_struct:
                msg = (
                    f"Reinterpreting 'struct {src_struct}*' as 'struct {cast_struct}*'. "
                    f"Structs have different types and potentially different layouts; "
                    f"this is undefined behaviour (CWE-843). "
                    f"Use a tagged union or explicit field conversion."
                )
                _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _parse_struct_ptr_cast(self, open_paren) -> Tuple[str, int, object]:
        t = open_paren.next
        if t is None or _tok_str(t) not in _COMPOSITE_KW:
            return "", 0, None
        t = t.next
        if t is None or not re.match(r'^[A-Za-z_]\w*$', _tok_str(t)):
            return "", 0, None
        struct_name = _tok_str(t)
        t = t.next
        stars = 0
        while t is not None and _tok_str(t) == '*':
            stars += 1
            t = t.next
        if t is None or _tok_str(t) != ')':
            return "", 0, None
        return struct_name, stars, t

    def _operand_struct_type(self, tok) -> str:
        try:
            v = tok.variable
            if v and v.isPointer and v.typeStartToken:
                ts = v.typeStartToken
                if _tok_str(ts) in _COMPOSITE_KW and ts.next:
                    return _tok_str(ts.next)
        except AttributeError:
            pass
        return ""


# ===========================================================================
#  TCD-08  char_width_confusion
#  CWE-704  Incorrect Type Conversion or Cast
#
#  Flags passing a char* argument to a function that expects wchar_t* or
#  vice-versa.  Uses lists of well-known wide/narrow string functions.
# ===========================================================================

class _TCD08_CharWidthConfusion(_BaseChecker):
    checker_id = "TCD-08"
    cwe        = 704
    severity   = "warning"

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if not tok.isName:
                continue
            fname = _tok_str(tok)
            if fname not in _WIDE_STRING_FUNCS and fname not in _NARROW_STRING_FUNCS:
                continue
            # Check the argument list
            paren = tok.next
            if paren is None or _tok_str(paren) != '(':
                continue
            expects_wide   = fname in _WIDE_STRING_FUNCS
            expects_narrow = fname in _NARROW_STRING_FUNCS
            # Walk through comma-separated arguments
            depth = 0
            arg_tok = paren.next
            arg_num = 0
            while arg_tok is not None:
                s = _tok_str(arg_tok)
                if s == '(':
                    depth += 1
                elif s == ')':
                    if depth == 0:
                        break
                    depth -= 1
                elif s == ',' and depth == 0:
                    arg_num += 1
                    arg_tok = arg_tok.next
                    continue
                # At depth==0, check if arg_tok is a char*/wchar_t* var
                if depth == 0 and arg_tok.isName and _safe_vid(arg_tok):
                    try:
                        v = arg_tok.variable
                        if v and v.isPointer:
                            base = self._base_char_type(v)
                            if base in _CHAR_TYPES and expects_wide:
                                msg = (
                                    f"Passing narrow 'char*' argument "
                                    f"'{_tok_str(arg_tok)}' to wide-string "
                                    f"function '{fname}' (arg {arg_num+1}). "
                                    f"This causes type confusion and undefined "
                                    f"behaviour (CWE-704)."
                                )
                                _emit(self.checker_id, self.cwe, self.severity,
                                      msg, arg_tok)
                            elif base in _WCHAR_TYPES and expects_narrow:
                                msg = (
                                    f"Passing wide '{base}*' argument "
                                    f"'{_tok_str(arg_tok)}' to narrow-string "
                                    f"function '{fname}' (arg {arg_num+1}). "
                                    f"This causes type confusion and undefined "
                                    f"behaviour (CWE-704)."
                                )
                                _emit(self.checker_id, self.cwe, self.severity,
                                      msg, arg_tok)
                    except AttributeError:
                        pass
                arg_tok = arg_tok.next

    def _base_char_type(self, var) -> str:
        try:
            ts = var.typeStartToken
            te = var.typeEndToken
            if ts:
                parts = []
                t = ts
                while t is not None:
                    s = _tok_str(t)
                    if s not in ('*', 'const', 'volatile', 'restrict'):
                        parts.append(s)
                    if t == te:
                        break
                    t = t.next
                return " ".join(parts).strip()
        except AttributeError:
            pass
        return ""


# ===========================================================================
#  TCD-09  sign_change_return
#  CWE-681  Incorrect Conversion Between Numeric Types
#
#  Flags functions that are declared to return unsigned T but have a
#  'return expr;' where expr is a signed variable, or vice-versa,
#  without an explicit cast.
# ===========================================================================

class _TCD09_SignChangeReturn(_BaseChecker):
    checker_id = "TCD-09"
    cwe        = 681
    severity   = "warning"

    def check(self, cfg) -> None:
        for func in self._iter_functions(cfg):
            ret_signed   = self._func_returns_signed(func)
            ret_unsigned = self._func_returns_unsigned(func)
            if not ret_signed and not ret_unsigned:
                continue
            # Walk function body for 'return' statements
            try:
                body_start = func.token   # function token
                # Find the opening brace
                tok = body_start
                while tok is not None and _tok_str(tok) != '{':
                    tok = tok.next
                if tok is None:
                    continue
                brace_end = tok.link
                if brace_end is None:
                    continue
                tok = tok.next
                while tok is not None and tok != brace_end:
                    if _tok_str(tok) == 'return':
                        expr = tok.next
                        if expr is None or _tok_str(expr) == ';':
                            tok = tok.next
                            continue
                        # Check for explicit cast — skip if next token is '('
                        if _tok_str(expr) == '(':
                            tok = tok.next
                            continue
                        # Check sign of the returned expression
                        if ret_unsigned and self._expr_is_signed(expr):
                            fname = _tok_str(func.token)
                            msg = (
                                f"Function '{fname}' declared to return "
                                f"unsigned type, but returning signed expression "
                                f"'{_tok_str(expr)}' without explicit cast. "
                                f"Negative values will wrap (CWE-681)."
                            )
                            _emit(self.checker_id, self.cwe, self.severity,
                                  msg, tok)
                        elif ret_signed and self._expr_is_unsigned(expr):
                            fname = _tok_str(func.token)
                            msg = (
                                f"Function '{fname}' declared to return "
                                f"signed type, but returning unsigned expression "
                                f"'{_tok_str(expr)}' without explicit cast. "
                                f"Large values may become negative (CWE-681)."
                            )
                            _emit(self.checker_id, self.cwe, self.severity,
                                  msg, tok)
                    tok = tok.next
            except AttributeError:
                pass

    def _iter_functions(self, cfg):
        try:
            for scope in cfg.scopes:
                if scope.type == "Function":
                    yield scope
        except AttributeError:
            pass

    def _func_returns_signed(self, scope) -> bool:
        try:
            f = scope.function
            if f and f.retDef:
                s = _tok_str(f.retDef).lower()
                if "unsigned" in s:
                    return False
                for st in _SIGNED_INT_TYPES:
                    if st in s:
                        return True
        except AttributeError:
            pass
        return False

    def _func_returns_unsigned(self, scope) -> bool:
        try:
            f = scope.function
            if f and f.retDef:
                s = _tok_str(f.retDef).lower()
                if "unsigned" in s:
                    return True
                for ut in _UNSIGNED_INT_TYPES:
                    if ut in s:
                        return True
        except AttributeError:
            pass
        return False

    def _expr_is_signed(self, tok) -> bool:
        try:
            if tok.variable:
                ts = _tok_str(tok.variable.typeStartToken) if tok.variable.typeStartToken else ""
                if "unsigned" in ts.lower():
                    return False
                for st in _SIGNED_INT_TYPES:
                    if st in ts.lower():
                        return True
        except AttributeError:
            pass
        return False

    def _expr_is_unsigned(self, tok) -> bool:
        try:
            if tok.variable:
                ts = _tok_str(tok.variable.typeStartToken) if tok.variable.typeStartToken else ""
                if "unsigned" in ts.lower():
                    return True
                for ut in _UNSIGNED_INT_TYPES:
                    if ut in ts.lower():
                        return True
        except AttributeError:
            pass
        return False


# ===========================================================================
#  TCD-10  implicit_narrowing_arith
#  CWE-190  Integer Overflow or Wraparound
#
#  Flags: narrow_var = expr  where expr involves arithmetic on int-or-wider
#  operands but narrow_var is char/short (or 8/16-bit typedef) without any
#  explicit cast.
# ===========================================================================

class _TCD10_ImplicitNarrowingArith(_BaseChecker):
    checker_id = "TCD-10"
    cwe        = 190
    severity   = "warning"

    _ARITH_OPS: frozenset = frozenset({'+', '-', '*', '/', '%', '<<', '>>'})
    _NARROW_WIDTHS: frozenset = frozenset({1, 2})   # char=1, short=2
    _WIDE_MIN_WIDTH: int = 4                          # int=4

    def check(self, cfg) -> None:
        for tok in _tokens(cfg):
            if _tok_str(tok) != '=':
                continue
            lhs = tok.astOperand1
            rhs = tok.astOperand2
            if lhs is None or rhs is None:
                continue
            # LHS must be a narrow integer variable
            lhs_width = self._var_width(lhs)
            if lhs_width not in self._NARROW_WIDTHS:
                continue
            # RHS must be an arithmetic expression (has operator node)
            if not self._is_arith_expr(rhs):
                continue
            # RHS must not be wrapped in an explicit cast
            # Heuristic: if the immediate AST parent is a cast node, skip
            if self._has_explicit_cast(rhs):
                continue
            msg = (
                f"Implicit narrowing assignment: arithmetic result "
                f"(likely {self._WIDE_MIN_WIDTH}+ bytes) stored into "
                f"'{_tok_str(lhs)}' ({lhs_width} bytes) without explicit cast. "
                f"Overflow/truncation may occur silently (CWE-190)."
            )
            _emit(self.checker_id, self.cwe, self.severity, msg, tok)

    def _var_width(self, tok) -> int:
        try:
            v = tok.variable
            if v and v.typeStartToken:
                ts = v.typeStartToken
                te = v.typeEndToken
                parts = []
                t = ts
                while t is not None:
                    s = _tok_str(t)
                    if s not in ('*', 'const', 'volatile', 'restrict'):
                        parts.append(s)
                    if t == te:
                        break
                    t = t.next
                type_s = " ".join(parts).strip().lower()
                return _TYPE_WIDTH.get(type_s, 0)
        except AttributeError:
            pass
        return 0

    def _is_arith_expr(self, tok) -> bool:
        if tok is None:
            return False
        s = _tok_str(tok)
        return s in self._ARITH_OPS

    def _has_explicit_cast(self, tok) -> bool:
        """
        Very conservative: if the entire RHS AST node is a single identifier
        (not a complex expression), we don't flag it.
        Return True if an explicit cast is detected, False otherwise.
        """
        # We look for a '(' immediately before the operand in the token stream
        try:
            prev = tok.previous
            if prev and _tok_str(prev) == ')':
                # The ')' closing a cast
                return True
        except AttributeError:
            pass
        return False


# ===========================================================================
#  Checker registry & runner
# ===========================================================================

_ALL_CHECKERS: List[_BaseChecker] = [
    _TCD01_PointerTypePun(),
    _TCD02_SignedUnsignedCompare(),
    _TCD03_TruncatingCast(),
    _TCD04_SizeofPointer(),
    _TCD05_VoidPtrFunctionCast(),
    _TCD06_EnumOutOfRange(),
    _TCD07_StructReinterpretCast(),
    _TCD08_CharWidthConfusion(),
    _TCD09_SignChangeReturn(),
    _TCD10_ImplicitNarrowingArith(),
]


def analyse(filename: str, *, checkers=None) -> None:
    """Parse the cppcheck dump file and run all enabled checkers."""
    if checkers is None:
        checkers = _ALL_CHECKERS
    try:
        data = cppcheckdata.CppcheckData(filename)
    except Exception as exc:
        sys.stderr.write(f"TypeConfusionDetector: failed to parse {filename}: {exc}\n")
        return
    for cfg in data.configurations:
        for chk in checkers:
            try:
                chk.check(cfg)
            except Exception as exc:
                sys.stderr.write(
                    f"TypeConfusionDetector: checker {chk.checker_id} raised "
                    f"{type(exc).__name__}: {exc}\n"
                )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(
            "Usage: python3 TypeConfusionDetector.py <file.c.dump>\n"
            "       (Pass one or more .dump files produced by cppcheck --dump)\n"
        )
        sys.exit(1)
    for dump_file in sys.argv[1:]:
        analyse(dump_file)
