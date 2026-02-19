"""
cppcheckdata_shims/type_analysis.py
════════════════════════════════════

Type constraint system and well-formedness checker for C programs,
built on cppcheck dump data.

Theory
──────
Following Møller & Schwartzbach, *Static Program Analysis*, Chapter 3,
we generate type constraints from the program AST and solve them via
unification over an almost-linear union-find structure.

Two analysis layers:

  1. **TypeConstraintAnalysis** — constraint generation + unification
     solver that infers / checks types across all expressions.

  2. **WellFormednessChecker** — enforces C standard structural rules
     that go beyond unification (complete types, storage-class
     legality, qualifier compatibility, etc.).

Both consume a ``cppcheckdata.Configuration`` and produce diagnostics.

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import itertools
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Protocol,
    Self,
    Sequence,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# ── cppcheckdata imports ─────────────────────────────────────────────────
try:
    from cppcheckdata import (  # type: ignore[import-untyped]
        CppcheckData,
        Configuration,
        Token,
        Scope,
        Variable,
        Function,
        ValueType,
    )
except ImportError:
    CppcheckData = Any  # type: ignore[assignment,misc]
    Configuration = Any  # type: ignore[assignment,misc]
    Token = Any  # type: ignore[assignment,misc]
    Scope = Any  # type: ignore[assignment,misc]
    Variable = Any  # type: ignore[assignment,misc]
    Function = Any  # type: ignore[assignment,misc]
    ValueType = Any  # type: ignore[assignment,misc]


# ═════════════════════════════════════════════════════════════════════════
#  PART 1 — TYPE REPRESENTATION
# ═════════════════════════════════════════════════════════════════════════
#
#  We model C types as a term algebra:
#
#    τ ::= α                          (type variable)
#        | void | bool | char | short | int | long | long_long
#        | float | double | long_double
#        | ptr(τ)                      (pointer to τ)
#        | array(τ, n)                 (array of τ, length n or unknown)
#        | func(τ_ret, [τ_1, …, τ_n]) (function type)
#        | struct(tag, {f_i: τ_i})     (struct type)
#        | union(tag, {f_i: τ_i})      (union type)
#        | enum(tag)                   (enumeration)
#        | qualified(τ, quals)         (const/volatile/restrict/_Atomic)
#        | typedef(name, τ)            (typedef alias)
#        | error                       (type error sentinel)
#
#  Type variables (α) represent unknown types awaiting unification.
# ═════════════════════════════════════════════════════════════════════════

class TypeKind(Enum):
    """Discriminant for the type term algebra."""
    VAR = auto()          # Type variable (unification)
    VOID = auto()
    BOOL = auto()
    CHAR = auto()
    SCHAR = auto()
    UCHAR = auto()
    SHORT = auto()
    USHORT = auto()
    INT = auto()
    UINT = auto()
    LONG = auto()
    ULONG = auto()
    LONG_LONG = auto()
    ULONG_LONG = auto()
    FLOAT = auto()
    DOUBLE = auto()
    LONG_DOUBLE = auto()
    PTR = auto()          # ptr(τ)
    ARRAY = auto()        # array(τ, n)
    FUNC = auto()         # func(ret, [params...], variadic?)
    STRUCT = auto()        # struct(tag, fields)
    UNION = auto()         # union(tag, fields)
    ENUM = auto()          # enum(tag)
    QUALIFIED = auto()     # qualified(τ, quals)
    TYPEDEF = auto()       # typedef(name, τ)
    ERROR = auto()         # unification failure sentinel
    BITFIELD = auto()      # bitfield(τ, width)


class Qualifier(Enum):
    CONST = auto()
    VOLATILE = auto()
    RESTRICT = auto()
    ATOMIC = auto()


@dataclass
class CType:
    """
    A node in the type term algebra.

    For compound types the children encode structure:
      - PTR:       children[0] = pointee type
      - ARRAY:     children[0] = element type; array_size = length or -1
      - FUNC:      children[0] = return type; children[1:] = param types
      - STRUCT:    field_map = {name: CType}
      - UNION:     field_map = {name: CType}
      - QUALIFIED: children[0] = underlying type; qualifiers = set
      - TYPEDEF:   children[0] = aliased type; typedef_name = str
      - BITFIELD:  children[0] = underlying integer type; bitfield_width = int
      - VAR:       var_id = unique int (for unification)
    """

    kind: TypeKind
    children: List[CType] = field(default_factory=list)

    # ── Kind-specific attributes ─────────────────────────────────────
    var_id: int = -1                          # VAR
    tag: str = ""                              # STRUCT / UNION / ENUM
    field_map: Dict[str, CType] = field(default_factory=dict)  # STRUCT / UNION
    # preserves declaration order
    field_order: List[str] = field(default_factory=list)
    qualifiers: Set[Qualifier] = field(default_factory=set)      # QUALIFIED
    typedef_name: str = ""                     # TYPEDEF
    array_size: int = -1                       # ARRAY (-1 = unknown)
    is_variadic: bool = False                  # FUNC
    is_signed: Optional[bool] = None           # integer types
    bitfield_width: int = 0                    # BITFIELD
    sign: Optional[str] = None                 # "signed" / "unsigned" / None

    # ── Source location for diagnostics ──────────────────────────────
    source_file: str = ""
    source_line: int = 0
    source_column: int = 0

    # ── Factory methods ──────────────────────────────────────────────

    _var_counter: ClassVar[int] = 0

    @classmethod
    def fresh_var(cls) -> CType:
        """Create a fresh type variable for unification."""
        cls._var_counter += 1
        return cls(kind=TypeKind.VAR, var_id=cls._var_counter)

    @classmethod
    def void(cls) -> CType:
        return cls(kind=TypeKind.VOID)

    @classmethod
    def bool_type(cls) -> CType:
        return cls(kind=TypeKind.BOOL)

    @classmethod
    def char_type(cls, signed: Optional[bool] = None) -> CType:
        if signed is True:
            return cls(kind=TypeKind.SCHAR, sign="signed")
        if signed is False:
            return cls(kind=TypeKind.UCHAR, sign="unsigned")
        return cls(kind=TypeKind.CHAR)

    @classmethod
    def int_type(cls, signed: bool = True) -> CType:
        return cls(
            kind=TypeKind.UINT if not signed else TypeKind.INT,
            sign="unsigned" if not signed else "signed",
        )

    @classmethod
    def short_type(cls, signed: bool = True) -> CType:
        return cls(
            kind=TypeKind.USHORT if not signed else TypeKind.SHORT,
            sign="unsigned" if not signed else "signed",
        )

    @classmethod
    def long_type(cls, signed: bool = True) -> CType:
        return cls(
            kind=TypeKind.ULONG if not signed else TypeKind.LONG,
            sign="unsigned" if not signed else "signed",
        )

    @classmethod
    def long_long_type(cls, signed: bool = True) -> CType:
        return cls(
            kind=TypeKind.ULONG_LONG if not signed else TypeKind.LONG_LONG,
            sign="unsigned" if not signed else "signed",
        )

    @classmethod
    def float_type(cls) -> CType:
        return cls(kind=TypeKind.FLOAT)

    @classmethod
    def double_type(cls) -> CType:
        return cls(kind=TypeKind.DOUBLE)

    @classmethod
    def long_double_type(cls) -> CType:
        return cls(kind=TypeKind.LONG_DOUBLE)

    @classmethod
    def ptr(cls, pointee: CType) -> CType:
        return cls(kind=TypeKind.PTR, children=[pointee])

    @classmethod
    def array(cls, element: CType, size: int = -1) -> CType:
        return cls(kind=TypeKind.ARRAY, children=[element], array_size=size)

    @classmethod
    def func(
        cls,
        ret: CType,
        params: Optional[List[CType]] = None,
        variadic: bool = False,
    ) -> CType:
        children = [ret] + (params or [])
        return cls(kind=TypeKind.FUNC, children=children, is_variadic=variadic)

    @classmethod
    def struct(
        cls,
        tag: str,
        fields: Optional[Dict[str, CType]] = None,
        field_order: Optional[List[str]] = None,
    ) -> CType:
        fm = fields or {}
        fo = field_order or list(fm.keys())
        return cls(kind=TypeKind.STRUCT, tag=tag, field_map=fm, field_order=fo)

    @classmethod
    def union(
        cls,
        tag: str,
        fields: Optional[Dict[str, CType]] = None,
        field_order: Optional[List[str]] = None,
    ) -> CType:
        fm = fields or {}
        fo = field_order or list(fm.keys())
        return cls(kind=TypeKind.UNION, tag=tag, field_map=fm, field_order=fo)

    @classmethod
    def enum_type(cls, tag: str) -> CType:
        return cls(kind=TypeKind.ENUM, tag=tag)

    @classmethod
    def qualified(cls, base: CType, quals: Set[Qualifier]) -> CType:
        if not quals:
            return base
        # Merge qualifiers if base is already qualified
        if base.kind == TypeKind.QUALIFIED:
            merged = base.qualifiers | quals
            return cls(
                kind=TypeKind.QUALIFIED,
                children=[base.children[0]],
                qualifiers=merged,
            )
        return cls(kind=TypeKind.QUALIFIED, children=[base], qualifiers=quals)

    @classmethod
    def typedef(cls, name: str, underlying: CType) -> CType:
        return cls(
            kind=TypeKind.TYPEDEF,
            children=[underlying],
            typedef_name=name,
        )

    @classmethod
    def bitfield(cls, base: CType, width: int) -> CType:
        return cls(kind=TypeKind.BITFIELD, children=[base], bitfield_width=width)

    @classmethod
    def error(cls) -> CType:
        return cls(kind=TypeKind.ERROR)

    # ── Predicates ───────────────────────────────────────────────────

    @property
    def is_integer(self) -> bool:
        unq = self.unqualified
        return unq.kind in {
            TypeKind.BOOL, TypeKind.CHAR, TypeKind.SCHAR, TypeKind.UCHAR,
            TypeKind.SHORT, TypeKind.USHORT, TypeKind.INT, TypeKind.UINT,
            TypeKind.LONG, TypeKind.ULONG, TypeKind.LONG_LONG, TypeKind.ULONG_LONG,
            TypeKind.ENUM,
        }

    @property
    def is_arithmetic(self) -> bool:
        unq = self.unqualified
        return unq.is_integer or unq.kind in {
            TypeKind.FLOAT, TypeKind.DOUBLE, TypeKind.LONG_DOUBLE,
        }

    @property
    def is_scalar(self) -> bool:
        unq = self.unqualified
        return unq.is_arithmetic or unq.kind == TypeKind.PTR

    @property
    def is_aggregate(self) -> bool:
        unq = self.unqualified
        return unq.kind in {TypeKind.STRUCT, TypeKind.UNION, TypeKind.ARRAY}

    @property
    def is_pointer(self) -> bool:
        return self.unqualified.kind == TypeKind.PTR

    @property
    def is_function(self) -> bool:
        return self.unqualified.kind == TypeKind.FUNC

    @property
    def is_void(self) -> bool:
        return self.unqualified.kind == TypeKind.VOID

    @property
    def is_complete(self) -> bool:
        """C standard: a type is complete if its size can be determined."""
        unq = self.unqualified
        if unq.kind == TypeKind.VOID:
            return False
        if unq.kind == TypeKind.ARRAY and unq.array_size < 0:
            return False
        if unq.kind in {TypeKind.STRUCT, TypeKind.UNION}:
            return len(unq.field_map) > 0 or unq.tag == ""
        return True

    @property
    def unqualified(self) -> CType:
        """Strip top-level qualifiers."""
        t = self
        while t.kind == TypeKind.QUALIFIED:
            t = t.children[0]
        while t.kind == TypeKind.TYPEDEF:
            t = t.children[0]
        return t

    @property
    def pointee(self) -> Optional[CType]:
        unq = self.unqualified
        if unq.kind == TypeKind.PTR:
            return unq.children[0]
        return None

    @property
    def element_type(self) -> Optional[CType]:
        unq = self.unqualified
        if unq.kind == TypeKind.ARRAY:
            return unq.children[0]
        return None

    @property
    def return_type(self) -> Optional[CType]:
        unq = self.unqualified
        if unq.kind == TypeKind.FUNC and unq.children:
            return unq.children[0]
        return None

    @property
    def param_types(self) -> List[CType]:
        unq = self.unqualified
        if unq.kind == TypeKind.FUNC:
            return unq.children[1:]
        return []

    # ── Integer conversion rank (C11 §6.3.1.1) ──────────────────────

    _INTEGER_RANK: ClassVar[Dict[TypeKind, int]] = {
        TypeKind.BOOL: 0,
        TypeKind.CHAR: 1, TypeKind.SCHAR: 1, TypeKind.UCHAR: 1,
        TypeKind.SHORT: 2, TypeKind.USHORT: 2,
        TypeKind.INT: 3, TypeKind.UINT: 3,
        TypeKind.LONG: 4, TypeKind.ULONG: 4,
        TypeKind.LONG_LONG: 5, TypeKind.ULONG_LONG: 5,
        TypeKind.ENUM: 3,  # enums have rank of int
    }

    @property
    def integer_rank(self) -> int:
        return self._INTEGER_RANK.get(self.unqualified.kind, -1)

    def __repr__(self) -> str:
        return _type_to_str(self)


def _type_to_str(t: CType, depth: int = 0) -> str:
    """Pretty-print a CType."""
    if depth > 20:
        return "..."
    k = t.kind
    if k == TypeKind.VAR:
        return f"α{t.var_id}"
    if k == TypeKind.ERROR:
        return "<error>"
    if k == TypeKind.VOID:
        return "void"
    if k == TypeKind.BOOL:
        return "_Bool"
    if k in {TypeKind.CHAR, TypeKind.SCHAR, TypeKind.UCHAR}:
        prefix = {"signed": "signed ", "unsigned": "unsigned "}.get(
            t.sign or "", "")
        return f"{prefix}char"
    if k in {TypeKind.SHORT, TypeKind.USHORT}:
        prefix = "unsigned " if t.sign == "unsigned" else ""
        return f"{prefix}short"
    if k in {TypeKind.INT, TypeKind.UINT}:
        prefix = "unsigned " if t.sign == "unsigned" else ""
        return f"{prefix}int"
    if k in {TypeKind.LONG, TypeKind.ULONG}:
        prefix = "unsigned " if t.sign == "unsigned" else ""
        return f"{prefix}long"
    if k in {TypeKind.LONG_LONG, TypeKind.ULONG_LONG}:
        prefix = "unsigned " if t.sign == "unsigned" else ""
        return f"{prefix}long long"
    if k == TypeKind.FLOAT:
        return "float"
    if k == TypeKind.DOUBLE:
        return "double"
    if k == TypeKind.LONG_DOUBLE:
        return "long double"
    if k == TypeKind.PTR:
        return f"ptr({_type_to_str(t.children[0], depth + 1)})"
    if k == TypeKind.ARRAY:
        sz = str(t.array_size) if t.array_size >= 0 else "?"
        return f"array({_type_to_str(t.children[0], depth + 1)}, {sz})"
    if k == TypeKind.FUNC:
        ret = _type_to_str(t.children[0], depth + 1)
        params = ", ".join(_type_to_str(p, depth + 1) for p in t.children[1:])
        va = ", ..." if t.is_variadic else ""
        return f"func({ret}, ({params}{va}))"
    if k == TypeKind.STRUCT:
        return f"struct {t.tag}" if t.tag else "struct <anon>"
    if k == TypeKind.UNION:
        return f"union {t.tag}" if t.tag else "union <anon>"
    if k == TypeKind.ENUM:
        return f"enum {t.tag}" if t.tag else "enum <anon>"
    if k == TypeKind.QUALIFIED:
        qs = " ".join(q.name.lower()
                      for q in sorted(t.qualifiers, key=lambda q: q.value))
        return f"{qs} {_type_to_str(t.children[0], depth + 1)}"
    if k == TypeKind.TYPEDEF:
        return f"typedef {t.typedef_name} = {_type_to_str(t.children[0], depth + 1)}"
    if k == TypeKind.BITFIELD:
        return f"bitfield({_type_to_str(t.children[0], depth + 1)}, {t.bitfield_width})"
    return f"<{k.name}>"


# ═════════════════════════════════════════════════════════════════════════
#  PART 2 — UNION-FIND FOR TYPE UNIFICATION
# ═════════════════════════════════════════════════════════════════════════
#
#  Following Møller & Schwartzbach §3.3: we solve type constraints via
#  unification over a union-find structure with path compression and
#  union-by-rank, giving almost-linear (α(n)) time complexity.
#
#  Each type variable maps to either itself (a root) or another type
#  variable (parent).  Non-variable types are always roots.  When we
#  unify two type terms, we check structural compatibility and merge
#  their roots.
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class UnificationError:
    """Describes a failed unification attempt."""
    type_a: CType
    type_b: CType
    message: str
    file: str = ""
    line: int = 0
    column: int = 0
    context: str = ""  # e.g. "in assignment", "in function call argument 2"

    def __repr__(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"UnificationError({self.message} @ {loc})"


class UnionFind:
    """
    Almost-linear union-find for type unification.

    Maps type-variable ids to their representative CType.
    Non-variable CTypes are their own representatives.

    Implements:
      - ``find(t)``     — find the representative of ``t``
      - ``unify(a, b)`` — unify two types, returning success/failure
    """

    def __init__(self) -> None:
        # parent[var_id] → CType (either another var, or a concrete type)
        self._parent: Dict[int, CType] = {}
        self._rank: Dict[int, int] = {}
        self._errors: List[UnificationError] = []

    @property
    def errors(self) -> List[UnificationError]:
        return list(self._errors)

    def _ensure_registered(self, t: CType) -> None:
        """Register a type variable if not already known."""
        if t.kind == TypeKind.VAR and t.var_id not in self._parent:
            self._parent[t.var_id] = t
            self._rank[t.var_id] = 0

    def find(self, t: CType) -> CType:
        """
        Find the representative (root) of type ``t``.

        For type variables, follows the parent chain with path compression.
        For concrete types, returns ``t`` itself (but recursively finds
        any type-variable children).
        """
        if t.kind != TypeKind.VAR:
            return t

        self._ensure_registered(t)

        # Path compression: walk to root, then compress
        root_id = t.var_id
        while True:
            parent = self._parent[root_id]
            if parent.kind != TypeKind.VAR or parent.var_id == root_id:
                break
            root_id = parent.var_id

        # Now root_id is the root; compress path
        current = t.var_id
        root = self._parent[root_id]
        while current != root_id:
            next_id = self._parent[current]
            if next_id.kind == TypeKind.VAR:
                self._parent[current] = root
                current = next_id.var_id
            else:
                break

        return root

    def unify(
        self,
        a: CType,
        b: CType,
        context: str = "",
        file: str = "",
        line: int = 0,
        column: int = 0,
    ) -> bool:
        """
        Unify types ``a`` and ``b``.

        Returns True on success, False on failure (adds to self.errors).

        Following Møller & Schwartzbach §3.3:
          - If both are the same type variable, do nothing.
          - If one is a type variable, point it at the other.
          - If both are concrete, check structural compatibility
            and recursively unify children.
        """
        ra = self.find(a)
        rb = self.find(b)

        # Same representative → already unified
        if ra is rb:
            return True
        if (
            ra.kind == TypeKind.VAR
            and rb.kind == TypeKind.VAR
            and ra.var_id == rb.var_id
        ):
            return True

        # ── At least one is a type variable → merge ─────────────────
        if ra.kind == TypeKind.VAR and rb.kind == TypeKind.VAR:
            # Union by rank
            if self._rank[ra.var_id] < self._rank[rb.var_id]:
                self._parent[ra.var_id] = rb
            elif self._rank[ra.var_id] > self._rank[rb.var_id]:
                self._parent[rb.var_id] = ra
            else:
                self._parent[rb.var_id] = ra
                self._rank[ra.var_id] += 1
            return True

        if ra.kind == TypeKind.VAR:
            # Occurs check: ensure ra doesn't appear in rb
            if self._occurs_in(ra.var_id, rb):
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Recursive type: α{ra.var_id} occurs in {rb}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            self._parent[ra.var_id] = rb
            return True

        if rb.kind == TypeKind.VAR:
            if self._occurs_in(rb.var_id, ra):
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Recursive type: α{rb.var_id} occurs in {ra}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            self._parent[rb.var_id] = ra
            return True

        # ── Both concrete → structural compatibility ─────────────────
        # Skip through qualifiers and typedefs for structural matching
        ua = ra.unqualified
        ub = rb.unqualified

        # ERROR absorbs everything
        if ua.kind == TypeKind.ERROR or ub.kind == TypeKind.ERROR:
            return True

        # Same kind → recursive unification of children
        if ua.kind != ub.kind:
            # Special cases: implicit conversions allowed in C
            if self._are_implicitly_compatible(ua, ub):
                return True
            self._errors.append(UnificationError(
                type_a=a, type_b=b,
                message=(
                    f"Type mismatch: {_type_to_str(ra)} vs {_type_to_str(rb)}"
                ),
                file=file, line=line, column=column, context=context,
            ))
            return False

        return self._unify_same_kind(ua, ub, context, file, line, column)

    def _unify_same_kind(
        self,
        a: CType,
        b: CType,
        context: str,
        file: str,
        line: int,
        column: int,
    ) -> bool:
        """Unify two types of the same kind."""
        k = a.kind

        # ── Primitive types: identical kind is sufficient ────────────
        if k in {
            TypeKind.VOID, TypeKind.BOOL,
            TypeKind.CHAR, TypeKind.SCHAR, TypeKind.UCHAR,
            TypeKind.SHORT, TypeKind.USHORT,
            TypeKind.INT, TypeKind.UINT,
            TypeKind.LONG, TypeKind.ULONG,
            TypeKind.LONG_LONG, TypeKind.ULONG_LONG,
            TypeKind.FLOAT, TypeKind.DOUBLE, TypeKind.LONG_DOUBLE,
        }:
            # Check sign compatibility
            if a.sign is not None and b.sign is not None and a.sign != b.sign:
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Sign mismatch: {a.sign} vs {b.sign}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            return True

        # ── Pointer: unify pointee types ─────────────────────────────
        if k == TypeKind.PTR:
            return self.unify(
                a.children[0], b.children[0], f"{context} (pointee)", file, line, column,
            )

        # ── Array: unify element types, check sizes ──────────────────
        if k == TypeKind.ARRAY:
            ok = self.unify(
                a.children[0], b.children[0], f"{context} (element)", file, line, column,
            )
            if a.array_size >= 0 and b.array_size >= 0 and a.array_size != b.array_size:
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Array size mismatch: {a.array_size} vs {b.array_size}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            return ok

        # ── Function: unify return + params ──────────────────────────
        if k == TypeKind.FUNC:
            if len(a.children) != len(b.children):
                # Different parameter counts
                if not a.is_variadic and not b.is_variadic:
                    self._errors.append(UnificationError(
                        type_a=a, type_b=b,
                        message=(
                            f"Parameter count mismatch: "
                            f"{len(a.children) - 1} vs {len(b.children) - 1}"
                        ),
                        file=file, line=line, column=column, context=context,
                    ))
                    return False
            ok = True
            for i, (ca, cb) in enumerate(
                zip(a.children, b.children)
            ):
                label = "return type" if i == 0 else f"parameter {i}"
                ok = self.unify(
                    ca, cb, f"{context} ({label})", file, line, column) and ok
            return ok

        # ── Struct / Union: match by tag, then unify field types ─────
        if k in {TypeKind.STRUCT, TypeKind.UNION}:
            if a.tag and b.tag and a.tag != b.tag:
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Tag mismatch: {a.tag} vs {b.tag}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            # Unify common fields
            ok = True
            for fname in a.field_map:
                if fname in b.field_map:
                    ok = self.unify(
                        a.field_map[fname],
                        b.field_map[fname],
                        f"{context} (field .{fname})",
                        file, line, column,
                    ) and ok
            return ok

        # ── Enum: match by tag ───────────────────────────────────────
        if k == TypeKind.ENUM:
            if a.tag and b.tag and a.tag != b.tag:
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Enum tag mismatch: {a.tag} vs {b.tag}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            return True

        # ── Bitfield ─────────────────────────────────────────────────
        if k == TypeKind.BITFIELD:
            ok = self.unify(
                a.children[0], b.children[0], f"{context} (bitfield base)", file, line, column,
            )
            if a.bitfield_width != b.bitfield_width:
                self._errors.append(UnificationError(
                    type_a=a, type_b=b,
                    message=f"Bitfield width mismatch: {a.bitfield_width} vs {b.bitfield_width}",
                    file=file, line=line, column=column, context=context,
                ))
                return False
            return ok

        return True

    def _are_implicitly_compatible(self, a: CType, b: CType) -> bool:
        """
        Check C implicit conversion compatibility.

        C allows many implicit conversions that a strict unification
        would reject.  We model the key ones here.
        """
        # Integer ↔ integer (usual arithmetic conversions)
        if a.is_integer and b.is_integer:
            return True

        # Arithmetic ↔ arithmetic (int ↔ float)
        if a.is_arithmetic and b.is_arithmetic:
            return True

        # Pointer ↔ integer (with warning) — C permits but warns
        if (a.is_pointer and b.is_integer) or (a.is_integer and b.is_pointer):
            return True  # We'll flag this separately in well-formedness

        # void* ↔ any pointer
        if a.kind == TypeKind.PTR and b.kind == TypeKind.PTR:
            pa = a.children[0].unqualified
            pb = b.children[0].unqualified
            if pa.kind == TypeKind.VOID or pb.kind == TypeKind.VOID:
                return True

        # NULL (integer 0) can convert to any pointer
        # Array decays to pointer
        if a.kind == TypeKind.ARRAY and b.kind == TypeKind.PTR:
            return True
        if a.kind == TypeKind.PTR and b.kind == TypeKind.ARRAY:
            return True

        # Function ↔ pointer-to-function
        if a.kind == TypeKind.FUNC and b.kind == TypeKind.PTR:
            pb = b.children[0].unqualified
            if pb.kind == TypeKind.FUNC:
                return True
        if b.kind == TypeKind.FUNC and a.kind == TypeKind.PTR:
            pa = a.children[0].unqualified
            if pa.kind == TypeKind.FUNC:
                return True

        # Enum ↔ int
        if (a.kind == TypeKind.ENUM and b.is_integer) or (
            b.kind == TypeKind.ENUM and a.is_integer
        ):
            return True

        return False

    def _occurs_in(self, var_id: int, t: CType) -> bool:
        """Occurs check: does type variable ``var_id`` appear in ``t``?"""
        t = self.find(t)
        if t.kind == TypeKind.VAR:
            return t.var_id == var_id
        for child in t.children:
            if self._occurs_in(var_id, child):
                return True
        for ft in t.field_map.values():
            if self._occurs_in(var_id, ft):
                return True
        return False

    def resolve(self, t: CType) -> CType:
        """
        Fully resolve a type, replacing all type variables with their
        unified representatives.
        """
        root = self.find(t)
        if root.kind == TypeKind.VAR:
            return root  # still unconstrained

        # Deep resolve children
        resolved_children = [self.resolve(c) for c in root.children]
        resolved_fields = {
            name: self.resolve(ft) for name, ft in root.field_map.items()
        }
        return CType(
            kind=root.kind,
            children=resolved_children,
            var_id=root.var_id,
            tag=root.tag,
            field_map=resolved_fields,
            field_order=root.field_order,
            qualifiers=root.qualifiers,
            typedef_name=root.typedef_name,
            array_size=root.array_size,
            is_variadic=root.is_variadic,
            is_signed=root.is_signed,
            bitfield_width=root.bitfield_width,
            sign=root.sign,
            source_file=root.source_file,
            source_line=root.source_line,
            source_column=root.source_column,
        )


# ═════════════════════════════════════════════════════════════════════════
#  PART 3 — TYPE CONSTRAINT
# ═════════════════════════════════════════════════════════════════════════
#
#  A constraint is a pair (τ₁, τ₂) meaning "τ₁ must unify with τ₂".
#  We also carry source location and a human-readable reason.
# ═════════════════════════════════════════════════════════════════════════

class ConstraintKind(Enum):
    """Classification of type constraints for diagnostic clarity."""
    ASSIGNMENT = auto()         # LHS = RHS type
    ARITHMETIC_OP = auto()      # operands and result must be arithmetic
    COMPARISON_OP = auto()      # operands must be compatible
    LOGICAL_OP = auto()         # operands must be scalar
    BITWISE_OP = auto()         # operands must be integer
    SHIFT_OP = auto()           # operands must be integer
    DEREFERENCE = auto()        # *E: E must be ptr(α), result is α
    ADDRESS_OF = auto()         # &E: result is ptr(typeof(E))
    ARRAY_SUBSCRIPT = auto()    # E1[E2]: E1 is ptr/array, E2 is integer
    FUNCTION_CALL = auto()      # f(args): param/arg type matching
    RETURN = auto()             # return E: E matches function return type
    CONDITIONAL = auto()        # if/while/for condition must be scalar
    TERNARY = auto()            # E1 ? E2 : E3: E2 and E3 must be compatible
    FIELD_ACCESS = auto()       # E.f: E must be struct/union with field f
    SIZEOF = auto()             # sizeof(E): result is size_t
    CAST = auto()               # (T)E: explicit conversion
    INITIALIZER = auto()        # variable init: type of init ≡ variable type
    DECLARATION = auto()        # variable decl consistency
    COMMA = auto()              # (E1, E2): result type is type of E2
    UNARY_MINUS = auto()        # -E: E must be arithmetic
    UNARY_PLUS = auto()         # +E: E must be arithmetic
    UNARY_NOT = auto()          # !E: E must be scalar
    BITWISE_NOT = auto()        # ~E: E must be integer
    INCREMENT = auto()          # ++/--: operand must be scalar
    IMPLICIT_CONVERSION = auto()


@dataclass(frozen=True)
class TypeConstraint:
    """
    A single type constraint: ``type_a ≡ type_b``.

    Attributes
    ----------
    type_a     : CType — left-hand side of the constraint
    type_b     : CType — right-hand side of the constraint
    kind       : ConstraintKind — classification for diagnostics
    reason     : str   — human-readable explanation
    file       : str   — source file
    line       : int   — source line
    column     : int   — source column
    token_id   : str   — cppcheck Token.Id for traceability
    """
    type_a: CType
    type_b: CType
    kind: ConstraintKind
    reason: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    token_id: str = ""

    def __repr__(self) -> str:
        return (
            f"Constraint({_type_to_str(self.type_a)} ≡ "
            f"{_type_to_str(self.type_b)}, "
            f"{self.kind.name}, {self.file}:{self.line})"
        )


# ═════════════════════════════════════════════════════════════════════════
#  PART 4 — TYPE ENVIRONMENT
# ═════════════════════════════════════════════════════════════════════════
#
#  Maps cppcheck identifiers (varId, scopeId, etc.) to CType.
# ═════════════════════════════════════════════════════════════════════════

class TypeEnvironment:
    """
    Maps variable ids, expression ids, and scope ids to their CTypes.

    Maintains separate namespaces:
      - variables  : varId → CType
      - expressions: (token Id) → CType (the [[E]] type variable)
      - functions  : (function Id) → CType (function type)
      - tags       : (tag name) → CType (struct/union/enum definitions)
      - typedefs   : (name) → CType
    """

    def __init__(self) -> None:
        self.variables: Dict[int, CType] = {}          # varId → CType
        self.expressions: Dict[str, CType] = {}        # token.Id → CType
        self.functions: Dict[str, CType] = {}           # function.Id → CType
        self.tags: Dict[str, CType] = {}                # "struct foo" → CType
        self.typedefs: Dict[str, CType] = {}            # "size_t" → CType

    def get_var_type(self, var_id: int) -> CType:
        """Get or create a type variable for ``var_id``."""
        if var_id not in self.variables:
            self.variables[var_id] = CType.fresh_var()
        return self.variables[var_id]

    def set_var_type(self, var_id: int, ctype: CType) -> None:
        self.variables[var_id] = ctype

    def get_expr_type(self, token_id: str) -> CType:
        """Get or create the [[E]] type variable for an expression."""
        if token_id not in self.expressions:
            self.expressions[token_id] = CType.fresh_var()
        return self.expressions[token_id]

    def set_expr_type(self, token_id: str, ctype: CType) -> None:
        self.expressions[token_id] = ctype

    def get_func_type(self, func_id: str) -> CType:
        if func_id not in self.functions:
            self.functions[func_id] = CType.fresh_var()
        return self.functions[func_id]

    def set_func_type(self, func_id: str, ctype: CType) -> None:
        self.functions[func_id] = ctype

    def get_tag_type(self, tag_key: str) -> Optional[CType]:
        return self.tags.get(tag_key)

    def set_tag_type(self, tag_key: str, ctype: CType) -> None:
        self.tags[tag_key] = ctype

    def get_typedef(self, name: str) -> Optional[CType]:
        return self.typedefs.get(name)

    def set_typedef(self, name: str, ctype: CType) -> None:
        self.typedefs[name] = ctype


# ═════════════════════════════════════════════════════════════════════════
#  PART 5 — cppcheckdata ValueType → CType CONVERSION
# ═════════════════════════════════════════════════════════════════════════
#
#  cppcheck already computes ValueType for many tokens.  We convert
#  these to our CType representation to seed the type environment,
#  then let unification discover any inconsistencies.
# ═════════════════════════════════════════════════════════════════════════

def valuetype_to_ctype(vt: Any, env: TypeEnvironment) -> CType:
    """
    Convert a cppcheckdata.ValueType to a CType.

    Parameters
    ----------
    vt  : cppcheckdata.ValueType (or None)
    env : TypeEnvironment — for resolving typedef/scope references

    Returns
    -------
    CType corresponding to the ValueType, or a fresh type variable
    if vt is None.
    """
    if vt is None:
        return CType.fresh_var()

    vt_type = getattr(vt, "type", None)
    vt_sign = getattr(vt, "sign", None)
    pointer = getattr(vt, "pointer", 0) or 0
    original = getattr(vt, "originalTypeName", None) or ""

    base: CType

    # ── Map base type ────────────────────────────────────────────────
    _TYPE_MAP: Dict[str, Callable[[], CType]] = {
        "void": CType.void,
        "bool": CType.bool_type,
        "char": lambda: CType.char_type(signed=_sign_to_bool(vt_sign)),
        "short": lambda: CType.short_type(signed=_sign_to_bool(vt_sign, True)),
        "int": lambda: CType.int_type(signed=_sign_to_bool(vt_sign, True)),
        "long": lambda: CType.long_type(signed=_sign_to_bool(vt_sign, True)),
        "long long": lambda: CType.long_long_type(signed=_sign_to_bool(vt_sign, True)),
        "float": CType.float_type,
        "double": CType.double_type,
        "long double": CType.long_double_type,
    }

    if vt_type in _TYPE_MAP:
        base = _TYPE_MAP[vt_type]()
    elif vt_type == "record":
        scope = getattr(vt, "typeScope", None)
        scope_type = getattr(scope, "type", "Struct") if scope else "Struct"
        tag = original or getattr(scope, "className", "") if scope else ""
        if scope_type == "Union":
            base = CType.union(tag)
        else:
            base = CType.struct(tag)
    elif vt_type == "container":
        # STL containers etc.  Model as an opaque named type.
        base = CType.struct(original or "<container>")
    elif vt_type == "smart-pointer":
        base = CType.struct(original or "<smart-pointer>")
    elif vt_type == "iterator":
        base = CType.struct(original or "<iterator>")
    elif vt_type == "nonstd":
        # Typedef or unknown
        if original:
            td = env.get_typedef(original)
            if td:
                base = td
            else:
                base = CType.fresh_var()
                env.set_typedef(original, base)
        else:
            base = CType.fresh_var()
    else:
        base = CType.fresh_var()

    # ── Build qualifier set ──────────────────────────────────────────
    constness = getattr(vt, "constness", 0) or 0
    quals: Set[Qualifier] = set()
    if constness & 1:
        quals.add(Qualifier.CONST)

    # ── Wrap in pointer(s) ───────────────────────────────────────────
    result = base
    for _ in range(int(pointer)):
        if quals:
            result = CType.qualified(result, quals)
            quals = set()  # qualifiers apply to the innermost non-pointer layer
        result = CType.ptr(result)

    if quals:
        result = CType.qualified(result, quals)

    return result


def _sign_to_bool(sign: Optional[str], default: bool = True) -> bool:
    if sign == "unsigned":
        return False
    if sign == "signed":
        return True
    return default


# ═════════════════════════════════════════════════════════════════════════
#  PART 6 — CONSTRAINT GENERATOR
# ═════════════════════════════════════════════════════════════════════════
#
#  Walks the cppcheck AST, generating TypeConstraints following the
#  rules from Møller & Schwartzbach §3.2, extended for full C.
#
#  For each expression E, we maintain a type variable [[E]].
#  Constraints are generated structurally from the AST.
# ═════════════════════════════════════════════════════════════════════════

class ConstraintGenerator:
    """
    Generates type constraints from a cppcheck Configuration's AST.

    Usage
    -----
    >>> gen = ConstraintGenerator(cfg)
    >>> gen.generate()
    >>> constraints = gen.constraints
    >>> env = gen.env
    """

    def __init__(self, configuration: Any) -> None:
        self.cfg = configuration
        self.env = TypeEnvironment()
        self.constraints: List[TypeConstraint] = []
        self._visited_tokens: Set[str] = set()

    def generate(self) -> None:
        """
        Generate all constraints from the configuration.

        Steps:
          1. Seed the type environment from variable declarations
          2. Seed from cppcheck's ValueType annotations
          3. Walk the AST and generate structural constraints
        """
        self._seed_variables()
        self._seed_functions()
        self._seed_scopes()
        self._walk_all_tokens()

    # ── Phase 1: Seed variable types ─────────────────────────────────

    def _seed_variables(self) -> None:
        """Populate type environment from variable declarations."""
        for var in getattr(self.cfg, "variables", []):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)

            # Use cppcheck's ValueType if available
            vt = getattr(var, "valueType", None)
            ctype = valuetype_to_ctype(vt, self.env)

            # Check for array dimensions
            dims = getattr(var, "dimensions", None)
            if dims:
                for dim in reversed(dims):
                    dim_size = getattr(dim, "size", -1) or -1
                    ctype = CType.array(ctype, int(dim_size))

            # Check for pointer
            is_pointer = getattr(var, "isPointer", False)
            is_array = getattr(var, "isArray", False)

            self.env.set_var_type(vid, ctype)

    def _seed_functions(self) -> None:
        """Populate type environment from function declarations."""
        for func in getattr(self.cfg, "functions", []):
            func_id = getattr(func, "Id", None)
            if func_id is None:
                continue

            # Return type
            ret_vt = getattr(func, "returnValueType", None)
            ret_type = valuetype_to_ctype(ret_vt, self.env)

            # Parameter types
            param_types: List[CType] = []
            arg_dict = getattr(func, "argument", {})
            if isinstance(arg_dict, dict):
                for idx in sorted(arg_dict.keys()):
                    arg = arg_dict[idx]
                    arg_vid = getattr(arg, "Id", None) or getattr(
                        arg, "varId", None)
                    arg_vt = getattr(arg, "valueType", None)
                    if arg_vt:
                        pt = valuetype_to_ctype(arg_vt, self.env)
                    elif arg_vid:
                        pt = self.env.get_var_type(int(arg_vid))
                    else:
                        pt = CType.fresh_var()
                    param_types.append(pt)

            is_variadic = getattr(func, "isVariadic", False)
            func_type = CType.func(ret_type, param_types, is_variadic)
            self.env.set_func_type(str(func_id), func_type)

            # Also register function name as a variable
            token_def = getattr(func, "tokenDef", None)
            if token_def:
                tok_vid = getattr(token_def, "varId", None)
                if tok_vid and tok_vid != 0:
                    self.env.set_var_type(tok_vid, func_type)

    def _seed_scopes(self) -> None:
        """Register struct/union/enum types from scope definitions."""
        for scope in getattr(self.cfg, "scopes", []):
            scope_type = getattr(scope, "type", "")
            class_name = getattr(scope, "className", "")

            if scope_type in {"Struct", "Union"}:
                fields: Dict[str, CType] = {}
                field_order: List[str] = []
                for var in getattr(self.cfg, "variables", []):
                    var_scope = getattr(var, "scope", None)
                    if var_scope is scope:
                        name = getattr(var, "nameToken", None)
                        name_str = getattr(name, "str", "") if name else ""
                        if not name_str:
                            name_str = getattr(var, "name", f"_anon_{id(var)}")
                        var_vid = getattr(var, "Id", None)
                        if var_vid:
                            ft = self.env.get_var_type(int(var_vid))
                        else:
                            ft = CType.fresh_var()
                        fields[name_str] = ft
                        field_order.append(name_str)

                if scope_type == "Struct":
                    tag_type = CType.struct(class_name, fields, field_order)
                else:
                    tag_type = CType.union(class_name, fields, field_order)

                key = f"{scope_type.lower()} {class_name}" if class_name else f"{scope_type.lower()} <anon:{id(scope)}>"
                self.env.set_tag_type(key, tag_type)

            elif scope_type == "Enum":
                tag_type = CType.enum_type(class_name)
                key = f"enum {class_name}" if class_name else f"enum <anon:{id(scope)}>"
                self.env.set_tag_type(key, tag_type)

    # ── Phase 2: Walk AST ────────────────────────────────────────────

    def _walk_all_tokens(self) -> None:
        """Walk every token in the configuration and generate constraints."""
        for tok in getattr(self.cfg, "tokenlist", []):
            self._visit_ast_root(tok)

    def _visit_ast_root(self, tok: Any) -> None:
        """Visit a token as a potential AST root or node."""
        # Only process each token once (via its AST role)
        tok_id = getattr(tok, "Id", None) or str(id(tok))
        if tok_id in self._visited_tokens:
            return

        # Only process tokens that are AST roots or are visited through
        # the AST traversal.  We identify AST roots as tokens with no
        # astParent (they're the top of an expression tree or statement).
        parent = getattr(tok, "astParent", None)
        if parent is not None:
            return  # will be visited when parent is processed

        self._generate_for_expr(tok)

    def _generate_for_expr(self, tok: Any) -> CType:
        """
        Recursively generate constraints for the expression rooted at ``tok``.

        Returns the [[E]] type variable/type for this expression.

        This is the core of Møller & Schwartzbach §3.2, extended for C.
        """
        if tok is None:
            return CType.fresh_var()

        tok_id = getattr(tok, "Id", None) or str(id(tok))
        if tok_id in self._visited_tokens:
            return self.env.get_expr_type(tok_id)
        self._visited_tokens.add(tok_id)

        file = getattr(tok, "file", "")
        line = getattr(tok, "linenr", 0)
        column = getattr(tok, "column", 0)
        s = getattr(tok, "str", "")
        op1 = getattr(tok, "astOperand1", None)
        op2 = getattr(tok, "astOperand2", None)

        # Seed from cppcheck's ValueType if available
        vt = getattr(tok, "valueType", None)
        if vt:
            known_type = valuetype_to_ctype(vt, self.env)
            self.env.set_expr_type(tok_id, known_type)

        expr_type = self.env.get_expr_type(tok_id)

        # ═══════════════════════════════════════════════════════════════
        #  Literal integer:  [[I]] = int
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isNumber", False) and getattr(tok, "isInt", False):
            self._emit(
                expr_type, CType.int_type(),
                ConstraintKind.DECLARATION,
                f"integer literal '{s}'",
                tok,
            )
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Literal float:  [[F]] = double
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isNumber", False) and getattr(tok, "isFloat", False):
            # Check suffix for float/long double
            if s.endswith("f") or s.endswith("F"):
                self._emit(expr_type, CType.float_type(),
                           ConstraintKind.DECLARATION, f"float literal '{s}'", tok)
            elif s.endswith("l") or s.endswith("L"):
                self._emit(expr_type, CType.long_double_type(),
                           ConstraintKind.DECLARATION, f"long double literal '{s}'", tok)
            else:
                self._emit(expr_type, CType.double_type(),
                           ConstraintKind.DECLARATION, f"double literal '{s}'", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  String literal:  [[S]] = ptr(char)
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isString", False):
            strlen_val = getattr(tok, "strlen", -1)
            # String literals are const char[]
            char_t = CType.qualified(CType.char_type(), {Qualifier.CONST})
            arr_t = CType.array(char_t, (strlen_val + 1)
                                if strlen_val >= 0 else -1)
            self._emit(expr_type, arr_t,
                       ConstraintKind.DECLARATION, f"string literal", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Char literal:  [[C]] = int (in C, char literals have type int)
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isChar", False):
            self._emit(expr_type, CType.int_type(),
                       ConstraintKind.DECLARATION, f"char literal '{s}'", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Boolean literal:  [[B]] = _Bool
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isBoolean", False):
            self._emit(expr_type, CType.bool_type(),
                       ConstraintKind.DECLARATION, f"boolean literal", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Variable reference:  [[X]] = env(X)
        # ═══════════════════════════════════════════════════════════════
        vid = getattr(tok, "varId", None)
        if vid and vid != 0 and getattr(tok, "isName", False):
            var_type = self.env.get_var_type(vid)
            self._emit(expr_type, var_type,
                       ConstraintKind.DECLARATION,
                       f"variable '{s}' (id={vid})", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Assignment:  [[X]] = [[E]]
        #  (includes +=, -=, etc.)
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isAssignmentOp", False):
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            if s == "=":
                # Simple assignment: [[LHS]] ≡ [[RHS]]
                self._emit(lhs_type, rhs_type,
                           ConstraintKind.ASSIGNMENT,
                           f"assignment '{s}'", tok)
                self._emit(expr_type, lhs_type,
                           ConstraintKind.ASSIGNMENT,
                           f"assignment result type", tok)
            else:
                # Compound: +=, -=, *=, /=, etc.
                # LHS and RHS must be arithmetic (or pointer for +=/-=)
                if s in {"+=", "-="}:
                    # ptr += int is valid; otherwise both arithmetic
                    pass
                else:
                    # Both must be arithmetic
                    arith = CType.fresh_var()
                    self._emit(lhs_type, arith,
                               ConstraintKind.ARITHMETIC_OP,
                               f"compound assignment '{s}' LHS", tok)
                    self._emit(rhs_type, arith,
                               ConstraintKind.ARITHMETIC_OP,
                               f"compound assignment '{s}' RHS", tok)
                self._emit(expr_type, lhs_type,
                           ConstraintKind.ASSIGNMENT,
                           f"compound assignment result", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Arithmetic binary:  [[E1]] = [[E2]] = [[E1 op E2]] = arith
        #  Following: E₁ op E₂ : [[E₁]] = [[E₂]] = [[E₁ op E₂]] = int
        #  Extended for C: operands must be arithmetic, result follows
        #  the usual arithmetic conversions.
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isArithmeticalOp", False):
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            if s in {"+", "-"}:
                # + and - also work for pointer arithmetic
                # If one is pointer and other is integer, result is pointer
                # We emit a weaker constraint: both must be at least scalar
                self._emit_scalar_constraint(
                    lhs_type, f"'{s}' left operand", tok)
                self._emit_scalar_constraint(
                    rhs_type, f"'{s}' right operand", tok)
            elif s in {"*", "/"}:
                self._emit_arithmetic_constraint(
                    lhs_type, f"'{s}' left operand", tok)
                self._emit_arithmetic_constraint(
                    rhs_type, f"'{s}' right operand", tok)
                self._emit_arithmetic_constraint(
                    expr_type, f"'{s}' result", tok)
            elif s == "%":
                self._emit_integer_constraint(
                    lhs_type, f"'%' left operand", tok)
                self._emit_integer_constraint(
                    rhs_type, f"'%' right operand", tok)
                self._emit_integer_constraint(expr_type, f"'%' result", tok)

            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Comparison:  [[E1 == E2]] = int,  [[E1]] ≡ [[E2]]
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isComparisonOp", False):
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            # Result is always int (C has no bool result for comparisons)
            self._emit(expr_type, CType.int_type(),
                       ConstraintKind.COMPARISON_OP,
                       f"comparison '{s}' result is int", tok)
            # Operands must be compatible
            self._emit(lhs_type, rhs_type,
                       ConstraintKind.COMPARISON_OP,
                       f"comparison '{s}' operands must be compatible", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Logical:  [[E1 && E2]] = int,  [[E1]] and [[E2]] must be scalar
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isLogicalOp", False):
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            self._emit(expr_type, CType.int_type(),
                       ConstraintKind.LOGICAL_OP,
                       f"logical '{s}' result is int", tok)
            self._emit_scalar_constraint(lhs_type, f"'{s}' left operand", tok)
            self._emit_scalar_constraint(rhs_type, f"'{s}' right operand", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Bitwise:  operands must be integer, result is integer
        # ═══════════════════════════════════════════════════════════════
        if s in {"&", "|", "^"} and op1 and op2:
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            self._emit_integer_constraint(lhs_type, f"'{s}' left operand", tok)
            self._emit_integer_constraint(
                rhs_type, f"'{s}' right operand", tok)
            self._emit_integer_constraint(expr_type, f"'{s}' result", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Shift:  operands must be integer
        # ═══════════════════════════════════════════════════════════════
        if s in {"<<", ">>"} and op1 and op2:
            lhs_type = self._generate_for_expr(op1)
            rhs_type = self._generate_for_expr(op2)

            self._emit_integer_constraint(lhs_type, f"'{s}' left operand", tok)
            self._emit_integer_constraint(
                rhs_type, f"'{s}' right operand", tok)
            self._emit(expr_type, lhs_type,
                       ConstraintKind.SHIFT_OP,
                       f"shift result has type of left operand", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Dereference:  *E  →  [[E]] = ptr([[*E]])
        #  Following Møller & Schwartzbach:  *E : [[E]] = &[[*E]]
        # ═══════════════════════════════════════════════════════════════
        if s == "*" and op1 and not op2:
            inner_type = self._generate_for_expr(op1)
            # [[E]] must be ptr(α) where α = [[*E]]
            expected_ptr = CType.ptr(expr_type)
            self._emit(inner_type, expected_ptr,
                       ConstraintKind.DEREFERENCE,
                       f"dereference: operand must be pointer", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Address-of:  &X  →  [[&X]] = ptr([[X]])
        # ═══════════════════════════════════════════════════════════════
        if s == "&" and op1 and not op2:
            inner_type = self._generate_for_expr(op1)
            self._emit(expr_type, CType.ptr(inner_type),
                       ConstraintKind.ADDRESS_OF,
                       f"address-of: result is pointer to operand type", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Array subscript:  E1[E2]  →  E1 is ptr/array, E2 is integer
        #  Result type = element type
        # ═══════════════════════════════════════════════════════════════
        if s == "[" and op1 and op2:
            base_type = self._generate_for_expr(op1)
            index_type = self._generate_for_expr(op2)

            self._emit_integer_constraint(
                index_type, "array subscript index", tok)
            # base must be ptr(α) or array(α, _); result is α
            expected_ptr = CType.ptr(expr_type)
            self._emit(base_type, expected_ptr,
                       ConstraintKind.ARRAY_SUBSCRIPT,
                       f"subscript base must be pointer/array", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Function call:  f(E1,...,En)
        #  [[f]] = func([[f(E1,...,En)]], [[E1]], ..., [[En]])
        # ═══════════════════════════════════════════════════════════════
        if s == "(" and op1:
            func_type_var = self._generate_for_expr(op1)

            # Collect argument types
            arg_types: List[CType] = []
            if op2:
                arg_types = self._collect_comma_args(op2)

            # Build expected function type
            expected_func = CType.func(expr_type, arg_types)
            self._emit(func_type_var, expected_func,
                       ConstraintKind.FUNCTION_CALL,
                       f"function call: callee must be function type", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Comma operator:  (E1, E2)  →  [[E1, E2]] = [[E2]]
        # ═══════════════════════════════════════════════════════════════
        if s == "," and op1 and op2:
            self._generate_for_expr(op1)  # evaluated for side-effects
            rhs_type = self._generate_for_expr(op2)
            self._emit(expr_type, rhs_type,
                       ConstraintKind.COMMA,
                       f"comma operator: result is right operand type", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Ternary:  E1 ? E2 : E3
        #  [[E1]] must be scalar, [[E2]] ≡ [[E3]] ≡ [[E1?E2:E3]]
        # ═══════════════════════════════════════════════════════════════
        if s == "?":
            cond_type = self._generate_for_expr(op1)
            self._emit_scalar_constraint(cond_type, "ternary condition", tok)
            if op2 and getattr(op2, "str", "") == ":":
                true_type = self._generate_for_expr(
                    getattr(op2, "astOperand1", None)
                )
                false_type = self._generate_for_expr(
                    getattr(op2, "astOperand2", None)
                )
                self._emit(true_type, false_type,
                           ConstraintKind.TERNARY,
                           f"ternary branches must have compatible types", tok)
                self._emit(expr_type, true_type,
                           ConstraintKind.TERNARY,
                           f"ternary result type", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Field access:  E.f or E->f
        #  E must be struct/union with field f; result type is field type
        # ═══════════════════════════════════════════════════════════════
        if s == "." and op1 and op2:
            base_type = self._generate_for_expr(op1)
            field_name = getattr(op2, "str", "")

            # Check if base_type has a known struct/union with this field
            resolved_base = base_type.unqualified
            if resolved_base.kind in {TypeKind.STRUCT, TypeKind.UNION}:
                field_type = resolved_base.field_map.get(field_name)
                if field_type:
                    self._emit(expr_type, field_type,
                               ConstraintKind.FIELD_ACCESS,
                               f"field access '.{field_name}'", tok)
                else:
                    # Field not found in current knowledge → emit fresh var
                    pass
            # If it's -> (arrow), base must be pointer to struct/union
            original_name = getattr(tok, "originalName", "")
            if original_name == "->":
                inner = CType.fresh_var()
                expected_ptr = CType.ptr(inner)
                self._emit(base_type, expected_ptr,
                           ConstraintKind.FIELD_ACCESS,
                           f"arrow access '->': left must be pointer", tok)

            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Unary minus/plus:  [[−E]] = [[E]], [[E]] must be arithmetic
        # ═══════════════════════════════════════════════════════════════
        if s == "-" and op1 and not op2:
            inner = self._generate_for_expr(op1)
            self._emit_arithmetic_constraint(inner, "unary minus operand", tok)
            self._emit(expr_type, inner,
                       ConstraintKind.UNARY_MINUS, "unary minus", tok)
            return expr_type

        if s == "+" and op1 and not op2:
            inner = self._generate_for_expr(op1)
            self._emit_arithmetic_constraint(inner, "unary plus operand", tok)
            self._emit(expr_type, inner,
                       ConstraintKind.UNARY_PLUS, "unary plus", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Logical not:  !E  →  result is int, E must be scalar
        # ═══════════════════════════════════════════════════════════════
        if s == "!" and op1 and not op2:
            inner = self._generate_for_expr(op1)
            self._emit_scalar_constraint(inner, "'!' operand", tok)
            self._emit(expr_type, CType.int_type(),
                       ConstraintKind.UNARY_NOT, "logical not result is int", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Bitwise not:  ~E  →  E must be integer, result is integer
        # ═══════════════════════════════════════════════════════════════
        if s == "~" and op1 and not op2:
            inner = self._generate_for_expr(op1)
            self._emit_integer_constraint(inner, "'~' operand", tok)
            self._emit(expr_type, inner,
                       ConstraintKind.BITWISE_NOT, "bitwise not", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Increment/decrement:  ++E, E++, --E, E--
        #  Operand must be scalar (integer or pointer)
        # ═══════════════════════════════════════════════════════════════
        if s in {"++", "--"}:
            inner = self._generate_for_expr(op1)
            self._emit_scalar_constraint(inner, f"'{s}' operand", tok)
            self._emit(expr_type, inner,
                       ConstraintKind.INCREMENT, f"'{s}' result", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Cast:  (T)E  →  [[cast]] = T
        # ═══════════════════════════════════════════════════════════════
        if getattr(tok, "isCast", False):
            self._generate_for_expr(op1)  # sub-expression
            # The cast type is in the token's valueType
            cast_vt = getattr(tok, "valueType", None)
            if cast_vt:
                cast_type = valuetype_to_ctype(cast_vt, self.env)
                self._emit(expr_type, cast_type,
                           ConstraintKind.CAST, "explicit cast", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  sizeof:  result is size_t (unsigned integer)
        # ═══════════════════════════════════════════════════════════════
        if s == "sizeof":
            # platform-dependent; use unsigned long
            size_t = CType.long_type(signed=False)
            self._emit(expr_type, size_t,
                       ConstraintKind.SIZEOF, "sizeof result is size_t", tok)
            if op1:
                self._generate_for_expr(op1)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Control-flow keywords:  if/while/for condition must be scalar
        # ═══════════════════════════════════════════════════════════════
        if s in {"if", "while", "for", "switch"}:
            if op1:
                cond_type = self._generate_for_expr(op1)
                self._emit_scalar_constraint(
                    cond_type, f"'{s}' condition must be scalar", tok
                )
            if op2:
                self._generate_for_expr(op2)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  return E  →  [[E]] ≡ return type of enclosing function
        # ═══════════════════════════════════════════════════════════════
        if s == "return":
            if op1:
                ret_val_type = self._generate_for_expr(op1)
                # Find enclosing function
                scope = getattr(tok, "scope", None)
                if scope:
                    func = getattr(scope, "function", None)
                    if func:
                        func_id = getattr(func, "Id", None)
                        if func_id:
                            ft = self.env.get_func_type(str(func_id))
                            resolved = ft.unqualified
                            if resolved.kind == TypeKind.FUNC and resolved.children:
                                ret_type = resolved.children[0]
                                self._emit(ret_val_type, ret_type,
                                           ConstraintKind.RETURN,
                                           f"return value must match function return type", tok)
            return expr_type

        # ═══════════════════════════════════════════════════════════════
        #  Fallback: recurse into children
        # ═══════════════════════════════════════════════════════════════
        if op1:
            self._generate_for_expr(op1)
        if op2:
            self._generate_for_expr(op2)

        return expr_type

    # ── Helper: collect comma-separated arguments ────────────────────

    def _collect_comma_args(self, tok: Any) -> List[CType]:
        """Flatten a comma-tree into a list of argument types."""
        if tok is None:
            return []
        s = getattr(tok, "str", "")
        if s == ",":
            left = self._collect_comma_args(getattr(tok, "astOperand1", None))
            right = self._collect_comma_args(getattr(tok, "astOperand2", None))
            return left + right
        return [self._generate_for_expr(tok)]

    # ── Helper: emit constraints ─────────────────────────────────────

    def _emit(
        self,
        type_a: CType,
        type_b: CType,
        kind: ConstraintKind,
        reason: str,
        tok: Any,
    ) -> None:
        """Create and store a type constraint."""
        self.constraints.append(TypeConstraint(
            type_a=type_a,
            type_b=type_b,
            kind=kind,
            reason=reason,
            file=getattr(tok, "file", ""),
            line=getattr(tok, "linenr", 0),
            column=getattr(tok, "column", 0),
            token_id=getattr(tok, "Id", ""),
        ))

    def _emit_arithmetic_constraint(
        self, t: CType, reason: str, tok: Any
    ) -> None:
        """Emit: t must be arithmetic (via a marker constraint)."""
        # We use a "phantom" unification: the resolved type must
        # ultimately be arithmetic.  We record this as a post-condition
        # checked after unification.  For now, we record the constraint
        # with a fresh arithmetic type variable tagged for post-check.
        self.constraints.append(TypeConstraint(
            type_a=t,
            type_b=CType.fresh_var(),  # placeholder
            kind=ConstraintKind.ARITHMETIC_OP,
            reason=f"must be arithmetic: {reason}",
            file=getattr(tok, "file", ""),
            line=getattr(tok, "linenr", 0),
            column=getattr(tok, "column", 0),
            token_id=getattr(tok, "Id", ""),
        ))

    def _emit_integer_constraint(
        self, t: CType, reason: str, tok: Any
    ) -> None:
        """Emit: t must be integer."""
        self.constraints.append(TypeConstraint(
            type_a=t,
            type_b=CType.fresh_var(),
            kind=ConstraintKind.BITWISE_OP,
            reason=f"must be integer: {reason}",
            file=getattr(tok, "file", ""),
            line=getattr(tok, "linenr", 0),
            column=getattr(tok, "column", 0),
            token_id=getattr(tok, "Id", ""),
        ))

    def _emit_scalar_constraint(
        self, t: CType, reason: str, tok: Any
    ) -> None:
        """Emit: t must be scalar (integer, float, or pointer)."""
        self.constraints.append(TypeConstraint(
            type_a=t,
            type_b=CType.fresh_var(),
            kind=ConstraintKind.CONDITIONAL,
            reason=f"must be scalar: {reason}",
            file=getattr(tok, "file", ""),
            line=getattr(tok, "linenr", 0),
            column=getattr(tok, "column", 0),
            token_id=getattr(tok, "Id", ""),
        ))


# ═════════════════════════════════════════════════════════════════════════
#  PART 7 — CONSTRAINT SOLVER
# ═════════════════════════════════════════════════════════════════════════
#
#  Feed constraints into UnionFind, then run post-unification checks.
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class TypeDiagnostic:
    """A type-related diagnostic (error or warning)."""
    severity: str  # "error", "warning", "info"
    message: str
    file: str = ""
    line: int = 0
    column: int = 0
    kind: str = ""  # constraint kind or well-formedness rule
    type_a: Optional[CType] = None
    type_b: Optional[CType] = None

    def __repr__(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"[{self.severity}] {self.message} ({loc})"


class ConstraintSolver:
    """
    Solve type constraints via unification, then validate post-conditions.

    Usage
    -----
    >>> gen = ConstraintGenerator(cfg)
    >>> gen.generate()
    >>> solver = ConstraintSolver(gen.constraints, gen.env)
    >>> solver.solve()
    >>> for diag in solver.diagnostics:
    ...     print(diag)
    """

    def __init__(
        self, constraints: List[TypeConstraint], env: TypeEnvironment
    ) -> None:
        self.constraints = constraints
        self.env = env
        self.uf = UnionFind()
        self.diagnostics: List[TypeDiagnostic] = []

    def solve(self) -> None:
        """
        Solve all constraints.

        Phase 1: Unification (structural)
        Phase 2: Post-unification checks (arithmetic/integer/scalar)
        """
        self._phase1_unification()
        self._phase2_postchecks()

    def _phase1_unification(self) -> None:
        """Run unification for all equality constraints."""
        for c in self.constraints:
            # Only unify actual equality constraints (not kind-markers)
            if c.kind in {
                ConstraintKind.ASSIGNMENT,
                ConstraintKind.COMPARISON_OP,
                ConstraintKind.LOGICAL_OP,
                ConstraintKind.DECLARATION,
                ConstraintKind.DEREFERENCE,
                ConstraintKind.ADDRESS_OF,
                ConstraintKind.ARRAY_SUBSCRIPT,
                ConstraintKind.FUNCTION_CALL,
                ConstraintKind.RETURN,
                ConstraintKind.TERNARY,
                ConstraintKind.FIELD_ACCESS,
                ConstraintKind.SIZEOF,
                ConstraintKind.CAST,
                ConstraintKind.COMMA,
                ConstraintKind.UNARY_MINUS,
                ConstraintKind.UNARY_PLUS,
                ConstraintKind.UNARY_NOT,
                ConstraintKind.BITWISE_NOT,
                ConstraintKind.INCREMENT,
                ConstraintKind.SHIFT_OP,
            }:
                self.uf.unify(
                    c.type_a, c.type_b,
                    context=c.reason,
                    file=c.file, line=c.line, column=c.column,
                )

        # Collect unification errors
        for err in self.uf.errors:
            self.diagnostics.append(TypeDiagnostic(
                severity="error",
                message=err.message,
                file=err.file,
                line=err.line,
                column=err.column,
                kind="unification",
                type_a=err.type_a,
                type_b=err.type_b,
            ))

    def _phase2_postchecks(self) -> None:
        """
        Post-unification validation.

        After unification resolves type variables, we verify that
        "must be arithmetic", "must be integer", "must be scalar"
        constraints are actually satisfied.
        """
        for c in self.constraints:
            resolved_a = self.uf.resolve(c.type_a)

            if c.kind == ConstraintKind.ARITHMETIC_OP and "must be arithmetic" in c.reason:
                if resolved_a.kind != TypeKind.VAR and not resolved_a.is_arithmetic:
                    self.diagnostics.append(TypeDiagnostic(
                        severity="error",
                        message=f"{c.reason}: got {_type_to_str(resolved_a)}",
                        file=c.file, line=c.line, column=c.column,
                        kind="arithmetic_required",
                        type_a=resolved_a,
                    ))

            elif c.kind == ConstraintKind.BITWISE_OP and "must be integer" in c.reason:
                if resolved_a.kind != TypeKind.VAR and not resolved_a.is_integer:
                    self.diagnostics.append(TypeDiagnostic(
                        severity="error",
                        message=f"{c.reason}: got {_type_to_str(resolved_a)}",
                        file=c.file, line=c.line, column=c.column,
                        kind="integer_required",
                        type_a=resolved_a,
                    ))

            elif c.kind == ConstraintKind.CONDITIONAL and "must be scalar" in c.reason:
                if resolved_a.kind != TypeKind.VAR and not resolved_a.is_scalar:
                    self.diagnostics.append(TypeDiagnostic(
                        severity="error",
                        message=f"{c.reason}: got {_type_to_str(resolved_a)}",
                        file=c.file, line=c.line, column=c.column,
                        kind="scalar_required",
                        type_a=resolved_a,
                    ))

    def resolved_type_of_var(self, var_id: int) -> CType:
        """Get the resolved type of a variable after solving."""
        t = self.env.get_var_type(var_id)
        return self.uf.resolve(t)

    def resolved_type_of_expr(self, token_id: str) -> CType:
        """Get the resolved type of an expression after solving."""
        t = self.env.get_expr_type(token_id)
        return self.uf.resolve(t)


# ═════════════════════════════════════════════════════════════════════════
#  PART 8 — C STANDARD WELL-FORMEDNESS CHECKER
# ═════════════════════════════════════════════════════════════════════════
#
#  Beyond type unification, C has structural well-formedness rules
#  that must be checked separately.  These are drawn from the C11/C17
#  standards (ISO/IEC 9899).
#
#  This checker validates:
#
#    §6.2.5   Types — completeness, compatibility
#    §6.5.2.2 Function calls — argument count, type compatibility
#    §6.5.3   Unary operators — constraints on operands
#    §6.5.16  Assignment — modifiable lvalue, type constraints
#    §6.7     Declarations — storage class, qualifier rules
#    §6.7.2   Type specifiers — valid combinations
#    §6.7.2.1 Struct/union — complete types for definitions
#    §6.7.2.2 Enum — well-formed enumerator lists
#    §6.7.3   Type qualifiers — restrict on pointers only, etc.
#    §6.7.6   Declarators — arrays of void forbidden, etc.
#    §6.7.6.2 Array declarators — element type constraints
#    §6.7.6.3 Function declarators — parameter type constraints
#    §6.7.9   Initialization — constraints on initializers
# ═════════════════════════════════════════════════════════════════════════

class WellFormednessRule(Enum):
    """Classification of well-formedness rules."""
    INCOMPLETE_TYPE_IN_DEFINITION = auto()    # §6.2.5
    VOID_VARIABLE = auto()                    # §6.2.5: variable cannot have void type
    ARRAY_OF_VOID = auto()                    # §6.7.6.2: array element cannot be void
    ARRAY_OF_FUNCTION = auto()                # §6.7.6.2: array of functions forbidden
    # §6.7.6.3: function cannot return array
    FUNCTION_RETURNING_ARRAY = auto()
    # §6.7.6.3: function cannot return function
    FUNCTION_RETURNING_FUNCTION = auto()
    # §6.7.3: restrict only on pointer types
    RESTRICT_ON_NON_POINTER = auto()
    # §6.7.3: _Atomic cannot qualify array type
    ATOMIC_ARRAY = auto()
    # §6.7.3: _Atomic cannot qualify function type
    ATOMIC_FUNCTION = auto()
    # §6.7.2.1: flexible array must be last field
    FLEXIBLE_ARRAY_NOT_LAST = auto()
    # §6.7.2.1: flexible array cannot be only member
    FLEXIBLE_ARRAY_ONLY_MEMBER = auto()
    # §6.7.1: at most one storage class specifier
    DUPLICATE_STORAGE_CLASS = auto()
    INVALID_STORAGE_CLASS_COMBO = auto()       # §6.7.1: invalid combinations
    # §6.7.2.1: bitfield must have integer type
    BITFIELD_NON_INTEGER = auto()
    # §6.7.2.1: zero-width bitfield must be unnamed
    BITFIELD_ZERO_NAMED = auto()
    BITFIELD_EXCEEDS_TYPE = auto()            # §6.7.2.1: width exceeds type width
    # §6.7.9: const object should be initialized
    CONST_UNINITIALIZED = auto()
    VOID_PARAMETER_WITH_OTHERS = auto()       # §6.7.6.3: void alone in param list
    DUPLICATE_QUALIFIERS = auto()             # §6.7.3: duplicate qualifiers
    # §6.7.2: signed/unsigned on float types
    SIGNED_UNSIGNED_FLOAT = auto()
    MULTIPLE_TYPE_SPECIFIERS = auto()         # §6.7.2: conflicting type specifiers
    # §6.9.1: function definition with incomplete return
    INCOMPLETE_RETURN_TYPE = auto()
    # §6.5.3.2: cannot take address of register variable
    REGISTER_ADDRESSOF = auto()
    # §6.8.6.4: void function returning value
    VOID_RETURN_WITH_VALUE = auto()
    # §6.8.6.4: non-void function missing return value
    NONVOID_RETURN_WITHOUT_VALUE = auto()


@dataclass
class WellFormednessDiagnostic:
    """A well-formedness violation."""
    rule: WellFormednessRule
    severity: str  # "error", "warning"
    message: str
    file: str = ""
    line: int = 0
    column: int = 0

    def __repr__(self) -> str:
        loc = f"{self.file}:{self.line}" if self.file else "?"
        return f"[{self.severity}] {self.rule.name}: {self.message} ({loc})"


class WellFormednessChecker:
    """
    Checks C standard well-formedness rules beyond type unification.

    Consumes a cppcheck Configuration and a solved TypeEnvironment.

    Usage
    -----
    >>> checker = WellFormednessChecker(cfg, solver.env, solver.uf)
    >>> checker.check()
    >>> for diag in checker.diagnostics:
    ...     print(diag)
    """

    def __init__(
        self,
        configuration: Any,
        env: TypeEnvironment,
        uf: UnionFind,
    ) -> None:
        self.cfg = configuration
        self.env = env
        self.uf = uf
        self.diagnostics: List[WellFormednessDiagnostic] = []

    def check(self) -> None:
        """Run all well-formedness checks."""
        self._check_variable_types()
        self._check_struct_union_well_formedness()
        self._check_function_signatures()
        self._check_qualifier_rules()
        self._check_storage_class_rules()
        self._check_return_statements()
        self._check_address_of_register()
        self._check_bitfield_rules()
        self._check_type_specifier_combinations()

    # ── §6.2.5, §6.7.6.2: Variable and array type rules ─────────────

    def _check_variable_types(self) -> None:
        """Check that variable types are well-formed."""
        for var in getattr(self.cfg, "variables", []):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)

            ctype = self.uf.resolve(self.env.get_var_type(vid))
            name = getattr(var, "nameToken", None)
            name_str = getattr(name, "str", "?") if name else "?"
            file = getattr(name, "file", "") if name else ""
            line = getattr(name, "linenr", 0) if name else 0
            column = getattr(name, "column", 0) if name else 0

            unq = ctype.unqualified

            # §6.2.5: variables cannot have type void
            if unq.kind == TypeKind.VOID:
                is_param = getattr(var, "isArgument", False)
                if not is_param:  # void parameters handled separately
                    self._diag(
                        WellFormednessRule.VOID_VARIABLE,
                        "error",
                        f"Variable '{name_str}' declared with type void",
                        file, line, column,
                    )

            # §6.7.6.2: array of void forbidden
            if unq.kind == TypeKind.ARRAY:
                elem = unq.children[0].unqualified if unq.children else None
                if elem and elem.kind == TypeKind.VOID:
                    self._diag(
                        WellFormednessRule.ARRAY_OF_VOID,
                        "error",
                        f"Variable '{name_str}': array of void is forbidden",
                        file, line, column,
                    )

                # §6.7.6.2: array of functions forbidden
                if elem and elem.kind == TypeKind.FUNC:
                    self._diag(
                        WellFormednessRule.ARRAY_OF_FUNCTION,
                        "error",
                        f"Variable '{name_str}': array of functions is forbidden",
                        file, line, column,
                    )

            # §6.2.5: variable definition requires complete type
            is_def = not getattr(var, "isExtern", False)
            if is_def and not ctype.is_complete and not ctype.is_void:
                # Exception: flexible array members handled below
                if not (unq.kind == TypeKind.ARRAY and unq.array_size < 0):
                    self._diag(
                        WellFormednessRule.INCOMPLETE_TYPE_IN_DEFINITION,
                        "warning",
                        f"Variable '{name_str}' defined with incomplete type {_type_to_str(ctype)}",
                        file, line, column,
                    )

            # §6.7.9: const variables should be initialized
            if Qualifier.CONST in ctype.qualifiers if ctype.kind == TypeKind.QUALIFIED else False:
                is_initialized = getattr(var, "isInit", False)
                is_extern = getattr(var, "isExtern", False)
                if not is_initialized and not is_extern and not getattr(var, "isArgument", False):
                    self._diag(
                        WellFormednessRule.CONST_UNINITIALIZED,
                        "warning",
                        f"Const variable '{name_str}' is not initialized",
                        file, line, column,
                    )

    # ── §6.7.2.1: Struct/union well-formedness ──────────────────────

    def _check_struct_union_well_formedness(self) -> None:
        """Check struct/union specific rules."""
        for scope in getattr(self.cfg, "scopes", []):
            scope_type = getattr(scope, "type", "")
            if scope_type not in {"Struct", "Union"}:
                continue

            class_name = getattr(scope, "className", "<anonymous>")
            body_start = getattr(scope, "bodyStart", None)
            file = getattr(body_start, "file", "") if body_start else ""
            line = getattr(body_start, "linenr", 0) if body_start else 0

            # Collect fields (variables in this scope)
            fields: List[Tuple[str, Any]] = []
            for var in getattr(self.cfg, "variables", []):
                if getattr(var, "scope", None) is scope:
                    name_tok = getattr(var, "nameToken", None)
                    name_str = getattr(name_tok, "str", "") if name_tok else ""
                    fields.append((name_str, var))

            # §6.7.2.1 p18: Flexible array member (FAM) must be last
            for i, (fname, fvar) in enumerate(fields):
                fvid = getattr(fvar, "Id", None)
                if fvid is None:
                    continue
                ftype = self.uf.resolve(
                    self.env.get_var_type(int(fvid))).unqualified
                if ftype.kind == TypeKind.ARRAY and ftype.array_size < 0:
                    if i != len(fields) - 1:
                        self._diag(
                            WellFormednessRule.FLEXIBLE_ARRAY_NOT_LAST,
                            "error",
                            f"Flexible array member '{fname}' in {scope_type.lower()} "
                            f"'{class_name}' must be last member",
                            file, line, 0,
                        )
                    # §6.7.2.1 p18: struct must have at least one named member
                    # before the FAM
                    if len(fields) < 2:
                        self._diag(
                            WellFormednessRule.FLEXIBLE_ARRAY_ONLY_MEMBER,
                            "error",
                            f"Flexible array member '{fname}' cannot be "
                            f"the only member of {scope_type.lower()} '{class_name}'",
                            file, line, 0,
                        )

    # ── §6.7.6.3: Function signature rules ──────────────────────────

    def _check_function_signatures(self) -> None:
        """Check function type well-formedness."""
        for func in getattr(self.cfg, "functions", []):
            func_id = getattr(func, "Id", None)
            if func_id is None:
                continue

            func_name = getattr(func, "name", getattr(func, "tokenDef", None))
            if hasattr(func_name, "str"):
                func_name = func_name.str
            func_name = func_name or "<anonymous>"

            token_def = getattr(func, "tokenDef", None)
            file = getattr(token_def, "file", "") if token_def else ""
            line = getattr(token_def, "linenr", 0) if token_def else 0

            ft = self.uf.resolve(self.env.get_func_type(str(func_id)))
            if ft.kind != TypeKind.FUNC:
                continue

            ret = ft.children[0].unqualified if ft.children else CType.void()

            # §6.7.6.3 p1: function cannot return array
            if ret.kind == TypeKind.ARRAY:
                self._diag(
                    WellFormednessRule.FUNCTION_RETURNING_ARRAY,
                    "error",
                    f"Function '{func_name}' cannot return array type",
                    file, line, 0,
                )

            # §6.7.6.3 p1: function cannot return function
            if ret.kind == TypeKind.FUNC:
                self._diag(
                    WellFormednessRule.FUNCTION_RETURNING_FUNCTION,
                    "error",
                    f"Function '{func_name}' cannot return function type",
                    file, line, 0,
                )

            # §6.9.1 p3: function definition must have complete return type
            # (void is complete for return purposes)
            if ret.kind not in {TypeKind.VOID, TypeKind.VAR} and not ret.is_complete:
                self._diag(
                    WellFormednessRule.INCOMPLETE_RETURN_TYPE,
                    "error",
                    f"Function '{func_name}' defined with incomplete return type",
                    file, line, 0,
                )

            # §6.7.6.3 p10: void as sole parameter
            params = ft.children[1:]
            if len(params) > 1:
                for i, p in enumerate(params):
                    if p.unqualified.kind == TypeKind.VOID:
                        self._diag(
                            WellFormednessRule.VOID_PARAMETER_WITH_OTHERS,
                            "error",
                            f"Function '{func_name}': void parameter cannot "
                            f"appear with other parameters (param {i + 1})",
                            file, line, 0,
                        )

    # ── §6.7.3: Qualifier rules ──────────────────────────────────────

    def _check_qualifier_rules(self) -> None:
        """Check type qualifier well-formedness."""
        for var in getattr(self.cfg, "variables", []):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)

            ctype = self.uf.resolve(self.env.get_var_type(vid))
            name = getattr(var, "nameToken", None)
            name_str = getattr(name, "str", "?") if name else "?"
            file = getattr(name, "file", "") if name else ""
            line = getattr(name, "linenr", 0) if name else 0

            # Walk the type looking for qualifier violations
            self._check_qualifier_on_type(ctype, name_str, file, line)

    def _check_qualifier_on_type(
        self, ctype: CType, name: str, file: str, line: int
    ) -> None:
        """Recursively check qualifier constraints."""
        if ctype.kind == TypeKind.QUALIFIED:
            base = ctype.children[0] if ctype.children else CType.fresh_var()
            base_unq = base.unqualified

            # §6.7.3 p2: restrict only on pointer-to-object type
            if Qualifier.RESTRICT in ctype.qualifiers:
                if base_unq.kind != TypeKind.PTR:
                    self._diag(
                        WellFormednessRule.RESTRICT_ON_NON_POINTER,
                        "error",
                        f"'restrict' qualifier on non-pointer type for '{name}'",
                        file, line, 0,
                    )

            # §6.7.3 p3: _Atomic shall not qualify array type
            if Qualifier.ATOMIC in ctype.qualifiers:
                if base_unq.kind == TypeKind.ARRAY:
                    self._diag(
                        WellFormednessRule.ATOMIC_ARRAY,
                        "error",
                        f"'_Atomic' cannot qualify array type for '{name}'",
                        file, line, 0,
                    )
                # _Atomic shall not qualify function type
                if base_unq.kind == TypeKind.FUNC:
                    self._diag(
                        WellFormednessRule.ATOMIC_FUNCTION,
                        "error",
                        f"'_Atomic' cannot qualify function type for '{name}'",
                        file, line, 0,
                    )

            # Recurse into base
            self._check_qualifier_on_type(base, name, file, line)

        elif ctype.kind == TypeKind.PTR and ctype.children:
            self._check_qualifier_on_type(ctype.children[0], name, file, line)
        elif ctype.kind == TypeKind.ARRAY and ctype.children:
            self._check_qualifier_on_type(ctype.children[0], name, file, line)

    # ── §6.7.1: Storage class specifier rules ────────────────────────

    def _check_storage_class_rules(self) -> None:
        """Check storage class specifier rules (simplified)."""
        for var in getattr(self.cfg, "variables", []):
            name = getattr(var, "nameToken", None)
            name_str = getattr(name, "str", "?") if name else "?"
            file = getattr(name, "file", "") if name else ""
            line = getattr(name, "linenr", 0) if name else 0

            is_extern = getattr(var, "isExtern", False)
            is_static = getattr(var, "isStatic", False)
            is_register = getattr(var, "isRegister", False)

            # Count storage class specifiers
            sc_count = sum([is_extern, is_static, is_register])
            if sc_count > 1:
                self._diag(
                    WellFormednessRule.DUPLICATE_STORAGE_CLASS,
                    "error",
                    f"Variable '{name_str}' has multiple storage class specifiers",
                    file, line, 0,
                )

    # ── §6.8.6.4: Return statement rules ────────────────────────────

    def _check_return_statements(self) -> None:
        """Check return statement type compatibility."""
        for tok in getattr(self.cfg, "tokenlist", []):
            s = getattr(tok, "str", "")
            if s != "return":
                continue

            scope = getattr(tok, "scope", None)
            if scope is None:
                continue
            func = getattr(scope, "function", None)
            if func is None:
                continue

            func_id = getattr(func, "Id", None)
            if func_id is None:
                continue

            ft = self.uf.resolve(self.env.get_func_type(str(func_id)))
            if ft.kind != TypeKind.FUNC or not ft.children:
                continue

            ret_type = ft.children[0].unqualified
            has_value = getattr(tok, "astOperand1", None) is not None

            file = getattr(tok, "file", "")
            line = getattr(tok, "linenr", 0)

            # §6.8.6.4 p1: void function returning value
            if ret_type.kind == TypeKind.VOID and has_value:
                self._diag(
                    WellFormednessRule.VOID_RETURN_WITH_VALUE,
                    "warning",
                    f"Void function returns a value",
                    file, line, 0,
                )

            # §6.8.6.4 p1: non-void function returning without value
            if ret_type.kind != TypeKind.VOID and not has_value:
                self._diag(
                    WellFormednessRule.NONVOID_RETURN_WITHOUT_VALUE,
                    "warning",
                    f"Non-void function should return a value",
                    file, line, 0,
                )

    # ── §6.5.3.2: Address of register variable ──────────────────────

    def _check_address_of_register(self) -> None:
        """Check that address-of is not applied to register variables."""
        for tok in getattr(self.cfg, "tokenlist", []):
            s = getattr(tok, "str", "")
            if s != "&":
                continue
            # Unary & (no right operand)
            op1 = getattr(tok, "astOperand1", None)
            op2 = getattr(tok, "astOperand2", None)
            if op2 is not None:
                continue  # binary & (bitwise)
            if op1 is None:
                continue

            vid = getattr(op1, "varId", None)
            if not vid or vid == 0:
                continue

            # Find variable and check if register
            for var in getattr(self.cfg, "variables", []):
                var_id = getattr(var, "Id", None)
                if var_id is not None and int(var_id) == vid:
                    if getattr(var, "isRegister", False):
                        self._diag(
                            WellFormednessRule.REGISTER_ADDRESSOF,
                            "error",
                            f"Cannot take address of register variable '{getattr(op1, 'str', '?')}'",
                            getattr(tok, "file", ""),
                            getattr(tok, "linenr", 0),
                            getattr(tok, "column", 0),
                        )
                    break

    # ── §6.7.2.1: Bitfield rules ────────────────────────────────────

    def _check_bitfield_rules(self) -> None:
        """Check bitfield well-formedness."""
        for var in getattr(self.cfg, "variables", []):
            vid = getattr(var, "Id", None)
            if vid is None:
                continue
            vid = int(vid)

            ctype = self.uf.resolve(self.env.get_var_type(vid))
            if ctype.kind != TypeKind.BITFIELD:
                continue

            name = getattr(var, "nameToken", None)
            name_str = getattr(name, "str", "") if name else ""
            file = getattr(name, "file", "") if name else ""
            line = getattr(name, "linenr", 0) if name else 0

            base = ctype.children[0] if ctype.children else CType.fresh_var()
            width = ctype.bitfield_width

            # §6.7.2.1 p5: bit-field type must be _Bool, signed int, or unsigned int
            # (or implementation-defined integer type)
            if not base.unqualified.is_integer:
                self._diag(
                    WellFormednessRule.BITFIELD_NON_INTEGER,
                    "error",
                    f"Bit-field '{name_str}' has non-integer type {_type_to_str(base)}",
                    file, line, 0,
                )

            # §6.7.2.1 p4: zero-width bit-field must be unnamed
            if width == 0 and name_str:
                self._diag(
                    WellFormednessRule.BITFIELD_ZERO_NAMED,
                    "error",
                    f"Zero-width bit-field '{name_str}' must be unnamed",
                    file, line, 0,
                )

            # §6.7.2.1 p4: width must not exceed type width
            _TYPE_WIDTHS: Dict[TypeKind, int] = {
                TypeKind.BOOL: 1,
                TypeKind.CHAR: 8, TypeKind.SCHAR: 8, TypeKind.UCHAR: 8,
                TypeKind.SHORT: 16, TypeKind.USHORT: 16,
                TypeKind.INT: 32, TypeKind.UINT: 32,
                TypeKind.LONG: 64, TypeKind.ULONG: 64,
                TypeKind.LONG_LONG: 64, TypeKind.ULONG_LONG: 64,
            }
            max_width = _TYPE_WIDTHS.get(base.unqualified.kind, 32)
            if width > max_width:
                self._diag(
                    WellFormednessRule.BITFIELD_EXCEEDS_TYPE,
                    "error",
                    f"Bit-field '{name_str}' width {width} exceeds type width {max_width}",
                    file, line, 0,
                )

    # ── §6.7.2: Type specifier combination rules ────────────────────

    def _check_type_specifier_combinations(self) -> None:
        """
        Check for invalid type specifier combinations.

        E.g., 'unsigned float', 'signed double' are invalid.
        We scan tokens for sequences of type specifiers.
        """
        # This is heuristic: we look for signed/unsigned followed by
        # float/double tokens.
        prev_sign: Optional[str] = None
        for tok in getattr(self.cfg, "tokenlist", []):
            s = getattr(tok, "str", "")
            if s in {"signed", "unsigned"}:
                prev_sign = s
                continue
            if prev_sign and s in {"float", "double"}:
                self._diag(
                    WellFormednessRule.SIGNED_UNSIGNED_FLOAT,
                    "error",
                    f"'{prev_sign}' cannot modify '{s}'",
                    getattr(tok, "file", ""),
                    getattr(tok, "linenr", 0),
                    getattr(tok, "column", 0),
                )
            if s not in {"long", "short", "int", "char", "_Bool",
                         "signed", "unsigned", "const", "volatile",
                         "restrict", "_Atomic", "static", "extern",
                         "register", "auto", "inline", "_Noreturn",
                         "typedef", "*"}:
                prev_sign = None

    # ── Diagnostic helper ────────────────────────────────────────────

    def _diag(
        self,
        rule: WellFormednessRule,
        severity: str,
        message: str,
        file: str,
        line: int,
        column: int,
    ) -> None:
        self.diagnostics.append(WellFormednessDiagnostic(
            rule=rule,
            severity=severity,
            message=message,
            file=file,
            line=line,
            column=column,
        ))


# ═════════════════════════════════════════════════════════════════════════
#  PART 9 — USUAL ARITHMETIC CONVERSIONS  (C11 §6.3.1.8)
# ═════════════════════════════════════════════════════════════════════════
#
#  When two arithmetic operands meet in a binary operator, C performs
#  the "usual arithmetic conversions" to find a common type.
#  We implement this for diagnostic enrichment.
# ═════════════════════════════════════════════════════════════════════════

def usual_arithmetic_conversions(a: CType, b: CType) -> CType:
    """
    Compute the common type after C's usual arithmetic conversions.

    C11 §6.3.1.8:
      1. If either is long double → long double
      2. If either is double → double
      3. If either is float → float
      4. Integer promotions on both, then:
         a. Same type → that type
         b. Same sign → higher rank
         c. Unsigned rank ≥ signed rank → unsigned type
         d. Signed type can represent all unsigned values → signed type
         e. Otherwise → unsigned version of signed type
    """
    ua = a.unqualified
    ub = b.unqualified

    # Step 1-3: floating point
    if ua.kind == TypeKind.LONG_DOUBLE or ub.kind == TypeKind.LONG_DOUBLE:
        return CType.long_double_type()
    if ua.kind == TypeKind.DOUBLE or ub.kind == TypeKind.DOUBLE:
        return CType.double_type()
    if ua.kind == TypeKind.FLOAT or ub.kind == TypeKind.FLOAT:
        return CType.float_type()

    # Step 4: integer promotions
    pa = _integer_promote(ua)
    pb = _integer_promote(ub)

    if pa.kind == pb.kind:
        return pa

    pa_signed = pa.sign != "unsigned"
    pb_signed = pb.sign != "unsigned"

    if pa_signed == pb_signed:
        # Same signedness → higher rank
        if pa.integer_rank >= pb.integer_rank:
            return pa
        return pb

    # Different signedness
    if not pa_signed:  # pa is unsigned
        unsigned, signed_ = pa, pb
    else:
        unsigned, signed_ = pb, pa

    if unsigned.integer_rank >= signed_.integer_rank:
        return unsigned

    # Can signed represent all unsigned values?
    # Simplified: if signed has strictly higher rank, yes
    if signed_.integer_rank > unsigned.integer_rank:
        return signed_

    # Otherwise: unsigned version of signed type
    _TO_UNSIGNED: Dict[TypeKind, TypeKind] = {
        TypeKind.SHORT: TypeKind.USHORT,
        TypeKind.INT: TypeKind.UINT,
        TypeKind.LONG: TypeKind.ULONG,
        TypeKind.LONG_LONG: TypeKind.ULONG_LONG,
    }
    unsigned_kind = _TO_UNSIGNED.get(signed_.kind, TypeKind.UINT)
    return CType(kind=unsigned_kind, sign="unsigned")


def _integer_promote(t: CType) -> CType:
    """
    C11 §6.3.1.1: Integer promotion.

    Types with rank < int are promoted to int (or unsigned int if
    the original type's range doesn't fit in int).
    """
    if t.integer_rank < CType._INTEGER_RANK.get(TypeKind.INT, 3):
        # Promote to int (simplified: assume int can hold all smaller types)
        return CType.int_type()
    return t


# ═════════════════════════════════════════════════════════════════════════
#  PART 10 — TOP-LEVEL ANALYSIS API
# ═════════════════════════════════════════════════════════════════════════

@dataclass
class TypeAnalysisResults:
    """
    Complete results of type analysis on a configuration.

    Attributes
    ----------
    constraints          : list of generated TypeConstraints
    unification_errors   : list from the union-find solver
    type_diagnostics     : list of post-unification type errors
    wellformedness_diags : list of C standard well-formedness violations
    env                  : the solved TypeEnvironment
    uf                   : the UnionFind (for querying resolved types)
    """
    constraints: List[TypeConstraint]
    unification_errors: List[UnificationError]
    type_diagnostics: List[TypeDiagnostic]
    wellformedness_diags: List[WellFormednessDiagnostic]
    env: TypeEnvironment
    uf: UnionFind

    @property
    def all_errors(self) -> List[str]:
        """Flat list of all error messages."""
        errors: List[str] = []
        for e in self.unification_errors:
            errors.append(f"[unification] {e.message} ({e.file}:{e.line})")
        for d in self.type_diagnostics:
            if d.severity == "error":
                errors.append(f"[type] {d.message} ({d.file}:{d.line})")
        for w in self.wellformedness_diags:
            if w.severity == "error":
                errors.append(f"[wellformed] {w.message} ({w.file}:{w.line})")
        return errors

    @property
    def all_warnings(self) -> List[str]:
        """Flat list of all warning messages."""
        warnings: List[str] = []
        for d in self.type_diagnostics:
            if d.severity == "warning":
                warnings.append(f"[type] {d.message} ({d.file}:{d.line})")
        for w in self.wellformedness_diags:
            if w.severity == "warning":
                warnings.append(
                    f"[wellformed] {w.message} ({w.file}:{w.line})")
        return warnings

    @property
    def is_well_typed(self) -> bool:
        """True if no type errors were found."""
        return len(self.all_errors) == 0

    def type_of_var(self, var_id: int) -> CType:
        """Get the resolved type of a variable."""
        return self.uf.resolve(self.env.get_var_type(var_id))

    def type_of_expr(self, token_id: str) -> CType:
        """Get the resolved type of an expression."""
        return self.uf.resolve(self.env.get_expr_type(token_id))


class TypeAnalysis:
    """
    Top-level type analysis for a cppcheck Configuration.

    Combines constraint generation, unification, post-checks, and
    well-formedness checking into a single API.

    Usage
    -----
    >>> from cppcheckdata import parsedump
    >>> from cppcheckdata_shims.type_analysis import TypeAnalysis
    >>>
    >>> data = parsedump("example.c.dump")
    >>> for cfg in data.configurations:
    ...     ta = TypeAnalysis(cfg)
    ...     results = ta.run()
    ...     if not results.is_well_typed:
    ...         for err in results.all_errors:
    ...             print(err)
    ...     # Query resolved types:
    ...     resolved = results.type_of_var(some_var_id)
    ...     print(f"Variable type: {resolved}")
    """

    def __init__(self, configuration: Any) -> None:
        self.cfg = configuration

    def run(self) -> TypeAnalysisResults:
        """
        Run the full type analysis pipeline.

        Returns
        -------
        TypeAnalysisResults with all diagnostics and resolved types.
        """
        # Phase 1: Generate constraints
        gen = ConstraintGenerator(self.cfg)
        gen.generate()

        # Phase 2: Solve via unification
        solver = ConstraintSolver(gen.constraints, gen.env)
        solver.solve()

        # Phase 3: Well-formedness checks
        wf = WellFormednessChecker(self.cfg, gen.env, solver.uf)
        wf.check()

        return TypeAnalysisResults(
            constraints=gen.constraints,
            unification_errors=solver.uf.errors,
            type_diagnostics=solver.diagnostics,
            wellformedness_diags=wf.diagnostics,
            env=gen.env,
            uf=solver.uf,
        )


# ═════════════════════════════════════════════════════════════════════════
#  PART 11 — PUBLIC API
# ═════════════════════════════════════════════════════════════════════════

__all__ = [
    # Type representation
    "CType",
    "TypeKind",
    "Qualifier",
    # Union-Find
    "UnionFind",
    "UnificationError",
    # Constraints
    "TypeConstraint",
    "ConstraintKind",
    "ConstraintGenerator",
    "ConstraintSolver",
    # Environment
    "TypeEnvironment",
    # Well-formedness
    "WellFormednessChecker",
    "WellFormednessRule",
    "WellFormednessDiagnostic",
    # Conversions
    "valuetype_to_ctype",
    "usual_arithmetic_conversions",
    # Top-level
    "TypeAnalysis",
    "TypeAnalysisResults",
    "TypeDiagnostic",
]
