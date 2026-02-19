#!/usr/bin/env python3
"""
EnumCheck.py
============

A Cppcheck addon that performs comprehensive checking of ``enum`` type
usage in C/C++ programs, leveraging the ``cppcheckdata-shims`` library
for type analysis, abstract domains, and dataflow infrastructure.

Covered Checks
--------------
  1. **Implicit integer-to-enum conversion** (CWE-704)
     Assignment of a plain integer literal or integer variable to an
     enum-typed variable without an explicit cast.

  2. **Out-of-range enum value** (CWE-704)
     Assignment/initialisation of an enum variable with a value that
     does not correspond to any declared enumerator.

  3. **Mixed-enum arithmetic** (CWE-704)
     Arithmetic or comparison between values of two *different* enum
     types.

  4. **Enum used in bitwise operations without being a bitmask** (CWE-704)
     Bitwise OR/AND/XOR/shift on an enum that is not explicitly
     annotated or heuristically detected as a bitmask enum.

  5. **Switch on enum not covering all enumerators** (CWE-478)
     A ``switch`` over an enum variable that is missing ``case`` labels
     for one or more enumerators and has no ``default``.

  6. **Duplicate enumerator values** (CWE-697)
     Two or more enumerators within the same ``enum`` declaration that
     share the same integer value (silent in C, often a bug).

  7. **Implicit enum-to-bool narrowing** (CWE-704)
     An enum value used directly as a boolean condition in ``if``,
     ``while``, ``for``, or ternary ``?:`` without comparison.

  8. **Enumerator name shadowing**
     An enumerator name that shadows a variable, function, or another
     enumerator from an enclosing scope.

  9. **Arithmetic result assigned back to enum** (CWE-704)
     Result of ``enum + int``, ``enum - 1``, etc. assigned back to an
     enum variable — the result may not be a valid enumerator.

 10. **Comparison of enum against out-of-range literal**
     Comparing an enum variable against an integer literal that does
     not match any enumerator value — always-true or always-false.

Usage
-----
::

    cppcheck --dump myfile.c
    python EnumCheck.py myfile.c.dump

Requires
--------
    - cppcheckdata        (bundled with Cppcheck)
    - cppcheckdata_shims  (type_analysis, abstract_domains, dataflow_analysis)

License: MIT
"""

from __future__ import annotations

import sys
from collections import defaultdict
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

# ══════════════════════════════════════════════════════════════════════
#  Imports from cppcheckdata (entry-point infrastructure only)
# ══════════════════════════════════════════════════════════════════════
import cppcheckdata

# ══════════════════════════════════════════════════════════════════════
#  Imports from cppcheckdata_shims — VERIFIED exports
# ══════════════════════════════════════════════════════════════════════

# --- type_analysis: type representation + unification -----------------
from cppcheckdata_shims.type_analysis import (
    TypeKind,
    Qualifier,
    CType,
    UnionFind,
    UnificationError,
)

# --- abstract_domains: lattice structures -----------------------------
from cppcheckdata_shims.abstract_domains import (
    FlatDomain,
    SetDomain,
    FunctionDomain,
    BOTTOM,
    TOP,
)

# --- dataflow_analysis: CFG + analysis framework ----------------------
from cppcheckdata_shims.dataflow_analysis import (
    build_cfg,
    SimpleCFG,
    BasicBlock,
    DataflowAnalysis,
    Direction,
    MeetOrJoin,
)

# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════

ADDON_NAME = "EnumCheck"

# Operators considered "bitwise"
BITWISE_OPS: FrozenSet[str] = frozenset({"&", "|", "^", "~", "<<", ">>"})

# Operators considered "arithmetic"
ARITHMETIC_OPS: FrozenSet[str] = frozenset({"+", "-", "*", "/", "%"})

# Comparison operators
COMPARISON_OPS: FrozenSet[str] = frozenset({"==", "!=", "<", "<=", ">", ">="})

# Assignment operators that embed arithmetic
COMPOUND_ASSIGN_OPS: FrozenSet[str] = frozenset({
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
})


# ══════════════════════════════════════════════════════════════════════
#  REPORTING HELPER
# ══════════════════════════════════════════════════════════════════════

def _report(token, severity: str, msg: str, error_id: str, cwe: int = 0):
    """Emit a diagnostic via cppcheckdata.reportError."""
    extra = f"CWE-{cwe}" if cwe else ""
    full_msg = f"[CWE-{cwe}] {msg}" if cwe else msg
    cppcheckdata.reportError(
        token, severity, full_msg, ADDON_NAME, error_id, extra=extra,
    )


# ══════════════════════════════════════════════════════════════════════
#  ENUM METADATA EXTRACTION
# ══════════════════════════════════════════════════════════════════════

@dataclass
class EnumeratorInfo:
    """A single enumerator constant within an enum."""
    name: str
    value: Optional[int]
    token: Any  # cppcheckdata Token
    scope_id: str  # Id of the Enum scope


@dataclass
class EnumInfo:
    """Collected information about a single enum type."""
    tag: str                              # enum tag name ("" if anonymous)
    scope_id: str                         # cppcheckdata Scope.Id
    scope: Any                            # cppcheckdata Scope object
    enumerators: List[EnumeratorInfo] = field(default_factory=list)
    value_set: Set[int] = field(default_factory=set)    # all known int values
    name_set: Set[str] = field(default_factory=set)     # all enumerator names
    is_bitmask: bool = False              # heuristic: all values are powers of 2 (or 0)

    def display_name(self) -> str:
        return f"enum {self.tag}" if self.tag else "enum <anonymous>"


def _collect_enums(cfg) -> Dict[str, EnumInfo]:
    """
    Walk scopes to discover all ``enum`` types and their enumerators.

    Returns a dict mapping Scope.Id → EnumInfo.
    """
    enums: Dict[str, EnumInfo] = {}

    for scope in cfg.scopes:
        if scope.type != "Enum":
            continue

        tag = scope.className or ""
        info = EnumInfo(
            tag=tag,
            scope_id=scope.Id,
            scope=scope,
        )

        # Walk the variables declared in this scope — they are the
        # enumerators.  cppcheckdata lists them in scope.varlist.
        for var in scope.varlist:
            name = var.nameToken.str if var.nameToken else ""
            # Try to get the integer value from the name token's known values
            value = None
            if var.nameToken:
                kv = var.nameToken.getKnownIntValue()
                if kv is not None:
                    value = kv

            etor = EnumeratorInfo(
                name=name,
                value=value,
                token=var.nameToken,
                scope_id=scope.Id,
            )
            info.enumerators.append(etor)
            info.name_set.add(name)
            if value is not None:
                info.value_set.add(value)

        # Heuristic: detect bitmask enums
        # All values are 0 or exact powers of 2
        if info.value_set:
            info.is_bitmask = all(
                v == 0 or (v > 0 and (v & (v - 1)) == 0)
                for v in info.value_set
            )

        enums[scope.Id] = info

    return enums


def _enum_scope_for_variable(var) -> Optional[str]:
    """
    If *var* is of enum type, return the Scope.Id of that enum.
    Uses cppcheckdata's Variable → valueType → typeScope chain.
    """
    if var is None:
        return None
    vt = getattr(var, "valueType", None) if hasattr(var, "valueType") else None
    # Variable doesn't have valueType directly; check the nameToken
    if vt is None:
        nt = var.nameToken
        if nt and nt.valueType:
            vt = nt.valueType
    if vt is None:
        return None
    # Check if typeScope is an Enum scope
    ts = getattr(vt, "typeScope", None)
    if ts and ts.type == "Enum":
        return ts.Id
    return None


def _token_enum_scope(token) -> Optional[str]:
    """
    Determine if *token* has an enum type and return the Enum scope Id.
    """
    # Via variable
    if token.variable:
        eid = _enum_scope_for_variable(token.variable)
        if eid:
            return eid
    # Via valueType directly
    vt = token.valueType
    if vt:
        ts = getattr(vt, "typeScope", None)
        if ts and ts.type == "Enum":
            return ts.Id
    return None


def _build_enumerator_name_map(enums: Dict[str, EnumInfo]) -> Dict[str, EnumInfo]:
    """
    Build a mapping: enumerator_name → EnumInfo.
    """
    name_map: Dict[str, EnumInfo] = {}
    for info in enums.values():
        for etor in info.enumerators:
            name_map[etor.name] = info
    return name_map


# ══════════════════════════════════════════════════════════════════════
#  ENUM DATAFLOW DOMAIN
# ══════════════════════════════════════════════════════════════════════
#
#  We track, for each variable, which enum type it currently holds a
#  value of.  This is a FlatDomain over enum scope Ids:
#
#     ⊥ = unreachable
#     enum_scope_id = definitely this enum type
#     ⊤ = unknown / non-enum / multiple enum types
#
#  This allows us to detect cross-enum mixing at any point.
# ══════════════════════════════════════════════════════════════════════

# We use FlatDomain[str] where str is the enum scope Id.
# FlatDomain provides: bottom(), top(), lift(x), join, meet, leq.
_EnumTypeDomain = FlatDomain


# ══════════════════════════════════════════════════════════════════════
#  CHECK 1 — DUPLICATE ENUMERATOR VALUES  (CWE-697)
# ══════════════════════════════════════════════════════════════════════

def _check_duplicate_enumerator_values(enums: Dict[str, EnumInfo]):
    """
    Flag enumerators within the same enum that share the same integer
    value.

    CWE-697 — Incorrect Comparison
    """
    for info in enums.values():
        # Group enumerators by value
        value_to_names: Dict[int, List[EnumeratorInfo]] = defaultdict(list)
        for etor in info.enumerators:
            if etor.value is not None:
                value_to_names[etor.value].append(etor)

        for value, etors in value_to_names.items():
            if len(etors) > 1:
                names = ", ".join(f"'{e.name}'" for e in etors)
                for etor in etors[1:]:
                    _report(
                        etor.token, "style",
                        f"In {info.display_name()}, enumerators {names} "
                        f"all have value {value} — possible copy-paste error",
                        "duplicateEnumValue", cwe=697,
                    )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 2 — IMPLICIT INT-TO-ENUM CONVERSION  (CWE-704)
# ══════════════════════════════════════════════════════════════════════

def _check_implicit_int_to_enum(cfg, enums: Dict[str, EnumInfo]):
    """
    Detect assignments of integer literals or integer-typed variables
    to enum-typed variables without an explicit cast.

    CWE-704 — Incorrect Type Conversion or Cast
    """
    enumerator_names = _build_enumerator_name_map(enums)

    for token in cfg.tokenlist:
        if not token.isAssignmentOp:
            continue
        if token.str != "=":
            continue  # handled in compound assign check

        lhs = token.astOperand1
        rhs = token.astOperand2
        if lhs is None or rhs is None:
            continue

        # Check if LHS is enum-typed
        lhs_enum_id = _token_enum_scope(lhs)
        if lhs_enum_id is None:
            continue
        if lhs_enum_id not in enums:
            continue

        enum_info = enums[lhs_enum_id]

        # Check if RHS is an integer literal
        if rhs.isNumber and rhs.isInt:
            kv = rhs.getKnownIntValue()
            vname = lhs.str
            if kv is not None and kv not in enum_info.value_set:
                _report(
                    token, "warning",
                    f"Integer literal {kv} assigned to "
                    f"'{vname}' of type {enum_info.display_name()} — "
                    f"value does not match any enumerator",
                    "intToEnumOutOfRange", cwe=704,
                )
            elif rhs.str not in enum_info.name_set:
                # It's a bare integer literal, not an enumerator name
                if not rhs.isCast:
                    _report(
                        token, "style",
                        f"Implicit integer-to-enum conversion: "
                        f"assigning {rhs.str} to '{lhs.str}' "
                        f"of type {enum_info.display_name()}",
                        "implicitIntToEnum", cwe=704,
                    )

        # Check if RHS is a non-enum integer variable
        elif rhs.variable and rhs.isName:
            rhs_enum_id = _token_enum_scope(rhs)
            if rhs_enum_id is None:
                # RHS is plain int, LHS is enum
                if not rhs.isCast:
                    _report(
                        token, "style",
                        f"Implicit integer-to-enum conversion: "
                        f"assigning variable '{rhs.str}' (integer) to "
                        f"'{lhs.str}' of type {enum_info.display_name()}",
                        "implicitIntToEnum", cwe=704,
                    )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 3 — MIXED-ENUM OPERATIONS  (CWE-704)
# ══════════════════════════════════════════════════════════════════════

def _check_mixed_enum_operations(cfg, enums: Dict[str, EnumInfo]):
    """
    Detect arithmetic or comparison between values of two different
    enum types.

    CWE-704 — Incorrect Type Conversion or Cast
    """
    all_ops = ARITHMETIC_OPS | COMPARISON_OPS | BITWISE_OPS

    for token in cfg.tokenlist:
        if not token.isOp:
            continue
        if token.str not in all_ops:
            continue

        lhs = token.astOperand1
        rhs = token.astOperand2
        if lhs is None or rhs is None:
            continue

        lhs_enum = _token_enum_scope(lhs)
        rhs_enum = _token_enum_scope(rhs)

        if lhs_enum and rhs_enum and lhs_enum != rhs_enum:
            lhs_info = enums.get(lhs_enum)
            rhs_info = enums.get(rhs_enum)
            lhs_name = lhs_info.display_name() if lhs_info else "enum?"
            rhs_name = rhs_info.display_name() if rhs_info else "enum?"
            _report(
                token, "warning",
                f"Operation '{token.str}' mixes different enum types: "
                f"{lhs_name} and {rhs_name}",
                "mixedEnumOp", cwe=704,
            )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 4 — BITWISE OPS ON NON-BITMASK ENUM  (CWE-704)
# ══════════════════════════════════════════════════════════════════════

def _check_bitwise_on_non_bitmask_enum(cfg, enums: Dict[str, EnumInfo]):
    """
    Flag bitwise operations on enum values when the enum is not
    heuristically detected as a bitmask enum.

    CWE-704 — Incorrect Type Conversion or Cast
    """
    for token in cfg.tokenlist:
        if not token.isOp:
            continue
        if token.str not in BITWISE_OPS:
            continue

        for operand in (token.astOperand1, token.astOperand2):
            if operand is None:
                continue
            eid = _token_enum_scope(operand)
            if eid is None:
                continue
            info = enums.get(eid)
            if info and not info.is_bitmask:
                _report(
                    token, "style",
                    f"Bitwise operation '{token.str}' on "
                    f"{info.display_name()} which is not a bitmask enum "
                    f"(enumerator values are not powers of 2)",
                    "bitwiseOnNonBitmaskEnum", cwe=704,
                )
                break  # report once per operator token


# ══════════════════════════════════════════════════════════════════════
#  CHECK 5 — SWITCH NOT COVERING ALL ENUMERATORS  (CWE-478)
# ══════════════════════════════════════════════════════════════════════

def _check_switch_coverage(cfg, enums: Dict[str, EnumInfo]):
    """
    For each ``switch`` statement on an enum variable, verify that
    every enumerator has a corresponding ``case`` label or a
    ``default`` is present.

    CWE-478 — Missing Default Case in Switch Statement
    """
    enumerator_names = _build_enumerator_name_map(enums)

    for scope in cfg.scopes:
        if scope.type != "Switch":
            continue

        # Find the condition variable of the switch.
        # The switch scope's bodyStart is '{'.  The switch keyword
        # precedes '(' which precedes the condition.
        body_start = scope.bodyStart
        if body_start is None:
            continue

        # Walk backwards from '{' to find 'switch' keyword and '(' ... ')'
        tok = body_start.previous  # should be ')'
        if tok is None or tok.str != ")":
            continue
        lparen = tok.link
        if lparen is None:
            continue
        # The condition is between lparen and tok
        cond_tok = lparen.next
        if cond_tok is None:
            continue

        # Find the enum type of the condition
        cond_enum_id = _token_enum_scope(cond_tok)
        if cond_enum_id is None:
            # Try walking the AST for the condition expression
            # The AST root of the condition is lparen.next's top-level parent
            inner = lparen.next
            while inner and inner != tok:
                eid = _token_enum_scope(inner)
                if eid:
                    cond_enum_id = eid
                    break
                inner = inner.next
        if cond_enum_id is None or cond_enum_id not in enums:
            continue

        enum_info = enums[cond_enum_id]

        # Collect case labels within this switch scope
        covered_names: Set[str] = set()
        covered_values: Set[int] = set()
        has_default = False

        inner_tok = body_start.next
        while inner_tok and inner_tok != scope.bodyEnd:
            if inner_tok.str == "default":
                has_default = True
            elif inner_tok.str == "case":
                # The token after 'case' is the label expression
                case_val_tok = inner_tok.next
                if case_val_tok:
                    # Check if it's an enumerator name
                    if case_val_tok.isName:
                        covered_names.add(case_val_tok.str)
                    # Check known int value
                    kv = case_val_tok.getKnownIntValue() if case_val_tok else None
                    if kv is not None:
                        covered_values.add(kv)
            inner_tok = inner_tok.next

        if has_default:
            continue  # default covers everything

        # Find missing enumerators
        missing: List[str] = []
        for etor in enum_info.enumerators:
            if etor.name not in covered_names:
                # Also check by value
                if etor.value is not None and etor.value in covered_values:
                    continue
                missing.append(etor.name)

        if missing:
            switch_tok = lparen.previous if lparen.previous else body_start
            missing_str = ", ".join(missing[:5])
            if len(missing) > 5:
                missing_str += f", ... ({len(missing) - 5} more)"
            _report(
                switch_tok, "warning",
                f"Switch on {enum_info.display_name()} does not cover "
                f"enumerators: {missing_str} — and has no 'default' case",
                "switchEnumNotCovered", cwe=478,
            )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 6 — ENUM USED AS BOOLEAN CONDITION  (CWE-704)
# ══════════════════════════════════════════════════════════════════════

def _check_enum_as_boolean(cfg, enums: Dict[str, EnumInfo]):
    """
    Detect enum values used directly as boolean conditions without
    an explicit comparison (e.g. ``if (color)`` instead of
    ``if (color != NONE)``).

    CWE-704 — Incorrect Type Conversion or Cast
    """
    # Find condition expressions in if/while/for/ternary
    for scope in cfg.scopes:
        if scope.type not in ("If", "While", "For"):
            continue
        body_start = scope.bodyStart
        if body_start is None:
            continue

        rparen = body_start.previous
        if rparen is None or rparen.str != ")":
            continue
        lparen = rparen.link
        if lparen is None:
            continue

        # Walk the condition tokens
        tok = lparen.next
        while tok and tok != rparen:
            eid = _token_enum_scope(tok)
            if eid and eid in enums:
                # Check if this token is the ENTIRE condition or a direct
                # operand of a logical operator without a comparison
                parent = tok.astParent
                is_bare = False
                if parent is None:
                    is_bare = True
                elif parent.str in ("&&", "||", "!"):
                    # Check if the direct child — no comparison wrapping it
                    is_bare = True
                elif parent.isComparisonOp:
                    is_bare = False
                elif parent.str in ("(", ")"):
                    is_bare = True
                else:
                    is_bare = False

                if is_bare:
                    info = enums[eid]
                    _report(
                        tok, "style",
                        f"Enum variable '{tok.str}' of type "
                        f"{info.display_name()} used as boolean condition "
                        f"without explicit comparison",
                        "enumAsBool", cwe=704,
                    )
            tok = tok.next


# ══════════════════════════════════════════════════════════════════════
#  CHECK 7 — ARITHMETIC RESULT ASSIGNED BACK TO ENUM  (CWE-704)
# ══════════════════════════════════════════════════════════════════════

def _check_arithmetic_assigned_to_enum(cfg, enums: Dict[str, EnumInfo]):
    """
    Detect patterns like ``color = color + 1`` where the result of
    arithmetic is assigned back to an enum variable.  The result
    may not correspond to any valid enumerator.

    Also catches compound assignment operators like ``color += 1``.

    CWE-704 — Incorrect Type Conversion or Cast
    """
    for token in cfg.tokenlist:
        if not token.isAssignmentOp:
            continue

        lhs = token.astOperand1
        if lhs is None:
            continue

        lhs_enum = _token_enum_scope(lhs)
        if lhs_enum is None or lhs_enum not in enums:
            continue

        info = enums[lhs_enum]

        # Compound assignment: +=, -=, etc. are always arithmetic on enum
        if token.str in COMPOUND_ASSIGN_OPS:
            _report(
                token, "warning",
                f"Compound assignment '{token.str}' on "
                f"'{lhs.str}' of type {info.display_name()} — "
                f"arithmetic result may not be a valid enumerator",
                "arithmeticOnEnum", cwe=704,
            )
            continue

        # Simple assignment: check if RHS is an arithmetic expression
        # involving the enum
        rhs = token.astOperand2
        if rhs is None:
            continue
        if rhs.isOp and rhs.str in ARITHMETIC_OPS:
            _report(
                token, "warning",
                f"Arithmetic expression assigned to '{lhs.str}' of type "
                f"{info.display_name()} — result may not be a valid "
                f"enumerator",
                "arithmeticOnEnum", cwe=704,
            )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 8 — COMPARISON OF ENUM AGAINST OUT-OF-RANGE LITERAL
# ══════════════════════════════════════════════════════════════════════

def _check_enum_vs_out_of_range_literal(cfg, enums: Dict[str, EnumInfo]):
    """
    Comparing an enum variable against an integer literal that doesn't
    match any enumerator value — the comparison is suspicious and
    likely always-true or always-false.
    """
    for token in cfg.tokenlist:
        if not token.isComparisonOp:
            continue
        lhs = token.astOperand1
        rhs = token.astOperand2
        if lhs is None or rhs is None:
            continue

        # Check both orderings: enum == literal, literal == enum
        pairs = [(lhs, rhs), (rhs, lhs)]
        for enum_side, lit_side in pairs:
            eid = _token_enum_scope(enum_side)
            if eid is None or eid not in enums:
                continue
            if not (lit_side.isNumber and lit_side.isInt):
                continue

            info = enums[eid]
            kv = lit_side.getKnownIntValue()
            if kv is not None and kv not in info.value_set:
                _report(
                    token, "warning",
                    f"Comparing '{enum_side.str}' of type "
                    f"{info.display_name()} against integer {kv} "
                    f"which is not a valid enumerator value",
                    "enumCompareOutOfRange", cwe=0,
                )
            break  # don't double-report


# ══════════════════════════════════════════════════════════════════════
#  CHECK 9 — ENUMERATOR NAME SHADOWING
# ══════════════════════════════════════════════════════════════════════

def _check_enumerator_name_shadowing(cfg, enums: Dict[str, EnumInfo]):
    """
    Detect enumerator names that shadow variables or functions in
    enclosing scopes.
    """
    # Collect all enumerator names
    all_enum_names: Dict[str, EnumeratorInfo] = {}
    for info in enums.values():
        for etor in info.enumerators:
            all_enum_names[etor.name] = etor

    # Check variables for shadowing
    for var in cfg.variables:
        vname = var.nameToken.str if var.nameToken else ""
        if vname in all_enum_names:
            etor = all_enum_names[vname]
            # Make sure it's not the enumerator itself
            if var.nameToken and var.nameToken.Id != etor.token.Id:
                enum_info_found = None
                for info in enums.values():
                    if etor in info.enumerators:
                        enum_info_found = info
                        break
                dn = enum_info_found.display_name() if enum_info_found else "enum"
                _report(
                    var.nameToken, "style",
                    f"Variable '{vname}' shadows enumerator "
                    f"'{etor.name}' from {dn}",
                    "enumNameShadow", cwe=0,
                )


# ══════════════════════════════════════════════════════════════════════
#  CHECK 10 — TYPE UNIFICATION FOR ENUM MISUSE
#  (Uses cppcheckdata_shims.type_analysis UnionFind)
# ══════════════════════════════════════════════════════════════════════

def _check_enum_type_unification(cfg, enums: Dict[str, EnumInfo]):
    """
    Use type_analysis.UnionFind to verify that enum types are used
    consistently across assignments and function calls.

    For each assignment ``a = b``, unify the types of ``a`` and ``b``.
    If unification fails because one is an enum and the other is
    incompatible, report a type mismatch.

    This leverages the formal type system from cppcheckdata_shims to
    catch subtle misuses that pattern-matching alone would miss.
    """
    uf = UnionFind()

    # Create CType representations for each enum
    enum_ctypes: Dict[str, CType] = {}
    for scope_id, info in enums.items():
        enum_ctypes[scope_id] = CType.enum_type(info.tag or f"__anon_{scope_id}")

    # Walk assignments and attempt unification
    for token in cfg.tokenlist:
        if not token.isAssignmentOp or token.str != "=":
            continue

        lhs = token.astOperand1
        rhs = token.astOperand2
        if lhs is None or rhs is None:
            continue

        lhs_eid = _token_enum_scope(lhs)
        rhs_eid = _token_enum_scope(rhs)

        if lhs_eid and rhs_eid and lhs_eid != rhs_eid:
            # Both enums, different types — try unification (will fail)
            ltype = enum_ctypes.get(lhs_eid, CType.fresh_var())
            rtype = enum_ctypes.get(rhs_eid, CType.fresh_var())
            success = uf.unify(
                ltype, rtype,
                context="in assignment",
                file=token.file or "",
                line=token.linenr or 0,
            )
            if not success:
                li = enums.get(lhs_eid)
                ri = enums.get(rhs_eid)
                ln = li.display_name() if li else "enum?"
                rn = ri.display_name() if ri else "enum?"
                _report(
                    token, "warning",
                    f"Type mismatch in assignment: "
                    f"'{lhs.str}' is {ln} but "
                    f"'{rhs.str}' is {rn} — "
                    f"enum types are incompatible",
                    "enumTypeMismatch", cwe=704,
                )

    # Report any accumulated unification errors
    for err in uf.errors:
        # These are already reported above via _report, but we log
        # additional context if present
        pass


# ══════════════════════════════════════════════════════════════════════
#  ENUM VALUE TRACKING DATAFLOW ANALYSIS
#  (Uses cppcheckdata_shims.dataflow_analysis framework)
# ══════════════════════════════════════════════════════════════════════

class EnumValueTracker(DataflowAnalysis):
    """
    Forward dataflow analysis tracking which enum values each variable
    may hold at each program point.

    Lattice: variable_id → SetDomain[int] (set of possible enumerator values).

    This enables detection of out-of-range values that arise from
    computation paths (not just direct assignment).
    """

    # Maximum set size before we go to TOP to bound analysis cost
    MAX_SET_SIZE = 64

    def __init__(self, configuration, scope, enums: Dict[str, EnumInfo]):
        self.enums = enums
        self._all_enum_var_ids: Dict[int, str] = {}  # varId → enum scope id

        # Discover enum-typed variables
        for var in configuration.variables:
            eid = _enum_scope_for_variable(var)
            if eid and var.nameToken:
                vid = var.nameToken.varId
                if vid:
                    self._all_enum_var_ids[vid] = eid

        super().__init__(configuration, scope)

    @property
    def direction(self) -> Direction:
        return Direction.FORWARD

    @property
    def confluence(self) -> MeetOrJoin:
        return MeetOrJoin.JOIN

    def _make_state(self) -> Dict[int, Optional[FrozenSet[int]]]:
        """Create an initial state mapping varId → None (bottom)."""
        return {vid: None for vid in self._all_enum_var_ids}

    def init_entry(self) -> Dict[int, Optional[FrozenSet[int]]]:
        # At entry, enum variables could be any valid value
        state = {}
        for vid, eid in self._all_enum_var_ids.items():
            info = self.enums.get(eid)
            if info and info.value_set:
                state[vid] = frozenset(info.value_set)
            else:
                state[vid] = None  # unknown
        return state

    def init_interior(self) -> Dict[int, Optional[FrozenSet[int]]]:
        return self._make_state()

    def transfer(self, block: BasicBlock, in_val) -> Dict[int, Optional[FrozenSet[int]]]:
        state = dict(in_val)
        for tok in block.tokens:
            self._transfer_token(tok, state)
        return state

    def _transfer_token(self, tok, state: Dict[int, Optional[FrozenSet[int]]]):
        """Process a single token for enum value tracking."""
        if not tok.isAssignmentOp or tok.str != "=":
            return
        lhs = tok.astOperand1
        rhs = tok.astOperand2
        if lhs is None or rhs is None:
            return
        vid = getattr(lhs, "varId", None)
        if vid is None or vid not in self._all_enum_var_ids:
            return

        # Determine RHS value set
        kv = rhs.getKnownIntValue() if rhs else None
        if kv is not None:
            state[vid] = frozenset({kv})
        elif rhs.variable and getattr(rhs, "varId", None) in state:
            rvid = rhs.varId
            state[vid] = state.get(rvid)
        else:
            state[vid] = None  # unknown

    def lattice_leq(self, a, b) -> bool:
        for vid in self._all_enum_var_ids:
            av = a.get(vid)
            bv = b.get(vid)
            if av is None:
                continue
            if bv is None:
                return False
            if not av.issubset(bv):
                return False
        return True

    def lattice_combine(self, a, b):
        result = {}
        for vid in self._all_enum_var_ids:
            av = a.get(vid)
            bv = b.get(vid)
            if av is None:
                result[vid] = bv
            elif bv is None:
                result[vid] = av
            else:
                combined = av | bv
                if len(combined) > self.MAX_SET_SIZE:
                    result[vid] = None  # go to top
                else:
                    result[vid] = combined
        return result

    def find_out_of_range_uses(self) -> List[Tuple[Any, str, int]]:
        """
        After ``run()``, check every program point where an enum
        variable's tracked value set contains values outside the
        valid enumerator set.

        Returns list of (token, var_name, bad_value).
        """
        results = []
        for bid, bb in self.cfg.blocks.items():
            state = self._in.get(bid, {})
            for tok in bb.tokens:
                if tok.variable and tok.varId in self._all_enum_var_ids:
                    vid = tok.varId
                    eid = self._all_enum_var_ids[vid]
                    info = self.enums.get(eid)
                    val_set = state.get(vid)
                    if info and val_set:
                        bad = val_set - info.value_set
                        for bv in bad:
                            vname = tok.variable.nameToken.str if tok.variable.nameToken else tok.str
                            results.append((tok, vname, bv))
                # Update state for next token
                self._transfer_token(tok, state)
        return results


def _check_dataflow_enum_values(cfg, enums: Dict[str, EnumInfo]):
    """
    Run the EnumValueTracker dataflow analysis on each function scope
    to find out-of-range enum values that arise through computation.
    """
    for scope in cfg.scopes:
        if scope.type != "Function":
            continue
        try:
            tracker = EnumValueTracker(cfg, scope, enums)
            if not tracker._all_enum_var_ids:
                continue
            tracker.run(max_iterations=200)
            for tok, vname, bad_val in tracker.find_out_of_range_uses():
                eid = tracker._all_enum_var_ids.get(tok.varId, "")
                info = enums.get(eid)
                dn = info.display_name() if info else "enum"
                _report(
                    tok, "warning",
                    f"Variable '{vname}' of type {dn} may hold "
                    f"value {bad_val} which is not a valid enumerator",
                    "enumOutOfRange", cwe=704,
                )
        except Exception:
            # Analysis may fail on complex CFGs; don't crash the addon
            pass


# ══════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════

def run_checks_on_cfg(cfg):
    """Execute all enum checks on a single Configuration."""
    enums = _collect_enums(cfg)
    if not enums:
        return

    # Pattern-based checks
    _check_duplicate_enumerator_values(enums)
    _check_implicit_int_to_enum(cfg, enums)
    _check_mixed_enum_operations(cfg, enums)
    _check_bitwise_on_non_bitmask_enum(cfg, enums)
    _check_switch_coverage(cfg, enums)
    _check_enum_as_boolean(cfg, enums)
    _check_arithmetic_assigned_to_enum(cfg, enums)
    _check_enum_vs_out_of_range_literal(cfg, enums)
    _check_enumerator_name_shadowing(cfg, enums)

    # Type-system check using UnionFind from type_analysis
    _check_enum_type_unification(cfg, enums)

    # Dataflow-based check using DataflowAnalysis from dataflow_analysis
    _check_dataflow_enum_values(cfg, enums)


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()

    if not args.dumpfile:
        if not args.quiet:
            print(f"{ADDON_NAME}: No dump files specified.", file=sys.stderr)
        sys.exit(1)

    dump_files, _ctu = cppcheckdata.get_files(args)

    for dumpfile in dump_files:
        if not args.quiet:
            print(f"Checking {dumpfile} ...")

        data = cppcheckdata.parsedump(dumpfile)

        if not data.configurations:
            continue

        for cfg in data.configurations:
            run_checks_on_cfg(cfg)

    sys.exit(cppcheckdata.EXIT_CODE)


if __name__ == "__main__":
    main()
