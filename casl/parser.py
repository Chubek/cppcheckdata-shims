# casl/parser.py
"""
CASL Parser — Parsimonious grammar + NodeVisitor → AST
"""

from __future__ import annotations

import ast as python_ast
from typing import Optional

from parsimonious.grammar import Grammar
from parsimonious.nodes import NodeVisitor, Node
from parsimonious.exceptions import ParseError, IncompleteParseError

from casl.grammar import CASL_GRAMMAR
from casl.ast_nodes import (
    Loc, Program, AddonDecl, AddonField, ImportStmt, CheckerDecl,
    PatternDecl, QueryDecl, OnBlock, SuppressDecl, FnDecl,
    ConstDecl, TypeAliasDecl, Param,
    Severity, Confidence, OnEvent, AssignOp, UnaryOp, BinOp,
    # Expressions
    Identifier, IntLiteral, FloatLiteral, StringLiteral, BoolLiteral,
    NullLiteral, ListLiteral, MapLiteral, SetLiteral, UnaryExpr,
    BinaryExpr, TernaryExpr, CallExpr, IndexExpr, MemberExpr,
    MethodCallExpr, LambdaExpr, MatchExpr, MatchArm,
    # Patterns
    TokenPattern, ScopePattern, CallPattern, AssignPattern,
    DerefPattern, BinopPattern, WildcardPattern,
    PatternClauseMatch, PatternClauseWhere, PatternClauseEnsures,
    # Statements
    LetStmt, AssignStmt, IfStmt, ForStmt, WhileStmt,
    ReturnStmt, EmitStmt, BreakStmt, ContinueStmt, ExprStmt,
    # Types
    TypeName, TypeGeneric,
)

_grammar = Grammar(CASL_GRAMMAR)


class CASLParseError(Exception):
    """Raised when CASL source cannot be parsed."""
    def __init__(self, message, filename="<string>", line=0, col=0):
        self.filename = filename
        self.line = line
        self.col = col
        super().__init__(f"{filename}:{line}:{col}: {message}")


def _loc(node: Node, filename: str = "<string>") -> Loc:
    """Extract source location from a Parsimonious Node."""
    text = node.full_text
    pos = node.start
    line = text.count('\n', 0, pos) + 1
    last_nl = text.rfind('\n', 0, pos)
    col = pos - last_nl if last_nl >= 0 else pos + 1
    return Loc(file=filename, line=line, col=col)


def _text(node: Node) -> str:
    """Get the matched text of a node."""
    return node.text.strip()


def _unwrap_string(s: str) -> str:
    """Remove surrounding quotes and handle escape sequences."""
    return python_ast.literal_eval(s)


def _collect(node_or_list) -> list:
    """Flatten a node or list of nodes into a flat list, discarding None."""
    if node_or_list is None:
        return []
    if isinstance(node_or_list, list):
        result = []
        for item in node_or_list:
            if item is not None:
                if isinstance(item, list):
                    result.extend(_collect(item))
                else:
                    result.append(item)
        return result
    return [node_or_list]


class CASLVisitor(NodeVisitor):
    """
    Transforms Parsimonious parse tree into CASL AST nodes.

    Parsimonious calls visit_<rule_name>(node, visited_children) for each
    grammar rule. We return our AST dataclass instances from each visitor.
    """

    def __init__(self, filename: str = "<string>"):
        super().__init__()
        self.filename = filename

    def _loc(self, node: Node) -> Loc:
        return _loc(node, self.filename)

    # ── Fallbacks ────────────────────────────────────────────────

    def generic_visit(self, node, visited_children):
        """Default: return children if multiple, single child if one, else node text."""
        children = [c for c in visited_children if c is not None]
        if len(children) == 1:
            return children[0]
        if len(children) == 0:
            return None
        return children

    # ── Program ──────────────────────────────────────────────────

    def visit_program(self, node, visited_children):
        _, preamble, _, items, _ = visited_children
        addon = None
        if preamble:
            addon = preamble[0] if isinstance(preamble, list) else preamble
        all_items = _collect(items)
        return Program(addon=addon, items=all_items, loc=self._loc(node))

    def visit_preamble(self, node, visited_children):
        return visited_children[0]

    # ── Addon Declaration ────────────────────────────────────────

    def visit_addon_decl(self, node, visited_children):
        _, _, name, _, desc_opt, _, _, _, body, _, _ = visited_children
        desc = None
        if desc_opt and isinstance(desc_opt, list) and len(desc_opt) > 0:
            desc = desc_opt[0]
        fields = _collect(body)
        return AddonDecl(
            name=name.name if isinstance(name, Identifier) else str(name),
            description=desc,
            fields=fields,
            loc=self._loc(node),
        )

    def visit_addon_body(self, node, visited_children):
        return _collect(visited_children)

    def visit_addon_field(self, node, visited_children):
        key_node, _, _, _, value, _, _ = visited_children
        key = _text(key_node) if isinstance(key_node, Node) else str(key_node)
        # key_node might be a list from the alternation
        if isinstance(key, list):
            key = key[0]
        if isinstance(key, Node):
            key = key.text.strip()
        return AddonField(key=key, value=value, loc=self._loc(node))

    # ── Import ───────────────────────────────────────────────────

    def visit_import_stmt(self, node, visited_children):
        _, _, path, _, _ = visited_children
        return ImportStmt(path=path, loc=self._loc(node))

    def visit_import_path(self, node, visited_children):
        first = visited_children[0]
        rest = visited_children[1] if len(visited_children) > 1 else []
        parts = [first.name if isinstance(first, Identifier) else str(first)]
        for item in _collect(rest):
            if isinstance(item, Identifier):
                parts.append(item.name)
            elif isinstance(item, str) and item != ".":
                parts.append(item)
        return parts

    # ── Checker ──────────────────────────────────────────────────

    def visit_checker_decl(self, node, visited_children):
        doc_opt, _, _, _, name, _, _, _, body, _, _ = visited_children
        docstring = None
        if doc_opt:
            ds = doc_opt[0] if isinstance(doc_opt, list) else doc_opt
            if isinstance(ds, str):
                docstring = ds

        members = _collect(body)

        error_id = None
        severity = None
        cwe = None
        confidence = None
        patterns = []
        queries = []
        on_blocks = []
        suppressions = []
        functions = []
        lets = []

        for m in members:
            if isinstance(m, tuple) and len(m) == 2:
                k, v = m
                if k == "error_id":
                    error_id = v
                elif k == "severity":
                    severity = v
                elif k == "cwe":
                    cwe = v
                elif k == "confidence":
                    confidence = v
            elif isinstance(m, PatternDecl):
                patterns.append(m)
            elif isinstance(m, QueryDecl):
                queries.append(m)
            elif isinstance(m, OnBlock):
                on_blocks.append(m)
            elif isinstance(m, SuppressDecl):
                suppressions.append(m)
            elif isinstance(m, FnDecl):
                functions.append(m)
            elif isinstance(m, LetStmt):
                lets.append(m)

        name_str = name.name if isinstance(name, Identifier) else str(name)
        return CheckerDecl(
            name=name_str, error_id=error_id, severity=severity,
            cwe=cwe, confidence=confidence, patterns=patterns,
            queries=queries, on_blocks=on_blocks,
            suppressions=suppressions, functions=functions,
            lets=lets, docstring=docstring, loc=self._loc(node),
        )

    def visit_checker_body(self, node, visited_children):
        return _collect(visited_children)

    def visit_checker_member(self, node, visited_children):
        return visited_children[0]

    def visit_error_id_decl(self, node, visited_children):
        _, _, _, _, val, _, _ = visited_children
        return ("error_id", val.value if isinstance(val, StringLiteral) else str(val))

    def visit_severity_decl(self, node, visited_children):
        _, _, _, _, level, _, _ = visited_children
        return ("severity", level)

    def visit_severity_level(self, node, visited_children):
        return Severity(_text(node))

    def visit_cwe_decl(self, node, visited_children):
        _, _, _, _, val, _, _ = visited_children
        return ("cwe", val.value if isinstance(val, IntLiteral) else int(str(val)))

    def visit_confidence_decl(self, node, visited_children):
        _, _, _, _, level, _, _ = visited_children
        text = _text(level) if isinstance(level, Node) else str(level)
        # handle list from alternation
        if isinstance(text, list):
            text = text[0]
        if isinstance(text, Node):
            text = text.text.strip()
        return ("confidence", Confidence(text))

    # ── Pattern ──────────────────────────────────────────────────

    def visit_pattern_decl(self, node, visited_children):
        doc_opt, _, _, _, name, _, _, _, params_opt, _, _, _, _, _,\
            body, _, _ = visited_children
        docstring = None
        if doc_opt:
            ds = doc_opt[0] if isinstance(doc_opt, list) else doc_opt
            if isinstance(ds, str):
                docstring = ds
        params = _collect(params_opt)
        clauses = _collect(body)
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return PatternDecl(
            name=name_str, params=params, clauses=clauses,
            docstring=docstring, loc=self._loc(node),
        )

    def visit_pattern_body(self, node, visited_children):
        return _collect(visited_children)

    def visit_pattern_clause(self, node, visited_children):
        return visited_children[0]

    def visit_match_clause(self, node, visited_children):
        _, _, pat, _, _ = visited_children
        return PatternClauseMatch(pattern=pat, loc=self._loc(node))

    def visit_where_clause(self, node, visited_children):
        _, _, expr, _, _ = visited_children
        return PatternClauseWhere(condition=expr, loc=self._loc(node))

    def visit_ensures_clause(self, node, visited_children):
        _, _, expr, _, _ = visited_children
        return PatternClauseEnsures(condition=expr, loc=self._loc(node))

    # ── Pattern Expressions ──────────────────────────────────────

    def visit_pattern_expr(self, node, visited_children):
        return visited_children[0]

    def visit_token_pattern(self, node, visited_children):
        _, _, _, _, constraints_opt, _, _ = visited_children
        constraints = {}
        items = _collect(constraints_opt)
        for item in items:
            if isinstance(item, tuple) and len(item) == 2:
                constraints[item[0]] = item[1]
        return TokenPattern(constraints=constraints, loc=self._loc(node))

    def visit_token_constraints(self, node, visited_children):
        first = visited_children[0]
        rest = visited_children[1] if len(visited_children) > 1 else []
        result = [first]
        for item in _collect(rest):
            if isinstance(item, tuple):
                result.append(item)
        return result

    def visit_token_constraint(self, node, visited_children):
        name, _, _, _, value = visited_children
        key = name.name if isinstance(name, Identifier) else str(name)
        return (key, value)

    def visit_scope_pattern(self, node, visited_children):
        _, _, _, _, name, _, _ = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return ScopePattern(name=name_str, loc=self._loc(node))

    def visit_call_pattern(self, node, visited_children):
        _, _, _, _, callee, rest, _, _ = visited_children
        args = [callee]
        args.extend(_collect(rest))
        return CallPattern(
            callee=args[0], args=args[1:], loc=self._loc(node)
        )

    def visit_assign_pattern(self, node, visited_children):
        _, _, _, _, lhs, _, _, rhs, _, _ = visited_children
        return AssignPattern(lhs=lhs, rhs=rhs, loc=self._loc(node))

    def visit_deref_pattern(self, node, visited_children):
        _, _, _, _, operand, _, _ = visited_children
        return DerefPattern(operand=operand, loc=self._loc(node))

    def visit_binop_pattern(self, node, visited_children):
        _, _, _, _, op, _, _, lhs, _, _, rhs, _, _ = visited_children
        op_str = op.value if isinstance(op, StringLiteral) else str(op)
        return BinopPattern(
            op=op_str, left=lhs, right=rhs, loc=self._loc(node)
        )

    def visit_wildcard_pattern(self, node, visited_children):
        return WildcardPattern(loc=self._loc(node))

    # ── Query ────────────────────────────────────────────────────

    def visit_query_decl(self, node, visited_children):
        doc_opt, _, _, _, name, _, _, _, params_opt, _, _, _, _, ret_type,\
            _, _, _, stmts, _, _ = visited_children
        docstring = None
        if doc_opt:
            ds = doc_opt[0] if isinstance(doc_opt, list) else doc_opt
            if isinstance(ds, str):
                docstring = ds
        params = _collect(params_opt)
        body = _collect(stmts)
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return QueryDecl(
            name=name_str, params=params, return_type=ret_type,
            body=body, docstring=docstring, loc=self._loc(node),
        )

    # ── On Block ─────────────────────────────────────────────────

    def visit_on_block(self, node, visited_children):
        _, _, event, _, _, _, stmts, _, _ = visited_children
        return OnBlock(
            event=event, body=_collect(stmts), loc=self._loc(node)
        )

    def visit_on_event(self, node, visited_children):
        return OnEvent(_text(node))

    # ── Functions ────────────────────────────────────────────────

    def visit_fn_decl(self, node, visited_children):
        doc_opt, _, _, _, name, _, _, _, params_opt, _, _, ret_opt,\
            _, _, _, stmts, _, _ = visited_children
        docstring = None
        if doc_opt:
            ds = doc_opt[0] if isinstance(doc_opt, list) else doc_opt
            if isinstance(ds, str):
                docstring = ds
        params = _collect(params_opt)
        body = _collect(stmts)
        ret_type = None
        if ret_opt:
            rt = ret_opt[0] if isinstance(ret_opt, list) else ret_opt
            if isinstance(rt, (TypeName, TypeGeneric)):
                ret_type = rt
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return FnDecl(
            name=name_str, params=params, return_type=ret_type,
            body=body, docstring=docstring, loc=self._loc(node),
        )

    def visit_param_list(self, node, visited_children):
        first = visited_children[0]
        rest = visited_children[1] if len(visited_children) > 1 else []
        result = [first]
        for item in _collect(rest):
            if isinstance(item, Param):
                result.append(item)
        return result

    def visit_param(self, node, visited_children):
        name, _, type_opt = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        type_ann = None
        items = _collect(type_opt)
        for item in items:
            if isinstance(item, (TypeName, TypeGeneric)):
                type_ann = item
        return Param(name=name_str, type_annotation=type_ann, loc=self._loc(node))

    # ── Types ────────────────────────────────────────────────────

    def visit_type_expr(self, node, visited_children):
        return visited_children[0]

    def visit_type_generic(self, node, visited_children):
        name, _, _, _, first, rest, _, _ = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        args = [first]
        args.extend(_collect(rest))
        return TypeGeneric(name=name_str, args=args, loc=self._loc(node))

    def visit_type_list(self, node, visited_children):
        _, _, _, _, inner, _, _ = visited_children
        return TypeGeneric(name="List", args=[inner], loc=self._loc(node))

    def visit_type_map(self, node, visited_children):
        _, _, _, _, k, _, _, v, _, _ = visited_children
        return TypeGeneric(name="Map", args=[k, v], loc=self._loc(node))

    def visit_type_set(self, node, visited_children):
        _, _, _, _, inner, _, _ = visited_children
        return TypeGeneric(name="Set", args=[inner], loc=self._loc(node))

    def visit_type_option(self, node, visited_children):
        _, _, _, _, inner, _, _ = visited_children
        return TypeGeneric(name="Option", args=[inner], loc=self._loc(node))

    def visit_type_name(self, node, visited_children):
        name = visited_children[0]
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return TypeName(name=name_str, loc=self._loc(node))

    # ── Constants & Type Aliases ─────────────────────────────────

    def visit_const_decl(self, node, visited_children):
        _, _, name, _, type_opt, _, _, _, value, _, _ = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        type_ann = None
        for item in _collect(type_opt):
            if isinstance(item, (TypeName, TypeGeneric)):
                type_ann = item
        return ConstDecl(
            name=name_str, type_annotation=type_ann,
            value=value, loc=self._loc(node),
        )

    def visit_type_alias(self, node, visited_children):
        _, _, name, _, _, _, target, _, _ = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return TypeAliasDecl(
            name=name_str, target=target, loc=self._loc(node),
        )

    def visit_suppress_decl(self, node, visited_children):
        _, _, error_id, _, glob_opt, _, _ = visited_children
        eid = error_id.value if isinstance(error_id, StringLiteral) else str(error_id)
        glob = None
        items = _collect(glob_opt)
        for item in items:
            if isinstance(item, StringLiteral):
                glob = item.value
            elif isinstance(item, str):
                glob = item
        return SuppressDecl(error_id=eid, file_glob=glob, loc=self._loc(node))

    # ── Statements ───────────────────────────────────────────────

    def visit_stmts(self, node, visited_children):
        return _collect(visited_children)

    def visit_stmt(self, node, visited_children):
        return visited_children[0]

    def visit_items(self, node, visited_children):
        return _collect(visited_children)

    def visit_item(self, node, visited_children):
        return visited_children[0]

    def visit_let_stmt(self, node, visited_children):
        _, _, mut_opt, _, name, _, type_opt, _, _, _, value, _, _ = visited_children
        mutable = bool(_collect(mut_opt))
        name_str = name.name if isinstance(name, Identifier) else str(name)
        type_ann = None
        for item in _collect(type_opt):
            if isinstance(item, (TypeName, TypeGeneric)):
                type_ann = item
        return LetStmt(
            name=name_str, mutable=mutable, type_annotation=type_ann,
            value=value, loc=self._loc(node),
        )

    def visit_assign_stmt(self, node, visited_children):
        target, _, op, _, value, _, _ = visited_children
        return AssignStmt(
            target=target, op=op, value=value, loc=self._loc(node),
        )

    def visit_assign_op(self, node, visited_children):
        return AssignOp(_text(node))

    def visit_lvalue(self, node, visited_children):
        return visited_children[0]

    def visit_if_stmt(self, node, visited_children):
        _, _, cond, _, _, _, then_body, _, _, elifs, _, else_opt = visited_children
        elif_clauses = []
        for item in _collect(elifs):
            if isinstance(item, tuple) and len(item) == 2:
                elif_clauses.append(item)
        else_body = None
        for item in _collect(else_opt):
            if isinstance(item, list):
                else_body = item
        return IfStmt(
            condition=cond, then_body=_collect(then_body),
            elif_clauses=elif_clauses, else_body=else_body,
            loc=self._loc(node),
        )

    def visit_elif_clause(self, node, visited_children):
        _, _, cond, _, _, _, body, _, _, _ = visited_children
        return (cond, _collect(body))

    def visit_else_clause(self, node, visited_children):
        _, _, _, _, body, _, _ = visited_children
        return _collect(body)

    def visit_for_stmt(self, node, visited_children):
        _, _, var, _, _, _, iterable, _, _, _, body, _, _ = visited_children
        var_str = var.name if isinstance(var, Identifier) else str(var)
        return ForStmt(
            var=var_str, iterable=iterable,
            body=_collect(body), loc=self._loc(node),
        )

    def visit_while_stmt(self, node, visited_children):
        _, _, cond, _, _, _, body, _, _ = visited_children
        return WhileStmt(
            condition=cond, body=_collect(body), loc=self._loc(node),
        )

    def visit_return_stmt(self, node, visited_children):
        _, _, value_opt, _, _ = visited_children
        value = None
        items = _collect(value_opt)
        if items:
            value = items[0]
        return ReturnStmt(value=value, loc=self._loc(node))

    def visit_emit_stmt(self, node, visited_children):
        _, _, error_id, _, _, _, args_opt, _, _, _, _ = visited_children
        eid = error_id.name if isinstance(error_id, Identifier) else str(error_id)
        args = _collect(args_opt)
        return EmitStmt(error_id=eid, args=args, loc=self._loc(node))

    def visit_break_stmt(self, node, visited_children):
        return BreakStmt(loc=self._loc(node))

    def visit_continue_stmt(self, node, visited_children):
        return ContinueStmt(loc=self._loc(node))

    def visit_expr_stmt(self, node, visited_children):
        expr, _, _ = visited_children
        return ExprStmt(expr=expr, loc=self._loc(node))

    # ── Expressions ──────────────────────────────────────────────

    def visit_expr(self, node, visited_children):
        return visited_children[0]

    def visit_match_expr(self, node, visited_children):
        _, _, subject, _, _, _, arms, _, _ = visited_children
        return MatchExpr(
            subject=subject, arms=_collect(arms), loc=self._loc(node),
        )

    def visit_match_arm(self, node, visited_children):
        pattern, _, _, _, body, _, _ = visited_children
        return MatchArm(pattern=pattern, body=body, loc=self._loc(node))

    def visit_pattern_val(self, node, visited_children):
        return visited_children[0]

    def visit_ternary(self, node, visited_children):
        left = visited_children[0]
        rest = _collect(visited_children[1]) if len(visited_children) > 1 else []
        if rest and len(rest) >= 2:
            # ? then_expr : else_expr
            return TernaryExpr(
                condition=left, then_expr=rest[0],
                else_expr=rest[1], loc=self._loc(node),
            )
        return left

    def _visit_binary_chain(self, node, visited_children):
        """Helper for left-associative binary operators."""
        left = visited_children[0]
        rest = visited_children[1] if len(visited_children) > 1 else []
        for group in _collect(rest):
            if isinstance(group, list) and len(group) >= 2:
                op_str, right = group[-2], group[-1]
                if isinstance(op_str, str):
                    try:
                        op = BinOp(op_str.strip())
                    except ValueError:
                        op = BinOp(op_str)
                    left = BinaryExpr(op=op, left=left, right=right,
                                      loc=self._loc(node))
            elif isinstance(group, tuple) and len(group) == 2:
                op, right = group
                left = BinaryExpr(op=op, left=left, right=right,
                                  loc=self._loc(node))
        return left

    visit_logical_or = _visit_binary_chain
    visit_logical_and = _visit_binary_chain
    visit_bitwise_or = _visit_binary_chain
    visit_bitwise_xor = _visit_binary_chain
    visit_bitwise_and = _visit_binary_chain
    visit_equality = _visit_binary_chain
    visit_comparison = _visit_binary_chain
    visit_addition = _visit_binary_chain
    visit_multiplication = _visit_binary_chain

    def visit_unary(self, node, visited_children):
        child = visited_children[0]
        if isinstance(child, list) and len(child) >= 2:
            op_str = child[0]
            operand = child[-1]
            if isinstance(op_str, str):
                op_str = op_str.strip()
            try:
                op = UnaryOp(op_str)
            except (ValueError, KeyError):
                return operand
            return UnaryExpr(op=op, operand=operand, loc=self._loc(node))
        return child

    def visit_postfix(self, node, visited_children):
        primary = visited_children[0]
        ops = _collect(visited_children[1]) if len(visited_children) > 1 else []
        result = primary
        for op in ops:
            if isinstance(op, tuple):
                kind = op[0]
                if kind == "call":
                    result = CallExpr(
                        callee=result, args=op[1], loc=self._loc(node)
                    )
                elif kind == "index":
                    result = IndexExpr(
                        obj=result, index=op[1], loc=self._loc(node)
                    )
                elif kind == "member":
                    result = MemberExpr(
                        obj=result, member=op[1], loc=self._loc(node)
                    )
                elif kind == "method":
                    result = MethodCallExpr(
                        obj=result, method=op[1], args=op[2],
                        loc=self._loc(node),
                    )
        return result

    def visit_postfix_op(self, node, visited_children):
        return visited_children[0]

    def visit_call_op(self, node, visited_children):
        _, _, args_opt, _, _ = visited_children
        args = _collect(args_opt)
        return ("call", args)

    def visit_index_op(self, node, visited_children):
        _, _, expr, _, _ = visited_children
        return ("index", expr)

    def visit_member_op(self, node, visited_children):
        _, name = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        return ("member", name_str)

    def visit_method_op(self, node, visited_children):
        _, name, _, _, _, args_opt, _, _ = visited_children
        name_str = name.name if isinstance(name, Identifier) else str(name)
        args = _collect(args_opt)
        return ("method", name_str, args)

    def visit_primary(self, node, visited_children):
        return visited_children[0]

    def visit_lambda_expr(self, node, visited_children):
        _, _, params_opt, _, _, _, ret_opt, _, _, _, stmts, _, _ = visited_children
        params = _collect(params_opt)
        ret_type = None
        for item in _collect(ret_opt):
            if isinstance(item, (TypeName, TypeGeneric)):
                ret_type = item
        return LambdaExpr(
            params=params, return_type=ret_type,
            body=_collect(stmts), loc=self._loc(node),
        )

    def visit_list_literal(self, node, visited_children):
        _, _, elems_opt, _, _ = visited_children
        return ListLiteral(elements=_collect(elems_opt), loc=self._loc(node))

    def visit_map_literal(self, node, visited_children):
        _, _, entries_opt, _, _ = visited_children
        entries = _collect(entries_opt)
        return MapLiteral(entries=entries, loc=self._loc(node))

    def visit_map_entry(self, node, visited_children):
        key, _, _, _, value = visited_children
        return (key, value)

    def visit_set_literal(self, node, visited_children):
        _, _, _, _, elems_opt, _, _ = visited_children
        return SetLiteral(elements=_collect(elems_opt), loc=self._loc(node))

    def visit_grouped(self, node, visited_children):
        _, _, expr, _, _ = visited_children
        return expr

    def visit_arg_list(self, node, visited_children):
        first = visited_children[0]
        rest = visited_children[1] if len(visited_children) > 1 else []
        result = [first]
        for item in _collect(rest):
            if item is not None and not isinstance(item, str):
                result.append(item)
        return result

    # ── Terminals ────────────────────────────────────────────────

    def visit_docstring(self, node, visited_children):
        raw = node.text.strip()
        # Remove surrounding triple quotes
        if raw.startswith('"""') and raw.endswith('"""'):
            return raw[3:-3].strip()
        return raw

    def visit_string_literal(self, node, visited_children):
        return StringLiteral(
            value=_unwrap_string(node.text.strip()),
            loc=self._loc(node),
        )

    def visit_integer(self, node, visited_children):
        text = node.text.strip()
        return IntLiteral(value=int(text, 0), loc=self._loc(node))

    def visit_float_lit(self, node, visited_children):
        return FloatLiteral(value=float(node.text.strip()), loc=self._loc(node))

    def visit_bool_lit(self, node, visited_children):
        return BoolLiteral(
            value=node.text.strip() == "true", loc=self._loc(node),
        )

    def visit_null_lit(self, node, visited_children):
        return NullLiteral(loc=self._loc(node))

    def visit_identifier(self, node, visited_children):
        return Identifier(name=node.text.strip(), loc=self._loc(node))

    # ── Whitespace / punctuation (return None) ───────────────────

    def visit_(self, node, visited_children):
        return None

    def visit_spacer(self, node, visited_children):
        return None

    def visit_semi(self, node, visited_children):
        return None

    def visit_lbrace(self, node, visited_children):
        return None

    def visit_rbrace(self, node, visited_children):
        return None

    def visit_lparen(self, node, visited_children):
        return None

    def visit_rparen(self, node, visited_children):
        return None

    def visit_lbracket(self, node, visited_children):
        return None

    def visit_rbracket(self, node, visited_children):
        return None

    def visit_arrow(self, node, visited_children):
        return None

    def visit_line_comment(self, node, visited_children):
        return None

    def visit_block_comment(self, node, visited_children):
        return None


def parse(source: str, filename: str = "<string>") -> Program:
    """Parse CASL source code into an AST Program node."""
    try:
        tree = _grammar.parse(source)
    except (ParseError, IncompleteParseError) as e:
        raise CASLParseError(str(e), filename=filename) from e
    visitor = CASLVisitor(filename=filename)
    return visitor.visit(tree)
