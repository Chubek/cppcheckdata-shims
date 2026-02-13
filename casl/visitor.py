#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casl/visitor.py
===============

Visitor pattern infrastructure for CASL AST traversal.

Provides:
- ``ASTVisitor`` — abstract base with default implementations
- ``DepthFirstVisitor`` — generic traversal that visits all children
- ``TransformingVisitor`` — visitor that rebuilds the tree (for rewrites)
"""

from __future__ import annotations

import abc
from typing import Any, Callable, Dict, List, Optional, Type, TypeVar

from casl import ast as A

__all__ = [
    "ASTVisitor",
    "DepthFirstVisitor",
    "TransformingVisitor",
    "visiting",
]

T = TypeVar("T", bound=A.ASTNode)


class ASTVisitor(abc.ABC):
    """Abstract base class for CASL AST visitors.
    
    Each ``visit_X`` method corresponds to an AST node type.  The default
    implementations call ``generic_visit``, which does nothing.  Subclasses
    override the methods they care about.
    """
    
    def visit(self, node: A.ASTNode) -> Any:
        """Dispatch to the appropriate visit method."""
        return node.accept(self)
    
    def generic_visit(self, node: A.ASTNode) -> Any:
        """Called when no specific visitor method exists.
        
        Default: return None.  Override for catch-all behavior.
        """
        return None
    
    # --- Top-level ---
    
    def visit_addon_spec(self, node: A.AddonSpec) -> Any:
        return self.generic_visit(node)
    
    def visit_metadata(self, node: A.Metadata) -> Any:
        return self.generic_visit(node)
    
    def visit_import(self, node: A.Import) -> Any:
        return self.generic_visit(node)
    
    # --- Declarations ---
    
    def visit_var_decl(self, node: A.VarDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_domain_element(self, node: A.DomainElement) -> Any:
        return self.generic_visit(node)
    
    def visit_domain_decl(self, node: A.DomainDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_function_decl(self, node: A.FunctionDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_transfer_decl(self, node: A.TransferDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_pattern_decl(self, node: A.PatternDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_query_decl(self, node: A.QueryDecl) -> Any:
        return self.generic_visit(node)
    
    def visit_checker_decl(self, node: A.CheckerDecl) -> Any:
        return self.generic_visit(node)
    
    # --- Code patterns ---
    
    def visit_wildcard_pattern(self, node: A.WildcardPattern) -> Any:
        return self.generic_visit(node)
    
    def visit_binding_pattern(self, node: A.BindingPattern) -> Any:
        return self.generic_visit(node)
    
    def visit_node_pattern(self, node: A.NodePattern) -> Any:
        return self.generic_visit(node)
    
    def visit_sequence_pattern(self, node: A.SequencePattern) -> Any:
        return self.generic_visit(node)
    
    def visit_star_pattern(self, node: A.StarPattern) -> Any:
        return self.generic_visit(node)
    
    def visit_optional_pattern(self, node: A.OptionalPattern) -> Any:
        return self.generic_visit(node)
    
    def visit_or_pattern(self, node: A.OrPattern) -> Any:
        return self.generic_visit(node)
    
    def visit_guarded_pattern(self, node: A.GuardedPattern) -> Any:
        return self.generic_visit(node)
    
    # --- Constraints ---
    
    def visit_where_clause(self, node: A.WhereClause) -> Any:
        return self.generic_visit(node)
    
    def visit_flows_to(self, node: A.FlowsTo) -> Any:
        return self.generic_visit(node)
    
    def visit_reaches(self, node: A.Reaches) -> Any:
        return self.generic_visit(node)
    
    def visit_dominates(self, node: A.Dominates) -> Any:
        return self.generic_visit(node)
    
    def visit_dataflow_fact(self, node: A.DataflowFact) -> Any:
        return self.generic_visit(node)
    
    # --- Expressions ---
    
    def visit_literal(self, node: A.Literal) -> Any:
        return self.generic_visit(node)
    
    def visit_identifier(self, node: A.Identifier) -> Any:
        return self.generic_visit(node)
    
    def visit_binary_op(self, node: A.BinaryOp) -> Any:
        return self.generic_visit(node)
    
    def visit_unary_op(self, node: A.UnaryOp) -> Any:
        return self.generic_visit(node)
    
    def visit_call(self, node: A.Call) -> Any:
        return self.generic_visit(node)
    
    def visit_field_access(self, node: A.FieldAccess) -> Any:
        return self.generic_visit(node)
    
    def visit_index_access(self, node: A.IndexAccess) -> Any:
        return self.generic_visit(node)
    
    def visit_if_expr(self, node: A.IfExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_let_expr(self, node: A.LetExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_match_arm(self, node: A.MatchArm) -> Any:
        return self.generic_visit(node)
    
    def visit_match_expr(self, node: A.MatchExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_lambda_expr(self, node: A.LambdaExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_set_expr(self, node: A.SetExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_map_expr(self, node: A.MapExpr) -> Any:
        return self.generic_visit(node)
    
    def visit_tuple_expr(self, node: A.TupleExpr) -> Any:
        return self.generic_visit(node)
    
    # --- Actions ---
    
    def visit_report_action(self, node: A.ReportAction) -> Any:
        return self.generic_visit(node)
    
    def visit_log_action(self, node: A.LogAction) -> Any:
        return self.generic_visit(node)
    
    def visit_set_fact_action(self, node: A.SetFactAction) -> Any:
        return self.generic_visit(node)
    
    def visit_abort_action(self, node: A.AbortAction) -> Any:
        return self.generic_visit(node)
    
    # --- Types ---
    
    def visit_type_ref(self, node: A.TypeRef) -> Any:
        return self.generic_visit(node)
    
    def visit_domain_type(self, node: A.DomainType) -> Any:
        return self.generic_visit(node)
    
    def visit_set_type(self, node: A.SetType) -> Any:
        return self.generic_visit(node)
    
    def visit_map_type(self, node: A.MapType) -> Any:
        return self.generic_visit(node)
    
    def visit_tuple_type(self, node: A.TupleType) -> Any:
        return self.generic_visit(node)
    
    def visit_function_type(self, node: A.FunctionType) -> Any:
        return self.generic_visit(node)
    
    # --- Dataflow specs ---
    
    def visit_lattice_spec(self, node: A.LatticeSpec) -> Any:
        return self.generic_visit(node)
    
    def visit_direction_spec(self, node: A.DirectionSpec) -> Any:
        return self.generic_visit(node)
    
    def visit_transfer_spec(self, node: A.TransferSpec) -> Any:
        return self.generic_visit(node)
    
    def visit_dataflow_spec(self, node: A.DataflowSpec) -> Any:
        return self.generic_visit(node)


class DepthFirstVisitor(ASTVisitor):
    """Visitor that traverses all children in depth-first order.
    
    Override ``enter_X`` / ``leave_X`` hooks instead of ``visit_X`` for
    pre/post-order processing.  The ``visit_X`` methods handle traversal.
    """
    
    def generic_visit(self, node: A.ASTNode) -> Any:
        """Visit all children."""
        for child in node.children():
            self.visit(child)
        return None
    
    # Hook methods — override these in subclasses
    
    def enter(self, node: A.ASTNode) -> None:
        """Called before visiting children."""
        pass
    
    def leave(self, node: A.ASTNode) -> None:
        """Called after visiting children."""
        pass
    
    def visit_addon_spec(self, node: A.AddonSpec) -> Any:
        self.enter(node)
        self.generic_visit(node)
        self.leave(node)
    
    # ... (similar pattern for all visit methods)


class TransformingVisitor(ASTVisitor):
    """Visitor that rebuilds the AST, allowing transformations.
    
    Each ``visit_X`` returns a new node (or the original if unchanged).
    Subclasses override specific methods to perform rewrites.
    """
    
    def visit_addon_spec(self, node: A.AddonSpec) -> A.AddonSpec:
        return A.AddonSpec(
            name=node.name,
            metadata=self.visit(node.metadata) if node.metadata else None,
            imports=[self.visit(i) for i in node.imports],
            domains=[self.visit(d) for d in node.domains],
            functions=[self.visit(f) for f in node.functions],
            transfers=[self.visit(t) for t in node.transfers],
            patterns=[self.visit(p) for p in node.patterns],
            queries=[self.visit(q) for q in node.queries],
            checkers=[self.visit(c) for c in node.checkers],
            dataflows=[self.visit(d) for d in node.dataflows],
            location=node.location,
            annotations=dict(node.annotations),
        )
    
    def visit_metadata(self, node: A.Metadata) -> A.Metadata:
        return node  # typically unchanged
    
    def visit_import(self, node: A.Import) -> A.Import:
        return node
    
    # ... (implement all visit_X methods to rebuild nodes)
    
    def generic_visit(self, node: A.ASTNode) -> A.ASTNode:
        """Default: return node unchanged."""
        return node


# ---------------------------------------------------------------------------
# Decorator for method-based visitor dispatch
# ---------------------------------------------------------------------------

def visiting(*node_types: Type[A.ASTNode]) -> Callable:
    """Decorator to register a method as handling specific node types.
    
    Usage:
        class MyVisitor(ASTVisitor):
            @visiting(A.BinaryOp, A.UnaryOp)
            def handle_ops(self, node):
                ...
    """
    def decorator(method: Callable) -> Callable:
        method._visiting_types = node_types
        return method
    return decorator
