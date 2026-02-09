"""
cppcheckdata_analysis.py

Base framework for building program analyses on top of Cppcheck dump data.
This module provides:
  - Control Flow Graph (CFG) construction from cppcheckdata.Scope
  - Abstract lattice framework for data flow analysis
  - Monotone framework with worklist algorithm
  - AST traversal utilities

No specific analyses are implemented here; this is the foundation layer.

Usage:
    import cppcheckdata
    from cppcheckdata_analysis import ControlFlowGraph, MonotoneFramework
    
    data = cppcheckdata.parsedump("file.cpp.dump")
    for cfg in data.configurations:
        for scope in cfg.scopes:
            if scope.type == "Function":
                flow_graph = ControlFlowGraph(scope)
                # ... build your analysis on top
"""

from __future__ import annotations

import cppcheckdata

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import (
    TypeVar, Generic, Dict, Set, List, Optional, Tuple,
    FrozenSet, Iterator, Callable, Any, Union
)
from collections import defaultdict, deque
from enum import Enum, auto


# =============================================================================
# SECTION 1: PROGRAM LABELS AND CFG NODES
# =============================================================================

@dataclass(frozen=True)
class ProgramLabel:
    """
    Uniquely identifies a program point for analysis.
    
    A program label corresponds to a specific location in the source code
    where analysis information can be attached (entry/exit of statements,
    expressions, etc.).
    
    Attributes:
        id: Unique identifier (typically from token or scope ID)
        line: Source line number
        column: Source column number
        file: Source file path
        description: Human-readable description of this program point
    """
    id: str
    line: int = 0
    column: int = 0
    file: str = ""
    description: str = ""
    
    def __repr__(self) -> str:
        if self.description:
            return f"L[{self.id}:{self.line}:{self.description}]"
        return f"L[{self.id}:{self.line}]"
    
    @classmethod
    def from_token(cls, token: cppcheckdata.Token, 
                   description: str = "") -> 'ProgramLabel':
        """Create a ProgramLabel from a cppcheckdata Token."""
        return cls(
            id=token.Id or f"tok_{id(token)}",
            line=token.linenr or 0,
            column=token.column or 0,
            file=token.file or "",
            description=description or token.str or ""
        )
    
    @classmethod
    def from_scope(cls, scope: cppcheckdata.Scope,
                   suffix: str = "") -> 'ProgramLabel':
        """Create a ProgramLabel from a cppcheckdata Scope."""
        desc = f"{scope.type}:{scope.className or 'anonymous'}"
        if suffix:
            desc = f"{desc}:{suffix}"
        return cls(
            id=f"{scope.Id}_{suffix}" if suffix else scope.Id,
            line=scope.bodyStart.linenr if scope.bodyStart else 0,
            column=scope.bodyStart.column if scope.bodyStart else 0,
            file=scope.bodyStart.file if scope.bodyStart else "",
            description=desc
        )


class CFGNodeType(Enum):
    """Classification of CFG node types."""
    ENTRY = auto()       # Function/scope entry point
    EXIT = auto()        # Function/scope exit point
    STATEMENT = auto()   # Regular statement
    BRANCH = auto()      # Conditional branch (if, switch, ?:)
    LOOP_HEADER = auto() # Loop condition (for, while, do-while)
    LOOP_END = auto()    # End of loop body
    CALL = auto()        # Function call site
    RETURN = auto()      # Return statement
    MERGE = auto()       # Control flow merge point
    EXPRESSION = auto()  # Expression evaluation


@dataclass
class CFGNode:
    """
    A node in the Control Flow Graph.
    
    Each node represents a program point with associated analysis information.
    
    Attributes:
        label: Unique program label for this node
        node_type: Classification of the node
        token: The cppcheckdata.Token at this program point (if any)
        successors: Set of labels for successor nodes
        predecessors: Set of labels for predecessor nodes
        scope: The enclosing cppcheckdata.Scope
    """
    label: ProgramLabel
    node_type: CFGNodeType
    token: Optional[cppcheckdata.Token] = None
    successors: Set[ProgramLabel] = field(default_factory=set)
    predecessors: Set[ProgramLabel] = field(default_factory=set)
    scope: Optional[cppcheckdata.Scope] = None
    
    # Additional metadata for analysis
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_successor(self, label: ProgramLabel) -> None:
        """Add a successor node."""
        self.successors.add(label)
    
    def add_predecessor(self, label: ProgramLabel) -> None:
        """Add a predecessor node."""
        self.predecessors.add(label)
    
    def __hash__(self) -> int:
        return hash(self.label)
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CFGNode):
            return False
        return self.label == other.label


# =============================================================================
# SECTION 2: CONTROL FLOW GRAPH
# =============================================================================

class ControlFlowGraph:
    """
    Control Flow Graph constructed from a cppcheckdata.Scope.
    
    The CFG represents the possible execution paths through a function or
    other executable scope. It provides:
      - Entry and exit nodes
      - Nodes for each statement/expression
      - Edges representing control flow
    
    Example:
        scope = ...  # cppcheckdata.Scope of type "Function"
        cfg = ControlFlowGraph(scope)
        
        for label, node in cfg.nodes.items():
            print(f"{label}: successors={node.successors}")
    """
    
    def __init__(self, scope: cppcheckdata.Scope):
        """
        Build a CFG from a cppcheckdata Scope.
        
        Args:
            scope: A cppcheckdata.Scope object (typically a Function scope)
        
        Raises:
            ValueError: If scope has no body (bodyStart is None)
        """
        if not scope.bodyStart:
            raise ValueError(f"Scope {scope.Id} has no body to analyze")
        
        self.scope = scope
        self.nodes: Dict[ProgramLabel, CFGNode] = {}
        self.entry: Optional[ProgramLabel] = None
        self.exit: Optional[ProgramLabel] = None
        
        # Build the CFG
        self._build()
    
    def _build(self) -> None:
        """Construct the CFG from the scope's tokens."""
        # Create entry node
        entry_label = ProgramLabel.from_scope(self.scope, "entry")
        self.entry = entry_label
        self.nodes[entry_label] = CFGNode(
            label=entry_label,
            node_type=CFGNodeType.ENTRY,
            token=self.scope.bodyStart,
            scope=self.scope
        )
        
        # Create exit node
        exit_label = ProgramLabel.from_scope(self.scope, "exit")
        self.exit = exit_label
        self.nodes[exit_label] = CFGNode(
            label=exit_label,
            node_type=CFGNodeType.EXIT,
            token=self.scope.bodyEnd,
            scope=self.scope
        )
        
        # Process tokens between bodyStart and bodyEnd
        self._process_tokens()
        
        # Connect any dangling nodes to exit
        self._finalize_edges()
    
    def _process_tokens(self) -> None:
        """Process tokens to build CFG nodes and edges."""
        token = self.scope.bodyStart.next  # Skip opening '{'
        end_token = self.scope.bodyEnd
        
        prev_label = self.entry
        
        while token and token != end_token:
            # Skip non-statement tokens
            if not self._is_significant_token(token):
                token = token.next
                continue
            
            # Determine node type
            node_type = self._classify_token(token)
            
            # Create node
            label = ProgramLabel.from_token(token)
            node = CFGNode(
                label=label,
                node_type=node_type,
                token=token,
                scope=self.scope
            )
            self.nodes[label] = node
            
            # Handle control flow based on token type
            if token.str in ('if', 'while', 'for', 'do', 'switch'):
                prev_label = self._handle_control_structure(token, prev_label)
            elif token.str == 'return':
                self._add_edge(prev_label, label)
                self._add_edge(label, self.exit)
                prev_label = None  # Dead code after return
            elif token.str in ('break', 'continue'):
                self._add_edge(prev_label, label)
                # break/continue handled by loop context
                prev_label = None
            elif token.str == 'goto':
                self._add_edge(prev_label, label)
                # goto target resolution would require label tracking
                prev_label = None
            else:
                # Regular statement
                if prev_label:
                    self._add_edge(prev_label, label)
                prev_label = label
            
            token = token.next
        
        # Connect last statement to exit
        if prev_label and prev_label != self.exit:
            self._add_edge(prev_label, self.exit)
    
    def _is_significant_token(self, token: cppcheckdata.Token) -> bool:
        """Determine if a token represents a significant program point."""
        # Skip punctuation and structure tokens
        if token.str in ('{', '}', '(', ')', '[', ']', ',', ';'):
            return False
        
        # Include statements and expressions
        if token.isOp or token.isName or token.isNumber:
            # Check if this is a statement-level token (has semicolon or is control)
            if token.str in ('if', 'else', 'while', 'for', 'do', 'switch',
                            'case', 'default', 'return', 'break', 'continue',
                            'goto', 'throw', 'try', 'catch'):
                return True
            
            # Assignment or function call at statement level
            if token.isAssignmentOp:
                return True
            if token.function:
                return True
            
            # Top-level expression
            if token.astParent is None and token.astOperand1:
                return True
        
        return False
    
    def _classify_token(self, token: cppcheckdata.Token) -> CFGNodeType:
        """Classify a token into a CFG node type."""
        if token.str == 'if':
            return CFGNodeType.BRANCH
        if token.str in ('while', 'for', 'do'):
            return CFGNodeType.LOOP_HEADER
        if token.str == 'switch':
            return CFGNodeType.BRANCH
        if token.str == 'return':
            return CFGNodeType.RETURN
        if token.function:
            return CFGNodeType.CALL
        return CFGNodeType.STATEMENT
    
    def _handle_control_structure(self, token: cppcheckdata.Token,
                                  prev_label: Optional[ProgramLabel]) -> Optional[ProgramLabel]:
        """
        Handle control flow structures (if, while, for, etc.).
        
        Returns the label to continue from after the structure.
        """
        label = ProgramLabel.from_token(token)
        
        if prev_label:
            self._add_edge(prev_label, label)
        
        # For simplicity, return the control token as the continue point
        # A full implementation would parse the entire structure
        return label
    
    def _add_edge(self, from_label: Optional[ProgramLabel],
                  to_label: Optional[ProgramLabel]) -> None:
        """Add a directed edge between two nodes."""
        if from_label is None or to_label is None:
            return
        if from_label not in self.nodes or to_label not in self.nodes:
            return
        
        self.nodes[from_label].add_successor(to_label)
        self.nodes[to_label].add_predecessor(from_label)
    
    def _finalize_edges(self) -> None:
        """Ensure all nodes are properly connected."""
        # Find nodes with no successors (except exit) and connect to exit
        for label, node in self.nodes.items():
            if label == self.exit:
                continue
            if not node.successors:
                self._add_edge(label, self.exit)
    
    # -------------------------------------------------------------------------
    # Query Methods
    # -------------------------------------------------------------------------
    
    def get_node(self, label: ProgramLabel) -> Optional[CFGNode]:
        """Get a node by its label."""
        return self.nodes.get(label)
    
    def successors(self, label: ProgramLabel) -> Iterator[ProgramLabel]:
        """Iterate over successor labels of a node."""
        node = self.nodes.get(label)
        if node:
            yield from node.successors
    
    def predecessors(self, label: ProgramLabel) -> Iterator[ProgramLabel]:
        """Iterate over predecessor labels of a node."""
        node = self.nodes.get(label)
        if node:
            yield from node.predecessors
    
    def all_labels(self) -> Iterator[ProgramLabel]:
        """Iterate over all labels in the CFG."""
        yield from self.nodes.keys()
    
    def reverse_postorder(self) -> List[ProgramLabel]:
        """
        Return nodes in reverse postorder (useful for forward analyses).
        
        Reverse postorder ensures that (in reducible CFGs) a node is visited
        after all its predecessors, except for back edges.
        """
        visited: Set[ProgramLabel] = set()
        postorder: List[ProgramLabel] = []
        
        def dfs(label: ProgramLabel) -> None:
            if label in visited:
                return
            visited.add(label)
            for succ in self.successors(label):
                dfs(succ)
            postorder.append(label)
        
        if self.entry:
            dfs(self.entry)
        
        return list(reversed(postorder))
    
    def postorder(self) -> List[ProgramLabel]:
        """
        Return nodes in postorder (useful for backward analyses).
        """
        visited: Set[ProgramLabel] = set()
        postorder: List[ProgramLabel] = []
        
        def dfs(label: ProgramLabel) -> None:
            if label in visited:
                return
            visited.add(label)
            for succ in self.successors(label):
                dfs(succ)
            postorder.append(label)
        
        if self.entry:
            dfs(self.entry)
        
        return postorder
    
    def __repr__(self) -> str:
        return f"CFG({self.scope.className}, nodes={len(self.nodes)})"


# =============================================================================
# SECTION 3: LATTICE FRAMEWORK
# =============================================================================

T = TypeVar('T')  # Lattice element type


class Lattice(ABC, Generic[T]):
    """
    Abstract base class for lattices used in data flow analysis.
    
    A lattice (L, ⊑, ⊔, ⊓, ⊥, ⊤) provides:
      - A partial order ⊑ (leq)
      - Join ⊔ (least upper bound)
      - Meet ⊓ (greatest lower bound)  
      - Bottom ⊥ (least element)
      - Top ⊤ (greatest element)
    
    Subclasses must implement all abstract methods.
    
    Example:
        class BoolLattice(Lattice[bool]):
            def bottom(self) -> bool: return False
            def top(self) -> bool: return True
            def leq(self, a: bool, b: bool) -> bool: return (not a) or b
            def join(self, a: bool, b: bool) -> bool: return a or b
            def meet(self, a: bool, b: bool) -> bool: return a and b
    """
    
    @abstractmethod
    def bottom(self) -> T:
        """Return the bottom element ⊥ of the lattice."""
        pass
    
    @abstractmethod
    def top(self) -> T