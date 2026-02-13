"""
use_after_free_detector.py

Detects use-after-free vulnerabilities by tracking:
1. Memory allocation points
2. Free/deallocation points
3. Subsequent uses of freed pointers

Uses: CFG, DataflowEngine, MemoryAbstraction, CallGraph
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Set, List, Optional, Tuple
from enum import Enum, auto
import cppcheckdata

# ============================================================================
# Import shim modules
# ============================================================================
from controlflow_graph import build_cfg, CFG, CFGNode
from callgraph import build_callgraph, CallGraph
from dataflow_engine import (
    AbstractDomain, DataflowAnalysis, TransferFunction,
    Direction, AnalysisResult
)
from memory_abstraction import (
    MemoryLocation, AbstractValue, MemoryState,
    PointsToGraph, HeapAllocation
)


# ============================================================================
# Domain: Pointer State Lattice
# ============================================================================

class PointerState(Enum):
    """State of a pointer in the program."""
    UNALLOCATED = auto()   # Never allocated
    ALLOCATED = auto()     # Currently allocated
    FREED = auto()         # Has been freed
    UNKNOWN = auto()       # Could be any state


@dataclass(frozen=True)
class PointerInfo:
    """Information about a single pointer."""
    var_id: int
    state: PointerState
    alloc_site: Optional[int] = None  # Line number of allocation
    free_site: Optional[int] = None   # Line number of free


class UseAfterFreeDomain(AbstractDomain):
    """
    Abstract domain tracking pointer allocation states.
    
    Maps varId -> PointerInfo
    
    Lattice structure:
        ⊥ = empty map (no information)
        ⊤ = all pointers in UNKNOWN state
        ⊔ = merge states conservatively
    """
    
    def __init__(self, pointers: Optional[Dict[int, PointerInfo]] = None,
                 is_top: bool = False):
        self.pointers: Dict[int, PointerInfo] = pointers or {}
        self._is_top = is_top
    
    @classmethod
    def bottom(cls) -> 'UseAfterFreeDomain':
        return cls({})
    
    @classmethod
    def top(cls) -> 'UseAfterFreeDomain':
        return cls({}, is_top=True)
    
    def _merge_state(self, s1: PointerState, s2: PointerState) -> PointerState:
        """Merge two pointer states conservatively."""
        if s1 == s2:
            return s1
        if s1 == PointerState.UNKNOWN or s2 == PointerState.UNKNOWN:
            return PointerState.UNKNOWN
        # Different concrete states -> unknown
        return PointerState.UNKNOWN
    
    def join(self, other: 'UseAfterFreeDomain') -> 'UseAfterFreeDomain':
        if self._is_top or other._is_top:
            return UseAfterFreeDomain.top()
        
        merged = {}
        all_vars = set(self.pointers.keys()) | set(other.pointers.keys())
        
        for vid in all_vars:
            p1 = self.pointers.get(vid)
            p2 = other.pointers.get(vid)
            
            if p1 is None:
                merged[vid] = p2
            elif p2 is None:
                merged[vid] = p1
            else:
                # Both present - merge states
                new_state = self._merge_state(p1.state, p2.state)
                merged[vid] = PointerInfo(
                    var_id=vid,
                    state=new_state,
                    alloc_site=p1.alloc_site if p1.alloc_site == p2.alloc_site else None,
                    free_site=p1.free_site if p1.free_site == p2.free_site else None,
                )
        
        return UseAfterFreeDomain(merged)
    
    def meet(self, other: 'UseAfterFreeDomain') -> 'UseAfterFreeDomain':
        if self._is_top:
            return UseAfterFreeDomain(other.pointers.copy())
        if other._is_top:
            return UseAfterFreeDomain(self.pointers.copy())
        
        # Intersection of keys with matching states
        merged = {}
        for vid in set(self.pointers.keys()) & set(other.pointers.keys()):
            p1, p2 = self.pointers[vid], other.pointers[vid]
            if p1.state == p2.state:
                merged[vid] = p1
        
        return UseAfterFreeDomain(merged)
    
    def leq(self, other: 'UseAfterFreeDomain') -> bool:
        if other._is_top:
            return True
        if self._is_top:
            return False
        
        # self ⊑ other iff self's info is subsumed by other's
        for vid, info in self.pointers.items():
            if vid not in other.pointers:
                return False
            other_info = other.pointers[vid]
            if info.state != other_info.state and \
               other_info.state != PointerState.UNKNOWN:
                return False
        return True
    
    def widen(self, other: 'UseAfterFreeDomain') -> 'UseAfterFreeDomain':
        # For finite state lattice, widening = join
        return self.join(other)
    
    def narrow(self, other: 'UseAfterFreeDomain') -> 'UseAfterFreeDomain':
        return self.meet(other)
    
    def set_allocated(self, var_id: int, line: int) -> 'UseAfterFreeDomain':
        """Mark a pointer as freshly allocated."""
        new_ptrs = self.pointers.copy()
        new_ptrs[var_id] = PointerInfo(var_id, PointerState.ALLOCATED, 
                                        alloc_site=line)
        return UseAfterFreeDomain(new_ptrs)
    
    def set_freed(self, var_id: int, line: int) -> 'UseAfterFreeDomain':
        """Mark a pointer as freed."""
        new_ptrs = self.pointers.copy()
        old_info = self.pointers.get(var_id)
        new_ptrs[var_id] = PointerInfo(
            var_id, 
            PointerState.FREED,
            alloc_site=old_info.alloc_site if old_info else None,
            free_site=line
        )
        return UseAfterFreeDomain(new_ptrs)
    
    def get_state(self, var_id: int) -> PointerState:
        """Get the state of a pointer."""
        if var_id in self.pointers:
            return self.pointers[var_id].state
        return PointerState.UNALLOCATED


# ============================================================================
# Transfer Function
# ============================================================================

class UseAfterFreeTransfer(TransferFunction[UseAfterFreeDomain]):
    """
    Transfer function that