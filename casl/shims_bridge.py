# casl/shims_bridge.py
"""
Bridge between CASL runtime and cppcheckdata-shims.
Provides typed wrappers and lazy analysis computation.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Set, Tuple


class ShimsBridge:
    """
    Lazy facade over cppcheckdata-shims analyses.

    Analyses are computed on first access and cached per-configuration.
    """

    def __init__(self):
        self._cache: Dict[Tuple[str, int], Any] = {}

    def get(self, name: str, cfg: Any) -> Any:
        key = (name, id(cfg))
        if key not in self._cache:
            self._cache[key] = self._build(name, cfg)
        return self._cache[key]

    def _build(self, name: str, cfg: Any) -> Any:
        from cppcheckdata_shims.dataflow_analyses import (
            ReachingDefinitions, LiveVariables, IntervalAnalysis,
            NullPointerAnalysis, TaintAnalysis, SignAnalysis,
            ConstantPropagation, PointerAnalysis, DefiniteAssignment,
            AvailableExpressions, VeryBusyExpressions, CopyPropagation,
            DominatorAnalysis,
        )
        _MAP = {
            "reaching_defs": ReachingDefinitions,
            "live_vars": LiveVariables,
            "intervals": IntervalAnalysis,
            "null_ptrs": NullPointerAnalysis,
            "taint": TaintAnalysis,
            "signs": SignAnalysis,
            "constants": ConstantPropagation,
            "pointers": PointerAnalysis,
            "definite_assignment": DefiniteAssignment,
            "available_exprs": AvailableExpressions,
            "very_busy_exprs": VeryBusyExpressions,
            "copy_propagation": CopyPropagation,
            "dominators": DominatorAnalysis,
        }
        cls = _MAP.get(name)
        if cls is None:
            raise ValueError(f"Unknown analysis: {name!r}")
        analysis = cls(cfg)
        analysis.run()
        return analysis

    def invalidate(self, cfg: Any = None):
        if cfg is None:
            self._cache.clear()
        else:
            cid = id(cfg)
            self._cache = {k: v for k, v in self._cache.items() if k[1] != cid}

    def null_check(self, cfg: Any, tok: Any) -> Optional[bool]:
        """Returns True if tok may be null, False if definitely non-null, None if unknown."""
        try:
            npa = self.get("null_ptrs", cfg)
            return npa.may_be_null(tok)
        except Exception:
            return None

    def interval_check(self, cfg: Any, var_id: int, lo: int, hi: int,
                       tok: Any) -> Optional[bool]:
        """Returns True if var is within [lo, hi] at tok, False if not, None if unknown."""
        try:
            ia = self.get("intervals", cfg)
            return ia.is_in_bounds(var_id, lo, hi, tok)
        except Exception:
            return None

    def is_tainted(self, cfg: Any, tok: Any) -> Optional[bool]:
        try:
            ta = self.get("taint", cfg)
            return ta.is_tainted_at(tok)
        except Exception:
            return None

    def is_live(self, cfg: Any, var_id: int, tok: Any) -> Optional[bool]:
        try:
            lv = self.get("live_vars", cfg)
            return lv.is_live_after(var_id, tok)
        except Exception:
            return None
