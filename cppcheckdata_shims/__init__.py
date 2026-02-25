"""
cppcheckdata_shims — Abstract Execution Substrate for Cppcheck Addons
=====================================================================

This package provides the foundational abstract interpretation infrastructure
used by Cppcheck static analysis addons such as ``StackDepthAnalyzer`` and
``EnergyConsumptionEstimator``.

Core modules
------------
interval
    Interval arithmetic domain with sound over-approximation semantics.
abstract_state
    Abstract program states mapping variables to abstract values.
abstract_executor
    The main abstract execution engine that walks Cppcheck AST/CFG structures.
cfg
    Control-flow graph construction from Cppcheck ``cppcheckdata`` dumps.
callgraph
    Inter-procedural call graph with Tarjan SCC detection.
widening
    Widening and narrowing operators for convergence of fixpoint iteration.
fixpoint
    Chaotic iteration fixpoint engine over abstract domains.
ast_helpers
    Utility functions for navigating Cppcheck token/scope/variable structures.
cost_algebra
    Symbolic cost expression algebra for parametric bound representation.
domains
    Auxiliary abstract domains (sign, parity, congruence).

Quick start
-----------
>>> from cppcheckdata_shims import IntervalDomain, Interval, CallGraph, tarjan_scc
>>> iv = Interval(0, 100)
>>> iv2 = IntervalDomain.add(iv, Interval(1, 1))
>>> print(iv2)
[1, 101]

Package layout
--------------
::

    cppcheckdata_shims/
    ├── __init__.py            ← this file
    ├── interval.py
    ├── abstract_state.py
    ├── abstract_executor.py
    ├── cfg.py
    ├── callgraph.py
    ├── widening.py
    ├── fixpoint.py
    ├── ast_helpers.py
    ├── cost_algebra.py
    └── domains.py
"""

from __future__ import annotations

import importlib
import logging
import sys
import warnings
from typing import TYPE_CHECKING, Any, List

# ---------------------------------------------------------------------------
# Package metadata
# ---------------------------------------------------------------------------

__version__ = "0.3.0"
__author__ = "Cppcheck Abstract Execution Contributors"
__license__ = "GPL-3.0-or-later"
__all__: List[str] = []          # populated incrementally below

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal registry: (module_name, list_of_names_to_import)
#
# Modules are grouped into tiers:
#   CORE  — always imported; failure is fatal
#   ADDON — imported eagerly but failure only warns (package still usable)
# ---------------------------------------------------------------------------

_CORE_MODULES = {
    "interval": [
        "Interval",
        "IntervalDomain",
        "TOP_INTERVAL",
        "BOT_INTERVAL",
    ],
    "abstract_state": [
        "AbstractState",
        "AbstractStore",
        "MemoryRegion",
    ],
    "abstract_executor": [
        "AbstractExecutor",
        "ExecutionContext",
        "StepResult",
    ],
    "cfg": [
        "CFGBuilder",
        "BasicBlock",
        "CFGEdge",
        "CFG",
    ],
    "callgraph": [
        "CallGraph",
        "CallGraphNode",
        "CallGraphEdge",
        "tarjan_scc",
    ],
    "widening": [
        "widen",
        "narrow",
        "WideningStrategy",
        "NarrowingStrategy",
    ],
    "fixpoint": [
        "FixpointEngine",
        "FixpointResult",
        "chaotic_iteration",
    ],
    "ast_helpers": [
        "token_to_op",
        "scope_functions",
        "find_loops",
        "variable_sizes",
        "alignment_of",
    ],
    "cost_algebra": [
        "CostExpr",
        "CostConst",
        "CostVar",
        "CostAdd",
        "CostMul",
        "simplify_cost",
    ],
}

_ADDON_MODULES = {
    "domains": [
        "SignDomain",
        "ParityDomain",
        "CongruenceDomain",
    ],
}

# ---------------------------------------------------------------------------
# Lazy-import helper
# ---------------------------------------------------------------------------

def _import_names(
    module_rel_name: str,
    names: List[str],
    *,
    fatal: bool = True,
) -> None:
    """Import *names* from a submodule and bind them in the package namespace.

    Parameters
    ----------
    module_rel_name:
        Module name relative to this package (e.g. ``"interval"``).
    names:
        Public symbols to re-export.
    fatal:
        If ``True``, an ``ImportError`` propagates.  If ``False``, a warning
        is issued and the names are skipped (addon tier).
    """
    fq_name = f"{__name__}.{module_rel_name}"
    try:
        mod = importlib.import_module(fq_name)
    except ImportError as exc:
        if fatal:
            raise ImportError(
                f"cppcheckdata_shims: required submodule '{module_rel_name}' "
                f"failed to import: {exc}"
            ) from exc
        warnings.warn(
            f"cppcheckdata_shims: optional submodule '{module_rel_name}' "
            f"could not be imported ({exc}); related symbols will be unavailable.",
            ImportWarning,
            stacklevel=2,
        )
        _log.debug("Skipped optional module %s: %s", module_rel_name, exc)
        return

    # Bind each name into the package namespace
    current_module = sys.modules[__name__]
    for name in names:
        obj = getattr(mod, name, None)
        if obj is None:
            msg = (
                f"cppcheckdata_shims.{module_rel_name} does not export '{name}'"
            )
            if fatal:
                raise AttributeError(msg)
            _log.warning(msg)
            continue
        setattr(current_module, name, obj)
        __all__.append(name)

    # Also expose the submodule itself as a package attribute so that
    #   cppcheckdata_shims.interval.Interval
    # works in addition to
    #   cppcheckdata_shims.Interval
    setattr(current_module, module_rel_name, mod)
    if module_rel_name not in __all__:
        __all__.append(module_rel_name)

# ---------------------------------------------------------------------------
# Eagerly import everything at package load time
# ---------------------------------------------------------------------------

for _mod, _names in _CORE_MODULES.items():
    _import_names(_mod, _names, fatal=True)

for _mod, _names in _ADDON_MODULES.items():
    _import_names(_mod, _names, fatal=False)

# Clean up loop variables from the module namespace
del _mod, _names

# ---------------------------------------------------------------------------
# Convenience aliases & derived constants
# ---------------------------------------------------------------------------

# Alias the most commonly used entry points under short names
# so addons can write:  from cppcheckdata_shims import IV, CG
IV = IntervalDomain          # noqa: F821  (bound dynamically above)
CG = CallGraph               # noqa: F821

__all__ += ["IV", "CG"]

# ---------------------------------------------------------------------------
# Package-level utilities
# ---------------------------------------------------------------------------

def list_submodules() -> List[str]:
    """Return the names of all submodules in the package (core + addon)."""
    return sorted(set(list(_CORE_MODULES.keys()) + list(_ADDON_MODULES.keys())))


def substrate_info() -> dict:
    """Return a dict of metadata about the abstract execution substrate.

    Useful for logging/diagnostics inside addons.
    """
    loaded = []
    missing = []
    for mod_name in list_submodules():
        fq = f"{__name__}.{mod_name}"
        if fq in sys.modules:
            loaded.append(mod_name)
        else:
            missing.append(mod_name)

    return {
        "package": __name__,
        "version": __version__,
        "python": sys.version,
        "loaded_submodules": loaded,
        "missing_submodules": missing,
        "all_exports": list(__all__),
    }


__all__ += ["list_submodules", "substrate_info", "__version__"]

# ---------------------------------------------------------------------------
# TYPE_CHECKING block — gives IDEs full visibility without runtime cost
# ---------------------------------------------------------------------------

if TYPE_CHECKING:
    # Re-declare every symbol for static type checkers / autocompletion.
    # These imports are never executed at runtime (guarded by TYPE_CHECKING).
    from .interval import (
        Interval as Interval,
        IntervalDomain as IntervalDomain,
        TOP_INTERVAL as TOP_INTERVAL,
        BOT_INTERVAL as BOT_INTERVAL,
    )
    from .abstract_state import (
        AbstractState as AbstractState,
        AbstractStore as AbstractStore,
        MemoryRegion as MemoryRegion,
    )
    from .abstract_executor import (
        AbstractExecutor as AbstractExecutor,
        ExecutionContext as ExecutionContext,
        StepResult as StepResult,
    )
    from .cfg import (
        CFGBuilder as CFGBuilder,
        BasicBlock as BasicBlock,
        CFGEdge as CFGEdge,
        CFG as CFG,
    )
    from .callgraph import (
        CallGraph as CallGraph,
        CallGraphNode as CallGraphNode,
        CallGraphEdge as CallGraphEdge,
        tarjan_scc as tarjan_scc,
    )
    from .widening import (
        widen as widen,
        narrow as narrow,
        WideningStrategy as WideningStrategy,
        NarrowingStrategy as NarrowingStrategy,
    )
    from .fixpoint import (
        FixpointEngine as FixpointEngine,
        FixpointResult as FixpointResult,
        chaotic_iteration as chaotic_iteration,
    )
    from .ast_helpers import (
        token_to_op as token_to_op,
        scope_functions as scope_functions,
        find_loops as find_loops,
        variable_sizes as variable_sizes,
        alignment_of as alignment_of,
    )
    from .cost_algebra import (
        CostExpr as CostExpr,
        CostConst as CostConst,
        CostVar as CostVar,
        CostAdd as CostAdd,
        CostMul as CostMul,
        simplify_cost as simplify_cost,
    )
    from .domains import (
        SignDomain as SignDomain,
        ParityDomain as ParityDomain,
        CongruenceDomain as CongruenceDomain,
    )
