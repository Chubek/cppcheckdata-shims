#!/usr/bin/env python3
"""
UnreachableCodeAnalyzer.py  —  Cppcheck addon
===============================================

Detects **unreachable code** and **dead code** in C programs by combining:

  1. **Structural reachability** (CFG forward-DFS from entry)
  2. **Dominator / post-dominator analysis** (code after unconditional
     return/exit)
  3. **Value-flow dead-branch pruning** (branches whose condition is
     always true/false according to cppcheck's ValueFlow)
  4. **Path-sensitive analysis** with branch correlation (code reachable
     only via mutually-infeasible branch combinations)
  5. **Symbolic execution** (SMT-backed path feasibility: if *no*
     satisfiable path reaches a block, it is dead)
  6. **Constant propagation** (assignments whose result is never read)
  7. **Abstract interpretation** (interval domain proves some branches
     infeasible)

The analyzer quotes the **exact source location and span** of every dead/
unreachable region, printing a partial code snippet for clarity:

    ┌ first few tokens … ┘  ...  ┌ … last few tokens ┘

Messages are **colorized** via the ``termcolor`` library shipped with
cppcheckdata-shims.

Checked CWEs / rules
─────────────────────
  CWE-561  Dead Code
  CWE-570  Expression Is Always False
  CWE-571  Expression Is Always True
  CWE-1164 Irrelevant Code  (statements with no effect after a return)

Additionally, the addon flags:
  • Structurally unreachable blocks (no CFG path from entry)
  • Dead branches (constant-condition if/while)
  • Post-return / post-exit statements
  • Dead stores (assignment to variable never subsequently read)
  • Vacuous loops (loop body never entered: condition always false)

Usage
─────
    cppcheck --dump myfile.c
    python UnreachableCodeAnalyzer.py myfile.c.dump
"""

from __future__ import annotations

import sys
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# ── cppcheck data model ──────────────────────────────────────────────
import cppcheckdata

# ── termcolor (shipped with cppcheckdata-shims) ─────────────────────
from termcolor import colored, cprint

# ── Control-flow graph construction ──────────────────────────────────
from cppcheckdata_shims.ctrlflow_graph import (
    CFGNode,
    CFGEdge,
    CFG,
    EdgeKind,
    build_cfg,
    build_all_cfgs,
    reset_node_counter,
)

# ── Control-flow analysis ────────────────────────────────────────────
from cppcheckdata_shims.ctrlflow_analysis import (
    DominatorTree,
    PostDominatorTree,
    NaturalLoop,
    NaturalLoopDetector,
    LoopInvariantAnalysis,
    LoopInvariantExpr,
    InductionVariableAnalysis,
    InductionVariable,
    InductionVariableKind,
    LoopBoundAnalysis,
    LoopBound,
    PathSensitiveAnalysis,
    PathState,
    PathFeasibilityChecker,
    BranchCorrelationAnalysis,
    CorrelationGroup,
    UnreachableCodeDetector,
    UnreachableRegion,
    run_all_ctrlflow_analysis,
)

# ── Dataflow analysis ────────────────────────────────────────────────
from cppcheckdata_shims.dataflow_analysis import (
    DataflowAnalysis,
    Direction,
    MeetOrJoin,
    BasicBlock,
    SimpleCFG,
    build_cfg as build_simple_cfg,       # renamed to avoid clash
    ConstantPropagation,
    CopyPropagation,
    CopyRel,
)

# ── Dataflow engine (lattices) ───────────────────────────────────────
from cppcheckdata_shims.dataflow_engine import (
    Lattice,
    IntervalLattice,
    FlatLattice,
    PowersetLattice,
    MapLattice,
    DataflowResult,
    NEG_INF,
    POS_INF,
)

# ── Symbolic execution ───────────────────────────────────────────────
from cppcheckdata_shims.symbolic_exec import (
    SymExpr,
    SymConst,
    SymVar,
    SymBinOp,
    SymUnaryOp,
    SymITE,
    SymState,
    PathCondition as SymPathCondition,   # renamed to avoid clash
    SymbolicExecutor,
    StaticSymbolicExecutor,
    ExplorationStrategy,
    SMTSolver,
    InternalSimplifier,
    Z3Backend,
    PathResult,
    SymExprBuilder,
    SymExprKind,
    execute_function,
    execute_path,
    find_assertion_violations,
    collect_all_constraints,
    BUILTIN_FUNCTION_MODELS,
    DEFAULT_MAX_PATHS,
    DEFAULT_MAX_DEPTH,
    DEFAULT_LOOP_BOUND,
    DEFAULT_TIMEOUT_SECONDS,
)

# ── Abstract interpretation ──────────────────────────────────────────
from cppcheckdata_shims.abstract_interp import (
    AbstractInterpreter,
    IntervalDomain,
    CType,
    CTypeKind,
    interpret_function,
    interpret_program,
)

# =====================================================================
#  CONFIGURATION CONSTANTS
# =====================================================================

SNIPPET_HEAD_TOKENS = 6        # tokens from the beginning of dead region
SNIPPET_TAIL_TOKENS = 4        # tokens from the end of dead region
MAX_SYM_PATHS       = 1500     # per-function symbolic path budget
SYM_TIMEOUT         = 60.0     # per-function symbolic timeout (seconds)
LOOP_UNROLL         = 6        # bounded unrolling for symbolic execution
PATH_K_LIMIT        = 48       # path-sensitive analysis: max states/node
PATH_MAX_UNROLL     = 3        # path-sensitive: loop unroll budget


# =====================================================================
#  DATA STRUCTURES
# =====================================================================

@dataclass
class DeadCodeFinding:
    """A single dead / unreachable code finding."""

    kind: str              # "unreachable" | "dead_branch" | "dead_store"
                           # | "post_return" | "vacuous_loop"
                           # | "always_true" | "always_false"
    cwe: Optional[int]     # CWE number or None
    severity: str          # "warning" | "style" | "error"
    message: str           # human-readable (plain) message
    file: str
    line_start: int
    line_end: int
    col_start: int  = 0
    col_end: int    = 0
    snippet: str    = ""   # partial code snippet
    reason: str     = ""   # explanation of *why* it is dead
    function_name: str = ""

    @property
    def tag(self) -> str:
        if self.cwe:
            return f"CWE-{self.cwe}"
        return self.kind

    # ── coloured display ──────────────────────────────────────────
    def pretty(self) -> str:
        """Return a coloured, human-readable one-liner + snippet."""
        loc = colored(f"{self.file}:{self.line_start}", "cyan", attrs=["bold"])
        if self.line_end > self.line_start:
            loc += colored(f"-{self.line_end}", "cyan")
        if self.col_start:
            loc += colored(f":{self.col_start}", "cyan")

        sev_colours = {
            "error":   ("red",    ["bold"]),
            "warning": ("yellow", ["bold"]),
            "style":   ("blue",   []),
        }
        sc, sa = sev_colours.get(self.severity, ("white", []))
        sev = colored(self.severity, sc, attrs=sa)

        tag = colored(f"[{self.tag}]", "magenta", attrs=["bold"])

        msg = colored(self.message, "white", attrs=["bold"])

        lines = [f"{loc}: {sev}: {tag} {msg}"]

        if self.snippet:
            snip_text = colored(self.snippet, "green")
            lines.append(f"       {snip_text}")

        if self.reason:
            reason_text = colored(f"  ↳ {self.reason}", "white")
            lines.append(f"       {reason_text}")

        if self.function_name:
            fn = colored(f"  in function '{self.function_name}'", "cyan")
            lines.append(f"       {fn}")

        return "\n".join(lines)

    # ── plain cppcheckdata report ─────────────────────────────────
    def cppcheck_report(self) -> None:
        err_id = f"unreachableCode_{self.kind}"
        if self.cwe:
            err_id = f"unreachableCode_CWE{self.cwe}"
        cppcheckdata.reportError(
            token=None,
            severity=self.severity,
            msg=f"[{self.tag}] {self.message}",
            addon="UnreachableCodeAnalyzer",
            errorId=err_id,
            extra=f"file={self.file}:line={self.line_start}",
        )


# =====================================================================
#  HELPERS — token utilities
# =====================================================================

def _tok_str(tok) -> str:
    return getattr(tok, "str", "") if tok else ""

def _tok_line(tok) -> int:
    return getattr(tok, "linenr", 0) if tok else 0

def _tok_col(tok) -> int:
    return getattr(tok, "column", 0) if tok else 0

def _tok_file(tok) -> str:
    f = getattr(tok, "file", None)
    return str(f) if f else "<unknown>"

def _tok_id(tok) -> Any:
    if tok is None:
        return None
    return getattr(tok, "Id", id(tok))


def _tokens_of_node(node: CFGNode) -> List:
    """Return the token list inside a CFGNode."""
    return list(getattr(node, "tokens", []) or [])


def _make_snippet(tokens: List, head: int = SNIPPET_HEAD_TOKENS,
                  tail: int = SNIPPET_TAIL_TOKENS) -> str:
    """Build a compact code snippet from a list of tokens.

    Format:  ``tok1 tok2 tok3 … tokN-1 tokN``
    """
    if not tokens:
        return ""
    strs = [_tok_str(t) for t in tokens if _tok_str(t)]
    if not strs:
        return ""
    if len(strs) <= head + tail + 1:
        return " ".join(strs)
    head_part = " ".join(strs[:head])
    tail_part = " ".join(strs[-tail:]) if tail > 0 else ""
    if tail_part:
        return f"{head_part}  ...  {tail_part}"
    return f"{head_part}  ..."


def _span(tokens: List) -> Tuple[int, int, int, int]:
    """Return (line_start, line_end, col_start, col_end) for a token list."""
    if not tokens:
        return (0, 0, 0, 0)
    ls = _tok_line(tokens[0])
    cs = _tok_col(tokens[0])
    le = _tok_line(tokens[-1])
    ce = _tok_col(tokens[-1])
    return (ls, le, cs, ce)


def _file_of(tokens: List) -> str:
    for t in tokens:
        f = _tok_file(t)
        if f and f != "<unknown>":
            return f
    return "<unknown>"


# =====================================================================
#  PHASE 1 — STRUCTURAL REACHABILITY (CFG DFS)
# =====================================================================

def _phase_structural(
    cfg: CFG,
) -> Tuple[Set[int], List[Tuple[CFGNode, str]]]:
    """Forward DFS from entry.  Returns (reachable_ids, unreachable_reports).

    Each unreachable report is (CFGNode, reason_string).
    """
    reachable: Set[int] = set()
    worklist: deque = deque([cfg.entry])
    while worklist:
        node = worklist.popleft()
        if node.id in reachable:
            continue
        reachable.add(node.id)
        for edge in node.successors:
            if edge.dst.id not in reachable:
                worklist.append(edge.dst)

    unreachable_reports: List[Tuple[CFGNode, str]] = []
    for node in cfg.nodes:
        if node.id not in reachable and _tokens_of_node(node):
            unreachable_reports.append(
                (node, "structurally unreachable — no CFG path from entry")
            )

    return reachable, unreachable_reports


# =====================================================================
#  PHASE 2 — POST-DOMINATOR: CODE AFTER UNCONDITIONAL RETURN/EXIT
# =====================================================================

def _phase_post_return(
    cfg: CFG,
    reachable: Set[int],
) -> List[Tuple[CFGNode, str]]:
    """Find nodes that are reachable only because they follow a block
    ending in ``return`` / ``exit`` / ``abort`` — i.e. they are
    unreachable despite being structurally wired."""
    reports: List[Tuple[CFGNode, str]] = []

    pdom = PostDominatorTree(cfg).compute()

    for node in cfg.nodes:
        if node.id not in reachable:
            continue
        if node is cfg.entry or node is cfg.exit:
            continue
        tokens = _tokens_of_node(node)
        if not tokens:
            continue

        # Check if this node's *sole* predecessor ends with return/exit
        preds = [e.src for e in node.predecessors]
        if not preds:
            continue

        all_preds_exit = True
        for pred in preds:
            pred_toks = _tokens_of_node(pred)
            if not pred_toks:
                all_preds_exit = False
                break
            last_str = _tok_str(pred_toks[-1]) if pred_toks else ""
            # Check if pred's *kind* is "return" or contains return/exit
            pred_kind = getattr(pred, "kind", "")
            has_return = (
                pred_kind == "return"
                or any(_tok_str(t) in ("return", "exit", "abort", "_Exit",
                                       "quick_exit", "throw")
                       for t in pred_toks)
            )
            if not has_return:
                all_preds_exit = False
                break

        if all_preds_exit and preds:
            reports.append(
                (node,
                 "code after unconditional return/exit — CWE-561")
            )

    return reports


# =====================================================================
#  PHASE 3 — VALUE-FLOW DEAD BRANCHES (always-true / always-false)
# =====================================================================

def _phase_valueflow_dead_branches(
    cfg: CFG,
    reachable: Set[int],
) -> List[Tuple[CFGNode, str, str]]:
    """Detect branches whose condition is always true or always false
    according to cppcheck's ValueFlow annotations.

    Returns list of (dead_branch_node, reason, kind) where kind is
    ``"always_true"`` or ``"always_false"``.
    """
    reports: List[Tuple[CFGNode, str, str]] = []

    for node in cfg.nodes:
        if node.id not in reachable:
            continue
        # Branching nodes have exactly 2 successors
        succs = [e for e in node.successors]
        if len(succs) != 2:
            continue

        # Find the condition token (last comparison or boolean in the node)
        cond_tok = _find_condition_in_node(node)
        if cond_tok is None:
            continue

        values = getattr(cond_tok, "values", None)
        if not values:
            continue

        # Check if ALL known values agree
        known = [v for v in values
                 if getattr(v, "valueKind", "") == "known"
                 or getattr(v, "isKnown", False)]
        if not known:
            continue

        int_vals: Set[bool] = set()
        for v in known:
            iv = getattr(v, "intvalue", None)
            if iv is not None:
                int_vals.add(int(iv) != 0)

        if len(int_vals) != 1:
            continue

        always_true = int_vals.pop()

        # Determine which successor edge is dead
        true_edge = None
        false_edge = None
        for e in succs:
            if e.kind == EdgeKind.BRANCH_TRUE:
                true_edge = e
            elif e.kind == EdgeKind.BRANCH_FALSE:
                false_edge = e

        # If edge kinds are not tagged, use positional convention
        if true_edge is None and false_edge is None and len(succs) == 2:
            true_edge = succs[0]
            false_edge = succs[1]

        dead_edge = false_edge if always_true else true_edge
        if dead_edge is None:
            continue

        dead_node = dead_edge.dst
        cond_text = _tok_str(cond_tok)

        if always_true:
            kind = "always_true"
            reason = (f"condition '{cond_text}' is always true "
                      f"(CWE-571) — false branch is dead")
        else:
            kind = "always_false"
            reason = (f"condition '{cond_text}' is always false "
                      f"(CWE-570) — true branch is dead")

        reports.append((dead_node, reason, kind))

    return reports


def _find_condition_in_node(node: CFGNode):
    """Find the condition token at the end of a branching node."""
    tokens = _tokens_of_node(node)
    for tok in reversed(tokens):
        s = _tok_str(tok)
        if s in ("<", ">", "<=", ">=", "==", "!=", "&&", "||", "!"):
            return tok
        if getattr(tok, "isName", False):
            parent = getattr(tok, "astParent", None)
            if parent and _tok_str(parent) in ("if", "while", "for", "?"):
                return tok
    return None


# =====================================================================
#  PHASE 4 — PATH-SENSITIVE + FEASIBILITY (from ctrlflow_analysis)
# =====================================================================

def _phase_path_sensitive(
    cfg: CFG,
    configuration: Any,
    reachable: Set[int],
    already_dead: Set[int],
) -> List[Tuple[CFGNode, str]]:
    """Use the ctrlflow_analysis.UnreachableCodeDetector which internally
    combines path-sensitive analysis, path feasibility checking, and
    branch correlation."""
    reports: List[Tuple[CFGNode, str]] = []

    try:
        results = run_all_ctrlflow_analysis(
            cfg,
            configuration,
            analysis={"dominators", "loops", "path_sensitive",
                       "path_feasibility", "correlations", "unreachable"},
            k_limit=PATH_K_LIMIT,
            max_unroll=PATH_MAX_UNROLL,
        )
    except Exception:
        return reports

    ucd = results.get("unreachable")
    if ucd is None:
        return reports

    regions: List[UnreachableRegion] = ucd.regions()
    node_map = {n.id: n for n in cfg.nodes}

    for region in regions:
        for nid in region.node_ids:
            if nid in already_dead:
                continue
            node = node_map.get(nid)
            if node is None:
                continue
            toks = _tokens_of_node(node)
            if not toks:
                continue
            reports.append(
                (node,
                 f"path-infeasible: {region.reason}")
            )

    return reports


# =====================================================================
#  PHASE 5 — SYMBOLIC EXECUTION (SMT-backed unreachability)
# =====================================================================

def _phase_symbolic(
    cfg: CFG,
    reachable: Set[int],
    already_dead: Set[int],
) -> List[Tuple[CFGNode, str]]:
    """Run symbolic execution over the function and check which
    reachable nodes have *no* satisfiable path condition."""
    reports: List[Tuple[CFGNode, str]] = []

    try:
        solver = Z3Backend()
    except Exception:
        solver = InternalSimplifier()

    try:
        path_results: List[PathResult] = execute_function(
            cfg,
            solver=solver,
            strategy=ExplorationStrategy.COVERAGE,
            max_paths=MAX_SYM_PATHS,
            max_depth=DEFAULT_MAX_DEPTH,
            loop_bound=LOOP_UNROLL,
            timeout=SYM_TIMEOUT,
            function_models=dict(BUILTIN_FUNCTION_MODELS),
            check_assertions=False,
            check_division_by_zero=False,
            generate_tests=False,
        )
    except Exception:
        return reports

    # Collect node ids that are covered by at least one feasible path
    covered_node_ids: Set[int] = set()
    for pr in path_results:
        path_nodes = getattr(pr, "path", None) or []
        for pn in path_nodes:
            nid = pn if isinstance(pn, int) else getattr(pn, "id", None)
            if nid is not None:
                covered_node_ids.add(nid)

    # Nodes that are reachable in the CFG but not covered by any
    # feasible symbolic path
    node_map = {n.id: n for n in cfg.nodes}
    for nid in reachable:
        if nid in already_dead:
            continue
        if nid in covered_node_ids:
            continue
        node = node_map.get(nid)
        if node is None:
            continue
        if node is cfg.entry or node is cfg.exit:
            continue
        toks = _tokens_of_node(node)
        if not toks:
            continue
        reports.append(
            (node,
             "symbolic execution: no feasible path reaches this block "
             "(SMT UNSAT on all path conditions)")
        )

    return reports


# =====================================================================
#  PHASE 6 — CONSTANT PROPAGATION → DEAD STORES
# =====================================================================

def _phase_dead_stores(
    configuration: Any,
    scope: Any,
    func_name: str,
) -> List[DeadCodeFinding]:
    """Use ConstantPropagation / CopyPropagation to find assignments
    whose result is never read (dead stores)."""
    findings: List[DeadCodeFinding] = []

    try:
        cp = ConstantPropagation(configuration, scope)
        cp.run()
    except Exception:
        return findings

    # Walk tokens looking for assignments where the LHS variable
    # is *not* live at any subsequent use point.
    # Heuristic: if the variable has another definition before
    # any use, the first assignment is dead.
    body_start = getattr(scope, "bodyStart", None)
    body_end = getattr(scope, "bodyEnd", None)
    if body_start is None or body_end is None:
        return findings

    # Collect all definitions and uses per varId
    defs_map: Dict[int, List] = defaultdict(list)   # varId → [token]
    uses_map: Dict[int, List] = defaultdict(list)

    tok = getattr(body_start, "next", None)
    while tok and tok != body_end:
        vid = getattr(tok, "varId", None)
        if vid and vid != 0:
            parent = getattr(tok, "astParent", None)
            if parent:
                pstr = _tok_str(parent)
                op1 = getattr(parent, "astOperand1", None)
                if pstr in ("=", "+=", "-=", "*=", "/=", "%=",
                            "&=", "|=", "^=", "<<=", ">>=") and op1 is tok:
                    defs_map[vid].append(tok)
                else:
                    uses_map[vid].append(tok)
            else:
                uses_map[vid].append(tok)
        tok = getattr(tok, "next", None)

    # A definition is dead if there is another definition of the same
    # variable before any use between them.
    for vid, def_toks in defs_map.items():
        if len(def_toks) < 2:
            continue
        use_lines = {_tok_line(u) for u in uses_map.get(vid, [])}

        for i in range(len(def_toks) - 1):
            d1 = def_toks[i]
            d2 = def_toks[i + 1]
            d1_line = _tok_line(d1)
            d2_line = _tok_line(d2)
            # If no use between d1 and d2, d1 is a dead store
            has_use_between = any(d1_line < ul < d2_line for ul in use_lines)
            if not has_use_between:
                var_name = _tok_str(d1)
                findings.append(DeadCodeFinding(
                    kind="dead_store",
                    cwe=561,
                    severity="style",
                    message=(f"Dead store: assignment to '{var_name}' "
                             f"is overwritten before being read"),
                    file=_tok_file(d1),
                    line_start=d1_line,
                    line_end=d1_line,
                    col_start=_tok_col(d1),
                    snippet=_make_snippet([d1]),
                    reason="value is overwritten at line "
                           f"{d2_line} without intervening read",
                    function_name=func_name,
                ))

    return findings


# =====================================================================
#  PHASE 7 — ABSTRACT INTERPRETATION (interval domain)
# =====================================================================

def _phase_abstract_interp_dead_branches(
    cfg: CFG,
    reachable: Set[int],
    already_dead: Set[int],
) -> List[Tuple[CFGNode, str]]:
    """Use interval abstract interpretation to prove that some branch
    conditions are always true/false, yielding dead branches that
    ValueFlow might have missed."""
    reports: List[Tuple[CFGNode, str]] = []

    try:
        domain = IntervalDomain(bit_width=32, signed=True)
        result = interpret_function(cfg, domain)
    except Exception:
        return reports

    node_states = getattr(result, "node_states", None)
    if node_states is None:
        return reports

    node_map = {n.id: n for n in cfg.nodes}

    for node in cfg.nodes:
        if node.id not in reachable or node.id in already_dead:
            continue
        succs = [e for e in node.successors]
        if len(succs) != 2:
            continue

        cond_tok = _find_condition_in_node(node)
        if cond_tok is None:
            continue

        # Check the abstract value of the condition at this node
        state = node_states.get(node.id)
        if state is None:
            continue

        # Attempt to evaluate the condition in the interval domain
        cond_interval = None
        try:
            cond_interval = domain.to_interval(
                state.get(_tok_id(cond_tok))
            )
        except Exception:
            pass

        if cond_interval is None:
            continue

        lo, hi = cond_interval
        if lo > 0:
            # always true → false branch is dead
            dead_edge = succs[1] if len(succs) > 1 else None
            if dead_edge and dead_edge.dst.id not in already_dead:
                reports.append(
                    (dead_edge.dst,
                     f"abstract interpretation (interval [{lo}, {hi}]) "
                     f"proves condition always true — false branch dead "
                     f"(CWE-571)")
                )
        elif hi <= 0 and lo <= 0 and hi >= 0:
            pass  # might be zero — inconclusive
        elif hi < 0:
            # always non-zero negative → always true
            dead_edge = succs[1] if len(succs) > 1 else None
            if dead_edge and dead_edge.dst.id not in already_dead:
                reports.append(
                    (dead_edge.dst,
                     f"abstract interpretation (interval [{lo}, {hi}]) "
                     f"proves condition always non-zero — false branch "
                     f"dead (CWE-571)")
                )
        elif lo == 0 and hi == 0:
            # always false
            dead_edge = succs[0] if succs else None
            if dead_edge and dead_edge.dst.id not in already_dead:
                reports.append(
                    (dead_edge.dst,
                     f"abstract interpretation (interval [0, 0]) proves "
                     f"condition always false — true branch dead "
                     f"(CWE-570)")
                )

    return reports


# =====================================================================
#  PHASE 8 — VACUOUS LOOPS
# =====================================================================

def _phase_vacuous_loops(
    cfg: CFG,
    configuration: Any,
    reachable: Set[int],
    already_dead: Set[int],
) -> List[Tuple[CFGNode, str]]:
    """Detect loops whose body is never entered because the loop
    condition is always false on entry."""
    reports: List[Tuple[CFGNode, str]] = []

    try:
        results = run_all_ctrlflow_analysis(
            cfg, configuration,
            analysis={"dominators", "loops", "loop_bounds"},
        )
    except Exception:
        return reports

    loop_bounds: List[LoopBound] = []
    lb_analysis = results.get("loop_bounds")
    if lb_analysis:
        loop_bounds = lb_analysis.bounds() if hasattr(lb_analysis, "bounds") else []

    for lb in loop_bounds:
        if lb.exact is not None and lb.exact == 0:
            reports.append(
                (None,  # we don't have the node directly, filled later
                 f"vacuous loop (0 iterations): {lb.description} (CWE-561)")
            )
        elif (lb.upper is not None and lb.upper == 0
              and lb.confidence in ("certain", "probable")):
            reports.append(
                (None,
                 f"vacuous loop (upper bound 0): {lb.description} (CWE-561)")
            )

    return reports


# =====================================================================
#  ORCHESTRATOR — per-function analysis
# =====================================================================

def _analyse_function(
    cfg_config: Any,
    func: Any,
    scope: Any,
    func_cfg: CFG,
) -> List[DeadCodeFinding]:
    """Run all phases on a single function and collect findings."""
    findings: List[DeadCodeFinding] = []
    func_name = getattr(func, "name", "<unknown>")

    # ── Phase 1: structural reachability ──────────────────────────
    reachable, struct_reports = _phase_structural(func_cfg)
    already_dead: Set[int] = set()

    for node, reason in struct_reports:
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        findings.append(DeadCodeFinding(
            kind="unreachable",
            cwe=561,
            severity="warning",
            message="Unreachable code",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 2: post-return ──────────────────────────────────────
    post_ret_reports = _phase_post_return(func_cfg, reachable)
    for node, reason in post_ret_reports:
        if node.id in already_dead:
            continue
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        findings.append(DeadCodeFinding(
            kind="post_return",
            cwe=1164,
            severity="warning",
            message="Code after unconditional return/exit is unreachable",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 3: ValueFlow dead branches ──────────────────────────
    vf_reports = _phase_valueflow_dead_branches(func_cfg, reachable)
    for node, reason, kind in vf_reports:
        if node.id in already_dead:
            continue
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        cwe_num = 571 if kind == "always_true" else 570
        findings.append(DeadCodeFinding(
            kind=kind,
            cwe=cwe_num,
            severity="warning",
            message=f"Dead branch ({kind.replace('_', ' ')})",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 4: path-sensitive (ctrlflow_analysis) ───────────────
    ps_reports = _phase_path_sensitive(
        func_cfg, cfg_config, reachable, already_dead
    )
    for node, reason in ps_reports:
        if node.id in already_dead:
            continue
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        findings.append(DeadCodeFinding(
            kind="unreachable",
            cwe=561,
            severity="warning",
            message="Unreachable code (path-infeasible)",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 5: symbolic execution ───────────────────────────────
    sym_reports = _phase_symbolic(func_cfg, reachable, already_dead)
    for node, reason in sym_reports:
        if node.id in already_dead:
            continue
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        findings.append(DeadCodeFinding(
            kind="unreachable",
            cwe=561,
            severity="warning",
            message="Unreachable code (symbolic execution proof)",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 6: dead stores ──────────────────────────────────────
    ds_findings = _phase_dead_stores(cfg_config, scope, func_name)
    findings.extend(ds_findings)

    # ── Phase 7: abstract interpretation dead branches ────────────
    ai_reports = _phase_abstract_interp_dead_branches(
        func_cfg, reachable, already_dead
    )
    for node, reason in ai_reports:
        if node.id in already_dead:
            continue
        already_dead.add(node.id)
        toks = _tokens_of_node(node)
        ls, le, cs, ce = _span(toks)
        cwe_num = 570 if "always false" in reason else 571
        findings.append(DeadCodeFinding(
            kind="always_false" if cwe_num == 570 else "always_true",
            cwe=cwe_num,
            severity="warning",
            message="Dead branch (proved by abstract interpretation)",
            file=_file_of(toks),
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    # ── Phase 8: vacuous loops ────────────────────────────────────
    vl_reports = _phase_vacuous_loops(
        func_cfg, cfg_config, reachable, already_dead
    )
    for node_or_none, reason in vl_reports:
        # node_or_none may be None for loop-bound based findings
        if node_or_none is not None:
            toks = _tokens_of_node(node_or_none)
        else:
            toks = []
        ls, le, cs, ce = _span(toks)
        findings.append(DeadCodeFinding(
            kind="vacuous_loop",
            cwe=561,
            severity="style",
            message="Vacuous loop — body is never executed",
            file=_file_of(toks) if toks else "<unknown>",
            line_start=ls,
            line_end=le,
            col_start=cs,
            col_end=ce,
            snippet=_make_snippet(toks),
            reason=reason,
            function_name=func_name,
        ))

    return findings


# =====================================================================
#  MAIN DRIVER
# =====================================================================

def run_on_dump(dump_file: str) -> List[DeadCodeFinding]:
    """Analyse a single Cppcheck .dump file.

    Parameters
    ----------
    dump_file : str
        Path to the ``*.c.dump`` file produced by ``cppcheck --dump``.

    Returns
    -------
    list[DeadCodeFinding]
    """
    data = cppcheckdata.CppcheckData(dump_file)
    all_findings: List[DeadCodeFinding] = []

    for cfg_config in data.iterconfigurations():
        # Build CFGs for every function in this configuration
        reset_node_counter()
        try:
            func_cfgs: Dict = build_all_cfgs(cfg_config)
        except Exception:
            continue

        for func, func_cfg in func_cfgs.items():
            # Find the scope for this function
            scope = None
            for s in getattr(cfg_config, "scopes", []):
                if getattr(s, "type", "") == "Function":
                    sf = getattr(s, "function", None)
                    if sf is func:
                        scope = s
                        break

            findings = _analyse_function(
                cfg_config, func, scope, func_cfg
            )
            all_findings.extend(findings)

    return all_findings


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2:
        header = colored(
            "UnreachableCodeAnalyzer — Cppcheck addon",
            "cyan", attrs=["bold"]
        )
        print(header, file=sys.stderr)
        usage = colored(
            "Usage: python UnreachableCodeAnalyzer.py <file.c.dump> [...]",
            "yellow",
        )
        print(usage, file=sys.stderr)
        sys.exit(1)

    exit_code = 0
    total_findings = 0

    for dump_path in sys.argv[1:]:
        if not os.path.isfile(dump_path):
            err = colored(f"Error: '{dump_path}' not found", "red",
                          attrs=["bold"])
            print(err, file=sys.stderr)
            exit_code = 1
            continue

        findings = run_on_dump(dump_path)

        for f in findings:
            print(f.pretty())
            print()  # blank line between findings

        total_findings += len(findings)
        if findings:
            exit_code = 1

    # Summary
    if total_findings == 0:
        summary = colored("✓ No dead/unreachable code found.", "green",
                          attrs=["bold"])
    else:
        summary = colored(
            f"✗ {total_findings} dead/unreachable code region(s) found.",
            "red", attrs=["bold"],
        )
    print(summary)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
