#!/usr/bin/env python3
"""
DeadStoreDetector.py
════════════════════

Cppcheck addon that detects dead stores (definitions of variables whose
values are never subsequently read) using the Program Dependency Graph
(PDG) from ``cppcheckdata_shims.dependency_graph``.

Detected patterns
─────────────────

  DS-001  Dead store — value assigned but never used before redefinition
          or end of scope.
          CWE-563: Assignment to Variable without Use

  DS-002  Unused initialisation — variable initialised at declaration but
          value is never read.
          CWE-563: Assignment to Variable without Use

  DS-003  Overwritten parameter — function parameter reassigned before
          first use of the original value.
          CWE-563: Assignment to Variable without Use

  DS-004  Write-after-write — two consecutive definitions of the same
          variable with no intervening read (OUTPUT dependence).
          CWE-563: Assignment to Variable without Use

  DS-005  Dead store before return — variable written on a path that
          immediately leads to a return without reading the variable.
          CWE-563: Assignment to Variable without Use

  DS-006  Self-assignment — variable assigned to itself (``x = x;``).
          CWE-561: Dead Code

  DS-007  Unused variable — variable defined but never appears in any
          use set across the entire function.
          CWE-563: Assignment to Variable without Use

Usage
─────

    # With cppcheck (--dump produces the .dump XML):
    cppcheck --dump myfile.c
    python DeadStoreDetector.py myfile.c.dump

    # Standalone (direct .dump path):
    python DeadStoreDetector.py path/to/myfile.c.dump

    # With CASL integration:
    casl run DeadStoreDetector.casl -- myfile.c.dump

Configuration
─────────────

    --severity=<level>      Minimum severity: style, warning, error
                            (default: style)
    --suppress=<DS-NNN,...>  Comma-separated list of check IDs to suppress
    --max-tokens=<N>        Skip functions with more than N tokens
                            (default: 50000)
    --include-anti          Include anti-dependence (WAR) analysis
    --include-output        Include output-dependence (WAW) analysis
    --dot-output=<dir>      Write DOT graph files to directory for debugging
    --verbose               Print analysis progress to stderr

Theory
──────

    A dead store is a definition  d: v = e  at program point p such that
    no use of v is reachable from p via a def-clear path for v in the CFG.

    In PDG terms:  d has **no outgoing DATA edge** for variable v — the
    reaching-definitions analysis found no use that this definition reaches.

    Reference:
      - Muchnick, "Advanced Compiler Design and Implementation" (1997), §8.4
      - Aho, Lam, Sethi, Ullman, "Compilers" (2nd ed.), §9.2.4
      - CWE-563: Assignment to Variable without Use (MITRE)

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

# ─────────────────────────────────────────────────────────────────────────
#  External imports — cppcheckdata for dump parsing
# ─────────────────────────────────────────────────────────────────────────

try:
    import cppcheckdata
except ImportError:
    # Allow running from repository root
    _here = os.path.dirname(os.path.abspath(__file__))
    _parent = os.path.dirname(_here)
    if _parent not in sys.path:
        sys.path.insert(0, _parent)
    import cppcheckdata

# ─────────────────────────────────────────────────────────────────────────
#  Shims imports — dependency graph module
# ─────────────────────────────────────────────────────────────────────────

try:
    from cppcheckdata_shims.dependency_graph import (
        DependencyGraph,
        DependencyGraphBuilder,
        DepEdge,
        DepKind,
        DepNode,
        build_from_dump,
        def_use_chains,
        find_unused_definitions,
        slice_backward,
        slice_forward,
    )
except ImportError:
    sys.stderr.write(
        "ERROR: cppcheckdata_shims.dependency_graph not found.\n"
        "       Ensure the cppcheckdata-shims library is installed.\n"
    )
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 0 — FINDING DATA STRUCTURE
# ═══════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class Finding:
    """
    A single dead-store finding to be reported.

    Attributes
    ----------
    check_id : str
        The check identifier (DS-001 through DS-007).
    file : str
        Source file path.
    line : int
        Source line number.
    column : int
        Source column number.
    severity : str
        One of: 'style', 'warning', 'error'.
    message : str
        Human-readable description.
    variable : str
        The variable name involved.
    cwe : int
        CWE identifier (563 or 561).
    function : str
        Enclosing function name.
    node_id : int
        The DepNode id (for deduplication).
    """
    check_id: str
    file: str
    line: int
    column: int
    severity: str
    message: str
    variable: str
    cwe: int = 563
    function: str = ""
    node_id: int = 0

    def format_cppcheck(self) -> str:
        """Format as cppcheck-compatible addon output."""
        return (
            f"[{self.file}:{self.line}:{self.column}] "
            f"({self.severity}) "
            f"{self.check_id}: {self.message} "
            f"[CWE-{self.cwe}]"
        )

    def format_gcc(self) -> str:
        """Format as GCC-style diagnostic."""
        return (
            f"{self.file}:{self.line}:{self.column}: "
            f"{self.severity}: {self.message} "
            f"[-W{self.check_id}]"
        )

    @property
    def dedup_key(self) -> Tuple[str, int, int, str, str]:
        """Key for deduplication."""
        return (self.file, self.line, self.column, self.check_id, self.variable)


# ═══════════════════════════════════════════════════════════════════════════
#  PART 1 — SUPPRESSION AND FILTERING
# ═══════════════════════════════════════════════════════════════════════════

# Variables that are commonly assigned without use (e.g., error codes,
# iterators in macros).  These are suppressed by default.
_DEFAULT_IGNORE_PATTERNS: FrozenSet[str] = frozenset({
    "_",           # conventional "don't care" variable
    "__unused",
    "unused",
})

# Types whose assignments are typically side-effectful (e.g., volatile,
# atomic).  We detect these from token properties.
_SIDEEFFECT_QUALIFIERS: FrozenSet[str] = frozenset({
    "volatile",
    "_Atomic",
    "atomic",
})

# Function calls whose return values are commonly ignored intentionally
_INTENTIONAL_IGNORE_FUNCS: FrozenSet[str] = frozenset({
    "memset",
    "memcpy",
    "memmove",
    "strcpy",
    "strncpy",
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "close",
    "fclose",
    "free",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
})


def _should_suppress(
    node: DepNode,
    variable: str,
    suppressed_ids: Set[str],
    check_id: str,
) -> bool:
    """
    Determine if a finding should be suppressed.

    Suppression reasons:
      1. Check ID is in the user's suppression list.
      2. Variable name matches a "don't care" pattern.
      3. Variable is volatile or atomic (side-effectful store).
      4. The token has a cppcheck inline suppression comment.
    """
    # User-suppressed check IDs
    if check_id in suppressed_ids:
        return True

    # "Don't care" variable names
    lower_var = variable.lower()
    if lower_var in _DEFAULT_IGNORE_PATTERNS:
        return True
    if lower_var.startswith("_unused") or lower_var.startswith("unused_"):
        return True

    # Volatile / atomic — assignment has side effects
    token = node.token
    if token is not None:
        var_obj = getattr(token, "variable", None)
        if var_obj is not None:
            type_start = getattr(var_obj, "typeStartToken", None)
            t = type_start
            while t is not None:
                s = getattr(t, "str", "")
                if s in _SIDEEFFECT_QUALIFIERS:
                    return True
                type_end = getattr(var_obj, "typeEndToken", None)
                if t is type_end:
                    break
                t = getattr(t, "next", None)

    # Cppcheck inline suppression (// cppcheck-suppress deadStore)
    # Check if there's a suppression comment on the same line
    if token is not None:
        # Walk forward to check for comment tokens (not always available)
        next_tok = getattr(token, "next", None)
        while next_tok is not None:
            next_line = getattr(next_tok, "linenr", 0)
            if next_line != node.line:
                break
            s = getattr(next_tok, "str", "")
            if "cppcheck-suppress" in s and "deadStore" in s:
                return True
            next_tok = getattr(next_tok, "next", None)

    return False


# ═══════════════════════════════════════════════════════════════════════════
#  PART 2 — DEAD STORE DETECTOR ENGINE
# ═══════════════════════════════════════════════════════════════════════════


class DeadStoreDetector:
    """
    Main analysis engine.

    Builds a PDG for each function in a cppcheck configuration, then
    queries it for dead store patterns.  Each detected pattern generates
    a ``Finding`` with an appropriate check ID and message.

    Usage::

        detector = DeadStoreDetector(severity="style")
        findings = detector.analyse(cfg)
        for f in findings:
            print(f.format_cppcheck())
    """

    def __init__(
        self,
        severity: str = "style",
        suppressed_ids: Optional[Set[str]] = None,
        max_tokens: int = 50_000,
        include_anti: bool = False,
        include_output: bool = True,
        dot_output_dir: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        severity : str
            Minimum severity level: 'style', 'warning', or 'error'.
        suppressed_ids : Optional[Set[str]]
            Set of check IDs to suppress (e.g., {'DS-002', 'DS-006'}).
        max_tokens : int
            Skip functions with more than this many tokens.
        include_anti : bool
            Include ANTI dependence edges in the PDG.
        include_output : bool
            Include OUTPUT dependence edges (needed for DS-004).
        dot_output_dir : Optional[str]
            If set, write DOT files for each function's PDG.
        verbose : bool
            Print progress to stderr.
        """
        self.severity = severity
        self.suppressed_ids: Set[str] = suppressed_ids or set()
        self.max_tokens = max_tokens
        self.include_anti = include_anti
        self.include_output = include_output
        self.dot_output_dir = dot_output_dir
        self.verbose = verbose

        self._builder = DependencyGraphBuilder(
            include_anti=include_anti,
            include_output=include_output,
            include_control=True,
            max_tokens=max_tokens,
        )

    # ── Main entry point ──────────────────────────────────────────────

    def analyse(self, cfg: Any) -> List[Finding]:
        """
        Analyse one cppcheck configuration and return all findings.

        Parameters
        ----------
        cfg : cppcheckdata Configuration
            A configuration object from ``cppcheckdata.parsedump()``.

        Returns
        -------
        List[Finding]
            All dead-store findings, deduplicated.
        """
        if self.verbose:
            sys.stderr.write(f"[DeadStoreDetector] Building PDG...\n")

        pdg = self._builder.build(cfg)

        if self.verbose:
            summary = pdg.summary()
            sys.stderr.write(
                f"[DeadStoreDetector] PDG: {summary['nodes']} nodes, "
                f"{summary['edges']} edges, "
                f"{summary['dead_stores']} potential dead stores\n"
            )

        # Optionally export DOT
        if self.dot_output_dir is not None:
            self._write_dot(pdg)

        findings: List[Finding] = []

        # Run each check
        findings.extend(self._check_ds001_dead_store(pdg))
        findings.extend(self._check_ds002_unused_init(pdg, cfg))
        findings.extend(self._check_ds003_overwritten_param(pdg, cfg))
        findings.extend(self._check_ds004_write_after_write(pdg))
        findings.extend(self._check_ds005_dead_before_return(pdg))
        findings.extend(self._check_ds006_self_assignment(pdg))
        findings.extend(self._check_ds007_unused_variable(pdg))

        # Deduplicate
        findings = self._deduplicate(findings)

        if self.verbose:
            sys.stderr.write(
                f"[DeadStoreDetector] {len(findings)} findings reported\n"
            )

        return findings

    # ── DS-001: Dead store (general) ──────────────────────────────────

    def _check_ds001_dead_store(self, pdg: DependencyGraph) -> List[Finding]:
        """
        DS-001: Definition with no outgoing DATA edge.

        This is the fundamental dead-store check:  a node defines a
        variable v but no subsequent use of v is reachable via a
        def-clear path — i.e., the PDG has no DATA edge from this
        definition.
        """
        findings: List[Finding] = []
        dead_nodes = find_unused_definitions(pdg)

        for node in dead_nodes:
            for vid in node.defs:
                var_name = node.def_names.get(vid, f"var_{vid}")

                if _should_suppress(node, var_name, self.suppressed_ids, "DS-001"):
                    continue

                # Check if this specific variable has an outgoing DATA edge
                has_data_edge = any(
                    e.var_id == vid
                    for e in node.out_edges(DepKind.DATA)
                )
                if has_data_edge:
                    continue  # not dead for this variable

                # Check if it's a function call return — might have side effects
                if self._is_sideeffect_call(node):
                    continue

                findings.append(Finding(
                    check_id="DS-001",
                    file=node.file,
                    line=node.line,
                    column=node.column,
                    severity="style",
                    message=(
                        f"Dead store: variable '{var_name}' is assigned a value "
                        f"that is never read"
                    ),
                    variable=var_name,
                    cwe=563,
                    function=node.function_name,
                    node_id=node.node_id,
                ))

        return findings

    # ── DS-002: Unused initialisation ─────────────────────────────────

    def _check_ds002_unused_init(
        self,
        pdg: DependencyGraph,
        cfg: Any,
    ) -> List[Finding]:
        """
        DS-002: Variable initialised at declaration but never read.

        Distinguishes from DS-001 by looking for declaration tokens
        (type keywords preceding the assignment).
        """
        findings: List[Finding] = []

        for node in pdg.nodes:
            if not node.defs:
                continue

            # Check if this is a declaration (heuristic: previous token
            # is a type keyword or the token itself is after a type)
            token = node.token
            if token is None:
                continue

            is_decl = False
            tok_str = getattr(token, "str", "")

            # Look for declaration patterns
            prev = getattr(token, "previous", None)
            if prev is not None:
                prev_str = getattr(prev, "str", "")
                # Common type keywords and qualifiers
                if prev_str in (
                    "int", "char", "float", "double", "long", "short",
                    "unsigned", "signed", "void", "auto", "const",
                    "static", "register", "extern",
                    "size_t", "ssize_t", "uint8_t", "uint16_t",
                    "uint32_t", "uint64_t", "int8_t", "int16_t",
                    "int32_t", "int64_t", "bool", "BOOL",
                ) or prev_str.endswith("_t"):
                    is_decl = True

                # Pointer declarations: "type *var"
                if prev_str == "*":
                    pp = getattr(prev, "previous", None)
                    if pp is not None:
                        is_decl = True

            if not is_decl:
                continue

            for vid in node.defs:
                var_name = node.def_names.get(vid, f"var_{vid}")

                if _should_suppress(node, var_name, self.suppressed_ids, "DS-002"):
                    continue

                has_data_edge = any(
                    e.var_id == vid for e in node.out_edges(DepKind.DATA)
                )
                if has_data_edge:
                    continue

                if self._is_sideeffect_call(node):
                    continue

                findings.append(Finding(
                    check_id="DS-002",
                    file=node.file,
                    line=node.line,
                    column=node.column,
                    severity="style",
                    message=(
                        f"Unused initialisation: variable '{var_name}' is "
                        f"initialised but its value is never read"
                    ),
                    variable=var_name,
                    cwe=563,
                    function=node.function_name,
                    node_id=node.node_id,
                ))

        return findings

    # ── DS-003: Overwritten parameter ─────────────────────────────────

    def _check_ds003_overwritten_param(
        self,
        pdg: DependencyGraph,
        cfg: Any,
    ) -> List[Finding]:
        """
        DS-003: Function parameter reassigned before its original value
        is ever used.

        void process(int n) {
            n = 0;          // <-- DS-003: parameter 'n' overwritten
            use(n);
        }
        """
        findings: List[Finding] = []

        # Collect parameter variable IDs
        param_var_ids: Set[int] = set()
        param_names: Dict[int, str] = {}

        scopes = getattr(cfg, "scopes", [])
        for scope in scopes:
            stype = getattr(scope, "type", "")
            if stype != "Function":
                continue
            func = getattr(scope, "function", None)
            if func is None:
                continue
            arg_list = getattr(func, "argument", {})
            if isinstance(arg_list, dict):
                for _idx, arg in arg_list.items():
                    nametok = getattr(arg, "nameToken", None)
                    if nametok is not None:
                        vid = getattr(nametok, "varId", 0)
                        if vid:
                            param_var_ids.add(vid)
                            param_names[vid] = getattr(nametok, "str", f"var_{vid}")

        if not param_var_ids:
            return findings

        # For each parameter, check if the first node that touches it
        # is a definition (not a use)
        for node in pdg.nodes:
            for vid in node.defs:
                if vid not in param_var_ids:
                    continue

                var_name = param_names.get(vid, node.def_names.get(vid, f"var_{vid}"))

                if _should_suppress(node, var_name, self.suppressed_ids, "DS-003"):
                    continue

                # Check: is there any use of this parameter BEFORE this def?
                has_prior_use = False
                for other_node in pdg.nodes:
                    if other_node.node_id >= node.node_id:
                        break
                    if vid in other_node.uses:
                        has_prior_use = True
                        break

                if not has_prior_use:
                    findings.append(Finding(
                        check_id="DS-003",
                        file=node.file,
                        line=node.line,
                        column=node.column,
                        severity="warning",
                        message=(
                            f"Overwritten parameter: parameter '{var_name}' is "
                            f"reassigned before its original value is used"
                        ),
                        variable=var_name,
                        cwe=563,
                        function=node.function_name,
                        node_id=node.node_id,
                    ))

                # Only report the first overwrite per parameter
                param_var_ids.discard(vid)

        return findings

    # ── DS-004: Write-after-write ─────────────────────────────────────

    def _check_ds004_write_after_write(self, pdg: DependencyGraph) -> List[Finding]:
        """
        DS-004: Two consecutive definitions of the same variable with
        no intervening read — the first definition is dead.

        Detected via OUTPUT dependence edges in the PDG (requires
        ``include_output=True`` in the builder).
        """
        findings: List[Finding] = []

        output_edges = pdg.edges_of_kind(DepKind.OUTPUT)
        for edge in output_edges:
            var_name = edge.variable
            if not var_name:
                var_name = edge.source.def_names.get(edge.var_id, f"var_{edge.var_id}")

            if _should_suppress(edge.source, var_name, self.suppressed_ids, "DS-004"):
                continue

            if self._is_sideeffect_call(edge.source):
                continue

            findings.append(Finding(
                check_id="DS-004",
                file=edge.source.file,
                line=edge.source.line,
                column=edge.source.column,
                severity="style",
                message=(
                    f"Write-after-write: variable '{var_name}' is assigned at "
                    f"line {edge.source.line} and reassigned at line "
                    f"{edge.target.line} with no intervening read"
                ),
                variable=var_name,
                cwe=563,
                function=edge.source.function_name,
                node_id=edge.source.node_id,
            ))

        return findings

    # ── DS-005: Dead store before return ──────────────────────────────

    def _check_ds005_dead_before_return(self, pdg: DependencyGraph) -> List[Finding]:
        """
        DS-005: Variable assigned on a path that immediately returns
        without reading the variable.

        x = expensive_call();   // <-- DS-005
        return other_value;
        """
        findings: List[Finding] = []

        # Find return nodes
        return_nodes: List[DepNode] = []
        for node in pdg.nodes:
            tok_str = getattr(node.token, "str", "")
            if tok_str == "return":
                return_nodes.append(node)

        if not return_nodes:
            return findings

        for ret_node in return_nodes:
            # Look at CFG predecessors of the return node
            pred_ids = pdg._cfg_preds.get(ret_node.node_id, [])
            for pid in pred_ids:
                pred_node = pdg.node_by_id(pid)
                if pred_node is None:
                    continue

                for vid in pred_node.defs:
                    var_name = pred_node.def_names.get(vid, f"var_{vid}")

                    # Is this variable used in the return expression?
                    if vid in ret_node.uses:
                        continue  # the return reads this variable, not dead

                    # Is there any other successor of pred that uses this var?
                    other_use = False
                    for sid in pdg._cfg_succs.get(pred_node.node_id, []):
                        if sid == ret_node.node_id:
                            continue
                        succ = pdg.node_by_id(sid)
                        if succ is not None and vid in succ.uses:
                            other_use = True
                            break

                    if other_use:
                        continue

                    if _should_suppress(pred_node, var_name, self.suppressed_ids, "DS-005"):
                        continue

                    if self._is_sideeffect_call(pred_node):
                        continue

                    findings.append(Finding(
                        check_id="DS-005",
                        file=pred_node.file,
                        line=pred_node.line,
                        column=pred_node.column,
                        severity="style",
                        message=(
                            f"Dead store before return: variable '{var_name}' "
                            f"is assigned at line {pred_node.line} but the "
                            f"return at line {ret_node.line} does not use it"
                        ),
                        variable=var_name,
                        cwe=563,
                        function=pred_node.function_name,
                        node_id=pred_node.node_id,
                    ))

        return findings

    # ── DS-006: Self-assignment ───────────────────────────────────────

    def _check_ds006_self_assignment(self, pdg: DependencyGraph) -> List[Finding]:
        """
        DS-006: Variable assigned to itself (``x = x;``).

        Detected by finding nodes where the def set and use set share
        a variable AND the AST structure shows a simple assignment
        (not +=, -=, etc.).
        """
        findings: List[Finding] = []

        for node in pdg.nodes:
            overlap = node.defs & node.uses
            if not overlap:
                continue

            for vid in overlap:
                # Check for simple assignment (=), not compound (+=, -=, etc.)
                token = node.token
                if token is None:
                    continue

                # Walk through the chunk to find the assignment operator
                is_simple_assign = False
                t = token
                max_walk = 30
                walked = 0
                while t is not None and walked < max_walk:
                    walked += 1
                    s = getattr(t, "str", "")
                    if s == "=":
                        # Verify it's not == or part of !=, <=, >=
                        next_t = getattr(t, "next", None)
                        prev_t = getattr(t, "previous", None)
                        next_s = getattr(next_t, "str", "") if next_t else ""
                        prev_s = getattr(prev_t, "str", "") if prev_t else ""
                        if next_s != "=" and prev_s not in ("!", "<", ">", "="):
                            is_simple_assign = True
                            break
                    if s in (";", "{", "}"):
                        break
                    t = getattr(t, "next", None)

                if not is_simple_assign:
                    continue

                # Verify: LHS and RHS refer to the same variable
                # by checking that both the def and use are for the same varId
                # and the assignment is of the form "v = v"
                var_name = node.def_names.get(vid, node.use_names.get(vid, f"var_{vid}"))

                if _should_suppress(node, var_name, self.suppressed_ids, "DS-006"):
                    continue

                findings.append(Finding(
                    check_id="DS-006",
                    file=node.file,
                    line=node.line,
                    column=node.column,
                    severity="warning",
                    message=(
                        f"Self-assignment: variable '{var_name}' is assigned "
                        f"to itself"
                    ),
                    variable=var_name,
                    cwe=561,
                    function=node.function_name,
                    node_id=node.node_id,
                ))

        return findings

    # ── DS-007: Unused variable ───────────────────────────────────────

    def _check_ds007_unused_variable(self, pdg: DependencyGraph) -> List[Finding]:
        """
        DS-007: Variable defined but never used anywhere in the function.

        Distinct from DS-001 (dead store) in that the variable has
        *zero* uses across the entire function, not just after a
        particular definition.
        """
        findings: List[Finding] = []

        # Collect all defined variable IDs and all used variable IDs
        all_defined: Dict[int, DepNode] = {}  # vid → first defining node
        all_used: Set[int] = set()

        for node in pdg.nodes:
            for vid in node.defs:
                if vid not in all_defined:
                    all_defined[vid] = node
            all_used |= node.uses

        # Variables defined but never used anywhere
        never_used = set(all_defined.keys()) - all_used

        for vid in never_used:
            node = all_defined[vid]
            var_name = node.def_names.get(vid, f"var_{vid}")

            if _should_suppress(node, var_name, self.suppressed_ids, "DS-007"):
                continue

            if self._is_sideeffect_call(node):
                continue

            findings.append(Finding(
                check_id="DS-007",
                file=node.file,
                line=node.line,
                column=node.column,
                severity="style",
                message=(
                    f"Unused variable: '{var_name}' is defined but never "
                    f"used in function '{node.function_name}'"
                ),
                variable=var_name,
                cwe=563,
                function=node.function_name,
                node_id=node.node_id,
            ))

        return findings

    # ── Helper: side-effect call detection ────────────────────────────

    def _is_sideeffect_call(self, node: DepNode) -> bool:
        """
        Check if a node's definition comes from a function call whose
        side effects are the primary purpose (e.g., memset, printf).

        In such cases, the "dead store" is intentional — the caller
        wants the side effect, not the return value.
        """
        token = node.token
        if token is None:
            return False

        # Walk forward looking for a function call in this statement
        t = token
        max_walk = 20
        walked = 0
        while t is not None and walked < max_walk:
            walked += 1
            s = getattr(t, "str", "")
            if s in _INTENTIONAL_IGNORE_FUNCS:
                return True
            if s in (";", "{", "}"):
                break
            t = getattr(t, "next", None)

        return False

    # ── Helper: DOT export ────────────────────────────────────────────

    def _write_dot(self, pdg: DependencyGraph) -> None:
        """Write the PDG to a DOT file for debugging."""
        if self.dot_output_dir is None:
            return
        os.makedirs(self.dot_output_dir, exist_ok=True)
        func = pdg.function_name or "unknown"
        path = os.path.join(self.dot_output_dir, f"pdg_{func}.dot")

        # Highlight dead store nodes
        dead_ids = {n.node_id for n in pdg.dead_stores()}
        dot_str = pdg.to_dot(
            title=f"PDG: {func} (dead stores highlighted)",
            highlight_nodes=dead_ids,
        )
        with open(path, "w") as f:
            f.write(dot_str)

        if self.verbose:
            sys.stderr.write(f"[DeadStoreDetector] DOT written to {path}\n")

    # ── Deduplication ─────────────────────────────────────────────────

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings.

        Priority when duplicates exist:
          1. Higher severity wins (error > warning > style).
          2. More specific check ID wins (DS-003 > DS-001).
        """
        _SEVERITY_RANK = {"error": 3, "warning": 2, "style": 1}
        _CHECK_SPECIFICITY = {
            "DS-003": 7,  # overwritten param — most specific
            "DS-006": 6,  # self-assignment
            "DS-004": 5,  # write-after-write
            "DS-005": 4,  # dead before return
            "DS-002": 3,  # unused init
            "DS-007": 2,  # unused variable
            "DS-001": 1,  # general dead store
        }

        best: Dict[Tuple[str, int, int, str], Finding] = {}
        for f in findings:
            key = (f.file, f.line, f.column, f.variable)
            if key not in best:
                best[key] = f
            else:
                existing = best[key]
                e_sev = _SEVERITY_RANK.get(existing.severity, 0)
                f_sev = _SEVERITY_RANK.get(f.severity, 0)
                e_spec = _CHECK_SPECIFICITY.get(existing.check_id, 0)
                f_spec = _CHECK_SPECIFICITY.get(f.check_id, 0)
                # Higher severity wins; on tie, higher specificity wins
                if (f_sev, f_spec) > (e_sev, e_spec):
                    best[key] = f

        # Return in original line order
        result = sorted(best.values(), key=lambda f: (f.file, f.line, f.column))
        return result


# ═══════════════════════════════════════════════════════════════════════════
#  PART 3 — CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="DeadStoreDetector",
        description=(
            "Cppcheck addon: detect dead stores using Program Dependency "
            "Graph analysis."
        ),
        epilog=(
            "Examples:\n"
            "  cppcheck --dump myfile.c && python DeadStoreDetector.py myfile.c.dump\n"
            "  python DeadStoreDetector.py --severity=warning --suppress=DS-002 file.dump\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "dumpfiles",
        nargs="+",
        metavar="DUMP_FILE",
        help="One or more .dump files produced by cppcheck --dump",
    )
    parser.add_argument(
        "--severity",
        default="style",
        choices=["style", "warning", "error"],
        help="Minimum severity to report (default: style)",
    )
    parser.add_argument(
        "--suppress",
        default="",
        help="Comma-separated list of check IDs to suppress (e.g., DS-002,DS-006)",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=50_000,
        help="Skip functions with more than N tokens (default: 50000)",
    )
    parser.add_argument(
        "--include-anti",
        action="store_true",
        default=False,
        help="Include anti-dependence (WAR) analysis in the PDG",
    )
    parser.add_argument(
        "--include-output",
        action="store_true",
        default=True,
        help="Include output-dependence (WAW) analysis (needed for DS-004)",
    )
    parser.add_argument(
        "--dot-output",
        default=None,
        metavar="DIR",
        help="Write DOT graph files to DIR for debugging",
    )
    parser.add_argument(
        "--format",
        default="cppcheck",
        choices=["cppcheck", "gcc"],
        help="Output format (default: cppcheck)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Print analysis progress to stderr",
    )
    return parser.parse_args(argv)


def _severity_rank(sev: str) -> int:
    """Map severity string to numeric rank for filtering."""
    return {"style": 1, "warning": 2, "error": 3}.get(sev, 0)


def main(argv: Optional[List[str]] = None) -> int:
    """
    CLI entry point.

    Returns
    -------
    int
        Exit code: 0 if no findings, 1 if findings reported,
        2 on fatal error.
    """
    args = _parse_args(argv)

    # Parse suppressed check IDs
    suppressed: Set[str] = set()
    if args.suppress:
        suppressed = {s.strip() for s in args.suppress.split(",") if s.strip()}

    min_severity = _severity_rank(args.severity)

    detector = DeadStoreDetector(
        severity=args.severity,
        suppressed_ids=suppressed,
        max_tokens=args.max_tokens,
        include_anti=args.include_anti,
        include_output=args.include_output,
        dot_output_dir=args.dot_output,
        verbose=args.verbose,
    )

    total_findings = 0

    for dumpfile in args.dumpfiles:
        if not os.path.isfile(dumpfile):
            sys.stderr.write(f"ERROR: File not found: {dumpfile}\n")
            continue

        if args.verbose:
            sys.stderr.write(f"[DeadStoreDetector] Processing {dumpfile}\n")

        try:
            data = cppcheckdata.parsedump(dumpfile)
        except Exception as e:
            sys.stderr.write(f"ERROR: Failed to parse {dumpfile}: {e}\n")
            continue

        configs = getattr(data, "configurations", [])
        if not configs:
            if args.verbose:
                sys.stderr.write(
                    f"[DeadStoreDetector] No configurations in {dumpfile}\n"
                )
            continue

        for cfg in configs:
            findings = detector.analyse(cfg)

            for f in findings:
                # Apply severity filter
                if _severity_rank(f.severity) < min_severity:
                    continue

                if args.format == "gcc":
                    print(f.format_gcc())
                else:
                    print(f.format_cppcheck())

                total_findings += 1

    return 1 if total_findings > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
