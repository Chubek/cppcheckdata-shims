"""
cppcheckdata_shims/abstract_exec.py
════════════════════════════════════

Abstract Execution engine for the cppcheckdata-shims library.

This module implements *abstract execution* as described by Larus (1990),
adapted for a purely static setting.  Where Larus instruments a compiled
program and regenerates traces at runtime, we:

    1. **Define** abstract events (``AbsExecEvent`` subclasses) that
       describe *what* to watch for: function calls, assignments, memory
       operations, control-flow patterns, etc.
    2. **Collect** those events by symbolically walking the CFG using the
       symbolic-execution engine (``symbolic_exec.py``) and the abstract
       VM (``abstract_vm.py``).  This produces a *Schema Listing* — the
       static analogue of Larus's trace file.
    3. **Compile** the schema listing into abstract VM bytecode, enriched
       with ``EVENT`` / ``OBSERVE`` instructions for every matched event.
    4. **Analyse** the compiled schema by interpreting it in the abstract
       VM, with user-defined ``AbsExecAnalysis`` subclasses consuming
       the event stream.

Architecture
────────────

    ┌───────────────┐   define    ┌──────────────────┐
    │ AbsExecEvent  │────────────►│                  │
    │ (user class)  │             │  AbsExecEngine   │
    └───────────────┘             │                  │
                                  │  1. match events │
    ┌───────────────┐   consume   │  2. build schema │
    │AbsExecAnalysis│◄────────────│  3. compile VM   │
    │ (user class)  │             │  4. run analysis │
    └───────────────┘             └────────┬─────────┘
                                           │
                        ┌──────────────────┤
                        ▼                  ▼
                 ┌─────────────┐   ┌──────────────┐
                 │symbolic_exec│   │ abstract_vm  │
                 │  (traces)   │   │ (interpret)  │
                 └─────────────┘   └──────────────┘

Connection to Larus (1990)
──────────────────────────

    Larus concept              Our analogue
    ─────────────────────────  ──────────────────────────────────
    Program P                  CFG from ctrlflow_graph.py
    Instrumented program P'    Schema-enriched abstract VM code
    Significant events SE      AbsExecEvent matches
    Trace file                 SchemaListing (from abstract_vm)
    Schema program             AbstractProgram (compiled bytecode)
    Regeneration (aec)         AbstractVM.interpret / .explore
    Analysis consumer          AbsExecAnalysis subclass

Connection to PQL (Martin et al.)
─────────────────────────────────

PQL queries describe *sequences of events* on Java objects (e.g.
``open → read → close``).  Our abstract execution engine supports the
same idea: an ``AbsExecEvent`` matches individual actions, and an
``AbsExecAnalysis`` can track *sequences* by maintaining an automaton
state, looking for patterns like "allocation without matching free" or
"tainted source flows to sink".  The ``EventSequenceMatcher`` helper
class provides built-in support for this.

Usage Example
─────────────

    >>> from cppcheckdata_shims.abstract_exec import *
    >>> from cppcheckdata_shims.abstract_vm import *
    >>>
    >>> class MallocEvent(AbsExecEvent):
    ...     event_kind = "alloc"
    ...     def match_token(self, tok, ctx):
    ...         if getattr(tok, 'str', '') == 'malloc':
    ...             return EventMatch(event=self, token=tok,
    ...                               bindings={'func': 'malloc'})
    ...         return None
    ...
    >>> class FreeEvent(AbsExecEvent):
    ...     event_kind = "free"
    ...     def match_token(self, tok, ctx):
    ...         if getattr(tok, 'str', '') == 'free':
    ...             return EventMatch(event=self, token=tok,
    ...                               bindings={'func': 'free'})
    ...         return None
    ...
    >>> class LeakAnalysis(AbsExecAnalysis):
    ...     def on_event(self, record, state, engine):
    ...         if record.event_id == 'alloc':
    ...             state.setdefault('allocs', set()).add(record.step)
    ...         elif record.event_id == 'free':
    ...             state.get('allocs', set()).discard(record.step)
    ...     def on_complete(self, state, engine):
    ...         for step in state.get('allocs', set()):
    ...             engine.report("Potential memory leak", step=step)
    ...
    >>> engine = AbsExecEngine(events=[MallocEvent(), FreeEvent()],
    ...                        analyses=[LeakAnalysis()])
    >>> engine.run_on_cfg(cfg, func_name="main")

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import abc
import enum
import itertools
import re
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    ClassVar,
    Dict,
    FrozenSet,
    Generic,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    runtime_checkable,
)

# ---------------------------------------------------------------------------
# Imports from sibling modules
# ---------------------------------------------------------------------------

from cppcheckdata_shims.abstract_domains import (
    AbstractDomain,
    IntervalDomain,
    SignDomain,
    BoolDomain,
    FlatDomain,
    FunctionDomain,
    make_interval_env,
)

from cppcheckdata_shims.abstract_vm import (
    AbstractCompiler,
    AbstractProgram,
    AbstractVM,
    ActivationFrame,
    BlockRef,
    BinOp,
    CmpOp,
    CodeBlock,
    CostLiteral,
    EventHandler,
    EventRecord,
    EventRef,
    FuncRef,
    FunctionCode,
    Instruction,
    InstructionBuilder,
    ObserverHandler,
    ObserverRef,
    Opcode,
    Reg,
    SchemaEntry,
    SchemaListing,
    UnOp,
    VMError,
    VMHalt,
    compile_cfg_to_abstract,
    compile_program,
    dump_program,
    estimate_cost,
    explore_function,
    interpret_function,
)

from cppcheckdata_shims.ctrlflow_graph import CFG, BasicBlock, CFGEdge

# Optional symbolic execution support
try:
    from cppcheckdata_shims.symbolic_exec import (
        SymbolicState,
        SymbolicValue,
        SymbolicExecutor,
    )

    _HAS_SYMEXEC = True
except ImportError:
    _HAS_SYMEXEC = False

# Optional AST helper
try:
    from cppcheckdata_shims.ast_helper import (
        ast_walk,
        is_function_call,
        get_called_function_name,
    )

    _HAS_AST_HELPER = True
except ImportError:
    _HAS_AST_HELPER = False


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

T = TypeVar("T")
AnalysisState = Dict[str, Any]
TokenLike = Any  # cppcheckdata Token (duck-typed)
ScopeLike = Any  # cppcheckdata Scope (duck-typed)


# ═══════════════════════════════════════════════════════════════════════════
# 1. EVENT MATCHING
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class MatchContext:
    """Context information passed to event matchers.

    Provides the matcher with information about where in the program
    the match is being attempted.

    Attributes
    ----------
    function_name : str
        Name of the enclosing function.
    scope : Optional[ScopeLike]
        The enclosing Cppcheck scope.
    block : Optional[BasicBlock]
        The enclosing CFG basic block.
    cfg : Optional[CFG]
        The enclosing CFG.
    token_index : int
        Index of the token within its block's token list.
    source_file : Optional[str]
        Source file name.
    line : int
        Source line number.
    column : int
        Source column.
    symbolic_state : Optional[Any]
        Current symbolic state (from symbolic execution), if available.
    abstract_state : Optional[Dict[str, AbstractDomain]]
        Current abstract state (register file), if available.
    """

    function_name: str = ""
    scope: Optional[ScopeLike] = None
    block: Optional[BasicBlock] = None
    cfg: Optional[CFG] = None
    token_index: int = 0
    source_file: Optional[str] = None
    line: int = 0
    column: int = 0
    symbolic_state: Optional[Any] = None
    abstract_state: Optional[Dict[str, AbstractDomain]] = None


@dataclass(slots=True)
class EventMatch:
    """Result of a successful event match.

    Attributes
    ----------
    event : AbsExecEvent
        The event descriptor that matched.
    token : Optional[TokenLike]
        The token that triggered the match.
    bindings : Dict[str, Any]
        Named bindings extracted from the match (analogous to PQL's
        variable bindings).  For example, a call-event matcher might
        bind ``{'callee': 'malloc', 'arg0': <Reg>}``.
    source_loc : Optional[Tuple[str, int, int]]
        Source location ``(file, line, column)``.
    confidence : float
        Confidence score in ``[0.0, 1.0]``.  1.0 = certain match;
        lower values indicate heuristic matches.
    metadata : Dict[str, Any]
        Arbitrary matcher-specific metadata.
    """

    event: AbsExecEvent
    token: Optional[TokenLike] = None
    bindings: Dict[str, Any] = field(default_factory=dict)
    source_loc: Optional[Tuple[str, int, int]] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def event_id(self) -> str:
        return self.event.event_kind

    def __repr__(self) -> str:
        loc = ""
        if self.source_loc:
            f, l, c = self.source_loc
            loc = f" at {f}:{l}:{c}"
        binds = ", ".join(f"{k}={v!r}" for k, v in self.bindings.items())
        return f"EventMatch({self.event_id}{loc}, {{{binds}}})"


class AbsExecEvent(abc.ABC):
    """Base class for user-defined abstract events.

    Subclass this to define *what* program actions are significant for
    your analysis.  Each event has a ``event_kind`` string identifier and
    implements one or more matching methods:

    - ``match_token``: match against a single AST token.
    - ``match_instruction``: match against an abstract VM instruction.
    - ``match_cfg_edge``: match against a CFG edge (for control-flow events).

    At least one of these must be overridden; the default implementations
    return ``None`` (no match).

    Class Attributes
    ----------------
    event_kind : str
        Unique identifier for this event type (e.g. "alloc", "call",
        "assign", "branch").  Used as the ``event_id`` in
        ``EventRecord`` objects.
    priority : int
        Matching priority (lower = matched first).  Default 0.
    """

    event_kind: ClassVar[str] = "unknown"
    priority: ClassVar[int] = 0

    def match_token(
        self,
        token: TokenLike,
        ctx: MatchContext,
    ) -> Optional[EventMatch]:
        """Attempt to match this event against a single token.

        Parameters
        ----------
        token : TokenLike
            The Cppcheck token to inspect.
        ctx : MatchContext
            Contextual information.

        Returns
        -------
        Optional[EventMatch]
            An ``EventMatch`` if the event fires, else ``None``.
        """
        return None

    def match_instruction(
        self,
        instr: Instruction,
        frame: Optional[ActivationFrame],
        ctx: MatchContext,
    ) -> Optional[EventMatch]:
        """Attempt to match this event against an abstract VM instruction.

        This is called during the schema-compilation phase when the
        engine walks the abstract bytecode.

        Parameters
        ----------
        instr : Instruction
            The abstract instruction.
        frame : Optional[ActivationFrame]
            The current VM frame (may be ``None`` during compilation).
        ctx : MatchContext
            Contextual information.

        Returns
        -------
        Optional[EventMatch]
        """
        return None

    def match_cfg_edge(
        self,
        edge: CFGEdge,
        ctx: MatchContext,
    ) -> Optional[EventMatch]:
        """Attempt to match against a CFG edge.

        Useful for control-flow events like "back-edge taken" (loop
        iteration) or "exception edge".

        Parameters
        ----------
        edge : CFGEdge
            The CFG edge.
        ctx : MatchContext
            Contextual information.

        Returns
        -------
        Optional[EventMatch]
        """
        return None

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(kind={self.event_kind!r})"


# ═══════════════════════════════════════════════════════════════════════════
# 2. BUILT-IN EVENT TYPES
# ═══════════════════════════════════════════════════════════════════════════


class FunctionCallEvent(AbsExecEvent):
    """Matches function calls.

    Parameters
    ----------
    func_names : Optional[Set[str]]
        If provided, only match calls to these function names.
        If ``None``, match *all* function calls.
    """

    event_kind: ClassVar[str] = "call"

    def __init__(self, func_names: Optional[Set[str]] = None):
        self._func_names = func_names

    def match_token(self, token: TokenLike, ctx: MatchContext) -> Optional[EventMatch]:
        tok_str = getattr(token, "str", "") or ""
        func = getattr(token, "function", None)

        if tok_str == "(" and func is not None:
            callee = getattr(func, "name", None) or ""
            if self._func_names is None or callee in self._func_names:
                return EventMatch(
                    event=self,
                    token=token,
                    bindings={"callee": callee},
                    source_loc=_token_loc(token),
                )
        return None

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.CALL and len(instr.operands) >= 2:
            fref = instr.operands[1]
            if isinstance(fref, FuncRef):
                if self._func_names is None or fref.name in self._func_names:
                    return EventMatch(
                        event=self,
                        bindings={"callee": fref.name},
                        source_loc=instr.source_loc,
                    )
        return None


class AssignmentEvent(AbsExecEvent):
    """Matches assignments to variables.

    Parameters
    ----------
    var_names : Optional[Set[str]]
        If provided, only match assignments to these variable names.
    """

    event_kind: ClassVar[str] = "assign"

    def __init__(self, var_names: Optional[Set[str]] = None):
        self._var_names = var_names

    def match_token(self, token: TokenLike, ctx: MatchContext) -> Optional[EventMatch]:
        if not getattr(token, "isAssignmentOp", False):
            return None
        lhs = getattr(token, "astOperand1", None)
        if lhs is None:
            return None
        var = getattr(lhs, "variable", None)
        var_name = getattr(getattr(var, "nameToken", None), "str", None) if var else None
        if var_name is None:
            var_name = getattr(lhs, "str", None) or "?"

        if self._var_names is None or var_name in self._var_names:
            return EventMatch(
                event=self,
                token=token,
                bindings={
                    "var": var_name,
                    "op": getattr(token, "str", "="),
                },
                source_loc=_token_loc(token),
            )
        return None

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.COPY and len(instr.operands) >= 2:
            dst = instr.operands[0]
            if isinstance(dst, Reg):
                var_name = dst.name.replace("var_", "", 1) if dst.name.startswith("var_") else dst.name
                if self._var_names is None or var_name in self._var_names:
                    return EventMatch(
                        event=self,
                        bindings={"var": var_name, "reg": dst},
                        source_loc=instr.source_loc,
                    )
        return None


class MemoryReadEvent(AbsExecEvent):
    """Matches memory read operations (LOAD, dereference)."""

    event_kind: ClassVar[str] = "mem_read"

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.LOAD:
            base = instr.operands[1] if len(instr.operands) > 1 else None
            return EventMatch(
                event=self,
                bindings={"base": base},
                source_loc=instr.source_loc,
            )
        return None


class MemoryWriteEvent(AbsExecEvent):
    """Matches memory write operations (STORE)."""

    event_kind: ClassVar[str] = "mem_write"

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.STORE:
            base = instr.operands[0] if instr.operands else None
            return EventMatch(
                event=self,
                bindings={"base": base},
                source_loc=instr.source_loc,
            )
        return None


class AllocationEvent(AbsExecEvent):
    """Matches dynamic memory allocation (malloc, calloc, realloc, new)."""

    event_kind: ClassVar[str] = "alloc"

    def __init__(self, alloc_funcs: Optional[Set[str]] = None):
        self._alloc_funcs = alloc_funcs or {"malloc", "calloc", "realloc"}

    def match_token(self, token: TokenLike, ctx: MatchContext) -> Optional[EventMatch]:
        tok_str = getattr(token, "str", "") or ""
        if tok_str in self._alloc_funcs:
            return EventMatch(
                event=self,
                token=token,
                bindings={"func": tok_str},
                source_loc=_token_loc(token),
            )
        return None

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.ALLOC:
            return EventMatch(
                event=self,
                bindings={"dst": instr.operands[0] if instr.operands else None},
                source_loc=instr.source_loc,
            )
        return None


class DeallocationEvent(AbsExecEvent):
    """Matches deallocation (free, delete)."""

    event_kind: ClassVar[str] = "dealloc"

    def __init__(self, free_funcs: Optional[Set[str]] = None):
        self._free_funcs = free_funcs or {"free"}

    def match_token(self, token: TokenLike, ctx: MatchContext) -> Optional[EventMatch]:
        tok_str = getattr(token, "str", "") or ""
        if tok_str in self._free_funcs:
            return EventMatch(
                event=self,
                token=token,
                bindings={"func": tok_str},
                source_loc=_token_loc(token),
            )
        return None

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.FREE:
            return EventMatch(
                event=self,
                bindings={"src": instr.operands[0] if instr.operands else None},
                source_loc=instr.source_loc,
            )
        return None


class BranchEvent(AbsExecEvent):
    """Matches conditional branches."""

    event_kind: ClassVar[str] = "branch"

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.BRANCH:
            cond = instr.operands[0] if instr.operands else None
            true_target = instr.operands[1] if len(instr.operands) > 1 else None
            false_target = instr.operands[2] if len(instr.operands) > 2 else None
            return EventMatch(
                event=self,
                bindings={
                    "cond": cond,
                    "true_target": true_target,
                    "false_target": false_target,
                },
                source_loc=instr.source_loc,
            )
        return None

    def match_cfg_edge(self, edge: CFGEdge, ctx: MatchContext) -> Optional[EventMatch]:
        edge_kind = getattr(edge, "kind", None) or getattr(edge, "type", None)
        if edge_kind in ("true", "false", "conditional"):
            return EventMatch(
                event=self,
                bindings={
                    "src_block": edge.src.id if edge.src else None,
                    "dst_block": edge.dst.id if edge.dst else None,
                    "kind": edge_kind,
                },
            )
        return None


class LoopEntryEvent(AbsExecEvent):
    """Matches loop back-edges (indicates a loop iteration)."""

    event_kind: ClassVar[str] = "loop_entry"

    def match_cfg_edge(self, edge: CFGEdge, ctx: MatchContext) -> Optional[EventMatch]:
        edge_kind = getattr(edge, "kind", None) or getattr(edge, "type", None)
        if edge_kind == "back":
            return EventMatch(
                event=self,
                bindings={
                    "header_block": edge.dst.id if edge.dst else None,
                },
            )
        return None


class ReturnEvent(AbsExecEvent):
    """Matches function returns."""

    event_kind: ClassVar[str] = "return"

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode == Opcode.RETURN:
            ret_val = instr.operands[0] if instr.operands else None
            return EventMatch(
                event=self,
                bindings={"return_value": ret_val},
                source_loc=instr.source_loc,
            )
        return None


class ScopeEvent(AbsExecEvent):
    """Matches scope entry / exit."""

    event_kind: ClassVar[str] = "scope"

    def match_instruction(
        self, instr: Instruction, frame: Optional[ActivationFrame], ctx: MatchContext
    ) -> Optional[EventMatch]:
        if instr.opcode in (Opcode.ENTER_SCOPE, Opcode.EXIT_SCOPE):
            scope_id = instr.operands[0] if instr.operands else None
            direction = "enter" if instr.opcode == Opcode.ENTER_SCOPE else "exit"
            return EventMatch(
                event=self,
                bindings={"scope": scope_id, "direction": direction},
                source_loc=instr.source_loc,
            )
        return None


class PatternEvent(AbsExecEvent):
    """Matches tokens by a regex pattern on the token string.

    Parameters
    ----------
    pattern : str
        Regular expression to match against ``token.str``.
    kind : str
        Event kind identifier.
    """

    event_kind: ClassVar[str] = "pattern"

    def __init__(self, pattern: str, kind: str = "pattern"):
        self._pattern = re.compile(pattern)
        # Override class-level event_kind for this instance
        self.event_kind = kind  # type: ignore[misc]

    def match_token(self, token: TokenLike, ctx: MatchContext) -> Optional[EventMatch]:
        tok_str = getattr(token, "str", "") or ""
        m = self._pattern.search(tok_str)
        if m:
            return EventMatch(
                event=self,
                token=token,
                bindings={"matched": m.group(0), "groups": m.groups()},
                source_loc=_token_loc(token),
            )
        return None


# ═══════════════════════════════════════════════════════════════════════════
# 3. ANALYSIS BASE CLASS
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class AnalysisReport:
    """A single report produced by an analysis.

    Attributes
    ----------
    message : str
        Human-readable description.
    severity : str
        One of: "error", "warning", "info", "style", "performance".
    event_id : str
        The event kind that triggered this report.
    source_loc : Optional[Tuple[str, int, int]]
        Source location.
    step : int
        The abstract execution step at which the report was generated.
    bindings : Dict[str, Any]
        Variable bindings from the triggering event match.
    analysis_name : str
        Name of the analysis that produced this report.
    metadata : Dict[str, Any]
        Arbitrary extra data.
    """

    message: str
    severity: str = "warning"
    event_id: str = ""
    source_loc: Optional[Tuple[str, int, int]] = None
    step: int = 0
    bindings: Dict[str, Any] = field(default_factory=dict)
    analysis_name: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        loc = ""
        if self.source_loc:
            f, l, c = self.source_loc
            loc = f" [{f}:{l}:{c}]"
        return f"[{self.severity.upper()}]{loc} {self.message} ({self.analysis_name})"


class AbsExecAnalysis(abc.ABC):
    """Base class for user-defined analyses that consume abstract events.

    Subclass this to implement your analysis logic.  The engine calls
    the following methods in order:

    1. ``on_begin(state, engine)`` — once, before analysis starts.
    2. ``on_event(record, state, engine)`` — for each matched event.
    3. ``on_complete(state, engine)`` — once, after all events processed.

    The ``state`` dictionary is a mutable bag of analysis-specific data
    that persists across calls.  You are free to put anything in it.

    Class Attributes
    ----------------
    analysis_name : str
        Human-readable name for this analysis.
    listens_to : Optional[Set[str]]
        If provided, only events with these ``event_id``s are forwarded
        to ``on_event``.  If ``None``, receives *all* events.
    """

    analysis_name: ClassVar[str] = "unnamed"
    listens_to: ClassVar[Optional[Set[str]]] = None

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        """Called once before the first event is delivered.

        Use this to initialise analysis-specific state.

        Parameters
        ----------
        state : AnalysisState
            The mutable analysis state dictionary.
        engine : AbsExecEngine
            The driving engine (for access to program, VM, etc.).
        """
        pass

    @abc.abstractmethod
    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        """Called for each event during abstract execution.

        Parameters
        ----------
        record : EventRecord
            The event record from the abstract VM.
        match : Optional[EventMatch]
            The original ``EventMatch`` that generated this event (may be
            ``None`` for events emitted by the compiler itself, e.g.
            ``func_entry``).
        state : AnalysisState
            The mutable analysis state dictionary.
        engine : AbsExecEngine
            The driving engine.
        """
        ...

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        """Called once after all events have been delivered.

        Use this for final checks (e.g. "were all resources freed?").

        Parameters
        ----------
        state : AnalysisState
            The analysis state.
        engine : AbsExecEngine
            The driving engine (call ``engine.report(...)`` to emit findings).
        """
        pass

    def on_schema_entry(
        self,
        entry: SchemaEntry,
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        """Called for every schema entry (not just events).

        Override this if you need access to the full instruction stream
        (e.g. for cost analysis).  Default: no-op.

        Parameters
        ----------
        entry : SchemaEntry
            The schema entry.
        state : AnalysisState
            The analysis state.
        engine : AbsExecEngine
            The driving engine.
        """
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.analysis_name!r})"


# ═══════════════════════════════════════════════════════════════════════════
# 4. EVENT SEQUENCE MATCHING (PQL-style)
# ═══════════════════════════════════════════════════════════════════════════


class _SeqState(enum.Enum):
    """State of a sequence automaton."""

    PENDING = "pending"  # Not yet started
    ACTIVE = "active"    # Partially matched
    MATCHED = "matched"  # Fully matched
    FAILED = "failed"    # Failed (no recovery)


@dataclass(slots=True)
class SequenceStep:
    """One step in an event sequence pattern.

    Attributes
    ----------
    event_kind : str
        The event kind to expect at this step.
    guard : Optional[Callable[[EventRecord, EventMatch, AnalysisState], bool]]
        Optional predicate that must hold for the step to match.
        Receives the event record, event match, and current state.
    bind_to : Optional[str]
        If provided, the matched event's bindings are stored in
        ``state[bind_to]``.
    """

    event_kind: str
    guard: Optional[Callable[[EventRecord, Optional[EventMatch], AnalysisState], bool]] = None
    bind_to: Optional[str] = None


@dataclass(slots=True)
class SequenceMatchResult:
    """Result of a completed sequence match.

    Attributes
    ----------
    matched : bool
        Whether the full sequence was matched.
    steps_matched : int
        Number of steps matched before completion/failure.
    bindings : Dict[str, Any]
        Accumulated bindings from all matched steps.
    events : List[EventRecord]
        The event records for each matched step.
    """

    matched: bool
    steps_matched: int = 0
    bindings: Dict[str, Any] = field(default_factory=dict)
    events: List[EventRecord] = field(default_factory=list)


class EventSequenceMatcher:
    """Matches *sequences* of abstract events, in the style of PQL.

    Given a sequence of ``SequenceStep`` objects, the matcher tracks
    incoming events and determines when the full sequence has been
    observed.  Multiple overlapping matches are tracked simultaneously
    (like NFA execution).

    This is the cppcheckdata-shims analogue of PQL's event sequence
    queries (Martin et al., "Finding Application Errors and Security
    Flaws Using PQL").

    Parameters
    ----------
    steps : List[SequenceStep]
        The ordered sequence of expected events.
    name : str
        Human-readable name for this sequence pattern.
    allow_interleaving : bool
        If ``True``, other events may occur between steps of the
        sequence without causing failure.  Default ``True``.

    Example
    -------
    >>> matcher = EventSequenceMatcher(
    ...     steps=[
    ...         SequenceStep("alloc", bind_to="alloc_event"),
    ...         SequenceStep("return",
    ...                      guard=lambda rec, m, s: True),
    ...     ],
    ...     name="alloc-then-return",
    ... )
    >>> for record in event_stream:
    ...     results = matcher.feed(record, match=None, state={})
    ...     for result in results:
    ...         if result.matched:
    ...             print("Allocation followed by return (potential leak)!")
    """

    def __init__(
        self,
        steps: List[SequenceStep],
        name: str = "sequence",
        allow_interleaving: bool = True,
    ):
        self.steps = list(steps)
        self.name = name
        self.allow_interleaving = allow_interleaving

        # Active tracking slots: each is (current_step_index, bindings, events)
        self._active: List[Tuple[int, Dict[str, Any], List[EventRecord]]] = []

    def reset(self) -> None:
        """Reset all active tracking state."""
        self._active.clear()

    def feed(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
    ) -> List[SequenceMatchResult]:
        """Feed an event into the matcher.

        Returns a list of ``SequenceMatchResult`` for any sequences that
        completed (either matched or failed) on this event.  Usually
        you only care about ``result.matched == True``.

        Parameters
        ----------
        record : EventRecord
            The incoming event.
        match : Optional[EventMatch]
            The event match (for accessing bindings).
        state : AnalysisState
            Current analysis state (passed to guards).

        Returns
        -------
        List[SequenceMatchResult]
        """
        completed: List[SequenceMatchResult] = []
        next_active: List[Tuple[int, Dict[str, Any], List[EventRecord]]] = []

        # Try to start a new tracking if this event matches step 0
        if self.steps and record.event_id == self.steps[0].event_kind:
            step = self.steps[0]
            if step.guard is None or step.guard(record, match, state):
                bindings: Dict[str, Any] = {}
                if step.bind_to and match:
                    bindings[step.bind_to] = match.bindings.copy() if match.bindings else {}
                events = [record]
                if len(self.steps) == 1:
                    # Single-step sequence: immediately complete
                    completed.append(
                        SequenceMatchResult(
                            matched=True,
                            steps_matched=1,
                            bindings=bindings,
                            events=events,
                        )
                    )
                else:
                    next_active.append((1, bindings, events))

        # Advance existing active trackings
        for step_idx, cur_bindings, cur_events in self._active:
            if step_idx >= len(self.steps):
                continue

            expected_step = self.steps[step_idx]
            if record.event_id == expected_step.event_kind:
                # Check guard
                if expected_step.guard is None or expected_step.guard(record, match, state):
                    new_bindings = dict(cur_bindings)
                    if expected_step.bind_to and match:
                        new_bindings[expected_step.bind_to] = (
                            match.bindings.copy() if match.bindings else {}
                        )
                    new_events = cur_events + [record]
                    new_idx = step_idx + 1
                    if new_idx >= len(self.steps):
                        # Sequence complete!
                        completed.append(
                            SequenceMatchResult(
                                matched=True,
                                steps_matched=new_idx,
                                bindings=new_bindings,
                                events=new_events,
                            )
                        )
                    else:
                        next_active.append((new_idx, new_bindings, new_events))
                elif self.allow_interleaving:
                    # Event doesn't match expected step, but we allow gaps
                    next_active.append((step_idx, cur_bindings, cur_events))
                else:
                    # Strict mode: sequence fails
                    completed.append(
                        SequenceMatchResult(
                            matched=False,
                            steps_matched=step_idx,
                            bindings=cur_bindings,
                            events=cur_events,
                        )
                    )
            elif self.allow_interleaving:
                # Different event kind; keep waiting
                next_active.append((step_idx, cur_bindings, cur_events))
            else:
                # Strict: unexpected event, fail
                completed.append(
                    SequenceMatchResult(
                        matched=False,
                        steps_matched=step_idx,
                        bindings=cur_bindings,
                        events=cur_events,
                    )
                )

        self._active = next_active
        return completed

    def pending_count(self) -> int:
        """Number of currently active (partially matched) sequences."""
        return len(self._active)

    def flush(self) -> List[SequenceMatchResult]:
        """Flush all active trackings as failures (called at end-of-function).

        Returns incomplete matches so the analysis can report them
        (e.g. "allocation without matching free").
        """
        results: List[SequenceMatchResult] = []
        for step_idx, bindings, events in self._active:
            results.append(
                SequenceMatchResult(
                    matched=False,
                    steps_matched=step_idx,
                    bindings=bindings,
                    events=events,
                )
            )
        self._active.clear()
        return results


# ═══════════════════════════════════════════════════════════════════════════
# 5. SCHEMA BUILDER — match events and build enriched schema
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class SchemaEventRecord:
    """An event match recorded during schema construction.

    Ties together the original ``EventMatch`` from the token/instruction
    scan and the ``EventRecord`` that will be generated in the VM.

    Attributes
    ----------
    match : EventMatch
        The original match.
    vm_event : EventRecord
        The corresponding VM event record.
    block_id : int
        Code block where the event lives.
    instruction_index : int
        Instruction index within the block.
    """

    match: EventMatch
    vm_event: EventRecord
    block_id: int = 0
    instruction_index: int = 0


class SchemaBuilder:
    """Constructs the enriched schema from a CFG and event specifications.

    This corresponds to Larus's "schema construction" phase.  It walks
    the CFG (via the abstract compiler) and the original token stream,
    matching user-defined events and injecting ``EVENT`` instructions
    into the abstract bytecode.

    Parameters
    ----------
    events : List[AbsExecEvent]
        User-defined events to match.
    compiler : Optional[AbstractCompiler]
        The abstract compiler to use.  If ``None``, a default one is
        created.
    use_symbolic : bool
        If ``True`` and symbolic_exec is available, perform symbolic
        execution alongside compilation for richer matching context.
    """

    def __init__(
        self,
        events: List[AbsExecEvent],
        compiler: Optional[AbstractCompiler] = None,
        use_symbolic: bool = True,
    ):
        self._events = sorted(events, key=lambda e: e.priority)
        self._compiler = compiler or AbstractCompiler(insert_events=True)
        self._use_symbolic = use_symbolic and _HAS_SYMEXEC
        self._matched_events: List[SchemaEventRecord] = []
        self._step_counter = itertools.count(0)

    @property
    def matched_events(self) -> List[SchemaEventRecord]:
        """All events matched during the last ``build_schema`` call."""
        return list(self._matched_events)

    def build_schema(
        self,
        cfg: CFG,
        func_name: str = "<unknown>",
        source_file: Optional[str] = None,
        initial_symbolic_state: Optional[Any] = None,
    ) -> Tuple[FunctionCode, List[SchemaEventRecord]]:
        """Build an enriched abstract program from a CFG.

        Returns the compiled ``FunctionCode`` with injected ``EVENT``
        instructions, and the list of matched events.

        Parameters
        ----------
        cfg : CFG
            The control-flow graph.
        func_name : str
            Function name.
        source_file : Optional[str]
            Source file path.
        initial_symbolic_state : Optional
            Initial state for symbolic execution (if ``use_symbolic``).

        Returns
        -------
        Tuple[FunctionCode, List[SchemaEventRecord]]
        """
        self._matched_events.clear()
        self._step_counter = itertools.count(0)

        # Phase 1: Compile CFG to abstract bytecode
        fc = self._compiler.compile_cfg(cfg, func_name=func_name, source_file=source_file)

        # Phase 2: Walk the original CFG tokens and match events
        token_matches = self._match_tokens(cfg, func_name, source_file)

        # Phase 3: Walk the compiled bytecode and match instruction-level events
        instr_matches = self._match_instructions(fc, func_name, source_file)

        # Phase 4: Match CFG edges
        edge_matches = self._match_edges(cfg, func_name, source_file)

        # Phase 5: Inject matched events into the bytecode
        all_matches = token_matches + instr_matches + edge_matches
        self._inject_events(fc, all_matches)

        self._matched_events = all_matches
        return fc, all_matches

    def build_program_schema(
        self,
        cfgs: Mapping[str, CFG],
        source_file: Optional[str] = None,
    ) -> Tuple[AbstractProgram, List[SchemaEventRecord]]:
        """Build enriched schemas for multiple functions.

        Parameters
        ----------
        cfgs : Mapping[str, CFG]
            Function name → CFG.
        source_file : Optional[str]
            Source file path.

        Returns
        -------
        Tuple[AbstractProgram, List[SchemaEventRecord]]
        """
        program = AbstractProgram(source_file=source_file)
        all_events: List[SchemaEventRecord] = []

        for name, cfg in cfgs.items():
            fc, matches = self.build_schema(cfg, func_name=name, source_file=source_file)
            program.add_function(fc)
            all_events.extend(matches)

        return program, all_events

    # ---- Internal matching methods ------------------------------------------

    def _match_tokens(
        self,
        cfg: CFG,
        func_name: str,
        source_file: Optional[str],
    ) -> List[SchemaEventRecord]:
        """Walk CFG tokens and match token-level events."""
        results: List[SchemaEventRecord] = []

        for bb in cfg.blocks:
            tokens = getattr(bb, "tokens", None) or []
            if not isinstance(tokens, (list, tuple)):
                tokens = [tokens]

            for idx, tok in enumerate(tokens):
                if tok is None:
                    continue

                ctx = MatchContext(
                    function_name=func_name,
                    scope=getattr(tok, "scope", None),
                    block=bb,
                    cfg=cfg,
                    token_index=idx,
                    source_file=source_file,
                    line=getattr(tok, "linenr", 0) or 0,
                    column=getattr(tok, "column", 0) or 0,
                )

                for event in self._events:
                    match = event.match_token(tok, ctx)
                    if match is not None:
                        step = next(self._step_counter)
                        vm_event = EventRecord(
                            event_id=match.event_id,
                            params=tuple(match.bindings.get(k, None) for k in sorted(match.bindings)),
                            source_loc=match.source_loc,
                            step=step,
                            func_name=func_name,
                            block_id=bb.id,
                        )
                        results.append(
                            SchemaEventRecord(
                                match=match,
                                vm_event=vm_event,
                                block_id=bb.id,
                                instruction_index=idx,
                            )
                        )

        return results

    def _match_instructions(
        self,
        fc: FunctionCode,
        func_name: str,
        source_file: Optional[str],
    ) -> List[SchemaEventRecord]:
        """Walk compiled bytecode and match instruction-level events."""
        results: List[SchemaEventRecord] = []

        for bid in fc.block_order():
            blk = fc.blocks.get(bid)
            if blk is None:
                continue

            for idx, instr in enumerate(blk.instructions):
                ctx = MatchContext(
                    function_name=func_name,
                    block=blk.cfg_block,
                    source_file=source_file,
                    line=instr.source_loc[1] if instr.source_loc else 0,
                    column=instr.source_loc[2] if instr.source_loc else 0,
                )

                for event in self._events:
                    match = event.match_instruction(instr, None, ctx)
                    if match is not None:
                        step = next(self._step_counter)
                        vm_event = EventRecord(
                            event_id=match.event_id,
                            params=tuple(match.bindings.get(k, None) for k in sorted(match.bindings)),
                            source_loc=match.source_loc or instr.source_loc,
                            step=step,
                            func_name=func_name,
                            block_id=bid,
                        )
                        results.append(
                            SchemaEventRecord(
                                match=match,
                                vm_event=vm_event,
                                block_id=bid,
                                instruction_index=idx,
                            )
                        )

        return results

    def _match_edges(
        self,
        cfg: CFG,
        func_name: str,
        source_file: Optional[str],
    ) -> List[SchemaEventRecord]:
        """Match events on CFG edges."""
        results: List[SchemaEventRecord] = []

        for edge in cfg.edges:
            ctx = MatchContext(
                function_name=func_name,
                cfg=cfg,
                source_file=source_file,
            )

            for event in self._events:
                match = event.match_cfg_edge(edge, ctx)
                if match is not None:
                    step = next(self._step_counter)
                    src_id = edge.src.id if edge.src else 0
                    vm_event = EventRecord(
                        event_id=match.event_id,
                        params=tuple(match.bindings.get(k, None) for k in sorted(match.bindings)),
                        source_loc=match.source_loc,
                        step=step,
                        func_name=func_name,
                        block_id=src_id,
                    )
                    results.append(
                        SchemaEventRecord(
                            match=match,
                            vm_event=vm_event,
                            block_id=src_id,
                            instruction_index=-1,  # edge, not instruction
                        )
                    )

        return results

    def _inject_events(
        self,
        fc: FunctionCode,
        matches: List[SchemaEventRecord],
    ) -> None:
        """Inject EVENT instructions into the compiled bytecode for each match.

        Events are inserted *after* the instruction they matched (for
        instruction matches) or at the beginning of the block (for
        token matches that map to a block).
        """
        # Group matches by block_id
        by_block: Dict[int, List[SchemaEventRecord]] = {}
        for m in matches:
            by_block.setdefault(m.block_id, []).append(m)

        for bid, block_matches in by_block.items():
            blk = fc.blocks.get(bid)
            if blk is None:
                continue

            # Sort by instruction index descending so insertions don't
            # shift subsequent indices
            block_matches.sort(key=lambda m: m.instruction_index, reverse=True)

            for m in block_matches:
                event_instr = Instruction(
                    opcode=Opcode.EVENT,
                    operands=(
                        EventRef(
                            event_id=m.match.event_id,
                            params=tuple(
                                m.match.bindings.get(k, None)
                                for k in sorted(m.match.bindings)
                            ),
                        ),
                    ),
                    source_loc=m.match.source_loc,
                    comment=f"abs_exec event: {m.match.event_id}",
                )

                insert_pos = m.instruction_index + 1
                if insert_pos < 0:
                    insert_pos = 0
                if insert_pos > len(blk.instructions):
                    insert_pos = len(blk.instructions)
                blk.instructions.insert(insert_pos, event_instr)


# ═══════════════════════════════════════════════════════════════════════════
# 6. ANALYSIS ENGINE
# ═══════════════════════════════════════════════════════════════════════════


class AbsExecEngine:
    """The main abstract execution engine.

    Orchestrates the full pipeline: event matching → schema construction →
    VM compilation → interpretation → analysis delivery.

    Parameters
    ----------
    events : List[AbsExecEvent]
        User-defined abstract events.
    analyses : List[AbsExecAnalysis]
        User-defined analyses to run.
    compiler : Optional[AbstractCompiler]
        Custom compiler (default: auto-created).
    vm_kwargs : Optional[Dict[str, Any]]
        Extra keyword arguments for ``AbstractVM`` construction.
    exploration_mode : str
        "single" for single-path interpretation, "explore" for
        all-paths exploration.  Default "explore".
    max_paths : int
        Maximum paths to explore (only for "explore" mode).
    use_symbolic : bool
        Whether to use symbolic execution during schema building.

    Usage
    -----
    >>> engine = AbsExecEngine(
    ...     events=[AllocationEvent(), DeallocationEvent()],
    ...     analyses=[MyLeakAnalysis()],
    ... )
    >>> results = engine.run_on_cfg(cfg, func_name="process_data")
    >>> for r in results.reports:
    ...     print(r)
    """

    def __init__(
        self,
        events: Optional[List[AbsExecEvent]] = None,
        analyses: Optional[List[AbsExecAnalysis]] = None,
        compiler: Optional[AbstractCompiler] = None,
        vm_kwargs: Optional[Dict[str, Any]] = None,
        exploration_mode: str = "explore",
        max_paths: int = 1000,
        use_symbolic: bool = True,
    ):
        self._events = list(events or [])
        self._analyses = list(analyses or [])
        self._compiler = compiler
        self._vm_kwargs = dict(vm_kwargs or {})
        self._exploration_mode = exploration_mode
        self._max_paths = max_paths
        self._use_symbolic = use_symbolic

        # State
        self._reports: List[AnalysisReport] = []
        self._schema_listing: Optional[SchemaListing] = None
        self._program: Optional[AbstractProgram] = None
        self._vm: Optional[AbstractVM] = None
        self._schema_events: List[SchemaEventRecord] = []
        self._analysis_states: Dict[str, AnalysisState] = {}

        # Map event_id → EventMatch for fast lookup during VM interpretation
        self._match_index: Dict[Tuple[str, int], EventMatch] = {}

    # ---- Public API ----------------------------------------------------------

    @property
    def reports(self) -> List[AnalysisReport]:
        """All analysis reports produced so far."""
        return list(self._reports)

    @property
    def schema_listing(self) -> Optional[SchemaListing]:
        """The schema listing from the last run."""
        return self._schema_listing

    @property
    def program(self) -> Optional[AbstractProgram]:
        """The compiled abstract program from the last run."""
        return self._program

    @property
    def vm(self) -> Optional[AbstractVM]:
        """The abstract VM from the last run."""
        return self._vm

    @property
    def matched_events(self) -> List[SchemaEventRecord]:
        """Events matched during the last schema build."""
        return list(self._schema_events)

    @property
    def cumulative_cost(self) -> Optional[IntervalDomain]:
        """Cumulative cost from the last run's VM execution."""
        if self._vm is not None:
            return self._vm.cumulative_cost
        return None

    def add_event(self, event: AbsExecEvent) -> AbsExecEngine:
        """Register an additional event type.  Returns ``self`` for chaining."""
        self._events.append(event)
        return self

    def add_analysis(self, analysis: AbsExecAnalysis) -> AbsExecEngine:
        """Register an additional analysis.  Returns ``self`` for chaining."""
        self._analyses.append(analysis)
        return self

    def report(
        self,
        message: str,
        severity: str = "warning",
        event_id: str = "",
        source_loc: Optional[Tuple[str, int, int]] = None,
        step: int = 0,
        bindings: Optional[Dict[str, Any]] = None,
        analysis_name: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit an analysis report.

        Called by ``AbsExecAnalysis`` subclasses to record findings.
        """
        self._reports.append(
            AnalysisReport(
                message=message,
                severity=severity,
                event_id=event_id,
                source_loc=source_loc,
                step=step,
                bindings=bindings or {},
                analysis_name=analysis_name,
                metadata=metadata or {},
            )
        )

    # ---- Single-function execution ------------------------------------------

    def run_on_cfg(
        self,
        cfg: CFG,
        func_name: str = "<unknown>",
        source_file: Optional[str] = None,
        initial_state: Optional[Dict[str, AbstractDomain]] = None,
    ) -> AbsExecResult:
        """Run the full abstract execution pipeline on a single CFG.

        Parameters
        ----------
        cfg : CFG
            The control-flow graph.
        func_name : str
            Function name.
        source_file : Optional[str]
            Source file path.
        initial_state : Optional[Dict[str, AbstractDomain]]
            Initial abstract register values for VM interpretation.

        Returns
        -------
        AbsExecResult
            Collected reports, schema, cost, and metadata.
        """
        self._reports.clear()
        self._analysis_states.clear()
        self._match_index.clear()

        # Phase 1: Build enriched schema
        builder = SchemaBuilder(
            events=self._events,
            compiler=self._compiler,
            use_symbolic=self._use_symbolic,
        )
        fc, schema_events = builder.build_schema(
            cfg, func_name=func_name, source_file=source_file
        )
        self._schema_events = schema_events

        # Build match index for fast lookup
        for se in schema_events:
            key = (se.match.event_id, se.vm_event.step)
            self._match_index[key] = se.match

        # Phase 2: Wrap in a program and create VM
        program = AbstractProgram(source_file=source_file)
        program.add_function(fc)
        self._program = program

        vm = AbstractVM(program, **self._vm_kwargs)
        self._vm = vm

        # Register an internal event handler that dispatches to analyses
        dispatcher = _AnalysisDispatcher(self, self._analyses, self._match_index)
        vm.register_event_handler(dispatcher)

        # Phase 3: Initialise analysis states
        for analysis in self._analyses:
            state: AnalysisState = {}
            self._analysis_states[analysis.analysis_name] = state
            analysis.on_begin(state, self)

        # Phase 4: Run the VM
        if self._exploration_mode == "explore":
            schema = vm.explore(
                func_name,
                initial_state=initial_state,
                max_paths=self._max_paths,
            )
        else:
            schema = vm.interpret(func_name, initial_state=initial_state)

        self._schema_listing = schema

        # Phase 5: Walk schema entries and deliver to analyses
        for entry in schema.entries:
            for analysis in self._analyses:
                state = self._analysis_states[analysis.analysis_name]
                analysis.on_schema_entry(entry, state, self)

            # Deliver events from this entry
            for ev_record in entry.events:
                self._deliver_event(ev_record)

        # Phase 6: Deliver any events from VM that weren't in schema entries
        schema_event_steps: Set[int] = set()
        for entry in schema.entries:
            for er in entry.events:
                schema_event_steps.add(er.step)
        for er in vm.events:
            if er.step not in schema_event_steps:
                self._deliver_event(er)

        # Phase 7: Complete analyses
        for analysis in self._analyses:
            state = self._analysis_states[analysis.analysis_name]
            analysis.on_complete(state, self)

        return AbsExecResult(
            reports=list(self._reports),
            schema=schema,
            program=program,
            matched_events=list(self._schema_events),
            cost=vm.cumulative_cost,
            analysis_states=dict(self._analysis_states),
            vm_step_count=vm.step_count,
        )

    # ---- Multi-function execution -------------------------------------------

    def run_on_program(
        self,
        cfgs: Mapping[str, CFG],
        source_file: Optional[str] = None,
        initial_states: Optional[Dict[str, Dict[str, AbstractDomain]]] = None,
    ) -> AbsExecResult:
        """Run abstract execution on multiple functions.

        Parameters
        ----------
        cfgs : Mapping[str, CFG]
            Function name → CFG.
        source_file : Optional[str]
            Source file.
        initial_states : Optional[Dict[str, Dict[str, AbstractDomain]]]
            Per-function initial abstract states.

        Returns
        -------
        AbsExecResult
        """
        self._reports.clear()
        self._analysis_states.clear()
        self._match_index.clear()

        initial_states = initial_states or {}
        all_schema_events: List[SchemaEventRecord] = []

        # Build schemas for all functions
        builder = SchemaBuilder(
            events=self._events,
            compiler=self._compiler,
            use_symbolic=self._use_symbolic,
        )
        program, schema_events = builder.build_program_schema(cfgs, source_file=source_file)
        all_schema_events.extend(schema_events)
        self._schema_events = all_schema_events
        self._program = program

        # Build match index
        for se in all_schema_events:
            key = (se.match.event_id, se.vm_event.step)
            self._match_index[key] = se.match

        # Create VM
        vm = AbstractVM(program, **self._vm_kwargs)
        self._vm = vm

        dispatcher = _AnalysisDispatcher(self, self._analyses, self._match_index)
        vm.register_event_handler(dispatcher)

        # Initialise analysis states
        for analysis in self._analyses:
            state: AnalysisState = {}
            self._analysis_states[analysis.analysis_name] = state
            analysis.on_begin(state, self)

        # Run each function
        total_cost = IntervalDomain.const(0)
        total_steps = 0
        combined_schema = SchemaListing(func_name="<program>")

        for func_name in sorted(program.functions.keys()):
            init = initial_states.get(func_name)
            if self._exploration_mode == "explore":
                schema = vm.explore(
                    func_name,
                    initial_state=init,
                    max_paths=self._max_paths,
                )
            else:
                schema = vm.interpret(func_name, initial_state=init)

            # Merge into combined schema
            for entry in schema.entries:
                combined_schema.append(entry)
                for analysis in self._analyses:
                    a_state = self._analysis_states[analysis.analysis_name]
                    analysis.on_schema_entry(entry, a_state, self)
                for ev_record in entry.events:
                    self._deliver_event(ev_record)

            combined_schema.path_count += schema.path_count
            total_cost = total_cost.add(schema.total_cost)
            total_steps += vm.step_count

        self._schema_listing = combined_schema

        # Complete analyses
        for analysis in self._analyses:
            state = self._analysis_states[analysis.analysis_name]
            analysis.on_complete(state, self)

        return AbsExecResult(
            reports=list(self._reports),
            schema=combined_schema,
            program=program,
            matched_events=list(all_schema_events),
            cost=total_cost,
            analysis_states=dict(self._analysis_states),
            vm_step_count=total_steps,
        )

    # ---- Internal event delivery --------------------------------------------

    def _deliver_event(self, record: EventRecord) -> None:
        """Deliver an event record to all matching analyses."""
        # Look up the original EventMatch
        match_key = (record.event_id, record.step)
        original_match = self._match_index.get(match_key)

        for analysis in self._analyses:
            if analysis.listens_to is not None and record.event_id not in analysis.listens_to:
                continue
            state = self._analysis_states.get(analysis.analysis_name, {})
            analysis.on_event(record, original_match, state, self)


# ═══════════════════════════════════════════════════════════════════════════
# 7. INTERNAL EVENT HANDLER (bridges VM events to analyses)
# ═══════════════════════════════════════════════════════════════════════════


class _AnalysisDispatcher:
    """Internal event handler that dispatches VM events to analyses.

    Registered with the ``AbstractVM`` to intercept ``EVENT`` instructions
    during interpretation and forward them to the engine's analysis
    delivery mechanism.

    Implements the ``EventHandler`` protocol.
    """

    # Accept all event IDs by using a wildcard
    event_id: str = "*"

    def __init__(
        self,
        engine: AbsExecEngine,
        analyses: List[AbsExecAnalysis],
        match_index: Dict[Tuple[str, int], EventMatch],
    ):
        self._engine = engine
        self._analyses = analyses
        self._match_index = match_index

    def handle(
        self,
        event: EventRecord,
        frame: ActivationFrame,
        vm: AbstractVM,
    ) -> None:
        """Forward the event to the engine's delivery mechanism.

        We also snapshot the abstract state into the event for richer
        analysis context.
        """
        # The engine._deliver_event handles analysis routing
        self._engine._deliver_event(event)


# ═══════════════════════════════════════════════════════════════════════════
# 8. RESULT OBJECT
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class AbsExecResult:
    """Result of an abstract execution run.

    Attributes
    ----------
    reports : List[AnalysisReport]
        All reports produced by analyses.
    schema : SchemaListing
        The schema listing.
    program : AbstractProgram
        The compiled abstract program.
    matched_events : List[SchemaEventRecord]
        All events matched during schema construction.
    cost : IntervalDomain
        Total abstract cost.
    analysis_states : Dict[str, AnalysisState]
        Final state of each analysis (keyed by analysis_name).
    vm_step_count : int
        Total VM steps executed.
    """

    reports: List[AnalysisReport] = field(default_factory=list)
    schema: Optional[SchemaListing] = None
    program: Optional[AbstractProgram] = None
    matched_events: List[SchemaEventRecord] = field(default_factory=list)
    cost: IntervalDomain = field(default_factory=lambda: IntervalDomain.const(0))
    analysis_states: Dict[str, AnalysisState] = field(default_factory=dict)
    vm_step_count: int = 0

    @property
    def has_errors(self) -> bool:
        return any(r.severity == "error" for r in self.reports)

    @property
    def has_warnings(self) -> bool:
        return any(r.severity == "warning" for r in self.reports)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.reports if r.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for r in self.reports if r.severity == "warning")

    def filter_reports(
        self,
        severity: Optional[str] = None,
        event_id: Optional[str] = None,
        analysis_name: Optional[str] = None,
    ) -> List[AnalysisReport]:
        """Filter reports by criteria."""
        results = self.reports
        if severity is not None:
            results = [r for r in results if r.severity == severity]
        if event_id is not None:
            results = [r for r in results if r.event_id == event_id]
        if analysis_name is not None:
            results = [r for r in results if r.analysis_name == analysis_name]
        return results

    def dump(self) -> str:
        """Pretty-print the result."""
        lines: List[str] = []
        lines.append(f"AbsExecResult: {len(self.reports)} reports, "
                      f"{len(self.matched_events)} events matched, "
                      f"cost={self.cost}")
        if self.reports:
            lines.append("  Reports:")
            for r in self.reports:
                lines.append(f"    {r}")
        if self.schema:
            lines.append(f"  Schema: {self.schema.func_name}, "
                          f"{len(self.schema.entries)} entries, "
                          f"paths={self.schema.path_count}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"AbsExecResult(reports={len(self.reports)}, "
            f"events={len(self.matched_events)}, "
            f"cost={self.cost})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 9. BUILT-IN ANALYSES
# ═══════════════════════════════════════════════════════════════════════════


class ResourceLeakAnalysis(AbsExecAnalysis):
    """Detects potential resource leaks (alloc without matching dealloc).

    Tracks allocation events and checks that each is paired with a
    deallocation before function exit.  This is the classic PQL-style
    query: ``alloc(x) ; ... ; ~free(x)`` (alloc not followed by free).

    Parameters
    ----------
    alloc_events : Set[str]
        Event kinds that represent allocation.
    dealloc_events : Set[str]
        Event kinds that represent deallocation.
    severity : str
        Severity for leak reports.
    """

    analysis_name: ClassVar[str] = "resource_leak"
    listens_to: ClassVar[Optional[Set[str]]] = {"alloc", "dealloc", "free", "func_exit"}

    def __init__(
        self,
        alloc_events: Optional[Set[str]] = None,
        dealloc_events: Optional[Set[str]] = None,
        severity: str = "warning",
    ):
        self._alloc_events = alloc_events or {"alloc"}
        self._dealloc_events = dealloc_events or {"dealloc", "free"}
        self._severity = severity

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        state["active_allocs"] = {}  # step → (source_loc, bindings)

    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        active: Dict[int, Tuple[Any, Dict]] = state["active_allocs"]

        if record.event_id in self._alloc_events:
            bindings = match.bindings if match else {}
            active[record.step] = (record.source_loc, bindings)

        elif record.event_id in self._dealloc_events:
            # Heuristic: remove the most recent allocation
            if active:
                # In a real analysis, we'd match by pointer value;
                # here we use LIFO as a conservative heuristic
                most_recent = max(active.keys())
                del active[most_recent]

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        active: Dict[int, Tuple[Any, Dict]] = state["active_allocs"]
        for step, (loc, bindings) in active.items():
            engine.report(
                message=f"Potential resource leak: allocation at step {step} not freed",
                severity=self._severity,
                event_id="alloc",
                source_loc=loc,
                step=step,
                bindings=bindings,
                analysis_name=self.analysis_name,
            )


class CostAnalysis(AbsExecAnalysis):
    """Static cost analysis using abstract execution.

    Accumulates the abstract cost of each instruction and reports
    functions that exceed a configurable cost threshold.

    Parameters
    ----------
    max_cost : float
        Report functions whose maximum estimated cost exceeds this value.
    """

    analysis_name: ClassVar[str] = "cost_analysis"
    listens_to: ClassVar[Optional[Set[str]]] = None  # Receives all events

    def __init__(self, max_cost: float = 10000.0):
        self._max_cost = max_cost

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        state["total_cost"] = IntervalDomain.const(0)
        state["block_costs"] = {}  # block_id → IntervalDomain

    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        # Cost analysis primarily uses on_schema_entry
        pass

    def on_schema_entry(
        self,
        entry: SchemaEntry,
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        cost: IntervalDomain = entry.cost if isinstance(entry.cost, IntervalDomain) else IntervalDomain.const(0)
        state["total_cost"] = state["total_cost"].add(cost)

        block_costs: Dict[int, IntervalDomain] = state["block_costs"]
        if entry.block_id in block_costs:
            block_costs[entry.block_id] = block_costs[entry.block_id].add(cost)
        else:
            block_costs[entry.block_id] = cost

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        total: IntervalDomain = state["total_cost"]
        if total.hi > self._max_cost:
            engine.report(
                message=(
                    f"Function cost [{total.lo}, {total.hi}] "
                    f"exceeds threshold {self._max_cost}"
                ),
                severity="performance",
                event_id="cost",
                analysis_name=self.analysis_name,
                metadata={"cost": total, "block_costs": state["block_costs"]},
            )


class SequenceAnalysis(AbsExecAnalysis):
    """Generic analysis that uses ``EventSequenceMatcher`` to find patterns.

    Parameters
    ----------
    matcher : EventSequenceMatcher
        The sequence matcher to use.
    on_match : Callable[[SequenceMatchResult, AbsExecEngine], None]
        Callback invoked when a complete sequence match is found.
    on_incomplete : Optional[Callable[[SequenceMatchResult, AbsExecEngine], None]]
        Callback for incomplete matches (flushed at end).
    """

    analysis_name: ClassVar[str] = "sequence"

    def __init__(
        self,
        matcher: EventSequenceMatcher,
        on_match: Optional[Callable[[SequenceMatchResult, AbsExecEngine], None]] = None,
        on_incomplete: Optional[Callable[[SequenceMatchResult, AbsExecEngine], None]] = None,
        name: Optional[str] = None,
    ):
        self._matcher = matcher
        self._on_match = on_match or self._default_on_match
        self._on_incomplete = on_incomplete
        if name:
            self.analysis_name = name  # type: ignore[misc]

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        self._matcher.reset()
        state["matches"] = []
        state["incomplete"] = []

    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        results = self._matcher.feed(record, match, state)
        for result in results:
            if result.matched:
                state["matches"].append(result)
                self._on_match(result, engine)

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        # Flush incomplete sequences
        incomplete = self._matcher.flush()
        state["incomplete"] = incomplete
        if self._on_incomplete:
            for inc in incomplete:
                self._on_incomplete(inc, engine)

    @staticmethod
    def _default_on_match(result: SequenceMatchResult, engine: AbsExecEngine) -> None:
        engine.report(
            message=f"Event sequence matched: {result.steps_matched} steps, "
                    f"bindings={result.bindings}",
            severity="info",
            event_id="sequence_match",
            analysis_name="sequence",
        )


class UseAfterFreeAnalysis(AbsExecAnalysis):
    """Detects potential use-after-free via event sequences.

    Watches for: ``free(p) ; ... ; use(p)`` where ``use`` is a memory
    read or write involving the freed pointer.

    This is a simplified version; a full implementation would integrate
    with pointer analysis.
    """

    analysis_name: ClassVar[str] = "use_after_free"
    listens_to: ClassVar[Optional[Set[str]]] = {"dealloc", "free", "mem_read", "mem_write"}

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        state["freed_pointers"] = set()  # Set of pointer register names

    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        freed: Set[str] = state["freed_pointers"]

        if record.event_id in ("dealloc", "free"):
            if match and "src" in match.bindings:
                src = match.bindings["src"]
                if isinstance(src, Reg):
                    freed.add(src.name)

        elif record.event_id in ("mem_read", "mem_write"):
            if match and "base" in match.bindings:
                base = match.bindings["base"]
                if isinstance(base, Reg) and base.name in freed:
                    engine.report(
                        message=f"Potential use-after-free: {base} was freed",
                        severity="error",
                        event_id=record.event_id,
                        source_loc=record.source_loc,
                        step=record.step,
                        bindings=match.bindings if match else {},
                        analysis_name=self.analysis_name,
                    )

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        pass


class DoubleFreAnalysis(AbsExecAnalysis):
    """Detects potential double-free.

    Watches for: ``free(p) ; ... ; free(p)``.
    """

    analysis_name: ClassVar[str] = "double_free"
    listens_to: ClassVar[Optional[Set[str]]] = {"dealloc", "free"}

    def on_begin(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        state["freed"] = set()  # Set of (pointer_name,)

    def on_event(
        self,
        record: EventRecord,
        match: Optional[EventMatch],
        state: AnalysisState,
        engine: AbsExecEngine,
    ) -> None:
        freed: Set[str] = state["freed"]

        if record.event_id in ("dealloc", "free"):
            ptr_name = None
            if match and "src" in match.bindings:
                src = match.bindings["src"]
                if isinstance(src, Reg):
                    ptr_name = src.name
            if match and "func" in match.bindings:
                # Token-level match might not have "src"
                ptr_name = ptr_name or str(match.bindings.get("func", "?"))

            if ptr_name:
                if ptr_name in freed:
                    engine.report(
                        message=f"Potential double-free of {ptr_name}",
                        severity="error",
                        event_id=record.event_id,
                        source_loc=record.source_loc,
                        step=record.step,
                        analysis_name=self.analysis_name,
                    )
                else:
                    freed.add(ptr_name)

    def on_complete(self, state: AnalysisState, engine: AbsExecEngine) -> None:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# 10. CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def run_abstract_execution(
    cfg: CFG,
    events: List[AbsExecEvent],
    analyses: List[AbsExecAnalysis],
    func_name: str = "<unknown>",
    source_file: Optional[str] = None,
    **engine_kwargs: Any,
) -> AbsExecResult:
    """One-shot convenience function for running abstract execution.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    events : List[AbsExecEvent]
        Abstract events to watch for.
    analyses : List[AbsExecAnalysis]
        Analyses to run.
    func_name : str
        Function name.
    source_file : Optional[str]
        Source file.
    **engine_kwargs
        Additional arguments for ``AbsExecEngine``.

    Returns
    -------
    AbsExecResult
    """
    engine = AbsExecEngine(events=events, analyses=analyses, **engine_kwargs)
    return engine.run_on_cfg(cfg, func_name=func_name, source_file=source_file)


def check_resource_leaks(
    cfg: CFG,
    func_name: str = "<unknown>",
    alloc_funcs: Optional[Set[str]] = None,
    free_funcs: Optional[Set[str]] = None,
    **engine_kwargs: Any,
) -> AbsExecResult:
    """Convenience: run resource-leak analysis on a CFG.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    func_name : str
        Function name.
    alloc_funcs : Optional[Set[str]]
        Allocation function names.
    free_funcs : Optional[Set[str]]
        Deallocation function names.

    Returns
    -------
    AbsExecResult
    """
    events: List[AbsExecEvent] = [
        AllocationEvent(alloc_funcs),
        DeallocationEvent(free_funcs),
    ]
    analyses: List[AbsExecAnalysis] = [ResourceLeakAnalysis()]
    return run_abstract_execution(
        cfg, events, analyses, func_name=func_name, **engine_kwargs
    )


def estimate_function_cost(
    cfg: CFG,
    func_name: str = "<unknown>",
    max_cost: float = 10000.0,
    **engine_kwargs: Any,
) -> AbsExecResult:
    """Convenience: run cost analysis on a CFG.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    func_name : str
        Function name.
    max_cost : float
        Threshold for cost reports.

    Returns
    -------
    AbsExecResult
    """
    events: List[AbsExecEvent] = []  # Cost analysis doesn't need special events
    analyses: List[AbsExecAnalysis] = [CostAnalysis(max_cost=max_cost)]
    return run_abstract_execution(
        cfg, events, analyses, func_name=func_name, **engine_kwargs
    )


def check_use_after_free(
    cfg: CFG,
    func_name: str = "<unknown>",
    **engine_kwargs: Any,
) -> AbsExecResult:
    """Convenience: run use-after-free analysis.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    func_name : str
        Function name.

    Returns
    -------
    AbsExecResult
    """
    events: List[AbsExecEvent] = [
        DeallocationEvent(),
        MemoryReadEvent(),
        MemoryWriteEvent(),
    ]
    analyses: List[AbsExecAnalysis] = [UseAfterFreeAnalysis()]
    return run_abstract_execution(
        cfg, events, analyses, func_name=func_name, **engine_kwargs
    )


def check_double_free(
    cfg: CFG,
    func_name: str = "<unknown>",
    **engine_kwargs: Any,
) -> AbsExecResult:
    """Convenience: run double-free analysis.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    func_name : str
        Function name.

    Returns
    -------
    AbsExecResult
    """
    events: List[AbsExecEvent] = [DeallocationEvent()]
    analyses: List[AbsExecAnalysis] = [DoubleFreAnalysis()]
    return run_abstract_execution(
        cfg, events, analyses, func_name=func_name, **engine_kwargs
    )


# ═══════════════════════════════════════════════════════════════════════════
# 11. INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════


def _token_loc(tok: Any) -> Optional[Tuple[str, int, int]]:
    """Extract source location from a token (best-effort)."""
    f = getattr(tok, "file", None)
    l = getattr(tok, "linenr", None)
    c = getattr(tok, "column", None)
    if f is not None or l is not None:
        return (
            str(f) if f else "<unknown>",
            int(l) if l else 0,
            int(c) if c else 0,
        )
    return None
