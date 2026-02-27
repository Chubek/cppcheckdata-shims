"""
casl/runtime.py
===============

CASL Runtime System — bridges the abstract VM infrastructure from cppcheckdata-shims
with CASL/CSQL language-level constructs for property monitoring, abstract interpretation,
trace recording, and counterexample generation.

This module provides:

* ``CaslRuntime``          – top-level façade that owns a VM, domains, and checker
* ``CaslActivationFrame``  – CASL-specific activation frame with property context
* ``PropertyMonitor``      – runtime observer that watches property automata
* ``DomainRegistry``       – registry of abstract domains keyed by type tag
* ``CaslExplorer``         – CASL-specific bounded explorer with property awareness
* ``CaslTraceBuilder``     – constructs human-readable counterexample traces
* ``RuntimeConfig``        – configuration dataclass for tuning exploration/interpretation
* Helper enums and dataclasses for exploration status, runtime events, etc.
"""

from __future__ import annotations

import enum
import time
import logging
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
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
    TypeVar,
    Union,
    runtime_checkable,
)

# ---------------------------------------------------------------------------
# Local imports — these come from the cppcheckdata-shims infrastructure and
# from the previously-implemented casl/errors.py module.
# ---------------------------------------------------------------------------
from casl.errors import (
    CaslError,
    ErrorReporter,
    RuntimeError as CaslRuntimeError,
    InternalError,
    ErrorCode,
)

logger = logging.getLogger(__name__)

# ===================================================================== #
#  Type Variables                                                        #
# ===================================================================== #

S = TypeVar("S")          # abstract state
A = TypeVar("A")          # action / transition label
D = TypeVar("D")          # abstract domain element
T = TypeVar("T")          # generic

# ===================================================================== #
#  Protocols — mirror the cppcheckdata-shims infrastructure contracts    #
# ===================================================================== #

@runtime_checkable
class AbstractDomain(Protocol):
    """Lattice element with join, meet, widen, narrow, leq, bottom, top."""

    def join(self, other: AbstractDomain) -> AbstractDomain: ...
    def meet(self, other: AbstractDomain) -> AbstractDomain: ...
    def leq(self, other: AbstractDomain) -> bool: ...
    def is_bottom(self) -> bool: ...
    def is_top(self) -> bool: ...
    def widen(self, other: AbstractDomain) -> AbstractDomain: ...
    def narrow(self, other: AbstractDomain) -> AbstractDomain: ...


@runtime_checkable
class EventHandler(Protocol):
    """Callback invoked when the VM fires a named event."""

    def handle(self, event_name: str, payload: Any) -> None: ...


@runtime_checkable
class ObserverHandler(Protocol):
    """Callback invoked after every VM step for observation / monitoring."""

    def observe(self, step: int, state: Any) -> None: ...


# ===================================================================== #
#  Enums                                                                 #
# ===================================================================== #

class Opcode(enum.Enum):
    """All 25 opcodes supported by the abstract VM."""
    NOP = "nop"
    LOAD_CONST = "load_const"
    LOAD_VAR = "load_var"
    STORE_VAR = "store_var"
    BINOP = "binop"
    UNOP = "unop"
    JUMP = "jump"
    BRANCH = "branch"
    CALL = "call"
    RETURN = "return"
    PHI = "phi"
    ALLOC = "alloc"
    FREE = "free"
    LOAD_MEM = "load_mem"
    STORE_MEM = "store_mem"
    EVENT = "event"
    OBSERVE = "observe"
    ASSERT = "assert"
    ASSUME = "assume"
    HAVOC = "havoc"
    WIDEN = "widen"
    NARROW = "narrow"
    COST = "cost"
    HALT = "halt"
    LABEL = "label"


class ExplorationStatus(enum.Enum):
    """Outcome of a bounded exploration run."""
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    DEPTH_EXCEEDED = "depth_exceeded"
    STATE_LIMIT = "state_limit"


class PropertyVerdict(enum.Enum):
    """Result of checking a single temporal / safety property."""
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    INCONCLUSIVE = "inconclusive"


class MonitorState(enum.Enum):
    """Internal state of a property monitor automaton."""
    INACTIVE = "inactive"
    ACTIVE = "active"
    ACCEPTING = "accepting"
    REJECTING = "rejecting"
    ERROR = "error"


# ===================================================================== #
#  Lightweight Operand and Instruction Mirrors                           #
# ===================================================================== #

@dataclass(frozen=True, slots=True)
class Reg:
    """Virtual register reference."""
    index: int

    def __repr__(self) -> str:
        return f"r{self.index}"


@dataclass(frozen=True, slots=True)
class BlockRef:
    """Reference to a basic block inside a function."""
    func_index: int
    block_index: int

    def __repr__(self) -> str:
        return f"B{self.func_index}.{self.block_index}"


@dataclass(frozen=True, slots=True)
class FuncRef:
    """Reference to a function in the program."""
    index: int

    def __repr__(self) -> str:
        return f"F{self.index}"


@dataclass(frozen=True, slots=True)
class EventRef:
    """Reference to a named event."""
    name: str

    def __repr__(self) -> str:
        return f"evt:{self.name}"


@dataclass(frozen=True, slots=True)
class ObserverRef:
    """Reference to a named observer."""
    name: str

    def __repr__(self) -> str:
        return f"obs:{self.name}"


@dataclass(frozen=True, slots=True)
class CostLiteral:
    """Literal cost annotation attached to an instruction."""
    value: float

    def __repr__(self) -> str:
        return f"cost({self.value})"


# Union of all operand types
Operand = Union[Reg, BlockRef, FuncRef, EventRef, ObserverRef, CostLiteral, int, float, str, bool]


@dataclass
class SourceLocation:
    """Source position for diagnostics."""
    file: str = "<unknown>"
    line: int = 0
    column: int = 0

    def __repr__(self) -> str:
        return f"{self.file}:{self.line}:{self.column}"


@dataclass
class Instruction:
    """Single VM instruction with opcode, operands, cost, and source location."""
    opcode: Opcode
    operands: List[Operand] = field(default_factory=list)
    cost: float = 0.0
    source_loc: Optional[SourceLocation] = None
    comment: str = ""

    @property
    def dst(self) -> Optional[Reg]:
        """Destination register, if any (first operand when it is a Reg for defining opcodes)."""
        if self.operands and isinstance(self.operands[0], Reg):
            return self.operands[0]
        return None

    def regs_used(self) -> List[Reg]:
        """All register operands read by this instruction."""
        # For defining opcodes the first Reg is the destination, skip it
        start = 1 if self.dst is not None else 0
        return [op for op in self.operands[start:] if isinstance(op, Reg)]

    def regs_defined(self) -> List[Reg]:
        """Registers written by this instruction."""
        d = self.dst
        return [d] if d is not None else []

    def __repr__(self) -> str:
        ops = ", ".join(repr(o) for o in self.operands)
        loc = f" @ {self.source_loc}" if self.source_loc else ""
        return f"Instruction({self.opcode.value} {ops}{loc})"


# ===================================================================== #
#  Structural Types — Blocks, Functions, Programs                        #
# ===================================================================== #

@dataclass
class BasicBlock:
    """A sequence of instructions terminated by a control-flow instruction."""
    index: int
    instructions: List[Instruction] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class FunctionCode:
    """A function consisting of an ordered list of basic blocks."""
    name: str
    index: int
    params: List[Reg] = field(default_factory=list)
    blocks: List[BasicBlock] = field(default_factory=list)
    entry_block: int = 0

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    def block(self, idx: int) -> BasicBlock:
        return self.blocks[idx]


@dataclass
class Program:
    """A complete CASL program: a collection of functions."""
    functions: List[FunctionCode] = field(default_factory=list)
    entry_function: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def function(self, idx: int) -> FunctionCode:
        return self.functions[idx]

    @property
    def num_functions(self) -> int:
        return len(self.functions)


# ===================================================================== #
#  Interval and Bool Domains (concrete implementations)                  #
# ===================================================================== #

_INF = float("inf")
_NEG_INF = float("-inf")


@dataclass(frozen=True, slots=True)
class IntervalDomain:
    """
    Classic integer/float interval abstract domain [lo, hi].

    Conventions:
    - bottom  = IntervalDomain(+∞, -∞)   (empty set)
    - top     = IntervalDomain(-∞, +∞)   (all values)
    """
    lo: float
    hi: float

    # --- Constructors ---------------------------------------------------
    @classmethod
    def bottom(cls) -> IntervalDomain:
        return cls(_INF, _NEG_INF)

    @classmethod
    def top(cls) -> IntervalDomain:
        return cls(_NEG_INF, _INF)

    @classmethod
    def const(cls, v: float) -> IntervalDomain:
        return cls(v, v)

    @classmethod
    def range(cls, lo: float, hi: float) -> IntervalDomain:
        if lo > hi:
            return cls.bottom()
        return cls(lo, hi)

    @classmethod
    def at_least(cls, lo: float) -> IntervalDomain:
        return cls(lo, _INF)

    @classmethod
    def at_most(cls, hi: float) -> IntervalDomain:
        return cls(_NEG_INF, hi)

    # --- Predicates -----------------------------------------------------
    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_top(self) -> bool:
        return self.lo == _NEG_INF and self.hi == _INF

    def is_const(self) -> bool:
        return self.lo == self.hi and not self.is_bottom()

    def const_value(self) -> Optional[float]:
        return self.lo if self.is_const() else None

    def contains(self, v: float) -> bool:
        return self.lo <= v <= self.hi

    def size(self) -> float:
        if self.is_bottom():
            return 0.0
        return self.hi - self.lo

    # --- Lattice --------------------------------------------------------
    def leq(self, other: IntervalDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return other.lo <= self.lo and self.hi <= other.hi

    def join(self, other: IntervalDomain) -> IntervalDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        return IntervalDomain(min(self.lo, other.lo), max(self.hi, other.hi))

    def meet(self, other: IntervalDomain) -> IntervalDomain:
        lo = max(self.lo, other.lo)
        hi = min(self.hi, other.hi)
        if lo > hi:
            return IntervalDomain.bottom()
        return IntervalDomain(lo, hi)

    def widen(self, other: IntervalDomain) -> IntervalDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = _NEG_INF if other.lo < self.lo else self.lo
        new_hi = _INF if other.hi > self.hi else self.hi
        return IntervalDomain(new_lo, new_hi)

    def narrow(self, other: IntervalDomain) -> IntervalDomain:
        if self.is_bottom():
            return self
        new_lo = other.lo if self.lo == _NEG_INF else self.lo
        new_hi = other.hi if self.hi == _INF else self.hi
        return IntervalDomain(new_lo, new_hi)

    # --- Arithmetic transfer functions ----------------------------------
    def add(self, other: IntervalDomain) -> IntervalDomain:
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        return IntervalDomain(self.lo + other.lo, self.hi + other.hi)

    def sub(self, other: IntervalDomain) -> IntervalDomain:
        if self.is_bottom() or other.is_bottom():
            return IntervalDomain.bottom()
        return IntervalDomain(self.lo - other.hi, self.hi - other.lo)

    def neg(self) -> IntervalDomain:
        if self.is_bottom():
            return self
        return IntervalDomain(-self.hi, -self.lo)

    def __repr__(self) -> str:
        if self.is_bottom():
            return "⊥"
        if self.is_top():
            return "⊤"
        return f"[{self.lo}, {self.hi}]"


class _BottomSentinel:
    """Sentinel for BoolDomain bottom."""
    _instance: Optional[_BottomSentinel] = None
    def __new__(cls) -> _BottomSentinel:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __repr__(self) -> str:
        return "⊥"

class _TopSentinel:
    """Sentinel for BoolDomain top."""
    _instance: Optional[_TopSentinel] = None
    def __new__(cls) -> _TopSentinel:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __repr__(self) -> str:
        return "⊤"


_BOTTOM = _BottomSentinel()
_TOP = _TopSentinel()


@dataclass(frozen=True, slots=True)
class BoolDomain:
    """Two-element abstract domain for booleans plus ⊥ and ⊤."""
    value: Union[bool, _BottomSentinel, _TopSentinel]

    @classmethod
    def bottom(cls) -> BoolDomain:
        return cls(_BOTTOM)

    @classmethod
    def top(cls) -> BoolDomain:
        return cls(_TOP)

    @classmethod
    def true_(cls) -> BoolDomain:
        return cls(True)

    @classmethod
    def false_(cls) -> BoolDomain:
        return cls(False)

    @classmethod
    def abstract(cls, v: bool) -> BoolDomain:
        return cls(v)

    def is_bottom(self) -> bool:
        return isinstance(self.value, _BottomSentinel)

    def is_top(self) -> bool:
        return isinstance(self.value, _TopSentinel)

    def is_concrete(self) -> bool:
        return isinstance(self.value, bool)

    def leq(self, other: BoolDomain) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        if self.is_top():
            return other.is_top()
        return self.value == other.value or other.is_top()

    def join(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return BoolDomain.top()
        if self.value == other.value:
            return self
        return BoolDomain.top()

    def meet(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom() or other.is_bottom():
            return BoolDomain.bottom()
        if self.is_top():
            return other
        if other.is_top():
            return self
        if self.value == other.value:
            return self
        return BoolDomain.bottom()

    def widen(self, other: BoolDomain) -> BoolDomain:
        return self.join(other)

    def narrow(self, other: BoolDomain) -> BoolDomain:
        return other

    def and_(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom() or other.is_bottom():
            return BoolDomain.bottom()
        if self.is_concrete() and self.value is False:
            return BoolDomain.false_()
        if other.is_concrete() and other.value is False:
            return BoolDomain.false_()
        if self.is_concrete() and other.is_concrete():
            return BoolDomain.abstract(self.value and other.value)
        return BoolDomain.top()

    def or_(self, other: BoolDomain) -> BoolDomain:
        if self.is_bottom() or other.is_bottom():
            return BoolDomain.bottom()
        if self.is_concrete() and self.value is True:
            return BoolDomain.true_()
        if other.is_concrete() and other.value is True:
            return BoolDomain.true_()
        if self.is_concrete() and other.is_concrete():
            return BoolDomain.abstract(self.value or other.value)
        return BoolDomain.top()

    def not_(self) -> BoolDomain:
        if self.is_bottom():
            return self
        if self.is_top():
            return self
        return BoolDomain.abstract(not self.value)

    def __repr__(self) -> str:
        return repr(self.value)


# ===================================================================== #
#  AbstractState — variable → domain element mapping                     #
# ===================================================================== #

class AbstractState:
    """Immutable-style map from variable names to abstract domain values."""

    __slots__ = ("domain_factory", "_values")

    def __init__(
        self,
        domain_factory: Callable[[], AbstractDomain],
        values: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.domain_factory = domain_factory
        self._values: Dict[str, Any] = dict(values) if values else {}

    def get(self, var: str) -> Any:
        """Return the abstract value for *var*, or ⊤ if unmapped."""
        if var in self._values:
            return self._values[var]
        return self.domain_factory().top() if hasattr(self.domain_factory(), "top") else None

    def set(self, var: str, value: Any) -> AbstractState:
        """Return a new state with *var* bound to *value*."""
        new_values = dict(self._values)
        new_values[var] = value
        return AbstractState(self.domain_factory, new_values)

    def remove(self, var: str) -> AbstractState:
        """Return a new state with *var* removed."""
        new_values = dict(self._values)
        new_values.pop(var, None)
        return AbstractState(self.domain_factory, new_values)

    def variables(self) -> FrozenSet[str]:
        return frozenset(self._values.keys())

    def items(self) -> Iterable[Tuple[str, Any]]:
        return self._values.items()

    def copy(self) -> AbstractState:
        return AbstractState(self.domain_factory, dict(self._values))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AbstractState):
            return NotImplemented
        all_vars = self.variables() | other.variables()
        for v in all_vars:
            a = self.get(v)
            b = other.get(v)
            if a != b:
                return False
        return True

    def __repr__(self) -> str:
        entries = ", ".join(f"{k}: {v}" for k, v in sorted(self._values.items()))
        return f"AbstractState({{{entries}}})"


# ===================================================================== #
#  Activation Frame and Event Record                                     #
# ===================================================================== #

@dataclass
class ActivationFrame:
    """A single stack frame in the VM call stack."""
    func_index: int
    block_index: int
    instr_index: int
    registers: Dict[int, Any] = field(default_factory=dict)
    return_reg: Optional[Reg] = None

    def current_location(self) -> Tuple[int, int, int]:
        return (self.func_index, self.block_index, self.instr_index)


@dataclass
class EventRecord:
    """Record of a single runtime event for trace construction."""
    step: int
    event_name: str
    payload: Any = None
    location: Optional[Tuple[int, int, int]] = None
    timestamp: float = field(default_factory=time.monotonic)


# ===================================================================== #
#  Schema types for execution summaries                                  #
# ===================================================================== #

@dataclass
class SchemaEntry:
    """One entry in a schema listing describing a reached program point."""
    func_index: int
    block_index: int
    visit_count: int
    abstract_state: Optional[AbstractState] = None


@dataclass
class SchemaListing:
    """Ordered collection of schema entries summarizing an exploration."""
    entries: List[SchemaEntry] = field(default_factory=list)

    def add(self, entry: SchemaEntry) -> None:
        self.entries.append(entry)

    def lookup(self, func_index: int, block_index: int) -> Optional[SchemaEntry]:
        for e in self.entries:
            if e.func_index == func_index and e.block_index == block_index:
                return e
        return None


# ===================================================================== #
#  Trace and Counterexample types                                        #
# ===================================================================== #

@dataclass
class TraceStep:
    """One step in a counterexample / witness trace."""
    step_index: int
    instruction: Optional[Instruction]
    location: Tuple[int, int, int]
    state_snapshot: Optional[Dict[str, Any]] = None
    event: Optional[str] = None
    message: str = ""


@dataclass
class Counterexample:
    """A concrete counterexample trace witnessing a property violation."""
    property_name: str
    verdict: PropertyVerdict
    steps: List[TraceStep] = field(default_factory=list)
    length: int = 0
    message: str = ""

    def __post_init__(self) -> None:
        if not self.length:
            self.length = len(self.steps)


@dataclass
class ExplorationResult:
    """Aggregated result of a bounded exploration / model checking run."""
    status: ExplorationStatus
    states_explored: int = 0
    max_depth_reached: int = 0
    violations: List[Counterexample] = field(default_factory=list)
    schema: Optional[SchemaListing] = None
    elapsed_seconds: float = 0.0
    statistics: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        return self.status == ExplorationStatus.SAFE

    @property
    def is_unsafe(self) -> bool:
        return self.status == ExplorationStatus.UNSAFE


# ===================================================================== #
#  Domain Registry                                                       #
# ===================================================================== #

class DomainRegistry:
    """
    Registry of abstract domains by type tag.

    Allows CASL analyses to look up the appropriate domain for a given
    variable type or annotation.
    """

    def __init__(self) -> None:
        self._domains: Dict[str, Callable[[], Any]] = {}
        # Register built-in domains
        self._domains["interval"] = IntervalDomain.top
        self._domains["bool"] = BoolDomain.top

    def register(self, tag: str, factory: Callable[[], Any]) -> None:
        """Register a domain factory under the given *tag*."""
        self._domains[tag] = factory

    def get(self, tag: str) -> Callable[[], Any]:
        """Return the factory for *tag*, or raise KeyError."""
        return self._domains[tag]

    def has(self, tag: str) -> bool:
        return tag in self._domains

    def tags(self) -> FrozenSet[str]:
        return frozenset(self._domains.keys())

    def create(self, tag: str) -> Any:
        """Instantiate a fresh ⊤ element for the domain identified by *tag*."""
        return self._domains[tag]()


# ===================================================================== #
#  Property Monitor                                                      #
# ===================================================================== #

@dataclass
class PropertySpec:
    """Declarative specification of a safety/liveness property to monitor."""
    name: str
    kind: str = "safety"  # "safety" | "liveness" | "invariant"
    predicate: Optional[Callable[[Dict[str, Any]], bool]] = None
    automaton_states: int = 1
    description: str = ""


class PropertyMonitor:
    """
    Runtime observer that tracks the status of a set of ``PropertySpec``
    objects against the evolving abstract state.

    Implements the ``ObserverHandler`` protocol so it can be registered with
    the ``AbstractVM`` observer registry.
    """

    def __init__(self, properties: Sequence[PropertySpec]) -> None:
        self._properties = list(properties)
        self._monitor_states: Dict[str, MonitorState] = {
            p.name: MonitorState.INACTIVE for p in properties
        }
        self._violation_steps: Dict[str, int] = {}
        self._history: List[Tuple[int, str, MonitorState]] = []

    # -- ObserverHandler protocol ----------------------------------------
    def observe(self, step: int, state: Any) -> None:
        """Called after every VM step; evaluates all property predicates."""
        for prop in self._properties:
            prev = self._monitor_states[prop.name]
            if prev in (MonitorState.REJECTING, MonitorState.ERROR):
                continue  # already terminal
            new_state = self._evaluate(prop, state, step)
            if new_state != prev:
                self._history.append((step, prop.name, new_state))
                self._monitor_states[prop.name] = new_state

    # -- Query -----------------------------------------------------------
    def verdict(self, prop_name: str) -> PropertyVerdict:
        """Return the current verdict for a named property."""
        ms = self._monitor_states.get(prop_name)
        if ms is None:
            raise CaslRuntimeError(f"Unknown property: {prop_name}")
        if ms == MonitorState.REJECTING:
            return PropertyVerdict.VIOLATED
        if ms == MonitorState.ACCEPTING:
            return PropertyVerdict.SATISFIED
        return PropertyVerdict.INCONCLUSIVE

    def all_verdicts(self) -> Dict[str, PropertyVerdict]:
        return {name: self.verdict(name) for name in self._monitor_states}

    def violations(self) -> List[str]:
        return [
            name
            for name, ms in self._monitor_states.items()
            if ms == MonitorState.REJECTING
        ]

    def history(self) -> List[Tuple[int, str, MonitorState]]:
        return list(self._history)

    def reset(self) -> None:
        for name in self._monitor_states:
            self._monitor_states[name] = MonitorState.INACTIVE
        self._violation_steps.clear()
        self._history.clear()

    # -- Internal --------------------------------------------------------
    def _evaluate(
        self, prop: PropertySpec, state: Any, step: int
    ) -> MonitorState:
        """Evaluate a property predicate against the current state."""
        if prop.predicate is None:
            return MonitorState.ACTIVE

        try:
            state_dict = self._state_to_dict(state)
            result = prop.predicate(state_dict)
        except Exception as exc:
            logger.warning(
                "Property %s predicate raised %s at step %d",
                prop.name,
                exc,
                step,
            )
            return MonitorState.ERROR

        if result:
            return MonitorState.ACCEPTING if prop.kind == "liveness" else MonitorState.ACTIVE
        else:
            if prop.name not in self._violation_steps:
                self._violation_steps[prop.name] = step
            return MonitorState.REJECTING

    @staticmethod
    def _state_to_dict(state: Any) -> Dict[str, Any]:
        """Coerce various state representations into a plain dict."""
        if isinstance(state, dict):
            return state
        if isinstance(state, AbstractState):
            return dict(state.items())
        if hasattr(state, "__dict__"):
            return state.__dict__
        return {"__raw__": state}


# ===================================================================== #
#  VMError / VMHalt exceptions                                           #
# ===================================================================== #

class VMError(CaslError):
    """Raised when the VM encounters an unrecoverable error."""

    def __init__(self, message: str, location: Optional[Tuple[int, int, int]] = None):
        super().__init__(message)
        self.location = location


class VMHalt(Exception):
    """Raised when the VM executes a HALT instruction (normal termination)."""

    def __init__(self, return_value: Any = None):
        super().__init__("VM halted")
        self.return_value = return_value


# ===================================================================== #
#  Abstract VM Core                                                      #
# ===================================================================== #

class AbstractVM:
    """
    Abstract virtual machine that interprets CASL bytecode programs over
    abstract domains.

    Mirrors the infrastructure from cppcheckdata-shims with full instruction
    dispatch, call stack management, event/observer handling, and cost tracking.
    """

    def __init__(
        self,
        program: Program,
        domain_registry: Optional[DomainRegistry] = None,
        error_reporter: Optional[ErrorReporter] = None,
    ) -> None:
        self._program = program
        self._domain_registry = domain_registry or DomainRegistry()
        self._error_reporter = error_reporter or ErrorReporter()

        # Runtime state
        self._call_stack: List[ActivationFrame] = []
        self._step_count: int = 0
        self._events: List[EventRecord] = []
        self._schema: SchemaListing = SchemaListing()
        self._cumulative_cost: IntervalDomain = IntervalDomain.const(0.0)
        self._visit_counts: Dict[Tuple[int, int], int] = {}
        self._memory: Dict[str, Any] = {}

        # Handler registries
        self._event_handlers: Dict[str, List[EventHandler]] = {}
        self._observer_handlers: List[ObserverHandler] = []

    # -- Handler registration --------------------------------------------
    def register_event_handler(self, event_name: str, handler: EventHandler) -> None:
        self._event_handlers.setdefault(event_name, []).append(handler)

    def register_observer(self, handler: ObserverHandler) -> None:
        self._observer_handlers.append(handler)

    # -- State access ----------------------------------------------------
    @property
    def step_count(self) -> int:
        return self._step_count

    @property
    def call_depth(self) -> int:
        return len(self._call_stack)

    @property
    def events(self) -> List[EventRecord]:
        return list(self._events)

    @property
    def schema(self) -> SchemaListing:
        return self._schema

    @property
    def cumulative_cost(self) -> IntervalDomain:
        return self._cumulative_cost

    def current_frame(self) -> Optional[ActivationFrame]:
        return self._call_stack[-1] if self._call_stack else None

    def current_location(self) -> Optional[Tuple[int, int, int]]:
        frame = self.current_frame()
        return frame.current_location() if frame else None

    # -- Memory helpers --------------------------------------------------
    def _memory_key(self, base: str, offset: Any = None) -> str:
        if offset is not None:
            return f"{base}[{offset}]"
        return base

    def _record_schema(self, frame: ActivationFrame, state: Optional[AbstractState] = None) -> None:
        key = (frame.func_index, frame.block_index)
        count = self._visit_counts.get(key, 0) + 1
        self._visit_counts[key] = count
        self._schema.add(
            SchemaEntry(
                func_index=frame.func_index,
                block_index=frame.block_index,
                visit_count=count,
                abstract_state=state,
            )
        )

    # -- Register file access --------------------------------------------
    def _read_reg(self, frame: ActivationFrame, reg: Reg) -> Any:
        if reg.index not in frame.registers:
            return IntervalDomain.top()  # undefined → ⊤
        return frame.registers[reg.index]

    def _write_reg(self, frame: ActivationFrame, reg: Reg, value: Any) -> None:
        frame.registers[reg.index] = value

    # -- Evaluation helpers ----------------------------------------------
    def _eval_binop(self, op: str, lhs: Any, rhs: Any) -> Any:
        """Evaluate a binary operation abstractly."""
        if isinstance(lhs, IntervalDomain) and isinstance(rhs, IntervalDomain):
            if op == "add":
                return lhs.add(rhs)
            if op == "sub":
                return lhs.sub(rhs)
            if op == "join":
                return lhs.join(rhs)
            if op == "meet":
                return lhs.meet(rhs)
        if isinstance(lhs, BoolDomain) and isinstance(rhs, BoolDomain):
            if op == "and":
                return lhs.and_(rhs)
            if op == "or":
                return lhs.or_(rhs)
        # Fallback: try numeric
        return IntervalDomain.top()

    def _eval_unop(self, op: str, val: Any) -> Any:
        """Evaluate a unary operation abstractly."""
        if isinstance(val, IntervalDomain) and op == "neg":
            return val.neg()
        if isinstance(val, BoolDomain) and op == "not":
            return val.not_()
        return IntervalDomain.top()

    # -- Call / return helpers -------------------------------------------
    def _handle_call(self, func_ref: FuncRef, args: List[Any], return_reg: Optional[Reg]) -> None:
        """Push a new activation frame for a function call."""
        func = self._program.function(func_ref.index)
        frame = ActivationFrame(
            func_index=func_ref.index,
            block_index=func.entry_block,
            instr_index=0,
            return_reg=return_reg,
        )
        # Bind parameters
        for i, param_reg in enumerate(func.params):
            if i < len(args):
                frame.registers[param_reg.index] = args[i]
            else:
                frame.registers[param_reg.index] = IntervalDomain.top()
        self._call_stack.append(frame)

    def _pop_frame(self, return_value: Any = None) -> None:
        """Pop the current frame; write return value to caller's return register."""
        if not self._call_stack:
            raise VMError("Cannot pop frame: call stack is empty")
        finished_frame = self._call_stack.pop()
        caller = self.current_frame()
        if caller is not None and finished_frame.return_reg is not None:
            self._write_reg(caller, finished_frame.return_reg, return_value)

    def _advance_to_next_block(self, frame: ActivationFrame, target_block: int) -> None:
        """Move *frame* to the beginning of *target_block*."""
        frame.block_index = target_block
        frame.instr_index = 0

    # -- Notification helpers --------------------------------------------
    def _fire_event(self, name: str, payload: Any = None) -> None:
        location = self.current_location()
        record = EventRecord(
            step=self._step_count,
            event_name=name,
            payload=payload,
            location=location,
        )
        self._events.append(record)
        for handler in self._event_handlers.get(name, []):
            handler.handle(name, payload)

    def _notify_observers(self) -> None:
        state = self._snapshot_state()
        for obs in self._observer_handlers:
            obs.observe(self._step_count, state)

    def _snapshot_state(self) -> Dict[str, Any]:
        """Create a snapshot of the current VM state for observers."""
        frame = self.current_frame()
        snapshot: Dict[str, Any] = {
            "step": self._step_count,
            "call_depth": self.call_depth,
            "cost": self._cumulative_cost,
        }
        if frame:
            snapshot["location"] = frame.current_location()
            snapshot["registers"] = dict(frame.registers)
        snapshot["memory"] = dict(self._memory)
        return snapshot

    # -- Instruction execution -------------------------------------------
    def _exec_instruction(self, instr: Instruction, frame: ActivationFrame) -> None:
        """Execute a single instruction, modifying *frame* in place."""
        ops = instr.operands
        opc = instr.opcode

        # Accumulate cost
        if instr.cost > 0:
            self._cumulative_cost = self._cumulative_cost.add(
                IntervalDomain.const(instr.cost)
            )

        if opc == Opcode.NOP:
            pass

        elif opc == Opcode.LOAD_CONST:
            # LOAD_CONST dst, value
            dst = ops[0]
            val = ops[1]
            if isinstance(dst, Reg):
                if isinstance(val, (int, float)):
                    self._write_reg(frame, dst, IntervalDomain.const(float(val)))
                elif isinstance(val, bool):
                    self._write_reg(frame, dst, BoolDomain.abstract(val))
                else:
                    self._write_reg(frame, dst, val)

        elif opc == Opcode.LOAD_VAR:
            # LOAD_VAR dst, var_name
            dst = ops[0]
            var_name = str(ops[1])
            if isinstance(dst, Reg):
                value = self._memory.get(var_name, IntervalDomain.top())
                self._write_reg(frame, dst, value)

        elif opc == Opcode.STORE_VAR:
            # STORE_VAR var_name, src
            var_name = str(ops[0])
            src = ops[1]
            value = self._read_reg(frame, src) if isinstance(src, Reg) else src
            self._memory[var_name] = value

        elif opc == Opcode.BINOP:
            # BINOP dst, op_name, lhs, rhs
            dst, op_name = ops[0], str(ops[1])
            lhs = self._read_reg(frame, ops[2]) if isinstance(ops[2], Reg) else ops[2]
            rhs = self._read_reg(frame, ops[3]) if isinstance(ops[3], Reg) else ops[3]
            if isinstance(dst, Reg):
                self._write_reg(frame, dst, self._eval_binop(op_name, lhs, rhs))

        elif opc == Opcode.UNOP:
            # UNOP dst, op_name, src
            dst, op_name = ops[0], str(ops[1])
            src = self._read_reg(frame, ops[2]) if isinstance(ops[2], Reg) else ops[2]
            if isinstance(dst, Reg):
                self._write_reg(frame, dst, self._eval_unop(op_name, src))

        elif opc == Opcode.JUMP:
            # JUMP target_block
            target = ops[0]
            if isinstance(target, BlockRef):
                self._advance_to_next_block(frame, target.block_index)
                return  # don't advance instr_index
            elif isinstance(target, int):
                self._advance_to_next_block(frame, target)
                return

        elif opc == Opcode.BRANCH:
            # BRANCH cond, true_block, false_block
            cond = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else ops[0]
            true_blk = ops[1]
            false_blk = ops[2]

            target_idx: int
            if isinstance(cond, BoolDomain):
                if cond.is_concrete() and cond.value is True:
                    target_idx = true_blk.block_index if isinstance(true_blk, BlockRef) else int(true_blk)
                elif cond.is_concrete() and cond.value is False:
                    target_idx = false_blk.block_index if isinstance(false_blk, BlockRef) else int(false_blk)
                else:
                    # Top / unknown → take true branch (single-path interpretation)
                    target_idx = true_blk.block_index if isinstance(true_blk, BlockRef) else int(true_blk)
            else:
                target_idx = true_blk.block_index if isinstance(true_blk, BlockRef) else int(true_blk)

            self._advance_to_next_block(frame, target_idx)
            return

        elif opc == Opcode.CALL:
            # CALL dst, func_ref, arg0, arg1, ...
            dst = ops[0] if isinstance(ops[0], Reg) else None
            func_ref = ops[1] if isinstance(ops[1], FuncRef) else FuncRef(int(ops[1]))
            args = [
                self._read_reg(frame, op) if isinstance(op, Reg) else op
                for op in ops[2:]
            ]
            # Advance caller past the CALL instruction before pushing
            frame.instr_index += 1
            self._handle_call(func_ref, args, return_reg=dst)
            return  # new frame is now active

        elif opc == Opcode.RETURN:
            # RETURN [value]
            ret_val = None
            if ops:
                ret_val = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else ops[0]
            self._pop_frame(ret_val)
            return  # caller frame is now active

        elif opc == Opcode.PHI:
            # PHI dst, (block_idx, reg)...  — simplified: join all inputs
            dst = ops[0]
            if isinstance(dst, Reg):
                values = [
                    self._read_reg(frame, op) if isinstance(op, Reg) else op
                    for op in ops[1:]
                    if isinstance(op, Reg)
                ]
                if values:
                    result = values[0]
                    for v in values[1:]:
                        if hasattr(result, "join"):
                            result = result.join(v)
                    self._write_reg(frame, dst, result)

        elif opc == Opcode.ALLOC:
            # ALLOC dst, size_or_name
            dst = ops[0]
            name = str(ops[1]) if len(ops) > 1 else f"alloc_{self._step_count}"
            if isinstance(dst, Reg):
                key = self._memory_key(name)
                self._memory[key] = IntervalDomain.top()
                self._write_reg(frame, dst, key)

        elif opc == Opcode.FREE:
            # FREE ptr_reg
            ptr = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else str(ops[0])
            if isinstance(ptr, str):
                self._memory.pop(ptr, None)

        elif opc == Opcode.LOAD_MEM:
            # LOAD_MEM dst, base, offset
            dst = ops[0]
            base = self._read_reg(frame, ops[1]) if isinstance(ops[1], Reg) else str(ops[1])
            offset = self._read_reg(frame, ops[2]) if len(ops) > 2 and isinstance(ops[2], Reg) else (ops[2] if len(ops) > 2 else None)
            if isinstance(dst, Reg):
                key = self._memory_key(str(base), offset)
                value = self._memory.get(key, IntervalDomain.top())
                self._write_reg(frame, dst, value)

        elif opc == Opcode.STORE_MEM:
            # STORE_MEM base, offset, src
            base = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else str(ops[0])
            offset = ops[1] if len(ops) > 2 else None
            src_idx = 2 if len(ops) > 2 else 1
            src = self._read_reg(frame, ops[src_idx]) if isinstance(ops[src_idx], Reg) else ops[src_idx]
            key = self._memory_key(str(base), offset)
            self._memory[key] = src

        elif opc == Opcode.EVENT:
            # EVENT event_ref, [payload_reg]
            evt = ops[0]
            name = evt.name if isinstance(evt, EventRef) else str(evt)
            payload = None
            if len(ops) > 1:
                payload = self._read_reg(frame, ops[1]) if isinstance(ops[1], Reg) else ops[1]
            self._fire_event(name, payload)

        elif opc == Opcode.OBSERVE:
            # OBSERVE observer_ref
            self._notify_observers()

        elif opc == Opcode.ASSERT:
            # ASSERT cond_reg
            cond = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else ops[0]
            if isinstance(cond, BoolDomain):
                if cond.is_concrete() and cond.value is False:
                    loc = instr.source_loc
                    self._fire_event("assertion_failure", {"location": loc, "step": self._step_count})
                    raise VMError(
                        f"Assertion failed at step {self._step_count}",
                        location=frame.current_location(),
                    )

        elif opc == Opcode.ASSUME:
            # ASSUME cond_reg — constrain the abstract state
            cond = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else ops[0]
            if isinstance(cond, BoolDomain) and cond.is_concrete() and cond.value is False:
                # Assumption is false → this path is infeasible (bottom)
                raise VMHalt(return_value=None)

        elif opc == Opcode.HAVOC:
            # HAVOC dst — set register to ⊤
            dst = ops[0]
            if isinstance(dst, Reg):
                self._write_reg(frame, dst, IntervalDomain.top())

        elif opc == Opcode.WIDEN:
            # WIDEN dst, lhs, rhs
            dst = ops[0]
            lhs = self._read_reg(frame, ops[1]) if isinstance(ops[1], Reg) else ops[1]
            rhs = self._read_reg(frame, ops[2]) if isinstance(ops[2], Reg) else ops[2]
            if isinstance(dst, Reg) and hasattr(lhs, "widen"):
                self._write_reg(frame, dst, lhs.widen(rhs))

        elif opc == Opcode.NARROW:
            # NARROW dst, lhs, rhs
            dst = ops[0]
            lhs = self._read_reg(frame, ops[1]) if isinstance(ops[1], Reg) else ops[1]
            rhs = self._read_reg(frame, ops[2]) if isinstance(ops[2], Reg) else ops[2]
            if isinstance(dst, Reg) and hasattr(lhs, "narrow"):
                self._write_reg(frame, dst, lhs.narrow(rhs))

        elif opc == Opcode.COST:
            # COST literal
            if ops and isinstance(ops[0], CostLiteral):
                self._cumulative_cost = self._cumulative_cost.add(
                    IntervalDomain.const(ops[0].value)
                )

        elif opc == Opcode.HALT:
            ret = None
            if ops:
                ret = self._read_reg(frame, ops[0]) if isinstance(ops[0], Reg) else ops[0]
            raise VMHalt(return_value=ret)

        elif opc == Opcode.LABEL:
            pass  # labels are no-ops at runtime

        else:
            raise VMError(f"Unknown opcode: {opc}", location=frame.current_location())

        # Advance to next instruction within the same block
        frame.instr_index += 1

    # -- Step driver -----------------------------------------------------
    def _step(self) -> bool:
        """
        Execute one instruction. Returns ``True`` if execution should continue,
        ``False`` if the VM has halted or the call stack is empty.
        """
        frame = self.current_frame()
        if frame is None:
            return False

        func = self._program.function(frame.func_index)
        block = func.block(frame.block_index)

        if frame.instr_index >= len(block.instructions):
            # Fell off the end of a block — advance to first successor
            if block.successors:
                self._advance_to_next_block(frame, block.successors[0])
            else:
                # No successors and no explicit return → implicit return
                self._pop_frame(None)
                if not self._call_stack:
                    return False
            return True

        instr = block.instructions[frame.instr_index]
        self._step_count += 1
        self._record_schema(frame)

        try:
            self._exec_instruction(instr, frame)
        except VMHalt:
            return False

        # Notify observers after each step
        self._notify_observers()
        return True

    # -- High-level execution entry points --------------------------------
    def interpret(self, max_steps: int = 100_000) -> ExplorationResult:
        """
        Single-path interpretation: execute from the program entry point
        until HALT, error, or step limit.
        """
        start_time = time.monotonic()
        entry_func = self._program.function(self._program.entry_function)

        # Push initial frame
        initial_frame = ActivationFrame(
            func_index=self._program.entry_function,
            block_index=entry_func.entry_block,
            instr_index=0,
        )
        self._call_stack.append(initial_frame)

        status = ExplorationStatus.SAFE
        violations: List[Counterexample] = []

        try:
            while self._step_count < max_steps:
                if not self._step():
                    break
        except VMError as exc:
            status = ExplorationStatus.UNSAFE
            violations.append(
                Counterexample(
                    property_name="__assertion__",
                    verdict=PropertyVerdict.VIOLATED,
                    message=str(exc),
                    length=self._step_count,
                )
            )
        else:
            if self._step_count >= max_steps:
                status = ExplorationStatus.DEPTH_EXCEEDED

        elapsed = time.monotonic() - start_time
        return ExplorationResult(
            status=status,
            states_explored=self._step_count,
            max_depth_reached=self._step_count,
            violations=violations,
            schema=self._schema,
            elapsed_seconds=elapsed,
            statistics={
                "visit_counts": dict(self._visit_counts),
                "cumulative_cost": self._cumulative_cost,
                "events_fired": len(self._events),
            },
        )

    def explore(
        self,
        max_steps: int = 100_000,
        max_depth: int = 100,
    ) -> ExplorationResult:
        """
        All-paths worklist exploration: explores every reachable branch
        combination up to the depth/step budget using a BFS worklist.

        Each worklist entry is a full VM snapshot (call stack + memory + registers).
        """
        start_time = time.monotonic()
        entry_func = self._program.function(self._program.entry_function)

        initial_frame = ActivationFrame(
            func_index=self._program.entry_function,
            block_index=entry_func.entry_block,
            instr_index=0,
        )

        # Worklist item: (call_stack_snapshot, memory_snapshot, depth)
        WorkItem = Tuple[List[ActivationFrame], Dict[str, Any], int]

        def _snapshot_frame(f: ActivationFrame) -> ActivationFrame:
            return ActivationFrame(
                func_index=f.func_index,
                block_index=f.block_index,
                instr_index=f.instr_index,
                registers=dict(f.registers),
                return_reg=f.return_reg,
            )

        worklist: List[WorkItem] = [
            ([_snapshot_frame(initial_frame)], {}, 0)
        ]
        total_states = 0
        max_depth_seen = 0
        status = ExplorationStatus.SAFE
        violations: List[Counterexample] = []
        visited: Set[Tuple[int, int, int]] = set()  # (func, block, instr) fingerprints

        while worklist and total_states < max_steps:
            stack_snap, mem_snap, depth = worklist.pop(0)

            if depth > max_depth:
                status = ExplorationStatus.DEPTH_EXCEEDED
                continue

            max_depth_seen = max(max_depth_seen, depth)

            # Restore VM state
            self._call_stack = [_snapshot_frame(f) for f in stack_snap]
            self._memory = dict(mem_snap)

            frame = self.current_frame()
            if frame is None:
                continue

            func = self._program.function(frame.func_index)
            block = func.block(frame.block_index)

            if frame.instr_index >= len(block.instructions):
                if block.successors:
                    for succ in block.successors:
                        new_frame = _snapshot_frame(frame)
                        self._advance_to_next_block(new_frame, succ)
                        new_stack = [_snapshot_frame(f) for f in stack_snap[:-1]] + [new_frame]
                        worklist.append((new_stack, dict(mem_snap), depth + 1))
                continue

            instr = block.instructions[frame.instr_index]
            total_states += 1
            self._step_count += 1

            # Check for BRANCH — fork the worklist
            if instr.opcode == Opcode.BRANCH:
                cond = self._read_reg(frame, instr.operands[0]) if isinstance(instr.operands[0], Reg) else instr.operands[0]
                true_blk = instr.operands[1]
                false_blk = instr.operands[2]
                true_idx = true_blk.block_index if isinstance(true_blk, BlockRef) else int(true_blk)
                false_idx = false_blk.block_index if isinstance(false_blk, BlockRef) else int(false_blk)

                should_take_true = True
                should_take_false = True

                if isinstance(cond, BoolDomain) and cond.is_concrete():
                    if cond.value is True:
                        should_take_false = False
                    else:
                        should_take_true = False

                if should_take_true:
                    new_frame_t = _snapshot_frame(frame)
                    self._advance_to_next_block(new_frame_t, true_idx)
                    new_stack_t = [_snapshot_frame(f) for f in stack_snap[:-1]] + [new_frame_t]
                    worklist.append((new_stack_t, dict(mem_snap), depth + 1))

                if should_take_false:
                    new_frame_f = _snapshot_frame(frame)
                    self._advance_to_next_block(new_frame_f, false_idx)
                    new_stack_f = [_snapshot_frame(f) for f in stack_snap[:-1]] + [new_frame_f]
                    worklist.append((new_stack_f, dict(mem_snap), depth + 1))

                continue

            # For non-branching instructions, execute normally
            try:
                self._exec_instruction(instr, frame)
            except VMHalt:
                continue
            except VMError as exc:
                status = ExplorationStatus.UNSAFE
                violations.append(
                    Counterexample(
                        property_name="__assertion__",
                        verdict=PropertyVerdict.VIOLATED,
                        message=str(exc),
                        length=depth,
                    )
                )
                continue

            # Enqueue the successor state
            new_stack = [_snapshot_frame(f) for f in self._call_stack]
            worklist.append((new_stack, dict(self._memory), depth + 1))

        if total_states >= max_steps and status == ExplorationStatus.SAFE:
            status = ExplorationStatus.STATE_LIMIT

        elapsed = time.monotonic() - start_time
        return ExplorationResult(
            status=status,
            states_explored=total_states,
            max_depth_reached=max_depth_seen,
            violations=violations,
            schema=self._schema,
            elapsed_seconds=elapsed,
            statistics={
                "visit_counts": dict(self._visit_counts),
                "cumulative_cost": self._cumulative_cost,
                "events_fired": len(self._events),
            },
        )

    def reset(self) -> None:
        """Reset all mutable VM state for a fresh run."""
        self._call_stack.clear()
        self._step_count = 0
        self._events.clear()
        self._schema = SchemaListing()
        self._cumulative_cost = IntervalDomain.const(0.0)
        self._visit_counts.clear()
        self._memory.clear()


# ===================================================================== #
#  Abstract Interpreter — fixpoint dataflow analysis driver              #
# ===================================================================== #

class AbstractInterpreter:
    """
    Fixpoint-based abstract interpreter for dataflow analysis.

    Runs a worklist algorithm over the CFG, applying transfer functions
    per-block and widening at loop heads until a fixpoint is reached.
    """

    def __init__(
        self,
        program: Program,
        domain_registry: DomainRegistry,
        widen_delay: int = 3,
        max_iterations: int = 1000,
    ) -> None:
        self._program = program
        self._domains = domain_registry
        self._widen_delay = widen_delay
        self._max_iterations = max_iterations

    def analyze(
        self,
        func_index: int = 0,
        initial_state: Optional[AbstractState] = None,
    ) -> Dict[Tuple[int, int], AbstractState]:
        """
        Compute the fixpoint abstract state at each (func, block) pair
        for the given function.

        Returns a mapping from ``(func_index, block_index)`` to the
        converged ``AbstractState``.
        """
        func = self._program.function(func_index)
        factory = self._domains.get("interval")

        if initial_state is None:
            initial_state = AbstractState(factory)

        # state_at[block_index] = AbstractState
        state_at: Dict[int, AbstractState] = {}
        state_at[func.entry_block] = initial_state.copy()

        # Iteration counts per block (for widen delay)
        iteration_counts: Dict[int, int] = {b.index: 0 for b in func.blocks}

        # Worklist of block indices
        worklist: List[int] = [func.entry_block]
        total_iterations = 0

        while worklist and total_iterations < self._max_iterations:
            block_idx = worklist.pop(0)
            block = func.block(block_idx)
            total_iterations += 1
            iteration_counts[block_idx] = iteration_counts.get(block_idx, 0) + 1

            current_state = state_at.get(block_idx)
            if current_state is None:
                continue

            # Apply transfer function: execute block abstractly
            new_state = self._transfer_block(block, current_state)

            # Propagate to successors
            for succ_idx in block.successors:
                old_succ = state_at.get(succ_idx)
                if old_succ is None:
                    state_at[succ_idx] = new_state.copy()
                    worklist.append(succ_idx)
                else:
                    # Join (or widen if past the delay threshold)
                    merged = self._join_states(
                        old_succ,
                        new_state,
                        use_widen=iteration_counts.get(succ_idx, 0) >= self._widen_delay,
                    )
                    if merged != old_succ:
                        state_at[succ_idx] = merged
                        if succ_idx not in worklist:
                            worklist.append(succ_idx)

        return {(func_index, bi): s for bi, s in state_at.items()}

    def _transfer_block(
        self, block: BasicBlock, state: AbstractState
    ) -> AbstractState:
        """Apply the transfer function for all instructions in a block."""
        current = state.copy()
        for instr in block.instructions:
            current = self._transfer_instruction(instr, current)
        return current

    def _transfer_instruction(
        self, instr: Instruction, state: AbstractState
    ) -> AbstractState:
        """Apply the abstract transfer function for a single instruction."""
        opc = instr.opcode
        ops = instr.operands

        if opc == Opcode.STORE_VAR:
            var_name = str(ops[0])
            if len(ops) > 1 and isinstance(ops[1], Reg):
                # Use register name as variable lookup
                reg_var = f"__r{ops[1].index}"
                val = state.get(reg_var)
                return state.set(var_name, val)
            return state

        if opc == Opcode.LOAD_VAR:
            if isinstance(ops[0], Reg):
                dst_var = f"__r{ops[0].index}"
                src_var = str(ops[1])
                return state.set(dst_var, state.get(src_var))
            return state

        if opc == Opcode.HAVOC:
            if isinstance(ops[0], Reg):
                var = f"__r{ops[0].index}"
                return state.set(var, IntervalDomain.top())
            return state

        if opc in (Opcode.LOAD_CONST, Opcode.BINOP, Opcode.UNOP, Opcode.PHI):
            if isinstance(ops[0], Reg):
                var = f"__r{ops[0].index}"
                return state.set(var, IntervalDomain.top())
            return state

        return state

    def _join_states(
        self,
        old: AbstractState,
        new: AbstractState,
        use_widen: bool = False,
    ) -> AbstractState:
        """Join (or widen) two abstract states variable-by-variable."""
        all_vars = old.variables() | new.variables()
        result = old.copy()
        for var in all_vars:
            old_val = old.get(var)
            new_val = new.get(var)
            if old_val is None:
                result = result.set(var, new_val)
            elif new_val is None:
                pass  # keep old
            elif hasattr(old_val, "widen") and use_widen:
                result = result.set(var, old_val.widen(new_val))
            elif hasattr(old_val, "join"):
                result = result.set(var, old_val.join(new_val))
            else:
                result = result.set(var, new_val)
        return result


# ===================================================================== #
#  Safety Checker                                                        #
# ===================================================================== #

class SafetyChecker:
    """
    Bounded model checker that combines the abstract VM exploration
    with property monitoring to detect safety violations.
    """

    def __init__(
        self,
        vm: AbstractVM,
        monitor: PropertyMonitor,
        max_steps: int = 100_000,
        max_depth: int = 100,
        stop_on_first_violation: bool = True,
    ) -> None:
        self._vm = vm
        self._monitor = monitor
        self._max_steps = max_steps
        self._max_depth = max_depth
        self._stop_on_first = stop_on_first_violation
        # Register monitor as an observer
        self._vm.register_observer(self._monitor)

    def check(self) -> ExplorationResult:
        """Run the bounded exploration and return the aggregated result."""
        result = self._vm.explore(
            max_steps=self._max_steps,
            max_depth=self._max_depth,
        )

        # Merge monitor verdicts into the exploration result
        monitor_violations = self._monitor.violations()
        for prop_name in monitor_violations:
            result.violations.append(
                Counterexample(
                    property_name=prop_name,
                    verdict=PropertyVerdict.VIOLATED,
                    message=f"Property '{prop_name}' violated during exploration",
                )
            )

        if result.violations:
            result = ExplorationResult(
                status=ExplorationStatus.UNSAFE,
                states_explored=result.states_explored,
                max_depth_reached=result.max_depth_reached,
                violations=result.violations,
                schema=result.schema,
                elapsed_seconds=result.elapsed_seconds,
                statistics=result.statistics,
            )

        return result


# ===================================================================== #
#  Trace Reconstructor                                                   #
# ===================================================================== #

class CaslTraceBuilder:
    """
    Reconstructs human-readable counterexample traces from VM event
    records and execution history.
    """

    def __init__(self, program: Program) -> None:
        self._program = program

    def build_trace(
        self,
        events: List[EventRecord],
        max_steps: Optional[int] = None,
    ) -> Counterexample:
        """
        Build a ``Counterexample`` from a sequence of event records,
        optionally truncated to *max_steps*.
        """
        steps: List[TraceStep] = []
        for i, evt in enumerate(events):
            if max_steps is not None and i >= max_steps:
                break
            loc = evt.location or (0, 0, 0)
            instr = self._lookup_instruction(loc)
            steps.append(
                TraceStep(
                    step_index=evt.step,
                    instruction=instr,
                    location=loc,
                    event=evt.event_name,
                    message=f"Event '{evt.event_name}' at step {evt.step}",
                )
            )

        return Counterexample(
            property_name="trace",
            verdict=PropertyVerdict.VIOLATED if steps else PropertyVerdict.INCONCLUSIVE,
            steps=steps,
            message=f"Trace with {len(steps)} steps",
        )

    def build_from_exploration(
        self, result: ExplorationResult
    ) -> List[Counterexample]:
        """Extract all counterexamples from an exploration result."""
        return list(result.violations)

    def format_trace(self, cex: Counterexample) -> str:
        """Format a counterexample as a human-readable string."""
        lines = [
            f"=== Counterexample: {cex.property_name} ===",
            f"Verdict: {cex.verdict.value}",
            f"Length:  {cex.length}",
            f"Message: {cex.message}",
            "",
        ]
        for step in cex.steps:
            loc_str = f"{step.location[0]}:{step.location[1]}:{step.location[2]}"
            instr_str = repr(step.instruction) if step.instruction else "<no instruction>"
            lines.append(f"  [{step.step_index:>5}] {loc_str}  {instr_str}")
            if step.event:
                lines.append(f"         event: {step.event}")
            if step.message:
                lines.append(f"         {step.message}")
        return "\n".join(lines)

    def _lookup_instruction(
        self, loc: Tuple[int, int, int]
    ) -> Optional[Instruction]:
        """Look up an instruction by (func, block, instr) triple."""
        func_idx, block_idx, instr_idx = loc
        try:
            func = self._program.function(func_idx)
            block = func.block(block_idx)
            if instr_idx < len(block.instructions):
                return block.instructions[instr_idx]
        except (IndexError, KeyError):
            pass
        return None


# ===================================================================== #
#  Runtime Configuration                                                 #
# ===================================================================== #

@dataclass
class RuntimeConfig:
    """Tuning knobs for the CASL runtime system."""
    max_steps: int = 100_000
    max_depth: int = 100
    max_call_depth: int = 50
    widen_delay: int = 3
    max_fixpoint_iterations: int = 1000
    stop_on_first_violation: bool = True
    record_events: bool = True
    record_schema: bool = True
    timeout_seconds: Optional[float] = None
    domain_tag: str = "interval"

    def validate(self) -> List[str]:
        """Return a list of validation warnings (empty if valid)."""
        warnings: List[str] = []
        if self.max_steps <= 0:
            warnings.append("max_steps must be positive")
        if self.max_depth <= 0:
            warnings.append("max_depth must be positive")
        if self.widen_delay < 0:
            warnings.append("widen_delay must be non-negative")
        return warnings


# ===================================================================== #
#  CaslRuntime — top-level façade                                        #
# ===================================================================== #

class CaslRuntime:
    """
    Top-level façade for the CASL runtime system.

    Owns and wires together:
    - an ``AbstractVM`` for bytecode execution
    - a ``DomainRegistry`` for abstract domain management
    - a ``PropertyMonitor`` for runtime property monitoring
    - an ``AbstractInterpreter`` for fixpoint-based dataflow analysis
    - a ``SafetyChecker`` for bounded model checking
    - a ``CaslTraceBuilder`` for counterexample generation
    - an ``ErrorReporter`` for diagnostic collection

    Usage::

        program = Program(functions=[...])
        config = RuntimeConfig(max_steps=50_000, max_depth=50)
        rt = CaslRuntime(program, config)

        # Register properties
        rt.add_property(PropertySpec(
            name="no_overflow",
            kind="safety",
            predicate=lambda s: s.get("x", IntervalDomain.top()).hi < 1000,
        ))

        # Run bounded model checking
        result = rt.check_safety()
        print(result.status)

        # Or run single-path interpretation
        result = rt.interpret()

        # Or run fixpoint analysis
        fixpoint = rt.analyze(func_index=0)
    """

    def __init__(
        self,
        program: Program,
        config: Optional[RuntimeConfig] = None,
        error_reporter: Optional[ErrorReporter] = None,
    ) -> None:
        self._config = config or RuntimeConfig()
        self._error_reporter = error_reporter or ErrorReporter()
        self._program = program

        # Validate config
        warnings = self._config.validate()
        for w in warnings:
            logger.warning("RuntimeConfig: %s", w)

        # Wire up subsystems
        self._domain_registry = DomainRegistry()
        self._properties: List[PropertySpec] = []
        self._monitor = PropertyMonitor([])

        self._vm = AbstractVM(
            program=program,
            domain_registry=self._domain_registry,
            error_reporter=self._error_reporter,
        )

        self._interpreter = AbstractInterpreter(
            program=program,
            domain_registry=self._domain_registry,
            widen_delay=self._config.widen_delay,
            max_iterations=self._config.max_fixpoint_iterations,
        )

        self._trace_builder = CaslTraceBuilder(program=program)

    # -- Property management ---------------------------------------------
    def add_property(self, prop: PropertySpec) -> None:
        """Register a property to monitor during exploration."""
        self._properties.append(prop)
        # Rebuild monitor with updated property list
        self._monitor = PropertyMonitor(self._properties)

    def add_properties(self, props: Iterable[PropertySpec]) -> None:
        for p in props:
            self.add_property(p)

    # -- Domain management -----------------------------------------------
    def register_domain(self, tag: str, factory: Callable[[], Any]) -> None:
        """Register a custom abstract domain under the given tag."""
        self._domain_registry.register(tag, factory)

    # -- Event / observer registration -----------------------------------
    def register_event_handler(self, event_name: str, handler: EventHandler) -> None:
        self._vm.register_event_handler(event_name, handler)

    def register_observer(self, handler: ObserverHandler) -> None:
        self._vm.register_observer(handler)

    # -- Execution entry points ------------------------------------------
    def interpret(self) -> ExplorationResult:
        """
        Single-path interpretation of the program from the entry point.
        """
        self._vm.reset()
        self._monitor.reset()
        self._vm.register_observer(self._monitor)
        return self._vm.interpret(max_steps=self._config.max_steps)

    def explore(self) -> ExplorationResult:
        """
        All-paths bounded exploration of the program.
        """
        self._vm.reset()
        self._monitor.reset()
        self._vm.register_observer(self._monitor)
        return self._vm.explore(
            max_steps=self._config.max_steps,
            max_depth=self._config.max_depth,
        )

    def check_safety(self) -> ExplorationResult:
        """
        Run bounded model checking with property monitoring.
        Returns an ``ExplorationResult`` with any violations found.
        """
        self._vm.reset()
        self._monitor.reset()
        checker = SafetyChecker(
            vm=self._vm,
            monitor=self._monitor,
            max_steps=self._config.max_steps,
            max_depth=self._config.max_depth,
            stop_on_first_violation=self._config.stop_on_first_violation,
        )
        return checker.check()

    def analyze(
        self,
        func_index: int = 0,
        initial_state: Optional[AbstractState] = None,
    ) -> Dict[Tuple[int, int], AbstractState]:
        """
        Run fixpoint abstract interpretation on the given function.
        Returns the converged abstract state at each program point.
        """
        return self._interpreter.analyze(
            func_index=func_index,
            initial_state=initial_state,
        )

    def build_trace(self, result: ExplorationResult) -> List[Counterexample]:
        """Build formatted counterexample traces from an exploration result."""
        return self._trace_builder.build_from_exploration(result)

    def format_counterexample(self, cex: Counterexample) -> str:
        """Format a single counterexample as a human-readable string."""
        return self._trace_builder.format_trace(cex)

    # -- Accessors -------------------------------------------------------
    @property
    def vm(self) -> AbstractVM:
        return self._vm

    @property
    def monitor(self) -> PropertyMonitor:
        return self._monitor

    @property
    def config(self) -> RuntimeConfig:
        return self._config

    @property
    def program(self) -> Program:
        return self._program

    @property
    def domain_registry(self) -> DomainRegistry:
        return self._domain_registry

    @property
    def error_reporter(self) -> ErrorReporter:
        return self._error_reporter

    @property
    def interpreter(self) -> AbstractInterpreter:
        return self._interpreter

    @property
    def trace_builder(self) -> CaslTraceBuilder:
        return self._trace_builder


# ===================================================================== #
#  Module-level convenience                                              #
# ===================================================================== #

def create_runtime(
    program: Program,
    *,
    max_steps: int = 100_000,
    max_depth: int = 100,
    stop_on_first: bool = True,
    domain_tag: str = "interval",
    error_reporter: Optional[ErrorReporter] = None,
) -> CaslRuntime:
    """
    Convenience factory that builds a fully-wired ``CaslRuntime``
    from a program and common options.
    """
    config = RuntimeConfig(
        max_steps=max_steps,
        max_depth=max_depth,
        stop_on_first_violation=stop_on_first,
        domain_tag=domain_tag,
    )
    return CaslRuntime(program, config, error_reporter)


__all__ = [
    # Enums
    "Opcode",
    "ExplorationStatus",
    "PropertyVerdict",
    "MonitorState",
    # Operand types
    "Reg",
    "BlockRef",
    "FuncRef",
    "EventRef",
    "ObserverRef",
    "CostLiteral",
    "Operand",
    # Instruction / structure
    "SourceLocation",
    "Instruction",
    "BasicBlock",
    "FunctionCode",
    "Program",
    # Domains
    "AbstractDomain",
    "IntervalDomain",
    "BoolDomain",
    "AbstractState",
    "DomainRegistry",
    # VM core
    "ActivationFrame",
    "EventRecord",
    "SchemaEntry",
    "SchemaListing",
    "AbstractVM",
    "VMError",
    "VMHalt",
    # Property system
    "PropertySpec",
    "PropertyMonitor",
    # Analysis
    "AbstractInterpreter",
    "SafetyChecker",
    # Traces
    "TraceStep",
    "Counterexample",
    "ExplorationResult",
    "CaslTraceBuilder",
    # Runtime facade
    "RuntimeConfig",
    "CaslRuntime",
    "create_runtime",
    # Protocols
    "EventHandler",
    "ObserverHandler",
]
