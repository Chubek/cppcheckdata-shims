"""
cppcheckdata_shims/abstract_vm.py
══════════════════════════════════

Abstract Virtual Machine for the cppcheckdata-shims library.

This module provides a *compiler* from the shims CFG representation to an
abstract bytecode, and a *virtual machine* that interprets that bytecode
symbolically.  Unlike a concrete VM the Abstract VM is not concerned with
**what** values are computed but rather **how** computation is structured:
control-flow shape, data-dependency patterns, event sequences, and cost.

Architecture
────────────

    ┌──────────────┐      compile       ┌──────────────────┐
    │  CFG (shims) │  ──────────────►   │  AbstractProgram  │
    └──────────────┘                    │  (bytecode image) │
                                        └────────┬─────────┘
                                                 │
                                          interpret / trace
                                                 │
                                        ┌────────▼─────────┐
                                        │  AbstractVM       │
                                        │  (schema, events, │
                                        │   cost, traces)   │
                                        └──────────────────┘

The bytecode is a linear sequence of ``Instruction`` objects grouped into
``CodeBlock`` units (one per CFG basic block, plus synthetic preamble /
epilogue blocks).  The VM walks these blocks following the abstract
control-flow edges, maintaining:

    • An **abstract register file** — mapping symbolic names to abstract
      domain elements (intervals by default, but any ``AbstractDomain``).
    • A **call stack** of activation frames for interprocedural analysis.
    • An **event trace** recording ``EVENT`` / ``OBSERVE`` firings.
    • A **cumulative cost** in the ``IntervalDomain``.
    • A **schema listing** that captures the static execution skeleton.

Instruction Set (Abstract ISA)
──────────────────────────────

  Mnemonic        Operands                   Semantics (abstract)
  ──────────────  ─────────────────────────  ───────────────────────────
  NOP                                        No operation
  CONST           dst, abstract_value        dst ← abstract constant
  COPY            dst, src                   dst ← src
  PHI             dst, [src₁, …, srcₙ]      dst ← ⊔ srcᵢ
  LOAD            dst, base, offset          dst ← Mem[base + offset]
  STORE           base, offset, src          Mem[base + offset] ← src
  BINOP           dst, op, lhs, rhs          dst ← lhs ⟨op⟩ rhs
  UNOP            dst, op, src               dst ← ⟨op⟩ src
  COMPARE         dst, rel, lhs, rhs         dst ← lhs ⟨rel⟩ rhs
  BRANCH          cond, true_bb, false_bb    conditional jump
  JUMP            target_bb                  unconditional jump
  CALL            dst, func_id, [args…]      interprocedural call
  RETURN          src                        return from function
  EVENT           event_id, [params…]        fire user-defined event
  OBSERVE         observer_id, [exprs…]      observe state for analysis
  WIDEN           dst, src                   dst ← widen(dst, src)
  NARROW          dst, src                   dst ← narrow(dst, src)
  COST            amount                     accumulate abstract cost
  ASSERT          cond                       abstract assertion
  HAVOC           dst                        dst ← ⊤ (unknown)
  ENTER_SCOPE     scope_id                   open a new scope
  EXIT_SCOPE      scope_id                   close scope
  ALLOC           dst, size                  abstract allocation
  FREE            src                        abstract deallocation
  CAST            dst, src, target_type      abstract type cast
  LABEL           name                       symbolic label (no-op)

Theory
──────

The abstract execution model follows Larus (1990): instead of directly
instrumenting a program P to record events E, we compile P into an
*abstract program* P' that collects *significant events* SE and later
*regenerates* E from SE.  In our setting P is the CFG, P' is the
abstract bytecode, SE are the ``EVENT`` instructions, and regeneration
is performed by the ``AbstractVM`` interpreter together with the user's
``AbsExecAnalysis`` (defined in ``abstract_exec.py``).

License: MIT — same as cppcheckdata-shims.
"""

from __future__ import annotations

import enum
import math
import itertools
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
# Imports from sibling modules
# ---------------------------------------------------------------------------

from cppcheckdata_shims.abstract_domains import (
    AbstractDomain,
    IntervalDomain,
    SignDomain,
    FunctionDomain,
    FlatDomain,
    BoolDomain,
    make_interval_env,
)
from cppcheckdata_shims.ctrlflow_graph import CFG, BasicBlock, CFGEdge

# We reference but do not hard-depend on symbolic_exec at import time so
# that the module can be loaded independently.
try:
    from cppcheckdata_shims.symbolic_exec import (
        SymbolicState as _SymState,
        SymbolicValue as _SymVal,
    )

    _HAS_SYMEXEC = True
except ImportError:  # pragma: no cover
    _HAS_SYMEXEC = False

# ---------------------------------------------------------------------------
# Type variables
# ---------------------------------------------------------------------------

D = TypeVar("D", bound=AbstractDomain)
T = TypeVar("T")

# ═══════════════════════════════════════════════════════════════════════════
# 1. INSTRUCTION SET
# ═══════════════════════════════════════════════════════════════════════════


class Opcode(enum.Enum):
    """Every opcode in the Abstract ISA."""

    NOP = "NOP"
    CONST = "CONST"
    COPY = "COPY"
    PHI = "PHI"
    LOAD = "LOAD"
    STORE = "STORE"
    BINOP = "BINOP"
    UNOP = "UNOP"
    COMPARE = "COMPARE"
    BRANCH = "BRANCH"
    JUMP = "JUMP"
    CALL = "CALL"
    RETURN = "RETURN"
    EVENT = "EVENT"
    OBSERVE = "OBSERVE"
    WIDEN = "WIDEN"
    NARROW = "NARROW"
    COST = "COST"
    ASSERT = "ASSERT"
    HAVOC = "HAVOC"
    ENTER_SCOPE = "ENTER_SCOPE"
    EXIT_SCOPE = "EXIT_SCOPE"
    ALLOC = "ALLOC"
    FREE = "FREE"
    CAST = "CAST"
    LABEL = "LABEL"


class BinOp(enum.Enum):
    """Abstract binary operators."""

    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"
    AND = "&"
    OR = "|"
    XOR = "^"
    SHL = "<<"
    SHR = ">>"
    LOGICAL_AND = "&&"
    LOGICAL_OR = "||"


class UnOp(enum.Enum):
    """Abstract unary operators."""

    NEG = "-"
    NOT = "!"
    BITWISE_NOT = "~"


class CmpOp(enum.Enum):
    """Comparison / relational operators."""

    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="


# ---------------------------------------------------------------------------
# Operand types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Reg:
    """A symbolic register (abstract variable)."""

    name: str

    def __repr__(self) -> str:
        return f"%{self.name}"


@dataclass(frozen=True, slots=True)
class BlockRef:
    """Reference to a ``CodeBlock`` by its id."""

    block_id: int

    def __repr__(self) -> str:
        return f"BB{self.block_id}"


@dataclass(frozen=True, slots=True)
class FuncRef:
    """Reference to a function (by name or id)."""

    name: str
    func_id: Optional[int] = None

    def __repr__(self) -> str:
        tag = f"#{self.func_id}" if self.func_id is not None else ""
        return f"@{self.name}{tag}"


@dataclass(frozen=True, slots=True)
class EventRef:
    """Reference to a user-defined abstract event."""

    event_id: str
    params: Tuple[Any, ...] = ()

    def __repr__(self) -> str:
        p = ", ".join(str(x) for x in self.params)
        return f"event:{self.event_id}({p})"


@dataclass(frozen=True, slots=True)
class ObserverRef:
    """Reference to a user-defined observer."""

    observer_id: str
    expressions: Tuple[Reg, ...] = ()

    def __repr__(self) -> str:
        e = ", ".join(str(x) for x in self.expressions)
        return f"observe:{self.observer_id}({e})"


@dataclass(frozen=True, slots=True)
class CostLiteral:
    """An abstract cost annotation (always an IntervalDomain)."""

    cost: IntervalDomain

    def __repr__(self) -> str:
        return f"cost({self.cost})"


Operand = Union[
    Reg,
    BlockRef,
    FuncRef,
    EventRef,
    ObserverRef,
    CostLiteral,
    IntervalDomain,
    SignDomain,
    BoolDomain,
    FlatDomain,
    BinOp,
    UnOp,
    CmpOp,
    int,
    float,
    str,
    None,
]

# ---------------------------------------------------------------------------
# Instruction
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Instruction:
    """A single abstract bytecode instruction.

    Parameters
    ----------
    opcode : Opcode
        The operation.
    operands : tuple[Operand, ...]
        Positional operands whose meaning is opcode-specific (see the ISA
        table in the module docstring).
    cost : Optional[IntervalDomain]
        Optional cost annotation carried by this instruction.  The VM
        accumulates costs as it walks the abstract program.
    source_loc : Optional[Tuple[str, int, int]]
        ``(file, line, column)`` from the original C/C++ source, carried
        for diagnostics and for the schema listing.
    comment : str
        Human-readable annotation (useful for ``dump()``).
    """

    opcode: Opcode
    operands: Tuple[Operand, ...] = ()
    cost: Optional[IntervalDomain] = None
    source_loc: Optional[Tuple[str, int, int]] = None
    comment: str = ""

    # Convenience helpers to decode operand slots ----------------------------

    @property
    def dst(self) -> Optional[Reg]:
        """Destination register (first operand for most instructions)."""
        if self.operands and isinstance(self.operands[0], Reg):
            return self.operands[0]
        return None

    def regs_defined(self) -> FrozenSet[Reg]:
        """Set of registers *written* by this instruction."""
        d = self.dst
        if d is not None:
            return frozenset({d})
        return frozenset()

    def regs_used(self) -> FrozenSet[Reg]:
        """Set of registers *read* by this instruction."""
        used: Set[Reg] = set()
        # Skip dst (operands[0]) for opcodes that define it
        start = 1 if self.opcode in _DEFINING_OPCODES else 0
        for op in self.operands[start:]:
            if isinstance(op, Reg):
                used.add(op)
            elif isinstance(op, (list, tuple)):
                for sub in op:
                    if isinstance(sub, Reg):
                        used.add(sub)
        return frozenset(used)

    # Pretty-print -----------------------------------------------------------

    def __repr__(self) -> str:
        ops = ", ".join(_fmt_operand(o) for o in self.operands)
        loc = ""
        if self.source_loc:
            f, l, c = self.source_loc
            loc = f"  ; {f}:{l}:{c}"
        cst = ""
        if self.cost is not None:
            cst = f"  [cost={self.cost}]"
        cmt = ""
        if self.comment:
            cmt = f"  # {self.comment}"
        return f"{self.opcode.value:15s} {ops}{cst}{loc}{cmt}"


# Opcodes whose first operand is a destination register
_DEFINING_OPCODES: FrozenSet[Opcode] = frozenset(
    {
        Opcode.CONST,
        Opcode.COPY,
        Opcode.PHI,
        Opcode.LOAD,
        Opcode.BINOP,
        Opcode.UNOP,
        Opcode.COMPARE,
        Opcode.CALL,
        Opcode.WIDEN,
        Opcode.NARROW,
        Opcode.HAVOC,
        Opcode.ALLOC,
        Opcode.CAST,
    }
)


def _fmt_operand(op: Operand) -> str:
    if isinstance(op, (list, tuple)):
        inner = ", ".join(_fmt_operand(x) for x in op)
        return f"[{inner}]"
    return repr(op)


# ═══════════════════════════════════════════════════════════════════════════
# 2. CODE BLOCK & ABSTRACT PROGRAM
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class CodeBlock:
    """A basic block in the abstract program.

    Maps 1-to-1 with a ``BasicBlock`` in the CFG (plus possible synthetic
    blocks for function preamble/epilogue).

    Attributes
    ----------
    block_id : int
        Unique identifier (same as the originating ``BasicBlock.id`` when
        applicable, negative ids for synthetic blocks).
    instructions : list[Instruction]
        Ordered instruction sequence.
    successors : list[int]
        Ids of successor ``CodeBlock``s.
    predecessors : list[int]
        Ids of predecessor ``CodeBlock``s.
    is_entry : bool
        True for the function entry block.
    is_exit : bool
        True for the function exit block.
    cfg_block : Optional[BasicBlock]
        Back-pointer to the originating CFG block (``None`` for synthetics).
    loop_depth : int
        Nesting depth of the innermost enclosing loop (0 = not in a loop).
    """

    block_id: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    is_entry: bool = False
    is_exit: bool = False
    cfg_block: Optional[Any] = None  # BasicBlock
    loop_depth: int = 0

    def append(self, instr: Instruction) -> None:
        """Append an instruction to this block."""
        self.instructions.append(instr)

    def prepend(self, instr: Instruction) -> None:
        """Prepend an instruction (useful for PHI insertion)."""
        self.instructions.insert(0, instr)

    def __len__(self) -> int:
        return len(self.instructions)

    def __iter__(self):
        return iter(self.instructions)

    def __repr__(self) -> str:
        entry = " [ENTRY]" if self.is_entry else ""
        exit_ = " [EXIT]" if self.is_exit else ""
        return f"CodeBlock(id={self.block_id}, #instr={len(self)}{entry}{exit_})"


@dataclass(slots=True)
class FunctionCode:
    """Abstract bytecode for a single function.

    Attributes
    ----------
    name : str
        Function name.
    func_id : int
        Unique numeric id.
    blocks : dict[int, CodeBlock]
        Block id → CodeBlock mapping.
    entry_id : int
        Id of the entry block.
    exit_ids : list[int]
        Ids of exit blocks (may have multiple return points).
    params : list[Reg]
        Formal parameter registers.
    locals_ : list[Reg]
        All local registers (including params).
    source_file : Optional[str]
        Originating source file.
    """

    name: str
    func_id: int
    blocks: Dict[int, CodeBlock] = field(default_factory=dict)
    entry_id: int = 0
    exit_ids: List[int] = field(default_factory=list)
    params: List[Reg] = field(default_factory=list)
    locals_: List[Reg] = field(default_factory=list)
    source_file: Optional[str] = None

    @property
    def entry_block(self) -> CodeBlock:
        return self.blocks[self.entry_id]

    def block_order(self) -> List[int]:
        """Return block ids in reverse post-order (good for forward analysis)."""
        visited: Set[int] = set()
        order: List[int] = []

        def _dfs(bid: int) -> None:
            if bid in visited:
                return
            visited.add(bid)
            blk = self.blocks.get(bid)
            if blk is None:
                return
            for succ in blk.successors:
                _dfs(succ)
            order.append(bid)

        _dfs(self.entry_id)
        order.reverse()
        return order

    def dump(self) -> str:
        """Pretty-print the function's bytecode."""
        lines: List[str] = []
        lines.append(f"function @{self.name} (id={self.func_id}) {{")
        if self.params:
            p = ", ".join(str(r) for r in self.params)
            lines.append(f"  params: {p}")
        for bid in self.block_order():
            blk = self.blocks[bid]
            tag = ""
            if blk.is_entry:
                tag += " [entry]"
            if blk.is_exit:
                tag += " [exit]"
            succs = ", ".join(f"BB{s}" for s in blk.successors)
            lines.append(f"  BB{bid}{tag}:  ; succs=[{succs}]")
            for instr in blk.instructions:
                lines.append(f"    {instr}")
        lines.append("}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"FunctionCode(name={self.name!r}, "
            f"#blocks={len(self.blocks)}, "
            f"#params={len(self.params)})"
        )


@dataclass(slots=True)
class AbstractProgram:
    """Complete abstract bytecode image for a translation unit.

    This is the top-level object produced by ``AbstractCompiler`` and
    consumed by ``AbstractVM``.

    Attributes
    ----------
    functions : dict[str, FunctionCode]
        Function name → bytecode.
    func_by_id : dict[int, FunctionCode]
        Function id → bytecode.
    globals_ : list[Instruction]
        Module-level initialisation instructions.
    source_file : Optional[str]
        Original file name.
    metadata : dict[str, Any]
        Arbitrary compiler metadata.
    """

    functions: Dict[str, FunctionCode] = field(default_factory=dict)
    func_by_id: Dict[int, FunctionCode] = field(default_factory=dict)
    globals_: List[Instruction] = field(default_factory=list)
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_function(self, fc: FunctionCode) -> None:
        self.functions[fc.name] = fc
        self.func_by_id[fc.func_id] = fc

    def dump(self) -> str:
        parts: List[str] = []
        if self.source_file:
            parts.append(f"; source: {self.source_file}")
        if self.globals_:
            parts.append("; --- globals ---")
            for instr in self.globals_:
                parts.append(f"  {instr}")
        for name in sorted(self.functions):
            parts.append("")
            parts.append(self.functions[name].dump())
        return "\n".join(parts)

    def __repr__(self) -> str:
        return (
            f"AbstractProgram(#funcs={len(self.functions)}, "
            f"source={self.source_file!r})"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 3. ABSTRACT COMPILER — CFG → Abstract Bytecode
# ═══════════════════════════════════════════════════════════════════════════


class AbstractCompiler:
    """Compiles a ``CFG`` (from ``ctrlflow_graph``) into an ``AbstractProgram``.

    The compiler performs the following passes:

    1. **Block mapping** — create one ``CodeBlock`` per ``BasicBlock``.
    2. **Instruction lowering** — walk each basic block's token list and
       emit abstract instructions.  The lowering is *conservative*: every
       side-effect is represented but concrete values are replaced by
       ``HAVOC`` (⊤) unless a constant is statically visible.
    3. **PHI insertion** — at join points (blocks with >1 predecessor),
       insert ``PHI`` instructions for every register live-in.
    4. **Edge translation** — conditional/unconditional edges become
       ``BRANCH`` / ``JUMP`` terminators.
    5. **Cost annotation** — each instruction gets a default unit cost
       (overridable via ``cost_model``).

    Parameters
    ----------
    cost_model : Optional[Callable[[Instruction], IntervalDomain]]
        If provided, called for every emitted instruction to assign a cost.
        Default: every instruction costs ``[1, 1]`` except ``NOP``/``LABEL``
        which cost ``[0, 0]``.
    insert_events : bool
        If ``True``, emit ``EVENT`` instructions at function entry/exit,
        call sites, and memory operations.  Default ``True``.
    """

    _UNIT_COST = IntervalDomain.const(1)
    _ZERO_COST = IntervalDomain.const(0)

    def __init__(
        self,
        cost_model: Optional[Callable[[Instruction], IntervalDomain]] = None,
        insert_events: bool = True,
    ):
        self._cost_model = cost_model
        self._insert_events = insert_events
        self._func_id_counter = itertools.count(0)
        self._reg_counters: Dict[str, int] = {}  # per-function

    # ---- public API --------------------------------------------------------

    def compile_cfg(
        self,
        cfg: CFG,
        func_name: str = "<unknown>",
        source_file: Optional[str] = None,
    ) -> FunctionCode:
        """Compile a single CFG into a ``FunctionCode`` object.

        Parameters
        ----------
        cfg : CFG
            The control flow graph (from ``ctrlflow_graph``).
        func_name : str
            Human-readable function name.
        source_file : Optional[str]
            Source file path for diagnostics.

        Returns
        -------
        FunctionCode
        """
        self._reg_counters.clear()
        fid = next(self._func_id_counter)

        fc = FunctionCode(
            name=func_name,
            func_id=fid,
            source_file=source_file,
        )

        # --- 1. Block mapping -----------------------------------------------
        block_map: Dict[int, CodeBlock] = {}
        for bb in cfg.blocks:
            cb = CodeBlock(
                block_id=bb.id,
                cfg_block=bb,
                is_entry=(bb is cfg.entry),
                is_exit=(bb is cfg.exit if hasattr(cfg, "exit") else False),
            )
            block_map[bb.id] = cb

        # If no exit was marked, detect blocks with no successors
        exit_ids: List[int] = []
        for bb in cfg.blocks:
            cb = block_map[bb.id]
            # Populate successor / predecessor lists from CFG edges
            for edge in cfg.edges:
                if edge.src is bb:
                    cb.successors.append(edge.dst.id)
                if edge.dst is bb:
                    cb.predecessors.append(edge.src.id)
            if not cb.successors:
                cb.is_exit = True
                exit_ids.append(cb.block_id)

        fc.blocks = block_map
        fc.exit_ids = exit_ids

        # Determine entry
        for bid, cb in block_map.items():
            if cb.is_entry:
                fc.entry_id = bid
                break
        else:
            # Fallback: pick the block with no predecessors
            for bid, cb in block_map.items():
                if not cb.predecessors:
                    cb.is_entry = True
                    fc.entry_id = bid
                    break

        # --- 2. Instruction lowering -----------------------------------------
        for bb in cfg.blocks:
            cb = block_map[bb.id]
            self._lower_block(cb, bb, cfg, fc)

        # --- 3. PHI insertion ------------------------------------------------
        self._insert_phis(fc, block_map)

        # --- 4. Edge translation (terminators) --------------------------------
        for bb in cfg.blocks:
            cb = block_map[bb.id]
            self._emit_terminator(cb, bb, cfg, block_map)

        # --- 5. Cost annotation -----------------------------------------------
        for cb in block_map.values():
            for instr in cb.instructions:
                if instr.cost is None:
                    instr.cost = self._assign_cost(instr)

        # --- Collect locals --------------------------------------------------
        all_regs: Set[Reg] = set()
        for cb in block_map.values():
            for instr in cb.instructions:
                all_regs |= instr.regs_defined()
                all_regs |= instr.regs_used()
        fc.locals_ = sorted(all_regs, key=lambda r: r.name)

        # Heuristic: registers named "param_*" are parameters
        fc.params = [r for r in fc.locals_ if r.name.startswith("param_")]

        return fc

    def compile_program(
        self,
        cfgs: Mapping[str, CFG],
        source_file: Optional[str] = None,
    ) -> AbstractProgram:
        """Compile a mapping of ``{func_name: CFG}`` into a full program.

        Parameters
        ----------
        cfgs : Mapping[str, CFG]
            One CFG per function.
        source_file : Optional[str]
            Source file path.

        Returns
        -------
        AbstractProgram
        """
        prog = AbstractProgram(source_file=source_file)
        for name, cfg in cfgs.items():
            fc = self.compile_cfg(cfg, func_name=name, source_file=source_file)
            prog.add_function(fc)
        return prog

    # ---- internal lowering helpers -----------------------------------------

    def _fresh_reg(self, prefix: str = "t") -> Reg:
        """Generate a fresh register name."""
        n = self._reg_counters.get(prefix, 0)
        self._reg_counters[prefix] = n + 1
        return Reg(f"{prefix}_{n}")

    def _source_loc(self, bb: Any) -> Optional[Tuple[str, int, int]]:
        """Extract source location from a BasicBlock (best-effort)."""
        # BasicBlock may carry tokens; pick the first one with a location
        if hasattr(bb, "tokens") and bb.tokens:
            tok = bb.tokens[0] if isinstance(bb.tokens, list) else bb.tokens
            if hasattr(tok, "file") and hasattr(tok, "linenr"):
                return (
                    str(tok.file) if tok.file else "<unknown>",
                    int(tok.linenr) if tok.linenr else 0,
                    int(tok.column) if hasattr(tok, "column") and tok.column else 0,
                )
        return None

    def _lower_block(
        self,
        cb: CodeBlock,
        bb: Any,  # BasicBlock
        cfg: CFG,
        fc: FunctionCode,
    ) -> None:
        """Lower a single BasicBlock into abstract instructions.

        We walk the tokens associated with the basic block and pattern-
        match on AST structure to emit the appropriate opcodes.
        """
        loc = self._source_loc(bb)

        # Emit scope entry if block is a function entry
        if cb.is_entry and self._insert_events:
            cb.append(
                Instruction(
                    Opcode.ENTER_SCOPE,
                    (fc.name,),
                    source_loc=loc,
                    comment=f"enter {fc.name}",
                )
            )
            cb.append(
                Instruction(
                    Opcode.EVENT,
                    (EventRef("func_entry", (fc.name,)),),
                    source_loc=loc,
                    comment="abstract event: function entry",
                )
            )

        # Walk tokens in the basic block
        tokens = getattr(bb, "tokens", None) or []
        if not isinstance(tokens, (list, tuple)):
            tokens = [tokens]

        for tok in tokens:
            self._lower_token(cb, tok, loc, fc)

        # Emit scope exit / event at exit blocks
        if cb.is_exit and self._insert_events:
            cb.append(
                Instruction(
                    Opcode.EVENT,
                    (EventRef("func_exit", (fc.name,)),),
                    source_loc=loc,
                    comment="abstract event: function exit",
                )
            )
            cb.append(
                Instruction(
                    Opcode.EXIT_SCOPE,
                    (fc.name,),
                    source_loc=loc,
                    comment=f"exit {fc.name}",
                )
            )

    def _lower_token(
        self,
        cb: CodeBlock,
        tok: Any,
        loc: Optional[Tuple[str, int, int]],
        fc: FunctionCode,
    ) -> Optional[Reg]:
        """Lower a single AST token node into abstract instructions.

        This method handles the major C/C++ expression and statement forms,
        emitting abstract bytecode that preserves the *shape* of the
        computation.

        Returns the register holding the result (if any).
        """
        if tok is None:
            return None

        # Source location from this specific token
        tok_loc = loc
        if hasattr(tok, "file") and hasattr(tok, "linenr"):
            tok_loc = (
                str(tok.file) if tok.file else "<unknown>",
                int(tok.linenr) if tok.linenr else 0,
                int(getattr(tok, "column", 0) or 0),
            )

        tok_str = getattr(tok, "str", None) or ""
        is_op = getattr(tok, "isOp", False)
        is_assign = getattr(tok, "isAssignmentOp", False)
        ast_op = getattr(tok, "astOperand1", None)

        # --- Constants -------------------------------------------------------
        if getattr(tok, "isNumber", False) or getattr(tok, "isInt", False):
            dst = self._fresh_reg("c")
            try:
                val = int(tok_str, 0) if tok_str else 0
                abstract_val = IntervalDomain.const(val)
            except (ValueError, TypeError):
                try:
                    val = float(tok_str)
                    abstract_val = IntervalDomain(val, val)
                except (ValueError, TypeError):
                    abstract_val = IntervalDomain.top()
            cb.append(
                Instruction(Opcode.CONST, (dst, abstract_val), source_loc=tok_loc)
            )
            return dst

        if getattr(tok, "isFloat", False):
            dst = self._fresh_reg("cf")
            try:
                val = float(tok_str)
                abstract_val = IntervalDomain(val, val)
            except (ValueError, TypeError):
                abstract_val = IntervalDomain.top()
            cb.append(
                Instruction(Opcode.CONST, (dst, abstract_val), source_loc=tok_loc)
            )
            return dst

        # --- Variables -------------------------------------------------------
        variable = getattr(tok, "variable", None)
        if variable is not None and not is_op and not is_assign:
            var_name = getattr(variable, "nameToken", None)
            vn = getattr(var_name, "str", None) if var_name else tok_str
            if not vn:
                vn = tok_str
            dst = Reg(f"var_{vn}")
            # Variable read is implicit — we just reference the register
            return dst

        # --- Assignment (=, +=, -= etc.) ------------------------------------
        if is_assign:
            lhs_tok = getattr(tok, "astOperand1", None)
            rhs_tok = getattr(tok, "astOperand2", None)
            rhs_reg = self._lower_token(cb, rhs_tok, tok_loc, fc)
            lhs_reg = self._lower_lhs(cb, lhs_tok, tok_loc, fc)
            if lhs_reg is not None and rhs_reg is not None:
                if tok_str == "=":
                    cb.append(
                        Instruction(
                            Opcode.COPY,
                            (lhs_reg, rhs_reg),
                            source_loc=tok_loc,
                            comment=f"assign {lhs_reg} = {rhs_reg}",
                        )
                    )
                else:
                    # Compound assignment: +=, -=, *=, etc.
                    op_char = tok_str.rstrip("=")
                    binop = _STR_TO_BINOP.get(op_char, BinOp.ADD)
                    tmp = self._fresh_reg("t")
                    cb.append(
                        Instruction(
                            Opcode.BINOP,
                            (tmp, binop, lhs_reg, rhs_reg),
                            source_loc=tok_loc,
                        )
                    )
                    cb.append(
                        Instruction(
                            Opcode.COPY,
                            (lhs_reg, tmp),
                            source_loc=tok_loc,
                            comment=f"compound assign {tok_str}",
                        )
                    )
                if self._insert_events:
                    cb.append(
                        Instruction(
                            Opcode.EVENT,
                            (EventRef("assign", (str(lhs_reg),)),),
                            source_loc=tok_loc,
                        )
                    )
            return lhs_reg

        # --- Binary operators ------------------------------------------------
        if is_op and getattr(tok, "astOperand1", None) and getattr(tok, "astOperand2", None):
            lhs_tok = tok.astOperand1
            rhs_tok = tok.astOperand2
            lhs_reg = self._lower_token(cb, lhs_tok, tok_loc, fc)
            rhs_reg = self._lower_token(cb, rhs_tok, tok_loc, fc)

            # Comparison?
            cmp = _STR_TO_CMPOP.get(tok_str)
            if cmp is not None:
                dst = self._fresh_reg("cmp")
                cb.append(
                    Instruction(
                        Opcode.COMPARE,
                        (dst, cmp, lhs_reg or Reg("?"), rhs_reg or Reg("?")),
                        source_loc=tok_loc,
                    )
                )
                return dst

            binop = _STR_TO_BINOP.get(tok_str)
            if binop is not None:
                dst = self._fresh_reg("t")
                cb.append(
                    Instruction(
                        Opcode.BINOP,
                        (dst, binop, lhs_reg or Reg("?"), rhs_reg or Reg("?")),
                        source_loc=tok_loc,
                    )
                )
                return dst

        # --- Unary operators -------------------------------------------------
        if is_op and getattr(tok, "astOperand1", None) and not getattr(tok, "astOperand2", None):
            operand_tok = tok.astOperand1
            operand_reg = self._lower_token(cb, operand_tok, tok_loc, fc)
            unop = _STR_TO_UNOP.get(tok_str)
            if unop is not None and operand_reg is not None:
                dst = self._fresh_reg("u")
                cb.append(
                    Instruction(
                        Opcode.UNOP,
                        (dst, unop, operand_reg),
                        source_loc=tok_loc,
                    )
                )
                return dst

            # Dereference (pointer load)
            if tok_str == "*":
                dst = self._fresh_reg("deref")
                cb.append(
                    Instruction(
                        Opcode.LOAD,
                        (dst, operand_reg or Reg("?"), IntervalDomain.const(0)),
                        source_loc=tok_loc,
                        comment="dereference",
                    )
                )
                if self._insert_events:
                    cb.append(
                        Instruction(
                            Opcode.EVENT,
                            (EventRef("mem_read", (str(operand_reg),)),),
                            source_loc=tok_loc,
                        )
                    )
                return dst

            # Address-of
            if tok_str == "&" and operand_reg is not None:
                dst = self._fresh_reg("addr")
                cb.append(
                    Instruction(
                        Opcode.CONST,
                        (dst, IntervalDomain.top()),
                        source_loc=tok_loc,
                        comment=f"address-of {operand_reg}",
                    )
                )
                return dst

        # --- Function calls --------------------------------------------------
        func_attr = getattr(tok, "function", None)
        if tok_str == "(" and func_attr is not None:
            callee_name = getattr(func_attr, "name", "<indirect>")
            # Gather arguments from astOperand2
            args: List[Reg] = []
            arg_tok = getattr(tok, "astOperand2", None)
            self._collect_args(cb, arg_tok, args, tok_loc, fc)

            dst = self._fresh_reg("ret")
            cb.append(
                Instruction(
                    Opcode.CALL,
                    (dst, FuncRef(callee_name), tuple(args)),
                    source_loc=tok_loc,
                    comment=f"call {callee_name}",
                )
            )
            if self._insert_events:
                cb.append(
                    Instruction(
                        Opcode.EVENT,
                        (EventRef("call", (callee_name, len(args))),),
                        source_loc=tok_loc,
                    )
                )
            return dst

        # --- Array subscript (treated as LOAD) --------------------------------
        if tok_str == "[":
            base_tok = getattr(tok, "astOperand1", None)
            idx_tok = getattr(tok, "astOperand2", None)
            base_reg = self._lower_token(cb, base_tok, tok_loc, fc)
            idx_reg = self._lower_token(cb, idx_tok, tok_loc, fc)
            dst = self._fresh_reg("elem")
            cb.append(
                Instruction(
                    Opcode.LOAD,
                    (dst, base_reg or Reg("?"), idx_reg or IntervalDomain.top()),
                    source_loc=tok_loc,
                    comment="array subscript",
                )
            )
            if self._insert_events:
                cb.append(
                    Instruction(
                        Opcode.EVENT,
                        (EventRef("mem_read", (str(base_reg),)),),
                        source_loc=tok_loc,
                    )
                )
            return dst

        # --- Return ----------------------------------------------------------
        if tok_str == "return":
            ret_tok = getattr(tok, "astOperand1", None)
            ret_reg = self._lower_token(cb, ret_tok, tok_loc, fc)
            cb.append(
                Instruction(
                    Opcode.RETURN,
                    (ret_reg,) if ret_reg else (),
                    source_loc=tok_loc,
                )
            )
            return None

        # --- malloc / free (heuristic) ----------------------------------------
        if tok_str in ("malloc", "calloc", "realloc"):
            arg_tok = getattr(tok, "astOperand1", None) or getattr(tok, "astOperand2", None)
            size_reg = self._lower_token(cb, arg_tok, tok_loc, fc)
            dst = self._fresh_reg("heap")
            cb.append(
                Instruction(
                    Opcode.ALLOC,
                    (dst, size_reg or Reg("?")),
                    source_loc=tok_loc,
                    comment=f"{tok_str} allocation",
                )
            )
            if self._insert_events:
                cb.append(
                    Instruction(
                        Opcode.EVENT,
                        (EventRef("alloc", (tok_str,)),),
                        source_loc=tok_loc,
                    )
                )
            return dst

        if tok_str == "free":
            arg_tok = getattr(tok, "astOperand1", None) or getattr(tok, "astOperand2", None)
            arg_reg = self._lower_token(cb, arg_tok, tok_loc, fc)
            cb.append(
                Instruction(
                    Opcode.FREE,
                    (arg_reg or Reg("?"),),
                    source_loc=tok_loc,
                )
            )
            if self._insert_events:
                cb.append(
                    Instruction(
                        Opcode.EVENT,
                        (EventRef("free", ()),),
                        source_loc=tok_loc,
                    )
                )
            return None

        # --- Cast expression --------------------------------------------------
        type_scope = getattr(tok, "typeScope", None)
        value_type = getattr(tok, "valueType", None)
        if tok_str == "(" and type_scope is not None and value_type is not None:
            inner_tok = getattr(tok, "astOperand1", None)
            inner_reg = self._lower_token(cb, inner_tok, tok_loc, fc)
            dst = self._fresh_reg("cast")
            type_name = getattr(value_type, "originalTypeName", "unknown")
            cb.append(
                Instruction(
                    Opcode.CAST,
                    (dst, inner_reg or Reg("?"), str(type_name)),
                    source_loc=tok_loc,
                    comment=f"cast to {type_name}",
                )
            )
            return dst

        # --- Fallthrough: anything we don't recognise → HAVOC ----------------
        if getattr(tok, "isName", False) and variable is None:
            # Unresolved name — could be a function name, macro, etc.
            dst = Reg(f"name_{tok_str}")
            return dst

        return None

    def _lower_lhs(
        self,
        cb: CodeBlock,
        tok: Any,
        loc: Optional[Tuple[str, int, int]],
        fc: FunctionCode,
    ) -> Optional[Reg]:
        """Lower the LHS of an assignment, returning the destination register."""
        if tok is None:
            return None
        variable = getattr(tok, "variable", None)
        tok_str = getattr(tok, "str", "") or ""
        if variable is not None:
            var_name = getattr(getattr(variable, "nameToken", None), "str", None) or tok_str
            return Reg(f"var_{var_name}")
        # Pointer dereference on LHS → STORE will be handled by caller
        if tok_str == "*":
            inner = getattr(tok, "astOperand1", None)
            inner_reg = self._lower_token(cb, inner, loc, fc)
            if inner_reg is not None:
                # We return a synthetic register; the COPY will become a STORE
                # in a later pass or is handled in-place.
                return self._fresh_reg("store_target")
        # Array subscript on LHS
        if tok_str == "[":
            base_tok = getattr(tok, "astOperand1", None)
            idx_tok = getattr(tok, "astOperand2", None)
            base_reg = self._lower_token(cb, base_tok, loc, fc)
            idx_reg = self._lower_token(cb, idx_tok, loc, fc)
            store_dst = self._fresh_reg("store_elem")
            # Emit a note that this is an array write
            if self._insert_events:
                cb.append(
                    Instruction(
                        Opcode.EVENT,
                        (EventRef("mem_write", (str(base_reg),)),),
                        source_loc=loc,
                    )
                )
            return store_dst
        return self._lower_token(cb, tok, loc, fc)

    def _collect_args(
        self,
        cb: CodeBlock,
        tok: Any,
        args: List[Reg],
        loc: Optional[Tuple[str, int, int]],
        fc: FunctionCode,
    ) -> None:
        """Recursively collect function-call arguments from comma-separated AST."""
        if tok is None:
            return
        tok_str = getattr(tok, "str", "") or ""
        if tok_str == ",":
            self._collect_args(cb, getattr(tok, "astOperand1", None), args, loc, fc)
            self._collect_args(cb, getattr(tok, "astOperand2", None), args, loc, fc)
        else:
            reg = self._lower_token(cb, tok, loc, fc)
            if reg is not None:
                args.append(reg)

    def _insert_phis(
        self, fc: FunctionCode, block_map: Dict[int, CodeBlock]
    ) -> None:
        """Insert PHI nodes at join points.

        We use a simplified approach: for every block with >1 predecessor,
        and for every register defined in any predecessor, insert a PHI
        merging all incoming definitions.
        """
        for bid, cb in block_map.items():
            if len(cb.predecessors) <= 1:
                continue
            # Gather registers defined in predecessor blocks
            pred_defs: Dict[str, List[Reg]] = {}
            for pid in cb.predecessors:
                pred_blk = block_map.get(pid)
                if pred_blk is None:
                    continue
                for instr in pred_blk.instructions:
                    for r in instr.regs_defined():
                        pred_defs.setdefault(r.name, []).append(r)

            # Also consider registers used in this block that need a PHI
            used_here: Set[str] = set()
            for instr in cb.instructions:
                for r in instr.regs_used():
                    used_here.add(r.name)

            # Insert PHI for each register that is both defined in a pred
            # and used here
            phi_instrs: List[Instruction] = []
            for rname in sorted(pred_defs.keys()):
                if rname in used_here or len(pred_defs[rname]) > 1:
                    sources = list(dict.fromkeys(pred_defs[rname]))  # deduplicate
                    phi_instrs.append(
                        Instruction(
                            Opcode.PHI,
                            (Reg(rname), tuple(sources)),
                            comment=f"φ({', '.join(str(s) for s in sources)})",
                        )
                    )
            # Prepend PHIs to the block
            cb.instructions = phi_instrs + cb.instructions

    def _emit_terminator(
        self,
        cb: CodeBlock,
        bb: Any,  # BasicBlock
        cfg: CFG,
        block_map: Dict[int, CodeBlock],
    ) -> None:
        """Emit the terminator instruction for a block."""
        # Check if we already emitted a RETURN
        if cb.instructions and cb.instructions[-1].opcode == Opcode.RETURN:
            return

        if len(cb.successors) == 0:
            # Implicit return (no successors, not already a RETURN)
            if not cb.is_exit:
                cb.append(Instruction(Opcode.RETURN, (), comment="implicit return"))
            return

        if len(cb.successors) == 1:
            cb.append(
                Instruction(
                    Opcode.JUMP,
                    (BlockRef(cb.successors[0]),),
                    comment=f"goto BB{cb.successors[0]}",
                )
            )
            return

        if len(cb.successors) == 2:
            # Look for a COMPARE result to use as branch condition
            cond_reg: Optional[Reg] = None
            for instr in reversed(cb.instructions):
                if instr.opcode == Opcode.COMPARE and instr.dst:
                    cond_reg = instr.dst
                    break
            if cond_reg is None:
                cond_reg = self._fresh_reg("br_cond")
                cb.append(
                    Instruction(
                        Opcode.HAVOC,
                        (cond_reg,),
                        comment="unknown branch condition",
                    )
                )
            cb.append(
                Instruction(
                    Opcode.BRANCH,
                    (cond_reg, BlockRef(cb.successors[0]), BlockRef(cb.successors[1])),
                    comment=f"branch BB{cb.successors[0]} / BB{cb.successors[1]}",
                )
            )
            return

        # More than 2 successors (switch-like): emit a series of branches
        # or just a JUMP to the first (conservative)
        cb.append(
            Instruction(
                Opcode.JUMP,
                (BlockRef(cb.successors[0]),),
                comment=f"switch → BB{cb.successors[0]} (+ {len(cb.successors)-1} others)",
            )
        )

    def _assign_cost(self, instr: Instruction) -> IntervalDomain:
        """Assign an abstract cost to an instruction."""
        if self._cost_model is not None:
            return self._cost_model(instr)
        if instr.opcode in (Opcode.NOP, Opcode.LABEL, Opcode.ENTER_SCOPE, Opcode.EXIT_SCOPE):
            return self._ZERO_COST
        if instr.opcode == Opcode.CALL:
            # Calls are more expensive; [1, ∞) by default
            return IntervalDomain(1.0, float("inf"))
        if instr.opcode in (Opcode.LOAD, Opcode.STORE):
            # Memory ops: [1, 100] heuristic
            return IntervalDomain(1.0, 100.0)
        return self._UNIT_COST


# Mapping helpers for token strings → enum values
_STR_TO_BINOP: Dict[str, BinOp] = {
    "+": BinOp.ADD,
    "-": BinOp.SUB,
    "*": BinOp.MUL,
    "/": BinOp.DIV,
    "%": BinOp.MOD,
    "&": BinOp.AND,
    "|": BinOp.OR,
    "^": BinOp.XOR,
    "<<": BinOp.SHL,
    ">>": BinOp.SHR,
    "&&": BinOp.LOGICAL_AND,
    "||": BinOp.LOGICAL_OR,
}

_STR_TO_UNOP: Dict[str, UnOp] = {
    "-": UnOp.NEG,
    "!": UnOp.NOT,
    "~": UnOp.BITWISE_NOT,
}

_STR_TO_CMPOP: Dict[str, CmpOp] = {
    "==": CmpOp.EQ,
    "!=": CmpOp.NE,
    "<": CmpOp.LT,
    "<=": CmpOp.LE,
    ">": CmpOp.GT,
    ">=": CmpOp.GE,
}


# ═══════════════════════════════════════════════════════════════════════════
# 4. ABSTRACT VM — Bytecode Interpreter
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(slots=True)
class ActivationFrame:
    """A single stack frame in the abstract VM.

    Attributes
    ----------
    func : FunctionCode
        The function this frame belongs to.
    registers : dict[str, AbstractDomain]
        Register file (register name → abstract value).
    current_block : int
        Id of the currently executing code block.
    pc : int
        Program counter (instruction index within current block).
    return_block : Optional[int]
        Block to return to in the caller.
    return_reg : Optional[Reg]
        Register in the caller that receives the return value.
    """

    func: FunctionCode
    registers: Dict[str, AbstractDomain] = field(default_factory=dict)
    current_block: int = 0
    pc: int = 0
    return_block: Optional[int] = None
    return_reg: Optional[Reg] = None

    def read(self, reg: Reg) -> AbstractDomain:
        """Read a register; returns ⊤ if undefined."""
        return self.registers.get(reg.name, IntervalDomain.top())

    def write(self, reg: Reg, value: AbstractDomain) -> None:
        """Write to a register."""
        self.registers[reg.name] = value


@dataclass(slots=True)
class EventRecord:
    """A recorded abstract event from execution.

    Attributes
    ----------
    event_id : str
        The event identifier.
    params : tuple
        Event parameters.
    source_loc : Optional[Tuple[str, int, int]]
        Where in the source the event fired.
    step : int
        The global step count at which this event fired.
    func_name : str
        Function in which the event occurred.
    block_id : int
        Block in which the event occurred.
    """

    event_id: str
    params: Tuple[Any, ...] = ()
    source_loc: Optional[Tuple[str, int, int]] = None
    step: int = 0
    func_name: str = ""
    block_id: int = 0


@dataclass(slots=True)
class SchemaEntry:
    """One entry in the schema listing.

    A schema listing is the static summary of what the abstract program
    would do along a particular path (or, for the whole-program schema,
    along *all* paths).  It is the key output consumed by
    ``abstract_exec.py``.

    Attributes
    ----------
    block_id : int
        Code block id.
    instruction_index : int
        Index within the block.
    opcode : Opcode
        The opcode executed.
    operand_summary : str
        Human-readable summary of operands.
    abstract_state : dict[str, str]
        Snapshot of relevant register values (as strings).
    cost : IntervalDomain
        Cost of this step.
    events : list[EventRecord]
        Events that fired at this step.
    """

    block_id: int
    instruction_index: int
    opcode: Opcode
    operand_summary: str = ""
    abstract_state: Dict[str, str] = field(default_factory=dict)
    cost: IntervalDomain = field(default_factory=IntervalDomain.const.__func__.__get__(IntervalDomain, type)(0).__class__.const)
    events: List[EventRecord] = field(default_factory=list)

    def __post_init__(self):
        # Fix the cost default (dataclass default_factory trick workaround)
        if callable(self.cost) and not isinstance(self.cost, IntervalDomain):
            self.cost = IntervalDomain.const(0)


@dataclass(slots=True)
class SchemaListing:
    """Complete schema listing for a function's abstract execution.

    Attributes
    ----------
    func_name : str
        Function name.
    entries : list[SchemaEntry]
        Ordered list of schema entries.
    total_cost : IntervalDomain
        Accumulated cost across all entries.
    events : list[EventRecord]
        All events collected.
    path_count : int
        Number of distinct paths explored.
    """

    func_name: str = ""
    entries: List[SchemaEntry] = field(default_factory=list)
    total_cost: IntervalDomain = field(default_factory=lambda: IntervalDomain.const(0))
    events: List[EventRecord] = field(default_factory=list)
    path_count: int = 0

    def append(self, entry: SchemaEntry) -> None:
        self.entries.append(entry)
        self.total_cost = self.total_cost.add(entry.cost)
        self.events.extend(entry.events)

    def dump(self) -> str:
        lines = [f"Schema for @{self.func_name}  (paths={self.path_count}, cost={self.total_cost})"]
        lines.append("=" * len(lines[0]))
        for i, e in enumerate(self.entries):
            ev = ""
            if e.events:
                ev = "  events=[" + ", ".join(r.event_id for r in e.events) + "]"
            lines.append(
                f"  [{i:4d}] BB{e.block_id}:{e.instruction_index:3d}  "
                f"{e.opcode.value:15s} {e.operand_summary}{ev}"
            )
        return "\n".join(lines)


class VMHalt(Exception):
    """Raised when the VM should halt (normal termination)."""
    pass


class VMError(Exception):
    """Raised on abstract assertion failure or invalid state."""
    pass


@runtime_checkable
class EventHandler(Protocol):
    """Protocol for user-defined event handlers.

    When the VM encounters an ``EVENT`` instruction it calls every
    registered handler whose ``event_id`` matches.
    """

    event_id: str

    def handle(
        self,
        event: EventRecord,
        frame: ActivationFrame,
        vm: AbstractVM,
    ) -> None:
        """Process the event.  May modify ``frame`` registers."""
        ...


@runtime_checkable
class ObserverHandler(Protocol):
    """Protocol for user-defined observers.

    Observers are passive: they inspect the abstract state but should
    **not** modify it.
    """

    observer_id: str

    def observe(
        self,
        regs: Dict[str, AbstractDomain],
        source_loc: Optional[Tuple[str, int, int]],
        vm: AbstractVM,
    ) -> None:
        ...


class AbstractVM:
    """Abstract Virtual Machine interpreter.

    Executes an ``AbstractProgram`` (or a single ``FunctionCode``)
    symbolically, maintaining abstract state and producing a
    ``SchemaListing``.

    The interpreter supports two modes:

    1. **Single-path** (``interpret``): follows one path through the CFG,
       choosing the first successor at every branch.  Fast, but
       incomplete.
    2. **All-paths** (``explore``): explores *every* feasible path up to
       a configurable depth / iteration bound using a worklist.  Sound
       (joins state at merge points).

    Parameters
    ----------
    program : AbstractProgram
        The compiled abstract program.
    domain_factory : Callable[[], AbstractDomain]
        Factory for creating ⊤ values in the chosen domain.  Default:
        ``IntervalDomain.top``.
    max_steps : int
        Hard limit on interpretation steps (prevents infinite loops).
    max_call_depth : int
        Maximum call-stack depth for interprocedural analysis.
    widening_threshold : int
        After this many visits to the same block, apply widening instead
        of join.
    """

    def __init__(
        self,
        program: AbstractProgram,
        domain_factory: Callable[[], AbstractDomain] = IntervalDomain.top,
        max_steps: int = 100_000,
        max_call_depth: int = 32,
        widening_threshold: int = 5,
    ):
        self.program = program
        self._domain_factory = domain_factory
        self.max_steps = max_steps
        self.max_call_depth = max_call_depth
        self.widening_threshold = widening_threshold

        # Runtime state
        self._call_stack: List[ActivationFrame] = []
        self._step_count: int = 0
        self._events: List[EventRecord] = []
        self._schema: SchemaListing = SchemaListing()
        self._cumulative_cost: IntervalDomain = IntervalDomain.const(0)

        # Visit counts per (func_id, block_id)
        self._visit_counts: Dict[Tuple[int, int], int] = {}

        # User-registered handlers
        self._event_handlers: Dict[str, List[EventHandler]] = {}
        self._observer_handlers: Dict[str, List[ObserverHandler]] = {}

        # Abstract memory model (flat: address-string → domain value)
        self._memory: Dict[str, AbstractDomain] = {}

    # ---- Handler registration -----------------------------------------------

    def register_event_handler(self, handler: EventHandler) -> None:
        """Register a handler for a specific event id."""
        self._event_handlers.setdefault(handler.event_id, []).append(handler)

    def register_observer(self, observer: ObserverHandler) -> None:
        """Register an observer for a specific observer id."""
        self._observer_handlers.setdefault(observer.observer_id, []).append(observer)

    # ---- Properties ----------------------------------------------------------

    @property
    def events(self) -> List[EventRecord]:
        return list(self._events)

    @property
    def schema(self) -> SchemaListing:
        return self._schema

    @property
    def cumulative_cost(self) -> IntervalDomain:
        return self._cumulative_cost

    @property
    def step_count(self) -> int:
        return self._step_count

    @property
    def call_depth(self) -> int:
        return len(self._call_stack)

    @property
    def current_frame(self) -> Optional[ActivationFrame]:
        return self._call_stack[-1] if self._call_stack else None

    # ---- Interpretation: single path -----------------------------------------

    def interpret(
        self,
        func_name: str,
        initial_state: Optional[Dict[str, AbstractDomain]] = None,
    ) -> SchemaListing:
        """Interpret a single function along the first-successor path.

        Parameters
        ----------
        func_name : str
            Name of the function to interpret.
        initial_state : Optional[Dict[str, AbstractDomain]]
            Initial register values (e.g. for function parameters).

        Returns
        -------
        SchemaListing
            The schema listing produced by this execution.
        """
        fc = self.program.functions.get(func_name)
        if fc is None:
            raise VMError(f"Function {func_name!r} not found in program")

        self._reset()
        self._schema.func_name = func_name

        # Create initial frame
        frame = ActivationFrame(func=fc, current_block=fc.entry_id)
        if initial_state:
            frame.registers.update(initial_state)
        self._call_stack.append(frame)

        try:
            while self._call_stack:
                self._step()
        except VMHalt:
            pass

        self._schema.path_count = 1
        return self._schema

    # ---- Interpretation: all-paths exploration --------------------------------

    def explore(
        self,
        func_name: str,
        initial_state: Optional[Dict[str, AbstractDomain]] = None,
        max_paths: int = 1000,
    ) -> SchemaListing:
        """Explore all paths through a function using a worklist algorithm.

        At join points the abstract states are *joined* (or widened after
        ``widening_threshold`` visits).

        Parameters
        ----------
        func_name : str
            Function to explore.
        initial_state : Optional[Dict[str, AbstractDomain]]
            Initial register values.
        max_paths : int
            Maximum number of path prefixes to explore.

        Returns
        -------
        SchemaListing
        """
        fc = self.program.functions.get(func_name)
        if fc is None:
            raise VMError(f"Function {func_name!r} not found in program")

        self._reset()
        self._schema.func_name = func_name

        # Worklist of (block_id, registers_snapshot)
        Snapshot = Dict[str, AbstractDomain]
        worklist: List[Tuple[int, Snapshot]] = []
        block_states: Dict[int, Snapshot] = {}

        init_regs: Snapshot = dict(initial_state) if initial_state else {}
        worklist.append((fc.entry_id, init_regs))
        paths_explored = 0

        while worklist and paths_explored < max_paths and self._step_count < self.max_steps:
            bid, regs = worklist.pop(0)
            cb = fc.blocks.get(bid)
            if cb is None:
                continue

            # Join / widen with existing state
            key = (fc.func_id, bid)
            visit = self._visit_counts.get(key, 0) + 1
            self._visit_counts[key] = visit

            if bid in block_states:
                old_state = block_states[bid]
                new_state = self._join_states(old_state, regs, widen=(visit > self.widening_threshold))
                if self._state_leq(new_state, old_state):
                    continue  # Fixed point reached for this block
                block_states[bid] = new_state
            else:
                new_state = dict(regs)
                block_states[bid] = new_state

            # Execute the block
            frame = ActivationFrame(func=fc, current_block=bid)
            frame.registers = dict(new_state)
            self._call_stack = [frame]

            for idx, instr in enumerate(cb.instructions):
                self._step_count += 1
                if self._step_count > self.max_steps:
                    break
                self._exec_instruction(instr, frame)
                self._record_schema(instr, idx, bid, frame)

            # Propagate to successors
            for succ_id in cb.successors:
                worklist.append((succ_id, dict(frame.registers)))

            if cb.is_exit or not cb.successors:
                paths_explored += 1

        self._schema.path_count = paths_explored
        return self._schema

    # ---- Core execution engine -----------------------------------------------

    def _reset(self) -> None:
        """Reset all runtime state."""
        self._call_stack.clear()
        self._step_count = 0
        self._events.clear()
        self._schema = SchemaListing()
        self._cumulative_cost = IntervalDomain.const(0)
        self._visit_counts.clear()
        self._memory.clear()

    def _step(self) -> None:
        """Execute one instruction in the current frame."""
        if not self._call_stack:
            raise VMHalt()

        frame = self._call_stack[-1]
        fc = frame.func
        cb = fc.blocks.get(frame.current_block)
        if cb is None:
            self._pop_frame(None)
            return

        if frame.pc >= len(cb.instructions):
            # End of block — follow successor
            self._advance_to_next_block(frame, cb)
            return

        instr = cb.instructions[frame.pc]
        self._step_count += 1
        if self._step_count > self.max_steps:
            raise VMHalt()

        self._exec_instruction(instr, frame)
        self._record_schema(instr, frame.pc, frame.current_block, frame)
        frame.pc += 1

    def _exec_instruction(self, instr: Instruction, frame: ActivationFrame) -> None:
        """Execute a single instruction, updating the frame."""
        op = instr.opcode
        ops = instr.operands

        # Accumulate cost
        if instr.cost is not None:
            self._cumulative_cost = self._cumulative_cost.add(instr.cost)

        if op == Opcode.NOP or op == Opcode.LABEL:
            return

        elif op == Opcode.CONST:
            dst, val = ops[0], ops[1]
            if isinstance(val, AbstractDomain):
                frame.write(dst, val)
            elif isinstance(val, (int, float)):
                frame.write(dst, IntervalDomain.const(val))
            else:
                frame.write(dst, self._domain_factory())

        elif op == Opcode.COPY:
            dst, src = ops[0], ops[1]
            if isinstance(src, Reg):
                frame.write(dst, frame.read(src))
            elif isinstance(src, AbstractDomain):
                frame.write(dst, src)
            else:
                frame.write(dst, self._domain_factory())

        elif op == Opcode.PHI:
            dst = ops[0]
            sources = ops[1] if len(ops) > 1 else ()
            if isinstance(sources, (list, tuple)) and sources:
                result = frame.read(sources[0]) if isinstance(sources[0], Reg) else self._domain_factory()
                for s in sources[1:]:
                    if isinstance(s, Reg):
                        result = result.join(frame.read(s))
                frame.write(dst, result)
            else:
                frame.write(dst, self._domain_factory())

        elif op == Opcode.LOAD:
            dst = ops[0]
            base = ops[1] if len(ops) > 1 else None
            offset = ops[2] if len(ops) > 2 else None
            # Abstract memory read
            addr_key = self._memory_key(base, offset, frame)
            val = self._memory.get(addr_key, self._domain_factory())
            frame.write(dst, val)

        elif op == Opcode.STORE:
            base = ops[0] if len(ops) > 0 else None
            offset = ops[1] if len(ops) > 1 else None
            src = ops[2] if len(ops) > 2 else None
            addr_key = self._memory_key(base, offset, frame)
            if isinstance(src, Reg):
                self._memory[addr_key] = frame.read(src)
            else:
                self._memory[addr_key] = self._domain_factory()

        elif op == Opcode.BINOP:
            dst, binop, lhs, rhs = ops[0], ops[1], ops[2], ops[3]
            lhs_val = frame.read(lhs) if isinstance(lhs, Reg) else self._domain_factory()
            rhs_val = frame.read(rhs) if isinstance(rhs, Reg) else self._domain_factory()
            result = self._eval_binop(binop, lhs_val, rhs_val)
            frame.write(dst, result)

        elif op == Opcode.UNOP:
            dst, unop, src = ops[0], ops[1], ops[2]
            src_val = frame.read(src) if isinstance(src, Reg) else self._domain_factory()
            result = self._eval_unop(unop, src_val)
            frame.write(dst, result)

        elif op == Opcode.COMPARE:
            dst = ops[0]
            # Comparison result is a BoolDomain
            frame.write(dst, BoolDomain.top())

        elif op == Opcode.BRANCH:
            # Handled by _advance_to_next_block; just note the branch
            pass

        elif op == Opcode.JUMP:
            # Handled by _advance_to_next_block
            pass

        elif op == Opcode.CALL:
            dst = ops[0]
            func_ref = ops[1] if len(ops) > 1 else None
            args = ops[2] if len(ops) > 2 else ()
            result = self._handle_call(func_ref, args, frame)
            frame.write(dst, result)

        elif op == Opcode.RETURN:
            ret_val = None
            if ops and isinstance(ops[0], Reg):
                ret_val = frame.read(ops[0])
            self._pop_frame(ret_val)

        elif op == Opcode.EVENT:
            if ops and isinstance(ops[0], EventRef):
                eref = ops[0]
                record = EventRecord(
                    event_id=eref.event_id,
                    params=eref.params,
                    source_loc=instr.source_loc,
                    step=self._step_count,
                    func_name=frame.func.name,
                    block_id=frame.current_block,
                )
                self._events.append(record)
                # Invoke handlers
                for handler in self._event_handlers.get(eref.event_id, []):
                    handler.handle(record, frame, self)

        elif op == Opcode.OBSERVE:
            if ops and isinstance(ops[0], ObserverRef):
                oref = ops[0]
                snapshot = {r.name: frame.read(r) for r in oref.expressions if isinstance(r, Reg)}
                for obs in self._observer_handlers.get(oref.observer_id, []):
                    obs.observe(snapshot, instr.source_loc, self)

        elif op == Opcode.WIDEN:
            dst, src = ops[0], ops[1]
            if isinstance(src, Reg):
                old = frame.read(dst)
                new = frame.read(src)
                frame.write(dst, old.widen(new))

        elif op == Opcode.NARROW:
            dst, src = ops[0], ops[1]
            if isinstance(src, Reg):
                old = frame.read(dst)
                new = frame.read(src)
                frame.write(dst, old.narrow(new))

        elif op == Opcode.COST:
            if ops and isinstance(ops[0], CostLiteral):
                self._cumulative_cost = self._cumulative_cost.add(ops[0].cost)
            elif ops and isinstance(ops[0], IntervalDomain):
                self._cumulative_cost = self._cumulative_cost.add(ops[0])

        elif op == Opcode.ASSERT:
            if ops and isinstance(ops[0], Reg):
                val = frame.read(ops[0])
                if isinstance(val, BoolDomain) and val == BoolDomain.false_():
                    raise VMError(
                        f"Abstract assertion failed at "
                        f"{instr.source_loc or 'unknown location'}"
                    )

        elif op == Opcode.HAVOC:
            dst = ops[0]
            frame.write(dst, self._domain_factory())

        elif op == Opcode.ENTER_SCOPE:
            pass  # Scope tracking could be added here

        elif op == Opcode.EXIT_SCOPE:
            pass

        elif op == Opcode.ALLOC:
            dst = ops[0]
            # Allocation returns a symbolic address (⊤)
            frame.write(dst, self._domain_factory())

        elif op == Opcode.FREE:
            # Could track freed addresses; for now, no-op
            if self._insert_events_enabled and ops:
                pass

        elif op == Opcode.CAST:
            dst = ops[0]
            src = ops[1] if len(ops) > 1 else None
            if isinstance(src, Reg):
                frame.write(dst, frame.read(src))
            else:
                frame.write(dst, self._domain_factory())

    @property
    def _insert_events_enabled(self) -> bool:
        return True

    def _advance_to_next_block(self, frame: ActivationFrame, cb: CodeBlock) -> None:
        """Move to the next block after the current one is exhausted."""
        if not cb.successors:
            self._pop_frame(None)
            return

        # Look at the last instruction for branch/jump
        last = cb.instructions[-1] if cb.instructions else None

        if last and last.opcode == Opcode.BRANCH:
            # Single-path mode: take the true branch (first successor)
            cond = last.operands[0] if last.operands else None
            if isinstance(cond, Reg):
                cond_val = frame.read(cond)
                # If we can determine the branch statically:
                if isinstance(cond_val, BoolDomain):
                    if cond_val == BoolDomain.true_():
                        target = last.operands[1]
                    elif cond_val == BoolDomain.false_():
                        target = last.operands[2] if len(last.operands) > 2 else last.operands[1]
                    else:
                        target = last.operands[1]  # default: true branch
                else:
                    target = last.operands[1]
            else:
                target = last.operands[1] if len(last.operands) > 1 else BlockRef(cb.successors[0])

            if isinstance(target, BlockRef):
                frame.current_block = target.block_id
            else:
                frame.current_block = cb.successors[0]
        elif last and last.opcode == Opcode.JUMP:
            target = last.operands[0] if last.operands else None
            if isinstance(target, BlockRef):
                frame.current_block = target.block_id
            else:
                frame.current_block = cb.successors[0]
        else:
            # Default: first successor
            frame.current_block = cb.successors[0]

        frame.pc = 0

    def _pop_frame(self, return_value: Optional[AbstractDomain]) -> None:
        """Pop the current frame from the call stack."""
        if not self._call_stack:
            raise VMHalt()

        frame = self._call_stack.pop()

        if not self._call_stack:
            raise VMHalt()

        # Write return value to caller
        caller = self._call_stack[-1]
        if frame.return_reg is not None and return_value is not None:
            caller.write(frame.return_reg, return_value)

    def _handle_call(
        self,
        func_ref: Optional[FuncRef],
        args: Any,
        caller_frame: ActivationFrame,
    ) -> AbstractDomain:
        """Handle a CALL instruction.

        If the callee is in the program and we haven't exceeded the call
        depth, perform interprocedural abstract interpretation.  Otherwise,
        return ⊤.
        """
        if func_ref is None or not isinstance(func_ref, FuncRef):
            return self._domain_factory()

        callee = self.program.functions.get(func_ref.name)
        if callee is None or len(self._call_stack) >= self.max_call_depth:
            # Unknown function or depth exceeded — return ⊤
            return self._domain_factory()

        # Build callee frame
        callee_frame = ActivationFrame(
            func=callee,
            current_block=callee.entry_id,
        )

        # Map arguments to parameters
        if isinstance(args, (list, tuple)):
            for i, (param, arg) in enumerate(
                itertools.zip_longest(callee.params, args)
            ):
                if param is not None and isinstance(arg, Reg):
                    callee_frame.write(param, caller_frame.read(arg))
                elif param is not None:
                    callee_frame.write(param, self._domain_factory())

        # For now, we don't recursively execute the callee in single-path
        # mode (that would require full re-entrant interpretation).
        # Instead, we return ⊤.
        # The `explore` method handles interprocedural analysis via the
        # worklist.
        return self._domain_factory()

    # ---- Abstract arithmetic helpers -----------------------------------------

    def _eval_binop(
        self, op: BinOp, lhs: AbstractDomain, rhs: AbstractDomain
    ) -> AbstractDomain:
        """Evaluate a binary operation abstractly."""
        if isinstance(lhs, IntervalDomain) and isinstance(rhs, IntervalDomain):
            dispatch = {
                BinOp.ADD: lhs.add,
                BinOp.SUB: lhs.sub,
                BinOp.MUL: lhs.mul,
                BinOp.DIV: lhs.div,
                BinOp.MOD: lhs.mod,
                BinOp.AND: lhs.bitwise_and,
                BinOp.SHL: lhs.shift_left,
            }
            fn = dispatch.get(op)
            if fn is not None:
                return fn(rhs)
        # Fallback for other domains or unsupported ops
        return self._domain_factory()

    def _eval_unop(self, op: UnOp, val: AbstractDomain) -> AbstractDomain:
        """Evaluate a unary operation abstractly."""
        if isinstance(val, IntervalDomain):
            if op == UnOp.NEG:
                return val.negate()
        # Fallback
        return self._domain_factory()

    def _memory_key(
        self, base: Any, offset: Any, frame: ActivationFrame
    ) -> str:
        """Compute a string key for abstract memory access."""
        base_str = base.name if isinstance(base, Reg) else str(base)
        off_str = ""
        if isinstance(offset, Reg):
            off_val = frame.read(offset)
            if isinstance(off_val, IntervalDomain) and off_val.is_const():
                off_str = f"+{int(off_val.lo)}"
            else:
                off_str = "+?"
        elif isinstance(offset, IntervalDomain):
            if offset.is_const():
                off_str = f"+{int(offset.lo)}"
            else:
                off_str = "+?"
        elif offset is not None:
            off_str = f"+{offset}"
        return f"mem[{base_str}{off_str}]"

    # ---- State management helpers --------------------------------------------

    def _join_states(
        self,
        s1: Dict[str, AbstractDomain],
        s2: Dict[str, AbstractDomain],
        widen: bool = False,
    ) -> Dict[str, AbstractDomain]:
        """Join (or widen) two abstract states pointwise."""
        result: Dict[str, AbstractDomain] = {}
        all_keys = set(s1.keys()) | set(s2.keys())
        for k in all_keys:
            v1 = s1.get(k, self._domain_factory())
            v2 = s2.get(k, self._domain_factory())
            if widen:
                result[k] = v1.widen(v2)
            else:
                result[k] = v1.join(v2)
        return result

    def _state_leq(
        self,
        s1: Dict[str, AbstractDomain],
        s2: Dict[str, AbstractDomain],
    ) -> bool:
        """Check if s1 ⊑ s2 pointwise."""
        for k in set(s1.keys()) | set(s2.keys()):
            v1 = s1.get(k)
            v2 = s2.get(k)
            if v1 is None:
                continue  # ⊥ ⊑ anything
            if v2 is None:
                return False  # something ⊑ ⊥ only if something is ⊥
            if not v1.leq(v2):
                return False
        return True

    # ---- Schema recording ----------------------------------------------------

    def _record_schema(
        self,
        instr: Instruction,
        idx: int,
        block_id: int,
        frame: ActivationFrame,
    ) -> None:
        """Record a schema entry for this instruction execution."""
        # Capture a small state snapshot (defined registers)
        state_snapshot: Dict[str, str] = {}
        for r in instr.regs_defined():
            val = frame.read(r)
            state_snapshot[r.name] = repr(val)

        # Collect events from this step
        step_events = [e for e in self._events if e.step == self._step_count]

        entry = SchemaEntry(
            block_id=block_id,
            instruction_index=idx,
            opcode=instr.opcode,
            operand_summary=", ".join(_fmt_operand(o) for o in instr.operands),
            abstract_state=state_snapshot,
            cost=instr.cost if instr.cost is not None else IntervalDomain.const(0),
            events=step_events,
        )
        self._schema.append(entry)


# ═══════════════════════════════════════════════════════════════════════════
# 5. UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════


def compile_cfg_to_abstract(
    cfg: CFG,
    func_name: str = "<unknown>",
    source_file: Optional[str] = None,
    **compiler_kwargs: Any,
) -> FunctionCode:
    """Convenience function: compile a CFG to abstract bytecode.

    Parameters
    ----------
    cfg : CFG
        The control-flow graph.
    func_name : str
        Function name.
    source_file : Optional[str]
        Source file path.
    **compiler_kwargs
        Passed to ``AbstractCompiler.__init__``.

    Returns
    -------
    FunctionCode
    """
    compiler = AbstractCompiler(**compiler_kwargs)
    return compiler.compile_cfg(cfg, func_name=func_name, source_file=source_file)


def compile_program(
    cfgs: Mapping[str, CFG],
    source_file: Optional[str] = None,
    **compiler_kwargs: Any,
) -> AbstractProgram:
    """Convenience: compile multiple CFGs into an AbstractProgram."""
    compiler = AbstractCompiler(**compiler_kwargs)
    return compiler.compile_program(cfgs, source_file=source_file)


def interpret_function(
    program: AbstractProgram,
    func_name: str,
    initial_state: Optional[Dict[str, AbstractDomain]] = None,
    **vm_kwargs: Any,
) -> SchemaListing:
    """Convenience: interpret a function and return its schema.

    Parameters
    ----------
    program : AbstractProgram
        The compiled program.
    func_name : str
        Function to interpret.
    initial_state : Optional[Dict[str, AbstractDomain]]
        Initial register bindings.
    **vm_kwargs
        Passed to ``AbstractVM.__init__``.

    Returns
    -------
    SchemaListing
    """
    vm = AbstractVM(program, **vm_kwargs)
    return vm.interpret(func_name, initial_state=initial_state)


def explore_function(
    program: AbstractProgram,
    func_name: str,
    initial_state: Optional[Dict[str, AbstractDomain]] = None,
    max_paths: int = 1000,
    **vm_kwargs: Any,
) -> SchemaListing:
    """Convenience: explore all paths through a function.

    Parameters
    ----------
    program : AbstractProgram
        The compiled program.
    func_name : str
        Function to explore.
    initial_state : Optional[Dict[str, AbstractDomain]]
        Initial register bindings.
    max_paths : int
        Path exploration limit.
    **vm_kwargs
        Passed to ``AbstractVM.__init__``.

    Returns
    -------
    SchemaListing
    """
    vm = AbstractVM(program, **vm_kwargs)
    return vm.explore(func_name, initial_state=initial_state, max_paths=max_paths)


def dump_program(program: AbstractProgram) -> str:
    """Pretty-print an entire abstract program."""
    return program.dump()


def estimate_cost(
    program: AbstractProgram,
    func_name: str,
    initial_state: Optional[Dict[str, AbstractDomain]] = None,
) -> IntervalDomain:
    """Estimate the abstract cost of executing a function.

    Returns an ``IntervalDomain`` representing [min_cost, max_cost].

    Parameters
    ----------
    program : AbstractProgram
        The compiled program.
    func_name : str
        Function to analyse.
    initial_state : Optional[Dict[str, AbstractDomain]]
        Initial state.

    Returns
    -------
    IntervalDomain
    """
    vm = AbstractVM(program)
    vm.explore(func_name, initial_state=initial_state)
    return vm.cumulative_cost


# ═══════════════════════════════════════════════════════════════════════════
# 6. BUILDER HELPERS (for manual bytecode construction)
# ═══════════════════════════════════════════════════════════════════════════


class InstructionBuilder:
    """Fluent builder for constructing abstract bytecode manually.

    Useful for tests, for ``abstract_exec.py``'s regeneration phase, and
    for the CASL compiler backend.

    Example
    -------
    >>> b = InstructionBuilder()
    >>> b.const("x", 42)
    >>> b.binop("y", "+", "x", "x")
    >>> b.ret("y")
    >>> b.instructions
    [Instruction(CONST, ...), Instruction(BINOP, ...), Instruction(RETURN, ...)]
    """

    def __init__(self) -> None:
        self.instructions: List[Instruction] = []
        self._reg_counter = itertools.count(0)

    def _r(self, name: str) -> Reg:
        return Reg(name)

    def fresh(self, prefix: str = "t") -> Reg:
        return Reg(f"{prefix}_{next(self._reg_counter)}")

    def nop(self, comment: str = "") -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.NOP, comment=comment))
        return self

    def label(self, name: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.LABEL, (name,)))
        return self

    def const(self, dst: str, value: Union[int, float, IntervalDomain]) -> InstructionBuilder:
        if isinstance(value, (int, float)):
            val = IntervalDomain.const(value)
        else:
            val = value
        self.instructions.append(Instruction(Opcode.CONST, (self._r(dst), val)))
        return self

    def copy(self, dst: str, src: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.COPY, (self._r(dst), self._r(src))))
        return self

    def phi(self, dst: str, sources: List[str]) -> InstructionBuilder:
        srcs = tuple(self._r(s) for s in sources)
        self.instructions.append(Instruction(Opcode.PHI, (self._r(dst), srcs)))
        return self

    def load(self, dst: str, base: str, offset: Union[str, int] = 0) -> InstructionBuilder:
        off = self._r(offset) if isinstance(offset, str) else IntervalDomain.const(offset)
        self.instructions.append(Instruction(Opcode.LOAD, (self._r(dst), self._r(base), off)))
        return self

    def store(self, base: str, offset: Union[str, int], src: str) -> InstructionBuilder:
        off = self._r(offset) if isinstance(offset, str) else IntervalDomain.const(offset)
        self.instructions.append(Instruction(Opcode.STORE, (self._r(base), off, self._r(src))))
        return self

    def binop(self, dst: str, op: str, lhs: str, rhs: str) -> InstructionBuilder:
        bop = _STR_TO_BINOP.get(op, BinOp.ADD)
        self.instructions.append(
            Instruction(Opcode.BINOP, (self._r(dst), bop, self._r(lhs), self._r(rhs)))
        )
        return self

    def unop(self, dst: str, op: str, src: str) -> InstructionBuilder:
        uop = _STR_TO_UNOP.get(op, UnOp.NEG)
        self.instructions.append(
            Instruction(Opcode.UNOP, (self._r(dst), uop, self._r(src)))
        )
        return self

    def compare(self, dst: str, rel: str, lhs: str, rhs: str) -> InstructionBuilder:
        cop = _STR_TO_CMPOP.get(rel, CmpOp.EQ)
        self.instructions.append(
            Instruction(Opcode.COMPARE, (self._r(dst), cop, self._r(lhs), self._r(rhs)))
        )
        return self

    def branch(self, cond: str, true_bb: int, false_bb: int) -> InstructionBuilder:
        self.instructions.append(
            Instruction(Opcode.BRANCH, (self._r(cond), BlockRef(true_bb), BlockRef(false_bb)))
        )
        return self

    def jump(self, target_bb: int) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.JUMP, (BlockRef(target_bb),)))
        return self

    def call(self, dst: str, func_name: str, args: Optional[List[str]] = None) -> InstructionBuilder:
        arg_regs = tuple(self._r(a) for a in (args or []))
        self.instructions.append(
            Instruction(Opcode.CALL, (self._r(dst), FuncRef(func_name), arg_regs))
        )
        return self

    def ret(self, src: Optional[str] = None) -> InstructionBuilder:
        ops = (self._r(src),) if src else ()
        self.instructions.append(Instruction(Opcode.RETURN, ops))
        return self

    def event(self, event_id: str, params: Optional[Tuple[Any, ...]] = None) -> InstructionBuilder:
        self.instructions.append(
            Instruction(Opcode.EVENT, (EventRef(event_id, params or ()),))
        )
        return self

    def observe(self, observer_id: str, regs: Optional[List[str]] = None) -> InstructionBuilder:
        expr_regs = tuple(self._r(r) for r in (regs or []))
        self.instructions.append(
            Instruction(Opcode.OBSERVE, (ObserverRef(observer_id, expr_regs),))
        )
        return self

    def widen(self, dst: str, src: str) -> InstructionBuilder:
        self.instructions.append(
            Instruction(Opcode.WIDEN, (self._r(dst), self._r(src)))
        )
        return self

    def narrow(self, dst: str, src: str) -> InstructionBuilder:
        self.instructions.append(
            Instruction(Opcode.NARROW, (self._r(dst), self._r(src)))
        )
        return self

    def cost(self, amount: Union[int, IntervalDomain]) -> InstructionBuilder:
        c = amount if isinstance(amount, IntervalDomain) else IntervalDomain.const(amount)
        self.instructions.append(Instruction(Opcode.COST, (CostLiteral(c),)))
        return self

    def assert_(self, cond: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.ASSERT, (self._r(cond),)))
        return self

    def havoc(self, dst: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.HAVOC, (self._r(dst),)))
        return self

    def enter_scope(self, scope_id: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.ENTER_SCOPE, (scope_id,)))
        return self

    def exit_scope(self, scope_id: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.EXIT_SCOPE, (scope_id,)))
        return self

    def alloc(self, dst: str, size: Union[str, int]) -> InstructionBuilder:
        sz = self._r(size) if isinstance(size, str) else IntervalDomain.const(size)
        self.instructions.append(Instruction(Opcode.ALLOC, (self._r(dst), sz)))
        return self

    def free(self, src: str) -> InstructionBuilder:
        self.instructions.append(Instruction(Opcode.FREE, (self._r(src),)))
        return self

    def cast(self, dst: str, src: str, target_type: str) -> InstructionBuilder:
        self.instructions.append(
            Instruction(Opcode.CAST, (self._r(dst), self._r(src), target_type))
        )
        return self

    def build_block(self, block_id: int, **kwargs: Any) -> CodeBlock:
        """Build a ``CodeBlock`` from accumulated instructions and reset."""
        cb = CodeBlock(block_id=block_id, instructions=list(self.instructions), **kwargs)
        self.instructions.clear()
        return cb

    def build_function(
        self,
        name: str,
        blocks: Dict[int, CodeBlock],
        entry_id: int = 0,
        exit_ids: Optional[List[int]] = None,
        params: Optional[List[str]] = None,
    ) -> FunctionCode:
        """Build a ``FunctionCode`` from pre-built blocks."""
        fc = FunctionCode(
            name=name,
            func_id=0,
            blocks=blocks,
            entry_id=entry_id,
            exit_ids=exit_ids or [],
            params=[Reg(p) for p in (params or [])],
        )
        # Wire up successors/predecessors
        for bid, blk in blocks.items():
            for instr in blk.instructions:
                if instr.opcode == Opcode.JUMP and instr.operands:
                    target = instr.operands[0]
                    if isinstance(target, BlockRef) and target.block_id not in blk.successors:
                        blk.successors.append(target.block_id)
                        if target.block_id in blocks:
                            blocks[target.block_id].predecessors.append(bid)
                elif instr.opcode == Opcode.BRANCH and len(instr.operands) >= 3:
                    for t in instr.operands[1:3]:
                        if isinstance(t, BlockRef) and t.block_id not in blk.successors:
                            blk.successors.append(t.block_id)
                            if t.block_id in blocks:
                                blocks[t.block_id].predecessors.append(bid)
        all_regs: Set[Reg] = set()
        for blk in blocks.values():
            for instr in blk.instructions:
                all_regs |= instr.regs_defined() | instr.regs_used()
        fc.locals_ = sorted(all_regs, key=lambda r: r.name)
        return fc
