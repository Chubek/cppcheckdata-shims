

# Vade Mecum: The `cppcheckdata-shims` Library

## A Comprehensive Reference Guide

---

## Table of Contents

1. [Preface & Philosophy](#1-preface--philosophy)
2. [Architecture Overview](#2-architecture-overview)
3. [Module Reference](#3-module-reference)
   - 3.1 `cppcheckdata` (Upstream Foundation)
   - 3.2 `ctrlflow_graph.py` — CFG Builder
   - 3.3 `callgraph.py` — Call Graph Construction
   - 3.4 `dataflow_analyses.py` — Classical Dataflow
   - 3.5 `ctrlflow_analyses.py` — Control-Flow-Based Analyses
   - 3.6 `shims_bridge.py` — Unified Facade
4. [Integration with Cppcheck Addons](#4-integration-with-cppcheck-addons)
5. [Theoretical Foundations](#5-theoretical-foundations)
6. [Cookbook: End-to-End Examples](#6-cookbook-end-to-end-examples)
7. [Appendices](#7-appendices)

---

## 1. Preface & Philosophy

### 1.1 What is `cppcheckdata-shims`?

`cppcheckdata-shims` is a **Python library layer** that sits atop the raw XML dump data produced by [Cppcheck](https://cppcheck.sourceforge.io/) and consumed via the upstream `cppcheckdata.py` module. While Cppcheck's native dump gives you token lists, scopes, variables, functions, and ValueFlow data, it does **not** directly provide higher-level program analysis artifacts such as:

- Control Flow Graphs (CFGs)
- Call Graphs
- Dominator / Post-Dominator Trees
- Natural Loop Detection
- Reaching Definitions, Live Variables, Taint Propagation
- Loop Invariant Analysis, Induction Variable Detection
- Path-Sensitive Feasibility Checking

The shims library **constructs all of these** from the raw dump, making them available to addon authors through a clean, lazy-evaluated, cache-friendly API.

### 1.2 Design Principles

| Principle | Rationale |
|---|---|
| **Zero external dependencies** | The library uses only Python 3 stdlib plus `cppcheckdata.py` |
| **Lazy computation** | Analyses are computed only when first requested, then cached |
| **Per-configuration isolation** | Cppcheck dumps may contain multiple `#ifdef` configurations; each is analyzed independently |
| **Theoretical rigor** | Every analysis is grounded in published algorithms (Aho–Ullman–Sethi, Cooper–Harvey–Kennedy, Kildall, etc.) |
| **Addon-friendly** | Output is formatted for Cppcheck's `--cli` JSON protocol or plain-text stderr |

### 1.3 Relationship to CASL

The **Cppcheck Addon Specification Language (CASL)** is a declarative DSL whose compiler emits Python code that calls into `cppcheckdata-shims`. A CASL specification such as:

checker NullDeref {
  pattern: *$ptr
  where: $ptr is_null
  severity: error
  message: "Null pointer dereference of {ptr}"
}


compiles down to a Python addon that:

1. Parses the Cppcheck dump via `cppcheckdata.parsedump()`
2. Obtains analysis results via `ShimsBridge`
3. Pattern-matches tokens and emits diagnostics

You can use the shims library **without CASL** — it is a standalone analysis framework.

---

## 2. Architecture Overview

### 2.1 Layer Diagram

┌─────────────────────────────────────────────────────────┐
│                  User Addon / CASL-generated code        │
├─────────────────────────────────────────────────────────┤
│                    shims_bridge.py                        │
│            (Facade — lazy init, caching, routing)        │
├──────────────┬──────────────────┬───────────────────────┤
│ ctrlflow_    │  dataflow_       │  callgraph.py          │
│ analyses.py  │  analyses.py     │  (Call graph builder)  │
├──────────────┴──────────────────┴───────────────────────┤
│                  ctrlflow_graph.py                        │
│            (CFG construction from token/scope data)      │
├─────────────────────────────────────────────────────────┤
│                    cppcheckdata.py                        │
│         (Upstream: XML dump parser, Token/Scope/etc.)    │
├─────────────────────────────────────────────────────────┤
│              Cppcheck XML Dump (.dump file)               │
└─────────────────────────────────────────────────────────┘


### 2.2 Data Flow Through the Stack

source.c  ──cppcheck --dump──►  source.c.dump (XML)
                                      │
                              cppcheckdata.parsedump()
                                      │
                                      ▼
                              CppcheckData object
                              ├── .configurations[]
                              │   ├── .tokenlist[]     ← Token objects
                              │   ├── .scopes[]        ← Scope objects
                              │   ├── .functions[]     ← Function objects
                              │   ├── .variables[]     ← Variable objects
                              │   └── .valueflow[]     ← ValueFlow objects
                              └── .directives[]
                                      │
                              ShimsBridge(cfg)
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                   ▼
               CFG Builder      Call Graph         Dataflow Analyses
               (BasicBlocks,    (CallSite nodes,   (ReachingDefs,
                edges, entry,    edges, callee      LiveVars, Taint,
                exit nodes)      resolution)        AvailExprs, etc.)
                    │                                    │
                    ▼                                    │
            Control-Flow Analyses                        │
            (Dominators, Loops,                          │
             Path Sensitivity,                           │
             Loop Invariants)                            │
                    │                                    │
                    └────────────────┬───────────────────┘
                                     ▼
                              Addon consumes results,
                              emits diagnostics


### 2.3 File Layout

cppcheckdata_shims/
├── __init__.py               # Package exports
├── ctrlflow_graph.py         # CFG builder
├── callgraph.py              # Call graph construction
├── dataflow_analyses.py      # Classical iterative dataflow
├── ctrlflow_analyses.py      # Dominance, loops, paths
├── shims_bridge.py           # Unified facade
└── __main__.py               # CLI entry point (for CASL)


---

## 3. Module Reference

---

### 3.1 `cppcheckdata.py` — The Upstream Foundation

This is **not** part of the shims package, but understanding it is essential since every shim builds upon it.

#### 3.1.1 Core Classes

**`CppcheckData`** — The top-level container returned by `parsedump()`.

| Attribute | Type | Description |
|---|---|---|
| `configurations` | `list[Configuration]` | One per `#ifdef` combination |
| `directives` | `list[Directive]` | Preprocessor directives |
| `platform` | `Platform` | Target platform info (sizeof, etc.) |

**`Configuration`** — One complete view of the program under a specific preprocessor configuration.

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Configuration identifier (e.g., `""`, `"DEBUG"`) |
| `tokenlist` | `list[Token]` | All tokens in order |
| `scopes` | `list[Scope]` | All scopes (global, function, class, etc.) |
| `functions` | `list[Function]` | All function definitions |
| `variables` | `list[Variable]` | All variable declarations |
| `valueflow` | `list[Value]` | All ValueFlow analysis results |
| `standards` | `Standards` | Language standard information |

**`Token`** — The fundamental unit. Every token has:

| Key Attribute | Description |
|---|---|
| `str` | The textual string of the token |
| `Id` | Unique XML identifier |
| `next` / `previous` | Doubly-linked list traversal |
| `scope` | The `Scope` this token belongs to |
| `variable` | If this token names a variable, the `Variable` object |
| `function` | If this token calls a function, the `Function` object |
| `values` | List of `Value` objects from ValueFlow |
| `astParent`, `astOperand1`, `astOperand2` | AST tree links |
| `valueType` | `ValueType` — promoted type information |
| `isName`, `isNumber`, `isOp`, etc. | Boolean type classifiers |
| `varId` / `exprId` | Numeric identifiers for variables/expressions |
| `file`, `linenr`, `column` | Source location |

**`Scope`** — Represents lexical/syntactic scopes:

| Attribute | Description |
|---|---|
| `type` | `"Global"`, `"Function"`, `"If"`, `"Else"`, `"While"`, `"For"`, `"Do"`, `"Switch"`, `"Class"`, `"Struct"`, `"Namespace"`, `"Enum"`, `"Try"`, `"Catch"`, `"Lambda"` |
| `className` | For named scopes |
| `bodyStart` / `bodyEnd` | Opening and closing `{`/`}` tokens |
| `nestedIn` | Parent scope |
| `nestedList` | Child scopes |
| `function` | The `Function` object if this is a function scope |

**`Variable`** — Variable declarations:

| Attribute | Description |
|---|---|
| `nameToken` | Token where the variable name appears |
| `typeStartToken` / `typeEndToken` | Token range for the type |
| `isArgument`, `isLocal`, `isGlobal`, `isStatic`, `isConst` | Classification booleans |
| `isPointer`, `isArray`, `isReference` | Type modifiers |

**`Function`** — Function definitions:

| Attribute | Description |
|---|---|
| `name` | Function name |
| `tokenDef` | Token at the function definition |
| `token` | Token at the function declaration |
| `argument` | Dict mapping position → `Variable` |
| `isVirtual`, `isStatic`, `isConst` | Modifiers |

**`Value`** — ValueFlow analysis result attached to tokens:

| Attribute | Description |
|---|---|
| `intvalue` | Integer value (if applicable) |
| `floatvalue` | Float value (if applicable) |
| `tokvalue` | Token-valued (for pointer aliasing) |
| `valueKind` | `"known"` or `"possible"` |
| `condition` | Token of the condition that leads to this value |
| `isImpossible()` | Whether this is a proven-impossible value |

#### 3.1.2 Parsing a Dump

```python
import cppcheckdata

# Parse the dump file
data = cppcheckdata.parsedump("source.c.dump")

# Iterate configurations
for cfg in data.configurations:
    print(f"Configuration: {cfg.name}")
    
    # Walk all tokens
    for token in cfg.tokenlist:
        if token.isName and token.variable:
            var = token.variable
            print(f"  Line {token.linenr}: variable '{token.str}' "
                  f"(pointer={var.isPointer}, const={var.isConst})")
    
    # Check ValueFlow
    for token in cfg.tokenlist:
        if token.values:
            for val in token.values:
                if val.intvalue is not None:
                    print(f"  Line {token.linenr}: '{token.str}' "
                          f"may be {val.intvalue} ({val.valueKind})")
```

#### 3.1.3 The `--cli` Protocol

When an addon is invoked with `--cli`, diagnostics must be emitted as JSON lines on stdout:

```python
import json, sys

def report_error(token, severity, error_id, message, addon_name):
    msg = {
        'file': token.file,
        'linenr': token.linenr,
        'column': token.column,
        'severity': severity,       # error, warning, style, performance, portability, information
        'message': message,
        'addon': addon_name,
        'errorId': error_id,
        'extra': ''
    }
    sys.stdout.write(json.dumps(msg) + '\n')
```

---

### 3.2 `ctrlflow_graph.py` — CFG Builder

#### 3.2.1 Purpose

Constructs **intra-procedural Control Flow Graphs** from the token/scope data in a `cppcheckdata.Configuration`. Each function scope yields one CFG with an `ENTRY` node, an `EXIT` node, and basic blocks connected by directed edges.

#### 3.2.2 Core Data Structures

```python
class BasicBlock:
    """A maximal sequence of straight-line tokens with no internal branches."""
    
    id: int                     # Unique block identifier
    tokens: list                # List of cppcheckdata.Token objects
    successors: list            # List of BasicBlock (outgoing edges)
    predecessors: list          # List of BasicBlock (incoming edges)
    scope: object               # The Scope this block is primarily in
    is_entry: bool              # True for synthetic ENTRY node
    is_exit: bool               # True for synthetic EXIT node
    
    @property
    def first_token(self) -> Token:
        """First token in the block (None for synthetic nodes)."""
        ...
    
    @property
    def last_token(self) -> Token:
        """Last token / branch point."""
        ...
    
    @property
    def label(self) -> str:
        """Human-readable label for DOT output."""
        ...


class CFG:
    """Control Flow Graph for a single function."""
    
    entry: BasicBlock           # Unique entry node
    exit: BasicBlock            # Unique exit node
    blocks: list                # All BasicBlock instances
    function: Function          # The cppcheckdata.Function this CFG represents
    
    def iter_blocks(self) -> Iterator[BasicBlock]:
        """Iterate all blocks in reverse postorder."""
        ...
    
    def reverse_postorder(self) -> list:
        """Return blocks in reverse postorder (for forward analyses)."""
        ...
    
    def postorder(self) -> list:
        """Return blocks in postorder (for backward analyses)."""
        ...
    
    def to_dot(self) -> str:
        """Export to Graphviz DOT format."""
        ...
```

#### 3.2.3 CFG Construction Algorithm

The builder operates as follows:

1. **Identify function scopes**: For each `Scope` with `type == "Function"`, extract the token range `[bodyStart, bodyEnd]`.

2. **Leader identification** (classic algorithm from Aho, Sethi, Ullman §8.4):
   - The first token after `bodyStart` is a leader.
   - The target of any branch (`if`, `else`, `while`, `for`, `do`, `switch`/`case`, `goto`) is a leader.
   - The token immediately following a branch or jump is a leader.

3. **Block formation**: Group consecutive tokens between leaders into `BasicBlock` objects.

4. **Edge construction**:
   - **Fall-through**: If a block does not end with an unconditional jump, add an edge to the next sequential block.
   - **Conditional**: For `if`/`while`/`for`, add edges to both the true-branch block and the false-branch (fall-through or else) block.
   - **Loop back-edges**: For `while`/`for`/`do`, add an edge from the loop-body end back to the condition block.
   - **Break/continue**: Resolve to the appropriate loop exit or header.
   - **Return**: Add an edge to the `EXIT` node.
   - **Switch/case**: Add edges from the switch expression to each case label.

5. **Synthetic nodes**: Add `ENTRY` (no tokens, successors = [first real block]) and `EXIT` (no tokens, predecessors = [all return blocks]).

#### 3.2.4 Usage

```python
from cppcheckdata_shims.ctrlflow_graph import build_cfg_for_function, build_all_cfgs

# Build CFG for a specific function scope
cfg = build_cfg_for_function(function_scope)

# Build CFGs for all functions in a configuration
cfgs = build_all_cfgs(configuration)  # Returns dict: Function -> CFG

# Visualize
print(cfg.to_dot())

# Traverse in analysis-friendly order
for block in cfg.reverse_postorder():
    print(f"Block {block.id}: {len(block.tokens)} tokens, "
          f"{len(block.successors)} successors")
```

#### 3.2.5 Handling C/C++ Constructs

| Construct | CFG Treatment |
|---|---|
| `if-else` | Condition block → true block + false block; both → join block |
| `while` | Header (condition) ← back-edge from body end; header → exit |
| `for` | Init block → header → body → increment → header; header → exit |
| `do-while` | Body → condition → body (back-edge) or exit |
| `switch/case` | Switch block → each case block; fall-through between cases unless `break` |
| `break` | Edge to immediately enclosing loop/switch exit |
| `continue` | Edge to enclosing loop header (for `for`: increment block) |
| `return` | Edge to `EXIT` |
| `goto` | Edge to labeled block |
| `try/catch` | Exceptional edges from try body to each catch handler |
| Short-circuit `&&`/`||` | Conditional edges reflecting short-circuit evaluation |

#### 3.2.6 Theoretical Note: Basic Blocks and Leaders

The partitioning into basic blocks is the cornerstone of all subsequent analysis. A **basic block** $B$ is a maximal sequence of instructions such that:

- The only entry point is the first instruction (the **leader**)
- The only exit point is the last instruction
- If any instruction in $B$ executes, all instructions in $B$ execute (assuming no exceptions)

This ensures that dataflow facts need only be tracked at block boundaries, reducing the problem from per-token to per-block granularity. For a function with $n$ tokens and $b$ basic blocks, we have $b \leq n$ and typically $b \ll n$.

---

### 3.3 `callgraph.py` — Call Graph Construction

#### 3.3.1 Purpose

Builds the **inter-procedural call graph** from the function and token data, linking call sites to their target functions.

#### 3.3.2 Data Structures

```python
class CallSite:
    """Represents a specific function call in the source."""
    
    token: Token                # The token where the call occurs
    caller: Function            # The function containing this call
    callee: Function            # The function being called (None if unresolved)
    arguments: list             # List of argument token trees
    linenr: int                 # Source line number
    file: str                   # Source file


class CallGraph:
    """Inter-procedural call graph."""
    
    nodes: dict                 # Function -> set of CallSite (outgoing calls)
    reverse: dict               # Function -> set of CallSite (incoming calls)
    roots: set                  # Functions with no callers (entry points)
    leaves: set                 # Functions with no callees (leaf functions)
    
    def callers_of(self, func: Function) -> set:
        """All functions that call `func`."""
        ...
    
    def callees_of(self, func: Function) -> set:
        """All functions called by `func`."""
        ...
    
    def call_sites_in(self, func: Function) -> list:
        """All CallSite objects within `func`."""
        ...
    
    def is_recursive(self, func: Function) -> bool:
        """True if `func` is (directly or transitively) recursive."""
        ...
    
    def topological_order(self) -> list:
        """Return functions in a valid topological order (bottom-up)."""
        ...
    
    def to_dot(self) -> str:
        """Export to Graphviz DOT format."""
        ...
```

#### 3.3.3 Construction Algorithm

1. **Direct calls**: For every token $t$ where `t.function is not None`, record a `CallSite` with `caller = scope_of(t).function` and `callee = t.function`.

2. **Indirect calls via function pointers**: If a token is a dereference `(*fp)(...)` where `fp.variable` has a function-pointer type, attempt to resolve via ValueFlow. If `fp` has `tokvalue` pointing to a function definition, link accordingly.

3. **Virtual calls**: For C++ virtual dispatch, mark the call site as potentially targeting any override. This is an overapproximation (Class Hierarchy Analysis).

4. **Unresolved calls**: Calls to external or dynamically-linked functions get `callee = None`.

#### 3.3.4 Usage

```python
from cppcheckdata_shims.callgraph import build_call_graph

cg = build_call_graph(configuration)

# Find all functions called by 'main'
for func in configuration.functions:
    if func.name == 'main':
        for callee_func in cg.callees_of(func):
            print(f"main calls {callee_func.name}")

# Bottom-up traversal (for summary-based interprocedural analysis)
for func in cg.topological_order():
    print(f"Analyzing {func.name}")
```

#### 3.3.5 Theoretical Note

The call graph is the backbone of **interprocedural analysis**. For a call graph $G = (F, C)$ where $F$ is the set of functions and $C \subseteq F \times F$ is the set of call edges:

- **Context-insensitive** analysis merges all calling contexts: one summary per function.
- **Context-sensitive** analysis (call-string or functional approach) distinguishes different calling contexts. The shims library provides the call graph; context sensitivity is layered on top by `ctrlflow_analyses.py`.

As Møller & Schwartzbach note: *"We take a constraint-based approach to static analysis where suitable constraint systems conceptually divide the analysis task into a front-end that generates constraints from program code and a back-end that solves the constraints to produce the analysis results."*

---

### 3.4 `dataflow_analyses.py` — Classical Dataflow

#### 3.4.1 Purpose

Implements the classical **iterative dataflow analysis framework** (Kildall 1973, Kam & Ullman 1977) over the CFG, providing a battery of standard analyses.

#### 3.4.2 Lattice Framework

All analyses are structured as instances of the general dataflow equation system:

$$\text{OUT}[B] = f_B(\text{IN}[B])$$
$$\text{IN}[B] = \bigsqcup_{P \in \text{pred}(B)} \text{OUT}[P] \quad \text{(forward analysis)}$$

or dually for backward analysis:

$$\text{IN}[B] = f_B(\text{OUT}[B])$$
$$\text{OUT}[B] = \bigsqcup_{S \in \text{succ}(B)} \text{IN}[S] \quad \text{(backward analysis)}$$

where $\sqcup$ is the **join** (or **meet**) operator of the lattice, and $f_B$ is the **transfer function** for block $B$.

The framework iterates until a **fixed point** is reached. Convergence is guaranteed when:
1. The lattice has **finite height** (or widening is applied)
2. Transfer functions are **monotone**: $x \sqsubseteq y \implies f(x) \sqsubseteq f(y)$

#### 3.4.3 Base Classes

```python
from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Set, Dict

T = TypeVar('T')

class DataflowAnalysis(ABC, Generic[T]):
    """Abstract base for all dataflow analyses."""
    
    cfg: CFG
    direction: str              # 'forward' or 'backward'
    
    @abstractmethod
    def init_entry(self) -> T:
        """Initial value for ENTRY (forward) or EXIT (backward)."""
        ...
    
    @abstractmethod
    def init_interior(self) -> T:
        """Initial value for all non-entry/exit blocks."""
        ...
    
    @abstractmethod
    def transfer(self, block: BasicBlock, in_val: T) -> T:
        """Transfer function: compute output from input for a block."""
        ...
    
    @abstractmethod
    def join(self, values: list) -> T:
        """Join (merge) multiple dataflow values."""
        ...
    
    def solve(self) -> Dict[int, tuple]:
        """
        Run iterative fixed-point algorithm.
        Returns {block_id: (IN_value, OUT_value)}.
        """
        ...


class ForwardAnalysis(DataflowAnalysis[T]):
    """Mixin for forward analyses."""
    direction = 'forward'


class BackwardAnalysis(DataflowAnalysis[T]):
    """Mixin for backward analyses."""
    direction = 'backward'
```

#### 3.4.4 Provided Analyses

##### 3.4.4.1 Reaching Definitions

**What**: For each point in the program, which definitions (assignments) may reach that point without being killed (overwritten)?

**Lattice**: $2^{\text{Defs}}$ with $\sqcup = \cup$ (union). Direction: forward.

**Transfer function**:
$$\text{OUT}[B] = \text{GEN}[B] \cup (\text{IN}[B] - \text{KILL}[B])$$

where $\text{GEN}[B]$ is the set of definitions in $B$ that reach the end, and $\text{KILL}[B]$ is the set of definitions of the same variables that are overridden.

```python
class ReachingDefinitions(ForwardAnalysis[frozenset]):
    """
    Computes which variable definitions may reach each program point.
    
    Each element in the set is a (var_id, token_id) pair representing
    'variable var_id was defined at token token_id'.
    """
    
    def __init__(self, cfg: CFG, configuration):
        self.cfg = cfg
        self.all_defs = self._collect_definitions(configuration)
    
    def init_entry(self) -> frozenset:
        return frozenset()   # No definitions reach the entry
    
    def init_interior(self) -> frozenset:
        return frozenset()   # Start empty (may-analysis)
    
    def transfer(self, block, in_val):
        gen, kill = self._compute_gen_kill(block)
        return gen | (in_val - kill)
    
    def join(self, values):
        return frozenset().union(*values) if values else frozenset()
```

**Usage**:

```python
from cppcheckdata_shims.dataflow_analyses import ReachingDefinitions

rd = ReachingDefinitions(cfg, configuration)
results = rd.solve()

# Check which definitions reach block 5
in_val, out_val = results[5]
for var_id, def_token_id in in_val:
    print(f"Definition of var {var_id} at token {def_token_id} reaches block 5")
```

##### 3.4.4.2 Live Variables

**What**: A variable is **live** at a point if there exists some path from that point to a use of the variable without an intervening definition.

**Lattice**: $2^{\text{Vars}}$ with $\sqcup = \cup$. Direction: **backward**.

**Transfer function**:
$$\text{IN}[B] = \text{USE}[B] \cup (\text{OUT}[B] - \text{DEF}[B])$$

```python
class LiveVariables(BackwardAnalysis[frozenset]):
    """
    Computes which variables are live (will be used before redefinition)
    at each program point.
    """
    
    def init_entry(self) -> frozenset:
        return frozenset()   # Nothing is live after EXIT
    
    def init_interior(self) -> frozenset:
        return frozenset()
    
    def transfer(self, block, out_val):
        use, deff = self._compute_use_def(block)
        return use | (out_val - deff)
    
    def join(self, values):
        return frozenset().union(*values) if values else frozenset()
```

**Application**: Dead code detection — if a definition $d$ of variable $v$ occurs at a point where $v$ is not live, the definition is dead (its value is never used).

```python
from cppcheckdata_shims.dataflow_analyses import LiveVariables

lv = LiveVariables(cfg, configuration)
results = lv.solve()

# Find dead assignments
for block in cfg.iter_blocks():
    _, out_val = results[block.id]
    for tok in reversed(block.tokens):
        if tok.isAssignmentOp and tok.astOperand1 and tok.astOperand1.varId:
            if tok.astOperand1.varId not in out_val:
                print(f"Dead assignment at line {tok.linenr}: "
                      f"'{tok.astOperand1.str}' is assigned but never used")
```

##### 3.4.4.3 Available Expressions

**What**: An expression $e$ is **available** at a point $p$ if on every path from ENTRY to $p$, $e$ has been computed and none of its operand variables have been redefined since.

**Lattice**: $2^{\text{Exprs}}$ with $\sqcup = \cap$ (intersection). Direction: forward. This is a **must-analysis**.

**Transfer function**:
$$\text{OUT}[B] = \text{EGEN}[B] \cup (\text{IN}[B] - \text{EKILL}[B])$$

```python
class AvailableExpressions(ForwardAnalysis[frozenset]):
    """
    Computes which expressions are available (already computed on all paths)
    at each program point. Useful for common subexpression elimination.
    """
    
    def init_entry(self) -> frozenset:
        return frozenset()
    
    def init_interior(self) -> frozenset:
        return self.all_expressions   # Start with all (must-analysis uses intersection)
    
    def transfer(self, block, in_val):
        egen, ekill = self._compute_egen_ekill(block)
        return egen | (in_val - ekill)
    
    def join(self, values):
        if not values:
            return frozenset()
        result = values[0]
        for v in values[1:]:
            result = result & v   # Intersection for must-analysis
        return result
```

##### 3.4.4.4 Very Busy Expressions

**What**: An expression $e$ is **very busy** at point $p$ if on every path from $p$, $e$ is evaluated before any of its operand variables are defined.

**Lattice**: $2^{\text{Exprs}}$ with $\sqcup = \cap$. Direction: **backward**. A must-analysis.

**Application**: Code hoisting — if $e$ is very busy at the entry of a block, it can be safely computed there.

##### 3.4.4.5 Taint Analysis

**What**: Track which variables may contain **tainted** (user-controlled, unvalidated) data.

**Lattice**: $2^{\text{Vars}}$ with $\sqcup = \cup$. Direction: forward.

**Transfer function**: Models taint sources (e.g., `scanf`, `recv`, `getenv`), taint propagation through assignments and expressions, and taint sinks (e.g., `system`, `exec`, format strings).

```python
class TaintAnalysis(ForwardAnalysis[frozenset]):
    """
    Tracks flow of tainted (user-controlled) data through the program.
    
    Taint sources: configurable list of functions (default: scanf, gets, recv, etc.)
    Taint sinks: configurable list (default: system, exec, SQL functions, etc.)
    """
    
    def __init__(self, cfg, configuration, 
                 sources=None, sinks=None, sanitizers=None):
        self.cfg = cfg
        self.sources = sources or DEFAULT_TAINT_SOURCES
        self.sinks = sinks or DEFAULT_TAINT_SINKS
        self.sanitizers = sanitizers or DEFAULT_SANITIZERS
    
    def transfer(self, block, in_val):
        tainted = set(in_val)
        for token in block.tokens:
            # Source: function call returns tainted data
            if self._is_source_call(token):
                if token.astParent and token.astParent.isAssignmentOp:
                    lhs = token.astParent.astOperand1
                    if lhs and lhs.varId:
                        tainted.add(lhs.varId)
            # Propagation: x = tainted_var propagates taint
            elif token.isAssignmentOp:
                rhs_vars = self._collect_vars(token.astOperand2)
                lhs = token.astOperand1
                if lhs and lhs.varId:
                    if any(v in tainted for v in rhs_vars):
                        tainted.add(lhs.varId)
                    else:
                        tainted.discard(lhs.varId)
            # Sanitizer: removes taint
            if self._is_sanitizer_call(token):
                sanitized = self._get_sanitized_var(token)
                if sanitized:
                    tainted.discard(sanitized)
        return frozenset(tainted)
```

**Detecting taint-sink violations**:

```python
taint = TaintAnalysis(cfg, configuration)
results = taint.solve()

for block in cfg.iter_blocks():
    in_val, _ = results[block.id]
    for tok in block.tokens:
        if taint._is_sink_call(tok):
            arg_vars = taint._collect_arg_vars(tok)
            for v in arg_vars:
                if v in in_val:
                    print(f"TAINT VIOLATION at line {tok.linenr}: "
                          f"tainted data reaches sink '{tok.str}'")
```

##### 3.4.4.6 Constant Propagation

**What**: Determine which variables have **constant values** at each point.

**Lattice**: $\text{Var} \to (\top, c_1, c_2, \ldots, \bot)$ — for each variable, $\top$ means "not yet seen", each $c_i$ is a specific constant, and $\bot$ means "not constant" (multiple values possible).

$$\text{join}(a, b) = \begin{cases} a & \text{if } b = \top \\ b & \text{if } a = \top \\ a & \text{if } a = b \\ \bot & \text{otherwise} \end{cases}$$

Direction: forward.

```python
class ConstantPropagation(ForwardAnalysis[dict]):
    """
    Determines which variables hold constant values at each point.
    Lattice per variable: TOP -> concrete value -> BOTTOM.
    """
    TOP = object()
    BOTTOM = object()
    
    def join(self, values):
        if not values:
            return {}
        result = dict(values[0])
        for other in values[1:]:
            all_vars = set(result) | set(other)
            for v in all_vars:
                a = result.get(v, self.TOP)
                b = other.get(v, self.TOP)
                result[v] = self._lattice_join(a, b)
        return result
```

##### 3.4.4.7 Interval Analysis (with Widening)

**What**: For each variable at each point, compute an **interval** $[l, u]$ bounding its possible values.

**Lattice**: $\text{Var} \to \text{Interval}$ where $\text{Interval} = \{[l, u] \mid l \in \mathbb{Z} \cup \{-\infty\}, u \in \mathbb{Z} \cup \{+\infty\}\}$.

**Widening operator** $\nabla$ (to ensure convergence for loops):

$$[l_1, u_1] \nabla [l_2, u_2] = \left[\begin{cases} l_1 & \text{if } l_1 \leq l_2 \\ -\infty & \text{otherwise} \end{cases}, \begin{cases} u_1 & \text{if } u_1 \geq u_2 \\ +\infty & \text{otherwise} \end{cases}\right]$$

**Narrowing** $\Delta$ refines after fixed point:

$$[l_1, u_1] \Delta [l_2, u_2] = \left[\begin{cases} l_2 & \text{if } l_1 = -\infty \\ l_1 & \text{otherwise} \end{cases}, \begin{cases} u_2 & \text{if } u_1 = +\infty \\ u_1 & \text{otherwise} \end{cases}\right]$$

This is critical for analyzing loops where a naive iteration would not terminate.

#### 3.4.5 The Fixed-Point Solver

```python
def solve(self) -> Dict[int, tuple]:
    """Iterative worklist algorithm for dataflow fixed point."""
    # Initialize
    IN = {}
    OUT = {}
    
    if self.direction == 'forward':
        order = self.cfg.reverse_postorder()
        entry_block = self.cfg.entry
        IN[entry_block.id] = self.init_entry()
        for b in self.cfg.blocks:
            if b != entry_block:
                IN[b.id] = self.init_interior()
            OUT[b.id] = self.transfer(b, IN[b.id])
    else:
        order = self.cfg.postorder()
        exit_block = self.cfg.exit
        OUT[exit_block.id] = self.init_entry()
        for b in self.cfg.blocks:
            if b != exit_block:
                OUT[b.id] = self.init_interior()
            IN[b.id] = self.transfer(b, OUT[b.id])
    
    # Worklist iteration
    worklist = list(order)
    while worklist:
        b = worklist.pop(0)
        
        if self.direction == 'forward':
            new_in = self.join([OUT[p.id] for p in b.predecessors])
            IN[b.id] = new_in
            new_out = self.transfer(b, new_in)
            if new_out != OUT[b.id]:
                OUT[b.id] = new_out
                for s in b.successors:
                    if s not in worklist:
                        worklist.append(s)
        else:
            new_out = self.join([IN[s.id] for s in b.successors])
            OUT[b.id] = new_out
            new_in = self.transfer(b, new_out)
            if new_in != IN[b.id]:
                IN[b.id] = new_in
                for p in b.predecessors:
                    if p not in worklist:
                        worklist.append(p)
    
    return {b.id: (IN[b.id], OUT[b.id]) for b in self.cfg.blocks}
```

**Complexity**: For a lattice of height $h$ and a CFG with $n$ blocks and $e$ edges, the worklist algorithm runs in $O(n \cdot h)$ iterations in the worst case (each block can change at most $h$ times). Each iteration visits edges, giving $O(e \cdot h)$ total work (ignoring transfer function cost).

---

### 3.5 `ctrlflow_analyses.py` — Control-Flow-Based Analyses

#### 3.5.1 Purpose

This module provides analyses that exploit the **structure** of the control flow graph — dominance relations, natural loops, path enumeration — rather than the dataflow lattice framework. It builds upon `ctrlflow_graph.py` and incorporates `ValueFlow` data from Cppcheck.

#### 3.5.2 Dominator Tree

##### Theory

A block $d$ **dominates** block $n$ (written $d \text{ dom } n$) in a CFG if every path from `ENTRY` to $n$ must pass through $d$. The **immediate dominator** $\text{idom}(n)$ is the closest strict dominator. The dominator tree has `ENTRY` as root, with edges from $\text{idom}(n)$ to $n$.

The dominance relation satisfies:

1. **Reflexivity**: $n \text{ dom } n$
2. **Transitivity**: $a \text{ dom } b \land b \text{ dom } c \implies a \text{ dom } c$
3. **Antisymmetry**: $a \text{ dom } b \land b \text{ dom } a \implies a = b$

##### Implementation: Cooper–Harvey–Kennedy Algorithm

The classic Lengauer–Tarjan algorithm runs in $O(n \cdot \alpha(n))$ but is complex to implement. We use the simpler iterative algorithm from Cooper, Harvey, and Kennedy (2001), which runs in $O(n^2)$ worst case but is often faster in practice due to simplicity and cache friendliness.

```python
class DominatorTree:
    """
    Computes the dominator tree using the Cooper-Harvey-Kennedy
    iterative algorithm.
    
    Reference: Cooper, Harvey, Kennedy. "A Simple, Fast Dominance Algorithm."
    Software Practice & Experience, 2001.
    """
    
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        self._idom = {}      # block_id -> immediate dominator block_id
        self._dom_tree = {}   # block_id -> list of children block_ids
        self._compute()
    
    def _compute(self):
        """Iterative dominance computation."""
        rpo = self.cfg.reverse_postorder()
        rpo_number = {b.id: i for i, b in enumerate(rpo)}
        
        entry = self.cfg.entry
        self._idom[entry.id] = entry.id
        
        changed = True
        while changed:
            changed = False
            for b in rpo:
                if b == entry:
                    continue
                # Find first processed predecessor
                new_idom = None
                for p in b.predecessors:
                    if p.id in self._idom:
                        if new_idom is None:
                            new_idom = p.id
                        else:
                            new_idom = self._intersect(
                                new_idom, p.id, rpo_number)
                if new_idom != self._idom.get(b.id):
                    self._idom[b.id] = new_idom
                    changed = True
    
    def _intersect(self, b1, b2, rpo_number):
        """Find common dominator using RPO numbers."""
        while b1 != b2:
            while rpo_number.get(b1, 0) > rpo_number.get(b2, 0):
                b1 = self._idom[b1]
            while rpo_number.get(b2, 0) > rpo_number.get(b1, 0):
                b2 = self._idom[b2]
        return b1
    
    def dominates(self, a_id: int, b_id: int) -> bool:
        """Does block `a` dominate block `b`?"""
        runner = b_id
        while runner != self.cfg.entry.id:
            if runner == a_id:
                return True
            runner = self._idom.get(runner)
            if runner is None:
                return False
        return a_id == self.cfg.entry.id
    
    def idom(self, block_id: int) -> int:
        """Return immediate dominator of block."""
        return self._idom.get(block_id)
    
    def dominance_frontier(self, block_id: int) -> set:
        """
        Compute dominance frontier of a block.
        DF(n) = {y | ∃ pred p of y such that n dom p but n does not
                 strictly dominate y}
        """
        ...
    
    def children(self, block_id: int) -> list:
        """Return children in the dominator tree."""
        return self._dom_tree.get(block_id, [])
```

##### Post-Dominator Tree

Dually, block $p$ **post-dominates** $n$ if every path from $n$ to `EXIT` passes through $p$. Computed by running the dominator algorithm on the **reverse CFG** (edges reversed, EXIT as entry).

```python
class PostDominatorTree:
    """
    Post-dominator tree: computed by reversing the CFG 
    and running the dominator algorithm from EXIT.
    """
    
    def __init__(self, cfg: CFG):
        self.cfg = cfg
        reversed_cfg = self._reverse_cfg(cfg)
        self._dom = DominatorTree(reversed_cfg)
    
    def post_dominates(self, a_id: int, b_id: int) -> bool:
        """Does block `a` post-dominate block `b`?"""
        return self._dom.dominates(a_id, b_id)
```

##### Usage

```python
from cppcheckdata_shims.ctrlflow_analyses import DominatorTree, PostDominatorTree

dom = DominatorTree(cfg)
pdom = PostDominatorTree(cfg)

# Check if block 2 dominates block 7
print(dom.dominates(2, 7))  # True/False

# Get immediate dominator
print(dom.idom(7))  # e.g., 3

# Dominance frontier (used in SSA construction)
print(dom.dominance_frontier(3))  # e.g., {5, 8}
```

#### 3.5.3 Natural Loop Detection

##### Theory

A **natural loop** is defined by a **back-edge** $(n, h)$ where $h$ **dominates** $n$. The loop body is the set of all blocks from which $n$ can be reached without going through $h$, plus $h$ itself.

**Algorithm** (Aho et al. §9.6.6):

1. Compute the dominator tree.
2. Identify back-edges: edge $(n, h)$ where $h \text{ dom } n$.
3. For each back-edge, compute the natural loop by a backward traversal from $n$, collecting blocks until reaching $h$.

A loop has:
- **Header** $h$: the dominator target of the back-edge
- **Back-edge node** $n$: the source of the back-edge (often the last block before looping back)
- **Body**: all blocks in the loop
- **Exit edges**: edges from body blocks to non-body blocks
- **Nesting**: loop $L_1$ is nested inside $L_2$ if $L_1.\text{body} \subset L_2.\text{body}$

```python
class NaturalLoop:
    """Represents a single natural loop."""
    
    header: BasicBlock          # Loop header
    back_edge_source: BasicBlock  # Source of the back-edge
    body: set                   # Set of BasicBlock in the loop body
    exits: list                 # List of (block, successor) exit edges
    depth: int                  # Nesting depth (1 = outermost)
    parent: 'NaturalLoop'      # Enclosing loop (None for outermost)
    children: list              # Nested loops


class NaturalLoopDetector:
    """
    Detects all natural loops in the CFG using back-edge analysis.
    """
    
    def __init__(self, cfg: CFG, dom_tree: DominatorTree = None):
        self.cfg = cfg
        self.dom = dom_tree or DominatorTree(cfg)
        self.loops = []
        self._detect()
    
    def _detect(self):
        # Step 1: Find all back-edges
        back_edges = []
        for block in self.cfg.blocks:
            for succ in block.successors:
                if self.dom.dominates(succ.id, block.id):
                    back_edges.append((block, succ))
        
        # Step 2: For each back-edge, compute the natural loop
        for (tail, header) in back_edges:
            body = {header}
            stack = [tail]
            while stack:
                node = stack.pop()
                if node not in body:
                    body.add(node)
                    for pred in node.predecessors:
                        if pred not in body:
                            stack.append(pred)
            
            # Find exit edges
            exits = []
            for b in body:
                for s in b.successors:
                    if s not in body:
                        exits.append((b, s))
            
            loop = NaturalLoop()
            loop.header = header
            loop.back_edge_source = tail
            loop.body = body
            loop.exits = exits
            self.loops.append(loop)
        
        # Step 3: Compute nesting
        self._compute_nesting()
    
    def _compute_nesting(self):
        """Establish parent/child relationships by set containment."""
        self.loops.sort(key=lambda l: len(l.body))  # Smallest first
        for i, inner in enumerate(self.loops):
            for outer in self.loops[i+1:]:
                if inner.body < outer.body:  # Strict subset
                    inner.parent = outer
                    outer.children.append(inner)
                    break
    
    def loop_of(self, block: BasicBlock) -> NaturalLoop:
        """Return the innermost loop containing this block, or None."""
        for loop in self.loops:
            if block in loop.body:
                # Check it's not in a nested sub-loop
                in_child = any(block in child.body for child in loop.children)
                if not in_child:
                    return loop
        return None
    
    def is_loop_header(self, block: BasicBlock) -> bool:
        return any(loop.header == block for loop in self.loops)
```

##### Usage

```python
from cppcheckdata_shims.ctrlflow_analyses import NaturalLoopDetector

detector = NaturalLoopDetector(cfg)

for loop in detector.loops:
    print(f"Loop at line {loop.header.first_token.linenr}:")
    print(f"  Body blocks: {[b.id for b in loop.body]}")
    print(f"  Exit edges: {len(loop.exits)}")
    print(f"  Nesting depth: {loop.depth}")
```

#### 3.5.4 Loop Invariant Analysis

##### Theory

An instruction $s$ in a loop $L$ is **loop-invariant** if, for every iteration of $L$, it computes the same value. Formally, an expression `x = a op b` is loop-invariant if:

1. Both `a` and `b` are **constants**, **or**
2. All reaching definitions of `a` and `b` that reach $s$ are **outside the loop**, **or**
3. There is exactly one reaching definition of `a` (or `b`) inside the loop, and that definition is itself loop-invariant (**recursive case**)

This is computed iteratively: start with the set of trivially invariant computations (rules 1 and 2), then repeatedly apply rule 3 until no new invariants are found.

##### Implementation

```python
class LoopInvariantAnalysis:
    """
    Identifies loop-invariant computations using the three-rule
    iterative algorithm (Aho et al. §9.5.4).
    
    Integrates with Cppcheck's ValueFlow to leverage known constant
    values from the upstream analysis.
    """
    
    def __init__(self, cfg: CFG, configuration, loop_detector=None):
        self.cfg = cfg
        self.config = configuration
        self.loops_det = loop_detector or NaturalLoopDetector(cfg)
        self._reaching_defs = ReachingDefinitions(cfg, configuration).solve()
        self._invariants = {}  # loop_header_id -> set of invariant token_ids
    
    def analyze_loop(self, loop: NaturalLoop) -> set:
        """
        Return the set of Token objects that are loop-invariant
        computations in the given loop.
        """
        loop_block_ids = {b.id for b in loop.body}
        invariant_tokens = set()
        
        changed = True
        while changed:
            changed = False
            for block in loop.body:
                for token in block.tokens:
                    if token in invariant_tokens:
                        continue
                    if not self._is_computation(token):
                        continue
                    if self._check_invariant(token, loop, invariant_tokens):
                        invariant_tokens.add(token)
                        changed = True
        
        return invariant_tokens
    
    def _check_invariant(self, token, loop, known_invariants):
        """Apply the three rules for loop invariance."""
        operands = self._get_operands(token)
        loop_block_ids = {b.id for b in loop.body}
        
        for operand in operands:
            # Rule 1: constant
            if operand.isNumber or (operand.values and 
                any(v.valueKind == 'known' for v in operand.values)):
                continue
            
            # Rule 2: all reaching definitions are outside the loop
            if operand.varId:
                defs_reaching = self._defs_for_var_at(operand)
                all_outside = all(
                    self._def_block(d) not in loop_block_ids 
                    for d in defs_reaching
                )
                if all_outside:
                    continue
                
                # Rule 3: exactly one reaching def inside loop, 
                #          and it's already known invariant
                inside_defs = [
                    d for d in defs_reaching 
                    if self._def_block(d) in loop_block_ids
                ]
                if (len(inside_defs) == 1 and 
                    inside_defs[0] in known_invariants):
                    continue
            
            return False  # This operand is NOT invariant
        
        return True  # All operands are invariant → computation is invariant
    
    def find_all_invariants(self) -> dict:
        """
        Analyze all loops, return {NaturalLoop: set of invariant Tokens}.
        """
        result = {}
        for loop in self.loops_det.loops:
            result[loop] = self.analyze_loop(loop)
        return result
```

##### Code Motion Safety

An invariant computation can be **hoisted** (moved before the loop) only if:

1. The block containing the computation **dominates** all loop exits
2. The variable being assigned is not assigned elsewhere in the loop
3. The variable is not used before the definition in the loop (or it dominates all uses)

```python
def is_hoistable(self, token, loop, dom_tree):
    """Check if an invariant token can safely be hoisted."""
    block = self._token_block(token)
    
    # Must dominate all exits
    for exit_block, _ in loop.exits:
        if not dom_tree.dominates(block.id, exit_block.id):
            return False
    
    # Must be the only definition in the loop
    if token.astOperand1 and token.astOperand1.varId:
        var_id = token.astOperand1.varId
        loop_defs = self._count_defs_in_loop(var_id, loop)
        if loop_defs > 1:
            return False
    
    return True
```

#### 3.5.5 Induction Variable Analysis

##### Theory

A **basic induction variable** (BIV) $i$ in loop $L$ is a variable whose only definitions in $L$ have the form $i = i \pm c$ where $c$ is loop-invariant.

A **derived induction variable** (DIV) $j$ is a variable defined as $j = c_1 \cdot i + c_2$ where $i$ is a BIV and $c_1, c_2$ are loop-invariant.

Induction variables are used for:
- Strength reduction ($i * k$ → repeated addition)
- Loop bound estimation
- Array bounds check elimination

```python
class InductionVariable:
    """Represents a detected induction variable."""
    variable: Variable
    kind: str               # 'basic' or 'derived'
    step: int               # Increment per iteration (for BIVs)
    base_iv: 'InductionVariable'  # For DIVs, the underlying BIV
    coefficient: int        # For DIVs: j = coefficient * base_iv + offset
    offset: int             # For DIVs


class InductionVariableAnalysis:
    """
    Detects basic and derived induction variables in loops.
    
    BIV detection: find variables with exactly one definition
    in the loop of the form i = i ± c (c loop-invariant).
    
    DIV detection: find variables defined as linear functions
    of BIVs with loop-invariant coefficients.
    """
    
    def __init__(self, cfg, configuration, loop_detector=None, 
                 invariant_analysis=None):
        self.cfg = cfg
        self.config = configuration
        self.loops_det = loop_detector or NaturalLoopDetector(cfg)
        self.invariants = invariant_analysis or \
                          LoopInvariantAnalysis(cfg, configuration, self.loops_det)
    
    def detect_bivs(self, loop: NaturalLoop) -> list:
        """Find all basic induction variables in the loop."""
        invariant_tokens = self.invariants.analyze_loop(loop)
        bivs = []
        
        for block in loop.body:
            for tok in block.tokens:
                if tok.isAssignmentOp and tok.str in ('=', '+=', '-='):
                    lhs = tok.astOperand1
                    if lhs and lhs.varId:
                        var_id = lhs.varId
                        # Check: only one def of this var in loop
                        if self._single_def_in_loop(var_id, loop, tok):
                            step = self._extract_step(tok, var_id, 
                                                       invariant_tokens)
                            if step is not None:
                                iv = InductionVariable()
                                iv.variable = lhs.variable
                                iv.kind = 'basic'
                                iv.step = step
                                bivs.append(iv)
        return bivs
    
    def _extract_step(self, assign_tok, var_id, invariants):
        """
        Check if assignment is of form i = i + c or i += c.
        Return c if so, None otherwise.
        """
        if assign_tok.str in ('+=', '-='):
            rhs = assign_tok.astOperand2
            if self._is_loop_invariant_expr(rhs, invariants):
                val = self._evaluate_constant(rhs)
                if val is not None:
                    return val if assign_tok.str == '+=' else -val
        elif assign_tok.str == '=':
            rhs = assign_tok.astOperand2
            if rhs and rhs.str in ('+', '-') and rhs.isBinaryOp():
                op1, op2 = rhs.astOperand1, rhs.astOperand2
                if op1 and op1.varId == var_id:
                    if self._is_loop_invariant_expr(op2, invariants):
                        val = self._evaluate_constant(op2)
                        if val is not None:
                            return val if rhs.str == '+' else -val
                elif op2 and op2.varId == var_id and rhs.str == '+':
                    if self._is_loop_invariant_expr(op1, invariants):
                        val = self._evaluate_constant(op1)
                        return val
        return None
```

#### 3.5.6 Loop Bound Analysis

```python
class LoopBoundAnalysis:
    """
    Estimates loop iteration counts using:
    1. Induction variable analysis (BIV step and initial value)
    2. Loop exit conditions (comparison with loop-invariant bound)
    3. Cppcheck ValueFlow data (known values at condition tokens)
    """
    
    def estimate_bounds(self, loop: NaturalLoop) -> dict:
        """
        Return estimated bounds: {
            'min_iterations': int or None,
            'max_iterations': int or None,
            'exact': int or None,
            'may_be_infinite': bool
        }
        """
        ...
```

#### 3.5.7 Path-Sensitive Analysis

##### Theory

Standard dataflow analysis is **path-insensitive** — it merges information at join points, losing the correlation between branch conditions and variable states. **Path-sensitive analysis** tracks information per execution path, preserving the branch conditions under which each fact holds.

From Møller & Schwartzbach: path sensitivity addresses the fundamental imprecision of merging at control flow joins. The challenge is the **exponential blowup**: a program with $k$ sequential `if` statements has $2^k$ possible paths.

##### K-Limiting and Loop Unrolling

To manage path explosion:

- **K-limiting**: Bound the number of paths explored to $k$. When the limit is exceeded, merge (widen) the remaining paths.
- **Loop unrolling**: For loops, unroll at most $u$ iterations explicitly; after that, merge to a summary.

```python
class PathState:
    """State along a single execution path."""
    constraints: list       # List of (token, bool) branch decisions
    facts: dict             # var_id -> abstract value
    feasible: bool          # Whether this path is still feasible
    
    def fork(self, condition_token, branch: bool) -> 'PathState':
        """Create a new state for taking a specific branch."""
        new = PathState()
        new.constraints = self.constraints + [(condition_token, branch)]
        new.facts = dict(self.facts)
        new.feasible = self.feasible
        return new


class PathSensitiveAnalysis:
    """
    Explores execution paths through the CFG with configurable
    k-limiting for path explosion control.
    
    Parameters:
        k_limit: Maximum number of paths to track simultaneously
        loop_unroll: Maximum loop iterations to unroll
    """
    
    def __init__(self, cfg: CFG, configuration, 
                 k_limit: int = 64, loop_unroll: int = 3):
        self.cfg = cfg
        self.config = configuration
        self.k_limit = k_limit
        self.loop_unroll = loop_unroll
    
    def explore(self, entry_state: PathState = None) -> list:
        """
        Explore paths from ENTRY, returning a list of PathState 
        objects at EXIT (one per feasible path discovered).
        """
        initial = entry_state or PathState()
        initial.feasible = True
        initial.constraints = []
        initial.facts = {}
        
        worklist = [(self.cfg.entry, initial)]
        exit_states = []
        
        while worklist:
            block, state = worklist.pop(0)
            
            if not state.feasible:
                continue
            
            # Apply transfer for this block
            state = self._transfer_block(block, state)
            
            if block.is_exit:
                exit_states.append(state)
                continue
            
            succs = block.successors
            if len(succs) == 1:
                worklist.append((succs[0], state))
            elif len(succs) == 2:
                # Conditional branch — fork the state
                cond_token = self._get_branch_condition(block)
                true_state = state.fork(cond_token, True)
                false_state = state.fork(cond_token, False)
                
                # Refine facts based on branch condition
                true_state = self._refine(true_state, cond_token, True)
                false_state = self._refine(false_state, cond_token, False)
                
                worklist.append((succs[0], true_state))   # true branch
                worklist.append((succs[1], false_state))   # false branch
            else:
                # Switch or other multi-way branch
                for succ in succs:
                    worklist.append((succ, state.fork(None, True)))
            
            # K-limiting: if too many paths, merge
            if len(worklist) > self.k_limit:
                worklist = self._merge_paths(worklist)
        
        return exit_states
```

#### 3.5.8 Path Feasibility Checker

A lightweight **interval-based constraint checker** that determines whether a path's accumulated branch conditions are satisfiable.

```python
class PathFeasibilityChecker:
    """
    Lightweight path feasibility checker using interval arithmetic.
    
    For each variable, tracks an interval [lo, hi]. When a branch
    condition like 'x < 10' is taken, refines the interval for x.
    If any variable's interval becomes empty, the path is infeasible.
    """
    
    def __init__(self):
        self.intervals = {}   # var_id -> (lo, hi)
    
    def assume(self, condition_token, branch: bool) -> bool:
        """
        Incorporate a branch decision. Returns False if the 
        resulting state is infeasible.
        """
        if condition_token is None:
            return True
        
        # Parse the condition token's AST
        op = condition_token.str
        if op in ('<', '<=', '>', '>=', '==', '!='):
            lhs = condition_token.astOperand1
            rhs = condition_token.astOperand2
            
            if lhs and lhs.varId and rhs and rhs.isNumber:
                var_id = lhs.varId
                bound = int(rhs.str) if rhs.isInt else float(rhs.str)
                return self._refine_interval(var_id, op, bound, branch)
        
        return True  # Can't analyze → assume feasible
    
    def _refine_interval(self, var_id, op, bound, branch):
        """Refine the interval for var_id given the condition."""
        lo, hi = self.intervals.get(var_id, (float('-inf'), float('inf')))
        
        if branch:  # Condition is TRUE
            if op == '<':    hi = min(hi, bound - 1)
            elif op == '<=': hi = min(hi, bound)
            elif op == '>':  lo = max(lo, bound + 1)
            elif op == '>=': lo = max(lo, bound)
            elif op == '==': lo, hi = bound, bound
            elif op == '!=': pass  # Can't easily represent
        else:  # Condition is FALSE
            if op == '<':    lo = max(lo, bound)
            elif op == '<=': lo = max(lo, bound + 1)
            elif op == '>':  hi = min(hi, bound)
            elif op == '>=': hi = min(hi, bound - 1)
            elif op == '==': pass  # Can't easily represent ≠
            elif op == '!=': lo, hi = bound, bound
        
        if lo > hi:
            return False  # Infeasible!
        
        self.intervals[var_id] = (lo, hi)
        return True
```

---

### 3.6 `shims_bridge.py` — Unified Facade

#### 3.6.1 Purpose

The bridge is the **single entry point** for addon code. It wraps all analysis modules behind a lazy-evaluation facade with per-configuration caching.

#### 3.6.2 Design Pattern

The bridge uses the **Facade** pattern combined with **Lazy Initialization**:

Addon code
    │
    └──► ShimsBridge(configuration)
              │
              ├─ .cfg(function)          → CFG              [lazy, cached]
              ├─ .call_graph()           → CallGraph         [lazy, cached]
              ├─ .dominators(function)   → DominatorTree     [lazy, cached]
              ├─ .post_dominators(func)  → PostDominatorTree [lazy, cached]
              ├─ .loops(function)        → NaturalLoopDetector [lazy, cached]
              ├─ .reaching_defs(func)    → results dict      [lazy, cached]
              ├─ .live_vars(function)    → results dict      [lazy, cached]
              ├─ .available_exprs(func)  → results dict      [lazy, cached]
              ├─ .taint(function, ...)   → results dict      [lazy, cached]
              ├─ .constants(function)    → results dict      [lazy, cached]
              ├─ .loop_invariants(func)  → {loop: tokens}    [lazy, cached]
              ├─ .induction_vars(func)   → {loop: [IV]}      [lazy, cached]
              ├─ .path_analysis(func,..) → [PathState]       [lazy, NOT cached]
              └─ .intervals(function)    → results dict      [lazy, cached]


#### 3.6.3 Implementation

```python
class ShimsBridge:
    """
    Unified facade for all cppcheckdata-shims analyses.
    
    Usage:
        bridge = ShimsBridge(configuration)
        for func in configuration.functions:
            cfg = bridge.cfg(func)
            dom = bridge.dominators(func)
            rd = bridge.reaching_defs(func)
            ...
    """
    
    def __init__(self, configuration):
        """
        Initialize with a cppcheckdata.Configuration.
        All analyses are lazily computed on first access.
        """
        self._config = configuration
        self._cache = {}
    
    def _get_or_compute(self, key, factory):
        """Generic lazy-init with caching."""
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]
    
    # ─── CFG ───────────────────────────────────────────────
    
    def cfg(self, function) -> 'CFG':
        """Get/build the CFG for a function."""
        return self._get_or_compute(
            ('cfg', function.Id),
            lambda: build_cfg_for_function(self._find_function_scope(function))
        )
    
    def all_cfgs(self) -> dict:
        """Get/build CFGs for all functions. Returns {Function: CFG}."""
        return self._get_or_compute(
            'all_cfgs',
            lambda: build_all_cfgs(self._config)
        )
    
    # ─── Call Graph ────────────────────────────────────────
    
    def call_graph(self) -> 'CallGraph':
        """Get/build the inter-procedural call graph."""
        return self._get_or_compute(
            'call_graph',
            lambda: build_call_graph(self._config)
        )
    
    # ─── Dominance ─────────────────────────────────────────
    
    def dominators(self, function) -> 'DominatorTree':
        """Get/compute the dominator tree for a function's CFG."""
        return self._get_or_compute(
            ('dom', function.Id),
            lambda: DominatorTree(self.cfg(function))
        )
    
    def post_dominators(self, function) -> 'PostDominatorTree':
        return self._get_or_compute(
            ('pdom', function.Id),
            lambda: PostDominatorTree(self.cfg(function))
        )
    
    # ─── Loops ─────────────────────────────────────────────
    
    def loops(self, function) -> 'NaturalLoopDetector':
        return self._get_or_compute(
            ('loops', function.Id),
            lambda: NaturalLoopDetector(
                self.cfg(function), self.dominators(function))
        )
    
    def loop_invariants(self, function) -> dict:
        """Returns {NaturalLoop: set of invariant Token objects}."""
        return self._get_or_compute(
            ('loop_inv', function.Id),
            lambda: LoopInvariantAnalysis(
                self.cfg(function), self._config,
                self.loops(function)
            ).find_all_invariants()
        )
    
    def induction_variables(self, function) -> dict:
        """Returns {NaturalLoop: list of InductionVariable}."""
        return self._get_or_compute(
            ('ind_var', function.Id),
            lambda: self._compute_induction_vars(function)
        )
    
    def _compute_induction_vars(self, function):
        iva = InductionVariableAnalysis(
            self.cfg(function), self._config,
            self.loops(function),
            LoopInvariantAnalysis(
                self.cfg(function), self._config, self.loops(function))
        )
        result = {}
        for loop in self.loops(function).loops:
            result[loop] = iva.detect_bivs(loop)
        return result
    
    # ─── Dataflow ──────────────────────────────────────────
    
    def reaching_defs(self, function) -> dict:
        return self._get_or_compute(
            ('rd', function.Id),
            lambda: ReachingDefinitions(
                self.cfg(function), self._config).solve()
        )
    
    def live_vars(self, function) -> dict:
        return self._get_or_compute(
            ('lv', function.Id),
            lambda: LiveVariables(
                self.cfg(function), self._config).solve()
        )
    
    def available_exprs(self, function) -> dict:
        return self._get_or_compute(
            ('ae', function.Id),
            lambda: AvailableExpressions(
                self.cfg(function), self._config).solve()
        )
    
    def taint(self, function, sources=None, sinks=None, 
              sanitizers=None) -> dict:
        """Note: not cached if custom sources/sinks are provided."""
        key = ('taint', function.Id, 
               tuple(sources or []), tuple(sinks or []), 
               tuple(sanitizers or []))
        return self._get_or_compute(
            key,
            lambda: TaintAnalysis(
                self.cfg(function), self._config,
                sources, sinks, sanitizers).solve()
        )
    
    def constants(self, function) -> dict:
        return self._get_or_compute(
            ('const', function.Id),
            lambda: ConstantPropagation(
                self.cfg(function), self._config).solve()
        )
    
    def intervals(self, function) -> dict:
        return self._get_or_compute(
            ('intervals', function.Id),
            lambda: IntervalAnalysis(
                self.cfg(function), self._config).solve()
        )
    
    # ─── Path Analysis ─────────────────────────────────────
    
    def path_analysis(self, function, k_limit=64, 
                      loop_unroll=3) -> list:
        """
        Path-sensitive analysis. NOT cached by default 
        (parameters may vary).
        """
        return PathSensitiveAnalysis(
            self.cfg(function), self._config,
            k_limit, loop_unroll
        ).explore()
    
    # ─── Utilities ─────────────────────────────────────────
    
    def _find_function_scope(self, function):
        """Find the Scope object for a Function."""
        for scope in self._config.scopes:
            if scope.type == 'Function' and scope.function == function:
                return scope
        return None
    
    def clear_cache(self):
        """Clear all cached analysis results."""
        self._cache.clear()
    
    def cache_stats(self) -> dict:
        """Return cache utilization statistics."""
        return {
            'entries': len(self._cache),
            'keys': list(self._cache.keys())
        }
```

#### 3.6.4 Dependency Graph

When you call `bridge.loop_invariants(func)`, the bridge automatically triggers the computation chain:

loop_invariants(func)
    └─► LoopInvariantAnalysis(cfg, config, loop_detector)
            ├─► cfg = bridge.cfg(func)             [cached after 1st call]
            │       └─► build_cfg_for_function(scope)
            ├─► loop_detector = bridge.loops(func)  [cached]
            │       └─► NaturalLoopDetector(cfg, dom)
            │               └─► dom = bridge.dominators(func) [cached]
            │                       └─► DominatorTree(cfg)
            └─► ReachingDefinitions(cfg, config).solve()


This ensures:
- No analysis is computed twice
- Dependencies are automatically resolved
- Memory is bounded (one result set per function per analysis)

---

## 4. Integration with Cppcheck Addons

### 4.1 The Addon Protocol

Cppcheck addons are Python scripts invoked by Cppcheck after it produces a `.dump` file. The invocation follows one of two protocols:

**Plain text mode** (default):
python my_addon.py source.c.dump

Diagnostics go to stderr: `[source.c:42] (style) message [errorId]`

**CLI mode** (`--cli`):
python my_addon.py --cli source.c.dump

Diagnostics go to stdout as JSON:
```json
{"file":"source.c","linenr":42,"column":5,"severity":"style","message":"...","addon":"myAddon","errorId":"myError","extra":""}
```

### 4.2 Addon Skeleton

```python
#!/usr/bin/env python3
"""
Example Cppcheck addon using cppcheckdata-shims.
Detects loop-invariant code that could be hoisted.
"""

import cppcheckdata
import sys
import json

from cppcheckdata_shims.shims_bridge import ShimsBridge


def report(token, severity, error_id, message, cli_mode=False, addon_name='myAddon'):
    """Report a diagnostic in the appropriate format."""
    if cli_mode:
        msg = {
            'file': token.file or '',
            'linenr': token.linenr or 0,
            'column': token.column or 0,
            'severity': severity,
            'message': message,
            'addon': addon_name,
            'errorId': error_id,
            'extra': ''
        }
        sys.stdout.write(json.dumps(msg) + '\n')
    else:
        sys.stderr.write(
            f'[{token.file}:{token.linenr}] ({severity}) '
            f'{message} [{error_id}]\n'
        )


def check_loop_invariants(configuration, cli_mode=False):
    """Find loop-invariant computations and report them."""
    bridge = ShimsBridge(configuration)
    
    for func in configuration.functions:
        # Get loop invariants for this function
        invariants = bridge.loop_invariants(func)
        dom = bridge.dominators(func)
        
        for loop, inv_tokens in invariants.items():
            for token in inv_tokens:
                # Only report if it's hoistable
                lia = bridge._cache.get(('loop_inv_analysis', func.Id))
                if lia and lia.is_hoistable(token, loop, dom):
                    report(
                        token,
                        'performance',
                        'loopInvariantComputation',
                        f"Expression '{token.str}' is loop-invariant and "
                        f"could be hoisted before the loop at line "
                        f"{loop.header.first_token.linenr}",
                        cli_mode
                    )


def check_dead_stores(configuration, cli_mode=False):
    """Find assignments to variables that are never subsequently read."""
    bridge = ShimsBridge(configuration)
    
    for func in configuration.functions:
        cfg = bridge.cfg(func)
        lv_results = bridge.live_vars(func)
        
        for block in cfg.iter_blocks():
            if block.is_entry or block.is_exit:
                continue
            _, out_val = lv_results[block.id]
            
            # Walk backwards through block tokens
            live = set(out_val)
            for tok in reversed(block.tokens):
                if (tok.isAssignmentOp and 
                    tok.astOperand1 and tok.astOperand1.varId):
                    var_id = tok.astOperand1.varId
                    if var_id not in live:
                        report(
                            tok, 'style', 'deadStore',
                            f"Value assigned to '{tok.astOperand1.str}' "
                            f"is never used",
                            cli_mode
                        )
                    # Kill the variable (defined here)
                    live.discard(var_id)
                
                # Add used variables
                if tok.isName and tok.varId and not tok.isAssignmentOp:
                    live.add(tok.varId)


def check_taint_violations(configuration, cli_mode=False):
    """Find tainted data flowing to dangerous sinks."""
    bridge = ShimsBridge(configuration)
    
    SOURCES = {'scanf', 'gets', 'fgets', 'recv', 'read', 'getenv', 'getchar'}
    SINKS = {'system', 'exec', 'execl', 'execlp', 'execvp', 'popen', 
             'sprintf', 'strcpy', 'strcat'}
    
    for func in configuration.functions:
        cfg = bridge.cfg(func)
        taint_results = bridge.taint(func, sources=SOURCES, sinks=SINKS)
        
        for block in cfg.iter_blocks():
            in_val, _ = taint_results[block.id]
            for tok in block.tokens:
                if (tok.isName and tok.function and 
                    tok.function.name in SINKS):
                    # Check if any argument is tainted
                    arg_tok = tok.next  # '(' after function name
                    if arg_tok and arg_tok.str == '(':
                        # Walk arguments
                        current = arg_tok.next
                        while current and current != arg_tok.link:
                            if current.isName and current.varId:
                                if current.varId in in_val:
                                    report(
                                        tok, 'error', 'taintedSink',
                                        f"Tainted data from "
                                        f"'{current.str}' flows to "
                                        f"sink '{tok.str}'",
                                        cli_mode
                                    )
                            current = current.next


def main():
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()
    
    cli_mode = '--cli' in sys.argv
    
    for dumpfile in args.dumpfile:
        data = cppcheckdata.parsedump(dumpfile)
        
        for cfg in data.configurations:
            check_loop_invariants(cfg, cli_mode)
            check_dead_stores(cfg, cli_mode)
            check_taint_violations(cfg, cli_mode)


if __name__ == '__main__':
    main()
```

### 4.3 Running with Cppcheck

```bash
# Step 1: Generate the dump file
cppcheck --dump source.c

# Step 2: Run the addon on the dump
python my_addon.py source.c.dump

# Or in CLI mode (for IDE integration)
python my_addon.py --cli source.c.dump

# Or let Cppcheck run the addon directly
cppcheck --addon=my_addon.py source.c
```

### 4.4 Addon Configuration via JSON

Cppcheck supports addon configuration through JSON:

```json
{
    "script": "my_addon.py",
    "args": ["--severity=style", "--taint-sources=custom_read"]
}
```

```bash
cppcheck --addon=my_addon.json source.c
```

### 4.5 Integration with CASL

If you are using the CASL compiler, the generated Python addon automatically uses `ShimsBridge`:

```bash
# Compile CASL specification to Python addon
python -m cppcheckdata_shims.casl compile my_checks.casl -o my_checks_addon.py

# Run with Cppcheck
cppcheck --addon=my_checks_addon.py source.c
```

The generated code follows the same structure as the manual addon above, with pattern matching implemented via AST traversal and analysis queries via the bridge.

---

## 5. Theoretical Foundations

### 5.1 Static Program Analysis: The Big Picture

Static analysis aims to determine properties of program behavior **without executing** the program. By Rice's theorem, all non-trivial semantic properties of programs are undecidable. Therefore, all practical static analyses are **approximations**:

- **Sound (over-approximate)** analyses report all real issues but may include false positives. If the analysis says "variable $x$ may be null," then there exists at least one execution path where it is null. If it says "variable $x$ is definitely not null," that is guaranteed.
- **Complete (under-approximate)** analyses never report false positives but may miss real issues.
- Most practical bug-finding tools aim for a pragmatic balance.

### 5.2 Lattice Theory and Fixed Points

#### The Mathematical Framework

A **complete lattice** $(L, \sqsubseteq)$ is a partially ordered set where every subset has both a least upper bound (join, $\sqcup$) and greatest lower bound (meet, $\sqcap$). Key elements:

- $\bot$ (bottom): the least element
- $\top$ (top): the greatest element

A function $f: L \to L$ is **monotone** if $x \sqsubseteq y \implies f(x) \sqsubseteq f(y)$.

**Tarski's Fixed-Point Theorem**: Every monotone function on a complete lattice has a least fixed point, obtained as:

$$\text{lfp}(f) = \bigsqcup_{n \geq 0} f^n(\bot)$$

This is the theoretical basis for iterative dataflow analysis: we start with $\bot$ (no information) and repeatedly apply the transfer functions until convergence.

#### Convergence and Widening

For lattices of finite height $h$, convergence is guaranteed in at most $h$ iterations per block. For infinite-height lattices (e.g., integers in interval analysis), we need **widening** $\nabla$ to force convergence:

$$x \nabla y \sqsupseteq x \sqcup y$$

and the widened sequence $x_0 = \bot$, $x_{n+1} = x_n \nabla f(x_n)$ is guaranteed to stabilize in finite steps.

After reaching a fixed point with widening, **narrowing** $\Delta$ can recover precision:

$$x \Delta y \sqsubseteq x$$

The narrowing sequence $y_0 = x^*$ (widened fixed point), $y_{n+1} = y_n \Delta f(y_n)$ decreases toward the true fixed point.

### 5.3 Control Flow Graphs

The CFG is the fundamental program representation for analysis. For a function with statements $s_1, \ldots, s_n$:

- **Nodes**: basic blocks (maximal straight-line sequences)
- **Edges**: possible transfers of control
- **ENTRY/EXIT**: synthetic nodes representing function start/end

The CFG captures the **operational semantics** of control flow: the set of paths through the CFG overapproximates the set of actual execution paths (some paths may be **infeasible** due to correlations between branch conditions).

### 5.4 Dominance and Its Applications

#### Why Dominance Matters

The dominance relation captures the "must pass through" property:

$$d \text{ dom } n \iff \forall \text{ paths } \pi \text{ from ENTRY to } n: d \in \pi$$

**Applications**:

| Application | How Dominance Is Used |
|---|---|
| **SSA construction** | $\phi$-functions are placed at dominance frontiers |
| **Loop detection** | Back-edges identified via dominator tree |
| **Code motion** | Invariant code hoistable only if it dominates all loop exits |
| **Dead code** | A block not dominated by ENTRY is unreachable |
| **Control dependence** | Node $n$ is control-dependent on $m$ if $m$ is not post-dominated by $n$ but some successor of $m$ is post-dominated by $n$ |

#### Dominance Frontier

The **dominance frontier** of node $n$, denoted $DF(n)$, is the set of nodes where $n$'s dominance "just ends":

$$DF(n) = \{y \mid \exists p \in \text{pred}(y): n \text{ dom } p \land n \not\text{ sdom } y\}$$

where $\text{sdom}$ denotes strict dominance. This is crucial for **SSA φ-function placement** (Cytron et al., 1991).

### 5.5 Natural Loops and Loop Analysis

#### Loop Terminology

| Term | Definition |
|---|---|
| **Back-edge** | Edge $(n, h)$ where $h$ dominates $n$ |
| **Loop header** | The target $h$ of a back-edge; the single entry point |
| **Loop body** | All nodes from which $n$ (the back-edge source) can be reached without passing through $h$, plus $h$ |
| **Loop exit** | An edge from a body node to a non-body node |
| **Loop-invariant** | A computation whose value doesn't change across iterations |
| **Induction variable** | A variable that changes by a constant amount per iteration |
| **Trip count** | The number of times the loop body executes |

#### Why Loops Are Special

Loops require special handling because:

1. **Back-edges create cycles** in the CFG, which cause iterative algorithms to re-process blocks.
2. **Loop-carried dependencies** mean that a variable's value in iteration $i$ depends on iteration $i-1$.
3. **Infinite-height lattices** arise naturally from loop counters (widening is needed).
4. **Loop invariants** enable powerful optimizations (hoisting, strength reduction).

### 5.6 Path Sensitivity

#### The Precision Problem

Consider:

```c
int x;
if (p) x = 1;
else   x = 2;
// At this point, path-insensitive: x ∈ {1, 2}
if (p) {
    // Path-sensitive: x == 1 (because p was true → x = 1)
    // Path-insensitive: x ∈ {1, 2}  ← imprecise!
}
```

Path-insensitive analysis merges the two branches at the join point, losing the correlation between `p` and `x`. Path-sensitive analysis maintains separate states for each path, preserving this correlation.

#### The Scalability Problem

For $k$ sequential branches, there are $2^k$ paths. Practical mitigations:

1. **K-limiting**: Cap the number of simultaneous paths
2. **Merging heuristics**: Merge paths that agree on "important" variables
3. **Symbolic execution with SMT**: Use constraint solvers (not in our lightweight implementation)
4. **Trace partitioning**: Group paths by key predicates (Das et al.)

Our implementation uses k-limiting with interval-based feasibility checking — a pragmatic balance between precision and performance.

### 5.7 Interprocedural Analysis

#### Context Sensitivity Approaches

| Approach | Precision | Cost | Used In Shims? |
|---|---|---|---|
| **Context-insensitive** | Low | $O(n)$ | Default |
| **Call-string (k-CFA)** | Medium | $O(n \cdot |CS|^k)$ | Configurable |
| **Functional** | High | $O(n \cdot |L|)$ | Future |
| **Object-sensitive** | High (OO) | $O(n \cdot |O|^k)$ | Not yet |

The call graph from `callgraph.py` provides the foundation; context sensitivity is an overlay applied by the analysis.

### 5.8 Comparison with Industrial Tools

| Feature | Cppcheck (native) | + shims library | Coverity | PVS-Studio |
|---|---|---|---|---|
| Token-level checks | ✅ | ✅ | ✅ | ✅ |
| ValueFlow | ✅ | ✅ (augmented) | ✅ | ✅ |
| CFG construction | Partial | Full | Full | Full |
| Dominator tree | ❌ | ✅ | ✅ | ✅ |
| Loop analysis | Basic | Full | Full | Full |
| Taint analysis | ❌ | ✅ | ✅ | ✅ |
| Path sensitivity | ❌ | Configurable | ✅ | ✅ |
| Interprocedural | Limited | Via call graph | Full | Full |
| Custom checks | Via addons | Via addons + CASL | Config files | Plugins |

---

## 6. Cookbook: End-to-End Examples

### 6.1 Example: Detecting Uninitialized Variable Use

```python
"""
Checker: detect potentially uninitialized local variables.

Theory: A variable is potentially uninitialized at a point if there
exists a path from ENTRY to that point on which the variable is not
assigned. This is a "may-analysis" variant of reaching definitions.
"""

from cppcheckdata_shims.shims_bridge import ShimsBridge

def check_uninit(configuration, cli_mode=False):
    bridge = ShimsBridge(configuration)
    
    for func in configuration.functions:
        cfg = bridge.cfg(func)
        rd_results = bridge.reaching_defs(func)
        
        # Collect all local variables (non-arguments)
        local_vars = {}
        for var in configuration.variables:
            if (var.isLocal and not var.isArgument and 
                var.nameToken and var.nameToken.scope and
                var.nameToken.scope.function == func):
                local_vars[var.Id] = var
        
        # For each use of a local variable, check if there's a path
        # where no definition reaches it
        for block in cfg.iter_blocks():
            in_val, _ = rd_results[block.id]
            for tok in block.tokens:
                if (tok.isName and tok.variable and 
                    tok.variable.Id in local_vars):
                    # Is this a use (not a definition)?
                    if not (tok.astParent and tok.astParent.isAssignmentOp
                            and tok.astParent.astOperand1 == tok):
                        # Check if any definition reaches here
                        var_defs = {(vid, did) for vid, did in in_val 
                                    if vid == tok.varId}
                        if not var_defs:
                            report(tok, 'warning', 'uninitVar',
                                   f"Variable '{tok.str}' may be "
                                   f"used uninitialized",
                                   cli_mode)
```

### 6.2 Example: Resource Leak Detection with Path Sensitivity

```python
"""
Checker: detect resource leaks (fopen without fclose on all paths).

Uses path-sensitive analysis to track FILE* handles.
"""

def check_resource_leaks(configuration, cli_mode=False):
    bridge = ShimsBridge(configuration)
    
    ALLOC_FUNCS = {'fopen', 'fdopen', 'tmpfile', 'popen'}
    FREE_FUNCS = {'fclose', 'pclose'}
    
    for func in configuration.functions:
        exit_states = bridge.path_analysis(func, k_limit=128)
        
        for state in exit_states:
            # Check if any allocated resource is not freed
            for var_id, status in state.facts.items():
                if status == 'allocated':
                    # Find the allocation token for reporting
                    alloc_tok = state.facts.get(f'{var_id}_alloc_token')
                    if alloc_tok:
                        report(alloc_tok, 'error', 'resourceLeak',
                               f"Resource allocated here may not be "
                               f"released on all paths",
                               cli_mode)
```

### 6.3 Example: Buffer Overflow via Interval Analysis

```python
"""
Checker: detect potential buffer overflow using interval analysis.

If array access a[i] and interval of i may exceed array bounds,
report a warning.
"""

def check_buffer_overflow(configuration, cli_mode=False):
    bridge = ShimsBridge(configuration)
    
    for func in configuration.functions:
        cfg = bridge.cfg(func)
        interval_results = bridge.intervals(func)
        
        for block in cfg.iter_blocks():
            in_val, _ = interval_results[block.id]
            for tok in block.tokens:
                # Look for array subscript: a[i]
                if tok.str == '[' and tok.astOperand1 and tok.astOperand2:
                    array_tok = tok.astOperand1
                    index_tok = tok.astOperand2
                    
                    # Get array size
                    if (array_tok.variable and 
                        array_tok.variable.isArray):
                        array_size = array_tok.variable.arrayDimensions
                        if array_size:
                            size = array_size[0]  # First dimension
                            
                            # Get interval for index
                            if index_tok.varId and index_tok.varId in in_val:
                                lo, hi = in_val[index_tok.varId]
                                
                                if hi >= size:
                                    report(
                                        tok, 'error', 'bufferOverflow',
                                        f"Array '{array_tok.str}' "
                                        f"(size {size}) accessed with "
                                        f"index that may be up to {hi}",
                                        cli_mode
                                    )
                                if lo < 0:
                                    report(
                                        tok, 'error', 'negativeIndex',
                                        f"Array '{array_tok.str}' may "
                                        f"be accessed with negative "
                                        f"index (min: {lo})",
                                        cli_mode
                                    )
```

### 6.4 Example: Finding Infinite Loops

```python
"""
Checker: detect potentially infinite loops using loop bound analysis
and induction variable detection.
"""

def check_infinite_loops(configuration, cli_mode=False):
    bridge = ShimsBridge(configuration)
    
    for func in configuration.functions:
        loop_det = bridge.loops(func)
        
        for loop in loop_det.loops:
            # Check 1: while(true) with no break
            if _is_literal_true_condition(loop):
                if not _has_break_or_return(loop):
                    report(
                        loop.header.first_token, 'warning', 
                        'infiniteLoop',
                        "Loop condition is always true with no "
                        "break/return statement",
                        cli_mode
                    )
                continue
            
            # Check 2: No modification of loop condition variables
            cond_vars = _get_condition_variables(loop)
            modified_in_body = _get_modified_variables(loop)
            
            unmodified = cond_vars - modified_in_body
            if unmodified and not _has_break_or_return(loop):
                var_names = ', '.join(
                    _var_name(v, configuration) for v in unmodified)
                report(
                    loop.header.first_token, 'warning',
                    'loopConditionUnmodified',
                    f"Loop condition depends on '{var_names}' "
                    f"which is not modified in the loop body",
                    cli_mode
                )
```

### 6.5 Example: Combining Multiple Analyses

```python
"""
Checker: detect use-after-free using reaching definitions + 
taint-like tracking of freed pointers.

This demonstrates combining multiple analysis results.
"""

def check_use_after_free(configuration, cli_mode=False):
    bridge = ShimsBridge(configuration)
    
    FREE_FUNCS = {'free', 'delete'}
    
    for func in configuration.functions:
        cfg = bridge.cfg(func)
        rd_results = bridge.reaching_defs(func)
        lv_results = bridge.live_vars(func)
        
        # Phase 1: Find all free() calls and the freed variable
        free_sites = []  # (block, token, var_id)
        for block in cfg.iter_blocks():
            for tok in block.tokens:
                if (tok.isName and tok.function and 
                    tok.function.name in FREE_FUNCS):
                    freed_var = _get_freed_variable(tok)
                    if freed_var:
                        free_sites.append((block, tok, freed_var))
        
        # Phase 2: For each free site, check if the variable is
        # used after the free without being reassigned
        for free_block, free_tok, freed_var_id in free_sites:
            # Check all blocks reachable from free_block
            visited = set()
            worklist = list(free_block.successors)
            
            while worklist:
                block = worklist.pop(0)
                if block.id in visited or block.is_exit:
                    continue
                visited.add(block.id)
                
                in_defs, _ = rd_results[block.id]
                
                for tok in block.tokens:
                    # If the variable is reassigned, stop tracking
                    if (tok.isAssignmentOp and tok.astOperand1 and
                        tok.astOperand1.varId == freed_var_id):
                        break  # Safe: reassigned
                    
                    # If the variable is used (dereferenced), report
                    if (tok.isName and tok.varId == freed_var_id):
                        # Check if it's actually being dereferenced
                        if _is_dereference(tok):
                            report(
                                tok, 'error', 'useAfterFree',
                                f"Pointer '{tok.str}' used after "
                                f"being freed at line "
                                f"{free_tok.linenr}",
                                cli_mode
                            )
                else:
                    # No break → variable not reassigned in block
                    worklist.extend(block.successors)
```

---

## 7. Appendices

### 7.1 Appendix A: Quick Reference Card

| Task | Code |
|---|---|
| Parse dump | `data = cppcheckdata.parsedump("f.c.dump")` |
| Get bridge | `bridge = ShimsBridge(cfg)` |
| Build CFG | `cfg = bridge.cfg(func)` |
| Dominators | `dom = bridge.dominators(func)` |
| Find loops | `loops = bridge.loops(func)` |
| Reaching defs | `rd = bridge.reaching_defs(func)` |
| Live vars | `lv = bridge.live_vars(func)` |
| Taint | `t = bridge.taint(func, sources={...})` |
| Constants | `c = bridge.constants(func)` |
| Intervals | `iv = bridge.intervals(func)` |
| Loop invariants | `li = bridge.loop_invariants(func)` |
| Path analysis | `ps = bridge.path_analysis(func, k_limit=64)` |
| Call graph | `cg = bridge.call_graph()` |
| Visualize CFG | `print(bridge.cfg(func).to_dot())` |

### 7.2 Appendix B: Glossary

| Term | Definition |
|---|---|
| **Basic block** | Maximal sequence of instructions with single entry/exit |
| **Back-edge** | CFG edge whose target dominates its source |
| **Dominator** | Block $d$ dominates $n$ if all paths from ENTRY to $n$ go through $d$ |
| **Fixed point** | State where iterative application produces no change: $f(x) = x$ |
| **Join** ($\sqcup$) | Least upper bound in a lattice; merge operation at confluence |
| **Lattice** | Partially ordered set with well-defined join and meet |
| **Live variable** | Variable whose current value may be used on some future path |
| **Loop invariant** | Computation producing the same value in every loop iteration |
| **Monotone** | $x \sqsubseteq y \implies f(x) \sqsubseteq f(y)$; ensures fixed-point convergence |
| **Natural loop** | Set of blocks induced by a back-edge |
| **Path sensitivity** | Tracking analysis state per-path, preserving branch correlations |
| **Reaching definition** | An assignment that may reach a point without being overwritten |
| **Transfer function** | Function modeling the effect of a basic block on the analysis state |
| **ValueFlow** | Cppcheck's built-in value propagation analysis |
| **Widening** ($\nabla$) | Operator forcing convergence on infinite-height lattices |

### 7.3 Appendix C: References

1. **Aho, A. V., Lam, M. S., Sethi, R., & Ullman, J. D.** (2006). *Compilers: Principles, Techniques, and Tools* (2nd ed.). Chapters 8–9 on optimization and dataflow analysis.

2. **Cooper, K. D., Harvey, T. J., & Kennedy, K.** (2001). A Simple, Fast Dominance Algorithm. *Software Practice & Experience*, 31(4), 929–940.

3. **Cytron, R., Ferrante, J., Rosen, B. K., Wegman, M. N., & Zadeck, F. K.** (1991). Efficiently computing static single assignment form and the control dependence graph. *ACM TOPLAS*, 13(4), 451–490.

4. **Kildall, G. A.** (1973). A Unified Approach to Global Program Optimization. *POPL '73*, 194–206.

5. **Kam, J. B. & Ullman, J. D.** (1977). Monotone Data Flow Analysis Frameworks. *Acta Informatica*, 7, 305–317.

6. **Møller, A. & Schwartzbach, M. I.** (2024). *Static Program Analysis*. Department of Computer Science, Aarhus University. (The constraint-based approach to analysis.)

7. **Ngo, M. N. & Tan, H. B. K.** (2008). Detecting Large Number of Denial of Service Attacks with Path-Oriented Program Analysis. *ICSE 2008*. (Path-oriented analysis methodology.)

8. **Balakrishnan, G. & Reps, T.** (2010). WYSINWYX: What You See Is Not What You eXecute. *ACM TOPLAS*, 32(6). (Binary-level analysis with value-set analysis.)

9. **Xie, Y. & Aiken, A.** (2005). Context- and Path-Sensitive Memory Leak Detection. *FSE 2005*. (The Saturn framework for leak detection.)

### 7.4 Appendix D: Performance Characteristics

| Analysis | Time Complexity | Space Complexity | Typical Runtime |
|---|---|---|---|
| CFG construction | $O(n)$ tokens | $O(n)$ | < 1ms per function |
| Dominator tree | $O(n^2)$ worst / $O(n)$ typical | $O(n)$ | < 1ms per function |
| Natural loops | $O(n + e)$ | $O(n)$ | < 1ms |
| Reaching defs | $O(n \cdot d)$ where $d = |\text{defs}|$ | $O(n \cdot d)$ | 1–10ms |
| Live variables | $O(n \cdot v)$ where $v = |\text{vars}|$ | $O(n \cdot v)$ | 1–10ms |
| Available exprs | $O(n \cdot e)$ where $e = |\text{exprs}|$ | $O(n \cdot e)$ | 1–10ms |
| Taint analysis | $O(n \cdot v)$ | $O(n \cdot v)$ | 1–10ms |
| Loop invariants | $O(L \cdot I)$ iterations × loop size | $O(n)$ | 1–5ms per loop |
| Path analysis (k=64) | $O(k \cdot n)$ per function | $O(k \cdot v)$ | 10–100ms |
| Interval analysis | $O(n \cdot w)$ with widening $w$ rounds | $O(n \cdot v)$ | 5–20ms |
| Call graph | $O(n)$ tokens | $O(F^2)$ worst | < 5ms |

Where $n$ = number of basic blocks, $e$ = number of CFG edges, $F$ = number of functions.

### 7.5 Appendix E: Troubleshooting

| Problem | Cause | Solution |
|---|---|---|
| Empty CFG | Function has no body (declaration only) | Filter `scope.type == 'Function'` with `bodyStart` |
| Missing ValueFlow | Cppcheck run without `--dump` or with `--max-configs=0` | Use `cppcheck --dump --max-configs=1 source.c` |
| Analysis returns empty | Configuration mismatch | Ensure you're iterating the correct configuration |
| Slow performance | Large function with many paths | Reduce `k_limit` in path analysis; use coarser analyses first |
| Incorrect dominator tree | Unreachable blocks in CFG | Clean unreachable blocks before analysis |
| Loop not detected | Structured loop compiled to `goto` | Ensure dump was generated without aggressive preprocessing |

---

*This Vade Mecum was prepared as a comprehensive reference for the `cppcheckdata-shims` library, integrating implementation details with the theoretical foundations of static program analysis. For the latest updates, consult the source modules directly.*