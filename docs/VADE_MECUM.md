

# Vade Mecum: The `cppcheckdata-shims` Library

## A Comprehensive Practitioner's Guide

---

## Preface

This document is the definitive guide to the `cppcheckdata-shims` library — a collection of Python modules that layer static-analysis infrastructure on top of the raw `cppcheckdata` API provided by Cppcheck. Where `cppcheckdata.py` gives you access to tokens, scopes, variables, and AST nodes parsed from Cppcheck's XML dump files, `cppcheckdata-shims` provides the theoretical and algorithmic machinery to *reason* about programs: control-flow graphs, dataflow analysis, abstract interpretation, interprocedural analysis, symbolic execution, call graphs, constraint solving, and more.

This guide does **not** cover CASL (the Cppcheck Addon Specification Language); that is a separate system documented elsewhere. Here, we treat `cppcheckdata-shims` as a standalone Python library for building Cppcheck addons by hand, or for use as an infrastructure layer by any tool that needs to perform static analysis over Cppcheck dump data.

### Who This Guide Is For

- **Addon authors** who want to write sophisticated Cppcheck addons that go beyond token-level pattern matching
- **Static analysis researchers** who want a rapid prototyping environment grounded in real-world C/C++ analysis
- **Tool developers** integrating Cppcheck's front-end with custom analysis back-ends

### Conventions

Throughout this document:
- Module references use the dotted form: `cppcheckdata_shims.ctrlflow_graph`
- Code examples assume you have `cppcheckdata.py` on your Python path and have a Cppcheck dump file ready
- Lattice-theoretic concepts are explained inline; familiarity with Møller & Schwartzbach's *Static Program Analysis* or equivalent material is helpful but not required

---

## Part I: Foundations

---

## 1. Architecture Overview

The library is organized into 15 modules, each addressing a distinct concern in static program analysis. They form a layered architecture:

┌─────────────────────────────────────────────────────────────┐
│                     User Addons / Checkers                  │
├─────────────────────────────────────────────────────────────┤
│   checkers.py          │   qscore.py                       │
│   (Checker Framework)  │   (Quality Scoring)               │
├────────────────────────┴────────────────────────────────────┤
│   constraint_engine.py │   symbolic_exec.py                │
│   (Constraint Solving) │   (Symbolic Execution)            │
├────────────────────────┴────────────────────────────────────┤
│   interproc_analysis.py│   distrib_analysis.py             │
│   (Interprocedural)    │   (Distributed/Modular)           │
├────────────────────────┴────────────────────────────────────┤
│   dataflow_analysis.py │   dataflow_engine.py              │
│   (Classical Dataflow) │   (Fixed-Point Engine)            │
├────────────────────────┴────────────────────────────────────┤
│   abstract_interp.py   │   abstract_domains.py             │
│   (Abstract Interp.)   │   (Lattices & Domains)            │
├────────────────────────┴────────────────────────────────────┤
│   ctrlflow_graph.py    │   ctrlflow_analysis.py            │
│   (CFG Construction)   │   (CFG-Based Analyses)            │
├────────────────────────┴────────────────────────────────────┤
│   callgraph.py         │   memory_abstraction.py           │
│   (Call Graph)         │   (Memory Model)                  │
├────────────────────────┴────────────────────────────────────┤
│   type_analysis.py                                         │
│   (Type Inference & Checking)                              │
├─────────────────────────────────────────────────────────────┤
│                   cppcheckdata.py (Cppcheck)                │
└─────────────────────────────────────────────────────────────┘


### Dependency Flow

The modules have a well-defined dependency structure. Lower layers know nothing about higher layers:

$$
\texttt{cppcheckdata} \leftarrow \texttt{ctrlflow\_graph} \leftarrow \texttt{dataflow\_engine} \leftarrow \texttt{abstract\_interp} \leftarrow \texttt{checkers}
$$

This means you can use the CFG module without pulling in the constraint engine, or use abstract domains without the checker framework.

---

## 2. Installation and Setup

### Prerequisites

- Python 3.8 or later
- Cppcheck (for generating dump files)
- The `cppcheckdata.py` module (ships with Cppcheck)

### Generating a Dump File

Before using any shim module, you need a Cppcheck dump file. Generate one with:

```bash
cppcheck --dump myfile.c
```

This produces `myfile.c.dump`, an XML file containing the token list, AST, scope information, variable declarations, and value-flow data that Cppcheck computed during parsing.

For C++ with includes:

```bash
cppcheck --dump --std=c++17 -I /usr/include myfile.cpp
```

### Loading a Dump File

```python
import cppcheckdata

data = cppcheckdata.parsedump("myfile.c.dump")

for cfg in data.configurations:
    # cfg.tokenlist  — list of Token objects
    # cfg.scopes     — list of Scope objects
    # cfg.functions  — list of Function objects
    # cfg.variables  — list of Variable objects
    print(f"Configuration: {cfg.name}")
    for token in cfg.tokenlist:
        print(f"  {token.file}:{token.linenr}:{token.column}  {token.str}")
```

### Understanding the Cppcheck Data Model

Before diving into the shims, you must understand what `cppcheckdata.py` provides. The key classes are:

| Class | Description | Key Attributes |
|-------|-------------|----------------|
| `Token` | A single token in the source | `.str`, `.next`, `.previous`, `.scope`, `.variable`, `.function`, `.astParent`, `.astOperand1`, `.astOperand2`, `.values`, `.valueType`, `.file`, `.linenr`, `.column`, `.varId`, `.isName`, `.isOp`, `.isNumber`, `.isString` |
| `Scope` | A lexical scope (function, class, if, while, etc.) | `.type`, `.className`, `.function`, `.bodyStart`, `.bodyEnd`, `.nestedIn` |
| `Variable` | A declared variable | `.nameToken`, `.typeStartToken`, `.typeEndToken`, `.isArgument`, `.isLocal`, `.isGlobal`, `.isPointer`, `.isArray`, `.isConst` |
| `Function` | A function declaration | `.name`, `.tokenDef`, `.token`, `.argument`, `.isVirtual`, `.isStatic` |
| `ValueType` | Type information on a token | `.type`, `.sign`, `.pointer`, `.constness`, `.originalTypeName` |
| `Value` | A value-flow value on a token | `.intvalue`, `.floatvalue`, `.tokvalue`, `.valueKind`, `.condition` |

The token list is a doubly-linked list; each token has `.next` and `.previous`. The AST is overlaid on the token list: each token has `.astParent`, `.astOperand1`, `.astOperand2`. Braces, brackets, and parentheses are linked via `.link`.

---

## Part II: Control Flow

---

## 3. `ctrlflow_graph` — Control Flow Graph Construction

### 3.1 Theoretical Background

A **control flow graph** (CFG) is a directed graph $G = (N, E, n_{\text{entry}}, n_{\text{exit}})$ where:

- $N$ is a set of **basic blocks** (maximal sequences of instructions with no branches except at the end)
- $E \subseteq N \times N$ is a set of **edges** representing possible transfers of control
- $n_{\text{entry}} \in N$ is the unique entry node
- $n_{\text{exit}} \in N$ is the unique exit node

For every execution of the program, the sequence of basic blocks visited forms a **path** in the CFG. The CFG is the fundamental data structure for nearly all intraprocedural analyses.

As Møller and Schwartzbach note: "The control flow graph is a common representation of the possible flow of control during execution. It provides the foundation for dataflow analysis."

### 3.2 Building a CFG

```python
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder, BasicBlock, CFG

import cppcheckdata

data = cppcheckdata.parsedump("example.c.dump")
cfg_data = data.configurations[0]

# Build CFGs for all functions in the configuration
builder = CFGBuilder()
cfgs = builder.build_all(cfg_data)

for func_name, cfg in cfgs.items():
    print(f"Function: {func_name}")
    print(f"  Entry block: {cfg.entry}")
    print(f"  Exit block:  {cfg.exit}")
    print(f"  Block count: {len(cfg.blocks)}")
```

### 3.3 The `CFG` Class

The `CFG` object exposes the graph structure:

```python
# Iterate over all basic blocks
for block in cfg.blocks:
    print(f"Block {block.id}:")
    
    # Tokens in this block (the "statements")
    for token in block.tokens:
        print(f"  {token.str}", end=" ")
    print()
    
    # Successors (outgoing edges)
    for succ in block.successors:
        print(f"  → Block {succ.id}")
    
    # Predecessors (incoming edges)
    for pred in block.predecessors:
        print(f"  ← Block {pred.id}")
```

### 3.4 Edge Types

CFG edges carry labels indicating the kind of control transfer:

```python
from cppcheckdata_shims.ctrlflow_graph import EdgeKind

for block in cfg.blocks:
    for succ, kind in block.successor_edges:
        if kind == EdgeKind.TRUE_BRANCH:
            print(f"  Block {block.id} →(true) Block {succ.id}")
        elif kind == EdgeKind.FALSE_BRANCH:
            print(f"  Block {block.id} →(false) Block {succ.id}")
        elif kind == EdgeKind.UNCONDITIONAL:
            print(f"  Block {block.id} → Block {succ.id}")
        elif kind == EdgeKind.BACK_EDGE:
            print(f"  Block {block.id} →(back) Block {succ.id}")
        elif kind == EdgeKind.EXCEPTION:
            print(f"  Block {block.id} →(exc) Block {succ.id}")
```

### 3.5 Handling Loops

Loops in the CFG are identified by **back edges** — edges from a node to one of its dominators. The CFG builder marks these during construction:

```python
# Get all loops in the CFG
loops = cfg.find_loops()

for loop in loops:
    print(f"Loop header: Block {loop.header.id}")
    print(f"Loop body blocks: {[b.id for b in loop.body]}")
    print(f"Back edges from: {[b.id for b in loop.back_edge_sources]}")
    print(f"Exit edges to:   {[b.id for b in loop.exit_targets]}")
    print(f"Nesting depth:   {loop.depth}")
```

This uses the natural loop identification algorithm: a natural loop for a back edge $n \to h$ is the set of all nodes $m$ such that $h$ dominates $m$ and there exists a path from $m$ to $n$ not passing through $h$.

### 3.6 Visualization

The companion script `scripts/dump2dot.py` can render CFGs as Graphviz DOT files:

```bash
python scripts/dump2dot.py example.c.dump --function main -o main.dot
dot -Tpng main.dot -o main.png
```

Programmatically:

```python
dot_source = cfg.to_dot(
    show_tokens=True,      # Show token text in blocks
    show_line_numbers=True, # Annotate with source lines
    highlight_loops=True,   # Color loop headers
)
with open("cfg.dot", "w") as f:
    f.write(dot_source)
```

---

## 4. `ctrlflow_analysis` — CFG-Based Analyses

### 4.1 Dominance

A node $d$ **dominates** a node $n$ (written $d \text{ dom } n$) if every path from the entry node to $n$ must pass through $d$. The **immediate dominator** $\text{idom}(n)$ is the closest strict dominator of $n$.

```python
from cppcheckdata_shims.ctrlflow_analysis import (
    compute_dominators,
    compute_dominator_tree,
    compute_dominance_frontier,
    compute_post_dominators,
)

# Compute the dominator relation
dom = compute_dominators(cfg)

# Check if block A dominates block B
if dom.dominates(block_a, block_b):
    print(f"Block {block_a.id} dominates Block {block_b.id}")

# Get the immediate dominator
idom = dom.idom(block_b)
print(f"idom({block_b.id}) = {idom.id}")

# Get the dominator tree
dom_tree = compute_dominator_tree(cfg)
for node, children in dom_tree.items():
    print(f"  {node.id} → {[c.id for c in children]}")
```

### 4.2 Dominance Frontiers

The **dominance frontier** of a node $n$, written $\text{DF}(n)$, is the set of nodes where $n$'s dominance "ends" — the first nodes reachable from $n$ that $n$ does *not* dominate. Dominance frontiers are critical for SSA construction.

$$
\text{DF}(n) = \{ w \mid \exists v \in \text{succ}(w') \text{ with } n \text{ dom } w' \text{ and } n \not\text{sdom } w \}
$$

```python
df = compute_dominance_frontier(cfg)

for block in cfg.blocks:
    frontier = df[block]
    if frontier:
        print(f"DF({block.id}) = {{{', '.join(str(b.id) for b in frontier)}}}")
```

### 4.3 Post-Dominance

Post-dominance is the dual of dominance: $p$ **post-dominates** $n$ if every path from $n$ to the exit must pass through $p$. This is equivalent to computing dominance on the reversed CFG.

```python
pdom = compute_post_dominators(cfg)

if pdom.post_dominates(block_p, block_n):
    print(f"Block {block_p.id} post-dominates Block {block_n.id}")
```

### 4.4 Reachability

```python
from cppcheckdata_shims.ctrlflow_analysis import (
    compute_reachability,
    find_all_paths,
    is_reachable,
)

# Check if one block can reach another
if is_reachable(cfg, block_a, block_b):
    print("Reachable!")

# Find all simple paths (warning: exponential in pathological cases)
paths = find_all_paths(cfg, block_a, block_b, max_paths=100)
for path in paths:
    print(" → ".join(str(b.id) for b in path))
```

### 4.5 Loop Analysis

Beyond finding loops (covered in §3.5), the analysis module provides deeper loop characterization:

```python
from cppcheckdata_shims.ctrlflow_analysis import (
    compute_loop_nesting,
    find_loop_invariants,
    classify_loop_exits,
)

# Compute the loop nesting tree
nesting = compute_loop_nesting(cfg)
for loop, depth in nesting.items():
    print(f"Loop at Block {loop.header.id}: depth {depth}")

# Find loop-invariant statements
# A statement is loop-invariant if all its operands are defined
# outside the loop or are themselves loop-invariant
invariants = find_loop_invariants(cfg, loop)
for token in invariants:
    print(f"  Loop-invariant: {token.str} at {token.file}:{token.linenr}")
```

---

## Part III: Data Flow Analysis

---

## 5. `abstract_domains` — Lattices and Abstract Domains

### 5.1 Lattice Theory Primer

A **lattice** $(L, \sqsubseteq)$ is a partially ordered set where every pair of elements has a unique **join** (least upper bound, $\sqcup$) and **meet** (greatest lower bound, $\sqcap$). A **complete lattice** additionally has a **bottom** element $\bot$ (smaller than everything) and a **top** element $\top$ (larger than everything).

In static analysis, we use lattices to represent *abstract values* — approximations of the concrete values a variable might hold at runtime. The ordering $a \sqsubseteq b$ means "the information in $a$ is at least as precise as in $b$" (or equivalently, "$b$ is a safe approximation of $a$").

### 5.2 Built-In Domains

The library provides several pre-built abstract domains:

```python
from cppcheckdata_shims.abstract_domains import (
    SignDomain,
    NullnessDomain,
    TaintDomain,
    IntervalDomain,
    ConstantPropDomain,
    ParityDomain,
    BoolDomain,
    TypeStateDomain,
    PointerDomain,
)
```

#### Sign Domain

The **sign domain** abstracts integers to their sign:

$$
L_{\text{sign}} = \{ \bot, \texttt{Neg}, \texttt{Zero}, \texttt{Pos}, \texttt{NonNeg}, \texttt{NonPos}, \texttt{NonZero}, \top \}
$$

```python
sign = SignDomain()

# Abstract values
print(sign.abstract(42))    # → Pos
print(sign.abstract(0))     # → Zero
print(sign.abstract(-7))    # → Neg

# Join (least upper bound)
print(sign.join("Pos", "Zero"))   # → NonNeg
print(sign.join("Pos", "Neg"))    # → NonZero
print(sign.join("Pos", "Neg", "Zero"))  # → Top

# Meet (greatest lower bound)
print(sign.meet("NonNeg", "NonPos"))  # → Zero

# Transfer functions for arithmetic
print(sign.add("Pos", "Pos"))    # → Pos
print(sign.add("Pos", "Neg"))    # → Top
print(sign.mul("Neg", "Neg"))    # → Pos
print(sign.mul("Pos", "Zero"))   # → Zero
```

#### Nullness Domain

Tracks whether a pointer is definitely null, definitely non-null, or unknown:

$$
L_{\text{null}} = \{ \bot, \texttt{Null}, \texttt{NonNull}, \top \}
$$

```python
null = NullnessDomain()

print(null.join("Null", "NonNull"))  # → Top (maybe null)
print(null.meet("Top", "NonNull"))   # → NonNull
print(null.is_safe("NonNull"))       # → True (safe to dereference)
print(null.is_safe("Top"))           # → False (might be null)
```

#### Taint Domain

Tracks whether data originates from an untrusted source:

$$
L_{\text{taint}} = \{ \bot, \texttt{Untainted}, \texttt{Tainted}, \top \}
$$

```python
taint = TaintDomain()

# Mark a value as tainted
val = taint.taint("Untainted")  # → Tainted

# Check if tainted
print(taint.is_tainted("Tainted"))     # → True
print(taint.is_tainted("Untainted"))   # → False
print(taint.is_tainted("Top"))         # → True (conservatively)
```

#### Interval Domain

Represents sets of integers as intervals $[l, u]$:

$$
L_{\text{interval}} = \{ \bot \} \cup \{ [l, u] \mid l, u \in \mathbb{Z} \cup \{-\infty, +\infty\}, l \leq u \}
$$

```python
intv = IntervalDomain()

a = intv.interval(0, 10)    # [0, 10]
b = intv.interval(5, 20)    # [5, 20]

print(intv.join(a, b))      # [0, 20]
print(intv.meet(a, b))      # [5, 10]
print(intv.add(a, b))       # [5, 30]
print(intv.contains(a, 7))  # True
print(intv.contains(a, 15)) # False

# Widening (for convergence on loops)
c = intv.interval(0, 100)
print(intv.widen(a, c))     # [0, +∞)
```

#### Constant Propagation Domain

$$
L_{\text{const}} = \{ \bot, \top \} \cup \mathbb{Z}
$$

```python
cp = ConstantPropDomain()

print(cp.join(42, 42))    # → 42 (same constant)
print(cp.join(42, 43))    # → Top (not a constant)
print(cp.transfer_add(3, 4))  # → 7
print(cp.transfer_add(3, "Top"))  # → Top
```

### 5.3 Defining Custom Domains

All domains implement the `AbstractDomain` protocol:

```python
from cppcheckdata_shims.abstract_domains import AbstractDomain

class MyDomain(AbstractDomain):
    """Example: a three-valued domain for resource state."""
    
    # The lattice elements
    BOTTOM = "⊥"
    OPENED = "Opened"
    CLOSED = "Closed"
    TOP = "⊤"
    
    def bottom(self):
        return self.BOTTOM
    
    def top(self):
        return self.TOP
    
    def leq(self, a, b):
        """Partial order: a ⊑ b"""
        if a == self.BOTTOM or b == self.TOP:
            return True
        return a == b
    
    def join(self, a, b):
        """Least upper bound: a ⊔ b"""
        if a == self.BOTTOM:
            return b
        if b == self.BOTTOM:
            return a
        if a == b:
            return a
        return self.TOP
    
    def meet(self, a, b):
        """Greatest lower bound: a ⊓ b"""
        if a == self.TOP:
            return b
        if b == self.TOP:
            return a
        if a == b:
            return a
        return self.BOTTOM
    
    def widen(self, a, b):
        """Widening operator (for this finite domain, join suffices)."""
        return self.join(a, b)
```

### 5.4 Product Domains

You can combine domains into product domains for richer analyses:

```python
from cppcheckdata_shims.abstract_domains import ProductDomain

# Track both nullness and taint simultaneously
combined = ProductDomain(NullnessDomain(), TaintDomain())

val = combined.bottom()
val = combined.set_component(val, 0, "NonNull")
val = combined.set_component(val, 1, "Tainted")

print(combined.get_component(val, 0))  # → NonNull
print(combined.get_component(val, 1))  # → Tainted
```

### 5.5 Map Domains (Environments)

An **environment** maps variables to abstract values. This is modeled as a map domain:

$$
\text{Env} = \text{Var} \to L
$$

```python
from cppcheckdata_shims.abstract_domains import MapDomain

env_domain = MapDomain(SignDomain())

env1 = env_domain.bottom()
env1 = env_domain.set(env1, "x", "Pos")
env1 = env_domain.set(env1, "y", "Neg")

env2 = env_domain.bottom()
env2 = env_domain.set(env2, "x", "Zero")
env2 = env_domain.set(env2, "y", "Neg")

# Join of environments (pointwise join)
merged = env_domain.join(env1, env2)
print(env_domain.get(merged, "x"))  # → NonNeg (Pos ⊔ Zero)
print(env_domain.get(merged, "y"))  # → Neg (Neg ⊔ Neg)
```

---

## 6. `dataflow_analysis` — Classical Dataflow Analysis

### 6.1 The Dataflow Analysis Framework

A dataflow analysis computes, for each program point, an abstract value that conservatively approximates some property of all possible executions reaching that point. The classical formulation uses the CFG and defines:

- A **domain** (lattice) $L$
- A **transfer function** $f_n : L \to L$ for each CFG node $n$
- A **merge operator** (join or meet) at confluence points
- A **direction** (forward or backward)

The analysis computes the least (or greatest) fixed point:

$$
\text{out}(n) = f_n(\text{in}(n)), \quad \text{in}(n) = \bigsqcup_{p \in \text{pred}(n)} \text{out}(p)
$$

### 6.2 Defining an Analysis

```python
from cppcheckdata_shims.dataflow_analysis import (
    ForwardAnalysis,
    BackwardAnalysis,
    DataflowResult,
)
from cppcheckdata_shims.abstract_domains import SignDomain

class SignAnalysis(ForwardAnalysis):
    """Determine the sign of each variable at each program point."""
    
    def __init__(self):
        super().__init__(
            domain=MapDomain(SignDomain()),
            direction="forward",
        )
        self._sign = SignDomain()
    
    def transfer(self, block, in_state):
        """Transfer function for a basic block."""
        state = in_state.copy()
        
        for token in block.tokens:
            # Handle assignment: x = expr
            if token.isAssignmentOp and token.str == "=":
                lhs = token.astOperand1
                rhs = token.astOperand2
                
                if lhs and lhs.variable:
                    var_name = lhs.variable.nameToken.str
                    rhs_sign = self._eval_sign(rhs, state)
                    state = self.domain.set(state, var_name, rhs_sign)
        
        return state
    
    def _eval_sign(self, token, state):
        """Evaluate the sign of an expression."""
        if token is None:
            return self._sign.top()
        
        # Constant integer
        if token.isNumber and token.isInt:
            value = int(token.str)
            return self._sign.abstract(value)
        
        # Variable reference
        if token.isName and token.variable:
            var_name = token.variable.nameToken.str
            return self.domain.get(state, var_name)
        
        # Binary operation
        if token.isBinaryOp():
            left = self._eval_sign(token.astOperand1, state)
            right = self._eval_sign(token.astOperand2, state)
            
            if token.str == "+":
                return self._sign.add(left, right)
            elif token.str == "-":
                return self._sign.sub(left, right)
            elif token.str == "*":
                return self._sign.mul(left, right)
        
        return self._sign.top()
    
    def initial_value(self):
        """Initial abstract state at the entry point."""
        return self.domain.bottom()
    
    def boundary_value(self):
        """Abstract state at the function entry (arguments are Top)."""
        return self.domain.top()
```

### 6.3 Running an Analysis

```python
from cppcheckdata_shims.dataflow_engine import DataflowEngine

# Build the CFG
builder = CFGBuilder()
cfgs = builder.build_all(cfg_data)
main_cfg = cfgs["main"]

# Create and run the analysis
analysis = SignAnalysis()
engine = DataflowEngine()
result = engine.run(analysis, main_cfg)

# Query results
for block in main_cfg.blocks:
    in_state = result.in_state(block)
    out_state = result.out_state(block)
    print(f"Block {block.id}:")
    print(f"  IN:  {in_state}")
    print(f"  OUT: {out_state}")
```

### 6.4 Built-In Analyses

The module ships with several pre-built analyses:

```python
from cppcheckdata_shims.dataflow_analysis import (
    ReachingDefinitions,
    LiveVariables,
    AvailableExpressions,
    VeryBusyExpressions,
    NullnessAnalysis,
    TaintAnalysis,
    ConstantPropagation,
    InitializationAnalysis,
)
```

#### Reaching Definitions

A definition $d: x = e$ at program point $p$ **reaches** a point $q$ if there is a path from $p$ to $q$ on which $x$ is not redefined. This is a forward, may-analysis (using join):

```python
rd = ReachingDefinitions()
result = engine.run(rd, main_cfg)

# At each point, which definitions might be current?
for block in main_cfg.blocks:
    reaching = result.out_state(block)
    for var, defs in reaching.items():
        print(f"  Variable '{var}' may be defined at: "
              f"{[d.linenr for d in defs]}")
```

#### Live Variables

A variable $x$ is **live** at a point $p$ if there exists a path from $p$ to a use of $x$ that does not pass through a definition of $x$. This is a backward, may-analysis:

```python
lv = LiveVariables()
result = engine.run(lv, main_cfg)

for block in main_cfg.blocks:
    live = result.in_state(block)
    print(f"Block {block.id}: live = {live}")
```

#### Available Expressions

An expression $e$ is **available** at a point $p$ if on *every* path from the entry to $p$, the expression $e$ has been computed and none of its operands have been redefined since. This is a forward, must-analysis (using meet):

```python
ae = AvailableExpressions()
result = engine.run(ae, main_cfg)
```

#### Nullness Analysis

```python
na = NullnessAnalysis()
result = engine.run(na, main_cfg)

# Find potential null dereferences
for block in main_cfg.blocks:
    state = result.in_state(block)
    for token in block.tokens:
        if token.str == "*" and token.isUnaryOp("*"):
            ptr = token.astOperand1
            if ptr and ptr.variable:
                nullness = state.get(ptr.variable.nameToken.str, "Top")
                if nullness in ("Null", "Top"):
                    print(f"WARNING: Potential null deref at "
                          f"{token.file}:{token.linenr}")
```

### 6.5 Understanding Fixed Points

The dataflow engine computes fixed points iteratively using a **worklist algorithm**:

Initialize all states to ⊥ (or boundary value for entry)
Add all blocks to the worklist
While worklist is not empty:
    Remove a block n from the worklist
    Compute in(n) = ⊔{out(p) | p ∈ pred(n)}
    Compute new_out = f_n(in(n))
    If new_out ≠ old_out(n):
        Set out(n) = new_out
        Add all successors of n to the worklist


The algorithm terminates because:
1. The domain is a lattice of finite height (or widening is applied)
2. Transfer functions are monotone: $a \sqsubseteq b \implies f(a) \sqsubseteq f(b)$
3. Each iteration moves states upward in the lattice, and there is a top element

### 6.6 Convergence and Widening

For domains of infinite height (like intervals), the fixed-point iteration may not terminate. **Widening** ensures convergence by extrapolating:

$$
a \nabla b = \begin{cases} a & \text{if } b \sqsubseteq a \\ \text{extrapolate} & \text{otherwise} \end{cases}
$$

```python
from cppcheckdata_shims.dataflow_engine import DataflowEngine

engine = DataflowEngine(
    max_iterations=1000,          # Safety limit
    use_widening=True,            # Enable widening
    widening_delay=3,             # Apply widening after 3 iterations
    use_narrowing=True,           # Refine with narrowing after convergence
    narrowing_iterations=2,       # Number of narrowing passes
)

result = engine.run(interval_analysis, cfg)
print(f"Converged in {result.iterations} iterations")
```

---

## 7. `dataflow_engine` — The Fixed-Point Engine

### 7.1 Engine Configuration

```python
from cppcheckdata_shims.dataflow_engine import DataflowEngine, WorklistStrategy

engine = DataflowEngine(
    strategy=WorklistStrategy.REVERSE_POSTORDER,
    max_iterations=10000,
    use_widening=True,
    widening_delay=5,
    use_narrowing=True,
    narrowing_iterations=3,
    trace=False,                  # Set True for debugging
)
```

### 7.2 Worklist Strategies

The order in which blocks are processed affects convergence speed:

| Strategy | Description | Best For |
|----------|-------------|----------|
| `FIFO` | Simple queue | General |
| `LIFO` | Stack-based | Depth-first exploration |
| `REVERSE_POSTORDER` | Process blocks in reverse post-order | Forward analyses (optimal for reducible CFGs) |
| `POSTORDER` | Process blocks in post-order | Backward analyses |
| `PRIORITY` | Configurable priority queue | Custom ordering |

For a forward analysis on a reducible CFG (one with no irreducible loops), reverse post-order processes each block at most $d + 2$ times, where $d$ is the loop nesting depth, achieving near-optimal convergence.

### 7.3 Tracing Execution

For debugging, enable tracing:

```python
engine = DataflowEngine(trace=True)
result = engine.run(analysis, cfg)

# The trace shows each iteration:
#   Iteration 1: processing Block 0
#     IN:  {x: ⊥, y: ⊥}
#     OUT: {x: Pos, y: ⊥}
#     Changed: True, adding successors [Block 1, Block 2]
#   Iteration 2: processing Block 1
#     ...
```

### 7.4 Result Queries

The `DataflowResult` object provides rich query capabilities:

```python
result = engine.run(analysis, cfg)

# State at block boundaries
in_state = result.in_state(block)
out_state = result.out_state(block)

# State at a specific token (interpolated)
state_at = result.state_at(token)

# Did the analysis converge?
print(result.converged)       # True/False
print(result.iterations)     # Number of iterations

# Performance metrics
print(result.elapsed_time)   # Wall-clock seconds
print(result.states_computed) # Total transfer function applications
```

---

## Part IV: Advanced Analyses

---

## 8. `abstract_interp` — Abstract Interpretation

### 8.1 From Dataflow to Abstract Interpretation

Abstract interpretation, formalized by Cousot & Cousot (1977), generalizes dataflow analysis. Where classical dataflow uses specific frameworks (gen/kill sets, bit vectors), abstract interpretation works with arbitrary lattices and provides a formal soundness guarantee through **Galois connections**.

A Galois connection between a concrete domain $C$ and an abstract domain $A$ is a pair of functions:

$$
\alpha : C \to A \quad \text{(abstraction)} \qquad \gamma : A \to C \quad \text{(concretization)}
$$

such that $\forall c \in C, a \in A: \alpha(c) \sqsubseteq a \iff c \sqsubseteq \gamma(a)$.

### 8.2 The Abstract Interpreter

```python
from cppcheckdata_shims.abstract_interp import (
    AbstractInterpreter,
    AbstractState,
    TransferFunction,
)

class MyInterpreter(AbstractInterpreter):
    """
    Abstract interpreter that tracks the sign and nullness
    of all variables simultaneously.
    """
    
    def __init__(self):
        super().__init__(
            domain=ProductDomain(
                MapDomain(SignDomain()),
                MapDomain(NullnessDomain()),
            ),
        )
    
    def interpret_assignment(self, state, lhs_var, rhs_token):
        """Abstract transfer for x = e."""
        signs, nulls = state
        
        # Compute the sign of the RHS
        rhs_sign = self.eval_sign(rhs_token, signs)
        signs = self.domain.components[0].set(signs, lhs_var, rhs_sign)
        
        # Compute nullness: if RHS is 0, pointer is null
        if rhs_sign == "Zero":
            nulls = self.domain.components[1].set(nulls, lhs_var, "Null")
        else:
            nulls = self.domain.components[1].set(nulls, lhs_var, "NonNull")
        
        return (signs, nulls)
    
    def interpret_condition(self, state, cond_token, branch):
        """
        Refine abstract state based on a branch condition.
        Called with branch=True for the true branch and
        branch=False for the false branch.
        """
        signs, nulls = state
        
        # Refine: if (ptr != NULL) on true branch → ptr is NonNull
        if (cond_token.str == "!=" and branch and
            cond_token.astOperand2 and 
            cond_token.astOperand2.str == "0"):
            ptr = cond_token.astOperand1
            if ptr and ptr.variable:
                var_name = ptr.variable.nameToken.str
                nulls = self.domain.components[1].set(
                    nulls, var_name, "NonNull"
                )
        
        return (signs, nulls)
```

### 8.3 Running the Interpreter

```python
interp = MyInterpreter()
result = interp.analyze(cfg)

# Query at any program point
for block in cfg.blocks:
    state = result.state_after(block)
    signs, nulls = state
    print(f"Block {block.id}:")
    print(f"  Signs:    {signs}")
    print(f"  Nullness: {nulls}")
```

### 8.4 Path-Sensitive Interpretation

The abstract interpreter can optionally maintain separate states for different paths, providing higher precision at the cost of exponential blowup:

```python
from cppcheckdata_shims.abstract_interp import PathSensitiveInterpreter

interp = PathSensitiveInterpreter(
    domain=MapDomain(NullnessDomain()),
    max_paths=64,         # Limit path explosion
    merge_threshold=32,   # Merge paths when count exceeds this
)

result = interp.analyze(cfg)

# Each program point may have multiple states (one per path)
for block in cfg.blocks:
    states = result.states_at(block)
    print(f"Block {block.id}: {len(states)} distinct path states")
    for i, state in enumerate(states):
        print(f"  Path {i}: {state}")
```

---

## 9. `callgraph` — Call Graph Construction

### 9.1 What Is a Call Graph?

A **call graph** is a directed graph where nodes represent functions and edges represent call relationships. An edge $(f, g)$ means that function $f$ may call function $g$.

The call graph is essential for interprocedural analysis — reasoning about the behavior of a program across function boundaries.

### 9.2 Building the Call Graph

```python
from cppcheckdata_shims.callgraph import CallGraphBuilder, CallGraph

import cppcheckdata

data = cppcheckdata.parsedump("project.c.dump")
cfg_data = data.configurations[0]

builder = CallGraphBuilder()
cg = builder.build(cfg_data)

# Iterate over all functions
for func_node in cg.nodes:
    print(f"Function: {func_node.name}")
    print(f"  Defined at: {func_node.file}:{func_node.line}")
    
    # Who does this function call?
    for callee in cg.callees(func_node):
        print(f"  Calls: {callee.name}")
    
    # Who calls this function?
    for caller in cg.callers(func_node):
        print(f"  Called by: {caller.name}")
```

### 9.3 Call Sites

Each edge in the call graph is annotated with the specific call site(s):

```python
for edge in cg.edges:
    print(f"{edge.caller.name} → {edge.callee.name}")
    for site in edge.call_sites:
        print(f"  at {site.file}:{site.linenr}: {site.token.str}(...)")
```

### 9.4 Indirect Calls and Virtual Dispatch

For function pointers and virtual method calls, the call graph may have edges to multiple potential targets:

```python
# Get all indirect call sites
for site in cg.indirect_call_sites:
    print(f"Indirect call at {site.file}:{site.linenr}")
    targets = cg.resolve_indirect(site)
    for target in targets:
        print(f"  Possible target: {target.name}")
```

### 9.5 Graph Properties

```python
# Strongly connected components (recursive call chains)
sccs = cg.strongly_connected_components()
for scc in sccs:
    if len(scc) > 1:
        names = [n.name for n in scc]
        print(f"Mutual recursion: {' ↔ '.join(names)}")

# Topological ordering (for bottom-up analysis)
order = cg.topological_order()
for func in order:
    print(f"  {func.name}")

# Reachability
reachable = cg.reachable_from("main")
print(f"Functions reachable from main: {len(reachable)}")

# Root functions (not called by anyone)
roots = cg.roots()
print(f"Root functions: {[r.name for r in roots]}")

# Leaf functions (don't call anything)
leaves = cg.leaves()
print(f"Leaf functions: {[l.name for l in leaves]}")
```

### 9.6 Visualization

```python
dot = cg.to_dot(
    highlight_recursive=True,
    cluster_by_file=True,
)
with open("callgraph.dot", "w") as f:
    f.write(dot)
```

---

## 10. `interproc_analysis` — Interprocedural Analysis

### 10.1 Context Sensitivity

Intraprocedural analysis treats each function in isolation. Interprocedural analysis reasons across function boundaries. A key challenge is **context sensitivity**: when function $f$ is called from two different call sites with different arguments, should we merge the results or keep them separate?

The library supports several context-sensitivity policies:

| Policy | Description | Precision | Cost |
|--------|-------------|-----------|------|
| Context-insensitive | Single summary per function | Low | $O(n)$ |
| Call-string $k$ | Distinguish last $k$ call sites | Medium | $O(n \cdot |CS|^k)$ |
| Functional | Full input-output summaries | High | $O(n \cdot |L|)$ |

### 10.2 Using the Interprocedural Framework

```python
from cppcheckdata_shims.interproc_analysis import (
    InterproceduralAnalysis,
    ContextPolicy,
    CallString,
    FunctionalApproach,
)

class InterNullness(InterproceduralAnalysis):
    """Interprocedural nullness analysis."""
    
    def __init__(self):
        super().__init__(
            intraprocedural=NullnessAnalysis(),
            context_policy=ContextPolicy.CALL_STRING_K(k=2),
        )
    
    def summarize_call(self, callee, args_state, context):
        """
        Called when we encounter a call to `callee`.
        Returns the abstract state after the call.
        """
        # Look up or compute the summary for this callee in this context
        summary = self.get_summary(callee, context)
        if summary is None:
            # Analyze the callee with the given argument state
            summary = self.analyze_callee(callee, args_state, context)
            self.set_summary(callee, context, summary)
        
        return summary.apply(args_state)
    
    def transfer_return(self, return_state, caller_state):
        """Transfer function for return from a call."""
        # Merge return value information into the caller's state
        return caller_state.merge_return(return_state)
```

### 10.3 Bottom-Up Analysis

For non-recursive programs, a bottom-up traversal of the call graph is efficient:

```python
from cppcheckdata_shims.interproc_analysis import BottomUpAnalyzer

analyzer = BottomUpAnalyzer(
    intraprocedural_factory=lambda: NullnessAnalysis(),
    call_graph=cg,
    cfgs=cfgs,
)

results = analyzer.analyze()

# Results are indexed by (function, context)
for (func_name, context), result in results.items():
    print(f"{func_name} [{context}]:")
    print(f"  Summary: {result.summary}")
```

### 10.4 Handling Recursion

For recursive functions, the analysis uses fixed-point iteration over the call graph's strongly connected components:

```python
from cppcheckdata_shims.interproc_analysis import SCCAnalyzer

analyzer = SCCAnalyzer(
    intraprocedural_factory=lambda: SignAnalysis(),
    call_graph=cg,
    cfgs=cfgs,
    max_context_depth=3,
)

results = analyzer.analyze()
```

---

## 11. `memory_abstraction` — Abstract Memory Model

### 11.1 Points-To Analysis

Pointer analysis determines which memory locations a pointer variable might point to. The `memory_abstraction` module provides several levels of precision:

```python
from cppcheckdata_shims.memory_abstraction import (
    PointsToAnalysis,
    AllocationSite,
    MemoryLocation,
    AbstractHeap,
)

pta = PointsToAnalysis(
    heap_model="allocation-site",  # Each malloc site is a distinct object
    field_sensitive=True,          # Distinguish struct fields
    flow_sensitive=True,           # Track changes across program points
)

result = pta.analyze(cfg)

# Query: what does pointer p point to at a given block?
targets = result.points_to("p", block)
for target in targets:
    print(f"  p may point to: {target}")
```

### 11.2 Alias Analysis

Two pointers **may-alias** if they might point to the same memory location:

```python
from cppcheckdata_shims.memory_abstraction import AliasAnalysis

alias = AliasAnalysis(pta_result=result)

# Check if two pointers may alias
if alias.may_alias("p", "q", at_block=block):
    print("p and q may alias!")

if alias.must_alias("p", "q", at_block=block):
    print("p and q definitely alias!")
```

### 11.3 Abstract Heap

The abstract heap models dynamically allocated memory:

```python
heap = AbstractHeap()

# Model: p = malloc(sizeof(int))
loc = heap.allocate(site=token, type_info="int*")

# Model: *p = 42
heap.store(loc, offset=0, value=abstract_42)

# Model: x = *p
val = heap.load(loc, offset=0)

# Model: free(p)
heap.deallocate(loc)

# Query: is this location allocated?
print(heap.is_allocated(loc))  # False (we freed it)
```

---

## 12. `symbolic_exec` — Symbolic Execution

### 12.1 Overview

Symbolic execution runs the program with **symbolic values** instead of concrete values. Instead of $x = 5$, we have $x = \alpha$ where $\alpha$ is a fresh symbol. Conditions along the path accumulate into a **path condition** $\pi$, and at each branch, the engine forks into two states:

$$
\pi_{\text{true}} = \pi \wedge c, \qquad \pi_{\text{false}} = \pi \wedge \neg c
$$

### 12.2 Using the Symbolic Engine

```python
from cppcheckdata_shims.symbolic_exec import (
    SymbolicExecutor,
    SymbolicState,
    PathCondition,
    SymbolicValue,
)

executor = SymbolicExecutor(
    cfg=main_cfg,
    max_depth=50,         # Maximum path length
    max_paths=1000,       # Maximum number of paths to explore
    solver="builtin",     # Use built-in constraint solver
)

# Execute symbolically
for path_result in executor.execute():
    print(f"Path condition: {path_result.path_condition}")
    print(f"  Feasible: {path_result.is_feasible}")
    print(f"  Final state: {path_result.state}")
    
    # Check a property along this path
    for token in path_result.visited_tokens:
        if token.str == "/" and token.isArithmeticalOp:
            divisor = path_result.state.get_symbolic(token.astOperand2)
            # Can divisor be zero?
            if executor.solver.is_satisfiable(
                path_result.path_condition & (divisor == 0)
            ):
                print(f"  ⚠ Possible division by zero at "
                      f"{token.file}:{token.linenr}")
```

### 12.3 Symbolic Values and Expressions

```python
from cppcheckdata_shims.symbolic_exec import Sym

# Create symbolic variables
x = Sym.var("x")
y = Sym.var("y")

# Build expressions
expr = (x + y) * Sym.const(2) - Sym.const(1)
print(expr)  # ((x + y) * 2) - 1

# Create constraints
constraint = (x > 0) & (y < 10) & (x + y == 15)
print(constraint)
```

### 12.4 Path Exploration Strategies

```python
from cppcheckdata_shims.symbolic_exec import ExplorationStrategy

executor = SymbolicExecutor(
    cfg=main_cfg,
    strategy=ExplorationStrategy.DFS,      # Depth-first
    # strategy=ExplorationStrategy.BFS,    # Breadth-first
    # strategy=ExplorationStrategy.RANDOM, # Random path selection
    # strategy=ExplorationStrategy.COVERAGE_GUIDED,  # Maximize coverage
)
```

---

## 13. `constraint_engine` — Constraint Solving

### 13.1 The Constraint Language

The constraint engine solves systems of constraints over abstract values. This is used internally by several analyses but can also be used directly:

```python
from cppcheckdata_shims.constraint_engine import (
    ConstraintEngine,
    Var,
    Constraint,
    SubsetConstraint,
    ConditionalConstraint,
)

engine = ConstraintEngine()

# Declare constraint variables
x = engine.var("x")
y = engine.var("y")
z = engine.var("z")

# Add constraints
engine.add(SubsetConstraint(x, y))           # x ⊆ y
engine.add(SubsetConstraint(y, z))           # y ⊆ z
engine.add(Constraint.eq(x, {"Pos", "Zero"}))  # x = {Pos, Zero}

# Solve
solution = engine.solve()
print(solution["x"])  # {Pos, Zero}
print(solution["y"])  # {Pos, Zero}  (from x ⊆ y)
print(solution["z"])  # {Pos, Zero}  (from y ⊆ z)
```

### 13.2 Conditional Constraints

```python
# If x contains Tainted, then y must contain Tainted
engine.add(ConditionalConstraint(
    condition=lambda sol: "Tainted" in sol["x"],
    then_constraint=SubsetConstraint({"Tainted"}, y),
))
```

### 13.3 Applications

The constraint engine is used internally for:

- **Type inference** (unification-based constraint solving)
- **Points-to analysis** (subset constraints on points-to sets)
- **Taint analysis** (propagation constraints)
- **Abstract interpretation** (fixed-point computation over constraint systems)

---

## 14. `type_analysis` — Type Inference and Checking

### 14.1 Type System

The type analysis module provides a type inference engine that works independently of (and can augment) Cppcheck's built-in type information:

```python
from cppcheckdata_shims.type_analysis import (
    TypeAnalyzer,
    TypeConstraint,
    TypeScheme,
    TypeEnv,
)

analyzer = TypeAnalyzer()
type_env = analyzer.analyze(cfg)

# Query the inferred type of a variable
for var in cfg_data.variables:
    inferred = type_env.get(var.nameToken.str)
    cppcheck_type = var.typeStartToken.str if var.typeStartToken else "?"
    print(f"  {var.nameToken.str}: declared={cppcheck_type}, inferred={inferred}")
```

### 14.2 Augmented Type Information

The type analyzer can infer properties that Cppcheck's front-end does not track:

```python
# Is this expression a function pointer?
tp = type_env.get_expr_type(token)
if tp.is_function_pointer():
    print(f"Token '{token.str}' is a function pointer")
    print(f"  Points to: {tp.target_signature}")

# What are the possible concrete types at this polymorphic call site?
if tp.is_polymorphic():
    for concrete_type in tp.possible_types():
        print(f"  Could be: {concrete_type}")
```

### 14.3 Typestate Analysis

Track protocols (sequences of operations) that types must follow:

```python
from cppcheckdata_shims.type_analysis import TypestateAnalysis

# Define a typestate for file handles
filestate = TypestateAnalysis(
    type_name="FILE*",
    states=["Unopened", "Open", "Closed", "Error"],
    initial_state="Unopened",
    transitions={
        ("Unopened", "fopen"):  "Open",
        ("Open",     "fread"):  "Open",
        ("Open",     "fwrite"): "Open",
        ("Open",     "fclose"): "Closed",
        ("Closed",   "fclose"): "Error",    # Double close!
    },
    error_states=["Error"],
    must_reach=["Closed"],  # Must close before scope exit
)

results = filestate.analyze(cfg)
for violation in results.violations:
    print(f"Typestate violation: {violation.message}")
    print(f"  at {violation.file}:{violation.linenr}")
```

---

## Part V: Checker Framework

---

## 15. `checkers` — Writing Checkers

### 15.1 The Checker API

The `checkers` module provides a framework for writing Cppcheck addons that uses the analysis infrastructure:

```python
from cppcheckdata_shims.checkers import (
    Checker,
    CheckerResult,
    Finding,
    Severity,
    register_checker,
)

class NullDerefChecker(Checker):
    """
    Detect potential null pointer dereferences using
    the nullness dataflow analysis.
    """
    
    name = "null-deref"
    description = "Detect potential null pointer dereferences"
    severity = Severity.ERROR
    
    def check(self, cfg, cfg_data):
        """Run the checker on a single function's CFG."""
        # Run nullness analysis
        analysis = NullnessAnalysis()
        engine = DataflowEngine()
        result = engine.run(analysis, cfg)
        
        findings = []
        
        for block in cfg.blocks:
            state = result.in_state(block)
            for token in block.tokens:
                # Look for pointer dereference: *ptr or ptr->field
                if self._is_deref(token):
                    ptr_name = self._get_ptr_name(token)
                    if ptr_name:
                        nullness = state.get(ptr_name, "Top")
                        if nullness == "Null":
                            findings.append(Finding(
                                file=token.file,
                                line=token.linenr,
                                column=token.column,
                                severity=Severity.ERROR,
                                message=f"Definite null pointer dereference: "
                                        f"'{ptr_name}' is always null here",
                                checker=self.name,
                                cwe=476,  # CWE-476: NULL Pointer Dereference
                            ))
                        elif nullness == "Top":
                            findings.append(Finding(
                                file=token.file,
                                line=token.linenr,
                                column=token.column,
                                severity=Severity.WARNING,
                                message=f"Possible null pointer dereference: "
                                        f"'{ptr_name}' may be null here",
                                checker=self.name,
                                cwe=476,
                            ))
        
        return CheckerResult(findings=findings)
    
    def _is_deref(self, token):
        """Check if a token represents a pointer dereference."""
        if token.str == "*" and token.astOperand1 and not token.astOperand2:
            return True
        if token.str == "->":
            return True
        return False
    
    def _get_ptr_name(self, token):
        """Extract the pointer variable name from a dereference."""
        if token.str == "*":
            op = token.astOperand1
        elif token.str == "->":
            op = token.astOperand1
        else:
            return None
        if op and op.variable:
            return op.variable.nameToken.str
        return None

# Register the checker
register_checker(NullDerefChecker)
```

### 15.2 Running Checkers

```python
from cppcheckdata_shims.checkers import CheckerRunner

runner = CheckerRunner(
    checkers=["null-deref", "use-after-free", "taint-sink"],
    cli_mode=True,  # Output in Cppcheck JSON format
)

import cppcheckdata
data = cppcheckdata.parsedump("project.c.dump")

for cfg_data in data.configurations:
    runner.run(cfg_data)
```

### 15.3 Output Formats

The checker framework supports multiple output formats:

```python
from cppcheckdata_shims.checkers import OutputFormat

runner = CheckerRunner(
    checkers=["null-deref"],
    output_format=OutputFormat.CPPCHECK_CLI,  # Cppcheck JSON
    # output_format=OutputFormat.SARIF,       # SARIF 2.1
    # output_format=OutputFormat.TEXT,         # Human-readable
    # output_format=OutputFormat.GCC,          # GCC-style warnings
)
```

#### Cppcheck CLI JSON Format

When `--cli` is passed or `OutputFormat.CPPCHECK_CLI` is selected, findings are emitted as JSON objects (one per line), matching Cppcheck's addon protocol:

```json
{"file": "main.c", "linenr": 42, "column": 5, "severity": "error", "message": "Definite null pointer dereference: 'ptr' is always null here", "addon": "null-deref", "errorId": "nullDeref", "extra": "CWE-476"}
```

### 15.4 Suppression Support

Checkers respect Cppcheck's suppression mechanism:

```python
class MyChecker(Checker):
    name = "my-check"
    suppression_id = "myCheckWarning"  # Used in // cppcheck-suppress myCheckWarning
    
    def check(self, cfg, cfg_data):
        findings = []
        for block in cfg.blocks:
            for token in block.tokens:
                if self.should_check(token):
                    finding = Finding(...)
                    # Check suppressions before adding
                    if not self.is_suppressed(finding, cfg_data):
                        findings.append(finding)
        return CheckerResult(findings=findings)
```

### 15.5 The Full Checker Entry Point

A complete addon script using the checker framework:

```python
#!/usr/bin/env python3
"""My custom Cppcheck addon."""

import sys
import cppcheckdata
from cppcheckdata_shims.checkers import CheckerRunner, register_checker
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder

# Import your checkers
from my_checkers import NullDerefChecker, UseAfterFreeChecker

# Register them
register_checker(NullDerefChecker)
register_checker(UseAfterFreeChecker)

def check(data):
    """Entry point called by Cppcheck."""
    builder = CFGBuilder()
    runner = CheckerRunner(
        checkers=["null-deref", "use-after-free"],
        cli_mode=("--cli" in sys.argv),
    )
    
    for cfg_data in data.configurations:
        cfgs = builder.build_all(cfg_data)
        runner.run_with_cfgs(cfg_data, cfgs)

if __name__ == "__main__":
    parser = cppcheckdata.ArgumentParser()
    args = parser.parse_args()
    data = cppcheckdata.parsedump(args.dumpfile)
    check(data)
```

---

## 16. `qscore` — Quality Scoring

### 16.1 Purpose

The `qscore` module computes quantitative quality metrics for analyzed code. Rather than binary "warning/no-warning" results, it produces continuous scores that can be aggregated, trended, and thresholded.

### 16.2 Usage

```python
from cppcheckdata_shims.qscore import (
    QualityScorer,
    MetricSet,
    ScoreCard,
)

scorer = QualityScorer(
    metrics=[
        "cyclomatic_complexity",
        "null_safety_score",
        "taint_safety_score",
        "resource_leak_score",
        "type_safety_score",
    ],
    weights={
        "cyclomatic_complexity": 0.15,
        "null_safety_score": 0.25,
        "taint_safety_score": 0.25,
        "resource_leak_score": 0.20,
        "type_safety_score": 0.15,
    },
)

scorecard = scorer.score(cfg_data, cfgs, analysis_results)

print(f"Overall quality score: {scorecard.overall:.1f}/100")
for metric, score in scorecard.items():
    print(f"  {metric}: {score.value:.1f}/100 "
          f"({score.grade})")  # A, B, C, D, F
```

### 16.3 Custom Metrics

```python
from cppcheckdata_shims.qscore import Metric

class MyMetric(Metric):
    name = "my_metric"
    description = "My custom quality metric"
    
    def compute(self, cfg_data, cfgs, results):
        """Return a score from 0 to 100."""
        # ... your logic ...
        return 85.0
```

---

## 17. `distrib_analysis` — Distributed / Modular Analysis

### 17.1 Purpose

For large codebases, analyzing everything in a single process is impractical. The `distrib_analysis` module supports modular analysis, where each translation unit (or module) is analyzed independently, and summaries are composed.

### 17.2 Summary-Based Composition

```python
from cppcheckdata_shims.distrib_analysis import (
    ModularAnalyzer,
    FunctionSummary,
    SummaryStore,
)

# Phase 1: Analyze each file independently
store = SummaryStore("summaries.db")

for dump_file in dump_files:
    data = cppcheckdata.parsedump(dump_file)
    analyzer = ModularAnalyzer(
        analyses=[NullnessAnalysis(), TaintAnalysis()],
        summary_store=store,
    )
    analyzer.analyze_module(data)
    # Summaries are automatically saved to the store

# Phase 2: Compose summaries for whole-program results
composer = store.compose()
whole_program_results = composer.results()
```

### 17.3 Incremental Analysis

When only a few files have changed, re-analyze only those and recompose:

```python
store = SummaryStore("summaries.db")

# Only re-analyze changed files
for changed_file in changed_files:
    dump = cppcheckdata.parsedump(changed_file + ".dump")
    analyzer = ModularAnalyzer(
        analyses=[NullnessAnalysis()],
        summary_store=store,
    )
    analyzer.analyze_module(dump, invalidate_old=True)

# Recompose
results = store.compose().results()
```

---

## Part VI: Practical Recipes

---

## 18. Recipe: Detecting Memory Leaks

This recipe combines pattern matching, CFG analysis, and dataflow to detect memory leaks:

```python
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder
from cppcheckdata_shims.dataflow_analysis import ForwardAnalysis
from cppcheckdata_shims.abstract_domains import MapDomain, TypeStateDomain
from cppcheckdata_shims.dataflow_engine import DataflowEngine
from cppcheckdata_shims.checkers import Checker, Finding, Severity

class ResourceState(TypeStateDomain):
    """Track allocation state of pointers."""
    STATES = ["Unallocated", "Allocated", "Freed"]
    BOTTOM = "⊥"
    TOP = "⊤"
    
    def initial(self):
        return "Unallocated"

class ResourceAnalysis(ForwardAnalysis):
    def __init__(self):
        super().__init__(domain=MapDomain(ResourceState()))
    
    def transfer(self, block, in_state):
        state = in_state.copy()
        for token in block.tokens:
            # malloc / calloc / realloc
            if (token.str in ("malloc", "calloc", "realloc") and
                token.astParent and token.astParent.str == "="):
                lhs = token.astParent.astOperand1
                if lhs and lhs.variable:
                    state = self.domain.set(
                        state, lhs.variable.nameToken.str, "Allocated"
                    )
            
            # free
            if token.str == "free" and token.astParent:
                arg = token.next  # simplified; real code needs AST walk
                if arg and arg.variable:
                    state = self.domain.set(
                        state, arg.variable.nameToken.str, "Freed"
                    )
        
        return state

class MemoryLeakChecker(Checker):
    name = "memory-leak"
    severity = Severity.WARNING
    
    def check(self, cfg, cfg_data):
        analysis = ResourceAnalysis()
        engine = DataflowEngine()
        result = engine.run(analysis, cfg)
        
        findings = []
        
        # At the exit block, any pointer still "Allocated" is leaked
        exit_state = result.out_state(cfg.exit)
        for var_name, state in exit_state.items():
            if state == "Allocated":
                # Find where it was allocated for the diagnostic
                alloc_site = self._find_allocation(var_name, cfg, result)
                findings.append(Finding(
                    file=alloc_site.file if alloc_site else "?",
                    line=alloc_site.linenr if alloc_site else 0,
                    severity=Severity.WARNING,
                    message=f"Memory leak: '{var_name}' is allocated "
                            f"but never freed on this path",
                    checker=self.name,
                    cwe=401,
                ))
        
        return findings
```

---

## 19. Recipe: Taint Analysis for SQL Injection

```python
from cppcheckdata_shims.dataflow_analysis import ForwardAnalysis
from cppcheckdata_shims.abstract_domains import MapDomain, TaintDomain

# Define sources and sinks
TAINT_SOURCES = {"getenv", "read", "recv", "fgets", "scanf", "gets"}
TAINT_SINKS = {"mysql_query", "sqlite3_exec", "system", "execve"}

class SQLInjectionAnalysis(ForwardAnalysis):
    def __init__(self):
        super().__init__(domain=MapDomain(TaintDomain()))
    
    def transfer(self, block, in_state):
        state = in_state.copy()
        for token in block.tokens:
            # Source: mark return values as tainted
            if (token.isName and token.str in TAINT_SOURCES and
                token.astParent and token.astParent.str == "="):
                lhs = token.astParent.astOperand1
                if lhs and lhs.variable:
                    state = self.domain.set(
                        state, lhs.variable.nameToken.str, "Tainted"
                    )
            
            # Propagation: assignment copies taint
            if token.isAssignmentOp and token.str == "=":
                lhs = token.astOperand1
                rhs = token.astOperand2
                if lhs and lhs.variable and rhs and rhs.variable:
                    rhs_taint = self.domain.get(
                        state, rhs.variable.nameToken.str
                    )
                    state = self.domain.set(
                        state, lhs.variable.nameToken.str, rhs_taint
                    )
        
        return state

class SQLInjectionChecker(Checker):
    name = "sql-injection"
    
    def check(self, cfg, cfg_data):
        analysis = SQLInjectionAnalysis()
        engine = DataflowEngine()
        result = engine.run(analysis, cfg)
        
        findings = []
        for block in cfg.blocks:
            state = result.in_state(block)
            for token in block.tokens:
                if token.isName and token.str in TAINT_SINKS:
                    # Check if any argument is tainted
                    args = self._get_call_args(token)
                    for arg in args:
                        if arg.variable:
                            taint = state.get(
                                arg.variable.nameToken.str, "Untainted"
                            )
                            if taint == "Tainted":
                                findings.append(Finding(
                                    file=token.file,
                                    line=token.linenr,
                                    severity=Severity.ERROR,
                                    message=(
                                        f"SQL injection: tainted value "
                                        f"'{arg.str}' flows to "
                                        f"'{token.str}()'"
                                    ),
                                    checker=self.name,
                                    cwe=89,
                                ))
        
        return findings
```

---

## 20. Recipe: Use-After-Free Detection

```python
from cppcheckdata_shims.checkers import Checker, Finding, Severity
from cppcheckdata_shims.dataflow_analysis import ForwardAnalysis
from cppcheckdata_shims.abstract_domains import MapDomain

class HeapState:
    """Three states: Valid, Freed, Unknown."""
    def bottom(self): return "⊥"
    def top(self): return "Unknown"
    def join(self, a, b):
        if a == b: return a
        if a == "⊥": return b
        if b == "⊥": return a
        return "Unknown"
    def leq(self, a, b):
        return a == "⊥" or a == b or b == "Unknown"

class UseAfterFreeAnalysis(ForwardAnalysis):
    def __init__(self):
        super().__init__(domain=MapDomain(HeapState()))
    
    def transfer(self, block, in_state):
        state = in_state.copy()
        for token in block.tokens:
            if token.str == "malloc" and self._is_assigned(token):
                var = self._get_assigned_var(token)
                if var:
                    state = self.domain.set(state, var, "Valid")
            
            if token.str == "free":
                arg_var = self._get_free_arg(token)
                if arg_var:
                    state = self.domain.set(state, arg_var, "Freed")
        
        return state

class UseAfterFreeChecker(Checker):
    name = "use-after-free"
    
    def check(self, cfg, cfg_data):
        analysis = UseAfterFreeAnalysis()
        engine = DataflowEngine()
        result = engine.run(analysis, cfg)
        
        findings = []
        for block in cfg.blocks:
            state = result.in_state(block)
            for token in block.tokens:
                if self._is_deref(token):
                    var = self._get_deref_var(token)
                    if var and state.get(var) == "Freed":
                        findings.append(Finding(
                            file=token.file,
                            line=token.linenr,
                            severity=Severity.ERROR,
                            message=f"Use after free: '{var}' was freed",
                            checker=self.name,
                            cwe=416,
                        ))
        
        return findings
```

---

## Part VII: Reference

---

## 21. Module Quick Reference

### `cppcheckdata_shims.abstract_domains`

| Class / Function | Description |
|---|---|
| `AbstractDomain` | Protocol for all abstract domains |
| `SignDomain` | Sign abstraction ($\bot$, Neg, Zero, Pos, ..., $\top$) |
| `NullnessDomain` | Null/NonNull/$\top$ |
| `TaintDomain` | Tainted/Untainted/$\top$ |
| `IntervalDomain` | Integer intervals $[l, u]$ with widening |
| `ConstantPropDomain` | Single constant or $\top$ |
| `ParityDomain` | Even/Odd/$\top$ |
| `BoolDomain` | True/False/$\top$ |
| `TypeStateDomain` | Protocol/typestate tracking |
| `PointerDomain` | Points-to sets |
| `ProductDomain(D1, D2, ...)` | Cartesian product of domains |
| `MapDomain(D)` | Map from variables to $D$ values |

### `cppcheckdata_shims.ctrlflow_graph`

| Class / Function | Description |
|---|---|
| `CFGBuilder` | Construct CFGs from Cppcheck data |
| `CFG` | Control flow graph with entry/exit |
| `BasicBlock` | A node in the CFG |
| `EdgeKind` | Edge type enum (TRUE/FALSE/UNCONDITIONAL/BACK/EXCEPTION) |

### `cppcheckdata_shims.ctrlflow_analysis`

| Function | Description |
|---|---|
| `compute_dominators(cfg)` | Dominator relation |
| `compute_dominator_tree(cfg)` | Dominator tree |
| `compute_dominance_frontier(cfg)` | Dominance frontiers |
| `compute_post_dominators(cfg)` | Post-dominator relation |
| `compute_reachability(cfg)` | Reachability matrix |
| `find_all_paths(cfg, src, dst)` | Enumerate simple paths |
| `compute_loop_nesting(cfg)` | Loop nesting structure |
| `find_loop_invariants(cfg, loop)` | Loop-invariant detection |

### `cppcheckdata_shims.dataflow_analysis`

| Class | Type | Direction | Merge |
|---|---|---|---|
| `ReachingDefinitions` | May | Forward | $\cup$ |
| `LiveVariables` | May | Backward | $\cup$ |
| `AvailableExpressions` | Must | Forward | $\cap$ |
| `VeryBusyExpressions` | Must | Backward | $\cap$ |
| `NullnessAnalysis` | May | Forward | $\sqcup$ |
| `TaintAnalysis` | May | Forward | $\sqcup$ |
| `ConstantPropagation` | Must | Forward | $\sqcap$ |
| `InitializationAnalysis` | Must | Forward | $\sqcap$ |

### `cppcheckdata_shims.dataflow_engine`

| Class / Enum | Description |
|---|---|
| `DataflowEngine` | Worklist-based fixed-point solver |
| `WorklistStrategy` | Ordering strategies (FIFO, LIFO, RPO, PO, PRIORITY) |
| `DataflowResult` | Query interface for analysis results |

### `cppcheckdata_shims.abstract_interp`

| Class | Description |
|---|---|
| `AbstractInterpreter` | Base class for abstract interpreters |
| `PathSensitiveInterpreter` | Path-sensitive variant |
| `AbstractState` | Abstract state container |

### `cppcheckdata_shims.callgraph`

| Class | Description |
|---|---|
| `CallGraphBuilder` | Build call graph from Cppcheck data |
| `CallGraph` | The call graph structure |
| `CallEdge` | An edge with call-site annotations |

### `cppcheckdata_shims.interproc_analysis`

| Class | Description |
|---|---|
| `InterproceduralAnalysis` | Base for interprocedural analyses |
| `ContextPolicy` | Context-sensitivity configuration |
| `BottomUpAnalyzer` | Bottom-up call-graph traversal |
| `SCCAnalyzer` | SCC-based recursive analysis |

### `cppcheckdata_shims.memory_abstraction`

| Class | Description |
|---|---|
| `PointsToAnalysis` | Flow-sensitive points-to analysis |
| `AliasAnalysis` | May/must alias queries |
| `AbstractHeap` | Heap model for dynamic allocation |

### `cppcheckdata_shims.symbolic_exec`

| Class | Description |
|---|---|
| `SymbolicExecutor` | Symbolic execution engine |
| `SymbolicState` | Symbolic variable bindings |
| `PathCondition` | Accumulated path constraints |
| `Sym` | Symbolic expression builder |

### `cppcheckdata_shims.constraint_engine`

| Class | Description |
|---|---|
| `ConstraintEngine` | Fixed-point constraint solver |
| `SubsetConstraint` | $X \subseteq Y$ |
| `ConditionalConstraint` | Guarded constraints |

### `cppcheckdata_shims.type_analysis`

| Class | Description |
|---|---|
| `TypeAnalyzer` | Type inference engine |
| `TypestateAnalysis` | Protocol/typestate tracking |
| `TypeEnv` | Type environment |

### `cppcheckdata_shims.checkers`

| Class | Description |
|---|---|
| `Checker` | Base class for all checkers |
| `CheckerRunner` | Execute registered checkers |
| `Finding` | A single diagnostic |
| `Severity` | ERROR / WARNING / STYLE / PERFORMANCE |
| `OutputFormat` | CPPCHECK_CLI / SARIF / TEXT / GCC |
| `register_checker(cls)` | Register a checker class |

### `cppcheckdata_shims.qscore`

| Class | Description |
|---|---|
| `QualityScorer` | Compute quality scores |
| `Metric` | Base class for metrics |
| `ScoreCard` | Results container |

### `cppcheckdata_shims.distrib_analysis`

| Class | Description |
|---|---|
| `ModularAnalyzer` | Per-module analysis |
| `SummaryStore` | Persistent summary database |

---

## 22. Error Handling

All shim modules raise exceptions from a consistent hierarchy:

```python
from cppcheckdata_shims import errors

# Base exception for all shim errors
errors.ShimError

# Specific categories
errors.CFGConstructionError    # CFG building failures
errors.AnalysisError           # Analysis convergence/soundness issues
errors.DomainError             # Lattice operation errors
errors.ConstraintError         # Constraint solving failures
errors.SymbolicError           # Symbolic execution issues
```

Example:

```python
try:
    result = engine.run(analysis, cfg)
except errors.AnalysisError as e:
    print(f"Analysis failed: {e}")
    print(f"  Converged: {e.converged}")
    print(f"  Iterations: {e.iterations}")
```

---

## 23. Performance Considerations

### 23.1 Complexity Bounds

| Analysis | Time Complexity | Space Complexity |
|----------|----------------|-----------------|
| CFG Construction | $O(n)$ where $n$ = tokens | $O(n)$ |
| Dominators | $O(n \cdot \alpha(n))$ (nearly linear) | $O(n)$ |
| Reaching Definitions | $O(n \cdot d)$ where $d$ = definitions | $O(n \cdot d)$ |
| Live Variables | $O(n \cdot v)$ where $v$ = variables | $O(n \cdot v)$ |
| Interval Analysis | $O(n \cdot k)$ where $k$ = widening iterations | $O(n)$ |
| Points-To (Andersen) | $O(n^3)$ worst case | $O(n^2)$ |
| Symbolic Execution | Exponential in branches | Exponential |

### 23.2 Practical Tips

1. **Use reverse post-order** for forward analyses — it minimizes iterations
2. **Set widening delays** to at least 2–3 iterations before widening kicks in
3. **Limit context sensitivity** — call-string $k=1$ or $k=2$ is usually sufficient
4. **Limit symbolic paths** — set `max_paths` to avoid exponential blowup
5. **Cache CFGs** — build once and reuse across multiple analyses
6. **Use modular analysis** for large projects — analyze each file once and compose

---

## 24. Testing Your Addons

### 24.1 Test Structure

Tests for addons should follow the pattern in `tests/`:

```python
import unittest
import cppcheckdata
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder
from cppcheckdata_shims.dataflow_engine import DataflowEngine

class TestMyAnalysis(unittest.TestCase):
    
    def setUp(self):
        """Load a test dump file."""
        self.data = cppcheckdata.parsedump("tests/fixtures/test.c.dump")
        self.cfg_data = self.data.configurations[0]
        self.builder = CFGBuilder()
        self.cfgs = self.builder.build_all(self.cfg_data)
    
    def test_simple_null_check(self):
        """Test that nullness is tracked through a simple if-check."""
        cfg = self.cfgs["test_null"]
        analysis = NullnessAnalysis()
        engine = DataflowEngine()
        result = engine.run(analysis, cfg)
        
        # After the null check, ptr should be NonNull in the true branch
        true_block = cfg.blocks[2]  # Known from the fixture
        state = result.in_state(true_block)
        self.assertEqual(state.get("ptr"), "NonNull")
```

### 24.2 Generating Test Fixtures

```bash
# Write a test C file
cat > tests/fixtures/test.c << 'EOF'
void test_null(int *ptr) {
    if (ptr != NULL) {
        *ptr = 42;
    }
}
EOF

# Generate the dump
cppcheck --dump tests/fixtures/test.c
```

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| **Abstract domain** | A lattice used to represent sets of concrete values |
| **Abstract interpretation** | A theory for sound approximation of program semantics |
| **Back edge** | A CFG edge from a node to one of its dominators (indicates a loop) |
| **Basic block** | A maximal sequence of instructions with no branches except at the end |
| **CFG** | Control flow graph |
| **Context sensitivity** | Distinguishing different calling contexts of the same function |
| **Dominance** | Node $d$ dominates $n$ if every path from entry to $n$ goes through $d$ |
| **Fixed point** | A value $x$ such that $f(x) = x$; the goal of iterative dataflow analysis |
| **Flow sensitivity** | An analysis that accounts for the order of statements |
| **Galois connection** | A formal relationship between concrete and abstract domains |
| **Join ($\sqcup$)** | Least upper bound in a lattice; used to merge information at confluence points |
| **Lattice** | A partially ordered set with join and meet operations |
| **Meet ($\sqcap$)** | Greatest lower bound in a lattice |
| **Monotone function** | $a \sqsubseteq b \implies f(a) \sqsubseteq f(b)$ |
| **Must analysis** | Analysis where information holds on *all* paths (uses meet) |
| **May analysis** | Analysis where information holds on *some* path (uses join) |
| **Narrowing** | Technique to recover precision lost by widening |
| **Path condition** | Conjunction of branch conditions along a symbolic execution path |
| **Points-to set** | The set of memory locations a pointer may reference |
| **Sound** | An analysis that never misses a true positive (may have false positives) |
| **Transfer function** | The abstract effect of a statement on the abstract state |
| **Widening ($\nabla$)** | An operator that ensures convergence by over-approximating |

---

## Appendix B: Further Reading

1. **Møller, A. & Schwartzbach, M.I.** — *Static Program Analysis*. Covers lattice theory, CFGs, dataflow analysis, abstract interpretation, pointer analysis.

2. **Cousot, P. & Cousot, R.** — *Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs by Construction or Approximation of Fixpoints* (POPL 1977). The foundational paper on abstract interpretation.

3. **Nielson, F., Nielson, H.R., & Hankin, C.** — *Principles of Program Analysis*. Comprehensive textbook covering dataflow analysis, constraint-based analysis, abstract interpretation, and type systems.

4. **Martin, M. et al.** — *PQL: A Purely Declarative Java Program Query Language* (2005). Inspiration for the pattern-matching query model.

5. **Cooper, K. & Torczon, L.** — *Engineering a Compiler*, Chapter 9 (Data-Flow Analysis). Practical treatment of iterative dataflow algorithms.

6. **Aho, A.V., Lam, M.S., Sethi, R., & Ullman, J.D.** — *Compilers: Principles, Techniques, and Tools* (Dragon Book), Chapters 9–12. Foundational algorithms for optimization and analysis.

---

*This Vade Mecum was prepared for version 0.1.0 of `cppcheckdata-shims`. For updates, consult the project repository.*