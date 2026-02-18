# SHIMS_VADE_MECUM.md

# Cppcheckdata-Shims: A Vade Mecum

**A Comprehensive Manual for the cppcheckdata-shims Library**

---

## Table of Contents

1. [Introduction](#1-introduction)
   - 1.1 [What is cppcheckdata-shims?](#11-what-is-cppcheckdata-shims)
   - 1.2 [Why Use cppcheckdata-shims?](#12-why-use-cppcheckdata-shims)
   - 1.3 [Prerequisites](#13-prerequisites)
   - 1.4 [Installation](#14-installation)

2. [Architecture Overview](#2-architecture-overview)
   - 2.1 [The Cppcheck Addon Ecosystem](#21-the-cppcheck-addon-ecosystem)
   - 2.2 [How cppcheckdata-shims Extends cppcheckdata.py](#22-how-cppcheckdata-shims-extends-cppcheckdatapy)
   - 2.3 [Module Organization](#23-module-organization)
   - 2.4 [Dependency Graph](#24-dependency-graph)

3. [The Foundation: Understanding cppcheckdata.py](#3-the-foundation-understanding-cppcheckdatapy)
   - 3.1 [Dump Files and Their Structure](#31-dump-files-and-their-structure)
   - 3.2 [Core Objects: Token, Variable, Scope, Function](#32-core-objects-token-variable-scope-function)
   - 3.3 [The AST Representation](#33-the-ast-representation)
   - 3.4 [Value Flow Information](#34-value-flow-information)

4. [Module Reference: ast_helper.py](#4-module-reference-ast_helperpy)
   - 4.1 [Safe Accessors](#41-safe-accessors)
   - 4.2 [AST Traversal](#42-ast-traversal)
   - 4.3 [AST Predicates](#43-ast-predicates)
   - 4.4 [Function Call Analysis](#44-function-call-analysis)
   - 4.5 [Expression Utilities](#45-expression-utilities)
   - 4.6 [Pattern Matching](#46-pattern-matching)

5. [Module Reference: checkers.py](#5-module-reference-checkerspy)
   - 5.1 [The Checker Framework](#51-the-checker-framework)
   - 5.2 [Creating a Basic Checker](#52-creating-a-basic-checker)
   - 5.3 [Findings and Severity](#53-findings-and-severity)
   - 5.4 [Checker Registration](#54-checker-registration)

6. [Module Reference: abstract_domains.py](#6-module-reference-abstract_domainspy)
   - 6.1 [What Are Abstract Domains?](#61-what-are-abstract-domains)
   - 6.2 [The AbstractDomain Protocol](#62-the-abstractdomain-protocol)
   - 6.3 [Flat Domains](#63-flat-domains)
   - 6.4 [Sign Domain](#64-sign-domain)
   - 6.5 [Interval Domain](#65-interval-domain)
   - 6.6 [Bitfield Domain](#66-bitfield-domain)
   - 6.7 [Product Domains](#67-product-domains)
   - 6.8 [Widening and Narrowing](#68-widening-and-narrowing)

7. [Module Reference: ctrlflow_graph.py](#7-module-reference-ctrlflow_graphpy)
   - 7.1 [CFG Nodes and Edges](#71-cfg-nodes-and-edges)
   - 7.2 [Building a CFG](#72-building-a-cfg)
   - 7.3 [CFG Traversal](#73-cfg-traversal)
   - 7.4 [Dominator Analysis](#74-dominator-analysis)

8. [Module Reference: dataflow_engine.py](#8-module-reference-dataflow_enginepy)
   - 8.1 [The Dataflow Framework](#81-the-dataflow-framework)
   - 8.2 [Forward Analysis](#82-forward-analysis)
   - 8.3 [Backward Analysis](#83-backward-analysis)
   - 8.4 [Worklist Algorithms](#84-worklist-algorithms)
   - 8.5 [Fixpoint Computation](#85-fixpoint-computation)

9. [Module Reference: taint_analysis.py](#9-module-reference-taint_analysispy)
   - 9.1 [Taint Analysis Concepts](#91-taint-analysis-concepts)
   - 9.2 [Configuring Sources, Sinks, and Sanitizers](#92-configuring-sources-sinks-and-sanitizers)
   - 9.3 [Running the Analyzer](#93-running-the-analyzer)
   - 9.4 [Interpreting Results](#94-interpreting-results)

10. [Module Reference: symbolic_exec.py](#10-module-reference-symbolic_execpy)
    - 10.1 [Symbolic Execution Basics](#101-symbolic-execution-basics)
    - 10.2 [Symbolic Values and Expressions](#102-symbolic-values-and-expressions)
    - 10.3 [Path Conditions](#103-path-conditions)
    - 10.4 [Constraint Solving](#104-constraint-solving)

11. [Module Reference: memory_abstraction.py](#11-module-reference-memory_abstractionpy)
    - 11.1 [Memory Models](#111-memory-models)
    - 11.2 [Points-To Analysis](#112-points-to-analysis)
    - 11.3 [Alias Analysis](#113-alias-analysis)

12. [Module Reference: callgraph.py](#12-module-reference-callgraphpy)
    - 12.1 [Building Call Graphs](#121-building-call-graphs)
    - 12.2 [Call Graph Traversal](#122-call-graph-traversal)
    - 12.3 [Interprocedural Analysis Support](#123-interprocedural-analysis-support)

13. [Module Reference: type_analysis.py](#13-module-reference-type_analysispy)
    - 13.1 [Type Representation](#131-type-representation)
    - 13.2 [Type Inference](#132-type-inference)
    - 13.3 [Type Compatibility Checking](#133-type-compatibility-checking)

14. [Module Reference: qscore.py](#14-module-reference-qscorepy)
    - 14.1 [Quality Scoring](#141-quality-scoring)
    - 14.2 [Confidence Metrics](#142-confidence-metrics)
    - 14.3 [False Positive Reduction](#143-false-positive-reduction)

15. [Putting It All Together: Complete Examples](#15-putting-it-all-together-complete-examples)
    - 15.1 [Example: Null Pointer Dereference Checker](#151-example-null-pointer-dereference-checker)
    - 15.2 [Example: Buffer Overflow Detector](#152-example-buffer-overflow-detector)
    - 15.3 [Example: Use-After-Free Analyzer](#153-example-use-after-free-analyzer)
    - 15.4 [Example: Format String Validator](#154-example-format-string-validator)
    - 15.5 [Example: Taint-Based SQL Injection Detector](#155-example-taint-based-sql-injection-detector)

16. [Best Practices](#16-best-practices)
    - 16.1 [Defensive Programming](#161-defensive-programming)
    - 16.2 [Performance Considerations](#162-performance-considerations)
    - 16.3 [Testing Your Addons](#163-testing-your-addons)
    - 16.4 [Common Pitfalls](#164-common-pitfalls)

17. [Troubleshooting](#17-troubleshooting)
    - 17.1 [Common Errors](#171-common-errors)
    - 17.2 [Debugging Techniques](#172-debugging-techniques)
    - 17.3 [Getting Help](#173-getting-help)

18. [Appendices](#18-appendices)
    - A. [Quick Reference Card](#a-quick-reference-card)
    - B. [Glossary](#b-glossary)
    - C. [CWE Reference](#c-cwe-reference)

---

## 1. Introduction

### 1.1 What is cppcheckdata-shims?

**cppcheckdata-shims** is a Python library that extends Cppcheck's addon infrastructure with industrial-strength static analysis capabilities. It provides a comprehensive toolkit for building sophisticated code analyzers that go far beyond simple pattern matching.

The library sits between your addon code and Cppcheck's `cppcheckdata.py` module, providing:

- **Safe, null-aware accessors** for AST traversal
- **Abstract interpretation frameworks** with pre-built domains
- **Dataflow analysis engines** (forward and backward)
- **Taint analysis infrastructure** for security vulnerability detection
- **Control flow graph construction** and analysis
- **Symbolic execution** capabilities
- **Memory abstraction** for pointer analysis
- **Call graph construction** for interprocedural analysis

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR ADDON CODE                              │
├─────────────────────────────────────────────────────────────────────┤
│                    cppcheckdata-shims                               │
│  ┌──────────────┬──────────────┬──────────────┬──────────────┐     │
│  │ ast_helper   │ taint_analysis│ dataflow_eng │ symbolic_exec│     │
│  ├──────────────┼──────────────┼──────────────┼──────────────┤     │
│  │ checkers     │ abstract_dom │ ctrlflow_grph│ memory_abstr │     │
│  └──────────────┴──────────────┴──────────────┴──────────────┘     │
├─────────────────────────────────────────────────────────────────────┤
│                      cppcheckdata.py                                │
├─────────────────────────────────────────────────────────────────────┤
│                     Cppcheck Dump Files                             │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 Why Use cppcheckdata-shims?

Writing robust Cppcheck addons directly against `cppcheckdata.py` is challenging:

1. **Null safety**: Token attributes can be `None` unexpectedly
2. **AST complexity**: Navigating the AST requires boilerplate code
3. **Analysis infrastructure**: Building dataflow engines from scratch is error-prone
4. **Domain knowledge**: Abstract interpretation requires mathematical foundations

cppcheckdata-shims solves these problems by providing:

| Challenge | Solution |
|-----------|----------|
| Null pointer exceptions | Safe accessors that never raise |
| AST traversal boilerplate | Pre-built iterators and predicates |
| Dataflow analysis | Plug-and-play analysis engines |
| Abstract domains | Ready-to-use interval, sign, taint domains |
| Security analysis | Complete taint tracking infrastructure |
| False positives | Quality scoring and confidence metrics |

### 1.3 Prerequisites

Before using cppcheckdata-shims, you should have:

- **Python 3.9+** (for type hints and dataclasses)
- **Cppcheck 2.x** installed and working
- **Basic understanding of**:
  - C/C++ syntax and semantics
  - Abstract syntax trees (ASTs)
  - Basic compiler concepts (control flow, data flow)

Familiarity with these concepts is helpful but not required:
- Lattice theory and abstract interpretation
- Dataflow analysis algorithms
- Taint tracking

### 1.4 Installation

```bash
# From PyPI (when published)
pip install cppcheckdata-shims

# From source
git clone https://github.com/your-repo/cppcheckdata-shims.git
cd cppcheckdata-shims
pip install -e .
```

Verify the installation:

```python
>>> from cppcheckdata_shims import ast_helper, checkers, taint_analysis
>>> print("Installation successful!")
```

---

## 2. Architecture Overview

### 2.1 The Cppcheck Addon Ecosystem

Cppcheck addons work with **dump files** — XML representations of parsed C/C++ code. The workflow is:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Source.c    │────▶│   Cppcheck   │────▶│  Source.dump │────▶│  Your Addon  │
│              │     │   --dump     │     │   (XML)      │     │   (Python)   │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

The dump file contains:
- Token stream with AST structure
- Variable and function declarations
- Scope hierarchy
- Type information
- Value flow analysis results

### 2.2 How cppcheckdata-shims Extends cppcheckdata.py

`cppcheckdata.py` (provided by Cppcheck) parses dump files into Python objects:

```python
import cppcheckdata

data = cppcheckdata.parsedump("file.c.dump")
for cfg in data.configurations:
    for token in cfg.tokenlist:
        # Direct access to token attributes
        print(token.str, token.astOperand1, token.astOperand2)
```

**The problem**: This code crashes if `astOperand1` is `None`:

```python
# DANGEROUS: Will crash on leaf nodes
print(token.astOperand1.str)  # AttributeError if astOperand1 is None
```

**cppcheckdata-shims provides safe wrappers**:

```python
from cppcheckdata_shims.ast_helper import tok_str, tok_op1

# SAFE: Returns None or empty string, never crashes
operand = tok_op1(token)
if operand:
    print(tok_str(operand))
```

Beyond safety, cppcheckdata-shims adds **analysis infrastructure** that doesn't exist in the base library:

| cppcheckdata.py | cppcheckdata-shims |
|-----------------|-------------------|
| Token objects | + Safe accessors, AST iterators |
| Basic AST | + Pattern matching, predicates |
| (none) | + Control flow graphs |
| (none) | + Dataflow analysis engines |
| (none) | + Abstract domains |
| (none) | + Taint tracking |
| (none) | + Symbolic execution |

### 2.3 Module Organization

```
cppcheckdata_shims/
├── ast_helper.py          # AST traversal and manipulation
├── checkers.py            # Checker framework and base classes
├── abstract_domains.py    # Lattices for abstract interpretation
├── ctrlflow_graph.py      # Control flow graph construction
├── ctrlflow_analysis.py   # CFG-based analyses
├── dataflow_engine.py     # Generic dataflow solver
├── dataflow_analysis.py   # Specific dataflow analyses
├── taint_analysis.py      # Taint tracking infrastructure
├── symbolic_exec.py       # Symbolic execution engine
├── constraint_engine.py   # Constraint solving
├── memory_abstraction.py  # Memory and pointer models
├── callgraph.py           # Call graph construction
├── interproc_analysis.py  # Interprocedural analysis
├── type_analysis.py       # Type inference and checking
├── qscore.py              # Quality scoring
└── distrib_analysis.py    # Distributed analysis support
```

### 2.4 Dependency Graph

Modules have clear dependencies, allowing you to use only what you need:

```
                    ┌─────────────────┐
                    │   ast_helper    │  ◀── Foundation (no dependencies)
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   checkers   │  │ ctrlflow_grph│  │type_analysis │
    └──────────────┘  └──────┬───────┘  └──────────────┘
                             │
            ┌────────────────┼────────────────┐
            ▼                ▼                ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │abstract_doms │  │dataflow_eng  │  │  callgraph   │
    └──────┬───────┘  └──────┬───────┘  └──────────────┘
           │                 │
           └────────┬────────┘
                    ▼
           ┌──────────────┐
           │taint_analysis│
           │symbolic_exec │
           │memory_abstrc │
           └──────────────┘
```

---

## 3. The Foundation: Understanding cppcheckdata.py

Before diving into cppcheckdata-shims, you must understand what Cppcheck provides.

### 3.1 Dump Files and Their Structure

Generate a dump file:

```bash
cppcheck --dump example.c
```

This creates `example.c.dump`, an XML file containing:

```xml
<?xml version="1.0"?>
<dumps>
  <dump cfg="...">
    <standards>...</standards>
    <directivelist>...</directivelist>
    <tokenlist>
      <token id="1" file="example.c" linenr="1" column="1" 
             str="int" scope="..." type="name"/>
      <!-- ... more tokens ... -->
    </tokenlist>
    <scopes>...</scopes>
    <functions>...</functions>
    <variables>...</variables>
    <valueflow>...</valueflow>
  </dump>
</dumps>
```

### 3.2 Core Objects: Token, Variable, Scope, Function

After parsing with `cppcheckdata.parsedump()`, you get Python objects:

#### Token

Represents a single token in the source code:

```python
token.str          # The token string (e.g., "int", "x", "+")
token.Id           # Unique identifier
token.file         # Source file name
token.linenr       # Line number (1-based)
token.column       # Column number (1-based)

# AST structure
token.astParent    # Parent in AST (or None)
token.astOperand1  # Left/first operand (or None)
token.astOperand2  # Right/second operand (or None)

# Linked list
token.next         # Next token in sequence
token.previous     # Previous token in sequence

# Semantic information
token.variable     # Associated Variable object (or None)
token.function     # Associated Function object (or None)
token.scope        # Enclosing Scope object
token.valueType    # Type information (or None)
token.values       # Value flow results (list)
```

#### Variable

Represents a declared variable:

```python
variable.Id           # Unique identifier
variable.nameToken    # Token where name appears
variable.typeStartToken  # Start of type declaration
variable.typeEndToken    # End of type declaration

# Properties
variable.isArgument   # Is a function parameter
variable.isLocal      # Is a local variable
variable.isGlobal     # Is a global variable
variable.isPointer    # Is a pointer type
variable.isArray      # Is an array type
variable.isConst      # Has const qualifier
```

#### Scope

Represents a lexical scope:

```python
scope.Id           # Unique identifier
scope.type         # "Global", "Function", "If", "While", etc.
scope.className    # Name (for functions/classes)
scope.bodyStart    # Opening brace token
scope.bodyEnd      # Closing brace token
scope.nestedIn     # Parent scope
```

#### Function

Represents a function declaration:

```python
function.Id           # Unique identifier
function.name         # Function name
function.tokenDef     # Token at function definition
function.argument     # Dict of argument Variables
function.argumentList # List of argument tokens
```

### 3.3 The AST Representation

Cppcheck represents expressions as binary trees. For example:

```c
x = a + b * c;
```

Becomes:

```
        =
       / \
      x   +
         / \
        a   *
           / \
          b   c
```

In code:

```python
# token.str == "="
# token.astOperand1.str == "x"
# token.astOperand2.str == "+"
# token.astOperand2.astOperand1.str == "a"
# token.astOperand2.astOperand2.str == "*"
# ... and so on
```

**Important**: Not every token has AST children. Only **operator tokens** have `astOperand1`/`astOperand2`. Identifiers and literals are leaves.

### 3.4 Value Flow Information

Cppcheck performs value flow analysis and stores results in `token.values`:

```python
for value in token.values:
    if value.intvalue is not None:
        print(f"Token may have integer value: {value.intvalue}")
    if value.isKnown:
        print("Value is definitely known")
    if value.isPossible:
        print("Value is possible but not certain")
```

This is crucial for detecting bugs like:

```c
int x = get_value();
if (x == 5) {
    // Here, Cppcheck knows x == 5
    int arr[5];
    arr[x] = 0;  // Buffer overflow! x is 5, valid indices are 0-4
}
```

---

## 4. Module Reference: ast_helper.py

The `ast_helper` module provides safe, convenient functions for AST manipulation.

### 4.1 Safe Accessors

These functions never raise `AttributeError`, even on `None` inputs:

```python
from cppcheckdata_shims.ast_helper import (
    tok_str, tok_op1, tok_op2, tok_parent,
    tok_var_id, tok_variable, tok_function,
    tok_value_type, tok_values,
    tok_file, tok_line, tok_column,
    token_location,
)
```

#### tok_str(token) → str

Returns the token's string representation, or empty string if None:

```python
>>> tok_str(some_token)
"+"
>>> tok_str(None)
""
```

#### tok_op1(token), tok_op2(token) → Optional[Token]

Returns the left/right AST operand:

```python
>>> assignment = find_assignment_token()
>>> lhs = tok_op1(assignment)  # Left-hand side
>>> rhs = tok_op2(assignment)  # Right-hand side
```

#### tok_parent(token) → Optional[Token]

Returns the AST parent:

```python
>>> expr = find_expression()
>>> parent = tok_parent(expr)
>>> if tok_str(parent) == "if":
...     print("Expression is an if condition")
```

#### tok_variable(token) → Optional[Variable]

Returns the associated variable:

```python
>>> var = tok_variable(identifier_token)
>>> if var and var.isPointer:
...     print("This is a pointer variable")
```

#### token_location(token) → str

Returns a formatted location string:

```python
>>> token_location(some_token)
"example.c:42:10"
```

### 4.2 AST Traversal

#### iter_ast_preorder(root) → Iterator[Token]

Yields all nodes in pre-order (parent before children):

```python
from cppcheckdata_shims.ast_helper import iter_ast_preorder

def find_all_function_calls(expr):
    """Find all function calls within an expression."""
    calls = []
    for node in iter_ast_preorder(expr):
        if is_function_call(node):
            calls.append(node)
    return calls
```

#### iter_ast_postorder(root) → Iterator[Token]

Yields all nodes in post-order (children before parent):

```python
from cppcheckdata_shims.ast_helper import iter_ast_postorder

def evaluate_constant_expr(expr):
    """Evaluate a constant expression bottom-up."""
    values = {}
    for node in iter_ast_postorder(expr):
        if is_number(node):
            values[node.Id] = int(tok_str(node))
        elif tok_str(node) == "+":
            left = values.get(tok_op1(node).Id, 0)
            right = values.get(tok_op2(node).Id, 0)
            values[node.Id] = left + right
    return values.get(expr.Id)
```

#### find_ast_root(token) → Token

Finds the root of the AST containing a token:

```python
from cppcheckdata_shims.ast_helper import find_ast_root

# Given any node in an expression, find the statement root
root = find_ast_root(some_subexpression)
```

#### collect_subtree(root) → List[Token]

Collects all nodes in a subtree:

```python
from cppcheckdata_shims.ast_helper import collect_subtree

nodes = collect_subtree(expression)
print(f"Expression has {len(nodes)} AST nodes")
```

### 4.3 AST Predicates

Boolean functions for classifying tokens:

```python
from cppcheckdata_shims.ast_helper import (
    is_assignment, is_compound_assignment,
    is_function_call, is_dereference, is_address_of,
    is_subscript, is_member_access,
    is_identifier, is_literal, is_number, is_string_literal,
    is_comparison, is_equality, is_relational,
    is_arithmetic_op, is_bitwise_op, is_logical_op,
    is_unary_op, is_binary_op,
    is_pointer_type, is_array_type,
    is_signed_type, is_unsigned_type,
)
```

#### Examples

```python
# Check if token is an assignment
if is_assignment(token):
    lhs = tok_op1(token)
    rhs = tok_op2(token)
    print(f"Assignment: {expr_to_string(lhs)} = {expr_to_string(rhs)}")

# Check for function calls
if is_function_call(token):
    name = get_called_function_name(token)
    args = get_call_arguments(token)
    print(f"Call to {name} with {len(args)} arguments")

# Check for pointer dereference
if is_dereference(token):
    ptr = tok_op1(token)
    print(f"Dereferencing: {expr_to_string(ptr)}")

# Check for array access
if is_subscript(token):
    array = tok_op1(token)
    index = tok_op2(token)
    print(f"Array access: {expr_to_string(array)}[{expr_to_string(index)}]")
```

### 4.4 Function Call Analysis

```python
from cppcheckdata_shims.ast_helper import (
    get_called_function_name,
    get_call_arguments,
    count_call_arguments,
    find_function_calls,
    find_calls_to,
    is_allocation_call,
    is_deallocation_call,
)
```

#### get_called_function_name(token) → str

Returns the name of the called function:

```python
>>> token  # represents: malloc(size)
>>> get_called_function_name(token)
"malloc"
```

#### get_call_arguments(token) → List[Token]

Returns the argument expressions:

```python
>>> token  # represents: printf("%d", x)
>>> args = get_call_arguments(token)
>>> len(args)
2
>>> expr_to_string(args[0])
'"%d"'
>>> expr_to_string(args[1])
'x'
```

#### find_calls_to(scope, function_name) → List[Token]

Finds all calls to a specific function:

```python
# Find all malloc calls in a function
malloc_calls = find_calls_to(function_scope, "malloc")
for call in malloc_calls:
    print(f"malloc at {token_location(call)}")
```

#### is_allocation_call(token), is_deallocation_call(token)

Checks for memory allocation/deallocation:

```python
if is_allocation_call(token):
    print(f"Allocation: {get_called_function_name(token)}")
    # malloc, calloc, realloc, new, etc.

if is_deallocation_call(token):
    print(f"Deallocation: {get_called_function_name(token)}")
    # free, delete, etc.
```

### 4.5 Expression Utilities

```python
from cppcheckdata_shims.ast_helper import (
    expr_to_string,
    is_lvalue,
    has_side_effects,
    may_be_zero,
    may_be_negative,
    get_variables_used,
    get_variables_written,
)
```

#### expr_to_string(token) → str

Reconstructs source code from AST:

```python
>>> expr_to_string(complex_expression)
"a + b * (c - d)"
```

#### is_lvalue(token) → bool

Checks if expression can appear on left side of assignment:

```python
>>> is_lvalue(identifier_token)
True
>>> is_lvalue(dereference_token)  # *ptr
True
>>> is_lvalue(literal_token)       # 42
False
```

#### has_side_effects(token) → bool

Checks if expression modifies state:

```python
>>> has_side_effects(simple_add)  # a + b
False
>>> has_side_effects(increment)   # i++
True
>>> has_side_effects(call)        # func()
True  # Conservative: assumes calls have side effects
```

#### get_variables_used(token) → Set[int]

Returns variable IDs read by expression:

```python
>>> expr  # represents: a + b * c
>>> var_ids = get_variables_used(expr)
>>> var_ids
{101, 102, 103}  # IDs of a, b, c
```

#### get_variables_written(token) → Set[int]

Returns variable IDs written by expression:

```python
>>> expr  # represents: x = y + z
>>> written = get_variables_written(expr)
>>> written
{100}  # ID of x
```

### 4.6 Pattern Matching

The `ASTPattern` class enables declarative AST matching:

```python
from cppcheckdata_shims.ast_helper import ASTPattern, match_pattern

# Match: x = malloc(...)
malloc_pattern = ASTPattern(
    operator="=",
    operand2=ASTPattern(
        is_call=True,
        function_name="malloc"
    )
)

for token in cfg.tokenlist:
    if match_pattern(token, malloc_pattern):
        print(f"Found malloc assignment at {token_location(token)}")
```

#### Pattern Components

```python
ASTPattern(
    operator="...",        # Match specific operator string
    operand1=...,          # Pattern for left operand
    operand2=...,          # Pattern for right operand
    is_call=True/False,    # Match function calls
    function_name="...",   # Match specific function name
    is_literal=True/False, # Match literals
    is_identifier=True,    # Match identifiers
    variable_name="...",   # Match specific variable name
    predicate=func,        # Custom predicate function
)
```

#### Complex Pattern Example

```python
# Match: if (ptr == NULL) or if (ptr != NULL)
null_check_pattern = ASTPattern(
    operator=lambda op: op in ("==", "!="),
    predicate=lambda t: (
        (is_identifier(tok_op1(t)) and tok_str(tok_op2(t)) == "NULL") or
        (is_identifier(tok_op2(t)) and tok_str(tok_op1(t)) == "NULL")
    )
)
```

---

## 5. Module Reference: checkers.py

The `checkers` module provides a framework for building structured analyzers.

### 5.1 The Checker Framework

A **checker** is a class that:
1. Inherits from `CheckerBase`
2. Implements analysis logic
3. Reports findings via the `Finding` class

```python
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity

class MyChecker(CheckerBase):
    name = "MyChecker"
    description = "Checks for something important"
    
    def check(self, cfg) -> List[Finding]:
        findings = []
        # ... analysis logic ...
        return findings
```

### 5.2 Creating a Basic Checker

```python
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity
from cppcheckdata_shims.ast_helper import (
    is_function_call, get_called_function_name,
    tok_file, tok_line, tok_column
)

class DangerousFunctionChecker(CheckerBase):
    """Detects use of dangerous functions."""
    
    name = "DangerousFunction"
    description = "Detects inherently dangerous functions"
    version = "1.0.0"
    
    DANGEROUS = {"gets", "sprintf", "strcpy", "strcat"}
    
    def check(self, cfg) -> List[Finding]:
        findings = []
        
        for token in cfg.tokenlist:
            if is_function_call(token):
                func = get_called_function_name(token)
                if func in self.DANGEROUS:
                    findings.append(Finding(
                        file=tok_file(token),
                        line=tok_line(token),
                        column=tok_column(token),
                        severity=Severity.WARNING,
                        message=f"Use of dangerous function '{func}'",
                        checker=self.name,
                        cwe=676,
                    ))
        
        return findings
```

### 5.3 Findings and Severity

The `Finding` dataclass represents a detected issue:

```python
@dataclass
class Finding:
    file: str                    # Source file
    line: int                    # Line number
    column: int                  # Column number
    severity: Severity           # ERROR, WARNING, STYLE, INFO
    message: str                 # Human-readable description
    checker: str = ""            # Checker name
    cwe: Optional[int] = None    # CWE identifier
    rule_id: str = ""            # Custom rule ID
    confidence: float = 1.0      # 0.0 to 1.0
```

Severity levels:

```python
class Severity(Enum):
    ERROR = auto()    # Definite bug, will cause problems
    WARNING = auto()  # Likely bug, should be investigated
    STYLE = auto()    # Code style issue, not necessarily a bug
    INFO = auto()     # Informational, for context
```

### 5.4 Checker Registration

For addon frameworks that auto-discover checkers:

```python
from cppcheckdata_shims.checkers import register_checker, get_registered_checkers

@register_checker
class MyChecker(CheckerBase):
    ...

# Later, get all registered checkers
checkers = get_registered_checkers()
for checker_cls in checkers:
    checker = checker_cls()
    findings = checker.check(cfg)
```

---

## 6. Module Reference: abstract_domains.py

Abstract domains are the mathematical foundation of static analysis.

### 6.1 What Are Abstract Domains?

An **abstract domain** approximates sets of concrete values with abstract values that are:
- **Finite** (or have finite height) — analysis terminates
- **Sound** — never misses real bugs
- **Computable** — operations are efficient

Example: Instead of tracking all possible values of `x`, we track whether `x` is:
- Negative (`⁻`)
- Zero (`0`)
- Positive (`⁺`)
- Unknown (`⊤`)

This is the **Sign Domain**.

### 6.2 The AbstractDomain Protocol

Every domain must implement:

```python
@runtime_checkable
class AbstractDomain(Protocol):
    def join(self, other: Self) -> Self:
        """Least upper bound: self ⊔ other"""
        ...
    
    def meet(self, other: Self) -> Self:
        """Greatest lower bound: self ⊓ other"""
        ...
    
    def leq(self, other: Self) -> bool:
        """Partial order: self ⊑ other"""
        ...
    
    def is_bottom(self) -> bool:
        """Is this the least element ⊥?"""
        ...
    
    def is_top(self) -> bool:
        """Is this the greatest element ⊤?"""
        ...
    
    def widen(self, other: Self) -> Self:
        """Widening for infinite-height domains"""
        ...
    
    def narrow(self, other: Self) -> Self:
        """Narrowing for precision recovery"""
        ...
```

### 6.3 Flat Domains

The simplest domain structure — a set of values with ⊥ below and ⊤ above:

```
        ⊤
    / | | | \
   v₁ v₂ v₃ … vₙ
    \ | | | /
        ⊥
```

```python
from cppcheckdata_shims.abstract_domains import FlatDomain

# Create values
bottom = FlatDomain.bottom()
top = FlatDomain.top()
five = FlatDomain.lift(5)
seven = FlatDomain.lift(7)

# Operations
assert five.join(five) == five      # Same value: unchanged
assert five.join(seven) == top      # Different values: ⊤
assert five.meet(top) == five       # Meet with ⊤: unchanged
assert five.leq(top)                # Everything ⊑ ⊤
```

### 6.4 Sign Domain

Tracks the sign of integer values:

```python
from cppcheckdata_shims.abstract_domains import SignDomain

pos = SignDomain.pos()      # Positive integers
neg = SignDomain.neg()      # Negative integers
zero = SignDomain.zero()    # Zero
top = SignDomain.top()      # Any integer

# Abstract arithmetic
assert pos.add(pos) == pos          # (+) + (+) = (+)
assert pos.add(neg) == top          # (+) + (-) = (?)
assert pos.mul(neg) == neg          # (+) × (-) = (-)
assert neg.mul(neg) == pos          # (-) × (-) = (+)

# From concrete values
assert SignDomain.abstract(42) == pos
assert SignDomain.abstract(-7) == neg
assert SignDomain.abstract(0) == zero
```

**Use case**: Detecting division by zero, array index sign checks.

### 6.5 Interval Domain

The workhorse of numerical analysis — tracks value ranges:

```python
from cppcheckdata_shims.abstract_domains import IntervalDomain

# Create intervals
zero_to_ten = IntervalDomain.range(0, 10)     # [0, 10]
five = IntervalDomain.const(5)                 # [5, 5]
non_negative = IntervalDomain.at_least(0)      # [0, +∞)
any_value = IntervalDomain.top()               # [-∞, +∞]

# Lattice operations
assert zero_to_ten.join(IntervalDomain.range(5, 20)) == IntervalDomain.range(0, 20)
assert zero_to_ten.meet(IntervalDomain.range(5, 20)) == IntervalDomain.range(5, 10)

# Abstract arithmetic
a = IntervalDomain.range(1, 5)
b = IntervalDomain.range(2, 3)
assert a.add(b) == IntervalDomain.range(3, 8)   # [1,5] + [2,3] = [3,8]
assert a.mul(b) == IntervalDomain.range(2, 15)  # [1,5] × [2,3] = [2,15]

# Refinement for conditionals
x = IntervalDomain.range(0, 100)
x_lt_50 = x.refine_lt(50)   # [0, 49]
x_ge_50 = x.refine_ge(50)   # [50, 100]
```

**Use case**: Buffer overflow detection, array bounds checking.

### 6.6 Bitfield Domain

Tracks which bits are definitely set or may be set:

```python
from cppcheckdata_shims.abstract_domains import BitfieldDomain

# Create from known value
bf = BitfieldDomain.from_value(0b1010)
assert bf.must_be_one == 0b1010   # These bits are definitely 1
assert bf.may_be_one == 0b1010    # These bits may be 1

# Operations
bf1 = BitfieldDomain.from_value(0b1100)
bf2 = BitfieldDomain.from_value(0b1010)
result = bf1.bitwise_or(bf2)
assert result.must_be_one == 0b1110  # At least these bits are set
```

**Use case**: Flag checking, permission analysis, hardware register analysis.

### 6.7 Product Domains

Combine multiple domains for more precision:

```python
from cppcheckdata_shims.abstract_domains import ProductDomain, IntervalDomain, ParityDomain

# Combine interval and parity
class IntervalParity(ProductDomain):
    def __init__(self, interval: IntervalDomain, parity: ParityDomain):
        self.interval = interval
        self.parity = parity
    
    def join(self, other):
        return IntervalParity(
            self.interval.join(other.interval),
            self.parity.join(other.parity)
        )
    
    # ... other methods ...
```

**Use case**: When one domain alone isn't precise enough.

### 6.8 Widening and Narrowing

For domains with infinite height (like intervals), we need **widening** to ensure termination:

```python
# Without widening: infinite loop
x = IntervalDomain.const(0)
while not fixpoint:
    x = x.join(IntervalDomain.const(x.hi + 1))
    # [0,0] → [0,1] → [0,2] → ... never terminates

# With widening: terminates
x = IntervalDomain.const(0)
while not fixpoint:
    new_x = x.join(IntervalDomain.const(x.hi + 1))
    x = x.widen(new_x)
    # [0,0] → [0,1] → [0,+∞] → done!
```

**Narrowing** recovers precision after widening:

```python
# After widening, x = [0, +∞]
# But we know from the loop condition that x < 100
x = x.narrow(IntervalDomain.range(0, 99))
# Now x = [0, 99] — more precise!
```

---

## 7. Module Reference: ctrlflow_graph.py

Control flow graphs are essential for path-sensitive analysis.

### 7.1 CFG Nodes and Edges

```python
from cppcheckdata_shims.ctrlflow_graph import CFGNode, CFGEdge, EdgeKind

# A CFG node represents a basic block
node = CFGNode(
    id=1,
    tokens=[...],          # Tokens in this block
    predecessors=[...],    # Incoming edges
    successors=[...],      # Outgoing edges
)

# An edge connects two nodes
edge = CFGEdge(
    source=node1,
    target=node2,
    kind=EdgeKind.TRUE_BRANCH,  # or FALSE_BRANCH, UNCONDITIONAL, etc.
    condition=condition_token,   # For conditional edges
)
```

### 7.2 Building a CFG

```python
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder

def analyze_function(scope):
    # Build CFG for a function
    builder = CFGBuilder()
    cfg = builder.build(scope)
    
    print(f"CFG has {len(cfg.nodes)} nodes")
    print(f"Entry node: {cfg.entry}")
    print(f"Exit node: {cfg.exit}")
    
    # Iterate over nodes
    for node in cfg.nodes:
        print(f"Node {node.id}: {len(node.tokens)} tokens")
        for succ in node.successors:
            print(f"  → Node {succ.target.id} ({succ.kind.name})")
```

### 7.3 CFG Traversal

```python
from cppcheckdata_shims.ctrlflow_graph import (
    iter_cfg_forward,
    iter_cfg_backward,
    iter_cfg_reverse_postorder,
)

# Forward traversal (for forward dataflow)
for node in iter_cfg_forward(cfg):
    process_node(node)

# Backward traversal (for backward dataflow)
for node in iter_cfg_backward(cfg):
    process_node(node)

# Reverse postorder (optimal for forward dataflow)
for node in iter_cfg_reverse_postorder(cfg):
    process_node(node)
```

### 7.4 Dominator Analysis

```python
from cppcheckdata_shims.ctrlflow_graph import compute_dominators, compute_postdominators

# Compute dominators
dominators = compute_dominators(cfg)
# dominators[node] = set of nodes that dominate node

# Check if A dominates B
if node_a in dominators[node_b]:
    print("A dominates B (all paths to B go through A)")

# Compute post-dominators
postdominators = compute_postdominators(cfg)
# postdominators[node] = set of nodes that post-dominate node
```

---

## 8. Module Reference: dataflow_engine.py

The dataflow engine provides generic solvers for dataflow problems.

### 8.1 The Dataflow Framework

A dataflow analysis is defined by:
1. **Direction**: Forward or backward
2. **Domain**: The abstract domain for facts
3. **Transfer function**: How facts change at each node
4. **Meet/Join operator**: How facts combine at merge points

```python
from cppcheckdata_shims.dataflow_engine import DataflowAnalysis, Direction

class MyAnalysis(DataflowAnalysis):
    direction = Direction.FORWARD
    
    def initial_value(self):
        """Value at entry (forward) or exit (backward)."""
        return MyDomain.bottom()
    
    def transfer(self, node, in_value):
        """Compute out_value from in_value for a node."""
        out_value = in_value
        for token in node.tokens:
            out_value = self.transfer_token(out_value, token)
        return out_value
    
    def merge(self, values):
        """Combine values at a merge point."""
        result = MyDomain.bottom()
        for v in values:
            result = result.join(v)
        return result
```

### 8.2 Forward Analysis

Information flows from entry to exit:

```python
from cppcheckdata_shims.dataflow_engine import ForwardDataflowSolver

class ReachingDefinitions(DataflowAnalysis):
    """Which definitions may reach each point?"""
    direction = Direction.FORWARD
    
    def initial_value(self):
        return set()  # No definitions at entry
    
    def transfer(self, node, in_defs):
        out_defs = set(in_defs)
        for token in node.tokens:
            if is_assignment(token):
                var_id = tok_var_id(tok_op1(token))
                # Kill previous definitions of this variable
                out_defs = {d for d in out_defs if d[0] != var_id}
                # Add this definition
                out_defs.add((var_id, token.Id))
        return out_defs
    
    def merge(self, values):
        return set().union(*values)

# Run the analysis
solver = ForwardDataflowSolver(cfg, ReachingDefinitions())
results = solver.solve()
# results[node] = set of (var_id, def_token_id) reaching node
```

### 8.3 Backward Analysis

Information flows from exit to entry:

```python
from cppcheckdata_shims.dataflow_engine import BackwardDataflowSolver

class LiveVariables(DataflowAnalysis):
    """Which variables are live (used later) at each point?"""
    direction = Direction.BACKWARD
    
    def initial_value(self):
        return set()  # No variables live at exit
    
    def transfer(self, node, out_live):
        in_live = set(out_live)
        # Process tokens in reverse order
        for token in reversed(node.tokens):
            if is_assignment(token):
                var_id = tok_var_id(tok_op1(token))
                in_live.discard(var_id)  # Definition kills liveness
            for used_var in get_variables_used(token):
                in_live.add(used_var)    # Use makes variable live
        return in_live
    
    def merge(self, values):
        return set().union(*values)

solver = BackwardDataflowSolver(cfg, LiveVariables())
results = solver.solve()
```

### 8.4 Worklist Algorithms

The engine uses efficient worklist algorithms:

```python
from cppcheckdata_shims.dataflow_engine import WorklistSolver, WorklistStrategy

# Different strategies for different use cases
solver = WorklistSolver(
    cfg,
    analysis,
    strategy=WorklistStrategy.REVERSE_POSTORDER  # Optimal for most cases
)

# Other strategies:
# - WorklistStrategy.FIFO: Simple queue
# - WorklistStrategy.LIFO: Stack-based
# - WorklistStrategy.PRIORITY: Priority queue based on node depth
```

### 8.5 Fixpoint Computation

For analyses with infinite-height domains:

```python
from cppcheckdata_shims.dataflow_engine import WideningStrategy

solver = ForwardDataflowSolver(
    cfg,
    interval_analysis,
    widening_strategy=WideningStrategy.DELAY(3),  # Widen after 3 iterations
    narrowing_iterations=2,  # Narrow 2 times after fixpoint
)
```

---

## 9. Module Reference: taint_analysis.py

Taint analysis tracks untrusted data flow for security vulnerability detection.

### 9.1 Taint Analysis Concepts

**Taint analysis** identifies when data from untrusted **sources** reaches sensitive **sinks** without proper **sanitization**.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    SOURCE    │────▶│  PROPAGATION │────▶│     SINK     │
│  (untrusted) │     │   (data flow)│     │  (sensitive) │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │  SANITIZER   │
                     │  (cleansing) │
                     └──────────────┘
```

Examples:
- **Source**: `getenv()`, `fgets()`, `recv()`, command-line arguments
- **Sink**: `system()`, `printf()` format string, SQL query
- **Sanitizer**: `escape()`, `validate()`, bounds checking

### 9.2 Configuring Sources, Sinks, and Sanitizers

```python
from cppcheckdata_shims.taint_analysis import (
    TaintConfig,
    TaintSource, SourceKind,
    TaintSink, SinkKind,
    TaintSanitizer,
    TaintPropagator, PropagationKind,
)

config = TaintConfig()

# Define sources
config.add_source(TaintSource(
    function="getenv",
    kind=SourceKind.RETURN_VALUE,
    description="Environment variable",
    cwe=78,
))

config.add_source(TaintSource(
    function="fgets",
    kind=SourceKind.ARGUMENT_OUT,
    argument_index=0,  # First argument receives tainted data
    description="User input from file",
))

# Define sinks
config.add_sink(TaintSink(
    function="system",
    argument_index=0,
    kind=SinkKind.COMMAND_INJECTION,
    description="Shell command execution",
    cwe=78,
    severity=10,
))

config.add_sink(TaintSink(
    function="printf",
    argument_index=0,
    kind=SinkKind.FORMAT_STRING,
    description="Format string",
    cwe=134,
    severity=8,
))

# Define sanitizers
config.add_sanitizer(TaintSanitizer(
    function="escape_shell",
    argument_index=0,
    sanitizes_return=True,
    valid_for_sinks=frozenset({SinkKind.COMMAND_INJECTION}),
))

# Define propagators (how taint flows through functions)
config.add_propagator(TaintPropagator(
    function="strcpy",
    propagation_kind=PropagationKind.COPY,
    from_arguments=frozenset({1}),  # Source argument
    to_arguments=frozenset({0}),     # Destination argument
    to_return=True,
))

# Mark function parameters as tainted
config.add_tainted_parameter("main", 1)  # argv
```

### 9.3 Running the Analyzer

```python
from cppcheckdata_shims.taint_analysis import TaintAnalyzer

# Create analyzer with configuration
analyzer = TaintAnalyzer(
    config,
    track_flow_paths=True,   # Record how taint propagates
    verbose=False,
)

# Analyze a function
result = analyzer.analyze_function(function_scope)

# Or analyze entire configuration
result = analyzer.analyze_configuration(cfg)

# Check results
if result.has_violations():
    for violation in result.violations:
        print(f"Vulnerability at {violation.location}")
        print(f"  Type: {violation.sink_kind.name}")
        print(f"  CWE: {violation.cwe}")
        print(f"  Severity: {violation.severity}/10")
```

### 9.4 Interpreting Results

```python
from cppcheckdata_shims.taint_analysis import (
    TaintViolation,
    format_violations_text,
    format_violations_sarif,
)

for violation in result.violations:
    # Basic information
    print(f"File: {violation.location}")
    print(f"Function: {violation.function}")
    print(f"Sink type: {violation.sink_kind.name}")
    print(f"CWE: {violation.cwe}")
    print(f"Severity: {violation.severity}")
    print(f"Confidence: {violation.confidence:.0%}")
    
    # Taint sources
    print(f"Tainted from: {violation.taint_sources}")
    
    # Flow path (if tracked)
    if violation.flow_path:
        print("Flow path:")
        for step in violation.flow_path.steps:
            print(f"  {step.location}: {step.description}")

# Format for output
print(format_violations_text(result.violations))

# Or generate SARIF for CI/CD integration
sarif_json = format_violations_sarif(result.violations)
```

---

## 10. Module Reference: symbolic_exec.py

Symbolic execution explores program paths with symbolic (unknown) values.

### 10.1 Symbolic Execution Basics

Instead of concrete values, we use **symbolic values** and track **path conditions**:

```c
void foo(int x) {
    if (x > 0) {
        // Path condition: x > 0
        if (x < 10) {
            // Path condition: x > 0 ∧ x < 10
            // x ∈ {1, 2, ..., 9}
        }
    }
}
```

### 10.2 Symbolic Values and Expressions

```python
from cppcheckdata_shims.symbolic_exec import (
    SymbolicValue,
    SymbolicExpr,
    SymbolicState,
)

# Create symbolic values
x = SymbolicValue.symbol("x")
y = SymbolicValue.symbol("y")
five = SymbolicValue.constant(5)

# Build expressions
expr = x.add(y).mul(five)  # (x + y) * 5

# Evaluate with concrete values
result = expr.evaluate({"x": 3, "y": 2})
assert result == 25

# Check satisfiability
is_sat = expr.eq(SymbolicValue.constant(25)).is_satisfiable()
```

### 10.3 Path Conditions

```python
from cppcheckdata_shims.symbolic_exec import PathCondition, SymbolicExecutor

# Build path conditions
pc = PathCondition()
pc = pc.add_constraint(x.gt(SymbolicValue.constant(0)))  # x > 0
pc = pc.add_constraint(x.lt(SymbolicValue.constant(10))) # x < 10

# Check if path is feasible
if pc.is_satisfiable():
    print("Path is feasible")
    model = pc.get_model()  # Get satisfying assignment
    print(f"Example: x = {model['x']}")
```

### 10.4 Constraint Solving

```python
from cppcheckdata_shims.constraint_engine import ConstraintSolver

solver = ConstraintSolver()

# Add constraints
solver.add(x > 0)
solver.add(x < 100)
solver.add(x + y == 50)

# Check and get model
if solver.check():
    model = solver.model()
    print(f"x = {model['x']}, y = {model['y']}")
```

---

## 11. Module Reference: memory_abstraction.py

Memory abstraction models heap and stack for pointer analysis.

### 11.1 Memory Models

```python
from cppcheckdata_shims.memory_abstraction import (
    MemoryModel,
    MemoryLocation,
    AllocationSite,
)

# Create memory model
memory = MemoryModel()

# Track allocation
alloc_site = AllocationSite(token=malloc_call, size=IntervalDomain.range(0, 100))
ptr_location = memory.allocate(alloc_site)

# Track pointer assignment
memory.assign(var_x, ptr_location)

# Check what a pointer may point to
targets = memory.points_to(var_x)
```

### 11.2 Points-To Analysis

```python
from cppcheckdata_shims.memory_abstraction import PointsToAnalysis

# Run points-to analysis
pta = PointsToAnalysis()
result = pta.analyze(cfg)

# Query results
for var_id in result.all_pointers():
    targets = result.points_to(var_id)
    print(f"Variable {var_id} may point to: {targets}")
```

### 11.3 Alias Analysis

```python
from cppcheckdata_shims.memory_abstraction import may_alias, must_alias

# Check if two pointers may alias
if may_alias(ptr_a, ptr_b, memory_state):
    print("Pointers may refer to same memory")

# Check if two pointers must alias
if must_alias(ptr_a, ptr_b, memory_state):
    print("Pointers definitely refer to same memory")
```

---

## 12. Module Reference: callgraph.py

Call graphs enable interprocedural analysis.

### 12.1 Building Call Graphs

```python
from cppcheckdata_shims.callgraph import CallGraphBuilder, CallGraph

# Build call graph from dump data
builder = CallGraphBuilder()
cg = builder.build(data)  # data from cppcheckdata.parsedump()

# Access nodes
for func_name, node in cg.nodes.items():
    print(f"Function: {func_name}")
    print(f"  Calls: {[callee.name for callee in node.callees]}")
    print(f"  Called by: {[caller.name for caller in node.callers]}")
```

### 12.2 Call Graph Traversal

```python
from cppcheckdata_shims.callgraph import (
    iter_callgraph_topological,
    iter_callgraph_reverse_topological,
    get_reachable_functions,
    get_call_chain,
)

# Topological order (callees before callers)
for func in iter_callgraph_topological(cg):
    analyze_function(func)

# Reverse topological (callers before callees)
for func in iter_callgraph_reverse_topological(cg):
    propagate_summaries(func)

# Get all functions reachable from main
reachable = get_reachable_functions(cg, "main")

# Get call chain between two functions
chain = get_call_chain(cg, "main", "vulnerable_func")
print(" → ".join(chain))
```

### 12.3 Interprocedural Analysis Support

```python
from cppcheckdata_shims.interproc_analysis import (
    FunctionSummary,
    InterproceduralAnalyzer,
)

class MySummary(FunctionSummary):
    """Summary of function behavior for interprocedural analysis."""
    
    def __init__(self):
        self.may_return_null = False
        self.modifies_globals = set()
        self.tainted_returns = False

# Build summaries bottom-up
analyzer = InterproceduralAnalyzer(cg)
summaries = analyzer.compute_summaries(MySummary)

# Use summaries in analysis
for func_name, summary in summaries.items():
    if summary.may_return_null:
        print(f"{func_name} may return NULL")
```

---

## 13. Module Reference: type_analysis.py

Type analysis provides type inference and checking.

### 13.1 Type Representation

```python
from cppcheckdata_shims.type_analysis import (
    CType,
    PrimitiveType,
    PointerType,
    ArrayType,
    FunctionType,
    StructType,
)

# Primitive types
int_type = PrimitiveType.INT
char_type = PrimitiveType.CHAR
void_type = PrimitiveType.VOID

# Pointer types
int_ptr = PointerType(int_type)          # int*
char_ptr_ptr = PointerType(PointerType(char_type))  # char**

# Array types
int_array = ArrayType(int_type, size=10)  # int[10]

# Function types
func_type = FunctionType(
    return_type=int_type,
    param_types=[int_type, char_ptr],
)
```

### 13.2 Type Inference

```python
from cppcheckdata_shims.type_analysis import infer_type, get_expression_type

# Infer type of an expression
expr_type = infer_type(expression_token)

# Get type from Cppcheck's valueType
ctype = get_expression_type(token)
if ctype:
    print(f"Type: {ctype}")
    print(f"Is pointer: {ctype.is_pointer()}")
    print(f"Is integral: {ctype.is_integral()}")
    print(f"Size in bytes: {ctype.sizeof()}")

# Type inference for complex expressions
def analyze_expression_type(token):
    """Infer the type of an expression."""
    if is_literal(token):
        s = tok_str(token)
        if s.startswith('"'):
            return PointerType(PrimitiveType.CHAR)  # String literal
        elif '.' in s or 'e' in s.lower():
            return PrimitiveType.DOUBLE
        else:
            return PrimitiveType.INT
    
    elif is_identifier(token):
        var = tok_variable(token)
        if var:
            return parse_variable_type(var)
    
    elif is_dereference(token):
        ptr_type = infer_type(tok_op1(token))
        if isinstance(ptr_type, PointerType):
            return ptr_type.pointee_type
    
    elif is_address_of(token):
        operand_type = infer_type(tok_op1(token))
        return PointerType(operand_type)
    
    elif is_subscript(token):
        array_type = infer_type(tok_op1(token))
        if isinstance(array_type, (ArrayType, PointerType)):
            return array_type.element_type
    
    return None
```

### 13.3 Type Compatibility Checking

```python
from cppcheckdata_shims.type_analysis import (
    types_compatible,
    can_implicitly_convert,
    get_common_type,
    TypeCompatibility,
)

# Check if types are compatible
result = types_compatible(type_a, type_b)
if result == TypeCompatibility.EXACT:
    print("Types are identical")
elif result == TypeCompatibility.COMPATIBLE:
    print("Types are compatible (implicit conversion)")
elif result == TypeCompatibility.INCOMPATIBLE:
    print("Types are incompatible")

# Check implicit conversion
if can_implicitly_convert(source_type, target_type):
    print(f"Can convert {source_type} to {target_type}")

# Get common type for binary operations
common = get_common_type(left_type, right_type)
# e.g., int + double → double

# Practical example: Check for dangerous narrowing
def check_narrowing_conversion(assignment_token):
    """Detect potentially dangerous narrowing conversions."""
    lhs = tok_op1(assignment_token)
    rhs = tok_op2(assignment_token)
    
    lhs_type = get_expression_type(lhs)
    rhs_type = get_expression_type(rhs)
    
    if lhs_type and rhs_type:
        if lhs_type.sizeof() < rhs_type.sizeof():
            return Finding(
                file=tok_file(assignment_token),
                line=tok_line(assignment_token),
                column=tok_column(assignment_token),
                severity=Severity.WARNING,
                message=f"Narrowing conversion from {rhs_type} to {lhs_type}",
                cwe=197,  # Numeric Truncation Error
            )
    return None
```

### 13.4 Type Qualifiers and Storage Classes

```python
from cppcheckdata_shims.type_analysis import (
    TypeQualifiers,
    StorageClass,
    get_type_qualifiers,
    get_storage_class,
)

# Check type qualifiers
qualifiers = get_type_qualifiers(variable)
if qualifiers.is_const:
    print("Variable is const-qualified")
if qualifiers.is_volatile:
    print("Variable is volatile-qualified")
if qualifiers.is_restrict:
    print("Variable is restrict-qualified")

# Check storage class
storage = get_storage_class(variable)
if storage == StorageClass.STATIC:
    print("Variable has static storage duration")
elif storage == StorageClass.EXTERN:
    print("Variable is externally linked")
elif storage == StorageClass.AUTO:
    print("Variable has automatic storage duration")
elif storage == StorageClass.REGISTER:
    print("Variable has register storage class hint")
```

---

## 14. Module Reference: qscore.py

Quality scoring helps prioritize findings and reduce false positives.

### 14.1 Quality Scoring

```python
from cppcheckdata_shims.qscore import (
    QualityScore,
    compute_finding_score,
    ScoreFactors,
)

# Compute a quality score for a finding
score = compute_finding_score(
    finding=my_finding,
    factors=ScoreFactors(
        path_feasibility=0.9,      # How likely is the path feasible?
        data_flow_precision=0.85,  # How precise is the data flow?
        type_correctness=1.0,      # Are types consistent?
        context_relevance=0.8,     # Is context (e.g., in test code)?
    )
)

print(f"Quality score: {score.value:.2f}")  # 0.0 to 1.0
print(f"Confidence: {score.confidence}")    # LOW, MEDIUM, HIGH
print(f"Should report: {score.should_report(threshold=0.5)}")
```

### 14.2 Confidence Metrics

```python
from cppcheckdata_shims.qscore import (
    Confidence,
    ConfidenceCalculator,
    EvidenceType,
)

# Build confidence from multiple evidence sources
calc = ConfidenceCalculator()

# Add positive evidence (increases confidence)
calc.add_evidence(EvidenceType.DEFINITE_VALUE, weight=1.0)
calc.add_evidence(EvidenceType.TYPE_MATCH, weight=0.8)
calc.add_evidence(EvidenceType.PATH_SENSITIVE, weight=0.7)

# Add negative evidence (decreases confidence)
calc.add_evidence(EvidenceType.MAY_BE_SANITIZED, weight=-0.3)
calc.add_evidence(EvidenceType.IN_TEST_CODE, weight=-0.5)

# Compute final confidence
confidence = calc.compute()
print(f"Confidence level: {confidence.level}")  # LOW, MEDIUM, HIGH
print(f"Confidence value: {confidence.value:.2f}")
```

### 14.3 False Positive Reduction

```python
from cppcheckdata_shims.qscore import (
    FalsePositiveFilter,
    FilterRule,
    FilterAction,
)

# Create a filter for reducing false positives
fp_filter = FalsePositiveFilter()

# Add filter rules
fp_filter.add_rule(FilterRule(
    name="test_code",
    description="Findings in test files are lower priority",
    condition=lambda f: "test" in f.file.lower(),
    action=FilterAction.REDUCE_CONFIDENCE,
    factor=0.5,
))

fp_filter.add_rule(FilterRule(
    name="generated_code",
    description="Skip generated code",
    condition=lambda f: f.file.endswith(".gen.c"),
    action=FilterAction.SUPPRESS,
))

fp_filter.add_rule(FilterRule(
    name="assert_context",
    description="Findings after assert are likely guarded",
    condition=lambda f: is_after_assert(f),
    action=FilterAction.REDUCE_CONFIDENCE,
    factor=0.7,
))

# Apply filter to findings
filtered_findings = fp_filter.apply(all_findings)

# Get statistics
stats = fp_filter.get_statistics()
print(f"Original: {stats.original_count}")
print(f"Suppressed: {stats.suppressed_count}")
print(f"Reduced confidence: {stats.reduced_count}")
print(f"Final: {stats.final_count}")
```

### 14.4 Ranking and Prioritization

```python
from cppcheckdata_shims.qscore import rank_findings, PriorityFactors

# Rank findings by importance
ranked = rank_findings(
    findings,
    factors=PriorityFactors(
        severity_weight=0.4,      # How much severity matters
        confidence_weight=0.3,    # How much confidence matters
        exploitability_weight=0.2,# How exploitable is the bug?
        recency_weight=0.1,       # Prefer findings in recently changed code
    )
)

# Print top 10 most important findings
for i, (finding, score) in enumerate(ranked[:10], 1):
    print(f"{i}. [{score:.2f}] {finding.file}:{finding.line} - {finding.message}")
```

---

## 15. Putting It All Together: Complete Examples

### 15.1 Example: Null Pointer Dereference Checker

This checker detects potential null pointer dereferences using dataflow analysis.

```python
#!/usr/bin/env python3
"""
NullDerefChecker.py — Null Pointer Dereference Detection

Detects CWE-476: NULL Pointer Dereference

This checker uses forward dataflow analysis to track which pointers
may be null at each program point, and reports when such pointers
are dereferenced.
"""

import sys
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
from enum import Enum, auto

import cppcheckdata
from cppcheckdata_shims.ast_helper import (
    tok_str, tok_op1, tok_op2, tok_parent,
    tok_var_id, tok_variable,
    tok_file, tok_line, tok_column,
    is_assignment, is_function_call, is_dereference,
    is_subscript, is_comparison, is_identifier,
    get_called_function_name, get_call_arguments,
    iter_ast_preorder, token_location,
)
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder, CFGNode
from cppcheckdata_shims.dataflow_engine import (
    DataflowAnalysis, Direction, ForwardDataflowSolver
)


class NullState(Enum):
    """Abstract state for a pointer variable."""
    BOTTOM = auto()      # Unreachable / no information
    NULL = auto()        # Definitely null
    NOT_NULL = auto()    # Definitely not null
    MAYBE_NULL = auto()  # May or may not be null
    TOP = auto()         # Any value (same as MAYBE_NULL for this analysis)


@dataclass
class NullnessState:
    """
    Abstract state mapping variables to their nullness.
    
    This is the domain for our dataflow analysis.
    """
    var_states: Dict[int, NullState]
    
    @classmethod
    def bottom(cls) -> 'NullnessState':
        """Unreachable state."""
        return cls({})
    
    @classmethod
    def top(cls) -> 'NullnessState':
        """State with no information."""
        return cls({})
    
    def copy(self) -> 'NullnessState':
        return NullnessState(dict(self.var_states))
    
    def get(self, var_id: int) -> NullState:
        """Get nullness state for a variable."""
        return self.var_states.get(var_id, NullState.MAYBE_NULL)
    
    def set(self, var_id: int, state: NullState) -> 'NullnessState':
        """Set nullness state for a variable."""
        result = self.copy()
        result.var_states[var_id] = state
        return result
    
    def join(self, other: 'NullnessState') -> 'NullnessState':
        """Least upper bound of two states."""
        result = {}
        all_vars = set(self.var_states.keys()) | set(other.var_states.keys())
        
        for var_id in all_vars:
            s1 = self.get(var_id)
            s2 = other.get(var_id)
            
            if s1 == s2:
                result[var_id] = s1
            elif s1 == NullState.BOTTOM:
                result[var_id] = s2
            elif s2 == NullState.BOTTOM:
                result[var_id] = s1
            else:
                # Different non-bottom states → may be null
                result[var_id] = NullState.MAYBE_NULL
        
        return NullnessState(result)
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, NullnessState):
            return False
        return self.var_states == other.var_states


class NullnessAnalysis(DataflowAnalysis):
    """
    Forward dataflow analysis tracking pointer nullness.
    """
    direction = Direction.FORWARD
    
    # Functions that may return NULL
    MAY_RETURN_NULL = frozenset({
        "malloc", "calloc", "realloc", "aligned_alloc",
        "fopen", "freopen", "tmpfile",
        "fgets", "gets",
        "getenv",
        "strchr", "strrchr", "strstr", "strpbrk",
        "bsearch",
        "dlopen", "dlsym",
    })
    
    # Functions that never return NULL (or don't return on failure)
    NEVER_RETURNS_NULL = frozenset({
        "xmalloc", "xrealloc", "xcalloc",  # Common "safe" allocators
    })
    
    def initial_value(self) -> NullnessState:
        """At function entry, parameters are assumed non-null."""
        return NullnessState.top()
    
    def transfer(self, node: CFGNode, in_state: NullnessState) -> NullnessState:
        """Transfer function for a basic block."""
        state = in_state.copy()
        
        for token in node.tokens:
            state = self.transfer_token(state, token)
        
        return state
    
    def transfer_token(self, state: NullnessState, token) -> NullnessState:
        """Transfer function for a single token."""
        # Handle assignments: x = ...
        if is_assignment(token):
            lhs = tok_op1(token)
            rhs = tok_op2(token)
            var_id = tok_var_id(lhs)
            
            if var_id:
                # Determine nullness of RHS
                rhs_nullness = self.evaluate_nullness(state, rhs)
                state = state.set(var_id, rhs_nullness)
        
        return state
    
    def evaluate_nullness(self, state: NullnessState, expr) -> NullState:
        """Evaluate the nullness of an expression."""
        if expr is None:
            return NullState.MAYBE_NULL
        
        s = tok_str(expr)
        
        # NULL literal
        if s in ("NULL", "nullptr", "0"):
            return NullState.NULL
        
        # Non-null literals
        if s.startswith('"') or s.startswith("'"):
            return NullState.NOT_NULL
        
        # Variable reference
        var_id = tok_var_id(expr)
        if var_id:
            return state.get(var_id)
        
        # Function call
        if is_function_call(expr):
            func_name = get_called_function_name(expr)
            if func_name in self.MAY_RETURN_NULL:
                return NullState.MAYBE_NULL
            elif func_name in self.NEVER_RETURNS_NULL:
                return NullState.NOT_NULL
            else:
                # Conservative: assume may return null for unknown functions
                return NullState.MAYBE_NULL
        
        # Address-of is never null
        if s == "&":
            return NullState.NOT_NULL
        
        # Array decay is never null (for local arrays)
        if is_identifier(expr):
            var = tok_variable(expr)
            if var and getattr(var, 'isArray', False):
                return NullState.NOT_NULL
        
        return NullState.MAYBE_NULL
    
    def merge(self, states: List[NullnessState]) -> NullnessState:
        """Merge states at a join point."""
        if not states:
            return NullnessState.bottom()
        
        result = states[0]
        for state in states[1:]:
            result = result.join(state)
        
        return result


class NullDerefChecker(CheckerBase):
    """
    Checker for null pointer dereferences.
    
    Uses dataflow analysis to track nullness and reports when
    potentially null pointers are dereferenced.
    """
    
    name = "NullDeref"
    description = "Detects potential null pointer dereferences"
    version = "1.0.0"
    
    def check(self, cfg) -> List[Finding]:
        """Run the checker on a configuration."""
        findings = []
        
        for scope in cfg.scopes:
            if getattr(scope, 'type', '') == 'Function':
                scope_findings = self.check_function(scope, cfg)
                findings.extend(scope_findings)
        
        return findings
    
    def check_function(self, scope, cfg) -> List[Finding]:
        """Check a single function for null dereferences."""
        findings = []
        
        # Build CFG
        try:
            builder = CFGBuilder()
            func_cfg = builder.build(scope)
        except Exception:
            return findings  # Skip if CFG construction fails
        
        # Run nullness analysis
        analysis = NullnessAnalysis()
        solver = ForwardDataflowSolver(func_cfg, analysis)
        results = solver.solve()
        
        # Check each node for dereferences of maybe-null pointers
        for node in func_cfg.nodes:
            state = results.get(node, NullnessState.top())
            
            for token in node.tokens:
                finding = self.check_token(token, state)
                if finding:
                    findings.append(finding)
                
                # Update state for subsequent checks in same block
                state = analysis.transfer_token(state, token)
        
        return findings
    
    def check_token(self, token, state: NullnessState) -> Optional[Finding]:
        """Check a token for null dereference."""
        # Check pointer dereference: *ptr
        if is_dereference(token):
            ptr = tok_op1(token)
            return self.check_pointer(ptr, state, token, "dereference")
        
        # Check array subscript: ptr[i]
        if is_subscript(token):
            ptr = tok_op1(token)
            return self.check_pointer(ptr, state, token, "array subscript")
        
        # Check member access: ptr->member
        if tok_str(token) == "->":
            ptr = tok_op1(token)
            return self.check_pointer(ptr, state, token, "member access")
        
        return None
    
    def check_pointer(
        self,
        ptr_expr,
        state: NullnessState,
        deref_token,
        context: str
    ) -> Optional[Finding]:
        """Check if a pointer expression may be null."""
        if ptr_expr is None:
            return None
        
        var_id = tok_var_id(ptr_expr)
        if not var_id:
            return None
        
        nullness = state.get(var_id)
        
        if nullness == NullState.NULL:
            return Finding(
                file=tok_file(deref_token) or "<unknown>",
                line=tok_line(deref_token) or 0,
                column=tok_column(deref_token) or 0,
                severity=Severity.ERROR,
                message=f"Definite null pointer {context}",
                checker=self.name,
                cwe=476,
                confidence=1.0,
            )
        
        elif nullness == NullState.MAYBE_NULL:
            return Finding(
                file=tok_file(deref_token) or "<unknown>",
                line=tok_line(deref_token) or 0,
                column=tok_column(deref_token) or 0,
                severity=Severity.WARNING,
                message=f"Potential null pointer {context}",
                checker=self.name,
                cwe=476,
                confidence=0.7,
            )
        
        return None


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dump-file>", file=sys.stderr)
        sys.exit(1)
    
    checker = NullDerefChecker()
    all_findings = []
    
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
            for cfg in data.configurations:
                findings = checker.check(cfg)
                all_findings.extend(findings)
        except Exception as e:
            print(f"Error processing {dump_file}: {e}", file=sys.stderr)
    
    # Print findings
    for finding in all_findings:
        print(finding)
    
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
```

### 15.2 Example: Buffer Overflow Detector

This checker uses interval analysis to detect buffer overflows.

```python
#!/usr/bin/env python3
"""
BufferOverflowChecker.py — Buffer Overflow Detection

Detects CWE-119: Improper Restriction of Operations within Memory Buffer Bounds
Detects CWE-120: Buffer Copy without Checking Size of Input
Detects CWE-125: Out-of-bounds Read
Detects CWE-787: Out-of-bounds Write

Uses interval analysis to track buffer sizes and access indices.
"""

import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import cppcheckdata
from cppcheckdata_shims.ast_helper import (
    tok_str, tok_op1, tok_op2,
    tok_var_id, tok_variable, tok_values,
    tok_file, tok_line, tok_column,
    is_assignment, is_function_call, is_subscript,
    is_identifier, is_number,
    get_called_function_name, get_call_arguments,
    get_array_size, expr_to_string,
    iter_tokens_in_scope,
)
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity
from cppcheckdata_shims.abstract_domains import IntervalDomain


@dataclass
class BufferInfo:
    """Information about a buffer."""
    var_id: int
    size: IntervalDomain  # Size in elements
    element_size: int     # Size of each element in bytes
    is_heap: bool         # True if heap-allocated
    allocation_site: Optional[object] = None


class BufferOverflowChecker(CheckerBase):
    """
    Checker for buffer overflow vulnerabilities.
    
    Tracks buffer sizes and detects when accesses may exceed bounds.
    """
    
    name = "BufferOverflow"
    description = "Detects buffer overflow vulnerabilities"
    version = "1.0.0"
    
    # Functions that copy data to buffers
    COPY_FUNCTIONS = {
        # function: (dest_arg, size_arg or None, src_arg)
        "strcpy": (0, None, 1),    # No size limit
        "strncpy": (0, 2, 1),
        "strcat": (0, None, 1),
        "strncat": (0, 2, 1),
        "memcpy": (0, 2, 1),
        "memmove": (0, 2, 1),
        "memset": (0, 2, None),
        "sprintf": (0, None, None),  # Format string, no size
        "snprintf": (0, 1, None),
        "gets": (0, None, None),     # DANGEROUS
        "fgets": (0, 1, None),
        "read": (1, 2, None),
        "recv": (1, 2, None),
    }
    
    def check(self, cfg) -> List[Finding]:
        """Run the checker on a configuration."""
        findings = []
        
        for scope in cfg.scopes:
            if getattr(scope, 'type', '') == 'Function':
                scope_findings = self.check_function(scope, cfg)
                findings.extend(scope_findings)
        
        return findings
    
    def check_function(self, scope, cfg) -> List[Finding]:
        """Check a single function for buffer overflows."""
        findings = []
        
        # Track known buffer sizes
        buffers: Dict[int, BufferInfo] = {}
        
        # First pass: collect buffer information
        for token in iter_tokens_in_scope(scope):
            self.collect_buffer_info(token, buffers)
        
        # Second pass: check accesses
        for token in iter_tokens_in_scope(scope):
            # Check array subscript
            if is_subscript(token):
                finding = self.check_array_access(token, buffers)
                if finding:
                    findings.append(finding)
            
            # Check buffer copy functions
            if is_function_call(token):
                func_findings = self.check_copy_function(token, buffers)
                findings.extend(func_findings)
        
        return findings
    
    def collect_buffer_info(self, token, buffers: Dict[int, BufferInfo]) -> None:
        """Collect information about buffers."""
        # Stack-allocated arrays
        if is_identifier(token):
            var = tok_variable(token)
            if var and getattr(var, 'isArray', False):
                var_id = var.Id
                if var_id not in buffers:
                    size = get_array_size(token)
                    if size is not None:
                        buffers[var_id] = BufferInfo(
                            var_id=var_id,
                            size=IntervalDomain.const(size),
                            element_size=self.get_element_size(var),
                            is_heap=False,
                        )
        
        # Heap allocations: ptr = malloc(size)
        if is_assignment(token):
            rhs = tok_op2(token)
            if is_function_call(rhs):
                func_name = get_called_function_name(rhs)
                if func_name in ("malloc", "calloc", "realloc"):
                    lhs = tok_op1(token)
                    var_id = tok_var_id(lhs)
                    if var_id:
                        size = self.get_allocation_size(rhs, func_name)
                        if size:
                            buffers[var_id] = BufferInfo(
                                var_id=var_id,
                                size=size,
                                element_size=1,  # Assume byte-sized for malloc
                                is_heap=True,
                                allocation_site=rhs,
                            )
    
    def get_element_size(self, var) -> int:
        """Get the size of array elements."""
        # This is simplified; real implementation would parse the type
        type_token = getattr(var, 'typeStartToken', None)
        if type_token:
            type_str = tok_str(type_token)
            sizes = {
                "char": 1, "unsigned char": 1, "signed char": 1,
                "short": 2, "unsigned short": 2,
                "int": 4, "unsigned int": 4, "unsigned": 4,
                "long": 8, "unsigned long": 8,
                "float": 4, "double": 8,
            }
            return sizes.get(type_str, 4)
        return 4  # Default assumption
    
    def get_allocation_size(self, call_token, func_name: str) -> Optional[IntervalDomain]:
        """Get the allocation size from a malloc/calloc/realloc call."""
        args = get_call_arguments(call_token)
        
        if func_name == "malloc" and len(args) >= 1:
            return self.evaluate_size_expr(args[0])
        
        elif func_name == "calloc" and len(args) >= 2:
            count = self.evaluate_size_expr(args[0])
            elem_size = self.evaluate_size_expr(args[1])
            if count and elem_size:
                return count.mul(elem_size)
        
        elif func_name == "realloc" and len(args) >= 2:
            return self.evaluate_size_expr(args[1])
        
        return None
    
    def evaluate_size_expr(self, expr) -> Optional[IntervalDomain]:
        """Evaluate a size expression to an interval."""
        if expr is None:
            return None
        
        # Numeric literal
        if is_number(expr):
            try:
                value = int(tok_str(expr))
                return IntervalDomain.const(value)
            except ValueError:
                pass
        
        # Use Cppcheck's value flow
        values = tok_values(expr)
        if values:
            int_values = []
            for v in values:
                intval = getattr(v, 'intvalue', None)
                if intval is not None:
                    int_values.append(intval)
            
            if int_values:
                return IntervalDomain.range(min(int_values), max(int_values))
        
        # Unknown size
        return IntervalDomain.at_least(0)  # Conservative: non-negative
    
    def check_array_access(
        self,
        subscript_token,
        buffers: Dict[int, BufferInfo]
    ) -> Optional[Finding]:
        """Check an array subscript for out-of-bounds access."""
        array_expr = tok_op1(subscript_token)
        index_expr = tok_op2(subscript_token)
        
        if not array_expr or not index_expr:
            return None
        
        # Get buffer info
        var_id = tok_var_id(array_expr)
        if not var_id or var_id not in buffers:
            return None
        
        buffer_info = buffers[var_id]
        
        # Get index value
        index_interval = self.evaluate_size_expr(index_expr)
        if index_interval is None:
            return None
        
        # Check for negative index
        if index_interval.may_be_negative():
            return Finding(
                file=tok_file(subscript_token) or "<unknown>",
                line=tok_line(subscript_token) or 0,
                column=tok_column(subscript_token) or 0,
                severity=Severity.WARNING,
                message=f"Array index may be negative: {expr_to_string(index_expr)}",
                checker=self.name,
                cwe=125,
                confidence=0.8,
            )
        
        # Check for overflow
        buffer_size = buffer_info.size
        if not buffer_size.is_top():
            # index >= size means overflow
            if index_interval.lo is not None and buffer_size.hi is not None:
                if index_interval.lo >= buffer_size.hi:
                    return Finding(
                        file=tok_file(subscript_token) or "<unknown>",
                        line=tok_line(subscript_token) or 0,
                        column=tok_column(subscript_token) or 0,
                        severity=Severity.ERROR,
                        message=f"Buffer overflow: index {index_interval} >= size {buffer_size}",
                        checker=self.name,
                        cwe=787,
                        confidence=1.0,
                    )
                elif index_interval.hi is not None and index_interval.hi >= buffer_size.hi:
                    return Finding(
                        file=tok_file(subscript_token) or "<unknown>",
                        line=tok_line(subscript_token) or 0,
                        column=tok_column(subscript_token) or 0,
                        severity=Severity.WARNING,
                        message=f"Potential buffer overflow: index may reach {index_interval.hi}, size is {buffer_size}",
                        checker=self.name,
                        cwe=787,
                        confidence=0.7,
                    )
        
        return None
    
    def check_copy_function(
        self,
        call_token,
        buffers: Dict[int, BufferInfo]
    ) -> List[Finding]:
        """Check a buffer copy function for overflow."""
        findings = []
        func_name = get_called_function_name(call_token)
        
        if func_name not in self.COPY_FUNCTIONS:
            return findings
        
        dest_idx, size_idx, src_idx = self.COPY_FUNCTIONS[func_name]
        args = get_call_arguments(call_token)
        
        # Check for dangerous functions with no size limit
        if size_idx is None and func_name in ("strcpy", "strcat", "sprintf", "gets"):
            findings.append(Finding(
                file=tok_file(call_token) or "<unknown>",
                line=tok_line(call_token) or 0,
                column=tok_column(call_token) or 0,
                severity=Severity.WARNING if func_name != "gets" else Severity.ERROR,
                message=f"Use of {func_name} without size limit",
                checker=self.name,
                cwe=120,
                confidence=0.9,
            ))
        
        # Check if copy size exceeds buffer size
        if dest_idx < len(args) and size_idx is not None and size_idx < len(args):
            dest_expr = args[dest_idx]
            size_expr = args[size_idx]
            
            var_id = tok_var_id(dest_expr)
            if var_id and var_id in buffers:
                buffer_info = buffers[var_id]
                copy_size = self.evaluate_size_expr(size_expr)
                
                if copy_size and not buffer_info.size.is_top():
                    if (copy_size.lo is not None and 
                        buffer_info.size.hi is not None and
                        copy_size.lo > buffer_info.size.hi):
                        findings.append(Finding(
                            file=tok_file(call_token) or "<unknown>",
                            line=tok_line(call_token) or 0,
                            column=tok_column(call_token) or 0,
                            severity=Severity.ERROR,
                            message=f"Buffer overflow in {func_name}: copying {copy_size} bytes to buffer of size {buffer_info.size}",
                            checker=self.name,
                            cwe=120,
                            confidence=1.0,
                        ))
        
        return findings


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dump-file>", file=sys.stderr)
        sys.exit(1)
    
    checker = BufferOverflowChecker()
    all_findings = []
    
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
            for cfg in data.configurations:
                findings = checker.check(cfg)
                all_findings.extend(findings)
        except Exception as e:
            print(f"Error processing {dump_file}: {e}", file=sys.stderr)
    
    for finding in all_findings:
        print(finding)
    
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
```

### 15.3 Example: Use-After-Free Analyzer

This checker detects use-after-free vulnerabilities.

```python
#!/usr/bin/env python3
"""
UseAfterFreeChecker.py — Use-After-Free Detection

Detects CWE-416: Use After Free
Detects CWE-415: Double Free

Tracks memory allocation state and reports when freed memory is accessed.
"""

import sys
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from enum import Enum, auto

import cppcheckdata
from cppcheckdata_shims.ast_helper import (
    tok_str, tok_op1, tok_op2,
    tok_var_id, tok_variable,
    tok_file, tok_line, tok_column,
    is_assignment, is_function_call, is_dereference,
    is_subscript, is_identifier,
    get_called_function_name, get_call_arguments,
    iter_tokens_in_scope, token_location,
)
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity
from cppcheckdata_shims.ctrlflow_graph import CFGBuilder
from cppcheckdata_shims.dataflow_engine import (
    DataflowAnalysis, Direction, ForwardDataflowSolver
)


class MemoryState(Enum):
    """State of a memory location."""
    UNKNOWN = auto()     # Unknown state
    ALLOCATED = auto()   # Memory is allocated
    FREED = auto()       # Memory has been freed
    MAYBE_FREED = auto() # Memory may or may not be freed


@dataclass
class AllocationState:
    """
    Abstract state tracking memory allocation status.
    """
    # Maps variable ID to memory state
    var_states: Dict[int, MemoryState] = field(default_factory=dict)
    # Maps variable ID to where it was freed (for error messages)
    free_sites: Dict[int, object] = field(default_factory=dict)
    
    @classmethod
    def initial(cls) -> 'AllocationState':
        return cls()
    
    def copy(self) -> 'AllocationState':
        return AllocationState(
            dict(self.var_states),
            dict(self.free_sites)
        )
    
    def get(self, var_id: int) -> MemoryState:
        return self.var_states.get(var_id, MemoryState.UNKNOWN)
    
    def set_allocated(self, var_id: int) -> 'AllocationState':
        result = self.copy()
        result.var_states[var_id] = MemoryState.ALLOCATED
        result.free_sites.pop(var_id, None)
        return result
    
    def set_freed(self, var_id: int, free_token) -> 'AllocationState':
        result = self.copy()
        result.var_states[var_id] = MemoryState.FREED
        result.free_sites[var_id] = free_token
        return result
    
    def set_unknown(self, var_id: int) -> 'AllocationState':
        result = self.copy()
        result.var_states[var_id] = MemoryState.UNKNOWN
        result.free_sites.pop(var_id, None)
        return result
    
    def join(self, other: 'AllocationState') -> 'AllocationState':
        """Merge two states at a join point."""
        result = AllocationState()
        all_vars = set(self.var_states.keys()) | set(other.var_states.keys())
        
        for var_id in all_vars:
            s1 = self.get(var_id)
            s2 = other.get(var_id)
            
            if s1 == s2:
                result.var_states[var_id] = s1
            elif s1 == MemoryState.UNKNOWN:
                result.var_states[var_id] = s2
            elif s2 == MemoryState.UNKNOWN:
                result.var_states[var_id] = s1
            elif (s1 == MemoryState.FREED and s2 == MemoryState.ALLOCATED) or \
                 (s1 == MemoryState.ALLOCATED and s2 == MemoryState.FREED):
                result.var_states[var_id] = MemoryState.MAYBE_FREED
            else:
                result.var_states[var_id] = MemoryState.MAYBE_FREED
        
        # Merge free sites
        result.free_sites = {**self.free_sites, **other.free_sites}
        
        return result
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, AllocationState):
            return False
        return self.var_states == other.var_states


class UseAfterFreeChecker(CheckerBase):
    """
    Checker for use-after-free and double-free vulnerabilities.
    """
    
    name = "UseAfterFree"
    description = "Detects use-after-free and double-free bugs"
    version = "1.0.0"
    
    ALLOC_FUNCTIONS = frozenset({
        "malloc", "calloc", "realloc", "aligned_alloc",
        "strdup", "strndup", "asprintf", "vasprintf",
        "new", "new[]",
    })
    
    FREE_FUNCTIONS = frozenset({
        "free", "delete", "delete[]",
    })
    
    def check(self, cfg) -> List[Finding]:
        """Run the checker on a configuration."""
        findings = []
        
        for scope in cfg.scopes:
            if getattr(scope, 'type', '') == 'Function':
                scope_findings = self.check_function(scope)
                findings.extend(scope_findings)
        
        return findings
    
    def check_function(self, scope) -> List[Finding]:
        """Check a single function."""
        findings = []
        state = AllocationState.initial()
        
        for token in iter_tokens_in_scope(scope):
            # Check for allocation
            if is_assignment(token):
                rhs = tok_op2(token)
                if is_function_call(rhs):
                    func_name = get_called_function_name(rhs)
                    if func_name in self.ALLOC_FUNCTIONS:
                        lhs = tok_op1(token)
                        var_id = tok_var_id(lhs)
                        if var_id:
                            state = state.set_allocated(var_id)
            
            # Check for free
            if is_function_call(token):
                func_name = get_called_function_name(token)
                if func_name in self.FREE_FUNCTIONS:
                    args = get_call_arguments(token)
                    if args:
                        ptr_expr = args[0]
                        var_id = tok_var_id(ptr_expr)
                        if var_id:
                            current_state = state.get(var_id)
                            
                            # Double free
                            if current_state in (MemoryState.FREED, MemoryState.MAYBE_FREED):
                                prev_free = state.free_sites.get(var_id)
                                msg = "Double free detected"
                                if prev_free:
                                    msg += f" (previously freed at {token_location(prev_free)})"
                                
                                findings.append(Finding(
                                    file=tok_file(token) or "<unknown>",
                                    line=tok_line(token) or 0,
                                    column=tok_column(token) or 0,
                                    severity=Severity.ERROR,
                                    message=msg,
                                    checker=self.name,
                                    cwe=415,
                                    confidence=1.0 if current_state == MemoryState.FREED else 0.8,
                                ))
                            
                            state = state.set_freed(var_id, token)
            
            # Check for use after free
            finding = self.check_use(token, state)
            if finding:
                findings.append(finding)
        
        return findings
    
    def check_use(self, token, state: AllocationState) -> Optional[Finding]:
        """Check if a token uses freed memory."""
        # Dereference: *ptr
        if is_dereference(token):
            ptr = tok_op1(token)
            return self.check_pointer_use(ptr, token, state, "dereference")
        
        # Array access: ptr[i]
        if is_subscript(token):
            ptr = tok_op1(token)
            return self.check_pointer_use(ptr, token, state, "array access")
        
        # Member access: ptr->member
        if tok_str(token) == "->":
            ptr = tok_op1(token)
            return self.check_pointer_use(ptr, token, state, "member access")
        
        return None
    
    def check_pointer_use(
        self,
        ptr_expr,
        use_token,
        state: AllocationState,
        context: str
    ) -> Optional[Finding]:
        """Check if a pointer use accesses freed memory."""
        if ptr_expr is None:
            return None
        
        var_id = tok_var_id(ptr_expr)
        if not var_id:
            return None
        
        mem_state = state.get(var_id)
        
        if mem_state == MemoryState.FREED:
            free_site = state.free_sites.get(var_id)
            msg = f"Use after free: {context} of freed pointer"
            if free_site:
                msg += f" (freed at {token_location(free_site)})"
            
            return Finding(
                file=tok_file(use_token) or "<unknown>",
                line=tok_line(use_token) or 0,
                column=tok_column(use_token) or 0,
                severity=Severity.ERROR,
                message=msg,
                checker=self.name,
                cwe=416,
                confidence=1.0,
            )
        
        elif mem_state == MemoryState.MAYBE_FREED:
            return Finding(
                file=tok_file(use_token) or "<unknown>",
                line=tok_line(use_token) or 0,
                column=tok_column(use_token) or 0,
                severity=Severity.WARNING,
                message=f"Potential use after free: {context} of possibly freed pointer",
                checker=self.name,
                cwe=416,
                confidence=0.7,
            )
        
        return None


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dump-file>", file=sys.stderr)
        sys.exit(1)
    
    checker = UseAfterFreeChecker()
    all_findings = []
    
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
            for cfg in data.configurations:
                findings = checker.check(cfg)
                all_findings.extend(findings)
        except Exception as e:
            print(f"Error processing {dump_file}: {e}", file=sys.stderr)
    
    for finding in all_findings:
        print(finding)
    
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
```

### 15.4 Example: Format String Validator

This checker validates format strings against their arguments.

```python
#!/usr/bin/env python3
"""
FormatStringChecker.py — Format String Validation

Detects CWE-134: Use of Externally-Controlled Format String
Detects CWE-787: Out-of-bounds Write (via %n)
Detects mismatched format specifiers and arguments

Validates printf/scanf family function calls.
"""

import sys
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum, auto

import cppcheckdata
from cppcheckdata_shims.ast_helper import (
    tok_str, tok_op1, tok_op2,
    tok_var_id, tok_variable, tok_value_type,
    tok_file, tok_line, tok_column,
    is_function_call, is_literal, is_identifier,
    get_called_function_name, get_call_arguments,
    is_pointer_type, is_signed_type, is_unsigned_type,
    get_type_str,
)
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity


class FormatKind(Enum):
    """Kind of format function."""
    PRINTF = auto()   # Output formatting
    SCANF = auto()    # Input parsing


@dataclass
class FormatSpec:
    """Parsed format specifier."""
    full_spec: str           # The full specifier (e.g., "%10.2f")
    flags: str               # Flags (e.g., "-+#0 ")
    width: Optional[int]     # Field width
    width_arg: bool          # Width from argument (*)
    precision: Optional[int] # Precision
    precision_arg: bool      # Precision from argument (*)
    length: str              # Length modifier (h, l, ll, etc.)
    conversion: str          # Conversion specifier (d, s, f, etc.)
    position: int            # Position in format string


class FormatStringChecker(CheckerBase):
    """
    Checker for format string vulnerabilities and mismatches.
    """
    
    name = "FormatString"
    description = "Validates format strings and detects vulnerabilities"
    version = "1.0.0"
    
    # Format functions: name -> (kind, format_arg_index, first_vararg_index)
    FORMAT_FUNCTIONS = {
        # printf family
        "printf": (FormatKind.PRINTF, 0, 1),
        "fprintf": (FormatKind.PRINTF, 1, 2),
        "dprintf": (FormatKind.PRINTF, 1, 2),
        "sprintf": (FormatKind.PRINTF, 1, 2),
        "snprintf": (FormatKind.PRINTF, 2, 3),
        "asprintf": (FormatKind.PRINTF, 1, 2),
        "vprintf": (FormatKind.PRINTF, 0, -1),  # va_list, not varargs
        "vfprintf": (FormatKind.PRINTF, 1, -1),
        "vsprintf": (FormatKind.PRINTF, 1, -1),
        "vsnprintf": (FormatKind.PRINTF, 2, -1),
        
        # scanf family
        "scanf": (FormatKind.SCANF, 0, 1),
        "fscanf": (FormatKind.SCANF, 1, 2),
        "sscanf": (FormatKind.SCANF, 1, 2),
        "vscanf": (FormatKind.SCANF, 0, -1),
        "vfscanf": (FormatKind.SCANF, 1, -1),
        "vsscanf": (FormatKind.SCANF, 1, -1),
        
        # syslog
        "syslog": (FormatKind.PRINTF, 1, 2),
    }
    
    # Regex for format specifiers
    FORMAT_REGEX = re.compile(
        r'%'
        r'(\d+\$)?'                    # Position (POSIX)
        r'([-+#0 \']*)'                # Flags
        r'(\*|\d+)?'                   # Width
        r'(?:\.(\*|\d+))?'             # Precision
        r'(hh|h|ll|l|L|z|j|t)?'        # Length modifier
        r'([diouxXeEfFgGaAcspn%])'     # Conversion specifier
    )
    
    def check(self, cfg) -> List[Finding]:
        """Run the checker on a configuration."""
        findings = []
        
        for token in cfg.tokenlist:
            if is_function_call(token):
                func_name = get_called_function_name(token)
                if func_name in self.FORMAT_FUNCTIONS:
                    func_findings = self.check_format_call(token, func_name)
                    findings.extend(func_findings)
        
        return findings
    
    def check_format_call(self, call_token, func_name: str) -> List[Finding]:
        """Check a format function call."""
        findings = []
        kind, fmt_idx, vararg_idx = self.FORMAT_FUNCTIONS[func_name]
        
        args = get_call_arguments(call_token)
        if fmt_idx >= len(args):
            return findings
        
        fmt_arg = args[fmt_idx]
        
        # Check for non-literal format string (CWE-134)
        if not is_literal(fmt_arg):
            if is_identifier(fmt_arg):
                findings.append(Finding(
                    file=tok_file(call_token) or "<unknown>",
                    line=tok_line(call_token) or 0,
                    column=tok_column(call_token) or 0,
                    severity=Severity.WARNING,
                    message=f"Format string is not a literal in {func_name}()",
                    checker=self.name,
                    cwe=134,
                    confidence=0.9,
                ))
            return findings
        
        # Parse format string
        fmt_str = tok_str(fmt_arg)
        if not fmt_str.startswith('"'):
            return findings
        
        # Remove quotes and unescape
        fmt_str = fmt_str[1:-1]  # Remove surrounding quotes
        
        # Parse format specifiers
        specs = self.parse_format_string(fmt_str)
        
        # Check for dangerous %n
        for spec in specs:
            if spec.conversion == 'n':
                findings.append(Finding(
                    file=tok_file(call_token) or "<unknown>",
                    line=tok_line(call_token) or 0,
                    column=tok_column(call_token) or 0,
                    severity=Severity.WARNING,
                    message=f"Use of %n format specifier in {func_name}()",
                    checker=self.name,
                    cwe=787,
                    confidence=0.8,
                ))
        
        # Check argument count and types
        if vararg_idx >= 0:  # Has varargs (not va_list)
            varargs = args[vararg_idx:]
            findings.extend(self.check_format_args(
                call_token, func_name, kind, specs, varargs
            ))
        
        return findings
    
    def parse_format_string(self, fmt_str: str) -> List[FormatSpec]:
        """Parse format specifiers from a format string."""
        specs = []
        
        for match in self.FORMAT_REGEX.finditer(fmt_str):
            pos, flags, width, precision, length, conversion = match.groups()[1:]
            
            spec = FormatSpec(
                full_spec=match.group(0),
                flags=flags or "",
                width=int(width) if width and width != '*' else None,
                width_arg=(width == '*'),
                precision=int(precision) if precision and precision != '*' else None,
                precision_arg=(precision == '*'),
                length=length or "",
                conversion=conversion,
                position=match.start(),
            )
            
            # Skip %% (literal percent)
            if conversion != '%':
                specs.append(spec)
        
        return specs
    
    def check_format_args(
        self,
        call_token,
        func_name: str,
        kind: FormatKind,
        specs: List[FormatSpec],
        args: List
    ) -> List[Finding]:
        """Check format arguments against specifiers."""
        findings = []
        
        # Count expected arguments
        expected_args = 0
        for spec in specs:
            if spec.width_arg:
                expected_args += 1
            if spec.precision_arg:
                expected_args += 1
            expected_args += 1  # The actual argument
        
        # Check argument count
        if len(args) < expected_args:
            findings.append(Finding(
                file=tok_file(call_token) or "<unknown>",
                line=tok_line(call_token) or 0,
                column=tok_column(call_token) or 0,
                severity=Severity.ERROR,
                message=f"Too few arguments for {func_name}(): expected {expected_args}, got {len(args)}",
                checker=self.name,
                cwe=134,
                confidence=1.0,
            ))
        elif len(args) > expected_args:
            findings.append(Finding(
                file=tok_file(call_token) or "<unknown>",
                line=tok_line(call_token) or 0,
                column=tok_column(call_token) or 0,
                severity=Severity.WARNING,
                message=f"Too many arguments for {func_name}(): expected {expected_args}, got {len(args)}",
                checker=self.name,
                cwe=134,
                confidence=0.9,
            ))
        
        # Check argument types
        arg_idx = 0
        for spec in specs:
            # Skip width/precision arguments
            if spec.width_arg:
                arg_idx += 1
            if spec.precision_arg:
                arg_idx += 1
            
            if arg_idx >= len(args):
                break
            
            arg = args[arg_idx]
            type_finding = self.check_arg_type(call_token, func_name, kind, spec, arg)
            if type_finding:
                findings.append(type_finding)
            
            arg_idx += 1
        
        return findings
    
    def check_arg_type(
        self,
        call_token,
        func_name: str,
        kind: FormatKind,
        spec: FormatSpec,
        arg
    ) -> Optional[Finding]:
        """Check if argument type matches format specifier."""
        arg_type = tok_value_type(arg)
        if not arg_type:
            return None
        
        type_str = get_type_str(arg)
        is_ptr = is_pointer_type(arg)
        is_signed = is_signed_type(arg)
        is_unsigned = is_unsigned_type(arg)
        
        # Expected type based on specifier
        conv = spec.conversion
        
        # Integer specifiers
        if conv in 'di':
            if is_ptr:
                return self.type_mismatch_finding(
                    call_token, func_name, spec, "signed integer", type_str
                )
        
        elif conv in 'ouxX':
            if is_ptr:
                return self.type_mismatch_finding(
                    call_token, func_name, spec, "unsigned integer", type_str
                )
        
        # Floating point
        elif conv in 'eEfFgGaA':
            if is_ptr or not (type_str and 'float' in type_str.lower() or 'double' in type_str.lower()):
                # This is a heuristic; real check would be more precise
                pass
        
        # String
        elif conv == 's':
            if kind == FormatKind.PRINTF:
                if not is_ptr:
                    return self.type_mismatch_finding(
                        call_token, func_name, spec, "char*", type_str
                    )
            else:  # SCANF
                if not is_ptr:
                    return self.type_mismatch_finding(
                        call_token, func_name, spec, "char*", type_str
                    )
        
        # Character
        elif conv == 'c':
            if is_ptr:
                return self.type_mismatch_finding(
                    call_token, func_name, spec, "char/int", type_str
                )
        
        # Pointer
        elif conv == 'p':
            if not is_ptr:
                return self.type_mismatch_finding(
                    call_token, func_name, spec, "pointer", type_str
                )
        
        return None
    
    def type_mismatch_finding(
        self,
        call_token,
        func_name: str,
        spec: FormatSpec,
        expected: str,
        actual: str
    ) -> Finding:
        """Create a finding for type mismatch."""
        return Finding(
            file=tok_file(call_token) or "<unknown>",
            line=tok_line(call_token) or 0,
            column=tok_column(call_token) or 0,
            severity=Severity.WARNING,
            message=f"Format specifier '{spec.full_spec}' expects {expected}, got {actual or 'unknown'}",
            checker=self.name,
            cwe=134,
            confidence=0.8,
        )


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dump-file>", file=sys.stderr)
        sys.exit(1)
    
    checker = FormatStringChecker()
    all_findings = []
    
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
            for cfg in data.configurations:
                findings = checker.check(cfg)
                all_findings.extend(findings)
        except Exception as e:
            print(f"Error processing {dump_file}: {e}", file=sys.stderr)
    
    for finding in all_findings:
        print(finding)
    
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
```

### 15.5 Example: Taint-Based SQL Injection Detector

This checker uses taint analysis to detect SQL injection vulnerabilities.

```python
#!/usr/bin/env python3
"""
SQLInjectionChecker.py — SQL Injection Detection

Detects CWE-89: Improper Neutralization of Special Elements used in an SQL Command

Uses taint analysis to track data from untrusted sources to SQL query execution.
"""

import sys
from typing import List

import cppcheckdata
from cppcheckdata_shims.ast_helper import (
    tok_file, tok_line, tok_column,
)
from cppcheckdata_shims.checkers import CheckerBase, Finding, Severity
from cppcheckdata_shims.taint_analysis import (
    TaintConfig,
    TaintSource, SourceKind,
    TaintSink, SinkKind,
    TaintSanitizer,
    TaintPropagator, PropagationKind,
    TaintAnalyzer,
    TaintViolation,
)


def create_sql_injection_config() -> TaintConfig:
    """Create taint configuration for SQL injection detection."""
    config = TaintConfig()
    
    # ─────────────────────────────────────────────────────────────────
    #  Sources: Where untrusted data enters
    # ─────────────────────────────────────────────────────────────────
    
    # User input
    config.add_source(TaintSource(
        function="fgets",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=0,
        description="User input from file/stdin",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="gets",
        kind=SourceKind.RETURN_VALUE,
        description="User input from stdin (dangerous)",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="scanf",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Formatted user input",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="getenv",
        kind=SourceKind.RETURN_VALUE,
        description="Environment variable",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="read",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Data read from file descriptor",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="recv",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Data received from network",
        cwe=89,
    ))
    
    config.add_source(TaintSource(
        function="recvfrom",
        kind=SourceKind.ARGUMENT_OUT,
        argument_index=1,
        description="Data received from network (UDP)",
        cwe=89,
    ))
    
    # Command line arguments (argv)
    config.add_tainted_parameter("main", 1)  # argv parameter
    
    # ─────────────────────────────────────────────────────────────────
    #  Sinks: SQL execution functions
    # ─────────────────────────────────────────────────────────────────
    
    # SQLite
    config.add_sink(TaintSink(
        function="sqlite3_exec",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="SQLite query execution",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="sqlite3_prepare",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="SQLite query preparation",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="sqlite3_prepare_v2",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="SQLite query preparation (v2)",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="sqlite3_prepare_v3",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="SQLite query preparation (v3)",
        cwe=89,
        severity=9,
    ))
    
    # MySQL
    config.add_sink(TaintSink(
        function="mysql_query",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="MySQL query execution",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="mysql_real_query",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="MySQL query execution",
        cwe=89,
        severity=9,
    ))
    
    # PostgreSQL
    config.add_sink(TaintSink(
        function="PQexec",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="PostgreSQL query execution",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="PQexecParams",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="PostgreSQL parameterized query",
        cwe=89,
        severity=9,
    ))
    
    # ODBC
    config.add_sink(TaintSink(
        function="SQLExecDirect",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="ODBC direct SQL execution",
        cwe=89,
        severity=9,
    ))
    
    config.add_sink(TaintSink(
        function="SQLPrepare",
        argument_index=1,
        kind=SinkKind.SQL_INJECTION,
        description="ODBC SQL preparation",
        cwe=89,
        severity=9,
    ))
    
    # ─────────────────────────────────────────────────────────────────
    #  Sanitizers: Functions that make data safe
    # ─────────────────────────────────────────────────────────────────
    
    # MySQL escaping
    config.add_sanitizer(TaintSanitizer(
        function="mysql_real_escape_string",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="MySQL string escaping",
    ))
    
    config.add_sanitizer(TaintSanitizer(
        function="mysql_escape_string",
        argument_index=1,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="MySQL string escaping (deprecated)",
    ))
    
    # PostgreSQL escaping
    config.add_sanitizer(TaintSanitizer(
        function="PQescapeStringConn",
        argument_index=2,
        sanitizes_return=False,
        sanitizes_in_place=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="PostgreSQL string escaping",
    ))
    
    config.add_sanitizer(TaintSanitizer(
        function="PQescapeLiteral",
        argument_index=1,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="PostgreSQL literal escaping",
    ))
    
    config.add_sanitizer(TaintSanitizer(
        function="PQescapeIdentifier",
        argument_index=1,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="PostgreSQL identifier escaping",
    ))
    
    # SQLite safe formatting
    config.add_sanitizer(TaintSanitizer(
        function="sqlite3_mprintf",
        argument_index=0,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="SQLite safe printf (with %q)",
    ))
    
    config.add_sanitizer(TaintSanitizer(
        function="sqlite3_snprintf",
        argument_index=2,
        sanitizes_return=True,
        valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
        description="SQLite safe snprintf",
    ))
    
    # Integer conversion (safe for SQL if result is used as integer)
    for func in ["atoi", "atol", "atoll", "strtol", "strtoll", "strtoul", "strtoull"]:
        config.add_sanitizer(TaintSanitizer(
            function=func,
            argument_index=0,
            sanitizes_return=True,
            valid_for_sinks=frozenset({SinkKind.SQL_INJECTION}),
            description=f"Integer conversion via {func}",
        ))
    
    # ─────────────────────────────────────────────────────────────────
    #  Propagators: How taint flows through functions
    # ─────────────────────────────────────────────────────────────────
    
    # String copying
    config.add_propagator(TaintPropagator(
        function="strcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="String copy",
    ))
    
    config.add_propagator(TaintPropagator(
        function="strncpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="Bounded string copy",
    ))
    
    config.add_propagator(TaintPropagator(
        function="strdup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
        description="String duplication",
    ))
    
    config.add_propagator(TaintPropagator(
        function="strndup",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({0}),
        to_return=True,
        description="Bounded string duplication",
    ))
    
    # String concatenation
    config.add_propagator(TaintPropagator(
        function="strcat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="String concatenation",
    ))
    
    config.add_propagator(TaintPropagator(
        function="strncat",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({0, 1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="Bounded string concatenation",
    ))
    
    # sprintf/snprintf (format string propagation)
    config.add_propagator(TaintPropagator(
        function="sprintf",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({1, 2, 3, 4, 5}),  # Format and args
        to_arguments=frozenset({0}),
        to_return=False,
        description="Formatted string output",
    ))
    
    config.add_propagator(TaintPropagator(
        function="snprintf",
        propagation_kind=PropagationKind.MERGE,
        from_arguments=frozenset({2, 3, 4, 5, 6}),  # Format and args
        to_arguments=frozenset({0}),
        to_return=False,
        description="Bounded formatted string output",
    ))
    
    # Memory copy
    config.add_propagator(TaintPropagator(
        function="memcpy",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="Memory copy",
    ))
    
    config.add_propagator(TaintPropagator(
        function="memmove",
        propagation_kind=PropagationKind.COPY,
        from_arguments=frozenset({1}),
        to_arguments=frozenset({0}),
        to_return=True,
        description="Memory move",
    ))
    
    return config


class SQLInjectionChecker(CheckerBase):
    """
    Checker for SQL injection vulnerabilities using taint analysis.
    """
    
    name = "SQLInjection"
    description = "Detects SQL injection vulnerabilities via taint analysis"
    version = "1.0.0"
    
    def __init__(self):
        super().__init__()
        self._config = create_sql_injection_config()
        self._analyzer = TaintAnalyzer(
            self._config,
            track_flow_paths=True,
            verbose=False,
        )
    
    def check(self, cfg) -> List[Finding]:
        """Run the checker on a configuration."""
        findings = []
        
        # Run taint analysis
        result = self._analyzer.analyze_configuration(cfg)
        
        # Convert violations to findings
        for violation in result.violations:
            finding = self.violation_to_finding(violation)
            findings.append(finding)
        
        return findings
    
    def violation_to_finding(self, violation: TaintViolation) -> Finding:
        """Convert a taint violation to a finding."""
        # Build message
        sources_str = ", ".join(violation.taint_sources) if violation.taint_sources else "external input"
        message = f"SQL Injection: Tainted data from {sources_str} reaches {violation.function}()"
        
        if violation.sink.argument_index >= 0:
            message += f" at argument {violation.sink.argument_index}"
        
        # Add flow path if available
        if violation.flow_path and len(violation.flow_path.steps) > 0:
            message += f" via {len(violation.flow_path.steps)} step(s)"
        
        return Finding(
            file=tok_file(violation.sink_token) or "<unknown>",
            line=tok_line(violation.sink_token) or 0,
            column=tok_column(violation.sink_token) or 0,
            severity=Severity.ERROR,
            message=message,
            checker=self.name,
            cwe=89,
            confidence=violation.confidence,
        )


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dump-file>", file=sys.stderr)
        sys.exit(1)
    
    checker = SQLInjectionChecker()
    all_findings = []
    
    for dump_file in sys.argv[1:]:
        try:
            data = cppcheckdata.parsedump(dump_file)
            for cfg in data.configurations:
                findings = checker.check(cfg)
                all_findings.extend(findings)
        except Exception as e:
            print(f"Error processing {dump_file}: {e}", file=sys.stderr)
    
    # Print findings
    if not all_findings:
        print("No SQL injection vulnerabilities found.")
    else:
        print(f"\n{'='*70}")
        print(f"  SQL INJECTION REPORT - {len(all_findings)} vulnerability(ies) found")
        print(f"{'='*70}\n")
        
        for i, finding in enumerate(all_findings, 1):
            print(f"{i}. {finding.file}:{finding.line}:{finding.column}")
            print(f"   {finding.message}")
            print(f"   Confidence: {finding.confidence:.0%}")
            print()
    
    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()
```

---

## 16. Best Practices

### 16.1 Defensive Programming

When writing addons with cppcheckdata-shims, follow these defensive programming practices:

#### Always Use Safe Accessors

```python
# ❌ BAD: Direct attribute access may crash
def bad_get_operand(token):
    return token.astOperand1.str  # Crashes if astOperand1 is None

# ✅ GOOD: Use safe accessors
from cppcheckdata_shims.ast_helper import tok_op1, tok_str

def good_get_operand(token):
    op1 = tok_op1(token)
    return tok_str(op1) if op1 else ""
```

#### Check for None at Every Step

```python
# ❌ BAD: Assumes chain of attributes exists
def bad_traverse(token):
    return token.astOperand1.astOperand2.variable.nameToken.str

# ✅ GOOD: Check each step
from cppcheckdata_shims.ast_helper import tok_op1, tok_op2, tok_variable, tok_str

def good_traverse(token):
    op1 = tok_op1(token)
    if not op1:
        return None
    
    op2 = tok_op2(op1)
    if not op2:
        return None
    
    var = tok_variable(op2)
    if not var:
        return None
    
    name_token = getattr(var, 'nameToken', None)
    if not name_token:
        return None
    
    return tok_str(name_token)
```

#### Use Type Hints

```python
from typing import Optional, List
from cppcheckdata_shims.checkers import Finding

def analyze_function(scope) -> List[Finding]:
    """
    Analyze a function scope for issues.
    
    Args:
        scope: A cppcheckdata Scope object with type='Function'
    
    Returns:
        List of findings, may be empty
    """
    findings: List[Finding] = []
    # ... analysis ...
    return findings
```

#### Handle Exceptions Gracefully

```python
def safe_analyze(dump_file: str) -> List[Finding]:
    """Analyze a dump file with error handling."""
    try:
        data = cppcheckdata.parsedump(dump_file)
    except FileNotFoundError:
        print(f"Error: File not found: {dump_file}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Error parsing {dump_file}: {e}", file=sys.stderr)
        return []
    
    findings = []
    for cfg in data.configurations:
        try:
            cfg_findings = analyze_configuration(cfg)
            findings.extend(cfg_findings)
        except Exception as e:
            print(f"Error analyzing configuration: {e}", file=sys.stderr)
            continue
    
    return findings
```

### 16.2 Performance Considerations

#### Cache Expensive Computations

```python
class MyChecker(CheckerBase):
    def check(self, cfg) -> List[Finding]:
        # Cache CFGs for functions
        self._cfg_cache: Dict[int, CFG] = {}
        
        findings = []
        for scope in cfg.scopes:
            if getattr(scope, 'type', '') == 'Function':
                func_cfg = self._get_or_build_cfg(scope)
                findings.extend(self.check_function(scope, func_cfg))
        
        return findings
    
    def _get_or_build_cfg(self, scope) -> CFG:
        scope_id = scope.Id
        if scope_id not in self._cfg_cache:
            builder = CFGBuilder()
            self._cfg_cache[scope_id] = builder.build(scope)
        return self._cfg_cache[scope_id]
```

#### Avoid Repeated Token Iteration

```python
# ❌ BAD: Multiple passes over token list
def bad_analyze(cfg):
    # First pass for assignments
    for token in cfg.tokenlist:
        if is_assignment(token):
            process_assignment(token)
    
    # Second pass for calls
    for token in cfg.tokenlist:
        if is_function_call(token):
            process_call(token)
    
    # Third pass for dereferences
    for token in cfg.tokenlist:
        if is_dereference(token):
            process_deref(token)

# ✅ GOOD: Single pass
def good_analyze(cfg):
    for token in cfg.tokenlist:
        if is_assignment(token):
            process_assignment(token)
        elif is_function_call(token):
            process_call(token)
        elif is_dereference(token):
            process_deref(token)
```

#### Use Generators for Large Data

```python
from typing import Iterator

def iter_all_function_calls(cfg) -> Iterator:
    """Yield function calls without building a list."""
    for token in cfg.tokenlist:
        if is_function_call(token):
            yield token

# Use in analysis
for call in iter_all_function_calls(cfg):
    check_call(call)
```

#### Limit Analysis Depth

```python
class BoundedAnalysis:
    MAX_ITERATIONS = 1000
    MAX_PATH_LENGTH = 100
    
    def analyze_with_bounds(self, cfg):
        iterations = 0
        worklist = [cfg.entry]
        
        while worklist and iterations < self.MAX_ITERATIONS:
            iterations += 1
            node = worklist.pop()
            # ... process node ...
        
        if iterations >= self.MAX_ITERATIONS:
            print("Warning: Analysis iteration limit reached", file=sys.stderr)
```

### 16.3 Testing Your Addons

#### Create Test Cases

Create a directory structure for tests:

```
my_addon/
├── my_checker.py
└── tests/
    ├── test_cases/
    │   ├── null_deref_positive.c      # Should find bugs
    │   ├── null_deref_negative.c      # Should NOT find bugs
    │   ├── buffer_overflow_positive.c
    │   └── buffer_overflow_negative.c
    └── test_my_checker.py
```

#### Write Test Code with Expected Results

```c
/* tests/test_cases/null_deref_positive.c */
/* Expected: 2 findings */

#include <stdlib.h>

void test_definite_null_deref(void) {
    int *p = NULL;
    *p = 42;  /* EXPECTED: Definite null pointer dereference */
}

void test_maybe_null_deref(void) {
    int *p = malloc(sizeof(int));
    /* No null check */
    *p = 42;  /* EXPECTED: Potential null pointer dereference */
}
```

```c
/* tests/test_cases/null_deref_negative.c */
/* Expected: 0 findings */

#include <stdlib.h>

void test_checked_null(void) {
    int *p = malloc(sizeof(int));
    if (p != NULL) {
        *p = 42;  /* Safe: null-checked */
    }
}

void test_non_null_init(void) {
    int x = 10;
    int *p = &x;
    *p = 42;  /* Safe: address-of is never null */
}
```

#### Automate Testing

```python
#!/usr/bin/env python3
"""test_my_checker.py — Test suite for MyChecker"""

import subprocess
import sys
import os
from pathlib import Path

TEST_DIR = Path(__file__).parent / "test_cases"

# Test cases: (filename, expected_finding_count)
TEST_CASES = [
    ("null_deref_positive.c", 2),
    ("null_deref_negative.c", 0),
    ("buffer_overflow_positive.c", 3),
    ("buffer_overflow_negative.c", 0),
]

def run_test(test_file: Path, expected_count: int) -> bool:
    """Run a single test case."""
    # Generate dump file
    dump_file = test_file.with_suffix(".c.dump")
    result = subprocess.run(
        ["cppcheck", "--dump", str(test_file)],
        capture_output=True,
        text=True,
    )
    
    if not dump_file.exists():
        print(f"  FAIL: Could not generate dump file")
        return False
    
    # Run checker
    result = subprocess.run(
        [sys.executable, "my_checker.py", str(dump_file)],
        capture_output=True,
        text=True,
    )
    
    # Count findings (assuming one per line in output)
    findings = [line for line in result.stdout.strip().split('\n') if line and ':' in line]
    actual_count = len(findings)
    
    # Clean up
    dump_file.unlink()
    
    # Check result
    if actual_count == expected_count:
        print(f"  PASS: {actual_count} findings (expected {expected_count})")
        return True
    else:
        print(f"  FAIL: {actual_count} findings (expected {expected_count})")
        for finding in findings:
            print(f"    {finding}")
        return False

def main():
    """Run all tests."""
    print("Running MyChecker tests...\n")
    
    passed = 0
    failed = 0
    
    for filename, expected in TEST_CASES:
        test_file = TEST_DIR / filename
        print(f"Testing {filename}:")
        
        if not test_file.exists():
            print(f"  SKIP: File not found")
            continue
        
        if run_test(test_file, expected):
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
```

### 16.4 Common Pitfalls

#### Pitfall 1: Forgetting That Tokens Form a Linked List AND a Tree

```python
# The token list is sequential (token.next, token.previous)
# The AST is a tree (token.astOperand1, token.astOperand2, token.astParent)

# ❌ BAD: Confusing the two
def bad_find_parent(token):
    return token.previous  # This is the previous TOKEN, not AST parent!

# ✅ GOOD: Use correct relationship
from cppcheckdata_shims.ast_helper import tok_parent

def good_find_parent(token):
    return tok_parent(token)  # AST parent
```

#### Pitfall 2: Assuming All Tokens Have AST Information

```python
# Not all tokens are part of expressions!
# Keywords, braces, semicolons, etc. don't have AST children

# ❌ BAD: Assumes token is an operator
def bad_process(token):
    left = token.astOperand1  # May be None for non-operators
    right = token.astOperand2  # May be None for non-operators
    return f"{left.str} {token.str} {right.str}"  # Crash!

# ✅ GOOD: Check first
from cppcheckdata_shims.ast_helper import tok_op1, tok_op2, tok_str, is_binary_op

def good_process(token):
    if not is_binary_op(token):
        return tok_str(token)
    
    left = tok_op1(token)
    right = tok_op2(token)
    
    left_str = tok_str(left) if left else "?"
    right_str = tok_str(right) if right else "?"
    
    return f"{left_str} {tok_str(token)} {right_str}"
```

#### Pitfall 3: Not Handling All Code Paths

```python
# ❌ BAD: Only handles one form of null check
def bad_has_null_check(token):
    # Only checks: if (ptr != NULL)
    parent = tok_parent(token)
    if tok_str(parent) == "!=" and tok_str(tok_op2(parent)) == "NULL":
        return True
    return False

# ✅ GOOD: Handle multiple forms
def good_has_null_check(token):
    """Check for various null check patterns."""
    parent = tok_parent(token)
    if not parent:
        return False
    
    parent_str = tok_str(parent)
    
    # if (ptr != NULL) or if (ptr != 0) or if (ptr != nullptr)
    if parent_str == "!=":
        other = tok_op2(parent) if tok_op1(parent) == token else tok_op1(parent)
        if tok_str(other) in ("NULL", "nullptr", "0"):
            return True
    
    # if (ptr == NULL) — negated check
    if parent_str == "==":
        other = tok_op2(parent) if tok_op1(parent) == token else tok_op1(parent)
        if tok_str(other) in ("NULL", "nullptr", "0"):
            return True  # Still a check, just inverted
    
    # if (ptr) — implicit check
    if parent_str == "if":
        return True
    
    # if (!ptr) — negated implicit check
    if parent_str == "!":
        grandparent = tok_parent(parent)
        if tok_str(grandparent) == "if":
            return True
    
    return False
```

#### Pitfall 4: Ignoring Scope and Lifetime

```python
# ❌ BAD: Tracking variable by name (wrong across scopes)
def bad_track_variable(cfg):
    freed_vars = set()  # Tracks by name
    
    for token in cfg.tokenlist:
        if is_function_call(token) and get_called_function_name(token) == "free":
            args = get_call_arguments(token)
            if args:
                freed_vars.add(tok_str(args[0]))  # "ptr" — but which ptr?

# ✅ GOOD: Track by unique variable ID
def good_track_variable(cfg):
    freed_vars = set()  # Tracks by ID
    
    for token in cfg.tokenlist:
        if is_function_call(token) and get_called_function_name(token) == "free":
            args = get_call_arguments(token)
            if args:
                var_id = tok_var_id(args[0])
                if var_id:
                    freed_vars.add(var_id)  # Unique across all scopes
```

#### Pitfall 5: Not Considering Aliasing

```python
# ❌ BAD: Ignores pointer aliasing
def bad_check_use_after_free(cfg):
    freed = set()
    
    for token in cfg.tokenlist:
        if is_free_call(token):
            freed.add(tok_var_id(get_call_arguments(token)[0]))
        
        if is_dereference(token):
            var_id = tok_var_id(tok_op1(token))
            if var_id in freed:
                report_uaf(token)

# Problem: What about this?
#   int *p = malloc(10);
#   int *q = p;  // q is an alias of p
#   free(p);
#   *q = 5;      // Use after free via alias — MISSED!

# ✅ BETTER: Consider aliasing (simplified)
def better_check_use_after_free(cfg):
    freed = set()
    aliases = {}  # var_id -> set of aliased var_ids
    
    for token in cfg.tokenlist:
        # Track aliasing: q = p
        if is_assignment(token):
            lhs_id = tok_var_id(tok_op1(token))
            rhs_id = tok_var_id(tok_op2(token))
            if lhs_id and rhs_id:
                # lhs is now an alias of rhs
                aliases.setdefault(rhs_id, {rhs_id}).add(lhs_id)
                aliases.setdefault(lhs_id, {lhs_id}).update(aliases.get(rhs_id, set()))
        
        if is_free_call(token):
            var_id = tok_var_id(get_call_arguments(token)[0])
            if var_id:
                # Mark all aliases as freed
                for alias_id in aliases.get(var_id, {var_id}):
                    freed.add(alias_id)
        
        if is_dereference(token):
            var_id = tok_var_id(tok_op1(token))
            if var_id in freed:
                report_uaf(token)
```

---

## 17. Troubleshooting

### 17.1 Common Errors

#### Error: "AttributeError: 'NoneType' object has no attribute '...'"

**Cause**: Accessing an attribute on a None value.

**Solution**: Use safe accessors from `ast_helper`:

```python
# Instead of:
token.astOperand1.str

# Use:
from cppcheckdata_shims.ast_helper import tok_op1, tok_str
op1 = tok_op1(token)
if op1:
    s = tok_str(op1)
```

#### Error: "KeyError" when accessing dictionaries

**Cause**: Assuming a key exists in a dictionary.

**Solution**: Use `.get()` with a default:

```python
# Instead of:
value = my_dict[key]

# Use:
value = my_dict.get(key, default_value)
```

#### Error: "RecursionError: maximum recursion depth exceeded"

**Cause**: Infinite recursion in AST traversal or analysis.

**Solution**: Use iterative approaches or add depth limits:

```python
# Instead of recursive traversal:
def bad_traverse(token):
    if token is None:
        return
    process(token)
    bad_traverse(token.astOperand1)
    bad_traverse(token.astOperand2)

# Use iterative:
from cppcheckdata_shims.ast_helper import iter_ast_preorder

def good_traverse(root):
    for token in iter_ast_preorder(root):
        process(token)
```

#### Error: Analysis doesn't terminate

**Cause**: Fixpoint not reached due to infinite-height domain.

**Solution**: Use widening:

```python
from cppcheckdata_shims.dataflow_engine import WideningStrategy

solver = ForwardDataflowSolver(
    cfg,
    analysis,
    widening_strategy=WideningStrategy.DELAY(3),
)
```

#### Error: "No module named 'cppcheckdata'"

**Cause**: Cppcheck's Python module not in path.

**Solution**: Ensure Cppcheck is installed and its Python path is set:

```bash
# Find cppcheck's Python modules
CPPCHECK_PATH=$(dirname $(which cppcheck))
export PYTHONPATH="$CPPCHECK_PATH:$PYTHONPATH"
```

### 17.2 Debugging Techniques

#### Print Token Information

```python
from cppcheckdata_shims.ast_helper import token_location, tok_str, expr_to_string

def debug_token(token, label="Token"):
    """Print detailed token information."""
    print(f"=== {label} ===")
    print(f"  Location: {token_location(token)}")
    print(f"  String: '{tok_str(token)}'")
    print(f"  Expression: {expr_to_string(token)}")
    print(f"  Has astOperand1: {token.astOperand1 is not None}")
    print(f"  Has astOperand2: {token.astOperand2 is not None}")
    print(f"  Has astParent: {token.astParent is not None}")
    print(f"  Variable ID: {getattr(token, 'varId', None)}")
    print(f"  Values: {len(token.values) if token.values else 0}")
```

#### Visualize AST

```python
def print_ast(token, indent=0):
    """Print AST structure."""
    if token is None:
        return
    
    prefix = "  " * indent
    print(f"{prefix}{tok_str(token)}")
    
    if token.astOperand1:
        print(f"{prefix}├─ op1:")
        print_ast(token.astOperand1, indent + 1)
    
    if token.astOperand2:
        print(f"{prefix}└─ op2:")
        print_ast(token.astOperand2, indent + 1)
```

#### Trace Dataflow

```python
class TracingAnalysis(DataflowAnalysis):
    """Wrapper that traces dataflow analysis."""
    
    def __init__(self, inner_analysis, verbose=True):
        self._inner = inner_analysis
        self._verbose = verbose
    
    def transfer(self, node, in_value):
        out_value = self._inner.transfer(node, in_value)
        
        if self._verbose:
            print(f"Node {node.id}:")
            print(f"  IN:  {in_value}")
            print(f"  OUT: {out_value}")
        
        return out_value
```

#### Dump Configuration State

```python
def dump_cfg_state(cfg):
    """Dump information about a Cppcheck configuration."""
    print(f"Configuration: {cfg}")
    print(f"  Tokens: {sum(1 for _ in cfg.tokenlist)}")
    print(f"  Scopes: {len(cfg.scopes)}")
    print(f"  Variables: {len(cfg.variables)}")
    print(f"  Functions: {len(cfg.functions)}")
    
    print("\nFunctions:")
    for func in cfg.functions:
        print(f"  - {func.name}")
    
    print("\nGlobal variables:")
    for var in cfg.variables:
        if getattr(var, 'isGlobal', False):
            print(f"  - {getattr(var.nameToken, 'str', '?')}")
```

### 17.3 Getting Help

#### Check the Cppcheck Documentation

- [Cppcheck Manual](http://cppcheck.sourceforge.net/manual.html)
- [Writing Cppcheck Addons](http://cppcheck.sourceforge.net/manual.html#addons)

#### Examine the Dump File

```bash
# Generate dump with maximum information
cppcheck --dump --max-configs=1 myfile.c

# View the XML
cat myfile.c.dump | xmllint --format - | less
```

#### Enable Verbose Mode

```python
analyzer = TaintAnalyzer(
    config,
    verbose=True,  # Enable debug output
)
```

#### Minimal Reproducible Example

When seeking help, create a minimal example:

```c
/* minimal.c - Minimal example demonstrating the issue */
int main() {
    int *p = 0;
    *p = 42;  /* Expected: null dereference warning */
    return 0;
}
```

```python
# minimal_check.py - Minimal checker demonstrating the issue
import sys
import cppcheckdata
from cppcheckdata_shims.ast_helper import is_dereference, tok_op1, tok_str

data = cppcheckdata.parsedump(sys.argv[1])
for cfg in data.configurations:
    for token in cfg.tokenlist:
        if is_dereference(token):
            print(f"Found dereference of: {tok_str(tok_op1(token))}")
```

---

## 18. Appendices

### A. Quick Reference Card

#### Safe Accessors

| Function | Returns | Description |
|----------|---------|-------------|
| `tok_str(t)` | `str` | Token string, "" if None |
| `tok_op1(t)` | `Optional[Token]` | Left/first AST operand |
| `tok_op2(t)` | `Optional[Token]` | Right/second AST operand |
| `tok_parent(t)` | `Optional[Token]` | AST parent |
| `tok_var_id(t)` | `Optional[int]` | Variable ID |
| `tok_variable(t)` | `Optional[Variable]` | Variable object |
| `tok_function(t)` | `Optional[Function]` | Function object |
| `tok_file(t)` | `Optional[str]` | Source file name |
| `tok_line(t)` | `Optional[int]` | Line number |
| `tok_column(t)` | `Optional[int]` | Column number |

#### AST Predicates

| Function | Description |
|----------|-------------|
| `is_assignment(t)` | `=` operator |
| `is_compound_assignment(t)` | `+=`, `-=`, etc. |
| `is_function_call(t)` | Function call expression |
| `is_dereference(t)` | `*ptr` |
| `is_address_of(t)` | `&var` |
| `is_subscript(t)` | `arr[i]` |
| `is_member_access(t)` | `.` or `->` |
| `is_identifier(t)` | Variable/function name |
| `is_literal(t)` | String/number literal |
| `is_comparison(t)` | `==`, `!=`, `<`, etc. |
| `is_arithmetic_op(t)` | `+`, `-`, `*`, `/`, `%` |

#### AST Traversal

| Function | Description |
|----------|-------------|
| `iter_ast_preorder(root)` | Pre-order traversal |
| `iter_ast_postorder(root)` | Post-order traversal |
| `find_ast_root(t)` | Find root of AST |
| `collect_subtree(root)` | List all nodes |

#### Function Calls

| Function | Description |
|----------|-------------|
| `get_called_function_name(t)` | Name of called function |
| `get_call_arguments(t)` | List of argument tokens |
| `count_call_arguments(t)` | Number of arguments |
| `is_allocation_call(t)` | malloc, new, etc. |
| `is_deallocation_call(t)` | free, delete, etc. |

### B. Glossary

| Term | Definition |
|------|------------|
| **Abstract Domain** | A set of abstract values with operations that approximate concrete computation |
| **AST** | Abstract Syntax Tree — tree representation of source code structure |
| **CFG** | Control Flow Graph — graph of basic blocks and control flow edges |
| **CWE** | Common Weakness Enumeration — standardized list of software weaknesses |
| **Dataflow Analysis** | Analysis that computes information about data flow through a program |
| **Dominator** | Node A dominates node B if all paths to B go through A |
| **Finding** | A detected issue reported by a checker |
| **Fixpoint** | State where further iteration produces no change |
| **Lattice** | Partially ordered set with join and meet operations |
| **Propagator** | Rule for how taint flows through a function |
| **Sanitizer** | Function that removes taint from data |
| **Sink** | Location where tainted data causes a vulnerability |
| **Source** | Origin of tainted (untrusted) data |
| **Taint Analysis** | Tracking flow of untrusted data through a program |
| **Token** | Single lexical element (keyword, identifier, operator, etc.) |
| **Widening** | Technique to ensure termination of analysis on infinite domains |

### C. CWE Reference

Common CWEs detected by cppcheckdata-shims addons:

| CWE | Name | Category |
|-----|------|----------|
| 78 | OS Command Injection | Injection |
| 89 | SQL Injection | Injection |
| 90 | LDAP Injection | Injection |
| 91 | XML Injection | Injection |
| 94 | Code Injection | Injection |
| 119 | Buffer Overflow | Memory |
| 120 | Buffer Copy without Size Check | Memory |
| 121 | Stack-based Buffer Overflow | Memory |
| 122 | Heap-based Buffer Overflow | Memory |
| 125 | Out-of-bounds Read | Memory |
| 126 | Buffer Over-read | Memory |
| 127 | Buffer Under-read | Memory |
| 129 | Improper Array Index Validation | Memory |
| 131 | Incorrect Buffer Size Calculation | Memory |
| 134 | Format String Vulnerability | Injection |
| 170 | Improper Null Termination | Memory |
| 190 | Integer Overflow | Integer |
| 191 | Integer Underflow | Integer |
| 193 | Off-by-one Error | Memory |
| 197 | Numeric Truncation Error | Integer |
| 242 | Inherently Dangerous Function | Code Quality |
| 252 | Unchecked Return Value | Code Quality |
| 401 | Memory Leak | Memory |
| 415 | Double Free | Memory |
| 416 | Use After Free | Memory |
| 457 | Uninitialized Variable | Code Quality |
| 467 | sizeof on Pointer | Code Quality |
| 476 | NULL Pointer Dereference | Memory |
| 676 | Potentially Dangerous Function | Code Quality |
| 787 | Out-of-bounds Write | Memory |
| 789 | Memory Allocation with Excessive Size | Memory |

---

## Conclusion

This vade mecum has provided comprehensive guidance on using the cppcheckdata-shims library to build sophisticated Cppcheck addons. You have learned:

1. **The architecture** of cppcheckdata-shims and how it extends cppcheckdata.py
2. **Safe AST manipulation** using the ast_helper module
3. **Building checkers** with the checker framework
4. **Abstract interpretation** with pre-built domains
5. **Dataflow analysis** using the generic solver
6. **Taint analysis** for security vulnerability detection
7. **Best practices** for robust addon development
8. **Troubleshooting** common issues

With these tools and techniques, you can create analyzers that detect complex bugs and security vulnerabilities that simple pattern matching cannot find.

**Remember the key principles:**

- Always use safe accessors
- Think about all code paths
- Consider aliasing and scope
- Test with both positive and negative cases
- Start simple and add complexity incrementally

Happy analyzing!

---

*This document is part of the cppcheckdata-shims library.*
*For updates and contributions, visit the project repository at https://github.com/Chubek/cppcheckdata-shims.*
```
