

# CASL — Cppcheck Addon Specification Language

## A Comprehensive Guide with Examples

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation & Quick Start](#2-installation--quick-start)
3. [Language Overview](#3-language-overview)
4. [S-Expression Syntax Foundation](#4-s-expression-syntax-foundation)
5. [Rule Anatomy](#5-rule-anatomy)
6. [Pattern Language](#6-pattern-language)
7. [Constraint System](#7-constraint-system)
8. [Action System](#8-action-system)
9. [Fact System & Inter-Rule Communication](#9-fact-system--inter-rule-communication)
10. [Type & Value Expressions](#10-type--value-expressions)
11. [Built-in Domains & Lattices](#11-built-in-domains--lattices)
12. [Control-Flow & Data-Flow Queries](#12-control-flow--data-flow-queries)
13. [Interprocedural Analysis](#13-interprocedural-analysis)
14. [Complete Worked Examples](#14-complete-worked-examples)
15. [CLI Reference](#15-cli-reference)
16. [Compilation Model & Generated Code](#16-compilation-model--generated-code)
17. [Diagnostics & Debugging](#17-diagnostics--debugging)
18. [Appendix A: Grammar Reference](#18-appendix-a-grammar-reference)
19. [Appendix B: Built-in Predicates & Functions](#19-appendix-b-built-in-predicates--functions)
20. [Appendix C: Comparison with PQL and Other Query Languages](#20-appendix-c-comparison-with-pql-and-other-query-languages)

---

## 1. Introduction

### 1.1 What is CASL?

CASL (Cppcheck Addon Specification Language) is a **declarative, S-expression-based domain-specific language** for writing static analysis rules that target C and C++ source code via the Cppcheck infrastructure. Instead of writing Python scripts that manually traverse token lists, ASTs, and scope trees, you write high-level *rules* that declare:

- **What** code patterns to match (patterns)
- **What** semantic conditions must hold (constraints)
- **What** to do when everything matches (actions)

The CASL compiler (`casl`) transforms these specifications into fully executable Python addons that plug into Cppcheck's `--addon=` mechanism.

### 1.2 Design Philosophy

CASL draws on ideas from several traditions in static analysis specification:

| Tradition | Influence on CASL |
|---|---|
| **PQL (Program Query Language)** | Declarative matching of program events; automatic generation of static checkers from high-level queries |
| **Datalog-based analyses** | Fact-based inter-rule communication; fixed-point reasoning |
| **Abstract Interpretation** | Built-in abstract domains (Sign, Nullness, Taint, Interval); Galois connection-aware lattice operations |
| **Path-oriented analysis** | Path constraints (`along-path`, `on-all-paths`) that reason about execution traces |
| **Classical dataflow** | `flows-to`, `reaches`, `dominates` constraints backed by the `cppcheckdata-shims` library |

### 1.3 What CASL Is Not

- CASL is **not** a general-purpose programming language. It cannot express arbitrary computation — only static analysis rules.
- CASL does **not** replace Cppcheck's built-in checkers. It provides a way to write *additional* addon checkers.
- CASL does **not** execute at compile time of the *target* program. It executes on Cppcheck's dump files (XML AST representations).

---

## 2. Installation & Quick Start

### 2.1 Prerequisites

- **Python ≥ 3.9**
- **Cppcheck** (any recent version that produces `.dump` files)
- **cppcheckdata-shims** library (the companion analysis library)
- **parsimonious** (PEG parser library)
- **sexpdata** (S-expression parser)

### 2.2 Installation

```bash
pip install casl-lang
# or from source:
git clone https://github.com/example/casl.git
cd casl
pip install -e .
```

### 2.3 Your First CASL Rule

Create a file `my-checker.casl`:

```scheme
(addon my-checker
  (metadata
    (version "1.0.0")
    (description "Warns on assignment in if-condition"))

  (rule no-assign-in-condition
    (pattern
      (if-stmt
        (condition (assign @lhs @rhs))))
    (action
      (report warning
        "Assignment in condition — did you mean '=='?"
        (location @lhs)))))
```

### 2.4 Compile and Run

```bash
# Compile to a Python addon
casl compile my-checker.casl -o my_checker.py

# Generate a Cppcheck dump
cppcheck --dump target.c

# Run the addon on the dump
python my_checker.py target.c.dump

# Or, do everything in one shot:
casl run my-checker.casl -- target.c.dump
```

### 2.5 Init — Skeleton Generation

```bash
casl init double-free-checker
# Creates double-free-checker.casl with a commented skeleton
```

Generated skeleton:

```scheme
(addon double-free-checker
  (metadata
    (version "0.1.0")
    (description "TODO: describe your checker"))

  ;; Define facts for inter-rule communication
  ;; (fact-schema freed-pointer (var token))

  (rule example-rule
    (pattern
      ;; TODO: define your code pattern
      (token @t))
    (constraint
      ;; TODO: add semantic constraints
      (true))
    (action
      (report style
        "TODO: describe the finding"
        (location @t)))))
```

---

## 3. Language Overview

### 3.1 Top-Level Structure

Every CASL file is a single `(addon ...)` form:

```scheme
(addon <addon-name>
  <metadata-section>?
  <import-section>*
  <domain-section>*
  <fact-schema>*
  <rule>+)
```

### 3.2 Section Types

| Section | Purpose | Required? |
|---|---|---|
| `metadata` | Version, description, author, cppcheck-version constraints | Optional |
| `import` | Import external CASL modules or Python helpers | Optional |
| `domain` | Define custom abstract domains | Optional |
| `fact-schema` | Declare fact types for inter-rule communication | Optional |
| `rule` | The core analysis rules | At least one |

### 3.3 Naming Conventions

- **Addon names**: `kebab-case` — e.g., `my-leak-checker`
- **Rule names**: `kebab-case` — e.g., `detect-double-free`
- **Bind variables**: Prefixed with `@` — e.g., `@ptr`, `@call-site`
- **Fact names**: `kebab-case` — e.g., `freed-pointer`
- **Domain names**: `PascalCase` — e.g., `TaintDomain`

---

## 4. S-Expression Syntax Foundation

### 4.1 Why S-Expressions?

CASL uses S-expressions for several reasons:

1. **Homoiconicity** — The structure of the specification *is* a tree, and S-expressions directly represent trees.
2. **No parsing ambiguity** — Unlike infix notation, parenthesized prefix notation is unambiguous.
3. **Tool-friendliness** — S-expressions are trivially parsed and pretty-printed, making tooling easy.
4. **Composability** — Nested forms compose naturally without precedence rules.

### 4.2 Lexical Elements

```scheme
;; Atoms
my-name          ; symbol
42               ; integer
3.14             ; float
"hello world"    ; string
#t               ; boolean true
#f               ; boolean false
@var             ; binding variable (symbol starting with @)

;; Lists
(a b c)          ; list of three symbols
(+ 1 2)          ; nested form
((a b) (c d))    ; nested lists

;; Comments
; This is a line comment
;; This is also a comment
```

### 4.3 Quoting and Special Forms

CASL has a small number of special syntactic markers:

| Marker | Meaning | Example |
|---|---|---|
| `@` | Binding variable — captures a matched AST node | `@ptr` |
| `_` | Wildcard — matches anything, captures nothing | `(call _ @arg)` |
| `...` | Ellipsis — matches zero or more elements | `(args @first ... @last)` |
| `$$` | Escaped Python expression (escape hatch) | `($$ "token.isName")` |

---

## 5. Rule Anatomy

### 5.1 General Rule Structure

```scheme
(rule <rule-name>
  (pattern <pattern-form>)
  (constraint <constraint-form>)?
  (action <action-form>)+)
```

A rule consists of three phases:

1. **Pattern** — Structural matching against the AST / token list / scope tree
2. **Constraint** — Semantic predicates that must hold for the match to be valid
3. **Action** — What to do when both pattern and constraints are satisfied

### 5.2 Rule Execution Model

For each configuration in the dump file:
  For each potential match site (determined by pattern type):
    If pattern matches → produce bindings {@var → AST node, ...}
    If all constraints hold under those bindings:
      Execute all actions with those bindings


### 5.3 Multiple Rules — Ordering and Independence

Rules within an addon execute **independently** by default. Each rule scans the AST and produces findings. The order in which rules are declared does not affect execution, **unless** they communicate through the fact system (see §9).

When fact dependencies exist, CASL performs a **topological sort** of rules by their fact production/consumption relationships and executes them in dependency order.

### 5.4 Rule Options

```scheme
(rule my-rule
  (options
    (severity warning)        ; default severity for reports
    (scope function)          ; iterate over function scopes only
    (enabled #t)              ; can be disabled from CLI
    (max-findings 100))       ; stop after N findings
  (pattern ...)
  (action ...))
```

Available options:

| Option | Values | Default | Description |
|---|---|---|---|
| `severity` | `error`, `warning`, `style`, `performance`, `portability` | `warning` | Default severity |
| `scope` | `global`, `function`, `class`, `namespace`, `block` | `global` | Iteration scope |
| `enabled` | `#t`, `#f` | `#t` | Whether rule is active |
| `max-findings` | integer | unlimited | Cap on findings |

---

## 6. Pattern Language

The pattern language is CASL's most expressive subsystem. It provides structural matching against Cppcheck's AST representation.

### 6.1 Token Patterns

The simplest patterns match individual tokens:

```scheme
;; Match a specific token string
(token "malloc")

;; Match by token properties
(token @t (is-name #t))
(token @t (is-op #t) (str "="))

;; Match a token with a specific varId
(token @t (var-id @vid))
```

### 6.2 AST Patterns

AST patterns match against the abstract syntax tree structure:

```scheme
;; Match an assignment where RHS is a function call to malloc
(ast-match
  (assign
    @lhs
    (call (name "malloc") @args)))

;; Match a comparison of a pointer against NULL
(ast-match
  (comparison @op
    @ptr
    (null-literal)))

;; Match any binary operation
(ast-match
  (binary-op @op @left @right))
```

### 6.3 Statement Patterns

Higher-level patterns that match statement structures:

```scheme
;; Match an if-statement
(if-stmt
  (condition @cond)
  (then-branch @then)
  (else-branch @else))

;; Match a for-loop
(for-stmt
  (init @init)
  (condition @cond)
  (increment @incr)
  (body @body))

;; Match a return statement
(return-stmt @expr)

;; Match a function definition
(function-def @func
  (name "processData")
  (params @params)
  (body @body))
```

### 6.4 Scope Patterns

```scheme
;; Match inside a specific scope type
(in-scope class
  (function-def @method
    (name @name)))

;; Match tokens within a function scope
(in-scope function
  (token @t (str "goto")))
```

### 6.5 Sequence Patterns

Match sequences of statements in order:

```scheme
;; Match: ptr = malloc(...); ... free(ptr); ... free(ptr);
(sequence
  (assign @ptr (call (name "malloc") _))
  ...                                      ; zero or more intervening statements
  (expr-stmt (call (name "free") @ptr))
  ...
  (expr-stmt (call (name "free") @ptr)))   ; same @ptr!
```

The `...` ellipsis matches zero or more intervening statements. When the same `@var` appears multiple times, CASL enforces that all occurrences bind to **semantically equivalent** nodes (same `varId` for variables, same `exprId` for expressions).

### 6.6 Wildcard and Binding

```scheme
_          ; wildcard — matches anything, binds nothing
@x         ; binding variable — matches anything, binds to @x
(name "f") ; literal match — matches only the name "f"
```

### 6.7 Negation and Alternation

```scheme
;; Negation: match if the sub-pattern does NOT match
(not-pattern
  (call (name "free") @ptr))

;; Alternation: match if ANY sub-pattern matches
(or-pattern
  (call (name "malloc") @arg)
  (call (name "calloc") @arg1 @arg2)
  (call (name "realloc") @arg1 @arg2))

;; Conjunction: match if ALL sub-patterns match (on same node)
(and-pattern
  (token @t (is-name #t))
  (token @t (var-id @vid)))
```

### 6.8 Repetition Patterns

```scheme
;; Match one or more arguments in a function call
(call (name @fn) (args @arg ...))

;; Match a chain of field accesses: a.b.c.d...
(field-chain @base (fields @field ...))
```

### 6.9 Guarded Patterns

Patterns with inline predicates:

```scheme
;; Match a token that is a pointer type
(token @p
  (where (pointer-type? @p)))

;; Match an integer literal greater than 1024
(token @n
  (is-int #t)
  (where (> (int-value @n) 1024)))
```

### 6.10 Pattern Composition with `let-pattern`

Define reusable pattern fragments:

```scheme
(addon my-checker
  (let-pattern alloc-call
    (or-pattern
      (call (name "malloc") @size)
      (call (name "calloc") @nmemb @size)
      (call (name "realloc") @old @size)))

  (let-pattern dealloc-call
    (or-pattern
      (call (name "free") @ptr)
      (call (name "delete") @ptr)))

  (rule double-free
    (pattern
      (sequence
        (expr-stmt (use-pattern dealloc-call (bind @ptr @first-free)))
        ...
        (expr-stmt (use-pattern dealloc-call (bind @ptr @second-free)))))
    (constraint
      (not (exists-between @first-free @second-free
        (assign @ptr _))))
    (action
      (report error
        "Double free of pointer"
        (location @second-free)
        (note "First free here" (location @first-free))))))
```

---

## 7. Constraint System

Constraints are semantic predicates that refine pattern matches. While patterns match *structure*, constraints check *meaning*.

### 7.1 Basic Predicates

```scheme
;; Type constraints
(pointer-type? @expr)             ; is @expr a pointer type?
(integral-type? @expr)            ; is @expr an integral type?
(float-type? @expr)               ; is @expr a floating-point type?
(type-equal? @a @b)               ; do @a and @b have the same type?
(type-name? @expr "std::string")  ; does @expr have this original type name?

;; Value constraints
(known-int-value? @tok)           ; does the token have a known int value?
(value-in-range? @tok 0 255)      ; is the known value in [0, 255]?
(null-value? @tok)                ; is the value known to be NULL/0?

;; Identity constraints
(same-variable? @a @b)            ; same varId?
(same-expression? @a @b)          ; same exprId?

;; Boolean combinators
(and <c1> <c2> ...)               ; all must hold
(or <c1> <c2> ...)                ; at least one must hold
(not <c>)                         ; negation
(implies <c1> <c2>)               ; logical implication
(true)                            ; always holds
(false)                           ; never holds
```

### 7.2 Control-Flow Constraints

These constraints query the control-flow graph built by `cppcheckdata-shims`:

```scheme
;; Reachability
(reaches @from @to)
;; "There exists a CFG path from @from to @to"

;; Dominance
(dominates @dominator @dominated)
;; "@dominator dominates @dominated in the CFG"

(post-dominates @post-dom @node)
;; "@post-dom post-dominates @node"

;; Path constraints
(on-all-paths @from @to @through)
;; "Every path from @from to @to passes through @through"

(along-path @from @to
  (not (contains (assign @ptr _))))
;; "There exists a path from @from to @to on which @ptr is not reassigned"

;; Loop constraints
(in-loop? @tok)
;; "Is @tok inside a loop body?"

(loop-invariant? @expr @loop)
;; "Is @expr invariant with respect to @loop?"
```

### 7.3 Data-Flow Constraints

```scheme
;; Definition-use chains
(def-reaches-use @def @use)
;; "The definition at @def reaches the use at @use without intervening redefinition"

;; Liveness
(live-at? @var @point)
;; "Is @var live at program point @point?"

;; Available expressions
(available-at? @expr @point)
;; "Is @expr available (already computed and unchanged) at @point?"

;; Taint flow
(flows-to @source @sink)
;; "Data from @source can flow to @sink"
;; (Uses the dataflow engine's reaching-definitions or taint analysis)

;; Very busy expressions
(very-busy-at? @expr @point)
;; "Is @expr very busy at @point?" (used on all subsequent paths before redefinition)
```

### 7.4 Abstract Domain Constraints

```scheme
;; Nullness analysis
(may-be-null? @ptr)
;; "According to nullness analysis, @ptr may be null at this point"

(must-be-null? @ptr)
;; "@ptr is definitely null"

(must-be-non-null? @ptr)
;; "@ptr is definitely non-null"

;; Sign analysis
(sign-of @expr positive)         ; @expr is known positive
(sign-of @expr negative)         ; @expr is known negative
(sign-of @expr zero)             ; @expr is known to be zero

;; Taint analysis
(tainted? @expr)                  ; @expr carries taint
(untainted? @expr)                ; @expr is clean

;; Interval analysis
(interval-subset? @expr (interval 0 100))
;; "The abstract value of @expr is within [0, 100]"
```

### 7.5 Scope and Function Constraints

```scheme
;; Scope constraints
(in-scope-type? @tok function)
(in-scope-type? @tok class)
(scope-encloses? @outer @inner)

;; Function constraints
(is-function-call? @tok)
(calls-function? @tok "memcpy")
(function-arg-count? @tok 3)
(is-constructor? @func)
(is-destructor? @func)
(is-virtual? @func)
(is-static-member? @func)
```

### 7.6 Custom Predicates (Escape Hatch)

When CASL's built-in constraint vocabulary is insufficient:

```scheme
(constraint
  (python-pred
    "token.valueType and token.valueType.pointer > 0 and 'const' not in (token.valueType.originalTypeName or '')"))
```

The `python-pred` form embeds a raw Python expression that receives the bound variables as local names (with `@` stripped and hyphens replaced by underscores).

---

## 8. Action System

Actions describe what happens when a rule fires.

### 8.1 Report Action

The primary action — emit a diagnostic:

```scheme
(report <severity> <message>
  (location <bind-var>)
  <note>*)
```

Severities: `error`, `warning`, `style`, `performance`, `portability`, `information`

```scheme
(action
  (report error
    "Use after free: '@ptr.str' was freed at line @free-site.linenr"
    (location @use-site)
    (note "Freed here" (location @free-site))
    (note "Pointer was allocated here" (location @alloc-site))))
```

### 8.2 String Interpolation in Messages

Message strings support interpolation of bound variable properties:

| Syntax | Meaning |
|---|---|
| `@var.str` | The token string of `@var` |
| `@var.linenr` | The line number of `@var` |
| `@var.file` | The file name of `@var` |
| `@var.column` | The column number of `@var` |
| `@var.type` | The token type of `@var` |

Example:

```scheme
"Buffer '@buf.str' accessed at index @idx.str which may exceed allocated size"
```

### 8.3 Set-Fact Action

Produce a fact for consumption by other rules:

```scheme
(action
  (set-fact freed-pointer
    (var @ptr)
    (token @free-tok)))
```

### 8.4 Log Action

Emit debug output (useful during development):

```scheme
(action
  (log "Matched: @tok.str at @tok.file:@tok.linenr"))
```

### 8.5 Suppress Action

Mark a location as suppressed (prevent other rules from firing there):

```scheme
(action
  (suppress @tok "intentional-fallthrough"))
```

### 8.6 Tag Action

Attach metadata to an AST node for use by subsequent rules:

```scheme
(action
  (tag @ptr "checked-for-null"))
```

Later rules can check:

```scheme
(constraint
  (not (has-tag? @ptr "checked-for-null")))
```

### 8.7 Multiple Actions

A rule can have multiple actions:

```scheme
(rule track-and-report-alloc
  (pattern
    (assign @ptr (call (name "malloc") @size)))
  (action
    (set-fact allocated-pointer
      (var @ptr)
      (token @ptr)
      (size @size))
    (log "Tracked allocation: @ptr.str")))
```

---

## 9. Fact System & Inter-Rule Communication

### 9.1 Overview

The fact system enables rules to communicate through typed tuples, inspired by Datalog relations. One rule *produces* facts; another *consumes* them.

### 9.2 Defining Fact Schemas

```scheme
(fact-schema <name>
  (<field-name> <field-type>)
  ...)
```

Field types:

| Type | Description |
|---|---|
| `token` | A reference to a Token node |
| `variable` | A reference to a Variable node |
| `function` | A reference to a Function node |
| `scope` | A reference to a Scope node |
| `string` | A string value |
| `int` | An integer value |
| `bool` | A boolean value |

Example:

```scheme
(fact-schema freed-pointer
  (ptr-var variable)
  (free-token token)
  (in-function function))

(fact-schema allocated-pointer
  (ptr-var variable)
  (alloc-token token)
  (byte-count int))
```

### 9.3 Producing Facts

```scheme
(action
  (set-fact freed-pointer
    (ptr-var @ptr.variable)
    (free-token @free-tok)
    (in-function @free-tok.scope.function)))
```

### 9.4 Consuming Facts

In a constraint or pattern:

```scheme
(rule use-after-free
  (pattern
    (token @use-tok
      (is-name #t)
      (where (variable-of @use-tok @var))))
  (constraint
    (and
      (has-fact freed-pointer
        (ptr-var @var)
        (free-token @free-tok))
      (reaches @free-tok @use-tok)
      (not (exists-between @free-tok @use-tok
        (assign-to-var @var)))))
  (action
    (report error
      "Use after free: '@use-tok.str'"
      (location @use-tok)
      (note "Freed here" (location @free-tok)))))
```

### 9.5 Execution Ordering

When rule A produces `freed-pointer` facts and rule B consumes them, CASL automatically schedules rule A before rule B. Circular dependencies are detected at compile time and reported as errors.

---

## 10. Type & Value Expressions

### 10.1 Type Matching

```scheme
;; Match by Cppcheck ValueType fields
(type-match @tok
  (type "int")
  (sign "signed")
  (pointer 0))

;; Match pointer to char
(type-match @tok
  (type "char")
  (pointer 1))

;; Match any pointer
(type-match @tok
  (pointer (>= 1)))

;; Match const pointer
(type-match @tok
  (constness (> 0))
  (pointer (>= 1)))

;; Match by original type name (typedef resolution)
(type-match @tok
  (original-type-name "size_t"))
```

### 10.2 Value Expressions

```scheme
;; Cppcheck's known values
(has-known-value? @tok)
(known-value @tok @val)

;; Comparison of known values
(value-satisfies? @tok (lambda (v) (> v 0)))

;; Impossible values (Cppcheck reports values that are impossible)
(has-impossible-value? @tok 0)  ; 0 is impossible → @tok is never zero
```

---

## 11. Built-in Domains & Lattices

CASL integrates with the abstract domains provided by `cppcheckdata-shims.abstract_domains`.

### 11.1 Using Built-in Domains in Constraints

```scheme
;; Run nullness analysis and query results
(constraint
  (with-analysis nullness @func-scope
    (may-be-null? @ptr)))

;; Run taint analysis 
(constraint
  (with-analysis taint @func-scope
    (tainted-at? @expr @program-point)))

;; Run interval analysis
(constraint
  (with-analysis intervals @func-scope
    (interval-of @index @lo @hi)
    (or (< @lo 0) (>= @hi @array-size))))
```

### 11.2 Defining Custom Domains

```scheme
(domain FileLeak
  (elements open closed error top bottom)
  (bottom bottom)
  (top top)
  (join
    (open open open)
    (closed closed closed)
    (open closed top)
    (error error error)
    (bottom _ identity)
    (_ bottom identity))
  (transfer-rules
    (call "fopen"  _ -> open)
    (call "fclose" open -> closed)
    (call "fclose" closed -> error)))  ; double-close!
```

### 11.3 Transfer Functions in Domain Definitions

```scheme
(domain TaintState
  (elements clean tainted top bottom)
  (bottom bottom)
  (top top)
  (join
    (clean tainted tainted)   ; tainted wins
    (clean clean clean)
    (tainted tainted tainted)
    (bottom _ identity)
    (_ bottom identity))
  (transfer-rules
    ;; Input functions produce taint
    (call "scanf"   _ -> tainted)
    (call "gets"    _ -> tainted)
    (call "getenv"  _ -> tainted)
    ;; Sanitizers remove taint
    (call "sanitize" tainted -> clean)
    ;; Assignments propagate taint from RHS to LHS
    (assign propagate)))
```

---

## 12. Control-Flow & Data-Flow Queries

### 12.1 CFG Construction

CASL's constraints automatically trigger CFG construction when needed. The CFG is built lazily — only when a rule uses a control-flow or data-flow constraint.

```scheme
;; This rule triggers CFG construction for the enclosing function
(rule dead-code
  (pattern
    (in-scope function
      (return-stmt @ret)))
  (constraint
    (exists-after @ret @unreachable
      (not (reaches @ret @unreachable))))
  (action
    (report style
      "Unreachable code after return statement"
      (location @unreachable))))
```

### 12.2 Dominance Queries

```scheme
;; Check that a null-check dominates a dereference
(rule null-deref-check
  (pattern
    (token @deref
      (where (is-deref? @deref))))
  (constraint
    (and
      (may-be-null? @deref)
      (not (exists @check
        (and
          (is-null-check? @check @deref)
          (dominates @check @deref))))))
  (action
    (report warning
      "Possible null dereference of '@deref.str'"
      (location @deref))))
```

### 12.3 Loop-Aware Analysis

```scheme
;; Detect loop-invariant conditions
(rule loop-invariant-condition
  (pattern
    (while-stmt
      (condition @cond)
      (body @body)))
  (constraint
    (loop-invariant? @cond @body))
  (action
    (report style
      "Loop condition '@cond.str' is invariant — possible infinite loop or unnecessary loop"
      (location @cond))))
```

### 12.4 Path-Sensitive Queries

```scheme
;; Detect a path where a lock is acquired but not released
(rule lock-leak
  (pattern
    (in-scope function
      (expr-stmt (call (name "pthread_mutex_lock") @mtx))))
  (constraint
    (exists-path @lock-site (function-exit)
      (not (contains
        (call (name "pthread_mutex_unlock") @mtx)))))
  (action
    (report warning
      "Mutex '@mtx.str' may not be unlocked on all paths"
      (location @lock-site))))
```

---

## 13. Interprocedural Analysis

### 13.1 Call Graph Queries

```scheme
;; Check if a function is recursive (directly or indirectly)
(constraint
  (in-call-graph
    (calls-transitively? @func @func)))

;; Check if function A can eventually call function B
(constraint
  (in-call-graph
    (calls-transitively? @caller @callee)))
```

### 13.2 Cross-Function Facts

Facts propagate across function boundaries when combined with call-graph information:

```scheme
(rule mark-allocators
  (pattern
    (function-def @func
      (body
        (contains
          (return-stmt
            (call (name "malloc") _))))))
  (action
    (set-fact allocator-function
      (func @func))))

(rule check-leaked-alloc
  (pattern
    (assign @ptr (call @callee _)))
  (constraint
    (and
      (has-fact allocator-function
        (func @callee.function))
      (not (exists-after @ptr
        (or-pattern
          (call (name "free") @ptr)
          (assign _ @ptr))))))     ; passed elsewhere
  (action
    (report warning
      "Return value of allocator '@callee.str' may leak"
      (location @ptr))))
```

---

## 14. Complete Worked Examples

### 14.1 Example 1: Double Free Detector

```scheme
(addon double-free-detector
  (metadata
    (version "1.0.0")
    (description "Detects double-free vulnerabilities in C code"))

  (fact-schema free-event
    (ptr-var variable)
    (free-token token)
    (enclosing-scope scope))

  ;; Phase 1: Record all free() calls
  (rule record-frees
    (pattern
      (expr-stmt
        (call (name "free")
          (args (token @ptr-tok (is-name #t))))))
    (constraint
      (pointer-type? @ptr-tok))
    (action
      (set-fact free-event
        (ptr-var @ptr-tok.variable)
        (free-token @ptr-tok)
        (enclosing-scope @ptr-tok.scope))))

  ;; Phase 2: Find double frees
  (rule detect-double-free
    (pattern
      (expr-stmt
        (call (name "free")
          (args (token @ptr-tok (is-name #t))))))
    (constraint
      (and
        ;; There exists a prior free of the same variable
        (has-fact free-event
          (ptr-var @ptr-tok.variable)
          (free-token @prior-free))
        ;; The prior free reaches this one
        (reaches @prior-free @ptr-tok)
        ;; No intervening reassignment of the pointer
        (along-path @prior-free @ptr-tok
          (not (contains (assign @ptr-tok.variable _))))
        ;; Not the same token (don't self-match)
        (not (same-token? @prior-free @ptr-tok))))
    (action
      (report error
        "Double free of '@ptr-tok.str'"
        (location @ptr-tok)
        (note "Previously freed here" (location @prior-free))))))
```

**Target C code this would catch:**

```c
void vulnerable(char *buf) {
    free(buf);
    // ... some code ...
    if (error_condition) {
        free(buf);  // DOUBLE FREE!
    }
}
```

### 14.2 Example 2: SQL Injection via Taint Tracking

```scheme
(addon sql-injection-checker
  (metadata
    (version "1.0.0")
    (description "Detects potential SQL injection via taint analysis"))

  (let-pattern taint-source
    (or-pattern
      (call (name "getenv") _)
      (call (name "gets") _)
      (call (name "fgets") _ _ _)
      (call (name "scanf") _ _)
      (call (name "readline") _)))

  (let-pattern sql-sink
    (or-pattern
      (call (name "mysql_query") _ @query)
      (call (name "sqlite3_exec") _ @query _ _ _)
      (call (name "PQexec") _ @query)))

  (let-pattern sanitizer
    (or-pattern
      (call (name "mysql_real_escape_string") _ _ _ _ _)
      (call (name "sqlite3_mprintf") _)
      (call (name "PQescapeLiteral") _ _ _)))

  (rule detect-sql-injection
    (pattern
      (in-scope function
        (sequence
          (assign @user-input (use-pattern taint-source))
          ...
          (expr-stmt (use-pattern sql-sink (bind @query @sink-tok))))))
    (constraint
      (and
        (flows-to @user-input @query)
        (along-path @user-input @sink-tok
          (not (contains (use-pattern sanitizer))))))
    (action
      (report error
        "Potential SQL injection: unsanitized input '@user-input.str' flows to SQL query"
        (location @sink-tok)
        (note "Tainted input originates here" (location @user-input))))))
```

### 14.3 Example 3: Resource Leak Detector (File Handles)

```scheme
(addon file-leak-checker
  (metadata
    (version "1.0.0")
    (description "Detects unclosed file handles"))

  (domain FileState
    (elements open closed top bottom)
    (bottom bottom)
    (top top)
    (join
      (open open open)
      (closed closed closed)
      (open closed top)
      (bottom _ identity)
      (_ bottom identity))
    (transfer-rules
      (call "fopen"  _ -> open)
      (call "fclose" open -> closed)))

  (rule detect-file-leak
    (pattern
      (in-scope function
        (assign @fp (call (name "fopen") _ _))))
    (constraint
      (exists-path @fp (function-exit)
        (not (contains
          (call (name "fclose") @fp)))))
    (action
      (report warning
        "File handle '@fp.str' may not be closed on all paths"
        (location @fp)
        (note "Opened here" (location @fp)))))

  (rule detect-double-close
    (pattern
      (in-scope function
        (sequence
          (expr-stmt (call (name "fclose") @fp))
          ...
          (expr-stmt (call (name "fclose") @fp)))))
    (constraint
      (along-path @first-close @second-close
        (not (contains (assign @fp (call (name "fopen") _ _))))))
    (action
      (report error
        "Double close of file handle '@fp.str'"
        (location @second-close)
        (note "First close here" (location @first-close))))))
```

### 14.4 Example 4: Buffer Overflow Detection

```scheme
(addon buffer-overflow-checker
  (metadata
    (version "1.0.0")
    (description "Detects potential buffer overflows"))

  (rule strcpy-overflow
    (pattern
      (call (name "strcpy")
        (args @dest @src)))
    (constraint
      (and
        (type-match @dest (type "char") (pointer 1))
        (or
          ;; Case 1: dest has known size, src has known strlen
          (and
            (known-buffer-size? @dest @dest-size)
            (known-string-length? @src @src-len)
            (>= @src-len @dest-size))
          ;; Case 2: src comes from untrusted input
          (tainted? @src))))
    (action
      (report error
        "Potential buffer overflow: strcpy to '@dest.str' from '@src.str'"
        (location @dest)
        (note "Consider using strncpy or strlcpy"))))

  (rule array-index-oob
    (pattern
      (ast-match
        (array-subscript @arr @index)))
    (constraint
      (with-analysis intervals @arr.scope
        (and
          (known-array-size? @arr @size)
          (interval-of @index @lo @hi)
          (or (< @lo 0) (>= @hi @size)))))
    (action
      (report warning
        "Array '@arr.str' index may be out of bounds: index range [@lo, @hi], array size @size"
        (location @index)))))
```

### 14.5 Example 5: Coding Style — Switch Fallthrough

```scheme
(addon switch-fallthrough-checker
  (metadata
    (version "1.0.0")
    (description "Warns on implicit switch case fallthrough"))

  (rule implicit-fallthrough
    (pattern
      (switch-stmt
        (body
          (case-label @case1)
          ...
          (case-label @case2))))
    (constraint
      (and
        ;; There's a path from case1 to case2 that doesn't go through break/return
        (reaches @case1 @case2)
        (along-path @case1 @case2
          (not (contains
            (or-pattern
              (break-stmt)
              (return-stmt _)
              (goto-stmt _)
              (token _ (where (has-comment-annotation? _ "fallthrough")))))))
        ;; Not an empty case (intentional grouping)
        (exists-between @case1 @case2
          (not-pattern (case-label _)))))  ; there's actual code between them
    (action
      (report style
        "Implicit fallthrough from case at line @case1.linenr to case at line @case2.linenr"
        (location @case2)
        (note "Previous case starts here" (location @case1))
        (note "Add /* fallthrough */ comment or break statement")))))
```

### 14.6 Example 6: MISRA C Compliance Rule

```scheme
(addon misra-c-extra
  (metadata
    (version "1.0.0")
    (description "Additional MISRA C:2012 rules"))

  ;; MISRA C:2012 Rule 17.7 — The value returned by a function having non-void
  ;; return type shall be used.
  (rule misra-17-7-unused-return
    (pattern
      (expr-stmt
        (call @fn (args _ ...))))
    (constraint
      (and
        (is-function-call? @fn)
        ;; Function has a non-void return type
        (not (return-type-void? @fn.function))
        ;; The return value is discarded (it's a bare expression-statement)
        (not (parent-is-assignment? @fn))
        (not (parent-is-initializer? @fn))
        (not (parent-is-condition? @fn))
        (not (parent-is-argument? @fn))
        ;; Exceptions: functions with known side-effects only
        (not (or
          (calls-function? @fn "printf")
          (calls-function? @fn "memset")
          (calls-function? @fn "memcpy")
          (calls-function? @fn "free")))))
    (action
      (report warning
        "[MISRA C:2012 Rule 17.7] Return value of '@fn.str' is discarded"
        (location @fn)))))
```

---

## 15. CLI Reference

### 15.1 Command Overview

casl <command> [options] [arguments]

Commands:
  compile     Compile a .casl file to a Python addon
  check       Validate a .casl file without generating code
  dump-ast    Print the parsed AST of a .casl file
  dump-sexp   Print the raw S-expression parse tree
  run         Compile and immediately execute on a dump file
  info        Show metadata and rule information for a .casl file
  init        Generate a skeleton .casl file


### 15.2 `compile` — Compile to Python

```bash
casl compile <input.casl> [options]

Options:
  -o, --output <file>    Output Python file (default: <input>_addon.py)
  --source-map           Generate a .map file for error tracing
  --no-optimize          Disable pattern compilation optimizations
  --python-version 3.9   Target Python version (default: current)
  --standalone            Include all dependencies inline (no imports)
  --header <text>         Add custom header comment to generated file
  -v, --verbose           Show compilation progress
```

Example:

```bash
casl compile my-checker.casl -o my_checker_addon.py --source-map -v
```

### 15.3 `check` — Validate Without Compiling

```bash
casl check <input.casl> [options]

Options:
  --strict               Treat warnings as errors
  --pedantic             Enable extra style warnings
  -W <warning-name>      Enable specific warning
```

Example:

```bash
casl check my-checker.casl --strict --pedantic
```

Output:

my-checker.casl:14:5: warning: constraint 'reaches' requires CFG — ensure
    target functions are not too large for analysis [perf-cfg-construction]
my-checker.casl:23:9: note: fact 'freed-pointer' is produced but never
    consumed [unused-fact]
✓ 0 errors, 2 warnings


### 15.4 `dump-ast` — Inspect Parsed Structure

```bash
casl dump-ast my-checker.casl

# Output:
Addon(name='my-checker',
  metadata=Metadata(version='1.0.0', ...),
  rules=[
    Rule(name='detect-double-free',
      pattern=SequencePattern([
        ExprStmtPattern(CallPattern(name='free', args=[...])),
        Ellipsis(),
        ExprStmtPattern(CallPattern(name='free', args=[...]))
      ]),
      constraint=AndConstraint([...]),
      actions=[ReportAction(severity='error', ...)])])
```

### 15.5 `dump-sexp` — Raw Parse Tree

```bash
casl dump-sexp my-checker.casl

# Output:
(addon my-checker
  (metadata (version "1.0.0") ...)
  (rule detect-double-free
    (pattern ...) ...))
```

### 15.6 `run` — Compile and Execute

```bash
casl run <input.casl> -- <dumpfile> [cppcheck-addon-options]

Options:
  --keep                 Keep the generated .py file after execution
  --timing               Show execution timing statistics
  --debug                Enable debug logging in generated code
```

Example:

```bash
# Generate dump first
cppcheck --dump my_project/src/*.c

# Run CASL checker on all dumps
casl run my-checker.casl --timing -- my_project/src/*.c.dump
```

### 15.7 `info` — Show Checker Information

```bash
casl info my-checker.casl

# Output:
Addon: my-checker v1.0.0
  Description: Detects double-free vulnerabilities in C code

  Facts:
    freed-pointer: (ptr-var: variable, free-token: token, enclosing-scope: scope)

  Rules:
    1. record-frees
       Pattern: expr-stmt > call[free]
       Produces: freed-pointer
       Consumes: (none)

    2. detect-double-free
       Pattern: expr-stmt > call[free]
       Produces: (none)
       Consumes: freed-pointer
       Uses: CFG reachability, path analysis

  Execution order: record-frees → detect-double-free
```

### 15.8 `init` — Generate Skeleton

```bash
casl init <name> [--template <template-name>]

Templates:
  basic        Minimal skeleton (default)
  leak         Memory leak detection skeleton
  taint        Taint analysis skeleton
  style        Coding style checker skeleton
  misra        MISRA C compliance skeleton
```

---

## 16. Compilation Model & Generated Code

### 16.1 Compilation Pipeline

┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌────────────┐
│  .casl file  │────▶│   S-expr     │────▶│   Semantic   │────▶│   Code     │
│  (source)    │     │   Parser     │     │   Analysis   │     │ Generation │
└─────────────┘     └──────────────┘     └──────────────┘     └────────────┘
                           │                     │                    │
                     ┌─────▼─────┐        ┌──────▼──────┐     ┌──────▼──────┐
                     │ Raw AST   │        │ Typed AST   │     │ Python      │
                     │ (sexpdata)│        │ + Symbol    │     │ Addon       │
                     │           │        │   Table     │     │ (.py file)  │
                     └───────────┘        └─────────────┘     └─────────────┘


### 16.2 What Gets Generated

A compiled CASL file produces a single Python file that:

1. **Imports** `cppcheckdata` and `cppcheckdata_shims` modules
2. **Defines** matching functions for each pattern
3. **Defines** constraint-checking functions
4. **Defines** action functions
5. **Defines** a main loop that:
   - Parses the dump file via `cppcheckdata.parsedump()`
   - Iterates through configurations
   - Runs each rule in dependency order
   - Reports diagnostics via `cppcheckdata.reportError()`

### 16.3 Example: Generated Code Structure

For a simple rule:

```scheme
(rule no-goto
  (pattern (token @t (str "goto")))
  (action (report style "goto considered harmful" (location @t))))
```

Generated Python (simplified):

```python
#!/usr/bin/env python3
"""Generated by CASL compiler v1.0.0 from no-goto.casl"""

import cppcheckdata
import sys

def check_rule_no_goto(data, cfg):
    """Rule: no-goto"""
    for token in cfg.tokenlist:
        # Pattern: (token @t (str "goto"))
        if token.str == "goto":
            t = token  # bind @t
            # Action: report
            cppcheckdata.reportError(
                t,            # location
                'style',      # severity
                'goto considered harmful',  # message
                'no-goto',    # addon name (from rule)
                'no-goto'     # errorId
            )

def main():
    for arg in sys.argv[1:]:
        if not arg.endswith('.dump'):
            continue
        data = cppcheckdata.parsedump(arg)
        if not data.configurations:
            continue
        for cfg in data.configurations:
            check_rule_no_goto(data, cfg)

if __name__ == '__main__':
    main()
```

### 16.4 Source Maps

When compiled with `--source-map`, a `.map` JSON file is produced:

```json
{
  "version": "1.0",
  "source": "my-checker.casl",
  "generated": "my_checker_addon.py",
  "mappings": [
    {"generated_line": 12, "source_line": 5, "source_col": 3, "element": "rule:no-goto/pattern"},
    {"generated_line": 14, "source_line": 6, "source_col": 5, "element": "rule:no-goto/action"}
  ]
}
```

This enables the `DiagnosticFormatter` to trace runtime errors back to CASL source locations.

---

## 17. Diagnostics & Debugging

### 17.1 Compile-Time Diagnostics

CASL produces GCC/Clang-style diagnostics:

my-checker.casl:14:5: error: unbound variable '@ptr' in constraint
   14 │     (reaches @free-tok @ptr)
      │                        ^^^^
      │ note: '@ptr' is not bound by the pattern in this rule
      │ note: did you mean '@ptr-tok'?

my-checker.casl:23:3: warning: rule 'helper-rule' produces fact 'temp-data'
    that is never consumed [-Wunused-fact]
   23 │   (set-fact temp-data ...)
      │   ^~~~~~~~~~~~~~~~~~~~~~~


### 17.2 Semantic Analysis Checks

The semantic analysis phase catches:

| Error | Description |
|---|---|
| Unbound variables | `@var` used in constraint/action but not bound in pattern |
| Type mismatches | Fact field type doesn't match provided value type |
| Undefined facts | Consuming a fact that no rule produces |
| Circular dependencies | Rule A depends on B depends on A |
| Invalid patterns | Structurally malformed patterns |
| Unknown predicates | Using a constraint predicate that doesn't exist |
| Arity errors | Wrong number of arguments to a pattern or constraint |

### 17.3 Runtime Debugging

When using `casl run --debug`:

[DEBUG] Rule record-frees: checking token 'free' at test.c:15
[DEBUG]   Pattern matched: @ptr-tok = Token(str='buf', varId=3)
[DEBUG]   Constraint pointer-type?: True
[DEBUG]   Action: set-fact freed-pointer(ptr-var=Variable(name='buf'), ...)
[DEBUG] Rule detect-double-free: checking token 'free' at test.c:22
[DEBUG]   Pattern matched: @ptr-tok = Token(str='buf', varId=3)
[DEBUG]   Constraint has-fact freed-pointer: found 1 match(es)
[DEBUG]   Constraint reaches: True (path length: 7 nodes)
[DEBUG]   Constraint along-path (no reassignment): True
[DEBUG]   → FINDING: Double free of 'buf' at test.c:22


### 17.4 Performance Profiling

With `--timing`:

Timing Report:
  Parse:              2.3ms
  Semantic analysis:  1.1ms
  CFG construction:   45.2ms  (3 functions)
  Rule execution:
    record-frees:           12.4ms (scanned 1,247 tokens, 3 matches)
    detect-double-free:     38.7ms (scanned 1,247 tokens, 1 finding)
  Total:              99.7ms


---

## 18. Appendix A: Grammar Reference

### 18.1 Formal Grammar (PEG)

```peg
addon       = "(" "addon" symbol metadata? import* domain* fact_schema* let_pattern* rule+ ")"
metadata    = "(" "metadata" meta_field+ ")"
meta_field  = "(" symbol string ")"

import      = "(" "import" string ")"

domain      = "(" "domain" symbol
                "(" "elements" symbol+ ")"
                "(" "bottom" symbol ")"
                "(" "top" symbol ")"
                "(" "join" join_entry+ ")"
                "(" "transfer-rules" transfer+ ")" ")"
join_entry  = "(" symbol symbol symbol ")"
transfer    = "(" "call" string symbol "->" symbol ")"
            / "(" "assign" "propagate" ")"

fact_schema = "(" "fact-schema" symbol field_decl+ ")"
field_decl  = "(" symbol type_name ")"
type_name   = "token" / "variable" / "function" / "scope" / "string" / "int" / "bool"

let_pattern = "(" "let-pattern" symbol pattern ")"

rule        = "(" "rule" symbol options? pattern constraint? action+ ")"
options     = "(" "options" option+ ")"
option      = "(" symbol atom ")"

pattern     = token_pat / ast_pat / stmt_pat / scope_pat / seq_pat
            / or_pat / and_pat / not_pat / use_pat / guard_pat

token_pat   = "(" "token" bind_or_wild prop* ")"
prop        = "(" symbol atom ")"
            / "(" "where" constraint ")"

ast_pat     = "(" "ast-match" ast_node ")"
ast_node    = "(" symbol bind_or_wild* ")"

stmt_pat    = if_pat / for_pat / while_pat / return_pat / expr_pat / switch_pat
              / break_pat / goto_pat / func_def_pat
if_pat      = "(" "if-stmt" clause* ")"
for_pat     = "(" "for-stmt" clause* ")"
while_pat   = "(" "while-stmt" clause* ")"
return_pat  = "(" "return-stmt" pattern ")"
expr_pat    = "(" "expr-stmt" pattern ")"
func_def_pat= "(" "function-def" bind_or_wild clause* ")"

clause      = "(" symbol pattern ")"

scope_pat   = "(" "in-scope" symbol pattern ")"
seq_pat     = "(" "sequence" seq_elem+ ")"
seq_elem    = pattern / "..."

or_pat      = "(" "or-pattern" pattern+ ")"
and_pat     = "(" "and-pattern" pattern+ ")"
not_pat     = "(" "not-pattern" pattern ")"
use_pat     = "(" "use-pattern" symbol bind_clause? ")"
bind_clause = "(" "bind" bind_var+ ")"
guard_pat   = "(" "token" bind_or_wild prop* "(" "where" constraint ")" ")"

constraint  = pred / bool_comb / flow_cons / df_cons / domain_cons
            / scope_cons / fact_cons / python_cons / type_cons / value_cons

pred        = "(" pred_name bind_or_wild* ")"
pred_name   = "pointer-type?" / "integral-type?" / "float-type?"
            / "type-equal?" / "known-int-value?" / "null-value?"
            / "same-variable?" / "same-expression?" / ... 

bool_comb   = "(" "and" constraint+ ")"
            / "(" "or" constraint+ ")"
            / "(" "not" constraint ")"
            / "(" "implies" constraint constraint ")"
            / "(" "true" ")"  /  "(" "false" ")"

flow_cons   = "(" "reaches" expr expr ")"
            / "(" "dominates" expr expr ")"
            / "(" "post-dominates" expr expr ")"
            / "(" "on-all-paths" expr expr expr ")"
            / "(" "along-path" expr expr path_cond ")"
            / "(" "exists-path" expr expr path_cond ")"

path_cond   = "(" "not" "(" "contains" pattern ")" ")"
            / "(" "contains" pattern ")"

df_cons     = "(" "def-reaches-use" expr expr ")"
            / "(" "live-at?" expr expr ")"
            / "(" "flows-to" expr expr ")"
            / "(" "available-at?" expr expr ")"

domain_cons = "(" "with-analysis" symbol expr constraint ")"
            / "(" "may-be-null?" expr ")"
            / "(" "tainted?" expr ")"
            / "(" "interval-of" expr bind_var bind_var ")"

fact_cons   = "(" "has-fact" symbol field_match+ ")"
field_match = "(" symbol bind_or_wild ")"

python_cons = "(" "python-pred" string ")"

type_cons   = "(" "type-match" expr type_field+ ")"
type_field  = "(" symbol atom ")"

action      = report_act / fact_act / log_act / suppress_act / tag_act
report_act  = "(" "report" severity string "(" "location" expr ")" note* ")"
severity    = "error" / "warning" / "style" / "performance" / "portability"
note        = "(" "note" string "(" "location" expr ")" ")"
            / "(" "note" string ")"
fact_act    = "(" "set-fact" symbol field_val+ ")"
field_val   = "(" symbol expr ")"
log_act     = "(" "log" string ")"
suppress_act= "(" "suppress" expr string ")"
tag_act     = "(" "tag" expr string ")"

bind_or_wild = bind_var / "_"
bind_var     = ~"@[a-zA-Z][a-zA-Z0-9_-]*"
symbol       = ~"[a-zA-Z_][a-zA-Z0-9_-]*"
atom         = symbol / string / integer / float / bool
string       = ~"\"[^\"]*\""
integer      = ~"-?[0-9]+"
float        = ~"-?[0-9]+\\.[0-9]+"
bool         = "#t" / "#f"
expr         = bind_var / bind_var "." symbol ("." symbol)*
```

---

## 19. Appendix B: Built-in Predicates & Functions

### 19.1 Type Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `pointer-type?` | `@tok` | True if token has pointer type ($\text{pointer} \geq 1$) |
| `integral-type?` | `@tok` | True if token type ∈ {bool, char, short, int, long, long long} |
| `float-type?` | `@tok` | True if token type ∈ {float, double, long double} |
| `enum-type?` | `@tok` | True if token type is an enum |
| `void-type?` | `@tok` | True if token type is void |
| `signed-type?` | `@tok` | True if token is signed |
| `unsigned-type?` | `@tok` | True if token is unsigned |
| `type-equal?` | `@a`, `@b` | True if both tokens have identical `ValueType` |
| `type-name?` | `@tok`, `name` | True if `originalTypeName` matches |
| `return-type-void?` | `@func` | True if function returns void |
| `const-qualified?` | `@tok` | True if constness > 0 |

### 19.2 Value Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `known-int-value?` | `@tok` | Token has a known integer value |
| `null-value?` | `@tok` | Token's known value is 0/NULL |
| `has-known-value?` | `@tok` | Token has any known value |
| `has-impossible-value?` | `@tok`, `val` | Value `val` is in impossible values set |
| `value-in-range?` | `@tok`, `lo`, `hi` | Known value ∈ $[\text{lo}, \text{hi}]$ |

### 19.3 Token Property Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `is-name?` | `@tok` | `token.isName` |
| `is-number?` | `@tok` | `token.isNumber` |
| `is-string-literal?` | `@tok` | `token.isString` |
| `is-op?` | `@tok` | `token.isOp` |
| `is-assignment-op?` | `@tok` | `token.isAssignmentOp` |
| `is-comparison-op?` | `@tok` | `token.isComparisonOp` |
| `is-logical-op?` | `@tok` | `token.isLogicalOp` |
| `is-arithmetical-op?` | `@tok` | `token.isArithmeticalOp` |
| `is-cast?` | `@tok` | `token.isCast` |
| `is-expanded-macro?` | `@tok` | `token.isExpandedMacro` |

### 19.4 Identity and Relationship Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `same-variable?` | `@a`, `@b` | Same `varId` |
| `same-expression?` | `@a`, `@b` | Same `exprId` |
| `same-token?` | `@a`, `@b` | Same `Id` |
| `is-deref?` | `@tok` | Token is a pointer dereference (`*ptr` or `ptr->`) |
| `is-address-of?` | `@tok` | Token is address-of (`&var`) |
| `is-function-call?` | `@tok` | Token represents a function call |
| `calls-function?` | `@tok`, `name` | Function call matches name |
| `function-arg-count?` | `@tok`, `n` | Function call has exactly n arguments |
| `variable-of` | `@tok`, `@var` | Binds `@var` to the Variable of `@tok` |
| `has-tag?` | `@tok`, `tag` | Token was tagged with the given string |

### 19.5 Scope Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `in-scope-type?` | `@tok`, `type` | Token is in a scope of the given type |
| `scope-encloses?` | `@outer`, `@inner` | Outer scope encloses inner scope |
| `is-constructor?` | `@func` | Function is a constructor |
| `is-destructor?` | `@func` | Function is a destructor |
| `is-virtual?` | `@func` | Function is virtual |
| `is-static-member?` | `@func` | Function is a static member function |

### 19.6 Control-Flow Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `reaches` | `@from`, `@to` | CFG path exists from `@from` to `@to` |
| `dominates` | `@dom`, `@node` | `@dom` dominates `@node` |
| `post-dominates` | `@pdom`, `@node` | `@pdom` post-dominates `@node` |
| `in-loop?` | `@tok` | Token is within a loop body |
| `loop-invariant?` | `@expr`, `@loop` | Expression is invariant w.r.t. loop |
| `on-all-paths` | `@from`, `@to`, `@through` | All paths pass through `@through` |
| `along-path` | `@from`, `@to`, `cond` | Some path satisfies the condition |
| `exists-path` | `@from`, `@to`, `cond` | Some path satisfies the condition |

### 19.7 Data-Flow Predicates

| Predicate | Arguments | Description |
|---|---|---|
| `def-reaches-use` | `@def`, `@use` | Definition reaches use without redefinition |
| `live-at?` | `@var`, `@point` | Variable is live at program point |
| `available-at?` | `@expr`, `@point` | Expression is available at program point |
| `flows-to` | `@source`, `@sink` | Data flows from source to sink |
| `very-busy-at?` | `@expr`, `@point` | Expression is very busy at point |
| `may-be-null?` | `@ptr` | Nullness analysis says possibly null |
| `must-be-null?` | `@ptr` | Nullness analysis says definitely null |
| `must-be-non-null?` | `@ptr` | Nullness analysis says definitely non-null |
| `tainted?` | `@expr` | Taint analysis says tainted |
| `untainted?` | `@expr` | Taint analysis says clean |

---

## 20. Appendix C: Comparison with PQL and Other Query Languages

### 20.1 CASL vs. PQL

PQL (Program Query Language) as described by Martin et al. expresses queries as sequences of events on Java objects. CASL draws inspiration from PQL's declarative approach but targets C/C++ and Cppcheck's infrastructure:

| Feature | PQL | CASL |
|---|---|---|
| **Target language** | Java bytecode | C/C++ (via Cppcheck dumps) |
| **Query model** | Object event sequences | AST pattern + CFG/dataflow constraints |
| **Pointer analysis** | Context-sensitive (bddbddb) | Via `cppcheckdata-shims` abstractions |
| **Dynamic fallback** | Yes (instrumented runtime) | No (pure static) |
| **Pattern language** | Java-like syntax | S-expressions |
| **Soundness** | Sound static + precise dynamic | Configurable (sound or unsound per rule) |
| **Fact system** | Implicit (via query matches) | Explicit (fact-schema declarations) |

### 20.2 CASL vs. CodeQL / Semgrep

| Feature | CodeQL | Semgrep | CASL |
|---|---|---|---|
| **Paradigm** | Datalog-like relational queries | Concrete syntax patterns | S-expression patterns + constraints |
| **Analysis depth** | Deep (full dataflow) | Shallow (syntactic) | Medium-Deep (CFG + dataflow + abstract domains) |
| **Target** | Multi-language (compiled DB) | Multi-language (text) | C/C++ only (Cppcheck dump) |
| **Learning curve** | Steep (QL language) | Gentle | Moderate |
| **Integration** | Standalone | Standalone / CI | Cppcheck addon ecosystem |
| **Custom domains** | Via library predicates | N/A | First-class `(domain ...)` declarations |

### 20.3 Design Rationale

CASL occupies a deliberate middle ground:
- **More powerful than Semgrep** — It has access to types, control flow, data flow, and abstract interpretation.
- **Less complex than CodeQL** — It doesn't require building a full relational database or learning a Datalog variant.
- **Deeply integrated with Cppcheck** — It leverages Cppcheck's existing dump infrastructure, token model, and reporting mechanism.
- **Extensible via Python** — The `python-pred` escape hatch and the generated Python code can be manually extended.

---

## Quick Reference Card

```scheme
;; ═══════════════════════════════════════════════════════════
;; CASL Quick Reference
;; ═══════════════════════════════════════════════════════════

;; Addon structure
(addon name (metadata ...) (rule name (pattern ...) (constraint ...) (action ...)))

;; Pattern atoms
@var                ; bind variable
_                   ; wildcard
...                 ; ellipsis (in sequences)
(token @t ...)      ; token match
(ast-match ...)     ; AST match
(sequence ...)      ; statement sequence
(or-pattern ...)    ; alternation
(not-pattern ...)   ; negation
(in-scope type ...) ; scoped match

;; Constraint atoms
(and ...)  (or ...)  (not ...)  (true)  (false)
(reaches @a @b)         (dominates @a @b)
(flows-to @src @sink)   (may-be-null? @p)
(tainted? @e)           (in-loop? @t)
(has-fact name ...)     (python-pred "...")

;; Action atoms
(report severity "msg" (location @v) (note "..." (location @v)))
(set-fact name (field val) ...)
(log "msg")  (tag @v "label")  (suppress @v "id")

;; CLI
casl compile in.casl -o out.py
casl check in.casl --strict
casl run in.casl -- file.c.dump
casl init my-checker
casl dump-ast in.casl
casl info in.casl
```

---

*This guide covers CASL version 1.0.0. For updates and additional examples, see the project repository.*