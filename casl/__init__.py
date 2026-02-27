"""casl — Cppcheck Abstract Specification Language.

This package provides the complete CASL tool-suite for abstract
interpretation, property verification, and query-based program
analysis on cppcheck dump files.

Submodules
----------
errors
    Hierarchical exception classes, structured error codes
    (``CASL-XXXX`` / ``CSQL-XXXX``), ``ErrorReporter``, and
    ``SourceSpan`` / ``ErrorMessage`` dataclasses for rich
    diagnostic context.

runtime
    Runtime infrastructure bridging cppcheckdata-shims VM with CASL
    language features: ``AbstractVM`` (25-opcode dispatch),
    ``AbstractInterpreter`` (fixpoint driver), ``SafetyChecker``
    (bounded model checking), ``PropertyMonitor``,
    ``TraceReconstructor``, abstract domains (``IntervalDomain``,
    ``BoolDomain``), and the ``CaslRuntime`` top-level façade.

main
    CLI entry-point with subcommands: ``analyze``, ``query``,
    ``compile``, ``interpret``, ``explore``, ``parse``, ``domains``.

Planned Submodules
------------------
parser
    CASL / CSQL front-end: lexer, recursive-descent parser, AST nodes.

compiler
    AST → IR lowering, type-checking, bytecode serialisation.

query_engine
    CSQL query execution engine over cppcheck dump data.

Usage
-----
Command-line::

    python -m casl analyze project.c.dump --spec rules.casl
    python -m casl query   project.c.dump --expr 'find uninitVar()'
    python -m casl --help

Programmatic::

    from casl.runtime import CaslRuntime, RuntimeConfig
    from casl.errors import ErrorReporter

    reporter = ErrorReporter()
    config = RuntimeConfig(max_iterations=200, widen_delay=3)
    rt = CaslRuntime(config=config)

"""

from __future__ import annotations

__version__: str = "0.1.0"
__all__: list[str] = [
    "__version__",
    "errors",
    "runtime",
    "__main__",
]
