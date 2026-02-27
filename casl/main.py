#!/usr/bin/env python3
"""casl/main.py — CLI entry-point for the CASL tool-suite.

Usage examples
--------------
    # Analyse a C/C++ dump file with a CASL specification
    python -m casl analyze project.c.dump --spec rules.casl

    # Run a CSQL query against a dump file
    python -m casl query project.c.dump --query find_null_deref.csql

    # Compile a CASL specification to IR (bytecode)
    python -m casl compile rules.casl --output rules.caslo

    # Interpret / execute compiled CASL bytecode against a dump
    python -m casl interpret rules.caslo --dump project.c.dump

    # Explore all execution paths (bounded model checking)
    python -m casl explore rules.caslo --dump project.c.dump --bound 500

    # Parse a CASL file and pretty-print the AST (debugging aid)
    python -m casl parse rules.casl --format sexp

    # List available abstract domains
    python -m casl domains --list

    # Show version and exit
    python -m casl --version

Exit codes
----------
    0   Success (no errors, no property violations).
    1   One or more diagnostics with severity ERROR were emitted.
    2   Infrastructure failure (missing dependency, bad file, etc.).
    3   Property violation detected (counterexample found).

The module doubles as ``python -m casl`` via the companion
``casl/__main__.py`` which simply calls :func:`main`.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Sequence,
    TextIO,
    Tuple,
)

# ---------------------------------------------------------------------------
# Lazy / guarded imports for heavy modules – keeps --help fast.
# ---------------------------------------------------------------------------

_log = logging.getLogger("casl")

# Exit codes ----------------------------------------------------------------

EXIT_OK: int = 0
EXIT_ERROR: int = 1
EXIT_INFRA: int = 2
EXIT_VIOLATION: int = 3

# Current version -----------------------------------------------------------

__version__: str = "0.1.0"


# ===========================================================================
# Utility helpers
# ===========================================================================

def _configure_logging(verbosity: int) -> None:
    """Set up the root ``casl`` logger.

    Parameters
    ----------
    verbosity:
        0 → WARNING, 1 → INFO, 2+ → DEBUG.
    """
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(levelname)-5.5s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    root = logging.getLogger("casl")
    root.setLevel(level)
    root.addHandler(handler)


def _resolve_path(raw: str, label: str = "file") -> Path:
    """Resolve *raw* to an absolute ``Path``, raising on missing files."""
    p = Path(raw).expanduser().resolve()
    if not p.exists():
        _log.error("%s not found: %s", label, p)
        raise SystemExit(EXIT_INFRA)
    return p


def _open_output(dest: Optional[str]) -> TextIO:
    """Return a writable text stream.

    *dest* ``None`` or ``"-"`` → ``sys.stdout``; otherwise open the path
    for writing (creating parent directories as needed).
    """
    if dest is None or dest == "-":
        return sys.stdout
    p = Path(dest).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return open(p, "w", encoding="utf-8")


def _emit_diagnostics(
    diagnostics: List[Any],
    fmt: str,
    stream: TextIO,
) -> int:
    """Write *diagnostics* to *stream* in the chosen format.

    Returns the count of ERROR-severity diagnostics.
    """
    error_count = 0
    for diag in diagnostics:
        sev = getattr(diag, "severity", "error")
        if str(sev).lower() == "error":
            error_count += 1

        if fmt == "json":
            # Use the cppcheck-compatible JSON serialisation when available.
            if hasattr(diag, "to_cppcheck_json"):
                stream.write(json.dumps(diag.to_cppcheck_json()) + "\n")
            elif hasattr(diag, "to_dict"):
                stream.write(json.dumps(diag.to_dict()) + "\n")
            else:
                stream.write(json.dumps(str(diag)) + "\n")
        elif fmt == "gcc":
            # GCC-style: file:line:col: severity: message [id]
            stream.write(str(diag) + "\n")
        else:
            # summary — one line per diagnostic
            stream.write(str(diag) + "\n")

    if fmt == "summary":
        stream.write(f"\n--- {len(diagnostics)} diagnostic(s), "
                      f"{error_count} error(s) ---\n")
    return error_count


# ===========================================================================
# Lazy-import helpers (keep top-level import light for --help speed)
# ===========================================================================

def _import_cppcheckdata():
    """Import ``cppcheckdata`` with a friendly error on failure."""
    try:
        import cppcheckdata  # type: ignore[import-untyped]
        return cppcheckdata
    except ImportError:
        _log.error(
            "cppcheckdata is not installed.  "
            "Install cppcheck or add its Python path."
        )
        raise SystemExit(EXIT_INFRA)


def _import_runtime():
    """Import ``casl.runtime`` lazily."""
    try:
        from casl import runtime  # type: ignore[import-untyped]
        return runtime
    except ImportError as exc:
        _log.error("Failed to import casl.runtime: %s", exc)
        raise SystemExit(EXIT_INFRA)


def _import_errors():
    """Import ``casl.errors`` lazily."""
    try:
        from casl import errors  # type: ignore[import-untyped]
        return errors
    except ImportError as exc:
        _log.error("Failed to import casl.errors: %s", exc)
        raise SystemExit(EXIT_INFRA)


# ===========================================================================
# Sub-command implementations
# ===========================================================================

# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    """Run CASL abstract-interpretation analysis on a cppcheck dump file.

    Workflow:
        1. Parse the ``.dump`` file via ``cppcheckdata.parsedump()``.
        2. Load the CASL specification (parse → compile → IR).
        3. Instantiate ``CaslRuntime`` with the chosen domains.
        4. Execute the ``SafetyChecker`` (or plain ``AbstractInterpreter``).
        5. Emit diagnostics and return an appropriate exit code.
    """
    cppcheckdata = _import_cppcheckdata()
    runtime = _import_runtime()
    errors = _import_errors()

    dump_path = _resolve_path(args.dump_file, "dump file")
    spec_path = _resolve_path(args.spec, "CASL spec") if args.spec else None

    _log.info("Parsing dump file: %s", dump_path)
    try:
        dump_data = cppcheckdata.parsedump(str(dump_path))
    except Exception as exc:
        _log.error("Failed to parse dump file: %s", exc)
        return EXIT_INFRA

    # Build runtime configuration from CLI flags.
    config_kwargs: Dict[str, Any] = {}
    if args.max_iterations is not None:
        config_kwargs["max_iterations"] = args.max_iterations
    if args.widen_delay is not None:
        config_kwargs["widen_delay"] = args.widen_delay
    if args.exploration_bound is not None:
        config_kwargs["exploration_bound"] = args.exploration_bound

    config = runtime.RuntimeConfig(**config_kwargs) if config_kwargs else runtime.RuntimeConfig()

    # Select abstract domains.
    domain_registry = runtime.DomainRegistry()
    if args.domains:
        for dname in args.domains:
            _log.info("Registering requested domain: %s", dname)
            # The DomainRegistry is expected to have built-in domains
            # registered by default; extra ones would be loaded here.

    # Instantiate the top-level facade.
    casl_rt = runtime.CaslRuntime(config=config, domain_registry=domain_registry)

    # --- Load & compile CASL spec (stub: assumes a loader exists) ---------
    program = None
    if spec_path is not None:
        _log.info("Loading CASL specification: %s", spec_path)
        try:
            # Future: casl.parser.parse_file(spec_path) → AST
            #         casl.compiler.compile(ast) → Program (IR)
            program = casl_rt.load_spec(spec_path)
        except AttributeError:
            _log.warning(
                "CaslRuntime.load_spec() not yet implemented; "
                "falling back to direct interpretation."
            )
        except Exception as exc:
            _log.error("Failed to load CASL specification: %s", exc)
            return EXIT_INFRA

    # --- Run analysis -----------------------------------------------------
    reporter = errors.ErrorReporter()
    t0 = time.monotonic()

    try:
        if program is not None and hasattr(casl_rt, "check_safety"):
            result = casl_rt.check_safety(program, dump_data, reporter=reporter)
        elif program is not None and hasattr(casl_rt, "interpret"):
            result = casl_rt.interpret(program, dump_data, reporter=reporter)
        else:
            _log.info("No program loaded; running built-in abstract interpretation.")
            if hasattr(casl_rt, "analyze_dump"):
                result = casl_rt.analyze_dump(dump_data, reporter=reporter)
            else:
                _log.warning("No analysis method available on CaslRuntime.")
                result = None
    except Exception as exc:
        _log.error("Analysis failed with exception: %s", exc)
        reporter.add_error(str(exc))
        result = None

    elapsed = time.monotonic() - t0
    _log.info("Analysis completed in %.3fs", elapsed)

    # --- Output diagnostics -----------------------------------------------
    diagnostics = reporter.diagnostics if hasattr(reporter, "diagnostics") else []
    out = _open_output(args.output)
    try:
        error_count = _emit_diagnostics(diagnostics, args.format, out)
    finally:
        if out is not sys.stdout:
            out.close()

    # --- Determine exit code ----------------------------------------------
    if result is not None and hasattr(result, "counterexamples"):
        if result.counterexamples:
            _log.info(
                "Found %d counterexample(s).", len(result.counterexamples)
            )
            return EXIT_VIOLATION

    return EXIT_ERROR if error_count > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# query (CSQL)
# ---------------------------------------------------------------------------

def cmd_query(args: argparse.Namespace) -> int:
    """Execute a CSQL query against a cppcheck dump file.

    CSQL (Cppcheck Specification Query Language) is the query sub-language
    of CASL, used for ad-hoc pattern matching and data extraction.
    """
    cppcheckdata = _import_cppcheckdata()
    errors = _import_errors()

    dump_path = _resolve_path(args.dump_file, "dump file")
    query_source: Optional[str] = None

    if args.query:
        qpath = _resolve_path(args.query, "CSQL query file")
        query_source = qpath.read_text(encoding="utf-8")
    elif args.expr:
        query_source = args.expr
    else:
        _log.error("Provide --query <file> or --expr '<inline query>'.")
        return EXIT_INFRA

    _log.info("Parsing dump file: %s", dump_path)
    try:
        dump_data = cppcheckdata.parsedump(str(dump_path))
    except Exception as exc:
        _log.error("Failed to parse dump file: %s", exc)
        return EXIT_INFRA

    # --- Execute query (stub: assumes a query engine exists) ---------------
    reporter = errors.ErrorReporter()
    results: List[Any] = []

    try:
        # Future: casl.query_engine.execute(query_source, dump_data, reporter)
        from casl import query_engine  # type: ignore[import-untyped]
        results = query_engine.execute(query_source, dump_data, reporter=reporter)
    except ImportError:
        _log.warning(
            "casl.query_engine not yet implemented.  "
            "Returning empty result set."
        )
    except Exception as exc:
        _log.error("Query execution failed: %s", exc)
        return EXIT_INFRA

    # --- Output results ----------------------------------------------------
    out = _open_output(args.output)
    try:
        if args.format == "json":
            serializable = [
                r.to_dict() if hasattr(r, "to_dict") else str(r)
                for r in results
            ]
            out.write(json.dumps(serializable, indent=2) + "\n")
        else:
            for r in results:
                out.write(str(r) + "\n")
            out.write(f"\n--- {len(results)} result(s) ---\n")
    finally:
        if out is not sys.stdout:
            out.close()

    diagnostics = reporter.diagnostics if hasattr(reporter, "diagnostics") else []
    error_count = sum(
        1 for d in diagnostics if str(getattr(d, "severity", "")).lower() == "error"
    )
    return EXIT_ERROR if error_count > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# compile
# ---------------------------------------------------------------------------

def cmd_compile(args: argparse.Namespace) -> int:
    """Compile a ``.casl`` specification to CASL IR bytecode (``.caslo``).

    The compiled artefact can later be fed to ``casl interpret`` or
    ``casl explore`` without re-parsing / re-type-checking.
    """
    errors = _import_errors()

    spec_path = _resolve_path(args.spec_file, "CASL spec")
    out_path = args.output or str(spec_path.with_suffix(".caslo"))

    _log.info("Compiling %s → %s", spec_path, out_path)

    reporter = errors.ErrorReporter()

    try:
        # Future pipeline: parse → typecheck → lower → serialise
        from casl import parser as casl_parser  # type: ignore[import-untyped]
        from casl import compiler as casl_compiler  # type: ignore[import-untyped]

        source = spec_path.read_text(encoding="utf-8")
        ast = casl_parser.parse(source, filename=str(spec_path), reporter=reporter)

        if reporter.error_count > 0:
            _log.error("Parse errors; aborting compilation.")
            _emit_diagnostics(
                reporter.diagnostics, args.format, sys.stderr
            )
            return EXIT_ERROR

        ir = casl_compiler.compile(ast, reporter=reporter)

        if reporter.error_count > 0:
            _log.error("Compilation errors; aborting.")
            _emit_diagnostics(
                reporter.diagnostics, args.format, sys.stderr
            )
            return EXIT_ERROR

        # Serialise the IR to disk.
        casl_compiler.serialize(ir, out_path)
        _log.info("Wrote compiled output to %s", out_path)

    except ImportError:
        _log.warning(
            "casl.parser / casl.compiler not yet implemented.  "
            "Creating placeholder output."
        )
        Path(out_path).write_text(
            f"# CASL compiled stub for {spec_path.name}\n", encoding="utf-8"
        )
    except Exception as exc:
        _log.error("Compilation failed: %s", exc)
        return EXIT_INFRA

    return EXIT_OK


# ---------------------------------------------------------------------------
# interpret
# ---------------------------------------------------------------------------

def cmd_interpret(args: argparse.Namespace) -> int:
    """Execute compiled CASL bytecode on a single (default) path.

    Uses ``AbstractVM.interpret()`` — deterministic, single-path execution.
    """
    runtime = _import_runtime()
    cppcheckdata = _import_cppcheckdata()
    errors = _import_errors()

    program_path = _resolve_path(args.program, "CASL bytecode")
    dump_path = _resolve_path(args.dump, "dump file") if args.dump else None

    config_kwargs: Dict[str, Any] = {}
    if args.max_iterations is not None:
        config_kwargs["max_iterations"] = args.max_iterations
    config = runtime.RuntimeConfig(**config_kwargs) if config_kwargs else runtime.RuntimeConfig()

    casl_rt = runtime.CaslRuntime(config=config)
    reporter = errors.ErrorReporter()

    dump_data = None
    if dump_path:
        try:
            dump_data = cppcheckdata.parsedump(str(dump_path))
        except Exception as exc:
            _log.error("Failed to parse dump: %s", exc)
            return EXIT_INFRA

    try:
        program = casl_rt.load_bytecode(program_path)
    except AttributeError:
        _log.warning("CaslRuntime.load_bytecode() not yet implemented.")
        program = None
    except Exception as exc:
        _log.error("Failed to load bytecode: %s", exc)
        return EXIT_INFRA

    if program is None:
        _log.error("No loadable program; aborting interpret.")
        return EXIT_INFRA

    t0 = time.monotonic()
    try:
        result = casl_rt.interpret(program, dump_data, reporter=reporter)
    except Exception as exc:
        _log.error("Interpretation failed: %s", exc)
        return EXIT_INFRA
    elapsed = time.monotonic() - t0
    _log.info("Interpretation completed in %.3fs", elapsed)

    diagnostics = reporter.diagnostics if hasattr(reporter, "diagnostics") else []
    out = _open_output(args.output)
    try:
        error_count = _emit_diagnostics(diagnostics, args.format, out)
    finally:
        if out is not sys.stdout:
            out.close()

    return EXIT_ERROR if error_count > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# explore
# ---------------------------------------------------------------------------

def cmd_explore(args: argparse.Namespace) -> int:
    """Explore all execution paths (bounded model checking).

    Uses ``AbstractVM.explore()`` — BFS/DFS over all reachable states up
    to the configured exploration bound, combined with
    ``SafetyChecker`` property monitoring.
    """
    runtime = _import_runtime()
    cppcheckdata = _import_cppcheckdata()
    errors = _import_errors()

    program_path = _resolve_path(args.program, "CASL bytecode")
    dump_path = _resolve_path(args.dump, "dump file") if args.dump else None

    config_kwargs: Dict[str, Any] = {}
    if args.bound is not None:
        config_kwargs["exploration_bound"] = args.bound
    if args.widen_delay is not None:
        config_kwargs["widen_delay"] = args.widen_delay
    config = runtime.RuntimeConfig(**config_kwargs) if config_kwargs else runtime.RuntimeConfig()

    casl_rt = runtime.CaslRuntime(config=config)
    reporter = errors.ErrorReporter()

    dump_data = None
    if dump_path:
        try:
            dump_data = cppcheckdata.parsedump(str(dump_path))
        except Exception as exc:
            _log.error("Failed to parse dump: %s", exc)
            return EXIT_INFRA

    try:
        program = casl_rt.load_bytecode(program_path)
    except AttributeError:
        _log.warning("CaslRuntime.load_bytecode() not yet implemented.")
        program = None
    except Exception as exc:
        _log.error("Failed to load bytecode: %s", exc)
        return EXIT_INFRA

    if program is None:
        _log.error("No loadable program; aborting exploration.")
        return EXIT_INFRA

    t0 = time.monotonic()
    try:
        result = casl_rt.explore(program, dump_data, reporter=reporter)
    except Exception as exc:
        _log.error("Exploration failed: %s", exc)
        return EXIT_INFRA
    elapsed = time.monotonic() - t0
    _log.info("Exploration completed in %.3fs", elapsed)

    # --- Counterexample output --------------------------------------------
    counterexamples = []
    if result is not None and hasattr(result, "counterexamples"):
        counterexamples = result.counterexamples or []

    if counterexamples and args.trace:
        trace_out = _open_output(args.trace)
        try:
            for idx, cex in enumerate(counterexamples):
                trace_out.write(f"=== Counterexample {idx + 1} ===\n")
                if hasattr(cex, "to_dict"):
                    trace_out.write(json.dumps(cex.to_dict(), indent=2) + "\n")
                else:
                    trace_out.write(str(cex) + "\n")
        finally:
            if trace_out is not sys.stdout:
                trace_out.close()

    # --- Diagnostics -------------------------------------------------------
    diagnostics = reporter.diagnostics if hasattr(reporter, "diagnostics") else []
    out = _open_output(args.output)
    try:
        error_count = _emit_diagnostics(diagnostics, args.format, out)
    finally:
        if out is not sys.stdout:
            out.close()

    if counterexamples:
        _log.info("Found %d counterexample(s).", len(counterexamples))
        return EXIT_VIOLATION

    return EXIT_ERROR if error_count > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# parse (debugging / AST dump)
# ---------------------------------------------------------------------------

def cmd_parse(args: argparse.Namespace) -> int:
    """Parse a CASL or CSQL source file and pretty-print its AST.

    Useful for debugging the front-end without running any analysis.
    """
    errors = _import_errors()

    src_path = _resolve_path(args.source_file, "source file")
    reporter = errors.ErrorReporter()

    source = src_path.read_text(encoding="utf-8")

    try:
        from casl import parser as casl_parser  # type: ignore[import-untyped]
        ast = casl_parser.parse(source, filename=str(src_path), reporter=reporter)
    except ImportError:
        _log.warning("casl.parser not yet implemented; echoing raw source.")
        ast = None
    except Exception as exc:
        _log.error("Parse error: %s", exc)
        return EXIT_ERROR

    out = _open_output(args.output)
    try:
        if ast is None:
            out.write(source)
        elif args.format == "sexp" and hasattr(ast, "to_sexp"):
            out.write(ast.to_sexp() + "\n")
        elif args.format == "json" and hasattr(ast, "to_dict"):
            out.write(json.dumps(ast.to_dict(), indent=2) + "\n")
        else:
            # Fallback: repr / str
            out.write(repr(ast) + "\n")
    finally:
        if out is not sys.stdout:
            out.close()

    diagnostics = reporter.diagnostics if hasattr(reporter, "diagnostics") else []
    if diagnostics:
        _emit_diagnostics(diagnostics, "gcc", sys.stderr)

    error_count = sum(
        1 for d in diagnostics if str(getattr(d, "severity", "")).lower() == "error"
    )
    return EXIT_ERROR if error_count > 0 else EXIT_OK


# ---------------------------------------------------------------------------
# domains (list / inspect abstract domains)
# ---------------------------------------------------------------------------

def cmd_domains(args: argparse.Namespace) -> int:
    """List or inspect the available abstract domains."""
    runtime = _import_runtime()

    registry = runtime.DomainRegistry()

    if args.list:
        # DomainRegistry is expected to expose iteration or a names() method.
        if hasattr(registry, "names"):
            names = registry.names()
        elif hasattr(registry, "__iter__"):
            names = [str(d) for d in registry]
        else:
            # Fallback: report the two built-in domains we know exist.
            names = ["IntervalDomain", "BoolDomain"]

        out = _open_output(args.output)
        try:
            for name in sorted(names):
                out.write(f"  {name}\n")
            out.write(f"\n{len(names)} domain(s) available.\n")
        finally:
            if out is not sys.stdout:
                out.close()
        return EXIT_OK

    if args.describe:
        domain_name = args.describe
        out = _open_output(args.output)
        try:
            if hasattr(registry, "get"):
                dom = registry.get(domain_name)
                if dom is None:
                    _log.error("Unknown domain: %s", domain_name)
                    return EXIT_ERROR
                doc = getattr(dom, "__doc__", None) or "(no description)"
                out.write(f"{domain_name}:\n{textwrap.indent(doc, '  ')}\n")
            else:
                out.write(f"{domain_name}: (domain registry has no get())\n")
        finally:
            if out is not sys.stdout:
                out.close()
        return EXIT_OK

    _log.error("Specify --list or --describe <domain>.")
    return EXIT_INFRA


# ===========================================================================
# Argument parser construction
# ===========================================================================

def _build_parser() -> argparse.ArgumentParser:
    """Construct the full CLI argument parser with subcommands."""

    # --- Top-level parser --------------------------------------------------
    parser = argparse.ArgumentParser(
        prog="casl",
        description=(
            "CASL — Cppcheck Abstract Specification Language tool-suite.\n\n"
            "Provides abstract interpretation, property verification, and\n"
            "query-based program analysis on cppcheck dump files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              casl analyze project.c.dump --spec rules.casl
              casl query   project.c.dump --expr 'find uninitVar()'
              casl compile rules.casl -o rules.caslo
              casl explore rules.caslo --dump project.c.dump --bound 1000
        """),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v info, -vv debug).",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        metavar="<command>",
    )

    # Shared argument groups (reusable) ------------------------------------

    def _add_output_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "-o", "--output",
            default=None,
            metavar="FILE",
            help='Output file ("-" or omit for stdout).',
        )
        p.add_argument(
            "-f", "--format",
            choices=["json", "gcc", "summary", "sexp"],
            default="gcc",
            help="Output format (default: gcc).",
        )

    def _add_runtime_args(p: argparse.ArgumentParser) -> None:
        g = p.add_argument_group("runtime tuning")
        g.add_argument(
            "--max-iterations",
            type=int,
            default=None,
            metavar="N",
            help="Maximum fixpoint iterations (default: from RuntimeConfig).",
        )
        g.add_argument(
            "--widen-delay",
            type=int,
            default=None,
            metavar="N",
            help="Iterations before widening kicks in (default: 3).",
        )

    # --- analyze -----------------------------------------------------------
    p_analyze = subparsers.add_parser(
        "analyze",
        aliases=["analyse"],
        help="Run CASL analysis on a cppcheck dump file.",
        description=(
            "Parse a .dump file, optionally load a CASL specification, "
            "and perform abstract-interpretation-based analysis."
        ),
    )
    p_analyze.add_argument(
        "dump_file",
        metavar="DUMP",
        help="Path to the cppcheck .dump file.",
    )
    p_analyze.add_argument(
        "-s", "--spec",
        metavar="FILE",
        default=None,
        help="CASL specification file (.casl).",
    )
    p_analyze.add_argument(
        "--domains",
        nargs="*",
        metavar="DOM",
        help="Abstract domains to enable (e.g. IntervalDomain BoolDomain).",
    )
    p_analyze.add_argument(
        "--exploration-bound",
        type=int,
        default=None,
        metavar="N",
        help="Max states for bounded exploration.",
    )
    _add_output_args(p_analyze)
    _add_runtime_args(p_analyze)
    p_analyze.set_defaults(func=cmd_analyze)

    # --- query -------------------------------------------------------------
    p_query = subparsers.add_parser(
        "query",
        help="Execute a CSQL query against a dump file.",
        description=(
            "Run a CSQL (Cppcheck Specification Query Language) query "
            "and print matching results."
        ),
    )
    p_query.add_argument(
        "dump_file",
        metavar="DUMP",
        help="Path to the cppcheck .dump file.",
    )
    p_query.add_argument(
        "-q", "--query",
        metavar="FILE",
        default=None,
        help="CSQL query file (.csql).",
    )
    p_query.add_argument(
        "-e", "--expr",
        metavar="EXPR",
        default=None,
        help="Inline CSQL expression (alternative to --query).",
    )
    _add_output_args(p_query)
    p_query.set_defaults(func=cmd_query)

    # --- compile -----------------------------------------------------------
    p_compile = subparsers.add_parser(
        "compile",
        help="Compile a CASL specification to bytecode.",
        description=(
            "Parse, type-check, and lower a .casl file to CASL IR "
            "bytecode (.caslo)."
        ),
    )
    p_compile.add_argument(
        "spec_file",
        metavar="SPEC",
        help="CASL source file (.casl).",
    )
    p_compile.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help="Output path (default: <spec>.caslo).",
    )
    p_compile.add_argument(
        "-f", "--format",
        choices=["json", "gcc", "summary"],
        default="gcc",
        help="Diagnostic format (default: gcc).",
    )
    p_compile.set_defaults(func=cmd_compile)

    # --- interpret ---------------------------------------------------------
    p_interpret = subparsers.add_parser(
        "interpret",
        help="Execute compiled CASL bytecode (single-path).",
        description=(
            "Load a .caslo bytecode file and run it via AbstractVM.interpret() "
            "for deterministic single-path execution."
        ),
    )
    p_interpret.add_argument(
        "program",
        metavar="PROGRAM",
        help="Compiled CASL bytecode file (.caslo).",
    )
    p_interpret.add_argument(
        "-d", "--dump",
        metavar="DUMP",
        default=None,
        help="Optional .dump file to analyse.",
    )
    _add_output_args(p_interpret)
    _add_runtime_args(p_interpret)
    p_interpret.set_defaults(func=cmd_interpret)

    # --- explore -----------------------------------------------------------
    p_explore = subparsers.add_parser(
        "explore",
        help="Explore all paths (bounded model checking).",
        description=(
            "Load a .caslo bytecode file and run AbstractVM.explore() with "
            "BFS over all reachable states, combined with SafetyChecker "
            "property monitoring."
        ),
    )
    p_explore.add_argument(
        "program",
        metavar="PROGRAM",
        help="Compiled CASL bytecode file (.caslo).",
    )
    p_explore.add_argument(
        "-d", "--dump",
        metavar="DUMP",
        default=None,
        help="Optional .dump file to analyse.",
    )
    p_explore.add_argument(
        "-b", "--bound",
        type=int,
        default=None,
        metavar="N",
        help="Exploration bound (max states to visit).",
    )
    p_explore.add_argument(
        "--trace",
        metavar="FILE",
        default=None,
        help="Write counterexample traces to this file.",
    )
    _add_output_args(p_explore)
    _add_runtime_args(p_explore)
    p_explore.set_defaults(func=cmd_explore)

    # --- parse -------------------------------------------------------------
    p_parse = subparsers.add_parser(
        "parse",
        help="Parse a CASL/CSQL file and dump the AST.",
        description=(
            "Parse a .casl or .csql source file and pretty-print its "
            "abstract syntax tree. Useful for front-end debugging."
        ),
    )
    p_parse.add_argument(
        "source_file",
        metavar="SOURCE",
        help="CASL or CSQL source file.",
    )
    p_parse.add_argument(
        "-f", "--format",
        choices=["sexp", "json", "repr"],
        default="sexp",
        help="AST output format (default: sexp).",
    )
    p_parse.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help='Output file ("-" or omit for stdout).',
    )
    p_parse.set_defaults(func=cmd_parse)

    # --- domains -----------------------------------------------------------
    p_domains = subparsers.add_parser(
        "domains",
        help="List or inspect available abstract domains.",
        description="Query the DomainRegistry for available abstract domains.",
    )
    p_domains.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all registered domain names.",
    )
    p_domains.add_argument(
        "--describe",
        metavar="DOMAIN",
        default=None,
        help="Show documentation for a specific domain.",
    )
    p_domains.add_argument(
        "-o", "--output",
        default=None,
        metavar="FILE",
        help='Output file ("-" or omit for stdout).',
    )
    p_domains.set_defaults(func=cmd_domains)

    return parser


# ===========================================================================
# Main entry point
# ===========================================================================

def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the CASL CLI.

    Parameters
    ----------
    argv:
        Command-line arguments.  ``None`` → ``sys.argv[1:]``.

    Returns
    -------
    int
        Exit code (see module docstring for semantics).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Configure logging based on verbosity level.
    _configure_logging(args.verbose)

    # No subcommand given → print help.
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        return EXIT_INFRA

    try:
        return args.func(args)
    except KeyboardInterrupt:
        _log.info("Interrupted by user.")
        return 130  # Standard UNIX convention for SIGINT
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_INFRA
    except Exception as exc:
        _log.error("Unhandled exception: %s", exc, exc_info=True)
        return EXIT_INFRA


# ---------------------------------------------------------------------------
# Module execution support
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())
