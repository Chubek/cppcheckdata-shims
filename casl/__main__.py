# casl/__main__.py
"""
CASL CLI — compile and run CASL addon specifications.

Usage:
    # Compile .casl to .py addon
    python -m casl compile addon.casl -o addon.py

    # Compile and immediately run against a dump file
    python -m casl run addon.casl example.c.dump

    # Check CASL syntax only
    python -m casl check addon.casl

    # Integration with cppcheck:
    cppcheck --addon=addon.py example.c
    # (after compiling addon.casl → addon.py)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def cmd_compile(args):
    """Compile a CASL source file to a Python cppcheck addon."""
    from casl.parser import parse, CASLParseError
    from casl.codegen import generate, CodeGenError

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"Error: {source_path} does not exist", file=sys.stderr)
        sys.exit(1)

    source = source_path.read_text(encoding="utf-8")

    try:
        ast = parse(source, filename=str(source_path))
    except CASLParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        python_code = generate(ast, source_filename=str(source_path))
    except CodeGenError as e:
        print(f"Code generation error: {e}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    if args.output:
        out_path = Path(args.output)
    else:
        out_path = source_path.with_suffix(".py")

    out_path.write_text(python_code, encoding="utf-8")
    print(f"Compiled {source_path} → {out_path}")


def cmd_run(args):
    """Compile and immediately run a CASL addon against a dump file."""
    from casl.parser import parse, CASLParseError
    from casl.codegen import generate, CodeGenError
    import tempfile
    import importlib.util

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"Error: {source_path} does not exist", file=sys.stderr)
        sys.exit(1)

    source = source_path.read_text(encoding="utf-8")

    try:
        ast = parse(source, filename=str(source_path))
    except CASLParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        python_code = generate(ast, source_filename=str(source_path))
    except CodeGenError as e:
        print(f"Code generation error: {e}", file=sys.stderr)
        sys.exit(1)

    # Write to temp file and execute
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(python_code)
        tmp_path = tmp.name

    try:
        # Inject the dump file path into sys.argv
        original_argv = sys.argv[:]
        sys.argv = [tmp_path, args.dumpfile]
        if args.cli:
            sys.argv.append("--cli")

        # Load and execute
        spec = importlib.util.spec_from_file_location("_casl_addon", tmp_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        if hasattr(mod, "main"):
            mod.main()
    finally:
        sys.argv = original_argv
        os.unlink(tmp_path)


def cmd_check(args):
    """Check CASL syntax without generating code."""
    from casl.parser import parse, CASLParseError

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"Error: {source_path} does not exist", file=sys.stderr)
        sys.exit(1)

    source = source_path.read_text(encoding="utf-8")

    try:
        ast = parse(source, filename=str(source_path))
    except CASLParseError as e:
        print(f"Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    # Count declarations
    checkers = [i for i in ast.items if hasattr(i, 'patterns')]
    fns = [i for i in ast.items if hasattr(i, 'body') and hasattr(i, 'params')
           and not hasattr(i, 'patterns')]
    consts = [i for i in ast.items if hasattr(i, 'value') and not hasattr(i, 'mutable')]

    print(f"✓ {source_path} is valid CASL")
    if ast.addon:
        print(f"  Addon: {ast.addon.name}")
    print(f"  Checkers: {len(checkers)}")
    print(f"  Functions: {len(fns)}")
    print(f"  Constants: {len(consts)}")


def main():
    parser = argparse.ArgumentParser(
        prog="casl",
        description="CASL — Cppcheck Addon Specification Language compiler",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # compile
    compile_parser = subparsers.add_parser(
        "compile", help="Compile .casl to .py cppcheck addon"
    )
    compile_parser.add_argument("source", help="CASL source file (.casl)")
    compile_parser.add_argument(
        "-o", "--output", help="Output Python file (default: same name .py)"
    )
    compile_parser.set_defaults(func=cmd_compile)

    # run
    run_parser = subparsers.add_parser(
        "run", help="Compile and run CASL addon against a dump file"
    )
    run_parser.add_argument("source", help="CASL source file (.casl)")
    run_parser.add_argument("dumpfile", help="cppcheck .dump file")
    run_parser.add_argument(
        "--cli", action="store_true", help="JSON protocol output"
    )
    run_parser.set_defaults(func=cmd_run)

    # check
    check_parser = subparsers.add_parser(
        "check", help="Check CASL syntax"
    )
    check_parser.add_argument("source", help="CASL source file (.casl)")
    check_parser.set_defaults(func=cmd_check)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
