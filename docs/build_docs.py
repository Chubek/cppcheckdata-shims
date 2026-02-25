#!/usr/bin/env python3
"""
docs/build_docs.py
==================

Batch documentation builder for cppcheckdata_shims.

Scans the cppcheckdata_shims directory and generates documentation
for all Python modules.

Usage:
    python build_docs.py [--output-dir api] [--format md] [--clean]

Example:
    python build_docs.py --output-dir api --format md --index
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Import from the extraction module
from extract_docs import extract_module_docs, format_docs, ModuleDoc


# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Default paths (relative to this script's location)
DEFAULT_SOURCE_DIR = "../cppcheckdata_shims"
DEFAULT_OUTPUT_DIR = "api"

# Files to exclude from documentation
EXCLUDED_FILES = {
    "__init__.py",
    "__pycache__",
    "*.pyc",
}

# Module categories for organization
MODULE_CATEGORIES = {
    "Core Analysis": [
        "abstract_domains",
        "abstract_interp",
        "dataflow_analysis",
        "dataflow_engine",
    ],
    "Control Flow": [
        "ctrlflow_analysis",
        "ctrlflow_graph",
    ],
    "Program Graphs": [
        "callgraph",
        "dependency_graph",
    ],
    "Specialized Analyses": [
        "taint_analysis",
        "symbolic_exec",
        "memory_abstraction",
        "type_analysis",
        "constraint_engine",
    ],
    "Utilities": [
        "ast_helper",
        "checkers",
        "plus_reporter",
        "qscore",
    ],
    "Advanced": [
        "interproc_analysis",
        "distrib_analysis",
    ],
}


# ═══════════════════════════════════════════════════════════════════════════
#  INDEX GENERATION
# ═══════════════════════════════════════════════════════════════════════════

def generate_index(
    modules: List[ModuleDoc],
    output_dir: Path,
    fmt: str = "md"
) -> str:
    """Generate an index file for all documented modules."""
    
    if fmt == "md":
        return _generate_markdown_index(modules, output_dir)
    elif fmt == "rst":
        return _generate_rst_index(modules, output_dir)
    else:
        raise ValueError(f"Index generation not supported for format: {fmt}")


def _generate_markdown_index(modules: List[ModuleDoc], output_dir: Path) -> str:
    """Generate a Markdown index."""
    lines = [
        "# cppcheckdata_shims API Reference",
        "",
        f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        "",
        "## Overview",
        "",
        "This documentation covers the `cppcheckdata_shims` library, which provides",
        "abstract domains, dataflow analysis engines, and static analysis utilities",
        "for building custom C/C++ checkers on top of Cppcheck.",
        "",
        "## Module Index",
        "",
    ]
    
    # Organize modules by category
    module_map = {m.name: m for m in modules}
    documented_modules = set()
    
    for category, module_names in MODULE_CATEGORIES.items():
        category_modules = []
        for name in module_names:
            if name in module_map:
                category_modules.append(module_map[name])
                documented_modules.add(name)
        
        if category_modules:
            lines.append(f"### {category}")
            lines.append("")
            lines.append("| Module | Description |")
            lines.append("|--------|-------------|")
            
            for mod in category_modules:
                # Extract first line of docstring as description
                desc = "No description"
                if mod.docstring:
                    first_line = mod.docstring.split("\n")[0].strip()
                    # Skip the module path line if present
                    if first_line.startswith("cppcheckdata_shims/"):
                        lines_list = mod.docstring.split("\n")
                        for line in lines_list[1:]:
                            if line.strip() and not line.startswith("="):
                                desc = line.strip()[:60]
                                break
                    else:
                        desc = first_line[:60]
                    if len(desc) >= 60:
                        desc += "..."
                
                lines.append(f"| [`{mod.name}`]({mod.name}.md) | {desc} |")
            
            lines.append("")
    
    # Add any uncategorized modules
    uncategorized = [m for m in modules if m.name not in documented_modules]
    if uncategorized:
        lines.append("### Other Modules")
        lines.append("")
        lines.append("| Module | Description |")
        lines.append("|--------|-------------|")
        for mod in uncategorized:
            desc = "No description"
            if mod.docstring:
                desc = mod.docstring.split("\n")[0].strip()[:60]
            lines.append(f"| [`{mod.name}`]({mod.name}.md) | {desc} |")
        lines.append("")
    
    # Quick reference
    lines.extend([
        "## Quick Reference",
        "",
        "### Key Classes",
        "",
        "| Class | Module | Purpose |",
        "|-------|--------|---------|",
    ])
    
    key_classes = [
        ("AbstractDomain", "abstract_domains", "Protocol for all abstract domains"),
        ("IntervalDomain", "abstract_domains", "Numerical interval analysis"),
        ("SignDomain", "abstract_domains", "Sign analysis (+/0/-)"),
        ("TaintLattice", "taint_analysis", "Taint tracking"),
        ("CFG", "ctrlflow_graph", "Control flow graph representation"),
        ("CallGraph", "callgraph", "Interprocedural call graph"),
    ]
    
    for cls_name, mod_name, purpose in key_classes:
        if mod_name in module_map:
            lines.append(f"| `{cls_name}` | [`{mod_name}`]({mod_name}.md) | {purpose} |")
    
    lines.append("")
    
    # See also
    lines.extend([
        "## See Also",
        "",
        "- [SHIMS_VADE_MECUM.md](SHIMS_VADE_MECUM.md) - User guide and tutorials",
        "- [Architecture](internals/architecture.rst) - Internal design documentation",
        "",
    ])
    
    return "\n".join(lines)


def _generate_rst_index(modules: List[ModuleDoc], output_dir: Path) -> str:
    """Generate an RST index."""
    lines = [
        "cppcheckdata_shims API Reference",
        "=================================",
        "",
        ".. toctree::",
        "   :maxdepth: 2",
        "   :caption: Modules:",
        "",
    ]
    
    for mod in sorted(modules, key=lambda m: m.name):
        lines.append(f"   {mod.name}")
    
    lines.append("")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN BUILD LOGIC
# ═══════════════════════════════════════════════════════════════════════════

def find_modules(source_dir: Path) -> List[Path]:
    """Find all Python modules in the source directory."""
    modules = []
    
    for path in source_dir.glob("*.py"):
        if path.name not in EXCLUDED_FILES and not path.name.startswith("_"):
            modules.append(path)
    
    return sorted(modules)


def build_docs(
    source_dir: Path,
    output_dir: Path,
    fmt: str = "md",
    clean: bool = False,
    generate_index_file: bool = True,
    verbose: bool = True,
) -> int:
    """
    Build documentation for all modules.
    
    Returns the number of modules processed.
    """
    # Clean output directory if requested
    if clean and output_dir.exists():
        if verbose:
            print(f"Cleaning output directory: {output_dir}")
        shutil.rmtree(output_dir)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find all modules
    module_paths = find_modules(source_dir)
    
    if verbose:
        print(f"Found {len(module_paths)} modules in {source_dir}")
    
    # Process each module
    processed_modules: List[ModuleDoc] = []
    errors: List[str] = []
    
    for module_path in module_paths:
        try:
            if verbose:
                print(f"  Processing: {module_path.name}")
            
            # Extract documentation
            module_doc = extract_module_docs(str(module_path))
            processed_modules.append(module_doc)
            
            # Format and write
            extension = "md" if fmt in ("md", "markdown") else fmt
            output_file = output_dir / f"{module_doc.name}.{extension}"
            
            formatted = format_docs(module_doc, fmt)
            output_file.write_text(formatted, encoding="utf-8")
            
            if verbose:
                print(f"    -> {output_file}")
        
        except Exception as e:
            error_msg = f"Error processing {module_path}: {e}"
            errors.append(error_msg)
            if verbose:
                print(f"    ERROR: {e}", file=sys.stderr)
    
    # Generate index
    if generate_index_file and processed_modules:
        try:
            index_content = generate_index(processed_modules, output_dir, fmt)
            extension = "md" if fmt in ("md", "markdown") else fmt
            index_file = output_dir / f"index.{extension}"
            index_file.write_text(index_content, encoding="utf-8")
            
            if verbose:
                print(f"\nGenerated index: {index_file}")
        except Exception as e:
            errors.append(f"Error generating index: {e}")
            if verbose:
                print(f"ERROR generating index: {e}", file=sys.stderr)
    
    # Summary
    if verbose:
        print(f"\n{'='*50}")
        print(f"Documentation build complete!")
        print(f"  Modules processed: {len(processed_modules)}")
        print(f"  Errors: {len(errors)}")
        print(f"  Output directory: {output_dir}")
    
    if errors:
        print("\nErrors encountered:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
    
    return len(processed_modules)


def main():
    parser = argparse.ArgumentParser(
        description="Build documentation for cppcheckdata_shims modules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--source-dir", "-s",
        default=DEFAULT_SOURCE_DIR,
        help=f"Source directory containing Python modules (default: {DEFAULT_SOURCE_DIR})",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for documentation (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["md", "markdown", "rst", "json"],
        default="md",
        help="Output format (default: md)",
    )
    parser.add_argument(
        "--clean", "-c",
        action="store_true",
        help="Clean output directory before building",
    )
    parser.add_argument(
        "--no-index",
        action="store_true",
        help="Don't generate index file",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    
    args = parser.parse_args()
    
    # Resolve paths relative to script location
    script_dir = Path(__file__).parent
    source_dir = (script_dir / args.source_dir).resolve()
    output_dir = (script_dir / args.output_dir).resolve()
    
    if not source_dir.exists():
        print(f"Error: Source directory not found: {source_dir}", file=sys.stderr)
        sys.exit(1)
    
    count = build_docs(
        source_dir=source_dir,
        output_dir=output_dir,
        fmt=args.format,
        clean=args.clean,
        generate_index_file=not args.no_index,
        verbose=not args.quiet,
    )
    
    sys.exit(0 if count > 0 else 1)


if __name__ == "__main__":
    main()