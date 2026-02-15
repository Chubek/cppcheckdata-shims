# =============================================================================
#  docs/conf.py — Sphinx Configuration for cppcheckdata-shims & CASL
#
#  This configuration:
#    1. Auto-extracts all docstrings from cppcheckdata_shims/ and casl/
#    2. Generates HTML, LaTeX/PDF, EPUB, and man pages
#    3. Integrates Doxygen output via Breathe (optional)
#    4. Strips raw docstrings and renders them as structured documentation
# =============================================================================

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# -- Path setup ---------------------------------------------------------------
# Add the project root to sys.path so that autodoc can import the packages.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# -- Project information ------------------------------------------------------
project = "cppcheckdata-shims"
author = "cppcheckdata-shims contributors"
copyright = f"2024–{datetime.now().year}, {author}"

# Read version from pyproject.toml
_version = "0.1.0"
try:
    import re
    _pyproject = PROJECT_ROOT / "pyproject.toml"
    if _pyproject.exists():
        _match = re.search(
            r'^version\s*=\s*"([^"]+)"',
            _pyproject.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if _match:
            _version = _match.group(1)
except Exception:
    pass

version = _version  # Short X.Y version
release = _version  # Full version including alpha/beta/rc tags

# -- General configuration ----------------------------------------------------
extensions = [
    # ── Core Sphinx extensions ──
    "sphinx.ext.autodoc",           # Extract docstrings from Python modules
    "sphinx.ext.autosummary",       # Generate summary tables
    "sphinx.ext.viewcode",          # Add [source] links to docs
    "sphinx.ext.intersphinx",       # Cross-reference external projects
    "sphinx.ext.napoleon",          # Google/NumPy docstring support
    "sphinx.ext.todo",              # TODO directives
    "sphinx.ext.coverage",          # Docstring coverage report
    "sphinx.ext.inheritance_diagram",  # Class hierarchy diagrams
    "sphinx.ext.graphviz",          # Graphviz diagrams

    # ── Third-party extensions ──
    "sphinx_autodoc_typehints",     # Render type hints in docs
    "sphinx_rtd_theme",             # ReadTheDocs theme
    "sphinx_copybutton",            # Copy button on code blocks
    "sphinx_design",                # Tabs, cards, grids
    "myst_parser",                  # Markdown support (.md files)

    # ── Doxygen integration (optional) ──
    # Uncomment if you run Doxygen first and want to pull in its output:
    # "breathe",
]

# -- Source file settings -----------------------------------------------------
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}
master_doc = "index"
exclude_patterns = [
    "_build",
    "Thumbs.db",
    ".DS_Store",
    "doxygen",
]
templates_path = ["_templates"]

# -- Autodoc configuration ----------------------------------------------------
# This is the key section: it controls how docstrings are extracted.

autodoc_default_options = {
    "members": True,                 # Document all members
    "undoc-members": True,           # Include members without docstrings
    "private-members": False,        # Skip _private members
    "special-members": "__init__",   # Include __init__ docstrings
    "inherited-members": False,      # Don't repeat inherited members
    "show-inheritance": True,        # Show base classes
    "member-order": "bysource",      # Preserve source order
}

autodoc_typehints = "both"           # Show types in signature AND description
autodoc_typehints_format = "short"   # Use short type names (not fully qualified)
autodoc_class_content = "both"       # Show class AND __init__ docstrings
autodoc_mock_imports = [
    "cppcheckdata",                  # May not be installed in doc build env
]

# Strip module-level docstring boilerplate
autodoc_docstring_signature = True

# -- Autosummary ---------------------------------------------------------------
autosummary_generate = True          # Auto-generate stub pages
autosummary_imported_members = False

# -- Napoleon (Google/NumPy docstrings) ----------------------------------------
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_attr_annotations = True

# -- Intersphinx (cross-reference Python stdlib, etc.) -------------------------
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- TODO extension ------------------------------------------------------------
todo_include_todos = True

# -- Coverage extension --------------------------------------------------------
coverage_show_missing_items = True

# -- Breathe (Doxygen integration) --------------------------------------------
# Uncomment and configure if using Doxygen:
# breathe_projects = {
#     "cppcheckdata-shims": str(PROJECT_ROOT / "docs" / "doxygen" / "xml"),
# }
# breathe_default_project = "cppcheckdata-shims"

# -- HTML output ---------------------------------------------------------------
html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": False,
    "display_version": True,
    "prev_next_buttons_location": "bottom",
    "style_external_links": True,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
}
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_show_sourcelink = True
html_show_sphinx = False
html_show_copyright = True

# -- LaTeX / PDF output --------------------------------------------------------
latex_engine = "xelatex"  # Better Unicode support than pdflatex

latex_elements = {
    "papersize": "a4paper",
    "pointsize": "11pt",
    "preamble": r"""
\usepackage{fontspec}
\usepackage{unicode-math}
\setmainfont{Latin Modern Roman}
\setsansfont{Latin Modern Sans}
\setmonofont{Latin Modern Mono}
\usepackage{enumitem}
\setlistdepth{9}
\usepackage{fancyhdr}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\leftmark}
\fancyhead[R]{\thepage}
\renewcommand{\headrulewidth}{0.4pt}
""",
    "figure_align": "htbp",
    "extraclassoptions": "openany,oneside",
    # Table of contents depth
    "tocdepth": 3,
    # Syntax highlighting style
    "sphinxsetup": (
        "verbatimwithframe=true, "
        "VerbatimColor={rgb}{0.97,0.97,0.97}, "
        "TitleColor={rgb}{0.1,0.1,0.4}"
    ),
}

latex_documents = [
    (
        master_doc,                              # source start file
        "cppcheckdata-shims.tex",                # target filename
        "cppcheckdata-shims Documentation",      # title
        author,                                  # author
        "manual",                                # documentclass
    ),
]

latex_show_urls = "footnote"
latex_show_pagerefs = True

# -- EPUB output ---------------------------------------------------------------
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright
epub_show_urls = "footnote"

# -- Man page output -----------------------------------------------------------
man_pages = [
    (
        "index",
        "cppcheckdata-shims",
        "cppcheckdata-shims Documentation",
        [author],
        1,
    ),
    (
        "api/casl",
        "casl",
        "CASL — Cppcheck Addon Specification Language",
        [author],
        1,
    ),
]

# -- Graphviz ------------------------------------------------------------------
graphviz_output_format = "svg"
inheritance_graph_attrs = {
    "rankdir": "TB",
    "fontsize": 10,
    "ratio": "compress",
}
