#!/usr/bin/env python3
"""
setup.py — Legacy / editable-install support for cppcheckdata-shims.

All canonical metadata lives in pyproject.toml (PEP 621).
This file exists solely to support:
  • pip install -e .       (editable installs)
  • python setup.py test   (legacy test runner fallback)
  • Environments where PEP 517 build isolation is unavailable

For normal installs, `pip install .` reads pyproject.toml directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

from setuptools import setup, find_packages

# ---------------------------------------------------------------------------
# Metadata that mirrors pyproject.toml (kept in sync manually)
# ---------------------------------------------------------------------------

HERE = Path(__file__).parent.resolve()

# Read the long description from README.md
long_description = ""
readme_path = HERE / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

# Read version from the package __init__.py to keep a single source of truth
VERSION = "0.1.0"
init_path = HERE / "cppcheckdata_shims" / "__init__.py"
if init_path.exists():
    for line in init_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            # __version__ = "0.1.0"
            VERSION = line.split("=", 1)[1].strip().strip("\"'")
            break

# ---------------------------------------------------------------------------
# Dependency lists
# ---------------------------------------------------------------------------

INSTALL_REQUIRES = [
    "parsimonious>=0.10.0",
    "sexpdata>=1.0.0",
]

EXTRAS_REQUIRE = {
    "test": [
        "pytest>=8.0",
        "pytest-cov>=5.0",
        "pytest-timeout>=2.3",
        "hypothesis>=6.100",
    ],
    "docs": [
        "sphinx>=7.0",
        "sphinx-rtd-theme>=2.0",
        "myst-parser>=3.0",
    ],
    "viz": [
        "graphviz>=0.20",
        "pygraphviz>=1.12",
    ],
}

# Composite extras
EXTRAS_REQUIRE["dev"] = (
    EXTRAS_REQUIRE["test"]
    + EXTRAS_REQUIRE["docs"]
    + EXTRAS_REQUIRE["viz"]
    + [
        "ruff>=0.4",
        "mypy>=1.10",
        "pre-commit>=3.7",
    ]
)
EXTRAS_REQUIRE["all"] = EXTRAS_REQUIRE["dev"]

# ---------------------------------------------------------------------------
# Package discovery
# ---------------------------------------------------------------------------

PACKAGES = find_packages(
    where=".",
    include=[
        "cppcheckdata_shims",
        "cppcheckdata_shims.*",
        "dsl",
        "dsl.*",
        "deps",
        "deps.*",
        "scripts",
        "scripts.*",
    ],
    exclude=[
        "tests",
        "tests.*",
        "env",
        "env.*",
        "examples",
        "examples.*",
    ],
)

# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

ENTRY_POINTS = {
    "console_scripts": [
        "ccs-qscore=cppcheckdata_shims.qscore:main",
        "ccs-dump2dot=scripts.dump2dot:main",
        "ccs-dump2sexp=scripts.dump2sexp:main",
    ],
    "cppcheckdata_shims.dsl": [
        "casl=dsl.casl:CASLEngine",
        "ccpl=dsl.ccpl:CCPLEngine",
        "ccql=dsl.ccql:CCQLEngine",
    ],
}

# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------

CLASSIFIERS = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: MIT License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Software Development :: Quality Assurance",
    "Topic :: Software Development :: Testing",
    "Topic :: Software Development :: Libraries :: Python Modules",
    "Typing :: Typed",
]

# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

setup(
    name="cppcheckdata-shims",
    version=VERSION,
    description=(
        "Semantic middle layer that lifts cppcheck dump IR into full "
        "static-analysis infrastructure: CFGs, dataflow engines, abstract "
        "interpretation, constraint solving, symbolic execution, call graphs, "
        "memory abstraction, quality scoring, and three DSLs "
        "(CASL / CCPL / CCQL)."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="cppcheckdata-shims contributors",
    license="MIT",
    url="https://github.com/cppcheckdata-shims/cppcheckdata-shims",
    project_urls={
        "Homepage": "https://github.com/cppcheckdata-shims/cppcheckdata-shims",
        "Repository": "https://github.com/cppcheckdata-shims/cppcheckdata-shims",
        "Issues": "https://github.com/cppcheckdata-shims/cppcheckdata-shims/issues",
        "Documentation": "https://cppcheckdata-shims.readthedocs.io/",
    },
    packages=PACKAGES,
    package_data={
        "dsl": ["*.peg", "*.grammar", "*.schema"],
        "cppcheckdata_shims": ["py.typed"],
    },
    python_requires=">=3.10",
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    entry_points=ENTRY_POINTS,
    classifiers=CLASSIFIERS,
    keywords=[
        "cppcheck",
        "static-analysis",
        "abstract-interpretation",
        "dataflow",
        "cfg",
        "control-flow-graph",
        "symbolic-execution",
        "quality-score",
        "program-analysis",
    ],
    zip_safe=False,
)
