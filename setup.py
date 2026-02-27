#!/usr/bin/env python3
# =============================================================================
#  cppcheckdata-shims — setup.py  (legacy compatibility shim)
#
#  All authoritative metadata lives in pyproject.toml.
#  This file exists so that:
#
#    1.  `pip install -e .` works on older pip / setuptools that pre-date
#        PEP 660 editable installs.
#    2.  `python setup.py sdist bdist_wheel` still works for CI scripts
#        that haven't migrated to `python -m build`.
#    3.  `python setup.py test` (deprecated) can fall back to pytest.
#
#  For new tooling, prefer:
#      pip install -e ".[dev]"
#      python -m build
#      python -m pytest
# =============================================================================

from __future__ import annotations

import re
from pathlib import Path

from setuptools import setup, find_packages

# ---------------------------------------------------------------------------
#  Read version from pyproject.toml so we have a single source of truth.
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent


def _read_version() -> str:
    """Extract the version string from pyproject.toml."""
    pyproject = _HERE / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match:
        return match.group(1)
    return "0.0.0"


def _read_long_description() -> str:
    """Read README.md for the long description."""
    readme = _HERE / "README.md"
    if readme.exists():
        return readme.read_text(encoding="utf-8")
    return ""


def _read_requirements() -> list[str]:
    """Read requirements.txt if it exists."""
    req_file = _HERE / "requirements.txt"
    if req_file.exists():
        lines = req_file.read_text(encoding="utf-8").splitlines()
        return [
            ln.strip()
            for ln in lines
            if ln.strip() and not ln.strip().startswith("#")
        ]
    return []


# ---------------------------------------------------------------------------
#  Main setup() call — mirrors pyproject.toml but keeps legacy compat.
#
#  KEY FIX:  Removed  scripts=["bin/casl"]
#
#    That parameter told setuptools to physically copy bin/casl into
#    build/scripts-3.14/ during install.  If the file didn't exist (or
#    the path was wrong), setuptools raised:
#
#        Error: [Errno 2] No such file or directory: 'build/scripts-3.14/casl'
#
#    The `casl` CLI is correctly exposed via entry_points/console_scripts
#    below, which auto-generates a wrapper — no physical script needed.
# ---------------------------------------------------------------------------
setup(
    name="cppcheckdata-shims",
    version=_read_version(),
    description=(
        "Static-analysis shims, abstract interpretation engines, "
        "and the CASL DSL for Cppcheck dump files."
    ),
    long_description=_read_long_description(),
    long_description_content_type="text/markdown",
    license="MIT",
    author="cppcheckdata-shims contributors",
    url="https://github.com/Chubek/cppcheckdata-shims",
    project_urls={
        "Repository": "https://github.com/Chubek/cppcheckdata-shims",
        "Issues": "https://github.com/Chubek/cppcheckdata-shims/issues",
        "Documentation": "https://github.com/Chubek/cppcheckdata-shims/tree/main/docs",
    },
    python_requires=">=3.10",
    packages=find_packages(
        include=[
            "cppcheckdata_shims",
            "cppcheckdata_shims.*",
            "casl",
            "casl.*",
        ],
        exclude=[
            "tests",
            "tests.*",
            "scripts",
            "scripts.*",
            "docs",
            "docs.*",
        ],
    ),
    package_data={
        "cppcheckdata_shims": ["py.typed"],
        "casl": ["py.typed"],
    },
    install_requires=_read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "ruff>=0.4",
            "mypy>=1.10",
            "black>=24.0",
            "isort>=5.13",
        ],
        "docs": [
            "sphinx>=7.0",
            "sphinx-rtd-theme>=2.0",
            "myst-parser>=3.0",
        ],
        "viz": [
            "graphviz>=0.20",
        ],
    },

    # ── THIS is the only CLI mechanism needed ──────────────────────────
    #  setuptools creates a platform-appropriate wrapper that calls
    #  casl.__main__:main — no physical bin/casl file required.
    entry_points={
        "console_scripts": [
            "casl=casl.__main__:main",
        ],
    },

    classifiers=[
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
        "Topic :: Software Development :: Compilers",
        "Typing :: Typed",
    ],
    keywords=[
        "cppcheck",
        "static-analysis",
        "abstract-interpretation",
        "data-flow",
        "control-flow",
        "CASL",
        "program-analysis",
    ],
    zip_safe=False,
)
