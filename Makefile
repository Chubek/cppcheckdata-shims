# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║  cppcheckdata-shims — Top-level Makefile                                ║
# ║                                                                         ║
# ║  Usage:                                                                 ║
# ║      make && sudo make install   Build and install the library          ║
# ║      make html                   Build HTML documentation               ║
# ║      make latex                  Build LaTeX documentation              ║
# ║      make pdf                    Build PDF documentation                ║
# ║      make uninstall              Remove installed package               ║
# ║      make clean                  Remove all build artifacts             ║
# ║      make help                   Show all available targets             ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

SHELL           := /bin/bash
.DEFAULT_GOAL   := build

# Python interpreter selection: honour $PYTHON, fall back to python3, then python
PYTHON          ?= $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null)

# pip — prefer the module form so it matches the same interpreter
PIP             ?= $(PYTHON) -m pip

# Sphinx — prefer the module form; fallback to sphinx-build on PATH
SPHINXBUILD     ?= $(PYTHON) -m sphinx
SPHINXOPTS      ?=

# Doxygen (optional, for supplementary call-graph diagrams)
DOXYGEN         ?= $(shell command -v doxygen 2>/dev/null)

# LaTeX engine for PDF generation (xelatex handles Unicode best)
LATEXMK         ?= $(shell command -v latexmk 2>/dev/null)
XELATEX         ?= $(shell command -v xelatex 2>/dev/null)

# Project directories
DOCS_SRCDIR     := docs
DOCS_BUILDDIR   := docs/_build
DIST_DIR        := dist
BUILD_DIR       := build
EGG_INFO_DIRS   := $(wildcard *.egg-info)

# Package metadata (extracted once so we can display it)
PKG_NAME        := $(shell $(PYTHON) -c \
                     "import configparser; c=configparser.ConfigParser(); \
                      c.read('pyproject.toml'); \
                      print(c.get('project','name','cppcheckdata-shims'))" \
                     2>/dev/null || echo "cppcheckdata-shims")
PKG_VERSION     := $(shell $(PYTHON) -c \
                     "import configparser; c=configparser.ConfigParser(); \
                      c.read('pyproject.toml'); \
                      print(c.get('project','version','0.0.0'))" \
                     2>/dev/null || echo "0.0.0")

# Terminal colours (disabled when stdout is not a tty)
ifneq ($(TERM),dumb)
  _BOLD  := $(shell tput bold   2>/dev/null)
  _RESET := $(shell tput sgr0   2>/dev/null)
  _CYAN  := $(shell tput setaf 6 2>/dev/null)
  _GREEN := $(shell tput setaf 2 2>/dev/null)
  _RED   := $(shell tput setaf 1 2>/dev/null)
  _YELLOW:= $(shell tput setaf 3 2>/dev/null)
else
  _BOLD  :=
  _RESET :=
  _CYAN  :=
  _GREEN :=
  _RED   :=
  _YELLOW:=
endif

# ─────────────────────────────────────────────────────────────────────────────
# Preflight checks
# ─────────────────────────────────────────────────────────────────────────────

ifeq ($(PYTHON),)
  $(error $(_RED)No Python interpreter found. Set $$PYTHON or install python3.$(_RESET))
endif

# ─────────────────────────────────────────────────────────────────────────────
# Phony targets
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: all build install install-dev install-editable uninstall \
        html latex pdf epub man doxygen doc-all doc-clean doc-coverage \
        test lint type-check format check-all \
        wheel sdist release \
        clean distclean help info

# ═════════════════════════════════════════════════════════════════════════════
#  BUILD & INSTALL
# ═════════════════════════════════════════════════════════════════════════════

## all        — Alias for 'build' (so `make && sudo make install` works)
all: build

## build      — Build the wheel (compile step; no installation)
build:
	@echo "$(_CYAN)$(_BOLD)══ Building $(PKG_NAME) $(PKG_VERSION) ══$(_RESET)"
	$(PIP) wheel --no-deps --wheel-dir $(DIST_DIR) .
	@echo "$(_GREEN)$(_BOLD)✓ Build complete.  Wheel in $(DIST_DIR)/$(_RESET)"

## install    — Install the package system-wide (run with sudo if needed)
install:
	@echo "$(_CYAN)$(_BOLD)══ Installing $(PKG_NAME) $(PKG_VERSION) ══$(_RESET)"
	$(PIP) install --no-deps .
	@echo "$(_GREEN)$(_BOLD)✓ Installed.$(_RESET)"
	@echo "  Verify with:  $(PYTHON) -c \"import cppcheckdata_shims; print(cppcheckdata_shims.__file__)\""

## install-dev — Install with all development / documentation dependencies
install-dev:
	@echo "$(_CYAN)$(_BOLD)══ Installing $(PKG_NAME) [dev] ══$(_RESET)"
	$(PIP) install -e ".[dev]"
	@if [ -f requirements-docs.txt ]; then \
		$(PIP) install -r requirements-docs.txt; \
	fi
	@echo "$(_GREEN)$(_BOLD)✓ Dev install complete.$(_RESET)"

## install-editable — Install in editable / development mode (no sudo needed)
install-editable:
	@echo "$(_CYAN)$(_BOLD)══ Installing $(PKG_NAME) (editable) ══$(_RESET)"
	$(PIP) install --no-deps -e .
	@echo "$(_GREEN)$(_BOLD)✓ Editable install complete.$(_RESET)"

## uninstall  — Remove the installed package
uninstall:
	@echo "$(_YELLOW)$(_BOLD)══ Uninstalling $(PKG_NAME) ══$(_RESET)"
	$(PIP) uninstall -y $(PKG_NAME) 2>/dev/null || true
	@echo "$(_GREEN)$(_BOLD)✓ Uninstalled.$(_RESET)"

# ═════════════════════════════════════════════════════════════════════════════
#  DOCUMENTATION — HTML
# ═════════════════════════════════════════════════════════════════════════════

## html       — Build browseable HTML documentation via Sphinx
html: $(DOCS_SRCDIR)/conf.py
	@echo "$(_CYAN)$(_BOLD)══ Building HTML docs ══$(_RESET)"
	@mkdir -p $(DOCS_BUILDDIR)/html
	$(SPHINXBUILD) -b html $(SPHINXOPTS) $(DOCS_SRCDIR) $(DOCS_BUILDDIR)/html
	@echo ""
	@echo "$(_GREEN)$(_BOLD)✓ HTML docs ready:$(_RESET) $(DOCS_BUILDDIR)/html/index.html"

# ═════════════════════════════════════════════════════════════════════════════
#  DOCUMENTATION — LaTeX
# ═════════════════════════════════════════════════════════════════════════════

## latex      — Build LaTeX source files via Sphinx
latex: $(DOCS_SRCDIR)/conf.py
	@echo "$(_CYAN)$(_BOLD)══ Building LaTeX docs ══$(_RESET)"
	@mkdir -p $(DOCS_BUILDDIR)/latex
	$(SPHINXBUILD) -b latex $(SPHINXOPTS) $(DOCS_SRCDIR) $(DOCS_BUILDDIR)/latex
	@echo ""
	@echo "$(_GREEN)$(_BOLD)✓ LaTeX sources ready:$(_RESET) $(DOCS_BUILDDIR)/latex/"

# ═════════════════════════════════════════════════════════════════════════════
#  DOCUMENTATION — PDF
# ═════════════════════════════════════════════════════════════════════════════

## pdf        — Build publication-quality PDF (Sphinx → LaTeX → xelatex)
pdf: latex
	@echo "$(_CYAN)$(_BOLD)══ Compiling PDF from LaTeX ══$(_RESET)"
ifneq ($(LATEXMK),)
	@# Preferred: latexmk drives the correct number of passes automatically
	cd $(DOCS_BUILDDIR)/latex && \
		$(LATEXMK) -xelatex -interaction=nonstopmode -halt-on-error \
		           -file-line-error *.tex || \
		(echo "$(_RED)$(_BOLD)✗ latexmk failed; see log above.$(_RESET)" && exit 1)
else ifneq ($(XELATEX),)
	@# Fallback: run xelatex manually (two passes for cross-references)
	cd $(DOCS_BUILDDIR)/latex && \
		$(XELATEX) -interaction=nonstopmode -halt-on-error *.tex && \
		$(XELATEX) -interaction=nonstopmode -halt-on-error *.tex || \
		(echo "$(_RED)$(_BOLD)✗ xelatex failed; see log above.$(_RESET)" && exit 1)
else
	@# Last resort: try Sphinx's own latexpdf builder (uses pdflatex)
	$(SPHINXBUILD) -M latexpdf $(DOCS_SRCDIR) $(DOCS_BUILDDIR) $(SPHINXOPTS) || \
		(echo "$(_RED)$(_BOLD)✗ No LaTeX toolchain found.$(_RESET)" && \
		 echo "  Install texlive:  sudo apt install texlive-xetex latexmk" && exit 1)
endif
	@echo ""
	@PDF=$$(ls $(DOCS_BUILDDIR)/latex/*.pdf 2>/dev/null | head -1); \
	if [ -n "$$PDF" ]; then \
		echo "$(_GREEN)$(_BOLD)✓ PDF ready:$(_RESET) $$PDF"; \
	else \
		echo "$(_YELLOW)$(_BOLD)⚠ PDF not found — check LaTeX logs.$(_RESET)"; \
	fi

# ═════════════════════════════════════════════════════════════════════════════
#  DOCUMENTATION — Additional formats
# ═════════════════════════════════════════════════════════════════════════════

## epub       — Build EPUB (e-book) documentation
epub: $(DOCS_SRCDIR)/conf.py
	@echo "$(_CYAN)$(_BOLD)══ Building EPUB docs ══$(_RESET)"
	@mkdir -p $(DOCS_BUILDDIR)/epub
	$(SPHINXBUILD) -b epub $(SPHINXOPTS) $(DOCS_SRCDIR) $(DOCS_BUILDDIR)/epub
	@echo "$(_GREEN)$(_BOLD)✓ EPUB ready:$(_RESET) $(DOCS_BUILDDIR)/epub/"

## man        — Build Unix manual pages
man: $(DOCS_SRCDIR)/conf.py
	@echo "$(_CYAN)$(_BOLD)══ Building man pages ══$(_RESET)"
	@mkdir -p $(DOCS_BUILDDIR)/man
	$(SPHINXBUILD) -b man $(SPHINXOPTS) $(DOCS_SRCDIR) $(DOCS_BUILDDIR)/man
	@echo "$(_GREEN)$(_BOLD)✓ Man pages ready:$(_RESET) $(DOCS_BUILDDIR)/man/"

## doxygen    — Run Doxygen for call-graphs and class diagrams (optional)
doxygen:
ifeq ($(DOXYGEN),)
	@echo "$(_YELLOW)$(_BOLD)⚠ Doxygen not found — skipping.$(_RESET)"
	@echo "  Install with:  sudo apt install doxygen graphviz"
else
	@echo "$(_CYAN)$(_BOLD)══ Running Doxygen ══$(_RESET)"
	@if [ -f $(DOCS_SRCDIR)/Doxyfile ]; then \
		cd $(DOCS_SRCDIR) && $(DOXYGEN) Doxyfile; \
		echo "$(_GREEN)$(_BOLD)✓ Doxygen output ready:$(_RESET) $(DOCS_SRCDIR)/doxygen-out/"; \
	else \
		echo "$(_YELLOW)No Doxyfile found at $(DOCS_SRCDIR)/Doxyfile$(_RESET)"; \
	fi
endif

## doc-all    — Build ALL documentation formats (html + latex + pdf + epub + man + doxygen)
doc-all: html latex pdf epub man doxygen
	@echo ""
	@echo "$(_GREEN)$(_BOLD)✓ All documentation formats built.$(_RESET)"
	@echo "  HTML  : $(DOCS_BUILDDIR)/html/index.html"
	@echo "  LaTeX : $(DOCS_BUILDDIR)/latex/"
	@echo "  PDF   : $(DOCS_BUILDDIR)/latex/*.pdf"
	@echo "  EPUB  : $(DOCS_BUILDDIR)/epub/"
	@echo "  Man   : $(DOCS_BUILDDIR)/man/"

## doc-coverage — Check docstring coverage via Sphinx
doc-coverage: $(DOCS_SRCDIR)/conf.py
	@echo "$(_CYAN)$(_BOLD)══ Checking docstring coverage ══$(_RESET)"
	@mkdir -p $(DOCS_BUILDDIR)/coverage
	$(SPHINXBUILD) -b coverage $(SPHINXOPTS) $(DOCS_SRCDIR) $(DOCS_BUILDDIR)/coverage
	@echo ""
	@cat $(DOCS_BUILDDIR)/coverage/python.txt 2>/dev/null || true
	@echo "$(_GREEN)$(_BOLD)✓ Coverage report:$(_RESET) $(DOCS_BUILDDIR)/coverage/"

## doc-clean  — Remove all documentation build artifacts
doc-clean:
	@echo "$(_YELLOW)$(_BOLD)══ Cleaning documentation build ══$(_RESET)"
	rm -rf $(DOCS_BUILDDIR)
	rm -rf $(DOCS_SRCDIR)/doxygen-out
	rm -rf $(DOCS_SRCDIR)/api/_autosummary
	@echo "$(_GREEN)$(_BOLD)✓ Documentation build cleaned.$(_RESET)"

# ═════════════════════════════════════════════════════════════════════════════
#  TESTING & QUALITY
# ═════════════════════════════════════════════════════════════════════════════

## test       — Run the test suite via pytest
test:
	@echo "$(_CYAN)$(_BOLD)══ Running tests ══$(_RESET)"
	$(PYTHON) -m pytest tests/ -v --tb=short
	@echo "$(_GREEN)$(_BOLD)✓ Tests passed.$(_RESET)"

## lint       — Run the ruff linter
lint:
	@echo "$(_CYAN)$(_BOLD)══ Linting ══$(_RESET)"
	$(PYTHON) -m ruff check .
	@echo "$(_GREEN)$(_BOLD)✓ Lint clean.$(_RESET)"

## type-check — Run mypy type checker
type-check:
	@echo "$(_CYAN)$(_BOLD)══ Type checking ══$(_RESET)"
	$(PYTHON) -m mypy --strict cppcheckdata_shims/ casl/
	@echo "$(_GREEN)$(_BOLD)✓ Type check passed.$(_RESET)"

## format     — Auto-format code with ruff
format:
	@echo "$(_CYAN)$(_BOLD)══ Formatting ══$(_RESET)"
	$(PYTHON) -m ruff format .
	@echo "$(_GREEN)$(_BOLD)✓ Formatted.$(_RESET)"

## check-all  — Run lint + type-check + test in sequence
check-all: lint type-check test

# ═════════════════════════════════════════════════════════════════════════════
#  PACKAGING & DISTRIBUTION
# ═════════════════════════════════════════════════════════════════════════════

## sdist      — Create a source distribution tarball
sdist:
	@echo "$(_CYAN)$(_BOLD)══ Building sdist ══$(_RESET)"
	$(PYTHON) -m build --sdist
	@echo "$(_GREEN)$(_BOLD)✓ Source distribution in $(DIST_DIR)/$(_RESET)"

## wheel      — Build a wheel package
wheel:
	@echo "$(_CYAN)$(_BOLD)══ Building wheel ══$(_RESET)"
	$(PYTHON) -m build --wheel
	@echo "$(_GREEN)$(_BOLD)✓ Wheel in $(DIST_DIR)/$(_RESET)"

## release    — Build both sdist and wheel for upload
release: sdist wheel
	@echo "$(_GREEN)$(_BOLD)✓ Release artifacts in $(DIST_DIR)/$(_RESET)"
	@ls -lh $(DIST_DIR)/

# ═════════════════════════════════════════════════════════════════════════════
#  CLEANUP
# ═════════════════════════════════════════════════════════════════════════════

## clean      — Remove build artifacts, caches, and generated files
clean: doc-clean
	@echo "$(_YELLOW)$(_BOLD)══ Cleaning build artifacts ══$(_RESET)"
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(EGG_INFO_DIRS)
	rm -rf .eggs .mypy_cache .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	find . -type f -name '*.pyo' -delete 2>/dev/null || true
	@echo "$(_GREEN)$(_BOLD)✓ Clean.$(_RESET)"

## distclean  — Remove everything not tracked by version control
distclean: clean
	@echo "$(_YELLOW)$(_BOLD)══ Deep cleaning ══$(_RESET)"
	rm -rf .tox .nox htmlcov coverage.xml .coverage
	@echo "$(_GREEN)$(_BOLD)✓ Distclean complete.$(_RESET)"

# ═════════════════════════════════════════════════════════════════════════════
#  INFO & HELP
# ═════════════════════════════════════════════════════════════════════════════

## info       — Display detected project configuration
info:
	@echo "$(_BOLD)Project Configuration$(_RESET)"
	@echo "  Package     : $(PKG_NAME)"
	@echo "  Version     : $(PKG_VERSION)"
	@echo "  Python      : $(PYTHON) ($$($(PYTHON) --version 2>&1))"
	@echo "  pip         : $(PIP)"
	@echo "  Sphinx      : $(SPHINXBUILD)"
	@echo "  Doxygen     : $(or $(DOXYGEN),(not found))"
	@echo "  latexmk     : $(or $(LATEXMK),(not found))"
	@echo "  xelatex     : $(or $(XELATEX),(not found))"
	@echo "  Docs source : $(DOCS_SRCDIR)/"
	@echo "  Docs build  : $(DOCS_BUILDDIR)/"

## help       — Show this help message
help:
	@echo ""
	@echo "$(_BOLD)cppcheckdata-shims Makefile$(_RESET)"
	@echo "$(_BOLD)══════════════════════════$(_RESET)"
	@echo ""
	@echo "$(_CYAN)Build & Install:$(_RESET)"
	@echo "  make                    Build the wheel"
	@echo "  sudo make install       Install the package system-wide"
	@echo "  make install-editable   Install in editable/dev mode"
	@echo "  make install-dev        Install with dev + doc dependencies"
	@echo "  make uninstall          Remove the installed package"
	@echo ""
	@echo "$(_CYAN)Documentation:$(_RESET)"
	@echo "  make html               Build HTML docs (Sphinx)"
	@echo "  make latex              Build LaTeX source files (Sphinx)"
	@echo "  make pdf                Build PDF via LaTeX (Sphinx → xelatex)"
	@echo "  make epub               Build EPUB e-book"
	@echo "  make man                Build Unix man pages"
	@echo "  make doxygen            Run Doxygen for diagrams"
	@echo "  make doc-all            Build ALL documentation formats"
	@echo "  make doc-coverage       Check docstring coverage"
	@echo "  make doc-clean          Remove documentation build artifacts"
	@echo ""
	@echo "$(_CYAN)Testing & Quality:$(_RESET)"
	@echo "  make test               Run pytest test suite"
	@echo "  make lint               Run ruff linter"
	@echo "  make type-check         Run mypy type checker"
	@echo "  make format             Auto-format with ruff"
	@echo "  make check-all          Run lint + type-check + test"
	@echo ""
	@echo "$(_CYAN)Packaging:$(_RESET)"
	@echo "  make sdist              Create source distribution"
	@echo "  make wheel              Build wheel package"
	@echo "  make release            Build sdist + wheel"
	@echo ""
	@echo "$(_CYAN)Cleanup:$(_RESET)"
	@echo "  make clean              Remove all build artifacts"
	@echo "  make distclean          Deep clean (tox, coverage, etc.)"
	@echo ""
	@echo "$(_CYAN)Info:$(_RESET)"
	@echo "  make info               Show detected project configuration"
	@echo "  make help               Show this help message"
	@echo ""
	@echo "$(_BOLD)Quick start:$(_RESET)"
	@echo "  make && sudo make install"
	@echo ""
