t #!/usr/bin/env bash
# =============================================================================
#  generate-docs.sh — Master documentation build script
#
#  Extracts docstrings from cppcheckdata_shims/ and casl/ Python packages
#  and generates documentation in multiple formats:
#
#    - HTML       (browseable documentation)
#    - PDF        (via LaTeX/xelatex)
#    - LaTeX      (raw .tex sources)
#    - EPUB       (e-book format)
#    - Man pages  (Unix manual pages)
#    - Doxygen    (call graphs, class diagrams, cross-references)
#
#  Usage:
#      ./generate-docs.sh                  # Build all formats
#      ./generate-docs.sh html             # HTML only
#      ./generate-docs.sh pdf              # PDF only
#      ./generate-docs.sh latex            # LaTeX sources only
#      ./generate-docs.sh epub             # EPUB only
#      ./generate-docs.sh man              # Man pages only
#      ./generate-docs.sh doxygen          # Doxygen only
#      ./generate-docs.sh coverage         # Docstring coverage report
#      ./generate-docs.sh clean            # Remove all build artifacts
#      ./generate-docs.sh install-deps     # Install documentation dependencies
#
#  Prerequisites:
#      pip install -r requirements-docs.txt
#      # For PDF: install xelatex (texlive-xetex) and latexmk
#      # For Doxygen: install doxygen and graphviz
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
#  Resolve paths
# ---------------------------------------------------------------------------
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SCRIPT_SOURCE" ]; do
    SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" && pwd)"
    SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
    [[ "$SCRIPT_SOURCE" != /* ]] && SCRIPT_SOURCE="$SCRIPT_DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR" && pwd)"
DOCS_DIR="$REPO_ROOT/docs"

# ---------------------------------------------------------------------------
#  Colors
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# ---------------------------------------------------------------------------
#  Utility functions
# ---------------------------------------------------------------------------
info()    { echo -e "${BLUE}${BOLD}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}${BOLD}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}${BOLD}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}${BOLD}[ERROR]${RESET} $*" >&2; }
header()  {
    echo ""
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}${BOLD}  $*${RESET}"
    echo -e "${CYAN}${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo ""
}

# ---------------------------------------------------------------------------
#  Check prerequisites
# ---------------------------------------------------------------------------
check_python() {
    local py="${PYTHON:-}"
    if [ -z "$py" ]; then
        if command -v python3 &>/dev/null; then
            py="python3"
        elif command -v python &>/dev/null; then
            py="python"
        else
            error "No Python interpreter found. Install Python 3.10+."
            exit 1
        fi
    fi
    echo "$py"
}

check_command() {
    local cmd="$1"
    local pkg="${2:-$1}"
    if ! command -v "$cmd" &>/dev/null; then
        warn "'$cmd' not found. Install '$pkg' for full functionality."
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
#  Actions
# ---------------------------------------------------------------------------
do_install_deps() {
    header "Installing Documentation Dependencies"
    local py
    py="$(check_python)"

    info "Installing Python documentation packages..."
    "$py" -m pip install -r "$REPO_ROOT/requirements-docs.txt"
    success "Python packages installed."

    echo ""
    info "System packages needed for PDF generation:"
    echo "    Debian/Ubuntu:  sudo apt install texlive-xetex texlive-fonts-recommended"
    echo "                    sudo apt install texlive-latex-extra latexmk"
    echo "                    sudo apt install doxygen graphviz"
    echo "    Fedora/RHEL:    sudo dnf install texlive-xetex texlive-collection-fontsrecommended"
    echo "                    sudo dnf install texlive-collection-latexextra latexmk"
    echo "                    sudo dnf install doxygen graphviz"
    echo "    macOS:          brew install --cask mactex"
    echo "                    brew install doxygen graphviz"
    echo "    Arch:           sudo pacman -S texlive-xetex texlive-latexextra latexmk"
    echo "                    sudo pacman -S doxygen graphviz"
    echo ""
}

do_clean() {
    header "Cleaning Build Artifacts"
    rm -rf "$DOCS_DIR/_build"
    rm -rf "$DOCS_DIR/api/_autosummary"
    rm -rf "$DOCS_DIR/doxygen"
    success "All build artifacts removed."
}

do_apidoc() {
    info "Generating API stub files with sphinx-apidoc..."
    local py
    py="$(check_python)"

    # Ensure packages are importable
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"

    "$py" -m sphinx.ext.apidoc \
        -f -e -M \
        -o "$DOCS_DIR/api/_autosummary" \
        "$REPO_ROOT/cppcheckdata_shims" \
        --implicit-namespaces \
        -H "cppcheckdata_shims API" 2>/dev/null || \
    sphinx-apidoc \
        -f -e -M \
        -o "$DOCS_DIR/api/_autosummary" \
        "$REPO_ROOT/cppcheckdata_shims" \
        --implicit-namespaces \
        -H "cppcheckdata_shims API" 2>/dev/null || \
    warn "sphinx-apidoc failed for cppcheckdata_shims (may not exist yet)"

    "$py" -m sphinx.ext.apidoc \
        -f -e -M \
        -o "$DOCS_DIR/api/_autosummary" \
        "$REPO_ROOT/casl" \
        --implicit-namespaces \
        -H "CASL API" 2>/dev/null || \
    sphinx-apidoc \
        -f -e -M \
        -o "$DOCS_DIR/api/_autosummary" \
        "$REPO_ROOT/casl" \
        --implicit-namespaces \
        -H "CASL API" 2>/dev/null || \
    warn "sphinx-apidoc failed for casl (may not exist yet)"

    success "API stubs generated."
}

do_html() {
    header "Building HTML Documentation"
    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
    sphinx-build -b html -j auto . _build/html
    echo ""
    success "HTML documentation: $DOCS_DIR/_build/html/index.html"
}

do_latex() {
    header "Building LaTeX Sources"
    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
    sphinx-build -b latex -j auto . _build/latex
    echo ""
    success "LaTeX sources: $DOCS_DIR/_build/latex/"
}

do_pdf() {
    header "Building PDF via LaTeX"

    if ! check_command "xelatex" "texlive-xetex"; then
        error "xelatex is required for PDF generation."
        error "Install: sudo apt install texlive-xetex texlive-fonts-recommended texlive-latex-extra latexmk"
        exit 1
    fi
    if ! check_command "latexmk" "latexmk"; then
        error "latexmk is required for PDF generation."
        exit 1
    fi

    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"

    info "Step 1/2: Generating LaTeX sources..."
    sphinx-build -b latex -j auto . _build/latex

    info "Step 2/2: Compiling LaTeX → PDF..."
    cd _build/latex
    latexmk -xelatex -interaction=nonstopmode -halt-on-error \
        cppcheckdata-shims.tex 2>&1 | tail -20

    echo ""
    success "PDF: $DOCS_DIR/_build/latex/cppcheckdata-shims.pdf"
}

do_epub() {
    header "Building EPUB"
    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
    sphinx-build -b epub -j auto . _build/epub
    echo ""
    success "EPUB: $DOCS_DIR/_build/epub/"
}

do_man() {
    header "Building Man Pages"
    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
    sphinx-build -b man -j auto . _build/man
    echo ""
    success "Man pages: $DOCS_DIR/_build/man/"
}

do_doxygen() {
    header "Running Doxygen"

    if ! check_command "doxygen" "doxygen"; then
        error "Doxygen is required. Install: sudo apt install doxygen graphviz"
        exit 1
    fi

    cd "$DOCS_DIR"
    doxygen Doxyfile
    echo ""

    # Count documented items
    if [ -d doxygen/html ]; then
        success "Doxygen HTML: $DOCS_DIR/doxygen/html/index.html"
    fi
    if [ -d doxygen/xml ]; then
        success "Doxygen XML (for Breathe): $DOCS_DIR/doxygen/xml/"
    fi
    if [ -d doxygen/latex ]; then
        success "Doxygen LaTeX: $DOCS_DIR/doxygen/latex/"

        # Optionally compile Doxygen LaTeX to PDF
        if check_command "latexmk" "latexmk" && check_command "xelatex" "texlive-xetex"; then
            info "Compiling Doxygen LaTeX → PDF..."
            cd doxygen/latex
            latexmk -xelatex -interaction=nonstopmode -halt-on-error \
                refman.tex 2>&1 | tail -10 || warn "Doxygen PDF compilation had warnings."
            if [ -f refman.pdf ]; then
                success "Doxygen PDF: $DOCS_DIR/doxygen/latex/refman.pdf"
            fi
        fi
    fi

    if [ -f doxygen/warnings.log ]; then
        local wc
        wc=$(wc -l < doxygen/warnings.log)
        if [ "$wc" -gt 0 ]; then
            warn "Doxygen produced $wc warning(s). See: doxygen/warnings.log"
        fi
    fi
}

do_coverage() {
    header "Docstring Coverage Report"
    do_apidoc
    cd "$DOCS_DIR"
    export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
    sphinx-build -b coverage -j auto . _build/coverage
    echo ""
    if [ -f _build/coverage/python.txt ]; then
        echo -e "${BOLD}Coverage Report:${RESET}"
        echo "────────────────────────────────────────"
        cat _build/coverage/python.txt
    fi
}

do_all() {
    header "Building All Documentation Formats"

    local start_time
    start_time=$(date +%s)

    do_html
    do_pdf
    do_epub
    do_man

    # Doxygen is optional — don't fail if not installed
    if check_command "doxygen" "doxygen"; then
        do_doxygen
    else
        warn "Skipping Doxygen (not installed)."
    fi

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    echo ""
    header "Documentation Build Complete (${elapsed}s)"
    echo "  HTML:          $DOCS_DIR/_build/html/index.html"
    echo "  PDF:           $DOCS_DIR/_build/latex/cppcheckdata-shims.pdf"
    echo "  EPUB:          $DOCS_DIR/_build/epub/"
    echo "  Man pages:     $DOCS_DIR/_build/man/"
    if [ -d "$DOCS_DIR/doxygen/html" ]; then
        echo "  Doxygen HTML:  $DOCS_DIR/doxygen/html/index.html"
    fi
    if [ -f "$DOCS_DIR/doxygen/latex/refman.pdf" ]; then
        echo "  Doxygen PDF:   $DOCS_DIR/doxygen/latex/refman.pdf"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
#  Main dispatch
# ---------------------------------------------------------------------------
main() {
    local cmd="${1:-all}"

    case "$cmd" in
        html)          do_html ;;
        pdf|latexpdf)  do_pdf ;;
        latex)         do_latex ;;
        epub)          do_epub ;;
        man)           do_man ;;
        doxygen)       do_doxygen ;;
        coverage)      do_coverage ;;
        clean)         do_clean ;;
        install-deps)  do_install_deps ;;
        all)           do_all ;;
        help|-h|--help)
            echo ""
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  html          Build HTML documentation"
            echo "  pdf           Build PDF via LaTeX (xelatex)"
            echo "  latex         Build LaTeX sources only"
            echo "  epub          Build EPUB e-book"
            echo "  man           Build Unix man pages"
            echo "  doxygen       Run Doxygen (call graphs, diagrams)"
            echo "  coverage      Report docstring coverage"
            echo "  clean         Remove all build artifacts"
            echo "  install-deps  Install Python documentation packages"
            echo "  all           Build all formats (default)"
            echo "  help          Show this message"
            echo ""
            ;;
        *)
            error "Unknown command: $cmd"
            echo "Run '$0 help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
