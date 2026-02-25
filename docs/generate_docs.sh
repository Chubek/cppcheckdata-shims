#!/bin/bash
#
# docs/generate_docs.sh
# =====================
#
# Convenience wrapper for generating documentation.
#
# Usage:
#   ./generate_docs.sh              # Generate all docs
#   ./generate_docs.sh --clean      # Clean and regenerate
#   ./generate_docs.sh --single <module>  # Generate for single module
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Python is available
if ! command -v python3 &> /dev/null; then
    echo_error "Python 3 is required but not found"
    exit 1
fi

# Parse arguments
CLEAN=""
SINGLE_MODULE=""
FORMAT="md"
OUTPUT_DIR="api"

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean|-c)
            CLEAN="--clean"
            shift
            ;;
        --single|-s)
            SINGLE_MODULE="$2"
            shift 2
            ;;
        --format|-f)
            FORMAT="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --clean, -c           Clean output directory before building"
            echo "  --single, -s MODULE   Generate docs for a single module"
            echo "  --format, -f FORMAT   Output format (md, rst, json) [default: md]"
            echo "  --output, -o DIR      Output directory [default: api]"
            echo "  --help, -h            Show this help"
            exit 0
            ;;
        *)
            echo_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Single module mode
if [[ -n "$SINGLE_MODULE" ]]; then
    SOURCE_FILE="../cppcheckdata_shims/${SINGLE_MODULE}.py"
    
    if [[ ! -f "$SOURCE_FILE" ]]; then
        echo_error "Module not found: $SOURCE_FILE"
        exit 1
    fi
    
    echo_info "Generating documentation for: $SINGLE_MODULE"
    
    mkdir -p "$OUTPUT_DIR"
    python3 extract_docs.py "$SOURCE_FILE" \
        --output "${OUTPUT_DIR}/${SINGLE_MODULE}.${FORMAT}" \
        --format "$FORMAT"
    
    echo_info "Done: ${OUTPUT_DIR}/${SINGLE_MODULE}.${FORMAT}"
    exit 0
fi

# Full build mode
echo_info "Building documentation for cppcheckdata_shims"
echo_info "Output format: $FORMAT"
echo_info "Output directory: $OUTPUT_DIR"

python3 build_docs.py \
    --source-dir "../cppcheckdata_shims" \
    --output-dir "$OUTPUT_DIR" \
    --format "$FORMAT" \
    $CLEAN

echo ""
echo_info "Documentation build complete!"
echo_info "View the docs at: ${OUTPUT_DIR}/index.${FORMAT}"