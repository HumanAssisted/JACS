#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BOOK_DIR}/../../.." && pwd)"

OUTPUT_PDF="${1:-${REPO_ROOT}/docs/jacsbook.pdf}"
OUTPUT_DIR="$(dirname "${OUTPUT_PDF}")"
PRINT_HTML="${BOOK_DIR}/book/print.html"

if ! command -v mdbook >/dev/null 2>&1; then
  echo "error: mdbook is required but not installed" >&2
  exit 1
fi

if ! command -v playwright >/dev/null 2>&1; then
  echo "error: playwright CLI is required but not installed" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

(
  cd "${BOOK_DIR}"
  mdbook build
)

if [[ ! -f "${PRINT_HTML}" ]]; then
  echo "error: expected print HTML was not generated at ${PRINT_HTML}" >&2
  exit 1
fi

PAPER_FORMAT="${JACSBOOK_PDF_PAPER_FORMAT:-Letter}"
BROWSER="${JACSBOOK_PDF_BROWSER:-chromium}"

playwright pdf \
  --browser "${BROWSER}" \
  --paper-format "${PAPER_FORMAT}" \
  "file://${PRINT_HTML}" \
  "${OUTPUT_PDF}"

echo "Generated PDF: ${OUTPUT_PDF}"
