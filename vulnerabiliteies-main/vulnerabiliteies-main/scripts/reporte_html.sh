#!/usr/bin/env bash
# reporte_html.sh — genera un reporte en HTML a partir del exportador TXT

set -euo pipefail

TARGET="${1:-http://localhost:8080}"
OUTDIR="${2:-./reportes}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$OUTDIR"

cd "$PROJECT_ROOT"

bash "$SCRIPT_DIR/reporte_export.sh" "$TARGET" "$OUTDIR" >/dev/null

LATEST_TXT="$(find "$OUTDIR" -maxdepth 1 -type f -name 'reporte_*.txt' | sort | tail -n 1)"
if [[ -z "$LATEST_TXT" ]]; then
  echo "No se encontró ningún reporte .txt generado en $OUTDIR" >&2
  exit 1
fi

HTML_FILE="${LATEST_TXT%.txt}.html"

python3 - "$LATEST_TXT" "$HTML_FILE" <<'PY'
import html
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
text = src.read_text(encoding='utf-8')
lines = text.splitlines()

body = []
for line in lines:
    if not line.strip():
        body.append('<div class="spacer"></div>')
    else:
        body.append(f'<p>{html.escape(line)}</p>')

html_content = f'''<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reporte de Vulnerabilidades</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #222; }}
    h1 {{ color: #0f172a; }}
    p {{ margin: 0.2rem 0; white-space: pre-wrap; }}
    .spacer {{ height: 0.6rem; }}
    code {{ background: #f3f4f6; padding: 0.1rem 0.25rem; border-radius: 0.25rem; }}
  </style>
</head>
<body>
  <h1>Reporte de Vulnerabilidades</h1>
  {"".join(body)}
</body>
</html>
'''

dst.write_text(html_content, encoding='utf-8')
PY

echo "Reporte HTML generado: $HTML_FILE"
