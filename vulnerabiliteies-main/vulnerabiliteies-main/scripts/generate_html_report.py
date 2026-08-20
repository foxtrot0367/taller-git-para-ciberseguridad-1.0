import argparse
import html
import os
from pathlib import Path


def find_latest_report(report_dir: Path) -> Path:
    reports = sorted(report_dir.glob("reporte_*.txt"))
    if not reports:
        raise FileNotFoundError(f"No se encontraron reportes .txt en {report_dir}")
    return reports[-1]


def convert_to_html(text: str) -> str:
    lines = text.splitlines()
    blocks = []
    for line in lines:
        if not line.strip():
            blocks.append("<div class='spacer'></div>")
            continue
        escaped = html.escape(line)
        blocks.append(f"<p>{escaped}</p>")
    body = "\n".join(blocks)
    return f"""<!DOCTYPE html>
<html lang=\"es\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
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
  {body}
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Convierte un reporte TXT a HTML")
    parser.add_argument("--input", "-i", help="Ruta al archivo .txt")
    parser.add_argument("--dir", "-d", default="reportes", help="Directorio con reportes .txt")
    args = parser.parse_args()

    if args.input:
        src = Path(args.input).resolve()
        if not src.exists():
            raise FileNotFoundError(f"No existe el archivo: {src}")
    else:
        report_dir = Path(args.dir).resolve()
        os.makedirs(report_dir, exist_ok=True)
        src = find_latest_report(report_dir)

    dst = src.with_suffix(".html")
    text = src.read_text(encoding="utf-8")
    dst.write_text(convert_to_html(text), encoding="utf-8")
    print(f"Reporte HTML generado: {dst}")


if __name__ == "__main__":
    main()
