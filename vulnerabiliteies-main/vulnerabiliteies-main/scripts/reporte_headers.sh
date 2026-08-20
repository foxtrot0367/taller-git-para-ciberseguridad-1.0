#!/usr/bin/env bash
# reporte_headers.sh — Auditoría de cabeceras de seguridad HTTP

TARGET="${1:-http://localhost:8080}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

score=0; total=0

header_check() {
  local name="$1" headers="$2" expected_val="${3:-}"
  ((total++)) || true
  local val
  val=$(echo "$headers" | grep -i "^${name}:" | head -1 | sed 's/^[^:]*: //' | tr -d '\r')
  if [[ -n "$val" ]]; then
    echo -e "  ${GREEN}[PRESENTE]${NC}  ${BOLD}${name}${NC}"
    echo -e "              └─ ${val}"
    ((score++)) || true
  else
    echo -e "  ${RED}[AUSENTE]${NC}   ${BOLD}${name}${NC}"
    if [[ -n "$expected_val" ]]; then
      echo -e "              └─ ${YELLOW}Recomendado: ${expected_val}${NC}"
    fi
  fi
}

echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  VulnLab — Auditoría de Cabeceras HTTP${NC}"
echo -e "${CYAN}  Target : ${TARGET}${NC}"
echo -e "${CYAN}  Fecha  : $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}\n"

echo -e "${BOLD}[ Cabeceras recibidas del servidor ]${NC}"
ALL_HEADERS=$(curl -sI "${TARGET}/" 2>/dev/null)
echo "$ALL_HEADERS" | grep -v "^$" | while IFS= read -r line; do
  echo -e "  ${CYAN}${line}${NC}"
done
echo ""

echo -e "${BOLD}[ Evaluación de cabeceras de seguridad ]${NC}"
header_check "Content-Security-Policy"   "$ALL_HEADERS" "default-src 'self'"
header_check "X-Frame-Options"           "$ALL_HEADERS" "DENY"
header_check "X-Content-Type-Options"    "$ALL_HEADERS" "nosniff"
header_check "Strict-Transport-Security" "$ALL_HEADERS" "max-age=31536000; includeSubDomains"
header_check "Referrer-Policy"           "$ALL_HEADERS" "strict-origin-when-cross-origin"
header_check "Permissions-Policy"        "$ALL_HEADERS" "geolocation=(), microphone=()"
header_check "X-XSS-Protection"         "$ALL_HEADERS" "1; mode=block"
header_check "Cache-Control"            "$ALL_HEADERS" "no-store"
echo ""

echo -e "${BOLD}[ Información del servidor expuesta ]${NC}"
server=$(echo "$ALL_HEADERS" | grep -i "^Server:" | tr -d '\r')
powered=$(echo "$ALL_HEADERS" | grep -i "^X-Powered-By:" | tr -d '\r')
[[ -n "$server"  ]] && echo -e "  ${YELLOW}[RIESGO]${NC} ${server}" || echo -e "  ${GREEN}[OK]${NC} Header Server no expuesto"
[[ -n "$powered" ]] && echo -e "  ${YELLOW}[RIESGO]${NC} ${powered}" || echo -e "  ${GREEN}[OK]${NC} Header X-Powered-By no expuesto"
echo ""

pct=$(( score * 100 / total ))
if   [[ $pct -ge 80 ]]; then color=$GREEN  grade="A"
elif [[ $pct -ge 60 ]]; then color=$YELLOW grade="B"
elif [[ $pct -ge 40 ]]; then color=$YELLOW grade="C"
else                          color=$RED    grade="F"
fi

echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  PUNTUACIÓN DE CABECERAS${NC}"
echo -e "  Presentes : ${score}/${total} (${pct}%)"
echo -e "  Calificación: ${color}${BOLD}${grade}${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}\n"
