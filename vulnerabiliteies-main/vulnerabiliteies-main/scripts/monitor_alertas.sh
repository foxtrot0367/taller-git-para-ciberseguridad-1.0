#!/usr/bin/env bash
# monitor_alertas.sh — Monitor de vulnerabilidades en tiempo real
# Escucha docker logs y alerta cada vez que se dispara una vulnerabilidad
#
# Uso: ./monitor_alertas.sh [container_name]
#      ./monitor_alertas.sh vulnlab

CONTAINER="${1:-vulnlab}"

# ── Colores ───────────────────────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; ORANGE='\033[0;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m'
PURPLE='\033[0;35m'; LPURPLE='\033[1;35m'
BOLD='\033[1m';      DIM='\033[2m';  NC='\033[0m'

# ── Contadores (archivos temporales para compartir entre procesos) ────────────
TMPDIR_MON=$(mktemp -d)
trap 'cleanup' EXIT INT TERM

cleanup() {
  tput cnorm 2>/dev/null  # restaurar cursor
  echo -e "\n"
  show_summary
  rm -rf "$TMPDIR_MON"
}

counter_file() { echo "${TMPDIR_MON}/cnt_${1}"; }
inc() { local f; f=$(counter_file "$1"); echo $(( $(cat "$f" 2>/dev/null || echo 0) + 1 )) > "$f"; }
get() { cat "$(counter_file "$1")" 2>/dev/null || echo 0; }

VULN_TYPES=(SQL_INJECTION XSS CMD_INJECTION IDOR PATH_TRAVERSAL SSRF
            INFO_DISCLOSURE BRUTE_FORCE DESERIALIZATION BROKEN_AUTH_API
            CRYPTO_FAILURE INSECURE_DESIGN VULN_COMPONENTS)
for vt in "${VULN_TYPES[@]}"; do echo 0 > "$(counter_file "$vt")"; done
echo 0 > "$(counter_file TOTAL)"

# ── Verificaciones previas ────────────────────────────────────
preflight() {
  if ! command -v docker &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} docker no encontrado"; exit 1
  fi
  if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER}$"; then
    echo -e "${RED}[ERROR]${NC} Contenedor '${CONTAINER}' no está corriendo"
    echo -e "  Ejecuta: ${CYAN}make start${NC}"
    exit 1
  fi
  if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} python3 requerido para parsear JSON"; exit 1
  fi
}

# ── Banner inicial ────────────────────────────────────────────
print_banner() {
  clear
  echo -e "${BOLD}${CYAN}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║         VulnLab — Monitor de Alertas en Vivo        ║"
  echo "  ║                                                      ║"
  echo -e "  ║  Contenedor : ${NC}${CONTAINER}$(printf '%*s' $((38 - ${#CONTAINER})) '')${BOLD}${CYAN}║"
  echo -e "  ║  Inicio     : ${NC}$(date '+%H:%M:%S')$(printf '%*s' 31 '')${BOLD}${CYAN}║"
  echo "  ║                                                      ║"
  echo "  ║  Ctrl+C para detener y ver resumen final            ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${DIM}Esperando actividad en ${CONTAINER}...${NC}\n"
}

# ── Mostrar alerta ────────────────────────────────────────────
print_alert() {
  local json="$1"

  # Parsear JSON con python3
  read -r ts ip method endpoint vuln_type severity owasp payload detail <<< \
    "$(echo "$json" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(
        d.get('ts','?'),
        d.get('ip','?'),
        d.get('method','?'),
        d.get('endpoint','?'),
        d.get('type','UNKNOWN'),
        d.get('severity','?'),
        d.get('owasp','?'),
        d.get('payload','')[:60].replace(' ','_'),
        d.get('detail','')[:50].replace(' ','_')
    )
except: print('? ? ? ? UNKNOWN ? ? ? ?')
" 2>/dev/null)"

  # Elegir color y emoji según severidad
  local sev_color box_color icon
  case "$severity" in
    CRITICO) sev_color=$LRED;    box_color=$RED;    icon="🔴" ;;
    ALTO)    sev_color=$ORANGE;  box_color=$YELLOW; icon="🟠" ;;
    MEDIO)   sev_color=$YELLOW;  box_color=$YELLOW; icon="🟡" ;;
    *)       sev_color=$BLUE;    box_color=$BLUE;   icon="🔵" ;;
  esac

  # Restaurar espacios en payload y detail
  payload="${payload//_/ }"
  detail="${detail//_/ }"

  # Incrementar contadores
  inc TOTAL
  inc "${vuln_type}" 2>/dev/null || true
  local total; total=$(get TOTAL)

  # ── Caja de alerta ──────────────────────────────────────────
  echo -e "${box_color}┌─────────────────────────────────────────────────────────────┐${NC}"
  echo -e "${box_color}│${NC} ${icon}  ${BOLD}${sev_color}[${severity}]${NC} ${BOLD}${vuln_type}${NC}  ${DIM}(${owasp})${NC}  ${box_color}Alerta #${total}${NC}"
  echo -e "${box_color}├─────────────────────────────────────────────────────────────┤${NC}"
  echo -e "${box_color}│${NC}  ${CYAN}Timestamp${NC}  : ${ts}"
  echo -e "${box_color}│${NC}  ${CYAN}IP origen ${NC} : ${ip}   ${DIM}${method} ${endpoint}${NC}"
  echo -e "${box_color}│${NC}  ${CYAN}Payload   ${NC} : ${sev_color}${payload}${NC}"
  [[ -n "$detail" && "$detail" != "?" ]] && \
  echo -e "${box_color}│${NC}  ${CYAN}Detalle   ${NC} : ${DIM}${detail}${NC}"
  echo -e "${box_color}└─────────────────────────────────────────────────────────────┘${NC}"
  echo ""
}

# ── Resumen final ────────────────────────────────────────────
show_summary() {
  local total; total=$(get TOTAL)
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  RESUMEN DE SESIÓN DE MONITOREO${NC}"
  echo -e "${CYAN}  Fin: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
  echo -e "  ${BOLD}Total alertas disparadas: ${RED}${total}${NC}\n"

  if [[ "$total" -eq 0 ]]; then
    echo -e "  ${GREEN}Sin actividad maliciosa detectada durante la sesión.${NC}"
  else
    echo -e "  ${BOLD}Desglose por tipo:${NC}"
    for vt in "${VULN_TYPES[@]}"; do
      local cnt; cnt=$(get "$vt")
      if [[ "$cnt" -gt 0 ]]; then
        local bar=""
        for ((i=0; i<cnt && i<20; i++)); do bar+="█"; done
        printf "  %-22s ${RED}%3d${NC}  ${ORANGE}%s${NC}\n" "$vt" "$cnt" "$bar"
      fi
    done

    echo ""
    # Generar reporte automático de la sesión
    local report_file="./reportes/session_$(date '+%Y-%m-%d_%H-%M-%S').log"
    mkdir -p ./reportes
    {
      echo "=== VulnLab Session Report ==="
      echo "Date: $(date)"
      echo "Container: ${CONTAINER}"
      echo "Total alerts: ${total}"
      echo ""
      echo "--- Breakdown ---"
      for vt in "${VULN_TYPES[@]}"; do
        local cnt; cnt=$(get "$vt")
        [[ "$cnt" -gt 0 ]] && echo "${vt}: ${cnt}"
      done
    } > "$report_file"
    echo -e "  ${DIM}Log de sesión guardado en: ${report_file}${NC}"
  fi
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}\n"
}

# ── Live status bar ───────────────────────────────────────────
status_line() {
  local total; total=$(get TOTAL)
  local crit; crit=$(get CMD_INJECTION)
  local sqli; sqli=$(get SQL_INJECTION)
  local xss;  xss=$(get XSS)
  printf "\r  ${DIM}[monitor activo]${NC}  Alertas: ${RED}${total}${NC}  " >&2
  printf "SQLi:${YELLOW}${sqli}${NC}  XSS:${YELLOW}${xss}${NC}  CMDi:${RED}${crit}${NC}  " >&2
}

# ── Loop principal ────────────────────────────────────────────
main() {
  preflight
  print_banner
  tput civis 2>/dev/null  # ocultar cursor

  # Tail de los logs del contenedor, filtrando líneas [VULN_ALERT]
  docker logs -f --tail=0 "$CONTAINER" 2>&1 | \
  while IFS= read -r line; do
    if [[ "$line" == *"[VULN_ALERT]"* ]]; then
      # Extraer el JSON que sigue a [VULN_ALERT]
      json="${line#*[VULN_ALERT] }"
      print_alert "$json"
    fi
    status_line
  done
}

main
