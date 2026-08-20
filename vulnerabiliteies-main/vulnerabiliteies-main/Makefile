# ─────────────────────────────────────────────────────────────
#  VulnLab — Makefile para gestión con Colima + Docker Compose
#  Uso: make <target>
# ─────────────────────────────────────────────────────────────

# Recursos de la VM de Colima (ajustar según tu Mac)
COLIMA_CPU    ?= 2
COLIMA_MEMORY ?= 2
COLIMA_DISK   ?= 10
COLIMA_ARCH   ?= host   # host = misma arch que tu Mac (arm64 en Apple Silicon)

APP_URL       := http://localhost:8080
DASHBOARD_URL := http://localhost:8080/dashboard

.PHONY: help start stop restart status logs shell build clean reset open \
        colima-start colima-stop colima-status

# ── Ayuda ────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  VulnLab — comandos disponibles"
	@echo ""
	@echo "  make start      Inicia Colima + construye imagen + levanta contenedor"
	@echo "  make stop       Detiene contenedor + para Colima"
	@echo "  make restart    Reinicia solo el contenedor"
	@echo "  make status     Estado de Colima y del contenedor"
	@echo "  make logs       Logs en tiempo real del contenedor"
	@echo "  make shell      Shell interactiva dentro del contenedor"
	@echo "  make build      Reconstruye la imagen sin cache"
	@echo "  make open       Abre el dashboard en el navegador"
	@echo "  make clean      Elimina contenedor + red + imagen (conserva BD)"
	@echo "  make reset      Elimina TODO incluyendo la base de datos"
	@echo ""

# ── Flujo principal ──────────────────────────────────────────
start: colima-start build
	@echo "→ Levantando contenedor..."
	@docker compose up -d
	@echo ""
	@echo "  Esperando que la app esté lista..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		curl -sf $(APP_URL)/api/health > /dev/null 2>&1 && break; \
		printf "."; sleep 2; \
	done
	@echo ""
	@echo "  ✓ VulnLab listo"
	@echo "  App:       $(APP_URL)"
	@echo "  Dashboard: $(DASHBOARD_URL)"

stop:
	@echo "→ Deteniendo contenedor..."
	@docker compose down
	@$(MAKE) colima-stop

restart:
	@echo "→ Reiniciando contenedor..."
	@docker compose restart vulnlab
	@echo "  ✓ Reiniciado"

build:
	@echo "→ Construyendo imagen vulnlab..."
	@docker compose build --no-cache
	@echo "  ✓ Imagen lista"

# ── Colima ───────────────────────────────────────────────────
colima-start:
	@if colima status 2>/dev/null | grep -q "Running"; then \
		echo "  ✓ Colima ya está corriendo"; \
	else \
		echo "→ Iniciando Colima (cpu=$(COLIMA_CPU) mem=$(COLIMA_MEMORY)G disk=$(COLIMA_DISK)G)..."; \
		colima start \
			--cpu $(COLIMA_CPU) \
			--memory $(COLIMA_MEMORY) \
			--disk $(COLIMA_DISK) \
			--arch $(COLIMA_ARCH) \
			--network-address; \
		echo "  ✓ Colima iniciado"; \
	fi

colima-stop:
	@echo "→ Deteniendo Colima..."
	@colima stop
	@echo "  ✓ Colima detenido"

colima-status:
	@colima status 2>&1 || true

# ── Observabilidad ───────────────────────────────────────────
status: colima-status
	@echo ""
	@echo "── Contenedor ────────────────────────────────────"
	@docker compose ps
	@echo ""
	@echo "── Healthcheck ───────────────────────────────────"
	@docker inspect --format='Estado: {{.State.Status}} | Health: {{.State.Health.Status}}' \
		vulnlab 2>/dev/null || echo "  Contenedor no encontrado"
	@echo ""
	@echo "── Uso de recursos ───────────────────────────────"
	@docker stats vulnlab --no-stream --format \
		"  CPU: {{.CPUPerc}}  Mem: {{.MemUsage}}" 2>/dev/null || true

logs:
	@docker compose logs -f vulnlab

shell:
	@docker compose exec vulnlab /bin/bash

open:
	@open $(DASHBOARD_URL)

# ── Limpieza ─────────────────────────────────────────────────
clean:
	@echo "→ Eliminando contenedor e imagen (la BD se conserva)..."
	@docker compose down --remove-orphans
	@docker rmi vulnlab:latest 2>/dev/null || true
	@echo "  ✓ Limpieza completada"

reset:
	@echo "→ Eliminando TODO (contenedor, imagen, red, volúmenes)..."
	@docker compose down -v --remove-orphans
	@docker rmi vulnlab:latest 2>/dev/null || true
	@docker volume rm vulnlab_db 2>/dev/null || true
	@echo "  ✓ Reset completado — próximo 'make start' crea la BD desde cero"
