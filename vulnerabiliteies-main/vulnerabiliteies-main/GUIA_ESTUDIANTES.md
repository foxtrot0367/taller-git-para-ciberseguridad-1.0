# VulnLab — Guía de Pentesting con Python

> **Entorno controlado.** Todo lo que practiques aquí queda dentro de tu máquina local o red de laboratorio. Nunca uses estas técnicas contra sistemas sin autorización escrita.

---

## Tabla de contenidos

1. [Objetivos](#objetivos)
2. [Requisitos previos](#requisitos-previos)
3. [Poner en marcha el laboratorio](#poner-en-marcha-el-laboratorio)
4. [Módulo 1 — Reconocimiento y escaneo de puertos](#módulo-1--reconocimiento-y-escaneo-de-puertos)
5. [Módulo 2 — SQL Injection](#módulo-2--sql-injection)
6. [Módulo 3 — Cross-Site Scripting (XSS)](#módulo-3--cross-site-scripting-xss)
7. [Módulo 4 — Command Injection](#módulo-4--command-injection)
8. [Módulo 5 — IDOR y enumeración de API](#módulo-5--idor-y-enumeración-de-api)
9. [Módulo 6 — Reconocimiento completo y reporte](#módulo-6--reconocimiento-completo-y-reporte)
10. [Dashboard web](#dashboard-web)
11. [Retos finales](#retos-finales)
12. [Glosario](#glosario)

---

## Objetivos

Al terminar este laboratorio serás capaz de:

- Explicar las vulnerabilidades OWASP Top 10 más comunes.
- Usar Python para automatizar escaneos y ataques en un entorno controlado.
- Leer e interpretar respuestas HTTP para detectar fallos de seguridad.
- Generar un reporte básico de hallazgos como lo haría un pentester profesional.

---

## Requisitos previos

| Herramienta | Versión mínima | Verificar |
|-------------|---------------|-----------|
| Python      | 3.10+         | `python --version` |
| Docker      | 24+           | `docker --version` |
| Docker Compose | 2+         | `docker compose version` |
| curl / navegador web | cualquiera | — |

Conocimientos recomendados:
- HTTP (métodos GET/POST, códigos de estado, cabeceras)
- SQL básico (SELECT, WHERE, UNION)
- Terminal / línea de comandos

---

## Poner en marcha el laboratorio

### Opción A — Docker (recomendada)

```bash
# 1. Clona o descarga el proyecto
cd vulnerabiliteies/

# 2. Levanta los contenedores
docker compose -f setup/docker-compose.yml up --build -d

# 3. Verifica que esté corriendo
docker compose -f setup/docker-compose.yml ps

# 4. Abre en el navegador
#    App vulnerable:  http://localhost:5000
#    Dashboard:       http://localhost:5000/dashboard
```

Para detenerlo:
```bash
docker compose -f setup/docker-compose.yml down
```

### Opción B — Python local

```bash
pip install flask requests

cd vulnerable_app/
python app.py
# → http://127.0.0.1:5000
```

### Verificar que todo funciona

```bash
curl http://localhost:5000/
# Debe devolver HTML con los enlaces a cada módulo
```

---

## Módulo 1 — Reconocimiento y escaneo de puertos

### Teoría

El reconocimiento (*recon*) es la primera fase de cualquier pentest. Antes de atacar, necesitas saber:

1. **¿Qué puertos están abiertos?** → cada puerto abierto es una superficie de ataque potencial.
2. **¿Qué servicio corre en cada puerto?** → el servicio determina qué técnicas aplicar.
3. **¿Qué banner expone el servidor?** → los banners revelan versiones que pueden tener CVEs conocidos.

Herramientas profesionales como **nmap** hacen esto. Nosotros lo haremos desde cero con Python para entender cómo funciona por dentro.

### Cómo funciona el script

```
01_port_scanner.py
│
├── scan_port()      → intenta TCP connect() al puerto
├── grab_banner()    → envía HTTP HEAD y lee la respuesta
└── scan()           → lanza N hilos concurrentes (ThreadPoolExecutor)
```

`socket.connect_ex()` devuelve `0` si la conexión fue exitosa (puerto abierto) y un código de error si no. Usar múltiples hilos reduce el tiempo de escaneo de minutos a segundos.

### Práctica

```bash
cd pentesting_scripts/

# Escanea los puertos 1-9000 en localhost
python 01_port_scanner.py 127.0.0.1 1 9000
```

Salida esperada:
```
[*] Escaneando 127.0.0.1 puertos 1-9000
[*] Inicio: 14:32:01

  [ABIERTO] 5000/tcp  unknown         HTTP/1.1 200 OK...

[*] 1 puertos abiertos encontrados
```

### Preguntas de reflexión

1. ¿Por qué usamos `ThreadPoolExecutor` en lugar de un bucle simple?
2. ¿Qué información útil nos da el banner del servicio?
3. ¿Cómo cambiarías el script para detectar puertos UDP?

---

## Módulo 2 — SQL Injection

### Teoría

SQL Injection ocurre cuando la aplicación **concatena** directamente el input del usuario en una query SQL sin sanitizarlo.

**Código vulnerable (lo que hace nuestra app):**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

Si el usuario escribe `' OR '1'='1` como usuario, la query queda:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='x'
```

`'1'='1'` siempre es verdadero → la query devuelve todos los usuarios → login bypasseado.

### Tipos de SQLi que practicarás

| Tipo | Técnica | Cuándo usarla |
|------|---------|---------------|
| In-band | UNION SELECT | Cuando la respuesta muestra datos |
| Error-based | Provocar error SQL | Cuando el error se muestra en pantalla |
| Blind time-based | `sleep()` | Cuando no hay output visible |

### Práctica

```bash
python 02_sqli_tester.py
```

**Prueba manual en el navegador:**

1. Ve a `http://localhost:5000/login`
2. En el campo usuario escribe: `' OR '1'='1`
3. En contraseña escribe: `cualquiercosa`
4. Haz clic en Entrar — deberías iniciar sesión sin credenciales válidas

**Extraer la base de datos con UNION:**

Ve a `http://localhost:5000/search` y en el campo de búsqueda escribe:
```
' UNION SELECT 1,username,password,role,email FROM users--
```

Verás todos los usuarios con sus contraseñas en texto claro.

### Cómo se previene

```python
# CORRECTO: usar parámetros preparados
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```

Los parámetros `?` hacen que el driver SQL trate el input como dato, nunca como código.

### Preguntas de reflexión

1. ¿Por qué `-- ` (doble guión + espacio) al final de un payload comenta el resto de la query?
2. ¿Qué diferencia hay entre SQLi in-band y blind?
3. ¿Cómo detectarías una SQLi si la aplicación no muestra errores?

---

## Módulo 3 — Cross-Site Scripting (XSS)

### Teoría

XSS ocurre cuando la aplicación refleja input del usuario en el HTML **sin codificarlo**. El navegador de la víctima ejecuta el script como si fuera código legítimo de la página.

**Impacto real:**
- Robo de cookies de sesión → secuestro de cuenta
- Redirigir al usuario a páginas falsas (phishing)
- Keylogging dentro de la página
- Defacement

**En nuestra app vulnerable:**
```python
# El template usa |safe — desactiva el escape de Jinja2
<div>Resultados para: {{ query|safe }}</div>
```

### Práctica

```bash
python 03_xss_scanner.py
```

**Prueba manual:**

Ve a `http://localhost:5000/search?q=<script>alert(document.cookie)</script>`

Si el navegador muestra una alerta con las cookies, la vulnerabilidad existe.

**Payloads alternativos (por si el navegador bloquea `<script>`):**
```html
<img src=x onerror=alert('XSS')>
<svg onload=alert(1)>
"><script>alert(1)</script>
```

### El script también verifica cabeceras de seguridad

| Cabecera | Para qué sirve |
|----------|---------------|
| `Content-Security-Policy` | Restringe qué scripts pueden ejecutarse |
| `X-XSS-Protection` | Activa el filtro XSS del navegador (legacy) |
| `X-Frame-Options` | Previene clickjacking |

### Cómo se previene

```python
# En Jinja2, NUNCA usar |safe con input del usuario
# Usar simplemente {{ query }} — Jinja2 escapa automáticamente
<div>Resultados para: {{ query }}</div>
```

### Preguntas de reflexión

1. ¿Cuál es la diferencia entre XSS reflejado y XSS almacenado?
2. ¿Cómo robarías la cookie de sesión de otro usuario con XSS?
3. ¿Por qué `Content-Security-Policy` es más efectivo que `X-XSS-Protection`?

---

## Módulo 4 — Command Injection

### Teoría

Command Injection es probablemente la vulnerabilidad más grave que existe: permite ejecutar **comandos del sistema operativo** directamente en el servidor.

Ocurre cuando la aplicación usa el input del usuario en una llamada al sistema operativo con `shell=True`:

```python
# VULNERABLE
subprocess.run(f"ping -c 1 {host}", shell=True)
```

Con `shell=True`, el sistema operativo interpreta operadores como `;`, `&&`, `|`:
- `127.0.0.1; id` → ejecuta ping Y luego `id`
- `127.0.0.1 && whoami` → ejecuta ping, si tiene éxito ejecuta `whoami`
- `127.0.0.1 | cat /etc/passwd` → pipe: la salida del ping se reemplaza por `/etc/passwd`

### Práctica

```bash
python 04_command_injection.py
```

**Prueba manual:**

1. Ve a `http://localhost:5000/ping`
2. En el campo Host escribe: `127.0.0.1; id`
3. Deberías ver la salida del ping seguida del output de `id`

**Payloads para explorar:**
```
127.0.0.1; whoami
127.0.0.1; ls /tmp
127.0.0.1; cat /etc/passwd
127.0.0.1; env
```

### Blind Command Injection (cuando no hay output)

Si la aplicación no muestra la salida del comando, puedes usar time-based:
```
127.0.0.1; sleep 5
```
Si la respuesta tarda 5 segundos, hay command injection aunque no veas el output.

### Cómo se previene

```python
# CORRECTO: lista de argumentos sin shell=True
import shlex
args = ["ping", "-c", "1", host]
subprocess.run(args, shell=False, timeout=3)

# O validar con lista blanca
import re
if not re.match(r'^[\d.]+$', host):
    return "Host inválido"
```

### Preguntas de reflexión

1. ¿Por qué `shell=False` con lista de argumentos previene command injection?
2. ¿Qué es blind command injection y cómo lo detectarías?
3. ¿Qué daño podría hacer un atacante con acceso RCE en un servidor de producción?

---

## Módulo 5 — IDOR y enumeración de API

### Teoría

**IDOR (Insecure Direct Object Reference)** ocurre cuando la aplicación usa identificadores predecibles (como IDs numéricos) para acceder a recursos, sin verificar que el usuario tenga permiso.

```
/notes?id=1  → nota del admin (¿debería verla cualquiera?)
/notes?id=2  → nota de Alice
/notes?id=3  → nota de Bob
```

Si cambiando el `id` en la URL puedes ver datos de otros usuarios, hay IDOR.

**Broken Authentication** en la API: la app usa un token hardcodeado `token123` que cualquiera puede descubrir con fuerza bruta.

### Práctica

```bash
python 05_idor_scanner.py
```

**Prueba manual:**

1. Sin iniciar sesión, ve a `http://localhost:5000/notes?id=1`
2. Verás la nota privada del admin (contiene una flag)
3. Prueba los IDs del 1 al 5

**Enumeración de la API:**
```bash
# Sin token
curl http://localhost:5000/api/users
# → 401 Unauthorized

# Con el token correcto
curl -H "X-Token: token123" http://localhost:5000/api/users
# → Lista completa de usuarios
```

### Cómo se previene

```python
# CORRECTO: verificar autorización en cada acceso
@app.route("/notes")
def notes():
    if "user_id" not in session:
        return redirect("/login")
    note_id = request.args.get("id")
    note = db.execute(
        "SELECT * FROM notes WHERE id=? AND user_id=?",
        (note_id, session["user_id"])  # solo notas del usuario en sesión
    ).fetchone()
```

### Preguntas de reflexión

1. ¿Por qué los UUIDs son más seguros que los IDs numéricos para IDOR?
2. ¿Cómo automatizarías la búsqueda de IDOR en una aplicación con 50 endpoints?
3. ¿Qué es el principio de mínimo privilegio y cómo aplica aquí?

---

## Módulo 6 — Reconocimiento completo y reporte

### Teoría

En un pentest real, el flujo es:

```
Reconocimiento → Escaneo → Explotación → Post-explotación → Reporte
```

El **reporte** es el producto final que entrega valor al cliente. Debe incluir:
- Severidad de cada hallazgo (CVSS o escala propia)
- Evidencia reproducible (capturas, payloads exactos)
- Recomendación de remediación
- Impacto en el negocio

### Práctica

```bash
python 06_full_recon.py
```

Esto ejecutará todos los módulos automáticamente y generará `recon_report.json`.

**Ver el reporte:**
```bash
cat recon_report.json | python -m json.tool
```

### Estructura del reporte generado

```json
{
  "target": "http://127.0.0.1:5000",
  "date": "2024-01-15 14:32:01",
  "findings": [
    {
      "severity": "CRITICO",
      "title": "SQL Injection en /login",
      "detail": "Payload: ' OR '1'='1"
    }
  ]
}
```

### Escala de severidad

| Nivel | Descripción | Ejemplo |
|-------|-------------|---------|
| CRÍTICO | Compromiso total del sistema | RCE, SQLi con dump de DB |
| ALTO | Acceso no autorizado a datos sensibles | IDOR, XSS con robo de sesión |
| MEDIO | Configuración incorrecta sin impacto directo | Cabeceras de seguridad ausentes |
| INFO | Hallazgo informativo | Versiones de software expuestas |

---

## Dashboard web

El laboratorio incluye un dashboard interactivo accesible en:

```
http://localhost:5000/dashboard
```

Desde el dashboard puedes:
- Probar cada vulnerabilidad con formularios interactivos
- Ver los resultados en tiempo real en un terminal simulado
- Ejecutar el escaneo completo con un solo botón
- Ver las cabeceras HTTP de respuesta

---

## Retos finales

Completa estos retos en orden de dificultad:

### Nivel 1 — Básico
- [ ] Extrae la lista completa de usuarios de la base de datos usando SQLi UNION en `/search`
- [ ] Accede a la nota secreta del admin en `/notes` sin credenciales
- [ ] Obtén el valor de `secret_key` desde `/info`

### Nivel 2 — Intermedio
- [ ] Encuentra el token de API válido mediante fuerza bruta (script Python)
- [ ] Usa XSS para mostrar `document.cookie` en el navegador
- [ ] Ejecuta el comando `id` en el servidor mediante Command Injection

### Nivel 3 — Avanzado
- [ ] Encadena SQLi + session hijacking: extrae la `secret_key`, forja una cookie de sesión con `flask` y accede como admin
- [ ] Modifica `06_full_recon.py` para exportar el reporte en formato HTML además de JSON
- [ ] Agrega detección de **Open Redirect** al suite de pentesting

### Flag del laboratorio
Cada módulo tiene una flag oculta. Encuéntralas todas:
- `FLAG{sql_injection_found}` — en la nota del admin vía IDOR o SQLi
- `FLAG{cmd_injection_rce}` — ejecuta `cat /flag.txt` en el servidor
- `FLAG{api_token_brute}` — llama a `/api/users` con el token correcto

---

## Glosario

| Término | Definición |
|---------|-----------|
| **SQLi** | SQL Injection — inyección de código SQL en queries de la aplicación |
| **XSS** | Cross-Site Scripting — ejecución de JS malicioso en el navegador de la víctima |
| **RCE** | Remote Code Execution — ejecución de comandos en el servidor |
| **IDOR** | Insecure Direct Object Reference — acceso a recursos de otros usuarios cambiando un ID |
| **OWASP** | Open Web Application Security Project — organización que publica el Top 10 de vulnerabilidades web |
| **Payload** | Código o datos enviados para explotar una vulnerabilidad |
| **Banner grabbing** | Técnica para obtener la versión de un servicio desde su mensaje de bienvenida |
| **Blind injection** | Variante donde no hay output visible — se detecta por tiempo o efectos secundarios |
| **Parametrized query** | Query SQL que usa `?` como placeholders — previene SQLi |
| **CSP** | Content Security Policy — cabecera HTTP que restringe recursos en la página |
| **CVSS** | Common Vulnerability Scoring System — escala estándar de severidad 0-10 |
| **Recon** | Reconocimiento — primera fase de un pentest |
| **Pentesting** | Penetration testing — simulación autorizada de un ataque para encontrar vulnerabilidades |
