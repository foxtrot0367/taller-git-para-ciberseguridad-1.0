# OWASP Top 10 — 2021

> OWASP (Open Web Application Security Project) publica cada pocos años la lista de las 10 categorías de vulnerabilidades más críticas en aplicaciones web. Esta guía las documenta con definición, ejemplo de código vulnerable vs. seguro, y su relación con VulnLab.

---

## A01:2021 — Broken Access Control

**Descripción:** Los controles de acceso no se aplican correctamente. Los usuarios pueden actuar fuera de sus permisos previstos, accediendo a datos de otros usuarios o funciones de administrador.

**Ejemplos comunes:**
- Acceder a la cuenta de otro usuario modificando un ID en la URL (`/notes?id=1` sin validar quién es el dueño).
- Escalar privilegios de usuario normal a administrador.
- Acceder a la API sin autenticación porque el control solo está en el frontend.

**En VulnLab:** Módulo IDOR (`/notes?id=N`) y API sin token (`/api/users`).

**Código vulnerable:**
```python
@app.route("/notes")
def notes():
    note_id = request.args.get("id")
    note = db.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone()
    return note["content"]  # No verifica que el user_id de la sesión sea el dueño
```

**Código seguro:**
```python
@app.route("/notes")
def notes():
    if "user_id" not in session:
        return redirect("/login")
    note_id = request.args.get("id")
    note = db.execute(
        "SELECT * FROM notes WHERE id=? AND user_id=?",
        (note_id, session["user_id"])
    ).fetchone()
    if not note:
        abort(403)
    return note["content"]
```

**Remediación:**
- Implementar control de acceso en el servidor, nunca en el cliente.
- Por defecto denegar acceso — permitir solo lo explícitamente autorizado.
- Usar UUIDs o tokens opacos en lugar de IDs numéricos secuenciales.
- Registrar fallos de control de acceso y alertar al equipo de seguridad.

---

## A02:2021 — Cryptographic Failures

**Descripción:** Exposición de datos sensibles por fallos relacionados con criptografía: almacenamiento de contraseñas en texto claro, uso de algoritmos obsoletos (MD5, SHA1), transmisión de datos sin HTTPS.

**Ejemplos comunes:**
- Contraseñas almacenadas como texto plano en la base de datos.
- Uso de MD5 para hashear contraseñas (reversible en segundos con rainbow tables).
- Datos sensibles transmitidos por HTTP sin TLS.
- Claves criptográficas hardcodeadas en el código fuente.

**En VulnLab:** La BD almacena contraseñas en texto claro. El endpoint `/info` expone la `secret_key`.

**Código vulnerable:**
```python
# Almacenar password en texto claro
db.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, role))

# Usar MD5 (obsoleto)
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
```

**Código seguro:**
```python
import bcrypt

# Hashear con bcrypt (factor de trabajo adaptable)
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
db.execute("INSERT INTO users VALUES (?, ?, ?)", (username, hashed, role))

# Verificar
bcrypt.checkpw(input_password.encode(), stored_hash)
```

**Remediación:**
- Usar bcrypt, scrypt o Argon2 para contraseñas (nunca MD5/SHA1/SHA256 directos).
- Habilitar TLS 1.2+ en todos los endpoints.
- Almacenar claves en variables de entorno o gestores de secretos (Vault, AWS Secrets Manager).
- No cachear datos sensibles en respuestas HTTP.

---

## A03:2021 — Injection

**Descripción:** El input del usuario se interpreta como código (SQL, OS, LDAP, NoSQL, XPath). Incluye SQL Injection, Command Injection, XSS y otras formas de inyección.

**Es la categoría con más CVEs y el mayor impacto potencial.**

**Ejemplos comunes:**
- SQL Injection: `' OR '1'='1` en un campo de login.
- Command Injection: `127.0.0.1; cat /etc/passwd` en un campo de ping.
- XSS: `<script>alert(1)</script>` en un buscador que muestra el resultado sin escapar.

**En VulnLab:** Módulos SQLi (`/login`, `/search`), Command Injection (`/ping`), XSS (`/search`).

**Código vulnerable:**
```python
# SQL Injection
query = f"SELECT * FROM users WHERE username='{username}'"

# Command Injection
subprocess.run(f"ping -c 1 {host}", shell=True)

# XSS (template Jinja2)
return f"<div>Resultados para: {query}</div>"  # Sin escapar
```

**Código seguro:**
```python
# SQL — parámetros preparados
cursor.execute("SELECT * FROM users WHERE username=?", (username,))

# Command — lista de argumentos, sin shell
subprocess.run(["ping", "-c", "1", host], shell=False)

# XSS — escapar siempre en Jinja2 (default), nunca usar |safe con input del usuario
return render_template("search.html", query=query)  # Jinja2 escapa automáticamente
```

**Remediación:**
- Usar ORMs o parámetros preparados para todas las queries.
- Validar input con listas blancas (no listas negras).
- Escapar output en el contexto correcto (HTML, JS, CSS, URL).
- Activar WAF como capa de defensa adicional (no sustituto).

---

## A04:2021 — Insecure Design

**Descripción:** Fallos en la fase de diseño del sistema. No es un fallo de implementación sino de arquitectura: la lógica de negocio no contempla escenarios de abuso.

**Ejemplos comunes:**
- Un sistema de recuperación de contraseña que pregunta "¿Cuál es el nombre de tu mascota?" (pregunta de seguridad débil).
- Un carrito de compras que permite cantidades negativas para obtener reembolsos.
- Un sistema de reservas que no limita el número de reservas por usuario.
- Flujos de autenticación multifactor que pueden ser omitidos.

**En VulnLab:** La app no tiene rate limiting en el login — permite fuerza bruta sin restricciones.

**Código vulnerable:**
```python
# Sin rate limiting — permite N intentos ilimitados
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (username, password)).fetchone()
```

**Código seguro:**
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # Máximo 5 intentos por minuto por IP
def login():
    ...
```

**Remediación:**
- Realizar threat modeling en la fase de diseño.
- Definir casos de abuso junto con los casos de uso.
- Implementar rate limiting, lockout y CAPTCHA en flujos sensibles.
- Revisar lógica de negocio con pruebas de integración que simulen abuso.

---

## A05:2021 — Security Misconfiguration

**Descripción:** Configuraciones por defecto inseguras, configuraciones incompletas, servicios innecesarios habilitados, mensajes de error que revelan información interna.

**Ejemplos comunes:**
- Flask en modo `debug=True` en producción (expone el debugger interactivo).
- Página de administración accesible sin autenticación.
- Headers de seguridad HTTP ausentes (CSP, HSTS, X-Frame-Options).
- Credenciales por defecto no cambiadas (admin/admin).
- Directorio listing habilitado en el servidor web.

**En VulnLab:** El endpoint `/info` expone la configuración completa del servidor. El app corre con `debug=True`. El endpoint `/upload` acepta cualquier tipo de archivo sin validar extensión ni tamaño, y es vulnerable a **path traversal** mediante el nombre del archivo.

**Endpoint `/upload` vulnerable:**
```python
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    # VULNERABLE 1: sin validación de extensión
    # VULNERABLE 2: path traversal — f.filename puede ser "../../../etc/cron.d/backdoor"
    # VULNERABLE 3: sin límite de tamaño
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
```

**Endpoint `/upload` seguro:**
```python
import magic
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf"}
MAX_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        abort(400)

    # 1. Nombre seguro — elimina path traversal
    filename = secure_filename(f.filename)

    # 2. Extensión en lista blanca
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400, f"Extensión no permitida: {ext}")

    # 3. Verificar tipo MIME real (no el que declara el cliente)
    content = f.read(2048)
    mime = magic.from_buffer(content, mime=True)
    if mime not in {"image/png", "image/jpeg", "image/gif", "application/pdf"}:
        abort(400, f"Tipo de archivo no permitido: {mime}")

    # 4. Límite de tamaño
    f.seek(0, 2)
    if f.tell() > MAX_SIZE_BYTES:
        abort(400, "Archivo demasiado grande")

    f.seek(0)
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)
```

**Configuración vulnerable:**
```python
app.run(debug=True, host="0.0.0.0")  # Debug en producción = RCE
app.secret_key = "supersecret123"    # Clave débil hardcodeada
```

**Configuración segura:**
```python
import secrets, os

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")

# Agregar cabeceras de seguridad
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
```

**Remediación:**
- Usar checklist de hardening para cada tecnología (OWASP, CIS Benchmarks).
- Eliminar endpoints de debug, administración y diagnóstico en producción.
- Gestionar secretos con variables de entorno o Vault.
- Implementar un proceso de revisión de configuración en CI/CD.

---

## A06:2021 — Vulnerable and Outdated Components

**Descripción:** Uso de librerías, frameworks o componentes con vulnerabilidades conocidas (CVEs públicos). Muchas brechas se producen por no actualizar dependencias.

**Ejemplos comunes:**
- Flask 1.x con vulnerabilidades de inyección de template conocidas.
- jQuery 1.x con XSS conocido.
- Log4j con Log4Shell (CVE-2021-44228).
- Sistema operativo del servidor sin parches de seguridad.

**Cómo detectarlo:**

```bash
# Python — auditar dependencias
pip audit

# Node.js
npm audit

# Verificar CVEs de una librería específica
pip index versions flask
# Buscar en https://nvd.nist.gov/vuln/search
```

**En VulnLab:** Instala dependencias sin versiones fijas — puede descargar versiones vulnerables.

**requirements.txt vulnerable:**
```
flask
requests
```

**requirements.txt seguro:**
```
flask==3.0.3
requests==2.31.0
flask-cors==4.0.1
```

**Remediación:**
- Fijar versiones exactas en `requirements.txt` / `package-lock.json`.
- Usar `pip audit` o `dependabot` para alertas automáticas de CVEs.
- Implementar política de actualización periódica (ej. cada sprint).
- Escanear imágenes Docker con Trivy o Snyk.

---

## A07:2021 — Identification and Authentication Failures

**Descripción:** Fallos en la implementación de autenticación e identificación: contraseñas débiles, tokens predecibles, falta de MFA, sesiones que no expiran, fuerza bruta sin protección.

**Ejemplos comunes:**
- Token de API hardcodeado (`token123`).
- Contraseñas de 4 caracteres sin restricciones.
- Sesiones que nunca expiran.
- Ausencia de MFA en cuentas privilegiadas.
- IDs de sesión predecibles o cortos.

**En VulnLab:** Token de API `token123` hardcodeado, contraseñas débiles en BD, `secret_key` débil.

**Código vulnerable:**
```python
API_TOKEN = "token123"  # Hardcodeado y débil

@app.route("/api/users")
def api_users():
    if request.headers.get("X-Token") != API_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401
```

**Código seguro:**
```python
import secrets, os
from functools import wraps

API_TOKEN = os.environ["API_TOKEN"]  # Token en variable de entorno, generado con secrets.token_urlsafe(32)

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not secrets.compare_digest(token, API_TOKEN):  # Comparación en tiempo constante
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated
```

**Remediación:**
- Generar tokens con `secrets.token_urlsafe(32)` — nunca inventarlos manualmente.
- Usar `secrets.compare_digest()` para comparar tokens (previene timing attacks).
- Implementar expiración de sesión y tokens.
- Obligar contraseñas de al menos 12 caracteres y verificar contra listas de passwords comunes.
- Implementar MFA para cuentas con privilegios.

---

## A08:2021 — Software and Data Integrity Failures

**Descripción:** El software o datos críticos no se verifican contra modificaciones no autorizadas. Incluye descargas sin verificar firmas, pipelines CI/CD sin control de integridad, deserialización insegura.

**Ejemplos comunes:**
- Cargar JavaScript desde CDN sin Subresource Integrity (SRI).
- Deserializar objetos Python con `pickle` de fuentes no confiables.
- Pipeline CI/CD que descarga dependencias sin verificar hashes.
- Actualización automática de software sin firma digital.

**En VulnLab:** El endpoint `/deserialize` acepta un objeto Python serializado en base64 y lo deserializa con `pickle.loads()` sin ninguna validación. Cualquier payload que implemente `__reduce__` ejecutará código arbitrario en el servidor.

**Cómo generar el payload de ataque:**
```python
# Ejecuta esto en tu máquina atacante para generar el payload
import pickle, os, base64

class RCE:
    def __reduce__(self):
        # Este comando se ejecutará en el SERVIDOR al deserializar
        return (os.system, ('id > /tmp/pwned.txt',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
# Luego pega ese base64 en el formulario /deserialize
```

**Endpoint `/deserialize` vulnerable:**
```python
@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.form.get("data", "")
    raw = base64.b64decode(data)
    obj = pickle.loads(raw)      # ← RCE: ejecuta __reduce__ del objeto
    return str(obj)
```

**Endpoint `/deserialize` seguro:**
```python
import json
from jsonschema import validate

SCHEMA = {"type": "object", "properties": {"name": {"type": "string"}}}

@app.route("/deserialize", methods=["POST"])
def deserialize():
    # Nunca usar pickle con input externo — solo JSON con validación de esquema
    try:
        obj = json.loads(request.form.get("data", "{}"))
        validate(obj, SCHEMA)
        return jsonify(obj)
    except Exception:
        abort(400, "Datos inválidos")
```

**SRI para recursos CDN:**
```html
<!-- VULNERABLE: sin verificación de integridad -->
<script src="https://cdn.example.com/jquery.min.js"></script>

<!-- SEGURO: con Subresource Integrity -->
<script src="https://cdn.example.com/jquery.min.js"
        integrity="sha384-HASH_AQUI"
        crossorigin="anonymous"></script>
```

**Remediación:**
- **Nunca usar `pickle`, `marshal` o `yaml.load()` (sin Loader)** con datos de usuarios externos.
- Usar JSON con validación de esquema (`jsonschema`) para datos estructurados.
- Verificar firmas digitales de paquetes descargados.
- Usar SRI para recursos de CDN externos.
- Implementar revisión de código y aprobaciones en pipelines CI/CD.

---

## A09:2021 — Security Logging and Monitoring Failures

**Descripción:** Sin logging adecuado, los ataques no se detectan ni se puede responder a tiempo. La mayoría de las brechas tardan más de 200 días en detectarse.

**En VulnLab:** El endpoint `/admin` permite fuerza bruta ilimitada sin que quede ningún registro. El endpoint `/admin-safe` es la versión correcta del mismo endpoint — escribe en `/tmp/security.log` cada intento de acceso. Puedes comparar ambos en vivo.

**Qué se debe registrar:**
- Todos los intentos de autenticación (éxito y fallo).
- Cambios de privilegios y accesos a datos sensibles.
- Errores de validación de input (posibles intentos de inyección).
- Eventos de administración del sistema.

**Endpoint `/admin` vulnerable — sin logging:**
```python
@app.route("/admin")
def admin():
    password = request.args.get("password", "")
    # VULNERABLE: cero logging — un atacante puede probar miles de passwords
    # sin dejar rastro en ningún archivo de log
    if password == "admin123":
        return jsonify({"status": "ok", "users": get_all_users()})
    return jsonify({"error": "forbidden"}), 403
```

**Endpoint `/admin-safe` seguro — con logging:**
```python
import logging

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
handler = logging.FileHandler("/var/log/app/security.log")
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
security_logger.addHandler(handler)

@app.route("/admin-safe")
def admin_safe():
    ip = request.remote_addr
    password = request.args.get("password", "")
    if password == "admin123":
        security_logger.info(f"ADMIN_LOGIN_OK ip={ip}")
        return jsonify({"status": "ok", "users": get_all_users()})
    security_logger.warning(f"ADMIN_LOGIN_FAIL ip={ip} pwd_len={len(password)}")
    return jsonify({"error": "forbidden"}), 403

# Una alerta simple sobre fuerza bruta
# Si hay más de 5 WARNING en 60s desde la misma IP → enviar alerta al equipo
```

**Prueba práctica — comparar los dos endpoints:**
```bash
# Sin logging: no queda rastro
for p in admin 1234 qwerty admin123; do
    curl -s "http://localhost:5000/admin?password=$p" | python -m json.tool
done

# Con logging: genera entradas en /tmp/security.log
for p in admin 1234 qwerty admin123; do
    curl -s "http://localhost:5000/admin-safe?password=$p" | python -m json.tool
done

# Ver los logs generados
cat /tmp/security.log
```

**Remediación:**
- Implementar logging centralizado (ELK Stack, Splunk, CloudWatch).
- Crear alertas para: N fallos de login por minuto, accesos fuera de horario, escalada de privilegios.
- Conservar logs por mínimo 12 meses con retención inmutable.
- Proteger logs contra modificación (write-only, almacenamiento separado).
- Correlacionar eventos entre servicios para detectar ataques distribuidos.

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Descripción:** La aplicación obtiene recursos remotos usando URLs proporcionadas por el usuario sin validarlas. Un atacante puede hacer que el servidor realice peticiones a servicios internos no expuestos públicamente.

**Ejemplos comunes:**
- Funcionalidad de "previsualizar URL" que accede a `http://169.254.169.254` (metadata de AWS).
- Webhooks que permiten apuntar a servicios internos (`http://redis:6379`).
- Importación de imágenes por URL que accede a la red interna.

**Impacto en entornos cloud:** El endpoint de metadata de AWS `169.254.169.254` devuelve credenciales temporales del rol IAM del servidor. Con una sola petición SSRF un atacante puede obtener acceso a toda la infraestructura cloud.

**En VulnLab:** El endpoint `/fetch?url=` obtiene cualquier URL sin validación de host ni de esquema. Prueba los siguientes ataques:

| Payload SSRF | Qué obtiene |
|---|---|
| `http://127.0.0.1:5000/info` | Config interna (secret_key, env vars) |
| `http://127.0.0.1:5000/api/users` | Lista de usuarios sin token |
| `file:///etc/passwd` | Archivo local del servidor |
| `http://169.254.169.254/latest/meta-data/` | Metadata AWS (en entornos cloud) |

**Endpoint `/fetch` vulnerable:**
```python
import urllib.request

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # VULNERABLE: acepta cualquier esquema y host incluyendo:
    #   file:///etc/passwd        → lectura de archivos locales
    #   http://127.0.0.1:5000/   → servicios internos
    #   http://169.254.169.254/  → metadata cloud
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=4) as resp:
        return resp.read(4096).decode(errors="replace")
```

**Endpoint `/fetch` seguro:**
```python
from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_SCHEMES  = {"https"}   # Solo HTTPS — no file://, no http://
ALLOWED_DOMAINS  = {"api.example.com", "cdn.example.com"}  # Lista blanca explícita

def resolve_and_validate(hostname: str) -> None:
    """Resuelve el hostname y verifica que la IP no sea privada."""
    try:
        ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError(f"IP privada/reservada no permitida: {ip}")
    except socket.gaierror:
        raise ValueError("Hostname no resoluble")

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        abort(400, f"Esquema no permitido: {parsed.scheme}")

    if parsed.hostname not in ALLOWED_DOMAINS:
        abort(400, f"Dominio no en lista blanca: {parsed.hostname}")

    try:
        resolve_and_validate(parsed.hostname)
    except ValueError as e:
        abort(400, str(e))

    resp = requests.get(url, timeout=5, allow_redirects=False)  # Sin seguir redirects
    return resp.content
```

**Remediación:**
- Usar **listas blancas de dominios** — nunca listas negras (siempre hay formas de eludir).
- Resolver el hostname a IP y verificar que no sea privada/loopback **después** de la resolución DNS (previene DNS rebinding).
- Permitir solo esquemas `https://` — bloquear `file://`, `ftp://`, `gopher://`, `dict://`.
- Deshabilitar redirecciones HTTP (`allow_redirects=False`).
- Aislar la funcionalidad de fetch en una red sin acceso a servicios internos.
- En AWS/GCP/Azure: activar IMDSv2 (requiere token de sesión para acceder a metadata).

---

## Resumen de remediaciones

| Categoría | Solución clave |
|-----------|---------------|
| A01 Broken Access Control | Verificar autorización en servidor en cada request |
| A02 Crypto Failures | bcrypt para passwords, TLS, secretos en env vars |
| A03 Injection | Parámetros preparados, escapar output, sin shell=True |
| A04 Insecure Design | Threat modeling, rate limiting, lockout |
| A05 Misconfiguration | Hardening checklist, sin debug en prod, security headers |
| A06 Outdated Components | pip audit, versiones fijas, actualizaciones periódicas |
| A07 Auth Failures | Tokens con secrets.token_urlsafe, MFA, expiración |
| A08 Integrity Failures | SRI en CDN, no pickle de input externo, firmas |
| A09 Logging Failures | Log centralizado, alertas en tiempo real |
| A10 SSRF | Validar URLs, lista blanca de destinos, segmentación de red |

---

## Recursos adicionales

- [OWASP Top 10 oficial (2021)](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NVD — Base de CVEs](https://nvd.nist.gov/)
- [HackTricks — Técnicas de pentesting](https://book.hacktricks.xyz/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — laboratorios gratuitos
