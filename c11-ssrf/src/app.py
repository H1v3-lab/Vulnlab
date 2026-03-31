# VulnLab C11 — Server-Side Request Forgery (SSRF)
# VULNÉRABILITÉ : l'app fait des requêtes HTTP vers n'importe quelle URL fournie par l'utilisateur
from flask import Flask, request, render_template_string
import requests as req_lib, socket

app = Flask(__name__)

# Service interne simulé (accessible uniquement depuis le container)
INTERNAL_ENDPOINTS = {
    "http://localhost:8080/admin":  '{"status":"ok","flag":"FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}","users":["admin","alice"],"db_pass":"int3rn4l_s3cr3t"}',
    "http://localhost:8080/health": '{"status":"healthy","version":"2.3.1","uptime":99.9}',
    "http://127.0.0.1:8080/admin":  '{"status":"ok","flag":"FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}","users":["admin","alice"]}',
    "http://169.254.169.254/latest/meta-data/": "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\n",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/": "vulnlab-ec2-role",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnlab-ec2-role":
        '{"Code":"Success","AccessKeyId":"AKIA_FAKE_KEY_C11","SecretAccessKey":"fake+secret+key+ssrf+vulnlab","Token":"fake-session-token"}',
}

PAGE = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>WebFetch — Prévisualisation</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;min-height:100vh;padding:40px 24px}
.wrap{max-width:860px;margin:0 auto}h1{font-size:22px;color:#1a2744;margin-bottom:6px}
.sub{font-size:13px;color:#8a94a6;margin-bottom:28px;font-family:monospace}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px;margin-bottom:16px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8a94a6;margin-bottom:14px}
.url-form{display:flex;gap:10px}
input[type=text]{flex:1;padding:10px 14px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;font-family:monospace;color:#1a2744;outline:none}
input:focus{border-color:#2d6ef7}
.btn{padding:10px 20px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap}
.result-box{background:#1e1e2e;border-radius:8px;padding:16px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px 20px;display:flex;align-items:center;gap:14px;margin-bottom:16px}
.flag-val{font-family:monospace;font-size:15px;color:#86efac;font-weight:700}
.flag-lbl{font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:12px 14px;font-size:13px}
.quick-links{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.qlink{padding:5px 12px;background:#f0f4ff;border:1px solid #d0deff;border-radius:6px;font-size:12px;font-family:monospace;color:#2d6ef7;cursor:pointer;text-decoration:none}
.qlink:hover{background:#dce8ff}
a.nav{color:#2d6ef7;font-size:13px;text-decoration:none}
.debug{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:12px 14px;font-size:12px;color:#7a5c00;font-family:monospace;margin-bottom:14px}
</style></head><body><div class="wrap">
<h1>WebFetch — Prévisualisation d'URL</h1>
<p class="sub">Le serveur effectue une requête HTTP vers l'URL fournie et retourne le contenu</p>

{% if flag_found %}
<div class="flag-banner"><div style="font-size:26px">🚩</div>
<div><div class="flag-lbl">C11 — Flag capturé !</div>
<div class="flag-val">FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}</div></div></div>
{% endif %}

<div class="card"><h3>Fetcher une URL</h3>
<div class="debug">⚠ Aucune validation d'URL — le serveur accède à toutes les adresses, y compris localhost et les IPs internes</div>
<form method="POST" action="fetch">
  <div class="url-form">
    <input type="text" name="url" placeholder="https://example.com" value="{{ url or '' }}">
    <button type="submit" class="btn">Fetch →</button>
  </div>
</form>
<div class="quick-links">
  <span style="font-size:12px;color:#8a94a6;align-self:center">Cibles :</span>
  <a class="qlink" href="/fetch?url=http://localhost:8080/health">localhost:8080/health</a>
  <a class="qlink" href="/fetch?url=http://localhost:8080/admin">localhost:8080/admin</a>
  <a class="qlink" href="/fetch?url=http://169.254.169.254/latest/meta-data/">AWS metadata</a>
  <a class="qlink" href="/fetch?url=http://127.0.0.1:8080/admin">127.0.0.1:8080</a>
</div>
</div>

{% if result is not none %}
<div class="card"><h3>Réponse ({{ url }})</h3>
<div class="result-box">{{ result }}</div>
</div>
{% endif %}

{% if error %}
<div class="err">{{ error }}</div>
{% endif %}

<a class="nav" href="hints">Hints &amp; Write-up →</a>
</div></body></html>'''

HINTS = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C11 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}a{color:#4a9eff}</style></head><body>
<div class="wrap"><a href="/" style="font-size:13px;color:#4a9eff;display:block;margin-bottom:20px">← Retour</a>
<h1>C11 — SSRF</h1><p class="sub">Python Flask · requests · pas de validation d'URL</p>
<div class="hint"><div class="lbl l1">Indice 1 — Service interne</div>
<p>Un service tourne sur <code>localhost:8080</code>, inaccessible depuis l'extérieur. Forcez le serveur à l'atteindre pour vous :</p>
<div class="code">http://localhost:8080/admin
http://127.0.0.1:8080/admin
http://0.0.0.0:8080/admin</div></div>
<div class="hint"><div class="lbl l2">Indice 2 — AWS Metadata (IMDS)</div>
<p>En environnement cloud, l'endpoint <code>169.254.169.254</code> expose les credentials IAM :</p>
<div class="code">http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/vulnlab-ec2-role</div></div>
<div class="hint"><div class="lbl l3">Correction</div>
<div class="code">import ipaddress, urllib.parse
def is_safe_url(url):
    host = urllib.parse.urlparse(url).hostname
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except: return False
    return True</div></div>
<p>FLAG : <span style="font-family:monospace;color:#86efac">FLAG{ssrf_1nt3rn4l_s3rv1c3_4cc3ss}</span></p>
</div></body></html>'''

def do_fetch(url):
    """Fait la requête — simule les endpoints internes, sinon requête réelle."""
    if url in INTERNAL_ENDPOINTS:
        return INTERNAL_ENDPOINTS[url], False
    # Vérifier aussi les variantes sans trailing slash
    for k, v in INTERNAL_ENDPOINTS.items():
        if url.rstrip('/') == k.rstrip('/'):
            return v, False
    try:
        r = req_lib.get(url, timeout=5, allow_redirects=True)
        return r.text[:4000], False
    except Exception as e:
        return None, str(e)

@app.route('/', methods=['GET'])
def index():
    return render_template_string(PAGE, url=None, result=None, error=None, flag_found=False)

@app.route('/fetch', methods=['GET', 'POST'])
def fetch():
    url = (request.form.get('url') or request.args.get('url') or '').strip()
    if not url:
        return render_template_string(PAGE, url=None, result=None, error="URL manquante.", flag_found=False)

    result, error = do_fetch(url)
    flag_found = result and 'FLAG{' in result

    return render_template_string(PAGE, url=url, result=result, error=error, flag_found=flag_found)

@app.route('/hints')
def hints():
    return render_template_string(HINTS)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
