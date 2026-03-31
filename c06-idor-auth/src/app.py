# VulnLab C06 — IDOR Auth (Flask)
from flask import Flask, request, jsonify, render_template_string
app = Flask(__name__)

USERS = {
    1: {"id":1,"username":"alice","email":"alice@corp.local","role":"user","iban":"FR76 1234 5678 9012 3456","balance":1200.50},
    2: {"id":2,"username":"bob","email":"bob@corp.local","role":"user","iban":"FR76 9876 5432 1098 7654","balance":340.00},
    3: {"id":3,"username":"charlie","email":"charlie@corp.local","role":"user","iban":"FR76 1111 2222 3333 4444","balance":8900.75},
    4: {"id":4,"username":"admin","email":"admin@corp.local","role":"admin","iban":"FR76 0000 0000 0000 0001","balance":99999.99,"flag":"FLAG{1d0r_s3qu3nt14l_1d_byp4ss}"},
}

TMPL = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>UserAPI</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;padding:40px 24px}
.wrap{max-width:800px;margin:0 auto}h1{font-size:22px;color:#1a2744;margin-bottom:6px}
.sub{font-size:13px;color:#8a94a6;margin-bottom:28px;font-family:monospace}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px;margin-bottom:16px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:14px;color:#5a6475;margin-bottom:12px;text-transform:uppercase;letter-spacing:.06em}
.kv{display:flex;gap:12px;padding:6px 0;border-bottom:1px solid #f0f2f5;font-size:14px}
.kv:last-child{border:none}.k{font-weight:600;width:120px;color:#1a2744;flex-shrink:0}.v{color:#4a5568}
.flag-val{font-family:monospace;color:#16a34a;font-weight:700}
.debug{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin-bottom:16px}
.nav{display:flex;gap:8px;margin-bottom:28px;flex-wrap:wrap}
.nav a{padding:8px 16px;background:#fff;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;color:#2d6ef7;text-decoration:none}
.nav a:hover{background:#f0f4ff}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:14px;font-size:13px}
</style></head><body><div class="wrap">
<h1>UserAPI — Profils</h1>
<p class="sub">GET /api/user/&lt;id&gt; — Aucune vérification d'appartenance</p>
<div class="nav">
  <a href="/c06/api/user/1">/api/user/1</a>
</div>
{% if user %}
<div class="debug">⚠ Requête : GET /api/user/{{ user.id }} — connecté en tant que alice (id=1)<br>
Aucune vérification : user_id_requested == current_user_id</div>
<div class="card"><h3>Profil #{{ user.id }}</h3>
  {% for k,v in user.items() %}
  <div class="kv"><span class="k">{{ k }}</span>
  <span class="v {% if k=='flag' %}flag-val{% endif %}">{{ v }}</span></div>
  {% endfor %}
</div>
{% elif error %}<div class="err">{{ error }}</div>
{% endif %}
</div></body></html>'''

HINTS_TMPL = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C06 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}
.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}
.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}
.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}
.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}
p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}
.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}
a{color:#4a9eff;text-decoration:none}</style></head><body><div class="wrap">
<a href="/c06/" style="font-size:13px;display:block;margin-bottom:20px">← Retour</a>
<h1>C06 — IDOR Profils</h1>
<p class="sub">Python Flask · IDs séquentiels sans contrôle d'accès</p>
<div class="hint"><div class="lbl l1">Indice 1</div>
<p>L'API expose les profils via un ID entier dans l'URL. Commencez par <code>/api/user/1</code>,
puis incrémentez manuellement l'ID dans la barre d'adresse.</p></div>
<div class="hint"><div class="lbl l2">Indice 2 — Automatiser</div>
<div class="code">for i in $(seq 1 10); do
  curl -s http://localhost/c06/api/user/$i | python3 -m json.tool
  echo "---"
done</div></div>
<div class="hint"><div class="lbl l3">Correction</div>
<div class="code"># ✅ Vérifier l'appartenance
@app.route('/api/user/&lt;int:uid&gt;')
def get_user(uid):
    if uid != current_user.id and current_user.role != 'admin':
        abort(403)
    return jsonify(USERS[uid])</div></div>
<p>FLAG : <span style="font-family:monospace;color:#86efac">FLAG{1d0r_s3qu3nt14l_1d_byp4ss}</span></p>
</div></body></html>'''

@app.route('/')
def index():
    return render_template_string(TMPL, user=None, error=None)

@app.route('/api/user/<int:uid>')
def get_user(uid):
    # ⚠️ VULNÉRABILITÉ : aucune vérification que uid == utilisateur connecté
    user = USERS.get(uid)
    if not user:
        return render_template_string(TMPL, user=None, error=f"Utilisateur #{uid} introuvable.")
    return render_template_string(TMPL, user=user, error=None)

@app.route('/api/user/<int:uid>/json')
def get_user_json(uid):
    user = USERS.get(uid)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)

@app.route('/hints')
def hints():
    return render_template_string(HINTS_TMPL)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
