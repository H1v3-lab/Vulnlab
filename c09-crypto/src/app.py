# VulnLab C09 — "The Cookie Baker"
# Scénario : cookie XOR+Base64, known-plaintext attack → forger role=admin
# Bonus : MD5 cracking pour accéder au compte flag_user et obtenir le flag
from flask import Flask, request, render_template_string, make_response
import base64, hashlib, os

app = Flask(__name__)

# ── Clé XOR (3 chars — volontairement courte) ──
XOR_KEY = b'ABC'   # clé à trouver via known-plaintext attack

# ── Utilisateurs ──
# flag_user : mot de passe MD5 faible (dans rockyou.txt)
USERS = {
    'guest':     {'role':'user',  'password_hash': None,  'flag': None},
    'admin':     {'role':'admin', 'password_hash': hashlib.md5(b'trustno1').hexdigest(), 'flag': None},
    'flag_user': {'role':'user',  'password_hash': hashlib.md5(b'iloveyou').hexdigest(),
                  'flag': 'FLAG{xor_kn0wn_pl41nt3xt_4nd_md5_cr4ck3d}'},
}

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def make_cookie(user: str, role: str) -> str:
    plaintext = f"user={user},role={role}".encode()
    encrypted = xor_encrypt(plaintext, XOR_KEY)
    return base64.b64encode(encrypted).decode()

def parse_cookie(cookie_b64: str):
    try:
        encrypted = base64.b64decode(cookie_b64)
        plaintext = xor_encrypt(encrypted, XOR_KEY).decode()
        parts = dict(p.split('=',1) for p in plaintext.split(',') if '=' in p)
        return parts.get('user','?'), parts.get('role','user')
    except Exception:
        return None, None

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f0f4ff;min-height:100vh;padding-top:54px}
.navbar{background:#1a3a6b;color:#fff;padding:0 28px;height:54px;display:flex;align-items:center;gap:16px;position:fixed;top:0;left:0;right:0;z-index:10}
.brand{font-weight:800;font-size:17px;text-decoration:none;color:#fff}
.nav-u{margin-left:auto;font-size:13px;opacity:.8}
.wrap{max-width:860px;margin:40px auto;padding:0 24px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:24px;margin-bottom:16px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8a94a6;margin-bottom:14px}
.kv{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid #f0f2f5;font-size:14px}
.kv:last-child{border:none}.k{font-weight:600;width:130px;color:#1a2744;flex-shrink:0}.v{color:#4a5568;font-family:monospace;word-break:break-all}
label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:5px}
input{width:100%;padding:9px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:13px;font-family:monospace;color:#1a2744;outline:none;margin-bottom:12px}
input:focus{border-color:#2d6ef7}
.btn{padding:9px 20px;background:#1a3a6b;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;margin-right:8px}
.code{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.9;word-break:break-all;margin:10px 0}
.lbl{font-size:10px;color:#6c7086;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px 20px;display:flex;align-items:center;gap:14px;margin-bottom:16px}
.flag-lbl{font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.flag-val{font-family:monospace;font-size:15px;color:#86efac;font-weight:700}
.warn{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:10px 14px;font-size:12px;color:#7a5c00;font-family:monospace;margin-bottom:12px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:12px}
.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:12px}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:600}
.b-admin{background:#fef3c7;color:#92400e}.b-user{background:#e0f2fe;color:#075985}
a{color:#2d6ef7;font-size:13px;text-decoration:none}
"""

def base_page(title, body, username='guest', role='user'):
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>{title} — CookieVault</title><style>{CSS}</style></head><body>
<nav class="navbar"><a class="brand" href="./">CookieVault</a>
<span class="nav-u">👤 {username} &nbsp;<span class="badge {'b-admin' if role=='admin' else 'b-user'}">{role}</span></span>
</nav><main><div class="wrap">{body}</div></main></body></html>"""

@app.route('/', methods=['GET'])
def index():
    raw_cookie = request.cookies.get('user_data', '')
    if raw_cookie:
        username, role = parse_cookie(raw_cookie)
        if not username:
            username, role = 'guest', 'user'
            raw_cookie = make_cookie('guest', 'user')
    else:
        username, role = 'guest', 'user'
        raw_cookie = make_cookie('guest', 'user')

    user_data = USERS.get(username, USERS['guest'])
    is_admin  = (role == 'admin')

    # Section flag_user (visible uniquement si connecté en tant que flag_user)
    flag_section = ''
    if username == 'flag_user' and user_data['flag']:
        flag_section = f"""<div class="flag-banner"><div style="font-size:26px">🚩</div>
<div><div class="flag-lbl">C09 — Flag !</div>
<div class="flag-val">{user_data['flag']}</div></div></div>"""

    # Section admin : affiche les comptes avec hash MD5
    admin_section = ''
    if is_admin:
        rows = ''.join(
            f'<div class="kv"><span class="k">{u}</span>'
            f'<span class="v">{d["role"]} &nbsp;|&nbsp; '
            f'MD5: {d["password_hash"] or "(aucun)"}</span></div>'
            for u, d in USERS.items() if d['password_hash']
        )
        admin_section = f"""<div class="card"><h3>🔐 Panneau admin — Utilisateurs</h3>
<div class="warn">Hashes MD5 — crackez-les pour vous connecter en tant que flag_user !</div>
{rows}</div>"""

    body = f"""
<h1 style="font-size:22px;color:#1a2744;margin-bottom:6px">CookieVault — Gestion de profil</h1>
<p style="font-size:13px;color:#8a94a6;font-family:monospace;margin-bottom:24px">
Authentification par cookie chiffré XOR+Base64</p>

{flag_section}
{admin_section}

<div class="card"><h3>Votre cookie actuel</h3>
<div class="warn">⚠ Votre identité est stockée dans un cookie <code>user_data</code> "chiffré".
Pouvez-vous le modifier pour devenir admin ?</div>
<div class="code">
<div class="lbl">Cookie user_data (Base64)</div>{raw_cookie}<br><br>
<div class="lbl">Texte clair connu (début)</div>user={username},role={role}
</div></div>

<div class="card"><h3>Connexion (flag_user)</h3>
<form method="POST" action="login">
<label>Nom d'utilisateur</label><input name="username" placeholder="flag_user">
<label>Mot de passe</label><input type="password" name="password" placeholder="mot de passe MD5 cracké">
<button type="submit" class="btn">Connexion</button>
</form></div>

<div class="card"><h3>Injecter un cookie forgé</h3>
<form method="POST" action="forge">
<label>Cookie forgé (Base64)</label><input name="cookie" placeholder="Collez votre cookie XOR+Base64 forgé…">
<button type="submit" class="btn">Appliquer</button>
</form></div>"""

    resp = make_response(base_page(f'Profil — {username}', body, username, role))
    resp.set_cookie('user_data', raw_cookie, path='/')
    return resp

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username','').strip()
    password = request.form.get('password','').strip()
    user_data = USERS.get(username)
    if not user_data or not user_data['password_hash']:
        return make_response(base_page('Erreur', '<div class="wrap"><div class="err">Utilisateur introuvable ou pas de mot de passe.</div><a href="./">← Retour</a></div>'))
    if hashlib.md5(password.encode()).hexdigest() != user_data['password_hash']:
        return make_response(base_page('Erreur', '<div class="wrap"><div class="err">Mot de passe incorrect.</div><a href="./">← Retour</a></div>'))
    cookie = make_cookie(username, user_data['role'])
    resp = make_response(base_page('Connecté',
        f'<div class="ok">✓ Connecté en tant que <strong>{username}</strong> !</div>'
        f'<a href="./">→ Voir le profil</a>', username, user_data['role']))
    resp.set_cookie('user_data', cookie, path='/')
    return resp

@app.route('/forge', methods=['POST'])
def forge():
    cookie = request.form.get('cookie','').strip()
    username, role = parse_cookie(cookie)
    if not username:
        body = '<div class="err">Cookie invalide (Base64/XOR mal formé).</div><a href="./">← Retour</a>'
        return base_page('Erreur', body)
    resp = make_response(base_page('Cookie appliqué',
        f'<div class="ok">Cookie appliqué : user=<strong>{username}</strong>, role=<strong>{role}</strong></div>'
        f'<a href="./">→ Voir le profil</a>', username, role))
    resp.set_cookie('user_data', cookie, path='/')
    return resp

@app.route('/hints')
def hints():
    known   = b"user=guest,role=user"
    example = make_cookie('guest','user')
    enc_ex  = base64.b64decode(example)
    key_hex = ''.join(f'{XOR_KEY[i%3]:02x}' for i in range(6))
    body = f"""<h1 style="font-size:22px;color:#1a2744;margin-bottom:8px">C09 — The Cookie Baker</h1>
<p style="font-family:monospace;font-size:13px;color:#8a94a6;margin-bottom:24px">Crypto faible · XOR + Base64 · Known-Plaintext Attack · MD5</p>

<div class="card"><h3 style="color:#16a34a">Étape 1 — Décoder le cookie</h3>
<div class="code">import base64
cookie_b64 = "{example}"
encrypted  = base64.b64decode(cookie_b64)
# encrypted = {list(enc_ex[:8])}...
print(encrypted)</div></div>

<div class="card"><h3 style="color:#d97706">Étape 2 — Known-Plaintext Attack</h3>
<p style="font-size:14px;color:#4a5568;margin:10px 0;line-height:1.7">
Le texte clair commence par <code>user=guest,role=user</code> (affiché sur la page).
XOR(plaintext, key) = ciphertext → key = XOR(plaintext, ciphertext)</p>
<div class="code">known_plain = b"user=guest,role=user"
key = bytes(known_plain[i] ^ encrypted[i] for i in range(len(known_plain)))
# La clé se répète → chercher le motif répété
# key[:6] = {key_hex} → clé de 3 octets qui se répète</div></div>

<div class="card"><h3 style="color:#d97706">Étape 3 — Forger un cookie admin</h3>
<div class="code">def xor_encrypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

key       = b'ABC'   # clé trouvée
payload   = b"user=hacker,role=admin"
encrypted = xor_encrypt(payload, key)
forged    = base64.b64encode(encrypted).decode()
print(forged)   # → coller dans "Injecter un cookie forgé"</div></div>

<div class="card"><h3 style="color:#dc2626">Étape 4 — Cracker le MD5 de flag_user</h3>
<p style="font-size:14px;color:#4a5568;margin:10px 0;line-height:1.7">
Une fois admin, le hash MD5 de flag_user est visible. Crackez-le :</p>
<div class="code">hashcat -m 0 &lt;hash_md5&gt; /usr/share/wordlists/rockyou.txt
# Ou : echo "&lt;hash&gt;" | john --format=raw-md5 --wordlist=rockyou.txt

# Une fois le mot de passe trouvé → formulaire Connexion → flag !</div></div>

<a href="./">← Retour</a>"""
    return base_page('Hints C09', body)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
