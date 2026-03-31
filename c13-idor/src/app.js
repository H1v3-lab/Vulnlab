'use strict';
// VulnLab C13 — IDOR API REST (Node.js + MongoDB)
// VULNÉRABILITÉ : GET /api/orders/:id sans vérifier que la commande appartient à l'utilisateur connecté
const express      = require('express');
const mongoose     = require('mongoose');
const cookieParser = require('cookie-parser');
const app          = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const MONGO_URL = process.env.MONGO_URL || 'mongodb://localhost:27017/vulnlab';

// ── Schéma ───────────────────────────────────
const OrderSchema = new mongoose.Schema({
  owner:       String,
  product:     String,
  amount:      Number,
  address:     String,
  card_last4:  String,
  status:      String,
  secret:      String,
});
const Order = mongoose.model('Order', OrderSchema);

// ── Seed ─────────────────────────────────────
async function seed() {
  const count = await Order.countDocuments();
  if (count > 0) return;
  await Order.insertMany([
    { owner:'alice', product:'Laptop Pro X',        amount:1299.99, address:'12 rue de la Paix, Paris',    card_last4:'4242', status:'livré',    secret:'' },
    { owner:'bob',   product:'Mechanical Keyboard', amount:149.00,  address:'8 avenue Victor Hugo, Lyon', card_last4:'1337', status:'en cours', secret:'' },
    { owner:'alice', product:'USB-C Hub',            amount:39.99,   address:'12 rue de la Paix, Paris',    card_last4:'4242', status:'livré',    secret:'' },
    { owner:'admin', product:'Server Rack',          amount:4500.00, address:'1 place de la République',   card_last4:'0000', status:'livré',    secret:'FLAG{1d0r_m0ng0db_0rd3r_l34k}' },
  ]);
  console.log('[C13] Base initialisée');
}

// Utilisateur simulé (alice est connectée)
const CURRENT_USER = 'alice';

const css = `<style>*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;min-height:100vh}
.navbar{background:#1c2b4a;color:#fff;padding:0 28px;height:54px;display:flex;align-items:center;gap:16px}
.brand{font-size:17px;font-weight:800;letter-spacing:-.02em}
.nav-u{margin-left:auto;font-size:13px;opacity:.75}
.wrap{max-width:900px;margin:40px auto;padding:0 24px}
h1{font-size:22px;color:#1a2744;margin-bottom:6px}
.sub{font-size:13px;color:#8a94a6;font-family:monospace;margin-bottom:28px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:22px;margin-bottom:16px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8a94a6;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f5f6f8;padding:9px 12px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#8a94a6}
td{padding:10px 12px;border-bottom:1px solid #f0f2f5;color:#4a5568}
tr:last-child td{border:none}
tr:hover td{background:#f8faff}
.id-link{font-family:monospace;font-size:11px;color:#2d6ef7;cursor:pointer}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.b-ok{background:#f0fdf4;color:#16a34a}
.b-pend{background:#fff8e1;color:#d97706}
.debug{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin-bottom:14px}
.warn{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:10px 14px;font-size:12px;color:#7a5c00;font-family:monospace;margin-bottom:14px}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px 20px;display:flex;align-items:center;gap:14px;margin-bottom:16px}
.flag-lbl{font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.flag-val{font-family:monospace;font-size:15px;color:#86efac;font-weight:700}
.kv{display:flex;gap:8px;padding:7px 0;border-bottom:1px solid #f0f2f5;font-size:13px}
.kv:last-child{border:none}.k{font-weight:600;width:120px;color:#1a2744;flex-shrink:0}.v{color:#4a5568;word-break:break-all}
.secret{color:#dc2626;font-family:monospace;font-weight:700}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:12px;font-size:13px}
a{color:#2d6ef7;font-size:13px;text-decoration:none}
input[type=text]{padding:8px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:13px;font-family:monospace;outline:none;width:300px}
input:focus{border-color:#2d6ef7}
.btn{padding:8px 18px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;margin-left:8px}
</style>`;

mongoose.connect(MONGO_URL).then(seed).catch(console.error);

// ── Routes ───────────────────────────────────

app.get('/', async (req, res) => {
  // Affiche uniquement les commandes de l'utilisateur connecté (alice)
  const myOrders = await Order.find({ owner: CURRENT_USER });
  const rows = myOrders.map(o => `
    <tr>
      <td><span class="id-link" onclick="fetchOrder('${o._id}')">${o._id}</span></td>
      <td>${o.product}</td>
      <td>${o.amount.toFixed(2)} €</td>
      <td><span class="badge ${o.status==='livré'?'b-ok':'b-pend'}">${o.status}</span></td>
      <td><a href="api/orders/${o._id}">Voir →</a></td>
    </tr>`).join('');

  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>ShopAPI</title>${css}</head><body>
<nav class="navbar"><span class="brand">ShopAPI</span>
<span class="nav-u">Connecté : <strong>${CURRENT_USER}</strong></span></nav>
<div class="wrap">
<h1>Mes commandes</h1>
<p class="sub">GET /api/orders/:id — aucune vérification d'appartenance</p>
<div class="warn">⚠ Utilisateur connecté : <strong>${CURRENT_USER}</strong> — essayez d'accéder aux commandes des autres utilisateurs en modifiant l'ID</div>
<div class="card"><h3>Mes commandes (alice)</h3>
<table><thead><tr><th>ID (MongoDB)</th><th>Produit</th><th>Montant</th><th>Statut</th><th></th></tr></thead>
<tbody>${rows}</tbody></table></div>
<div class="card"><h3>Accéder à une commande par ID</h3>
<div style="display:flex;align-items:center;gap:0;margin-bottom:14px">
  <input type="text" id="oid" placeholder="ObjectId MongoDB…">
  <button class="btn" onclick="fetchOrder(document.getElementById('oid').value)">Fetch →</button>
</div>
<div class="debug" id="result">// Résultat ici…</div>
</div>
<a href="hints">Hints &amp; Write-up →</a>
</div>
<script>
async function fetchOrder(id) {
  document.getElementById('oid').value = id;
  const r = await fetch('/api/orders/' + id);
  const d = await r.json();
  document.getElementById('result').textContent = JSON.stringify(d, null, 2);
  if (d.secret && d.secret.includes('FLAG')) {
    document.getElementById('result').style.color = '#86efac';
  }
}
</script></body></html>`);
});

// ⚠️  VULNÉRABILITÉ : aucune vérification que order.owner === utilisateur connecté
app.get('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Commande introuvable' });
    // Pas de : if (order.owner !== CURRENT_USER) return res.status(403)...
    res.json(order);
  } catch (e) {
    res.status(400).json({ error: 'ID invalide' });
  }
});

app.get('/hints', (req, res) => {
  res.send(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C13 Hints</title>${css}</head><body>
<div style="background:#0f1117;min-height:100vh;padding:40px 24px">
<div style="max-width:720px;margin:0 auto">
<a href="/" style="color:#4a9eff;font-size:13px;display:block;margin-bottom:20px">← Retour</a>
<h1 style="color:#e4e8f0;margin-bottom:8px">C13 — IDOR API MongoDB</h1>
<p style="font-family:monospace;font-size:13px;color:#5a6475;margin-bottom:28px">Node.js · Mongoose · REST API</p>
<div style="background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px">
<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#16a34a;margin-bottom:8px">Indice 1 — Énumérer les IDs</div>
<p style="font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px">
L'API expose les commandes via ObjectId MongoDB. Récupérez les IDs affichés dans le tableau, puis essayez ceux qui n'appartiennent pas à alice :</p>
<div style="background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;white-space:pre"># Via curl — tester tous les ObjectIds récupérés depuis la page
curl http://localhost/c13/api/orders/&lt;OBJECTID_ADMIN&gt;

# La commande admin contient le flag dans le champ "secret"</div></div>
<div style="background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px">
<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#dc2626;margin-bottom:8px">Correction</div>
<div style="background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;white-space:pre">// ✅ Toujours filtrer par owner
const order = await Order.findOne({ _id: req.params.id, owner: currentUser });
if (!order) return res.status(403).json({ error: 'Accès refusé' });</div></div>
<p style="font-family:monospace;color:#86efac">FLAG{1d0r_m0ng0db_0rd3r_l34k}</p>
</div></div></body></html>`);
});

app.listen(3000, () => console.log('[C13-IDOR] port 3000'));
