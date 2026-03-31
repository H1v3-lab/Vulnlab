<?php
// VulnLab C14 — CSRF
// VULNÉRABILITÉ : formulaire de changement d'email sans token CSRF
session_start();

// Init session utilisateur simulée
if (!isset($_SESSION['user'])) {
    $_SESSION['user']  = 'alice';
    $_SESSION['email'] = 'alice@corp.local';
    $_SESSION['role']  = 'user';
    $_SESSION['balance'] = '2 450,00 €';
}

$msg = ''; $flag = '';

// ⚠️  VULNÉRABILITÉ : action POST acceptée sans vérification du token CSRF
//     N'importe quelle page externe peut déclencher ce changement si l'utilisateur est connecté
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    $new_email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $old_email = $_SESSION['email'];
    $_SESSION['email'] = $new_email;
    $msg = "Email mis à jour : $old_email → $new_email";
    if (str_contains($new_email, 'attacker') || str_contains($new_email, 'hacker')) {
        $flag = 'FLAG{csrf_n0_t0k3n_3m41l_h1j4ck}';
    }
}
?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>BankPortal — Mon compte</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f0f4ff;min-height:100vh}
.navbar{background:#1a3a6b;color:#fff;padding:0 28px;height:54px;display:flex;align-items:center;gap:16px}
.brand{font-weight:800;font-size:17px}
.nav-u{margin-left:auto;font-size:13px;opacity:.8}
.wrap{max-width:860px;margin:40px auto;padding:0 24px}
.grid{display:grid;grid-template-columns:260px 1fr;gap:20px}
.card{background:#fff;border:1px solid #dce8ff;border-radius:10px;padding:22px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8a94a6;margin-bottom:14px}
.menu-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:8px;font-size:14px;color:#4a5568;cursor:pointer;margin-bottom:4px}
.menu-item.active{background:#f0f4ff;color:#1a3a6b;font-weight:600}
.stat-val{font-size:26px;font-weight:700;color:#1a3a6b;margin-bottom:4px}
.stat-lbl{font-size:12px;color:#8a94a6}
.kv{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid #f0f2f5;font-size:14px}
.kv:last-child{border:none}.k{font-weight:600;width:100px;color:#1a2744;flex-shrink:0}.v{color:#4a5568}
label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:5px}
input[type=email]{width:100%;padding:9px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;color:#1a2744;outline:none;margin-bottom:12px}
input:focus{border-color:#2d6ef7}
.btn{padding:10px 20px;background:#1a3a6b;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer}
.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:12px;font-size:13px;margin-bottom:14px}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px;display:flex;align-items:center;gap:14px;margin-bottom:14px}
.flag-val{font-family:monospace;font-size:15px;color:#86efac;font-weight:700}
.flag-lbl{font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.warn{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:10px 14px;font-size:12px;color:#7a5c00;font-family:monospace;margin-bottom:14px}
a{color:#2d6ef7;font-size:13px;text-decoration:none}
</style></head><body>
<nav class="navbar">
  <span class="brand">BankPortal</span>
  <span class="nav-u">👤 <?= htmlspecialchars($_SESSION['user']) ?></span>
</nav>
<div class="wrap">
<div class="grid">
  <div>
    <div class="card" style="margin-bottom:16px">
      <div class="menu-item active">⚙ Mon compte</div>
      <div class="menu-item">💳 Cartes</div>
      <div class="menu-item">📊 Historique</div>
    </div>
    <div class="card">
      <div class="stat-val"><?= $_SESSION['balance'] ?></div>
      <div class="stat-lbl">Solde disponible</div>
    </div>
  </div>

  <div>
    <div class="card">
      <h3>Informations du compte</h3>
      <div class="kv"><span class="k">Utilisateur</span><span class="v"><?= htmlspecialchars($_SESSION['user']) ?></span></div>
      <div class="kv"><span class="k">Email</span><span class="v" id="cur-email"><?= htmlspecialchars($_SESSION['email']) ?></span></div>
      <div class="kv"><span class="k">Rôle</span><span class="v"><?= htmlspecialchars($_SESSION['role']) ?></span></div>
    </div>

    <div class="card" style="margin-top:16px">
      <h3>Modifier mon email</h3>
      <div class="warn">⚠ Formulaire sans token CSRF — soumission possible depuis n'importe quel site externe</div>

      <?php if ($flag): ?>
      <div class="flag-banner"><div style="font-size:24px">🚩</div>
        <div><div class="flag-lbl">C14 — CSRF réussi !</div>
        <div class="flag-val"><?= $flag ?></div></div>
      </div>
      <?php endif; ?>

      <?php if ($msg): ?>
      <div class="ok">✓ <?= htmlspecialchars($msg) ?></div>
      <?php endif; ?>

      <!-- ⚠️  PAS de token CSRF dans ce formulaire -->
      <form method="POST" action="index.php">
        <label>Nouvel email</label>
        <input type="email" name="email" value="<?= htmlspecialchars($_SESSION['email']) ?>">
        <!-- Token CSRF absent intentionnellement -->
        <button type="submit" class="btn">Mettre à jour</button>
      </form>
    </div>

    <p style="margin-top:16px"><a href="hints.php">Hints &amp; Write-up →</a></p>
  </div>
</div>
</div>
</body></html>
