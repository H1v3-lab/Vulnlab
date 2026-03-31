<?php
session_start();
// ⚠️  VULNÉRABILITÉ : le rôle est lu depuis le cookie, pas depuis la session serveur
//     Un attaquant peut modifier cookie role=admin sans se connecter
$role     = $_COOKIE['role']     ?? ($_SESSION['role']     ?? 'guest');
$username = $_COOKIE['username'] ?? ($_SESSION['username'] ?? 'inconnu');
$is_admin = ($role === 'admin');
?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>BankApp — Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f0f4ff;min-height:100vh}
.navbar{background:#1a3a6b;color:#fff;padding:0 28px;height:54px;display:flex;align-items:center;gap:16px}
.brand{font-weight:800;font-size:17px;letter-spacing:-.02em}
.nav-user{margin-left:auto;font-size:13px;opacity:.8}
.badge{padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700}
.badge-admin{background:#fef3c7;color:#92400e}
.badge-user{background:#e0f2fe;color:#075985}
.wrap{max-width:900px;margin:40px auto;padding:0 24px}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:20px 24px;display:flex;align-items:center;gap:16px;margin-bottom:28px}
.flag-icon{font-size:28px}
.flag-label{font-size:11px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px}
.flag-val{font-family:monospace;font-size:16px;color:#86efac;font-weight:700}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px}
.stat-card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.stat-val{font-size:28px;font-weight:700;color:#1a3a6b;margin-bottom:4px}
.stat-lbl{font-size:12px;color:#8a94a6}
.info-card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px;margin-bottom:16px}
.info-card h3{font-size:14px;font-weight:600;margin-bottom:12px;color:#1a2744}
.debug{background:#1e1e2e;border-radius:8px;padding:14px 16px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8}
.debug-lbl{color:#6c7086;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
.vuln{color:#f38ba8}
a{color:#2d6ef7;font-size:13px}
</style></head><body>
<nav class="navbar">
  <span class="brand">BankApp</span>
  <span>Dashboard</span>
  <span class="nav-user">
    <?= htmlspecialchars($username) ?> &nbsp;
    <span class="badge <?= $is_admin ? 'badge-admin' : 'badge-user' ?>"><?= htmlspecialchars($role) ?></span>
  </span>
</nav>
<div class="wrap">
  <?php if ($is_admin): ?>
  <div class="flag-banner">
    <div class="flag-icon">🚩</div>
    <div>
      <div class="flag-label">C04 — Flag capturé !</div>
      <div class="flag-val">FLAG{br0k3n_4uth_c00k13_t4mp3r}</div>
    </div>
  </div>
  <?php endif; ?>

  <div class="grid">
    <div class="stat-card"><div class="stat-val">€12,450</div><div class="stat-lbl">Solde compte courant</div></div>
    <div class="stat-card"><div class="stat-val">€3,200</div><div class="stat-lbl">Épargne</div></div>
  </div>

  <div class="info-card">
    <h3>🔍 Debug session &amp; cookies</h3>
    <div class="debug">
      <div class="debug-lbl">Valeurs lues</div>
      Cookie <span class="vuln">role</span>     = <span class="vuln"><?= htmlspecialchars($role) ?></span> &nbsp;<em style="color:#6c7086">(⚠ non signé !)</em><br>
      Cookie username = <?= htmlspecialchars($username) ?><br>
      Session role    = <?= htmlspecialchars($_SESSION['role'] ?? '(aucune session)') ?><br>
      Session ID      = <?= session_id() ?>
    </div>
  </div>

  <p><a href="index.php">← Déconnexion</a> &nbsp;·&nbsp; <a href="hints.php">Hints</a></p>
</div>
</body></html>
