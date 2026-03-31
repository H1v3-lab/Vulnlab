<?php
// ─────────────────────────────────────────────
// VulnLab C01 — Page admin
// Accessible en se loggant en tant qu'admin
// ─────────────────────────────────────────────

$db_host = getenv('DB_HOST') ?: 'mysql';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: 'root';
$db_name = getenv('DB_NAME') ?: 'vulnlab';

$conn = @mysqli_connect($db_host, $db_user, $db_pass, $db_name);

// Lecture des tables si connecté
$users   = [];
$secrets = [];
$orders  = [];

if ($conn) {
    $r = mysqli_query($conn, "SELECT id, username, role, email FROM users");
    while ($row = mysqli_fetch_assoc($r)) $users[] = $row;

    $r = mysqli_query($conn, "SELECT * FROM secrets");
    while ($row = mysqli_fetch_assoc($r)) $secrets[] = $row;

    $r = mysqli_query($conn, "SELECT o.id, u.username, o.product, o.amount FROM orders o JOIN users u ON o.user_id = u.id");
    while ($row = mysqli_fetch_assoc($r)) $orders[] = $row;
}

// Paramètre UNION demo — vulnérabilité bonus sur cette page aussi
$search = $_GET['search'] ?? '';
$search_results = [];
if ($search && $conn) {
    // ⚠️  VULNÉRABILITÉ : UNION-based possible ici aussi
    $q = "SELECT id, username, email FROM users WHERE username LIKE '%$search%'";
    $r = mysqli_query($conn, $q);
    if ($r) {
        while ($row = mysqli_fetch_assoc($r)) $search_results[] = $row;
    }
    $search_query_display = htmlspecialchars($q);
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CorpNet — Administration</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #f0f2f5;
    color: #1a2744;
    min-height: 100vh;
  }
  .topbar {
    background: #1a2744;
    color: #fff;
    padding: 0 28px;
    height: 52px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 14px;
  }
  .topbar .logo-icon {
    width: 28px; height: 28px; background: #e83c3c; border-radius: 6px;
    display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700;
  }
  .topbar .admin-badge {
    margin-left: auto; background: rgba(232,60,60,0.2);
    border: 1px solid rgba(232,60,60,0.4); color: #fca5a5;
    padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;
  }

  .wrap { max-width: 1000px; margin: 0 auto; padding: 32px 24px; }

  .flag-banner {
    background: linear-gradient(135deg, #0f2a0f, #1a4a1a);
    border: 1px solid #2d6b2d;
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 28px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .flag-banner .icon { font-size: 28px; }
  .flag-banner .flag-label { font-size: 11px; color: #6dbf6d; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px; }
  .flag-banner .flag-val { font-family: 'Courier New', monospace; font-size: 16px; color: #86efac; font-weight: 700; }

  h2 { font-size: 15px; font-weight: 600; margin-bottom: 14px; color: #1a2744; }

  .section { margin-bottom: 32px; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 8px rgba(0,0,0,0.06); }
  th { background: #1a2744; color: #fff; padding: 10px 14px; text-align: left; font-size: 11px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; }
  td { padding: 10px 14px; border-bottom: 1px solid #f0f2f5; color: #4a5568; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8faff; }

  .badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }
  .badge-admin { background:#fef3c7; color:#92400e; }
  .badge-user  { background:#e0f2fe; color:#075985; }

  .search-form {
    display: flex; gap: 10px; margin-bottom: 14px;
  }
  .search-form input {
    flex: 1; padding: 9px 14px; border: 1.5px solid #e2e8f0; border-radius: 8px;
    font-size: 13px; color: #1a2744; outline: none;
  }
  .search-form input:focus { border-color: #2d6ef7; }
  .search-form button {
    padding: 9px 18px; background: #2d6ef7; color: #fff; border: none;
    border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
  }

  .debug-box {
    background: #1e1e2e; border-radius: 8px; padding: 12px 16px;
    font-family: 'Courier New', monospace; font-size: 11px; color: #cdd6f4;
    word-break: break-all; line-height: 1.6; margin-bottom: 14px;
  }
  .debug-label { color: #6c7086; font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
  .kw { color: #cba6f7; } .str { color: #a6e3a1; }

  .secret-val { font-family: 'Courier New', monospace; color: #e83c3c; font-size: 12px; }

  .back-link { display:inline-flex; align-items:center; gap:6px; font-size:13px; color:#2d6ef7; text-decoration:none; margin-bottom:24px; }
  .back-link:hover { text-decoration:underline; }
</style>
</head>
<body>

<div class="topbar">
  <div class="logo-icon">C</div>
  CorpNet — Panneau d'administration
  <span class="admin-badge">⚠ ADMIN</span>
</div>

<div class="wrap">
  <a class="back-link" href="/">← Retour au portail</a>

  <!-- Flag -->
  <div class="flag-banner">
    <div class="icon">🚩</div>
    <div>
      <div class="flag-label">Challenge C01 — Flag capturé</div>
      <div class="flag-val">FLAG{sql1_1nj3ct10n_byp4ss_succ3ss}</div>
    </div>
  </div>

  <!-- Secrets table -->
  <div class="section">
    <h2>🔐 Table <code>secrets</code></h2>
    <table>
      <thead><tr><th>ID</th><th>Nom</th><th>Valeur</th></tr></thead>
      <tbody>
        <?php foreach ($secrets as $s): ?>
        <tr>
          <td><?= $s['id'] ?></td>
          <td><?= htmlspecialchars($s['name']) ?></td>
          <td class="secret-val"><?= htmlspecialchars($s['value']) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <!-- Users table -->
  <div class="section">
    <h2>👥 Table <code>users</code> (mots de passe inclus)</h2>
    <!-- ⚠️  BONUS : champ de recherche vulnérable à UNION-based injection -->
    <form class="search-form" method="GET">
      <input type="text" name="search" placeholder="Rechercher un utilisateur… (essayez une UNION !)" value="<?= htmlspecialchars($search) ?>">
      <button type="submit">Rechercher</button>
    </form>

    <?php if ($search): ?>
    <div class="debug-box">
      <div class="debug-label">🔍 Requête exécutée</div>
      <?= $search_query_display ?>
    </div>
    <?php if ($search_results): ?>
    <table style="margin-bottom:16px">
      <thead><tr><th>ID</th><th>Username</th><th>Email</th></tr></thead>
      <tbody>
        <?php foreach ($search_results as $row): ?>
        <tr>
          <td><?= htmlspecialchars($row['id'] ?? '') ?></td>
          <td><?= htmlspecialchars($row['username'] ?? '') ?></td>
          <td><?= htmlspecialchars($row['email'] ?? '') ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <?php else: ?>
    <p style="font-size:13px;color:#8a94a6;margin-bottom:14px">Aucun résultat.</p>
    <?php endif; ?>
    <?php endif; ?>

    <table>
      <thead><tr><th>ID</th><th>Username</th><th>Password</th><th>Role</th><th>Email</th></tr></thead>
      <tbody>
        <?php foreach ($users as $u): ?>
        <tr>
          <td><?= $u['id'] ?></td>
          <td><?= htmlspecialchars($u['username']) ?></td>
          <td class="secret-val">hidden</td>
          <td><span class="badge <?= $u['role'] === 'admin' ? 'badge-admin' : 'badge-user' ?>"><?= $u['role'] ?></span></td>
          <td><?= htmlspecialchars($u['email']) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <!-- Orders -->
  <div class="section">
    <h2>📦 Table <code>orders</code></h2>
    <table>
      <thead><tr><th>ID</th><th>Utilisateur</th><th>Produit</th><th>Montant</th></tr></thead>
      <tbody>
        <?php foreach ($orders as $o): ?>
        <tr>
          <td><?= $o['id'] ?></td>
          <td><?= htmlspecialchars($o['username']) ?></td>
          <td><?= htmlspecialchars($o['product']) ?></td>
          <td><?= number_format($o['amount'], 2) ?> €</td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>

</div>
</body>
</html>
