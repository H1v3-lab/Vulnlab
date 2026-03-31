<?php
// ─────────────────────────────────────────────
// VulnLab C01 — SQL Injection
// VULNÉRABILITÉ INTENTIONNELLE — NE PAS UTILISER EN PROD
// ─────────────────────────────────────────────

$db_host = getenv('DB_HOST') ?: 'mysql';
$db_user = getenv('DB_USER') ?: 'root';
$db_pass = getenv('DB_PASS') ?: 'root';
$db_name = getenv('DB_NAME') ?: 'vulnlab';

$error   = '';
$success = '';
$user    = null;

// Connexion MySQL (retry simple car MySQL peut démarrer après PHP)
$conn = null;
for ($i = 0; $i < 5; $i++) {
    $conn = @mysqli_connect($db_host, $db_user, $db_pass, $db_name);
    if ($conn) break;
    sleep(2);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    if ($conn) {
        // ⚠️  VULNÉRABILITÉ INTENTIONNELLE : concaténation directe sans échappement
        $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

        // On expose la requête dans un commentaire HTML pour aider l'apprenant
        $debug_query = htmlspecialchars($query);

        $result = mysqli_query($conn, $query);

        if ($result && mysqli_num_rows($result) > 0) {
            $user    = mysqli_fetch_assoc($result);
            $success = 'Connexion réussie ! Bienvenue, ' . htmlspecialchars($user['username']) . '.';
        } else {
            $error = 'Identifiants invalides.';
        }
    } else {
        $error = 'Erreur de connexion à la base de données. Réessayez dans quelques secondes.';
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CorpNet — Portail employés</title>
<style>
  /* ── Reset & base ── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    min-height: 100vh;
    background: #f0f2f5;
    font-family: 'Segoe UI', system-ui, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  /* ── Topbar ── */
  .topbar {
    position: fixed;
    top: 0; left: 0; right: 0;
    background: #1a2744;
    color: #fff;
    padding: 0 24px;
    height: 52px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 14px;
    font-weight: 500;
    letter-spacing: 0.02em;
    z-index: 10;
  }
  .topbar .logo {
    display: flex; align-items: center; gap: 8px;
  }
  .topbar .logo-icon {
    width: 28px; height: 28px;
    background: #2d6ef7;
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 700;
  }
  .topbar .sep {
    margin-left: auto;
    font-size: 11px;
    color: rgba(255,255,255,0.4);
  }

  /* ── Card ── */
  .card {
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 2px 16px rgba(0,0,0,0.10);
    padding: 40px 44px;
    width: 100%;
    max-width: 420px;
    margin-top: 52px;
  }

  .card-header {
    text-align: center;
    margin-bottom: 32px;
  }
  .card-header .brand {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #2d6ef7;
    margin-bottom: 8px;
  }
  .card-header h1 {
    font-size: 22px;
    font-weight: 600;
    color: #1a2744;
  }
  .card-header p {
    font-size: 13px;
    color: #8a94a6;
    margin-top: 6px;
  }

  /* ── Form ── */
  .form-group { margin-bottom: 18px; }

  label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    color: #4a5568;
    margin-bottom: 6px;
    letter-spacing: 0.03em;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 11px 14px;
    border: 1.5px solid #e2e8f0;
    border-radius: 8px;
    font-size: 14px;
    color: #1a2744;
    background: #fafafa;
    transition: border-color 0.15s, box-shadow 0.15s;
    outline: none;
  }
  input:focus {
    border-color: #2d6ef7;
    background: #fff;
    box-shadow: 0 0 0 3px rgba(45,110,247,0.12);
  }

  .btn {
    display: block;
    width: 100%;
    padding: 12px;
    background: #2d6ef7;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    margin-top: 8px;
  }
  .btn:hover { background: #1a5ce8; }

  /* ── Alerts ── */
  .alert {
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 13px;
    margin-bottom: 20px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }
  .alert-error {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
  }
  .alert-success {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
  }
  .alert-icon { font-size: 15px; flex-shrink: 0; }

  /* ── Debug hint (aide pédagogique) ── */
  .debug-box {
    margin-top: 28px;
    padding: 14px 16px;
    background: #1e1e2e;
    border-radius: 8px;
    font-family: 'Courier New', monospace;
    font-size: 11px;
    color: #cdd6f4;
    word-break: break-all;
    line-height: 1.6;
  }
  .debug-box .debug-label {
    color: #6c7086;
    font-size: 10px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .debug-box .kw  { color: #cba6f7; }
  .debug-box .str { color: #a6e3a1; }
  .debug-box .op  { color: #89dceb; }

  /* ── User info box (après connexion) ── */
  .user-info {
    margin-top: 20px;
    background: #f8faff;
    border: 1px solid #dce8ff;
    border-radius: 8px;
    padding: 16px;
  }
  .user-info h3 {
    font-size: 12px;
    font-weight: 600;
    color: #2d6ef7;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 10px;
  }
  .user-info table { width: 100%; font-size: 13px; border-collapse: collapse; }
  .user-info td { padding: 4px 0; color: #4a5568; }
  .user-info td:first-child { font-weight: 600; width: 80px; color: #1a2744; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-admin { background: #fef3c7; color: #92400e; }
  .badge-user  { background: #e0f2fe; color: #075985; }

  .footer-note {
    margin-top: 24px;
    text-align: center;
    font-size: 11px;
    color: #b0b7c3;
  }
</style>
</head>
<body>

<!-- Topbar corporate fictive -->
<div class="topbar">
  <div class="logo">
    <div class="logo-icon">C</div>
    CorpNet Intranet
  </div>
  <span class="sep">Portail Employés v2.3.1 &nbsp;·&nbsp; IT Support: ext. 4200</span>
</div>

<div class="card">
  <div class="card-header">
    <div class="brand">CorpNet</div>
    <h1>Authentification</h1>
    <p>Accès réservé aux employés autorisés</p>
  </div>

  <?php if ($error): ?>
  <div class="alert alert-error">
    <span class="alert-icon">✕</span>
    <span><?= htmlspecialchars($error) ?></span>
  </div>
  <?php endif; ?>

  <?php if ($success): ?>
  <div class="alert alert-success">
    <span class="alert-icon">✓</span>
    <span><?= $success ?></span>
  </div>

  <!-- Données retournées par la requête -->
  <div class="user-info">
    <h3>Données session</h3>
    <table>
      <tr><td>ID</td><td><?= htmlspecialchars($user['id']) ?></td></tr>
      <tr><td>Login</td><td><?= htmlspecialchars($user['username']) ?></td></tr>
      <tr><td>Email</td><td><?= htmlspecialchars($user['email'] ?? '—') ?></td></tr>
      <tr><td>Rôle</td><td>
        <span class="badge <?= $user['role'] === 'admin' ? 'badge-admin' : 'badge-user' ?>">
          <?= htmlspecialchars($user['role']) ?>
        </span>
      </td></tr>
      <?php if ($user['role'] === 'admin'): ?>
      <tr><td>Flag</td><td style="color:#166534;font-weight:600">FLAG{sql1_1nj3ct10n_byp4ss_succ3ss}</td></tr>
      <?php endif; ?>
    </table>
  </div>

  <?php else: ?>
  <form method="POST" action="">
    <div class="form-group">
      <label for="username">Identifiant</label>
      <input type="text" id="username" name="username"
             placeholder="ex: jean.dupont"
             value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
             autocomplete="off">
    </div>
    <div class="form-group">
      <label for="password">Mot de passe</label>
      <input type="password" id="password" name="password" placeholder="••••••••">
    </div>
    <button type="submit" class="btn">Se connecter</button>
  </form>
  <?php endif; ?>

  <?php if (isset($debug_query)): ?>
  <!-- ── Debug pédagogique ── -->
  <div class="debug-box">
    <div class="debug-label">🔍 Requête SQL générée</div>
    <span class="kw">SELECT</span> * <span class="kw">FROM</span> users
    <span class="kw">WHERE</span> username = <span class="str">'<?= htmlspecialchars($_POST['username'] ?? '') ?>'</span>
    <span class="kw">AND</span> password = <span class="str">'<?= htmlspecialchars($_POST['password'] ?? '') ?>'</span>
  </div>
  <?php endif; ?>

  <p class="footer-note">Problème de connexion ? Contactez le support IT</p>
</div>

</body>
</html>
