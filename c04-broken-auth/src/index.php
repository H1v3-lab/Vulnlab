<?php
// ─────────────────────────────────────────────
// VulnLab C04 — Broken Authentication
// VULNÉRABILITÉS : session ID prévisible, rôle dans cookie non signé
// ─────────────────────────────────────────────

// ⚠️  Session ID généré de façon prévisible (timestamp MD5)
$predictable_id = md5(time());
session_id($predictable_id);
session_start();

$users = [
    'alice' => ['password' => 'alice123', 'role' => 'user'],
    'admin' => ['password' => 'adm1n_2024!', 'role' => 'admin'],
];

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (isset($users[$u]) && $users[$u]['password'] === $p) {
        $_SESSION['username'] = $u;
        $_SESSION['role']     = $users[$u]['role'];
        // ⚠️  Rôle aussi stocké dans un cookie non signé, modifiable côté client
        setcookie('role', $users[$u]['role'], 0, '/');
        setcookie('username', $u, 0, '/');
        header('Location: dashboard.php');
        exit;
    } else {
        $error = 'Identifiants incorrects.';
    }
}
?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>BankApp — Connexion</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f0f4ff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,.1);padding:40px;width:100%;max-width:400px}
.logo{text-align:center;margin-bottom:28px}
.logo-mark{display:inline-flex;align-items:center;justify-content:center;width:48px;height:48px;background:#1a3a6b;border-radius:12px;color:#fff;font-size:20px;font-weight:800;margin-bottom:10px}
h1{font-size:20px;color:#1a2744;text-align:center;margin-bottom:4px}
.sub{font-size:13px;color:#8a94a6;text-align:center;margin-bottom:28px}
label{display:block;font-size:12px;font-weight:600;color:#4a5568;margin-bottom:5px}
input{width:100%;padding:10px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:14px;margin-bottom:16px;outline:none;transition:border-color .15s}
input:focus{border-color:#2d6ef7}
.btn{width:100%;padding:12px;background:#1a3a6b;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.btn:hover{background:#152e56}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:16px}
a{color:#2d6ef7;font-size:13px}
.hint{margin-top:16px;text-align:center}
</style></head><body>
<div class="card">
  <div class="logo">
    <div class="logo-mark">B</div>
    <h1>BankApp</h1>
    <p class="sub">Portail client sécurisé</p>
  </div>
  <?php if ($error): ?><div class="err"><?= htmlspecialchars($error) ?></div><?php endif; ?>
  <form method="POST">
    <label>Identifiant</label>
    <input type="text" name="username" placeholder="ex: alice" autocomplete="off">
    <label>Mot de passe</label>
    <input type="password" name="password" placeholder="••••••••">
    <button type="submit" class="btn">Se connecter</button>
  </form>
  <!-- Hints : accès direct via /c04/hints.php uniquement -->
</div>
</body></html>
