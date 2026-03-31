<?php
// VulnLab C08 — Local File Inclusion / Path Traversal
// ⚠️ VULNÉRABILITÉ : ?page= injecté dans include() sans filtrage ni extension forcée

$page  = $_GET['page'] ?? 'home';
$pages = ['home', 'about', 'contact'];

ob_start();
// ⚠️ VULNÉRABILITÉ INTENTIONNELLE : include direct sans extension forcée
//    Payloads fonctionnels :
//    ?page=../../../flag          → lit /flag.txt (sans .php)
//    ?page=../../../etc/passwd
//    ?page=../../../proc/self/environ
$file = "pages/" . $page;

if (@is_readable($file . ".php")) {
    // Page légitime
    include($file . ".php");
} elseif (@is_readable($file)) {
    // Fichier sans extension (ex: /flag, /etc/passwd)
    $raw = file_get_contents($file);
    echo '<pre style="font-family:monospace;font-size:13px;background:#1e1e2e;color:#a6e3a1;'
       . 'padding:20px;border-radius:8px;overflow-x:auto;white-space:pre-wrap">'
       . htmlspecialchars($raw) . '</pre>';
} else {
    // Tentative de lecture avec file_get_contents (chemins absolus)
    $raw = @file_get_contents($file);
    if ($raw !== false) {
        echo '<pre style="font-family:monospace;font-size:13px;background:#1e1e2e;color:#a6e3a1;'
           . 'padding:20px;border-radius:8px;overflow-x:auto;white-space:pre-wrap">'
           . htmlspecialchars($raw) . '</pre>';
    } else {
        echo '<div class="alert-err">Fichier introuvable ou non lisible : '
           . htmlspecialchars($file) . '</div>';
    }
}
$content = ob_get_clean();
?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>DocuPortal</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;min-height:100vh}
.navbar{background:#1c2b4a;color:#fff;padding:0 28px;height:54px;display:flex;align-items:center;gap:20px}
.brand{font-weight:800;font-size:17px;letter-spacing:-.02em;color:#fff;text-decoration:none}
.nav-links{display:flex;gap:16px}
.nav-links a{color:rgba(255,255,255,.7);text-decoration:none;font-size:13px}
.nav-links a:hover,.nav-links a.active{color:#fff}
.wrap{max-width:900px;margin:40px auto;padding:0 24px}
.debug-bar{background:#1e1e2e;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.6;margin-bottom:20px}
.k{color:#cba6f7}.v{color:#f38ba8}
.content-card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:28px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.alert-err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:14px;font-size:13px}
</style></head>
<body>
<nav class="navbar">
  <a class="brand" href="?page=home">DocuPortal</a>
  <div class="nav-links">
    <?php foreach ($pages as $p): ?>
    <a href="?page=<?= $p ?>" class="<?= $page===$p?'active':'' ?>"><?= ucfirst($p) ?></a>
    <?php endforeach; ?>
    <!-- Hints accessible via URL directe uniquement : ?page=hints/hints -->
  </div>
</nav>
<div class="wrap">
  <div class="debug-bar">
    <span class="k">include(</span><span class="v">"pages/<?= htmlspecialchars($page) ?>"</span><span class="k">)</span>
    &nbsp;·&nbsp; Paramètre : <span class="v">?page=<?= htmlspecialchars($page) ?></span>
  </div>
  <div class="content-card"><?= $content ?></div>
</div>
</body></html>
