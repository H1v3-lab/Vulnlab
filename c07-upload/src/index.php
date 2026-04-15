<?php
// VulnLab C07 — Unrestricted File Upload
// VULNÉRABILITÉ : seule l'extension est vérifiée (côté client), le MIME type n'est pas contrôlé
$msg = ''; $err = ''; $uploaded = '';
$uploadDir = '/var/www/html/uploads';
$uploadErrors = [
    UPLOAD_ERR_INI_SIZE => "Le fichier dépasse la taille autorisée par le serveur.",
    UPLOAD_ERR_FORM_SIZE => "Le fichier dépasse la taille autorisée par le formulaire.",
    UPLOAD_ERR_PARTIAL => "Le fichier n'a été envoyé que partiellement.",
    UPLOAD_ERR_NO_FILE => "Aucun fichier n'a été envoyé.",
    UPLOAD_ERR_NO_TMP_DIR => "Dossier temporaire manquant sur le serveur.",
    UPLOAD_ERR_CANT_WRITE => "Le serveur n'a pas pu écrire le fichier sur le disque.",
    UPLOAD_ERR_EXTENSION => "L'envoi du fichier a été interrompu par une extension PHP."
];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    $name = basename($file['name']);
    $ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));

    // ⚠️  VULNÉRABILITÉ : liste blanche d'extensions seulement, pas de vérif magic bytes
    $allowed = ['jpg','jpeg','png','gif'];
    if (!in_array($ext, $allowed)) {
        $err = "Extension non autorisée : .$ext — seules jpg, jpeg, png, gif sont acceptées.";
    } else {
        // ⚠️  Le fichier est stocké avec son nom original dans un dossier web-accessible
        $dest = $uploadDir . '/' . $name;
        $uploadErrorCode = $file['error'] ?? UPLOAD_ERR_OK;
        if ($uploadErrorCode !== UPLOAD_ERR_OK) {
            $err = isset($uploadErrors[$uploadErrorCode])
                ? $uploadErrors[$uploadErrorCode]
                : "Échec de l'upload.";
        } elseif (!is_dir($uploadDir)) {
            $err = "Le dossier de destination n'existe pas.";
        } elseif (!is_writable($uploadDir)) {
            $err = "Le dossier de destination n'est pas accessible en écriture.";
        } elseif (!move_uploaded_file($file['tmp_name'], $dest)) {
            $err = "Impossible de déplacer le fichier uploadé.";
        } else {
            $uploaded = $name;
            $msg = "Fichier uploadé : uploads/$name";
        }
    }
}

// Lister les fichiers uploadés
$scannedFiles = is_dir($uploadDir) ? scandir($uploadDir) : false;
$files = is_array($scannedFiles) ? array_diff($scannedFiles, ['.','..']) : [];
if ($scannedFiles === false && $err === '') {
    $err = "Impossible de lire le dossier des uploads.";
}
?><!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>AvatarHub — Upload</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;min-height:100vh;padding:40px 24px}
.wrap{max-width:800px;margin:0 auto}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:28px;margin-bottom:20px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
h1{font-size:22px;color:#1a2744;margin-bottom:6px}
.sub{font-size:13px;color:#8a94a6;margin-bottom:24px;font-family:monospace}
.drop-zone{border:2px dashed #c3d4f0;border-radius:10px;padding:40px;text-align:center;background:#f8faff;cursor:pointer;transition:border-color .2s}
.drop-zone:hover{border-color:#2d6ef7}
.drop-label{font-size:14px;color:#8a94a6;margin-bottom:8px}
.drop-hint{font-size:12px;color:#b0b7c3}
input[type=file]{display:none}
.btn{display:inline-block;margin-top:16px;padding:10px 24px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer}
.ok{background:#f0fdf4;border:1px solid #bbf7d0;color:#166534;border-radius:8px;padding:12px 16px;font-size:13px;margin-bottom:14px}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:12px 16px;font-size:13px;margin-bottom:14px}
.file-list{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}
.file-item{background:#f5f6f8;border:1px solid #e2e8f0;border-radius:8px;padding:8px 14px;font-size:13px;font-family:monospace}
.file-item a{color:#2d6ef7;text-decoration:none}
.file-item.php-file{background:#fef2f2;border-color:#fecaca}
.file-item.php-file a{color:#dc2626}
.debug{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin-top:16px}
.flag{color:#86efac;font-weight:700}
a.nav{color:#2d6ef7;font-size:13px;text-decoration:none}
</style></head><body>
<div class="wrap">
  <div class="card">
    <h1>AvatarHub — Gestionnaire d'avatars</h1>
    <p class="sub">Upload restreint aux images (jpg, png, gif) — vérification par extension uniquement</p>

    <?php if ($msg): ?><div class="ok">✓ <?= htmlspecialchars($msg) ?></div><?php endif; ?>
    <?php if ($err): ?><div class="err">✕ <?= htmlspecialchars($err) ?></div><?php endif; ?>

    <form method="POST" enctype="multipart/form-data" id="form">
      <div class="drop-zone" onclick="document.getElementById('f').click()">
        <div class="drop-label">📁 Cliquez pour choisir un fichier</div>
        <div class="drop-hint" id="fname">jpg, jpeg, png, gif — max 5 Mo</div>
        <input type="file" name="avatar" id="f" onchange="document.getElementById('fname').textContent=this.files[0]?.name||''">
      </div>
      <button type="submit" class="btn">Uploader →</button>
    </form>

    <?php if ($uploaded): ?>
    <div class="debug">
      Fichier stocké dans : <span style="color:#f38ba8">/var/www/html/uploads/<?= htmlspecialchars($uploaded) ?></span><br>
      URL accessible : <a href="/c07/uploads/<?= urlencode($uploaded) ?>" style="color:#89dceb" target="_blank">/c07/uploads/<?= htmlspecialchars($uploaded) ?></a><br>
      <?php if (str_ends_with(strtolower($uploaded), '.php')): ?>
      <span class="flag">⚡ Webshell déployé ! Accédez-y via le lien ci-dessus.</span>
      <?php endif; ?>
    </div>
    <?php endif; ?>
  </div>

  <div class="card">
    <h3 style="font-size:15px;font-weight:600;margin-bottom:14px;color:#1a2744">Fichiers uploadés</h3>
    <?php if (empty($files)): ?>
    <p style="font-size:13px;color:#8a94a6">Aucun fichier uploadé.</p>
    <?php else: ?>
    <div class="file-list">
      <?php foreach ($files as $f):
        $is_php = str_ends_with(strtolower($f), '.php'); ?>
      <div class="file-item <?= $is_php ? 'php-file' : '' ?>">
        <a href="/c07/uploads/<?= urlencode($f) ?>" target="_blank"><?= htmlspecialchars($f) ?></a>
        <?php if ($is_php): ?> ⚡<?php endif; ?>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </div>

  <!-- hints: accès direct via /c07/hints.php uniquement -->
</div>
</body></html>
