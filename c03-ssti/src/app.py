# VulnLab C03 — SSTI Jinja2
from flask import Flask, request, render_template, render_template_string
from markupsafe import Markup
from werkzeug.middleware.proxy_fix import ProxyFix
import datetime
import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_folder=os.path.join(BASE_DIR, 'static'),
    static_url_path='/c03/static',
)
app.secret_key = 'vulnlab-c03-not-secret'
app.wsgi_app = ProxyFix(app.wsgi_app, x_prefix=1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.errorhandler(Exception)
def handle_exception(e):
    logger.exception("Unhandled exception: %s", e)
    return "500 Internal Server Error", 500

# Le template du rapport — body est injecté comme variable Jinja2
# ⚠️ VULNÉRABILITÉ : body est rendu via render_template_string, donc
#    si l'utilisateur met {{ 7*7 }} dans le corps, Jinja2 l'évalue.
#    La clé est que REPORT_TEMPLATE passe body directement comme string
#    dans un SECOND render_template_string, ce qui déclenche la SSTI.

BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>ReportGen — Rapport généré</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
<nav class="navbar">
  <div class="nav-inner">
    <a class="brand" href="{{ url_for('index') }}">ReportGen</a>
    <div class="nav-links">
      <a href="{{ url_for('index') }}">Générateur</a>
      <a href="{{ url_for('history') }}">Historique</a>
    </div>
  </div>
</nav>
<main>
  <div class="page-wrap">
    <div class="report-card">
      <div class="report-header">
        <div class="report-meta">
          <span class="report-badge">RAPPORT</span>
          <span class="report-date">{{ gen_date }}</span>
        </div>
        <h1 class="report-title">{{ title }}</h1>
        <p class="report-author">Rédigé par : {{ author }}</p>
      </div>
      <div class="report-body">
        {{ rendered_body }}
      </div>
      <div class="report-footer">
        Généré par ReportGen v2.1 &nbsp;·&nbsp; Confidentiel<br>
        <a href="{{ url_for('index') }}">← Nouveau rapport</a>
      </div>
    </div>
  </div>
</main>
</body>
</html>"""

reports_history = [
    {"id":1,"title":"Bilan Q3 2024","author":"alice","date":"2024-10-01",
     "body":"Chiffre d'affaires en hausse de 12%. Objectifs atteints sur tous les segments."},
    {"id":2,"title":"Audit infrastructure","author":"bob","date":"2024-11-05",
     "body":"Revue complète des serveurs. 3 vulnérabilités critiques identifiées et corrigées."},
]

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        title  = request.form.get('title',  'Sans titre')
        author = request.form.get('author', 'Anonyme')
        body   = request.form.get('body',   '')
        gen_date = datetime.datetime.now().strftime('%d/%m/%Y %H:%M')

        try:
            # ⚠️ VULNÉRABILITÉ INTENTIONNELLE en deux étapes :
            # Étape 1 : render_template_string évalue body comme template Jinja2
            #           → {{7*7}} devient 49, config.__class__... donne accès aux objets Python
            rendered_body = render_template_string(body)

            # Étape 2 : le résultat est inséré dans le rapport via Markup
            #           (Markup évite le double-encodage HTML mais le body a déjà été évalué)
            return render_template_string(
                BASE_TEMPLATE,
                title        = title,
                author       = author,
                rendered_body= Markup(rendered_body),
                gen_date     = gen_date
            )
        except Exception as e:
            error = f"Erreur lors du rendu : {e}"

    return render_template('index.html', error=error)


@app.route('/history')
def history():
    return render_template('history.html', reports=reports_history)


@app.route('/hints')
def hints():
    return render_template('hints.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
