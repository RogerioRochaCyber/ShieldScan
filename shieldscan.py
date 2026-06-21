from flask import Flask, request, render_template_string
import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# ─────────────────────────────────────────────
# Proteção contra SSRF
# ─────────────────────────────────────────────
def is_safe_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
        blocked_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18.",
                            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                            "172.29.", "172.30.", "172.31."]
        if hostname in blocked_hosts:
            return False
        for prefix in blocked_prefixes:
            if hostname.startswith(prefix):
                return False
        return True
    except Exception:
        return False


def check_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except (socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError):
        return False


def check_headers(url):
    security_headers = [
        ("Content-Security-Policy", "Protege contra ataques XSS e injeção de conteúdo", "ALTO"),
        ("X-Frame-Options", "Previne ataques de Clickjacking", "MÉDIO"),
        ("X-XSS-Protection", "Proteção adicional contra scripts maliciosos", "MÉDIO"),
        ("Strict-Transport-Security", "Força uso de HTTPS em todas as conexões", "ALTO"),
        ("X-Content-Type-Options", "Previne que o browser interprete arquivos incorretamente", "BAIXO"),
        ("Referrer-Policy", "Controla informações enviadas em requisições", "BAIXO"),
        ("Permissions-Policy", "Controla acesso a recursos do navegador", "BAIXO"),
    ]
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing = []
        present = []
        for h, desc, criticidade in security_headers:
            if h not in headers:
                missing.append({"header": h, "descricao": desc, "criticidade": criticidade})
            else:
                present.append({"header": h, "descricao": desc})
        return missing, present
    except (requests.ConnectionError, requests.Timeout, requests.RequestException):
        return [], []


def calcular_score(ssl_ok, missing_headers):
    score = 100
    if not ssl_ok:
        score -= 40
    for h in missing_headers:
        if h["criticidade"] == "ALTO":
            score -= 12
        elif h["criticidade"] == "MÉDIO":
            score -= 8
        else:
            score -= 4
    return max(score, 0)


def classificar_risco(score):
    if score >= 80:
        return "BAIXO", "#00d97e", "Seu site está bem protegido!"
    elif score >= 50:
        return "MÉDIO", "#f6c343", "Seu site tem vulnerabilidades que precisam de atenção."
    else:
        return "ALTO", "#e63757", "Seu site está em risco! Ação imediata recomendada."


def analyze_site(url):
    if not url.startswith("http"):
        url = "http://" + url

    if not is_safe_url(url):
        return None, "URL não permitida por razões de segurança"

    hostname = urlparse(url).hostname or ""
    ssl_ok = check_ssl(hostname)
    missing_headers, present_headers = check_headers(url)
    score = calcular_score(ssl_ok, missing_headers)
    risco, cor, mensagem = classificar_risco(score)

    recomendacoes = []
    if not ssl_ok:
        recomendacoes.append({
            "titulo": "Instalar certificado SSL",
            "descricao": "Seu site não possui HTTPS. Isso expõe dados dos usuários. Instale um certificado SSL gratuito via Let's Encrypt.",
            "prioridade": "URGENTE"
        })
    for h in missing_headers:
        if h["criticidade"] == "ALTO":
            recomendacoes.append({
                "titulo": f"Adicionar header {h['header']}",
                "descricao": h["descricao"],
                "prioridade": "IMPORTANTE"
            })
    for h in missing_headers:
        if h["criticidade"] in ["MÉDIO", "BAIXO"]:
            recomendacoes.append({
                "titulo": f"Adicionar header {h['header']}",
                "descricao": h["descricao"],
                "prioridade": "RECOMENDADO"
            })

    return {
        "url": url,
        "hostname": hostname,
        "ssl": ssl_ok,
        "score": score,
        "risco": risco,
        "cor_risco": cor,
        "mensagem": mensagem,
        "headers_faltando": missing_headers,
        "headers_ok": present_headers,
        "recomendacoes": recomendacoes,
        "data": datetime.now().strftime("%d/%m/%Y às %H:%M")
    }, None


# ─────────────────────────────────────────────
# Template HTML
# ─────────────────────────────────────────────
HOME_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShieldScan — Scanner de Segurança</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #050810;
    --surface: #0d1120;
    --border: #1a2240;
    --accent: #00e5ff;
    --accent2: #7b5cff;
    --text: #e8eaf6;
    --muted: #5c6880;
    --danger: #e63757;
    --warning: #f6c343;
    --success: #00d97e;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Background grid */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .glow-orb {
    position: fixed;
    width: 600px;
    height: 600px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(0,229,255,0.06) 0%, transparent 70%);
    top: -200px;
    left: 50%;
    transform: translateX(-50%);
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 760px;
    margin: 0 auto;
    padding: 60px 24px;
  }

  /* Header */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(0,229,255,0.08);
    border: 1px solid rgba(0,229,255,0.2);
    color: var(--accent);
    padding: 6px 14px;
    border-radius: 100px;
    font-size: 12px;
    font-weight: 500;
    letter-spacing: 0.5px;
    margin-bottom: 32px;
    animation: fadeDown 0.6s ease;
  }

  .badge::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent);
    animation: pulse 2s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.8); }
  }

  h1 {
    font-family: 'Syne', sans-serif;
    font-size: clamp(36px, 6vw, 58px);
    font-weight: 800;
    line-height: 1.1;
    margin-bottom: 20px;
    animation: fadeDown 0.6s ease 0.1s both;
  }

  h1 span {
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .subtitle {
    color: var(--muted);
    font-size: 18px;
    line-height: 1.6;
    margin-bottom: 48px;
    max-width: 520px;
    animation: fadeDown 0.6s ease 0.2s both;
  }

  /* Scan form */
  .scan-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 32px;
    margin-bottom: 48px;
    animation: fadeUp 0.6s ease 0.3s both;
    position: relative;
    overflow: hidden;
  }

  .scan-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: 0.4;
  }

  .input-row {
    display: flex;
    gap: 12px;
  }

  input[type="text"] {
    flex: 1;
    background: rgba(255,255,255,0.04);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 20px;
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    font-size: 15px;
    outline: none;
    transition: border-color 0.2s;
  }

  input[type="text"]:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(0,229,255,0.1);
  }

  input[type="text"]::placeholder { color: var(--muted); }

  button {
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    border: none;
    border-radius: 12px;
    padding: 16px 28px;
    color: #050810;
    font-family: 'Syne', sans-serif;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
    white-space: nowrap;
    transition: opacity 0.2s, transform 0.1s;
  }

  button:hover { opacity: 0.9; transform: translateY(-1px); }
  button:active { transform: translateY(0); }

  /* Stats */
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    animation: fadeUp 0.6s ease 0.4s both;
  }

  .stat {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    text-align: center;
  }

  .stat-value {
    font-family: 'Syne', sans-serif;
    font-size: 28px;
    font-weight: 800;
    color: var(--accent);
  }

  .stat-label {
    color: var(--muted);
    font-size: 13px;
    margin-top: 4px;
  }

  @keyframes fadeDown {
    from { opacity: 0; transform: translateY(-16px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @media (max-width: 480px) {
    .input-row { flex-direction: column; }
    .stats { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="glow-orb"></div>
<div class="container">
  <div class="badge">🛡️ Scanner de Segurança Web</div>
  <h1>Seu site está<br><span>realmente seguro?</span></h1>
  <p class="subtitle">Analise vulnerabilidades em segundos. Relatório completo com score de segurança, headers HTTP e recomendações detalhadas.</p>

  <div class="scan-card">
    <form method="post" action="/scan_web">
      <div class="input-row">
        <input type="text" name="url" placeholder="Digite o endereço do site (ex: meusite.com.br)" required>
        <button type="submit">🔍 Analisar</button>
      </div>
    </form>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-value">7</div>
      <div class="stat-label">Verificações de segurança</div>
    </div>
    <div class="stat">
      <div class="stat-value">60s</div>
      <div class="stat-label">Tempo médio de análise</div>
    </div>
    <div class="stat">
      <div class="stat-value">100%</div>
      <div class="stat-label">Gratuito para testar</div>
    </div>
  </div>
</div>
</body>
</html>
"""

RESULT_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Resultado — {{ result.hostname }}</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg: #050810;
    --surface: #0d1120;
    --border: #1a2240;
    --accent: #00e5ff;
    --accent2: #7b5cff;
    --text: #e8eaf6;
    --muted: #5c6880;
    --danger: #e63757;
    --warning: #f6c343;
    --success: #00d97e;
  }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'DM Sans', sans-serif;
    min-height: 100vh;
  }

  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 820px;
    margin: 0 auto;
    padding: 48px 24px;
  }

  .back-link {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: var(--muted);
    text-decoration: none;
    font-size: 14px;
    margin-bottom: 32px;
    transition: color 0.2s;
  }
  .back-link:hover { color: var(--text); }

  /* Score hero */
  .hero {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 24px;
    padding: 40px;
    margin-bottom: 24px;
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 32px;
    align-items: center;
    position: relative;
    overflow: hidden;
    animation: fadeUp 0.5s ease;
  }

  .hero::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, {{ result.cor_risco }}, transparent);
  }

  .hero-title {
    font-family: 'Syne', sans-serif;
    font-size: 13px;
    font-weight: 600;
    color: var(--muted);
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .hero-url {
    font-family: 'Syne', sans-serif;
    font-size: 22px;
    font-weight: 700;
    margin-bottom: 12px;
    color: var(--accent);
  }

  .hero-message {
    color: var(--muted);
    font-size: 15px;
    line-height: 1.5;
  }

  .score-circle {
    width: 140px;
    height: 140px;
    position: relative;
    flex-shrink: 0;
  }

  .score-circle svg {
    transform: rotate(-90deg);
    width: 140px;
    height: 140px;
  }

  .score-circle .track {
    fill: none;
    stroke: var(--border);
    stroke-width: 8;
  }

  .score-circle .fill {
    fill: none;
    stroke: {{ result.cor_risco }};
    stroke-width: 8;
    stroke-linecap: round;
    stroke-dasharray: 345;
    stroke-dashoffset: {{ 345 - (345 * result.score / 100) }};
    filter: drop-shadow(0 0 6px {{ result.cor_risco }});
    transition: stroke-dashoffset 1s ease;
  }

  .score-value {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }

  .score-number {
    font-family: 'Syne', sans-serif;
    font-size: 36px;
    font-weight: 800;
    color: {{ result.cor_risco }};
    line-height: 1;
  }

  .score-label {
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
  }

  /* Risk badge */
  .risk-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border-radius: 100px;
    font-size: 13px;
    font-weight: 600;
    margin-top: 12px;
    background: {{ result.cor_risco }}20;
    color: {{ result.cor_risco }};
    border: 1px solid {{ result.cor_risco }}40;
  }

  /* Cards grid */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 24px;
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 28px;
    animation: fadeUp 0.5s ease 0.1s both;
  }

  .card-title {
    font-family: 'Syne', sans-serif;
    font-size: 14px;
    font-weight: 700;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  /* SSL status */
  .ssl-status {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px;
    border-radius: 12px;
    background: {% if result.ssl %}rgba(0,217,126,0.08){% else %}rgba(230,55,87,0.08){% endif %};
    border: 1px solid {% if result.ssl %}rgba(0,217,126,0.2){% else %}rgba(230,55,87,0.2){% endif %};
  }

  .ssl-icon {
    font-size: 28px;
  }

  .ssl-text strong {
    font-family: 'Syne', sans-serif;
    font-size: 16px;
    color: {% if result.ssl %}var(--success){% else %}var(--danger){% endif %};
    display: block;
  }

  .ssl-text span {
    font-size: 13px;
    color: var(--muted);
  }

  /* Header items */
  .header-item {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid var(--border);
  }

  .header-item:last-child { border-bottom: none; }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-top: 5px;
    flex-shrink: 0;
  }

  .dot-ok { background: var(--success); }
  .dot-miss { background: var(--danger); }
  .dot-warn { background: var(--warning); }

  .header-name {
    font-size: 13px;
    font-weight: 500;
    color: var(--text);
    font-family: 'DM Sans', monospace;
  }

  .header-desc {
    font-size: 12px;
    color: var(--muted);
    margin-top: 2px;
    line-height: 1.4;
  }

  /* Criticidade tags */
  .crit {
    font-size: 10px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-left: auto;
    flex-shrink: 0;
  }
  .crit-alto { background: rgba(230,55,87,0.15); color: var(--danger); }
  .crit-medio { background: rgba(246,195,67,0.15); color: var(--warning); }
  .crit-baixo { background: rgba(0,217,126,0.15); color: var(--success); }

  /* Recomendações */
  .rec-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 28px;
    margin-bottom: 24px;
    animation: fadeUp 0.5s ease 0.2s both;
  }

  .rec-item {
    display: flex;
    gap: 16px;
    padding: 16px 0;
    border-bottom: 1px solid var(--border);
  }

  .rec-item:last-child { border-bottom: none; }

  .rec-priority {
    font-size: 10px;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    white-space: nowrap;
    height: fit-content;
    margin-top: 2px;
  }

  .prio-urgente { background: rgba(230,55,87,0.15); color: var(--danger); border: 1px solid rgba(230,55,87,0.3); }
  .prio-importante { background: rgba(246,195,67,0.15); color: var(--warning); border: 1px solid rgba(246,195,67,0.3); }
  .prio-recomendado { background: rgba(0,217,126,0.1); color: var(--success); border: 1px solid rgba(0,217,126,0.2); }

  .rec-content strong {
    font-size: 14px;
    font-weight: 600;
    display: block;
    margin-bottom: 4px;
  }

  .rec-content span {
    font-size: 13px;
    color: var(--muted);
    line-height: 1.5;
  }

  /* Footer CTA */
  .cta {
    background: linear-gradient(135deg, rgba(0,229,255,0.06), rgba(123,92,255,0.06));
    border: 1px solid rgba(0,229,255,0.15);
    border-radius: 20px;
    padding: 32px;
    text-align: center;
    animation: fadeUp 0.5s ease 0.3s both;
  }

  .cta h3 {
    font-family: 'Syne', sans-serif;
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 8px;
  }

  .cta p {
    color: var(--muted);
    font-size: 14px;
    margin-bottom: 20px;
  }

  .cta-btn {
    display: inline-block;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #050810;
    font-family: 'Syne', sans-serif;
    font-weight: 700;
    font-size: 14px;
    padding: 14px 28px;
    border-radius: 12px;
    text-decoration: none;
    transition: opacity 0.2s;
  }

  .cta-btn:hover { opacity: 0.85; }

  .meta {
    text-align: right;
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 24px;
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(16px); }
    to { opacity: 1; transform: translateY(0); }
  }

  @media (max-width: 600px) {
    .hero { grid-template-columns: 1fr; }
    .score-circle { margin: 0 auto; }
    .grid-2 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<div class="container">
  <a href="/" class="back-link">← Fazer nova análise</a>
  <p class="meta">Análise realizada em {{ result.data }}</p>

  <!-- Score Hero -->
  <div class="hero">
    <div>
      <div class="hero-title">Relatório de Segurança</div>
      <div class="hero-url">{{ result.hostname }}</div>
      <div class="hero-message">{{ result.mensagem }}</div>
      <div class="risk-badge">
        {% if result.risco == 'BAIXO' %}✅{% elif result.risco == 'MÉDIO' %}⚠️{% else %}🚨{% endif %}
        Risco {{ result.risco }}
      </div>
    </div>
    <div class="score-circle">
      <svg viewBox="0 0 120 120">
        <circle class="track" cx="60" cy="60" r="55"/>
        <circle class="fill" cx="60" cy="60" r="55"/>
      </svg>
      <div class="score-value">
        <div class="score-number">{{ result.score }}</div>
        <div class="score-label">/ 100</div>
      </div>
    </div>
  </div>

  <!-- SSL + Headers OK -->
  <div class="grid-2">
    <div class="card">
      <div class="card-title">🔒 Certificado SSL</div>
      <div class="ssl-status">
        <div class="ssl-icon">{% if result.ssl %}🟢{% else %}🔴{% endif %}</div>
        <div class="ssl-text">
          <strong>{% if result.ssl %}HTTPS Ativo{% else %}HTTPS Ausente{% endif %}</strong>
          <span>{% if result.ssl %}Conexão criptografada e segura{% else %}Dados dos usuários expostos{% endif %}</span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">✅ Headers OK ({{ result.headers_ok|length }})</div>
      {% if result.headers_ok %}
        {% for h in result.headers_ok %}
        <div class="header-item">
          <div class="dot dot-ok"></div>
          <div>
            <div class="header-name">{{ h.header }}</div>
            <div class="header-desc">{{ h.descricao }}</div>
          </div>
        </div>
        {% endfor %}
      {% else %}
        <p style="color: var(--muted); font-size: 14px;">Nenhum header de segurança encontrado.</p>
      {% endif %}
    </div>
  </div>

  <!-- Headers Faltando -->
  {% if result.headers_faltando %}
  <div class="card" style="margin-bottom: 24px;">
    <div class="card-title">❌ Headers Faltando ({{ result.headers_faltando|length }})</div>
    {% for h in result.headers_faltando %}
    <div class="header-item">
      <div class="dot {% if h.criticidade == 'ALTO' %}dot-miss{% elif h.criticidade == 'MÉDIO' %}dot-warn{% else %}dot-ok{% endif %}"></div>
      <div style="flex: 1;">
        <div class="header-name">{{ h.header }}</div>
        <div class="header-desc">{{ h.descricao }}</div>
      </div>
      <div class="crit crit-{% if h.criticidade == 'ALTO' %}alto{% elif h.criticidade == 'MÉDIO' %}medio{% else %}baixo{% endif %}">{{ h.criticidade }}</div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Recomendações -->
  {% if result.recomendacoes %}
  <div class="rec-card">
    <div class="card-title">💡 Recomendações ({{ result.recomendacoes|length }})</div>
    {% for rec in result.recomendacoes %}
    <div class="rec-item">
      <div class="rec-priority prio-{{ rec.prioridade|lower }}">{{ rec.prioridade }}</div>
      <div class="rec-content">
        <strong>{{ rec.titulo }}</strong>
        <span>{{ rec.descricao }}</span>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- CTA -->
  <div class="cta">
    <h3>Quer monitoramento contínuo?</h3>
    <p>Receba alertas automáticos toda vez que uma nova vulnerabilidade for detectada no seu site.</p>
    <div style="display:flex; gap:12px; justify-content:center; flex-wrap:wrap;">
      <a href="/" class="cta-btn">🚀 Analisar outro site</a>
      <form method="post" action="/export_pdf" style="margin:0;">
        <input type="hidden" name="url" value="{{ result.url }}">
        <button type="submit" class="cta-btn" style="background: linear-gradient(135deg, #1a2240, #0d1120); border: 1px solid rgba(0,229,255,0.3); color: #00e5ff; cursor:pointer; font-family:'Syne',sans-serif; font-size:14px; font-weight:700; padding:14px 28px; border-radius:12px; text-decoration:none; transition:opacity 0.2s;">
          📄 Exportar PDF
        </button>
      </form>
    </div>
  </div>
</div>
</body>
</html>
"""

ERROR_HTML = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Erro — ShieldScan</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans&display=swap" rel="stylesheet">
<style>
  body { background: #050810; color: #e8eaf6; font-family: 'DM Sans', sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .box { text-align: center; max-width: 400px; padding: 40px; }
  h2 { font-family: 'Syne', sans-serif; font-size: 28px; margin-bottom: 12px; color: #e63757; }
  p { color: #5c6880; margin-bottom: 24px; }
  a { color: #00e5ff; text-decoration: none; }
</style>
</head>
<body>
<div class="box">
  <h2>⚠️ Erro na análise</h2>
  <p>{{ erro }}</p>
  <a href="/">← Voltar e tentar novamente</a>
</div>
</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(HOME_HTML)


@app.route("/scan_web", methods=["POST"])
def scan_web():
    url = request.form.get("url", "").strip()
    if not url:
        return render_template_string(ERROR_HTML, erro="URL não fornecida.")
    result, erro = analyze_site(url)
    if erro:
        return render_template_string(ERROR_HTML, erro=erro)
    return render_template_string(RESULT_HTML, result=result)


@app.route("/scan", methods=["POST"])
def scan():
    from flask import jsonify
    data = request.json
    if not data:
        return jsonify({"erro": "JSON inválido"}), 400
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"erro": "URL não fornecida"}), 400
    result, erro = analyze_site(url)
    if erro:
        return jsonify({"erro": erro}), 400
    return jsonify(result)


@app.route("/export_pdf", methods=["POST"])
def export_pdf():
    from flask import send_file, jsonify
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    url = request.form.get("url", "").strip()
    if not url:
        return "URL não fornecida", 400

    result, erro = analyze_site(url)
    if erro:
        return erro, 400

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    # Color palette
    BG_DARK    = colors.HexColor("#050810")
    ACCENT     = colors.HexColor("#00e5ff")
    ACCENT2    = colors.HexColor("#7b5cff")
    TEXT       = colors.HexColor("#e8eaf6")
    MUTED      = colors.HexColor("#5c6880")
    DANGER     = colors.HexColor("#e63757")
    WARNING    = colors.HexColor("#f6c343")
    SUCCESS    = colors.HexColor("#00d97e")
    SURFACE    = colors.HexColor("#0d1120")
    BORDER     = colors.HexColor("#1a2240")

    risk_color = {
        "BAIXO": SUCCESS,
        "MÉDIO": WARNING,
        "ALTO":  DANGER
    }.get(result["risco"], ACCENT)

    prio_color = {
        "URGENTE":    DANGER,
        "IMPORTANTE": WARNING,
        "RECOMENDADO": SUCCESS
    }

    # Styles
    def S(name, **kw):
        base = dict(fontName="Helvetica", fontSize=10, textColor=TEXT, leading=14, spaceAfter=0, spaceBefore=0)
        base.update(kw)
        return ParagraphStyle(name, **base)

    style_title    = S("title",    fontName="Helvetica-Bold", fontSize=22, textColor=ACCENT,  leading=28, spaceAfter=4)
    style_subtitle = S("subtitle", fontSize=11, textColor=MUTED, leading=16, spaceAfter=2)
    style_url      = S("url",      fontName="Helvetica-Bold", fontSize=13, textColor=ACCENT, leading=18)
    style_section  = S("section",  fontName="Helvetica-Bold", fontSize=11, textColor=MUTED,  leading=16, spaceBefore=6)
    style_body     = S("body",     fontSize=10, textColor=TEXT,  leading=14)
    style_small    = S("small",    fontSize=9,  textColor=MUTED, leading=13)
    style_score    = S("score",    fontName="Helvetica-Bold", fontSize=36, textColor=risk_color, leading=40, alignment=TA_CENTER)
    style_risk     = S("risk",     fontName="Helvetica-Bold", fontSize=13, textColor=risk_color, leading=18, alignment=TA_CENTER)
    style_msg      = S("msg",      fontSize=10, textColor=MUTED, leading=14, alignment=TA_CENTER)
    style_meta     = S("meta",     fontSize=8,  textColor=MUTED, leading=12, alignment=TA_RIGHT)
    style_hname    = S("hname",    fontName="Helvetica-Bold", fontSize=10, textColor=TEXT, leading=14)
    style_hdesc    = S("hdesc",    fontSize=9,  textColor=MUTED, leading=13)

    story = []

    # ── Header ──────────────────────────────────────────
    header_data = [[
        Paragraph("🛡️ ShieldScan", S("logo", fontName="Helvetica-Bold", fontSize=16, textColor=ACCENT, leading=20)),
        Paragraph(f"Análise realizada em {result['data']}", style_meta)
    ]]
    header_table = Table(header_data, colWidths=[10*cm, 7*cm])
    header_table.setStyle(TableStyle([
        ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
        ("BACKGROUND",  (0,0), (-1,-1), SURFACE),
        ("TOPPADDING",  (0,0), (-1,-1), 14),
        ("BOTTOMPADDING",(0,0),(-1,-1), 14),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
        ("RIGHTPADDING",(0,0), (-1,-1), 16),
        ("LINEBELOW",   (0,0), (-1,-1), 1, BORDER),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 16))

    # ── Score Hero ───────────────────────────────────────
    hero_left = [
        [Paragraph("RELATÓRIO DE SEGURANÇA", style_section)],
        [Paragraph(result["hostname"], style_url)],
        [Spacer(1, 6)],
        [Paragraph(result["mensagem"], style_body)],
        [Spacer(1, 10)],
        [Paragraph(f"⚠ Risco {result['risco']}" if result["risco"] != "BAIXO" else f"✓ Risco {result['risco']}", S("rb", fontName="Helvetica-Bold", fontSize=12, textColor=risk_color, leading=16))],
    ]
    hero_right = [
        [Paragraph(str(result["score"]), style_score)],
        [Paragraph("/ 100", style_msg)],
        [Spacer(1, 4)],
        [Paragraph(result["risco"], style_risk)],
    ]

    left_t  = Table(hero_left,  colWidths=[10.5*cm])
    right_t = Table(hero_right, colWidths=[5.5*cm])
    for t in (left_t, right_t):
        t.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),0),("RIGHTPADDING",(0,0),(-1,-1),0),("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2)]))

    hero = Table([[left_t, right_t]], colWidths=[10.5*cm, 5.5*cm])
    hero.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), SURFACE),
        ("TOPPADDING",   (0,0),(-1,-1), 20),
        ("BOTTOMPADDING",(0,0),(-1,-1), 20),
        ("LEFTPADDING",  (0,0),(-1,-1), 20),
        ("RIGHTPADDING", (0,0),(-1,-1), 20),
        ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ("LINEABOVE",    (0,0),(-1,0),  2, risk_color),
    ]))
    story.append(hero)
    story.append(Spacer(1, 16))

    # ── SSL ──────────────────────────────────────────────
    ssl_color = SUCCESS if result["ssl"] else DANGER
    ssl_text  = "HTTPS Ativo — Conexão criptografada e segura" if result["ssl"] else "HTTPS Ausente — Dados dos usuários expostos"
    ssl_icon  = "🟢" if result["ssl"] else "🔴"
    ssl_table = Table([
        [Paragraph("🔒 CERTIFICADO SSL", style_section)],
        [Paragraph(f"{ssl_icon}  {ssl_text}", S("ssl", fontName="Helvetica-Bold", fontSize=11, textColor=ssl_color, leading=16))],
    ], colWidths=[17*cm])
    ssl_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), SURFACE),
        ("TOPPADDING",   (0,0),(-1,-1), 12),
        ("BOTTOMPADDING",(0,0),(-1,-1), 12),
        ("LEFTPADDING",  (0,0),(-1,-1), 16),
        ("RIGHTPADDING", (0,0),(-1,-1), 16),
        ("LINEABOVE",    (0,0),(-1,0),  1, BORDER),
        ("LINEBELOW",    (0,-1),(-1,-1),1, BORDER),
    ]))
    story.append(ssl_table)
    story.append(Spacer(1, 12))

    # ── Headers OK ───────────────────────────────────────
    if result["headers_ok"]:
        rows = [[Paragraph(f"✅ HEADERS OK ({len(result['headers_ok'])})", style_section)]]
        for h in result["headers_ok"]:
            rows.append([Table([[
                Paragraph("●", S("dot", fontSize=10, textColor=SUCCESS, leading=14)),
                Table([
                    [Paragraph(h["header"], style_hname)],
                    [Paragraph(h["descricao"], style_hdesc)],
                ], colWidths=[14*cm])
            ]], colWidths=[1*cm, 14*cm])])
        ok_table = Table(rows, colWidths=[17*cm])
        ok_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), SURFACE),
            ("TOPPADDING",   (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ("LEFTPADDING",  (0,0),(-1,-1), 16),
            ("RIGHTPADDING", (0,0),(-1,-1), 16),
            ("LINEABOVE",    (0,0),(-1,0),  1, BORDER),
            ("LINEBELOW",    (0,-1),(-1,-1),1, BORDER),
        ]))
        story.append(ok_table)
        story.append(Spacer(1, 12))

    # ── Headers Faltando ─────────────────────────────────
    if result["headers_faltando"]:
        crit_colors = {"ALTO": DANGER, "MÉDIO": WARNING, "BAIXO": SUCCESS}
        rows = [[Paragraph(f"❌ HEADERS FALTANDO ({len(result['headers_faltando'])})", style_section)]]
        for h in result["headers_faltando"]:
            cc = crit_colors.get(h["criticidade"], MUTED)
            rows.append([Table([[
                Paragraph("●", S("dot2", fontSize=10, textColor=cc, leading=14)),
                Table([
                    [Paragraph(h["header"], style_hname),
                     Paragraph(h["criticidade"], S("crit", fontName="Helvetica-Bold", fontSize=8, textColor=cc, leading=12))],
                    [Paragraph(h["descricao"], style_hdesc), Paragraph("", style_hdesc)],
                ], colWidths=[11*cm, 3*cm])
            ]], colWidths=[1*cm, 14*cm])])
        miss_table = Table(rows, colWidths=[17*cm])
        miss_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), SURFACE),
            ("TOPPADDING",   (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ("LEFTPADDING",  (0,0),(-1,-1), 16),
            ("RIGHTPADDING", (0,0),(-1,-1), 16),
            ("LINEABOVE",    (0,0),(-1,0),  1, BORDER),
            ("LINEBELOW",    (0,-1),(-1,-1),1, BORDER),
        ]))
        story.append(miss_table)
        story.append(Spacer(1, 12))

    # ── Recomendações ─────────────────────────────────────
    if result["recomendacoes"]:
        rows = [[Paragraph(f"💡 RECOMENDAÇÕES ({len(result['recomendacoes'])})", style_section)]]
        for rec in result["recomendacoes"]:
            pc = prio_color.get(rec["prioridade"], MUTED)
            rows.append([Table([[
                Paragraph(rec["prioridade"], S("prio", fontName="Helvetica-Bold", fontSize=8, textColor=pc, leading=12)),
                Table([
                    [Paragraph(rec["titulo"],   style_hname)],
                    [Paragraph(rec["descricao"], style_hdesc)],
                ], colWidths=[12.5*cm])
            ]], colWidths=[3.5*cm, 12.5*cm])])
        rec_table = Table(rows, colWidths=[17*cm])
        rec_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), SURFACE),
            ("TOPPADDING",   (0,0),(-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ("LEFTPADDING",  (0,0),(-1,-1), 16),
            ("RIGHTPADDING", (0,0),(-1,-1), 16),
            ("LINEABOVE",    (0,0),(-1,0),  1, BORDER),
            ("LINEBELOW",    (0,-1),(-1,-1),1, BORDER),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 16))

    # ── Footer ───────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Gerado por ShieldScan — Scanner de Segurança Web  |  Relatório confidencial",
        S("footer", fontSize=8, textColor=MUTED, alignment=TA_CENTER, leading=12)
    ))

    doc.build(story)
    buffer.seek(0)

    filename = f"shieldscan_{result['hostname'].replace('.', '_')}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
