"""
VIGIL + NeuroGuard AI — Unified Cybersecurity Intelligence Platform
Clean rebuild: real system monitoring + real ML phishing detection
"""
from streamlit_autorefresh import st_autorefresh
import streamlit as st
import streamlit.components.v1 as components
import time
import pickle
from datetime import datetime

import psutil
from phishing_detector import check_phishing
# 🔥 ADD THIS LINE
st.session_state.setdefault("ext_url", "")
st.session_state.setdefault("auto_scan", False)
# ✅ history init
if "history" not in st.session_state:
    st.session_state["history"] = []

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="VIGIL + NeuroGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Sample URLs for batch scan ────────────────────────────────────────────────
SAMPLE_URLS = [
    "http://paypa1-secure-login.tk/account/verify?id=84729",
    "http://192.168.1.1/admin/steal-credentials.php",
    "https://www.google.com",
    "https://github.com/streamlit/streamlit",
    "http://free-iphone-winner.xyz/claim?ref=abc123&token=xyz",
]

# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL CSS
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');

:root {
    --cyan:   #00f5ff;
    --pink:   #ff00a0;
    --green:  #00ff88;
    --yellow: #ffe600;
    --red:    #ff2244;
    --purple: #a855f7;
    --bg:     #020b14;
    --glass:  rgba(0,245,255,0.04);
    --border: rgba(0,245,255,0.18);
    --text:   #c8f0ff;
    --dim:    rgba(200,240,255,0.45);
}
.glass-card::-webkit-scrollbar {
    width: 4px;
}
html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'Rajdhani', sans-serif !important;
}
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse 80% 50% at 20% 10%,  rgba(0,245,255,0.07) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 80% 80%,  rgba(168,85,247,0.08) 0%, transparent 55%),
        radial-gradient(ellipse 50% 60% at 50% 50%,  rgba(255,0,160,0.04) 0%, transparent 70%),
        var(--bg) !important;
    background-attachment: fixed !important;
}
[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,245,255,0.012) 2px,rgba(0,245,255,0.012) 4px);
    pointer-events: none; z-index: 9999;
}

#MainMenu, footer, header { visibility: hidden !important; }
[data-testid="stDecoration"] { display: none !important; }
.block-container { padding: 1.5rem 2rem 4rem !important; max-width: 1400px !important; }

::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--cyan); border-radius: 3px; }

/* Tabs */
[data-testid="stTabs"] > div:first-child {
    border-bottom: 1px solid var(--border) !important;
}
button[data-baseweb="tab"] {
    font-family: 'Orbitron', sans-serif !important;
    font-size: 0.72rem !important; font-weight: 700 !important;
    letter-spacing: 0.12em !important; color: rgba(200,240,255,0.45) !important;
    background: transparent !important; border: none !important;
    padding: 0.75rem 2rem !important; text-transform: uppercase !important;
    transition: all 0.3s ease !important;
}
button[data-baseweb="tab"]:hover { color: var(--cyan) !important; text-shadow: 0 0 12px var(--cyan) !important; }
button[data-baseweb="tab"][aria-selected="true"] {
    color: var(--cyan) !important;
    text-shadow: 0 0 20px var(--cyan), 0 0 40px rgba(0,245,255,0.4) !important;
    border-bottom: 2px solid var(--cyan) !important;
    background: rgba(0,245,255,0.05) !important;
}

/* Cards */
.glass-card {
    background: var(--glass); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem;
    backdrop-filter: blur(20px); position: relative; overflow: hidden;
    margin-bottom: 1rem;
}
.glass-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent); opacity: 0.6;
}

/* Metric tile */
.metric-tile {
    background: rgba(0,245,255,0.04); border: 1px solid rgba(0,245,255,0.15);
    border-radius: 10px; padding: 1.2rem; text-align: center;
    transition: border-color 0.3s, box-shadow 0.3s;
}
.metric-tile:hover {
    border-color: var(--cyan);
    box-shadow: 0 0 20px rgba(0,245,255,0.18), inset 0 0 20px rgba(0,245,255,0.05);
}
.metric-value {
    font-family: 'Orbitron', sans-serif; font-size: 2rem; font-weight: 800; line-height: 1;
    margin-bottom: 0.3rem;
}
.metric-label {
    font-family: 'Orbitron', sans-serif; font-size: 0.58rem;
    letter-spacing: 0.18em; color: rgba(200,240,255,0.45); text-transform: uppercase;
}

/* Neon text helpers */
.neon-cyan   { color: var(--cyan);   text-shadow: 0 0 20px var(--cyan); }
.neon-green  { color: var(--green);  text-shadow: 0 0 20px var(--green); }
.neon-red    { color: var(--red);    text-shadow: 0 0 20px var(--red); }
.neon-yellow { color: var(--yellow); text-shadow: 0 0 20px var(--yellow); }
.neon-purple { color: var(--purple); text-shadow: 0 0 20px var(--purple); }

/* Streamlit widget overrides */
[data-testid="stTextInput"] input {
    background: rgba(0,245,255,0.05) !important;
    border: 1px solid rgba(0,245,255,0.3) !important;
    border-radius: 8px !important; color: var(--cyan) !important;
    font-family: 'Share Tech Mono', monospace !important; font-size: 0.85rem !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 2px rgba(0,245,255,0.2) !important;
}
[data-testid="stTextInput"] label {
    color: rgba(200,240,255,0.45) !important;
    font-family: 'Orbitron', sans-serif !important; font-size: 0.65rem !important;
    letter-spacing: 0.12em !important;
}

.stButton > button {
    background: transparent !important;
    border: 1px solid var(--cyan) !important;
    color: var(--cyan) !important;
    font-family: 'Orbitron', sans-serif !important;
    font-size: 0.68rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.1em !important;
    padding: 0.55rem 1.6rem !important;
    border-radius: 6px !important;
    transition: all 0.25s ease !important;
    text-transform: uppercase !important;
}

/* DEFAULT CYAN HOVER */
.stButton > button:hover {
    background: rgba(0,245,255,0.12) !important;
    box-shadow:
        0 0 10px rgba(0,245,255,0.6),
        0 0 20px rgba(0,245,255,0.5),
        0 0 40px rgba(0,245,255,0.3) !important;
    transform: translateY(-1px);
}

/* PHISHING (RED GLOW) */
.phishing-btn button:hover {
    box-shadow:
        0 0 10px rgba(255,34,68,0.7),
        0 0 20px rgba(255,34,68,0.6),
        0 0 40px rgba(255,34,68,0.4) !important;
    border-color: #ff2244 !important;
    color: #ff2244 !important;
}

/* SUSPICIOUS (YELLOW GLOW) */
.suspicious-btn button:hover {
    box-shadow:
        0 0 10px rgba(255,230,0,0.7),
        0 0 20px rgba(255,230,0,0.6),
        0 0 40px rgba(255,230,0,0.4) !important;
    border-color: #ffe600 !important;
    color: #ffe600 !important;
}

/* SAFE (GREEN GLOW) */
.safe-btn button:hover {
    box-shadow:
        0 0 10px rgba(0,255,136,0.7),
        0 0 20px rgba(0,255,136,0.6),
        0 0 40px rgba(0,255,136,0.4) !important;
    border-color: #00ff88 !important;
    color: #00ff88 !important;
}

/* Progress bar */
[data-testid="stProgressBar"] > div > div {
    background: linear-gradient(90deg, var(--cyan), var(--purple)) !important;
}

/* Footer */
.vigil-footer {
    text-align: center; padding: 1.2rem;
    border-top: 1px solid rgba(0,245,255,0.1);
    font-family: 'Share Tech Mono', monospace; font-size: 0.65rem;
    color: rgba(200,240,255,0.3); letter-spacing: 0.15em; margin-top: 2rem;
}

/* Glow Pulse Animation */
@keyframes glowPulse {
    0% {
        box-shadow: 0 0 5px rgba(0,245,255,0.4),
                    0 0 10px rgba(0,245,255,0.3);
    }
    50% {
        box-shadow: 0 0 20px rgba(0,245,255,0.8),
                    0 0 40px rgba(0,245,255,0.6);
    }
    100% {
        box-shadow: 0 0 5px rgba(0,245,255,0.4),
                    0 0 10px rgba(0,245,255,0.3);
    }
}

.stButton > button:hover {
    animation: glowPulse 1.2s infinite alternate !important;
}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<div style="text-align:center; padding: 2rem 0 1.5rem;">
    <div style="font-family:'Orbitron',sans-serif; font-weight:900; font-size:2.2rem;
                letter-spacing:0.2em; color:#00f5ff;
                text-shadow: 0 0 30px #00f5ff, 0 0 60px rgba(0,245,255,0.4);">
        ◈ VIGIL + NEUROGUARD AI ◈
    </div>
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.72rem;
                color:rgba(200,240,255,0.4); letter-spacing:0.25em; margin-top:0.5rem;">
        CYBERSECURITY INTELLIGENCE PLATFORM  //  {datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}
    </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  TABS
# ══════════════════════════════════════════════════════════════════════════════
tab_monitor, tab_vigil = st.tabs(["🖥  NEUROGUARD — System Monitor", "🌐  VIGIL — Phishing Detector"])


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 1 — NEUROGUARD: REAL SYSTEM MONITOR
# ══════════════════════════════════════════════════════════════════════════════
with tab_monitor:

    # Auto-refresh toggle
    col_r1, col_r2 = st.columns([6, 1])
    with col_r2:
        auto_refresh = st.toggle("Auto Refresh", value=False)

    # Gather real metrics
    cpu_pct  = psutil.cpu_percent(interval=0.5)
    ram      = psutil.virtual_memory()
    disk     = psutil.disk_usage("/")
    ram_pct  = ram.percent
    disk_pct = disk.percent

    def color_for(pct):
        if pct >= 85: return "#ff2244"
        if pct >= 60: return "#ffe600"
        return "#00ff88"

    # ── Metric tiles ─────────────────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    for col, label, value, unit in [
        (c1, "CPU Usage",  cpu_pct,  "%"),
        (c2, "RAM Usage",  ram_pct,  "%"),
        (c3, "Disk Usage", disk_pct, "%"),
    ]:
        clr = color_for(value)
        with col:
            st.markdown(f"""
            <div class="metric-tile">
                <div class="metric-value" style="color:{clr};text-shadow:0 0 20px {clr};">
                    {value:.1f}<span style="font-size:1rem;">{unit}</span>
                </div>
                <div class="metric-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)
            st.progress(int(value) / 100)

    st.markdown("<div style='height:0.8rem'></div>", unsafe_allow_html=True)

    # ── Secondary RAM / Disk detail ───────────────────────────────────────────
    d1, d2 = st.columns(2)
    with d1:
        st.markdown(f"""
        <div class="glass-card">
            <div style="font-family:'Orbitron',sans-serif;font-size:0.62rem;letter-spacing:.18em;
                        color:rgba(200,240,255,0.35);margin-bottom:0.8rem;">MEMORY DETAIL</div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;">
                <span style="color:rgba(200,240,255,0.45);">Used</span>
                <span style="color:#00f5ff;">{ram.used / 1e9:.2f} GB</span>
            </div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;margin-top:0.4rem;">
                <span style="color:rgba(200,240,255,0.45);">Available</span>
                <span style="color:#00ff88;">{ram.available / 1e9:.2f} GB</span>
            </div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;margin-top:0.4rem;">
                <span style="color:rgba(200,240,255,0.45);">Total</span>
                <span style="color:#a855f7;">{ram.total / 1e9:.2f} GB</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with d2:
        st.markdown(f"""
        <div class="glass-card">
            <div style="font-family:'Orbitron',sans-serif;font-size:0.62rem;letter-spacing:.18em;
                        color:rgba(200,240,255,0.35);margin-bottom:0.8rem;">DISK DETAIL</div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;">
                <span style="color:rgba(200,240,255,0.45);">Used</span>
                <span style="color:#00f5ff;">{disk.used / 1e9:.1f} GB</span>
            </div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;margin-top:0.4rem;">
                <span style="color:rgba(200,240,255,0.45);">Free</span>
                <span style="color:#00ff88;">{disk.free / 1e9:.1f} GB</span>
            </div>
            <div style="display:flex;justify-content:space-between;font-family:'Share Tech Mono',monospace;font-size:0.78rem;margin-top:0.4rem;">
                <span style="color:rgba(200,240,255,0.45);">Total</span>
                <span style="color:#a855f7;">{disk.total / 1e9:.1f} GB</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # ── Top 5 processes ───────────────────────────────────────────────────────
    st.markdown("""
    <div style="font-family:'Orbitron',sans-serif;font-size:0.65rem;letter-spacing:.18em;
                color:rgba(200,240,255,0.35);margin:1rem 0 0.6rem;">TOP 5 PROCESSES BY CPU</div>
    """, unsafe_allow_html=True)

    procs = []

    # init
    for p in psutil.process_iter(["pid", "name"]):
        try:
            p.cpu_percent(None)
        except:
            pass

    time.sleep(1)   # stable reading

    # actual values
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            if p.info["name"] != "System Idle Process":
                procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    top5 = sorted(procs, key=lambda x: min(x.get("cpu_percent") or 0, 100), reverse=True)[:5]

    header_row = """
    <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:0.5rem;
                padding:0.5rem 1rem;font-family:'Orbitron',sans-serif;font-size:0.58rem;
                letter-spacing:.12em;color:rgba(200,240,255,0.3);border-bottom:1px solid rgba(0,245,255,0.1);">
        <span>PROCESS</span><span style="text-align:right;">CPU %</span><span style="text-align:right;">MEM %</span>
    </div>"""
    st.markdown(f'<div class="glass-card" style="padding:0.8rem;">{header_row}', unsafe_allow_html=True)

    for proc in top5:
        cpu_c = color_for(proc.get("cpu_percent") or 0)
        st.markdown(f"""
        <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:0.5rem;
                    padding:0.55rem 1rem;font-family:'Share Tech Mono',monospace;font-size:0.75rem;
                    border-bottom:1px solid rgba(0,245,255,0.06);">
            <span style="color:#c8f0ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                {proc.get('name','—')}</span>
            <span style="text-align:right;color:{cpu_c};">{proc.get('cpu_percent',0):.1f}%</span>
            <span style="text-align:right;color:#a855f7;">{proc.get('memory_percent',0):.1f}%</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # ✅ TASK 2 FIX: Auto-refresh INSIDE with tab_monitor, at the END
    if auto_refresh:
        time.sleep(1)
        st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER: run phishing scan on one URL
# ══════════════════════════════════════════════════════════════════════════════
def scan_url(url: str) -> dict:
    try:
        result = check_phishing(url)

        if result.get("result") == "ERROR":
            return {
                "url": url,
                "label": "ERROR",
                "color": "#ff2244",
                "icon": "❌",
                "score": 0,
                "features": {}
            }

        probability = float(result.get("probability", result.get("confidence", 0.0)))
        risk_score = float(result.get("risk_score", probability * 100.0))
        features = result.get("features", {})
        label = result.get("label", "SAFE")

        color = "#00ff88"
        icon = "✅"
        if label == "PHISHING":
            color = "#ff2244"
            icon = "🚨"
        elif label == "SUSPICIOUS":
            color = "#ffe600"
            icon = "⚠️"

        return {
            "url": url,
            "label": label,
            "color": color,
            "icon": icon,
            "score": max(0.0, min(100.0, risk_score)),
            "features": features,
            "probability": probability,
        }

    except Exception:
        return {
            "url": url,
            "label": "ERROR",
            "color": "#ff2244",
            "icon": "❌",
            "score": 0,
            "features": {}
        }


# ✅ TASK 1 FIX: uses components.html() to bypass Streamlit's HTML sanitizer
def render_result_card(r: dict):
    key_features = {
        k: r["features"][k]
        for k in ["URLLength", "IsHTTPS", "IsDomainIP", "NoOfSubDomain",
                  "HasObfuscation", "NoOfQMarkInURL", "NoOfAmpersandInURL"]
        if k in r["features"]
    }

    feat_html = ""
    for k, v in key_features.items():
        feat_html += f"""
        <div style="display:flex;justify-content:space-between;padding:0.3rem 0;
                    border-bottom:1px solid rgba(0,245,255,0.06);">
            <span style="color:rgba(200,240,255,0.45);font-size:0.72rem;
                         font-family:'Rajdhani',sans-serif;">{k}</span>
            <span style="color:#00f5ff;font-family:'Share Tech Mono',monospace;
                         font-size:0.72rem;">{v}</span>
        </div>
        """

    card_height = 200 + len(key_features) * 36

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=Share+Tech+Mono&family=Rajdhani:wght@500;600&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: transparent;
            font-family: 'Rajdhani', sans-serif;
        }}
        .card {{
            background: rgba(0,245,255,0.04);
            border: 1px solid {r['color']}44;
            border-radius: 12px;
            padding: 1.2rem 1.4rem;
            position: relative;
            overflow: hidden;
            max-width: 480px;
            margin: 0 auto;
        }}
        .card::before {{
            content: '';
            position: absolute; top: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, transparent, {r['color']}, transparent);
            opacity: 0.5;
        }}
        .header {{ display:flex; align-items:center; gap:0.9rem; margin-bottom:1rem; }}
        .icon {{ font-size:2rem; line-height:1; }}
        .label {{
            font-family:'Orbitron',sans-serif; font-size:1.05rem; font-weight:900;
            color:{r['color']}; text-shadow:0 0 16px {r['color']}88;
        }}
        .url {{
            font-size:0.68rem; color:rgba(200,240,255,0.45);
            word-break:break-all; margin-top:0.2rem;
            font-family:'Share Tech Mono',monospace;
        }}
        .score-label {{
            display:flex; justify-content:space-between; align-items:center;
            margin-bottom:0.35rem;
        }}
        .score-title {{
            font-family:'Orbitron',sans-serif; font-size:0.55rem;
            letter-spacing:0.18em; color:rgba(200,240,255,0.3);
        }}
        .score-value {{
            font-family:'Orbitron',sans-serif; font-size:0.8rem; font-weight:800;
            color:{r['color']};
        }}
        .bar-track {{
            height:7px; background:rgba(0,245,255,0.08);
            border-radius:99px; overflow:hidden; margin-bottom:0.2rem;
        }}
        .bar-fill {{
            height:100%; width:{r['score']:.1f}%;
            background:{r['color']};
            border-radius:99px;
            box-shadow:0 0 8px {r['color']}88;
        }}
        .section-title {{
            font-family:'Orbitron',sans-serif; font-size:0.55rem;
            letter-spacing:0.18em; color:rgba(200,240,255,0.28);
            margin:0.8rem 0 0.4rem;
        }}
        .divider {{ height:1px; background:rgba(0,245,255,0.08); margin:0.6rem 0; }}
    </style>
    </head>
    <body>
    <div class="card">
        <div class="header">
            <span class="icon">{r['icon']}</span>
            <div>
                <div class="label">{r['label']}</div>
                <div class="url">{r['url'].replace("<","&lt;").replace(">","&gt;")}</div>
            </div>
        </div>
        <div class="divider"></div>
        <div class="score-label">
            <span class="score-title">RISK SCORE</span>
            <span class="score-value">{r['score']:.1f}%</span>
        </div>
        <div class="bar-track"><div class="bar-fill"></div></div>
        <div class="section-title">KEY FEATURES</div>
        {feat_html}
    </div>
    </body>
    </html>
    """

    components.html(html, height=card_height, scrolling=False)


# ══════════════════════════════════════════════════════════════════════════════
#  TAB 2 — VIGIL: PHISHING DETECTOR
# ══════════════════════════════════════════════════════════════════════════════
with tab_vigil:

    st.markdown("""
    <div class="glass-card" style="max-width:600px;margin:auto;">
        <div style="font-family:'Orbitron',sans-serif;font-size:0.65rem;letter-spacing:.2em;
                    color:rgba(200,240,255,0.35);margin-bottom:0.3rem;">SINGLE URL ANALYSIS</div>
        <div style="font-family:'Rajdhani',sans-serif;font-size:1rem;color:rgba(200,240,255,0.6);">
            Enter any URL to run real-time phishing detection via the trained ML model.
        </div>
    </div>
    """, unsafe_allow_html=True)

    
    # 🔥 AUTO INPUT FROM EXTENSION (fallback = manual input)
    # 🔥 FETCH URL FROM EXTENSION BACKEND
    import requests
    try:
        res = requests.get("https://vigil-hbc5.onrender.com", timeout=2)
        if res.status_code == 200:
            data = res.json()
            if data.get("url"):
                st.session_state["ext_url"] = data["url"]
                st.session_state["auto_scan"] = True
    except:
        pass
    url_input = st.text_input(
        "TARGET URL",
        value=st.session_state.get("ext_url", ""),
        placeholder="https://example.com/page?param=value",
        key="url_input"
)

# 🔥 AUTO TRIGGER SCAN WHEN EXTENSION UPDATES
if url_input and url_input != st.session_state.get("last_url"):
    st.session_state["last_url"] = url_input
    st.session_state["auto_scan"] = True

    # ✅ TASK 3: Auto-scan trigger on URL change
    if url_input and url_input != st.session_state.get("last_url"):
        st.session_state["last_url"] = url_input
        st.session_state["auto_scan"] = True

    st.markdown(
        "<small style='color:rgba(200,240,255,0.35);'>⬡ Press Scan to analyze URL</small>",
        unsafe_allow_html=True
    )

    col_scan, col_clear, _ = st.columns([1, 1, 5])

    with col_scan:
        st.markdown('<div class="safe-btn">', unsafe_allow_html=True)
        scan_btn = st.button("⬡  SCAN URL", key="scan_btn")
        st.markdown('</div>', unsafe_allow_html=True)

    with col_clear:
        st.markdown('<div class="phishing-btn">', unsafe_allow_html=True)
        clear_btn = st.button("✕  CLEAR", key="clear_btn")
        st.markdown('</div>', unsafe_allow_html=True)

    # ✅ CLEAR BUTTON
    if clear_btn:
        st.session_state.pop("single_result", None)
        st.rerun()

    # ✅ TASK 3: SCAN BUTTON + AUTO SCAN combined trigger
    if scan_btn or st.session_state.get("auto_scan"):
        st.session_state["auto_scan"] = False

        url = url_input.strip()
        if not url:
            st.warning("Please enter a URL before scanning.")
        else:
            with st.spinner("Analysing URL…"):
                steps = [
                    (0.25, "Parsing URL structure…"),
                    (0.55, "Extracting lexical features…"),
                    (0.85, "Running ML model…"),
                    (1.00, "Done."),
                ]
                prog = st.progress(0)
                for pct, msg in steps:
                    prog.progress(pct, text=f"⬡  {msg}")
                    time.sleep(0.1)
                prog.empty()
                result = scan_url(url)

            st.session_state["single_result"] = result
            if result["label"] != "ERROR":
                st.session_state.setdefault("history", []).insert(0, result)
                st.session_state["history"] = st.session_state["history"][:10]

    # ✅ RESULT + HISTORY
    if "single_result" in st.session_state:
        render_result_card(st.session_state["single_result"])

        if st.session_state["history"]:
            st.markdown(f"### 🕘 Scan History  •  Total Scans: {len(st.session_state['history'])}")

            if st.button("🧹 Clear History", disabled=not st.session_state["history"]):
                st.session_state["history"] = []
                st.rerun()

            for r in st.session_state["history"][:5]:
                st.markdown(f"""
                <div style="border:1px solid {r['color']}44;padding:0.5rem 0.8rem;
                            border-radius:8px;margin-bottom:0.4rem;
                            display:flex;justify-content:space-between;">
                    <span style="font-size:0.75rem;">{r['icon']} {r['url'][:60].replace("<", "&lt;").replace(">", "&gt;")}</span>
                    <span style="color:{r['color']};font-weight:600;">{r['label']}</span>
                </div>
                """, unsafe_allow_html=True)
