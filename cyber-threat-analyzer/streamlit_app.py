import streamlit as st
import pandas as pd
import os
from src.risk_engine import calculate_risk_score, calculate_risk_factors, classify_risk

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Cyber Threat Severity Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- LOAD LIQUID GLASS CSS ---
def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "assets", "styles.css")
    try:
        with open(css_path, "r", encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning("CSS file not found. Styles may not apply correctly.")

load_css()

# --- PRESET BOUNDARIES WITH REAL ATTRIBUTES ---
PRESETS = {
    "90 (Critical Min)": {
        "severity": "Critical",
        "exploitability": "Easy",
        "exposure": "Internet-facing",
        "confidence": "High",
        "frequency": "Single Event"
    },
    "89 (High Max)": {
        "severity": "High",
        "exploitability": "Easy",
        "exposure": "Internet-facing",
        "confidence": "High",
        "frequency": "Occasional"
    },
    "70 (High Min)": {
        "severity": "Critical",
        "exploitability": "Easy",
        "exposure": "Internet-facing",
        "confidence": "Low",
        "frequency": "Single Event"
    },
    "69 (Medium Max)": {
        "severity": "High",
        "exploitability": "Easy",
        "exposure": "Internet-facing",
        "confidence": "Low",
        "frequency": "Occasional"
    },
    "40 (Medium Min)": {
        "severity": "Critical",
        "exploitability": "Moderate",
        "exposure": "Isolated",
        "confidence": "Low",
        "frequency": "Single Event"
    },
    "39 (Low Max)": {
        "severity": "High",
        "exploitability": "Moderate",
        "exposure": "Isolated",
        "confidence": "Low",
        "frequency": "Occasional"
    },
    "20 (Low Min)": {
        "severity": "Informational",
        "exploitability": "Easy",
        "exposure": "Isolated",
        "confidence": "Low",
        "frequency": "Single Event"
    },
    "18 (Info Max)": {
        "severity": "Low",
        "exploitability": "Moderate",
        "exposure": "Isolated",
        "confidence": "Low",
        "frequency": "Single Event"
    },
    "0 (Absolute Min)": {
        "severity": "Informational",
        "exploitability": "Difficult",
        "exposure": "Isolated",
        "confidence": "Low",
        "frequency": "Single Event"
    }
}

SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"]
EXPLOITABILITY_OPTIONS = ["Easy", "Moderate", "Difficult"]
EXPOSURE_OPTIONS = ["Internet-facing", "Internal", "Isolated"]
CONFIDENCE_OPTIONS = ["High", "Medium", "Low"]
FREQUENCY_OPTIONS = ["Repeated", "Occasional", "Single Event"]

if "param_severity" not in st.session_state:
    st.session_state.param_severity = "High"
if "param_exploitability" not in st.session_state:
    st.session_state.param_exploitability = "Easy"
if "param_exposure" not in st.session_state:
    st.session_state.param_exposure = "Internet-facing"
if "param_confidence" not in st.session_state:
    st.session_state.param_confidence = "High"
if "param_frequency" not in st.session_state:
    st.session_state.param_frequency = "Occasional"

def apply_preset(preset_key: str):
    preset = PRESETS[preset_key]
    st.session_state.param_severity = preset["severity"]
    st.session_state.param_exploitability = preset["exploitability"]
    st.session_state.param_exposure = preset["exposure"]
    st.session_state.param_confidence = preset["confidence"]
    st.session_state.param_frequency = preset["frequency"]

# --- LIQUID HEADER ---
st.markdown("""
<div class="status-indicator">
    <div class="status-dot"></div>
    SECURITY ENGINE ONLINE &bull; REAL-TIME TELEMETRY
</div>
<div class="title-text">🛡️ Cyber Threat Severity Analyzer</div>
<div class="subtitle-text">Interactive Multi-Condition Cybersecurity Decision Engine with Liquid Glass UI</div>
<div>
    <span class="badge">PYTHON 3.11+</span>
    <span class="badge">LIQUID GLASS UI</span>
    <span class="badge">DYNAMIC RISK ENGINE</span>
    <span class="badge">IF / ELIF / ELSE</span>
</div>
<br>
""", unsafe_allow_html=True)

# --- 2-COLUMN RESPONSIVE LAYOUT ---
col_input, col_output = st.columns([1, 1.25], gap="large")

# ==========================================
# 1. USER INPUT SECTION (COL 1)
# ==========================================
with col_input:
    with st.container(border=True):
        st.markdown("### ⚙️ Security Event Parameters")
        st.markdown("<p style='color: var(--text-secondary); font-size: 0.9rem;'>Adjust parameters below. All risk scores, condition traces, graphs, and gauges update dynamically.</p>", unsafe_allow_html=True)
        
        curr_severity = st.selectbox(
            "Vulnerability Severity",
            SEVERITY_OPTIONS,
            key="param_severity",
            help="Inherent severity of the discovered vulnerability (CVSS baseline)."
        )
        curr_exploitability = st.selectbox(
            "Exploitability",
            EXPLOITABILITY_OPTIONS,
            key="param_exploitability",
            help="Difficulty level required for an attacker to execute an exploit."
        )
        curr_exposure = st.selectbox(
            "Asset Exposure",
            EXPOSURE_OPTIONS,
            key="param_exposure",
            help="Network exposure and accessibility of the target system."
        )
        curr_confidence = st.selectbox(
            "Detection Confidence",
            CONFIDENCE_OPTIONS,
            key="param_confidence",
            help="Fidelity and reliability of the alerting security telemetry."
        )
        curr_frequency = st.selectbox(
            "Event Frequency",
            FREQUENCY_OPTIONS,
            key="param_frequency",
            help="Recurrence cadence of the detected anomaly or attack."
        )

    with st.container(border=True):
        st.markdown("### 🎯 Boundary Testing")
        st.markdown(
            "<p style='color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 14px;'>"
            "Click any boundary score to simulate how changing the score triggers each <code>if / elif / else</code> branch:"
            "</p>",
            unsafe_allow_html=True
        )
        
        b_rows = [
            ["90 (Critical Min)", "89 (High Max)"],
            ["70 (High Min)", "69 (Medium Max)"],
            ["40 (Medium Min)", "39 (Low Max)"],
            ["20 (Low Min)", "18 (Info Max)"],
            ["0 (Absolute Min)"]
        ]
        
        for row in b_rows:
            cols = st.columns(len(row))
            for idx, key_name in enumerate(row):
                with cols[idx]:
                    st.button(
                        key_name,
                        key=f"btn_{key_name}",
                        on_click=apply_preset,
                        args=(key_name,),
                        use_container_width=True
                    )

# ==========================================
# 2. CALCULATION & ENGINE EVALUATION
# ==========================================
risk_breakdown = calculate_risk_factors(
    st.session_state.param_severity,
    st.session_state.param_exploitability,
    st.session_state.param_exposure,
    st.session_state.param_confidence,
    st.session_state.param_frequency
)

risk_score = min(100, max(0, sum(risk_breakdown.values())))
result = classify_risk(risk_score)
severity_level = result["severity"]
matched_condition = result["matched_condition"]

SEV_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#38bdf8",
    "INFORMATIONAL": "#94a3b8"
}
active_color = SEV_COLORS.get(severity_level, "#38bdf8")

RECOMMENDATIONS = {
    "CRITICAL": "Immediate Incident Response - Dispatch SOC Tier 3 & Isolate Host",
    "HIGH": "High Priority Review - Escalate to Security Analyst within 15 min",
    "MEDIUM": "Standard Investigation - Correlate SIEM telemetry within 4 hours",
    "LOW": "Routine Monitoring - Suppress active alerts; log for auditing",
    "INFORMATIONAL": "Informational Logging - Record baseline; no operator action required"
}

# ==========================================
# 3. OUTPUT FLOW (COL 2)
# ==========================================
with col_output:
    # ----------------------------------------------------
    # FLOW STEP: Threat Severity Card & Risk Score Gauge
    # ----------------------------------------------------
    with st.container(border=True):
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 0.85rem; font-family: 'JetBrains Mono', monospace; color: var(--text-muted); letter-spacing: 0.08em; text-transform: uppercase;">Real-Time Assessment</span>
            <span class="badge" style="margin: 0; color: {active_color}; border-color: {active_color}55;">ACTIVE THREAT LEVEL</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="text-align: center; padding: 6px 0 14px 0;">
            <div style="font-size: 0.95rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.12em; font-family: 'JetBrains Mono', monospace;">Threat Classification</div>
            <div style="font-size: 3.4rem; font-weight: 800; color: {active_color}; text-shadow: 0 0 24px {active_color}55; letter-spacing: -0.02em; line-height: 1.15; margin: 4px 0 10px 0;">
                {severity_level}
            </div>
            <div style="display: inline-block; padding: 6px 16px; border-radius: 9999px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.08); font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; color: #e2e8f0;">
                Matched Rule: <code style="color: {active_color}; font-weight: 700;">{matched_condition}</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"""
        <div style="padding: 12px 16px; border-radius: 12px; background: rgba(0, 0, 0, 0.25); border: 1px solid rgba(255, 255, 255, 0.06); font-size: 0.9rem; margin-bottom: 16px;">
            <span style="color: #94a3b8; font-weight: 600;">Recommended Action:</span><br>
            <span style="color: #f8fafc; font-weight: 500;">{RECOMMENDATIONS.get(severity_level)}</span>
        </div>
        """, unsafe_allow_html=True)

        # Risk Score Gauge Visual
        st.markdown(f"""
        <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
            <span style="font-weight: 700; font-size: 1.05rem; letter-spacing: -0.01em;">Cyber Risk Score Gauge</span>
            <span style="font-family: 'JetBrains Mono', monospace; font-size: 1.3rem; font-weight: 800; color: {active_color};">
                {risk_score} <span style="font-size: 0.9rem; color: #64748b; font-weight: 500;">/ 100</span>
            </span>
        </div>
        """, unsafe_allow_html=True)
        
        st.progress(risk_score / 100.0)

        # Dynamic horizontal ruler indicator: 0 ──────────────── 100
        safe_score_pct = max(0, min(100, risk_score))
        st.markdown(f"""
        <div class="gauge-axis-track">
            <div class="gauge-marker-pin" style="left: {safe_score_pct}%; color: {active_color};">
                ▲ {risk_score}
            </div>
        </div>
        <div class="gauge-ruler">
            <span>0 (SAFE)</span>
            <span>20 (LOW)</span>
            <span>40 (MED)</span>
            <span>70 (HIGH)</span>
            <span>100 (CRIT)</span>
        </div>
        """, unsafe_allow_html=True)

        # Second Visualization: Final Risk Level Stepper with Dynamic Indicator
        stepper_levels = [
            ("INFORMATIONAL", "0-19", "active-informational"),
            ("LOW", "20-39", "active-low"),
            ("MEDIUM", "40-69", "active-medium"),
            ("HIGH", "70-89", "active-high"),
            ("CRITICAL", "90-100", "active-critical")
        ]
        
        level_indices = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        active_idx = level_indices.get(severity_level, 0)
        pointer_pos_pct = 10 + (active_idx * 20)

        stepper_html = '<div class="risk-stepper-container">'
        stepper_html += '<div style="font-family: \'JetBrains Mono\', monospace; font-size: 0.75rem; color: #64748b; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">Risk Level Track</div>'
        stepper_html += '<div class="risk-stepper-track">'
        for lvl_name, lvl_range, active_cls in stepper_levels:
            is_cur = (lvl_name == severity_level)
            cls = f"stepper-node {active_cls}" if is_cur else "stepper-node"
            stepper_html += f'<div class="{cls}">{lvl_name}<br><span style="font-size: 0.65rem; opacity: 0.7;">{lvl_range}</span></div>'
        stepper_html += '</div>'
        
        stepper_html += f"""
        <div class="stepper-pointer-row">
            <div class="stepper-pointer" style="left: {pointer_pos_pct}%; color: {active_color};">
                <span class="stepper-arrow">▲</span>
                <span>SCORE {risk_score} &bull; {severity_level}</span>
            </div>
        </div>
        """
        stepper_html += '</div>'
        st.markdown(stepper_html, unsafe_allow_html=True)

    # ----------------------------------------------------
    # FLOW STEP: Condition Trace
    # ----------------------------------------------------
    with st.container(border=True):
        st.markdown("### 🔍 Condition Trace")
        st.markdown("<p style='color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 12px;'>Step-by-step sequential evaluation of the Python multi-condition tree:</p>", unsafe_allow_html=True)
        
        for cond in result["conditions"]:
            st.markdown(f"""
            <div class="trace-item {cond['class']}">
                <span style="font-weight: 700; width: 140px; display: inline-block;">{cond['symbol']} {cond['status']}</span>
                <span><code>{cond['text']}</code></span>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown(f"""
        <div class="explanation-callout">
            <div style="font-weight: 700; margin-bottom: 6px; color: var(--cyber-cyan);">💡 Why was this severity selected?</div>
            {result['explanation'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    # ----------------------------------------------------
    # FLOW STEP: Risk Factor Analysis (Interactive Graph & Card)
    # ----------------------------------------------------
    with st.container(border=True):
        st.markdown("""
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 style="margin: 0; font-size: 1.25rem;">📊 Risk Factor Analysis</h3>
            <span class="badge" style="margin: 0;">DYNAMIC TELEMETRY</span>
        </div>
        <p style='color: var(--text-secondary); font-size: 0.88rem; margin-bottom: 16px;'>
            Interactive breakdown of each parameter's contribution to the total calculated risk score:
        </p>
        """, unsafe_allow_html=True)

        df_chart = pd.DataFrame({
            "Contribution": list(risk_breakdown.values()),
            "Factor": list(risk_breakdown.keys())
        })

        st.bar_chart(
            data=df_chart,
            x="Contribution",
            y="Factor",
            horizontal=True,
            color="#06b6d4",
            height=240
        )

        max_weights = {
            "Vulnerability Severity": 30,
            "Exploitability": 20,
            "Asset Exposure": 20,
            "Detection Confidence": 20,
            "Event Frequency": 10
        }

        for factor_name, factor_score in risk_breakdown.items():
            max_w = max_weights.get(factor_name, 30)
            pct_of_total = f"{(factor_score / risk_score * 100):.0f}% of total" if risk_score > 0 else "0%"
            st.markdown(f"""
            <div class="breakdown-row">
                <span>
                    <strong style="color: #f1f5f9;">{factor_name}</strong>
                    <span style="font-size: 0.78rem; color: #64748b; margin-left: 8px;">(max {max_w})</span>
                </span>
                <span>
                    <span style="font-size: 0.8rem; color: #94a3b8; margin-right: 10px;">{pct_of_total}</span>
                    <span class="breakdown-val">+{factor_score}</span>
                </span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown(f"""
        <div class="card-footer-total">
            <span>Total Risk Score</span>
            <span>{risk_score} / 100</span>
        </div>
        """, unsafe_allow_html=True)

# ==========================================
# 4. PYTHON LOGIC & EXPLANATION (FOOTER)
# ==========================================
st.markdown("<hr style='border: none; border-top: 1px solid rgba(255, 255, 255, 0.08); margin: 30px 0 24px 0;'>", unsafe_allow_html=True)
col_code, col_learn = st.columns(2, gap="large")

with col_code:
    with st.container(border=True):
        st.markdown("### 🐍 Python Multi-Condition Logic")
        st.markdown("<p style='color: var(--text-secondary); font-size: 0.88rem;'>Production rule evaluation implementation in Python:</p>", unsafe_allow_html=True)
        
        code = '''if risk_score >= 90:
    severity = "CRITICAL"
elif risk_score >= 70:
    severity = "HIGH"
elif risk_score >= 40:
    severity = "MEDIUM"
elif risk_score >= 20:
    severity = "LOW"
else:
    severity = "INFORMATIONAL"'''
        st.code(code, language="python")

with col_learn:
    with st.container(border=True):
        st.markdown("### 🧠 How Python Evaluates Branches")
        st.markdown("""
        * **`if`**: The initial condition branch. If it evaluates to `True`, Python executes its block and immediately skips all subsequent branches.
        * **`elif`** (Else If): Evaluated sequentially **only** if all prior branches evaluated to `False`. Multiple `elif` clauses can be chained for granular tiering.
        * **`else`**: The catch-all default fallback. It executes if and only if **all** prior `if` and `elif` checks evaluated to `False`.
        
        **Cybersecurity Operational Mapping:**
        * **CRITICAL** (Score ≥ 90) &rarr; Active containment, emergency paging, host isolation.
        * **HIGH** (Score ≥ 70) &rarr; SOC priority queue, triage within 15 minutes.
        * **MEDIUM** (Score ≥ 40) &rarr; Correlation with endpoint logs within 4 hours.
        * **LOW** (Score ≥ 20) &rarr; Automated heuristic monitoring; ticket logged.
        * **INFORMATIONAL** (Score &lt; 20) &rarr; Event recorded for compliance and threat hunting baselines.
        """)
