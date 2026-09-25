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

# --- LOAD CSS ---
def load_css():
    css_path = os.path.join(os.path.dirname(__file__), "assets", "styles.css")
    try:
        with open(css_path, "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning("CSS file not found. Styles may not apply correctly.")

load_css()

# --- HEADER ---
st.markdown("""
<div class="status-indicator">
    <div class="status-dot"></div>
    ANALYZER ONLINE
</div>
<div class="title-text cyber-glow">🛡️ Cyber Threat Severity Analyzer</div>
<div class="subtitle-text">Interactive Python Multi-Condition Cybersecurity Decision Engine</div>
<div>
    <span class="badge">PYTHON 3.11+</span>
    <span class="badge">STREAMLIT</span>
    <span class="badge">CLAYMORPHISM UI</span>
    <span class="badge">IF / ELIF / ELSE</span>
</div>
<br>
""", unsafe_allow_html=True)

# State initialization
if 'analyzed' not in st.session_state:
    st.session_state.analyzed = False
if 'risk_score' not in st.session_state:
    st.session_state.risk_score = 0
if 'form_data' not in st.session_state:
    st.session_state.form_data = {
        "severity": "High",
        "exploitability": "Easy",
        "exposure": "Internet-facing",
        "confidence": "High",
        "frequency": "Repeated"
    }

# --- LAYOUT ---
col1, col2 = st.columns([1, 1.2], gap="large")

with col1:
    st.markdown('<div class="clay-card">', unsafe_allow_html=True)
    st.subheader("Security Event Parameters")
    
    with st.form("event_form"):
        severity = st.selectbox(
            "Vulnerability Severity",
            ["Critical", "High", "Medium", "Low", "Informational"],
            index=1,
            help="Inherent severity of the vulnerability."
        )
        exploitability = st.selectbox(
            "Exploitability",
            ["Easy", "Moderate", "Difficult"],
            index=0,
            help="How easy is it to exploit?"
        )
        exposure = st.selectbox(
            "Asset Exposure",
            ["Internet-facing", "Internal", "Isolated"],
            index=0,
            help="Where is the vulnerable asset located?"
        )
        confidence = st.selectbox(
            "Detection Confidence",
            ["High", "Medium", "Low"],
            index=0,
            help="How confident are we in the detection mechanism?"
        )
        frequency = st.selectbox(
            "Event Frequency",
            ["Repeated", "Occasional", "Single Event"],
            index=0,
            help="How often does this event occur?"
        )
        
        analyze_btn = st.form_submit_button("⚡ ANALYZE THREAT", use_container_width=True)
        
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Boundary Testing Section
    st.markdown('<div class="clay-card">', unsafe_allow_html=True)
    st.subheader("Boundary Testing")
    st.write("Click a specific score to demonstrate how changing the risk score evaluates `if / elif / else` conditions:")
    
    b_col1, b_col2, b_col3, b_col4 = st.columns(4)
    boundary_scores = [19, 20, 39, 40, 69, 70, 89, 90]
    
    for i, b_score in enumerate(boundary_scores):
        col_idx = i % 4
        current_col = [b_col1, b_col2, b_col3, b_col4][col_idx]
        with current_col:
            if st.button(f"{b_score}", key=f"btn_{b_score}", use_container_width=True):
                st.session_state.risk_score = b_score
                st.session_state.analyzed = True
                st.session_state.form_data["custom"] = True
    
    st.markdown('</div>', unsafe_allow_html=True)

# Trigger analysis on form submit or initial view
if analyze_btn or not st.session_state.analyzed:
    if analyze_btn:
        st.session_state.form_data = {
            "severity": severity,
            "exploitability": exploitability,
            "exposure": exposure,
            "confidence": confidence,
            "frequency": frequency,
            "custom": False
        }
        st.session_state.risk_score = calculate_risk_score(
            severity, exploitability, exposure, confidence, frequency
        )
    elif not st.session_state.analyzed:
        # Default initialization
        st.session_state.analyzed = True
        st.session_state.risk_score = calculate_risk_score(
            "High", "Easy", "Internet-facing", "High", "Repeated"
        )

with col2:
    if st.session_state.analyzed:
        result = classify_risk(st.session_state.risk_score)
        
        # 1. THREAT ASSESSMENT CARD & RISK SCORE GAUGE
        st.markdown('<div class="clay-card">', unsafe_allow_html=True)
        st.subheader("THREAT ASSESSMENT")
        
        color_map = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFORMATIONAL": "#6b7280"
        }
        sev_color = color_map.get(result["severity"], "#38bdf8")
        
        st.markdown(f"""
        <div style="text-align: center; margin: 15px 0;">
            <div style="font-size: 1.1rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">Threat Classification</div>
            <div style="font-size: 3.2rem; font-weight: 800; color: {sev_color}; text-shadow: 0 0 16px {sev_color}44;">{result['severity']}</div>
        </div>
        """, unsafe_allow_html=True)
        
        rec_map = {
            "CRITICAL": "Immediate Incident Response",
            "HIGH": "Immediate Review",
            "MEDIUM": "Normal Investigation",
            "LOW": "Monitor",
            "INFORMATIONAL": "Log and Ignore"
        }
        
        # Risk Score Gauge Visual
        st.markdown(f"### Cyber Risk Score: **{result['score']} / 100**")
        st.progress(result['score'] / 100.0)
        
        col_meta1, col_meta2 = st.columns(2)
        with col_meta1:
            st.write(f"**Recommended Priority:** {rec_map.get(result['severity'])}")
        with col_meta2:
            st.write(f"**Matched Condition:** `{result['matched_condition']}`")
            
        # Stepper Visualization for Level
        levels = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        stepper_html = '<div class="level-stepper">'
        for lvl in levels:
            is_active = (lvl == result["severity"])
            active_class = "active" if is_active else ""
            pointer = f'<span class="level-pointer" style="color: {sev_color};">▲ SCORE {result["score"]}</span>' if is_active else ''
            stepper_html += f'<div class="level-step {active_class}">{lvl}{pointer}</div>'
        stepper_html += '</div>'
        st.markdown(stepper_html, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # 2. CONDITION TRACE
        st.markdown('<div class="clay-card">', unsafe_allow_html=True)
        st.subheader("CONDITION ANALYSIS")
        
        for cond in result["conditions"]:
            st.markdown(f"""
            <div class="trace-item {cond['class']}">
                {cond['symbol']} {cond['status']} : <code>{cond['text']}</code>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown(f"""
        <div style="margin-top: 14px; padding: 12px 16px; border-left: 4px solid #38bdf8; background: rgba(56,189,248,0.06); border-radius: 8px;">
            <strong>Why was this severity selected?</strong><br>
            {result['explanation'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # 3. RISK FACTOR ANALYSIS (BAR CHART GRAPH & BREAKDOWN)
        st.markdown('<div class="clay-card">', unsafe_allow_html=True)
        st.subheader("RISK FACTOR ANALYSIS")
        
        if not st.session_state.form_data.get("custom"):
            fd = st.session_state.form_data
            factors = calculate_risk_factors(
                fd['severity'], fd['exploitability'], fd['exposure'], fd['confidence'], fd['frequency']
            )
            
            # Interactive Bar Chart using Streamlit Native Charts
            df_chart = pd.DataFrame(
                list(factors.items()),
                columns=["Risk Factor", "Score Contribution"]
            ).set_index("Risk Factor")
            
            st.bar_chart(df_chart, color="#38bdf8", height=220)
            
            # Breakdown Table
            st.markdown('<div class="breakdown-divider"></div>', unsafe_allow_html=True)
            for factor, val in factors.items():
                st.markdown(f'<div class="breakdown-row"><span>{factor}</span> <span>+{val}</span></div>', unsafe_allow_html=True)
            st.markdown(f'<div class="total-row"><span>Total Risk Score</span> <span>{result["score"]} / 100</span></div>', unsafe_allow_html=True)
        else:
            st.info("Boundary test active. Select parameters in the event form to view individual factor scores.")
            st.markdown(f'<div class="total-row"><span>Boundary Test Score</span> <span>{result["score"]} / 100</span></div>', unsafe_allow_html=True)
            
        st.markdown('</div>', unsafe_allow_html=True)

# --- LEARNING & PYTHON LOGIC SECTION ---
st.markdown("---")
col3, col4 = st.columns(2, gap="large")

with col3:
    st.markdown('<div class="clay-card">', unsafe_allow_html=True)
    st.subheader("PYTHON LOGIC")
    
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
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="clay-card">', unsafe_allow_html=True)
    st.subheader("UNDERSTANDING PYTHON DECISION FLOW")
    st.markdown("""
    * **`if`**: Evaluated first. If `True`, its body executes and evaluation stops immediately.
    * **`elif`**: Evaluated sequentially **only** if all prior conditions were `False`.
    * **`else`**: Executes as the default fallback when every previous condition evaluates to `False`.
    
    **Cybersecurity Action Mapping:**
    - **CRITICAL** (≥ 90): Immediate Incident Response
    - **HIGH** (≥ 70): Immediate Review
    - **MEDIUM** (≥ 40): Normal Investigation
    - **LOW** (≥ 20): Monitor
    - **INFORMATIONAL** (< 20): Log and Ignore
    """)
    st.markdown('</div>', unsafe_allow_html=True)
