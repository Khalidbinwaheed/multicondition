import streamlit as st
from src.risk_engine import calculate_risk_score, classify_risk
import os

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
    <span class="badge">PYTHON</span>
    <span class="badge">STREAMLIT</span>
    <span class="badge">CYBERSECURITY</span>
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
    st.session_state.form_data = {}

# --- LAYOUT ---
# Mobile auto-stacks, Desktop uses columns
col1, col2 = st.columns([1, 1.2], gap="large")

with col1:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Security Event Parameters")
    
    with st.form("event_form"):
        severity = st.selectbox(
            "Vulnerability Severity",
            ["Critical", "High", "Medium", "Low", "Informational"],
            help="Inherent severity of the vulnerability."
        )
        exploitability = st.selectbox(
            "Exploitability",
            ["Easy", "Moderate", "Difficult"],
            help="How easy is it to exploit?"
        )
        exposure = st.selectbox(
            "Asset Exposure",
            ["Internet-facing", "Internal", "Isolated"],
            help="Where is the vulnerable asset located?"
        )
        confidence = st.selectbox(
            "Detection Confidence",
            ["High", "Medium", "Low"],
            help="How confident are we in the detection mechanism?"
        )
        frequency = st.selectbox(
            "Event Frequency",
            ["Repeated", "Occasional", "Single Event"],
            help="How often does this event occur?"
        )
        
        analyze_btn = st.form_submit_button("⚡ ANALYZE THREAT", use_container_width=True)
        
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Boundary Testing Section
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Boundary Testing")
    st.write("Click a specific score to demonstrate how changing the risk score changes the if/elif/else result.")
    
    b_col1, b_col2, b_col3, b_col4 = st.columns(4)
    boundary_scores = [19, 20, 39, 40, 69, 70, 89, 90]
    
    for i, b_score in enumerate(boundary_scores):
        col_idx = i % 4
        current_col = [b_col1, b_col2, b_col3, b_col4][col_idx]
        with current_col:
            if st.button(f"{b_score}", key=f"btn_{b_score}", use_container_width=True):
                st.session_state.risk_score = b_score
                st.session_state.analyzed = True
                st.session_state.form_data = {"custom": True} # Flag for custom boundary test
    
    st.markdown('</div>', unsafe_allow_html=True)

if analyze_btn:
    st.session_state.analyzed = True
    st.session_state.form_data = {
        "severity": severity,
        "exploitability": exploitability,
        "exposure": exposure,
        "confidence": confidence,
        "frequency": frequency
    }
    st.session_state.risk_score = calculate_risk_score(
        severity, exploitability, exposure, confidence, frequency
    )

with col2:
    if st.session_state.analyzed:
        result = classify_risk(st.session_state.risk_score)
        
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("Threat Assessment")
        
        # Color mapping for severity
        color_map = {
            "CRITICAL": "#ef4444", # Red
            "HIGH": "#f97316",     # Orange
            "MEDIUM": "#eab308",   # Yellow
            "LOW": "#3b82f6",      # Blue
            "INFORMATIONAL": "#6b7280" # Gray
        }
        sev_color = color_map.get(result["severity"], "#ffffff")
        
        st.markdown(f"""
        <div style="text-align: center; margin: 20px 0;">
            <div style="font-size: 1.2rem; color: #94a3b8; text-transform: uppercase;">Severity Level</div>
            <div style="font-size: 3.5rem; font-weight: 800; color: {sev_color}; letter-spacing: 2px;">{result['severity']}</div>
        </div>
        """, unsafe_allow_html=True)
        
        # Recommendations mapping
        rec_map = {
            "CRITICAL": "Immediate Incident Response",
            "HIGH": "Immediate Review",
            "MEDIUM": "Normal Investigation",
            "LOW": "Monitor",
            "INFORMATIONAL": "Log and Ignore"
        }
        
        st.metric("Cyber Risk Score", f"{result['score']} / 100")
        st.progress(result['score'] / 100.0)
        st.write(f"**Recommended Priority:** {rec_map.get(result['severity'])}")
        st.write(f"**Matched Condition:** `{result['matched_condition']}`")
        st.markdown('</div>', unsafe_allow_html=True)
        
        
        # Condition Trace
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.subheader("Condition Trace")
        
        for cond in result["conditions"]:
            st.markdown(f"""
            <div class="trace-item {cond['class']}">
                {cond['symbol']} {cond['status']} : <code>{cond['text']}</code>
            </div>
            """, unsafe_allow_html=True)
            
        st.markdown(f"""
        <div style="margin-top: 16px; padding: 12px; border-left: 3px solid #38bdf8; background: rgba(56,189,248,0.1);">
            <strong>Why was this severity selected?</strong><br>
            {result['explanation'].replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        # Breakdown (only show if not from boundary test)
        if not st.session_state.form_data.get("custom"):
            fd = st.session_state.form_data
            
            # Map factors to their scores for display
            s_val = {"Critical": 30, "High": 24, "Medium": 16, "Low": 8, "Informational": 0}.get(fd['severity'], 0)
            ex_val = {"Easy": 20, "Moderate": 10, "Difficult": 0}.get(fd['exploitability'], 0)
            ast_val = {"Internet-facing": 20, "Internal": 10, "Isolated": 0}.get(fd['exposure'], 0)
            conf_val = {"High": 20, "Medium": 10, "Low": 0}.get(fd['confidence'], 0)
            freq_val = {"Repeated": 10, "Occasional": 5, "Single Event": 0}.get(fd['frequency'], 0)
            
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.subheader("Risk Score Breakdown")
            st.markdown(f"""
            <div class="breakdown-row"><span>Vulnerability Severity ({fd['severity']})</span> <span>+{s_val}</span></div>
            <div class="breakdown-row"><span>Exploitability ({fd['exploitability']})</span> <span>+{ex_val}</span></div>
            <div class="breakdown-row"><span>Asset Exposure ({fd['exposure']})</span> <span>+{ast_val}</span></div>
            <div class="breakdown-row"><span>Detection Confidence ({fd['confidence']})</span> <span>+{conf_val}</span></div>
            <div class="breakdown-row"><span>Event Frequency ({fd['frequency']})</span> <span>+{freq_val}</span></div>
            <div class="breakdown-divider"></div>
            <div class="total-row"><span>Total Risk Score</span> <span>{result['score']}</span></div>
            """, unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
    else:
        st.markdown('<div class="glass-card" style="text-align: center; color: #94a3b8; padding: 40px;">', unsafe_allow_html=True)
        st.write("👈 Configure event parameters and click **ANALYZE THREAT** to begin.")
        st.markdown('</div>', unsafe_allow_html=True)

# --- LEARNING & CODE SECTION ---
st.markdown("---")
col3, col4 = st.columns(2)

with col3:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Python Logic")
    
    code = '''
if risk_score >= 90:
    severity = "CRITICAL"
elif risk_score >= 70:
    severity = "HIGH"
elif risk_score >= 40:
    severity = "MEDIUM"
elif risk_score >= 20:
    severity = "LOW"
else:
    severity = "INFORMATIONAL"
'''
    st.code(code, language="python")
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("Understanding Python Decision Flow")
    st.markdown("""
    * **`if`**: The first condition is checked. If it evaluates to `True`, its block executes, and the rest are skipped.
    * **`elif`** (Else If): Checked *only* when the previous condition(s) evaluate to `False`. It provides alternative conditions.
    * **`else`**: Runs automatically when *all* previous `if` and `elif` conditions evaluate to `False`. It acts as the default fallback.
    
    **Cybersecurity Example Context:**
    * If risk is Critical → immediate incident response
    * Else if risk is High → high-priority review
    * Else if risk is Medium → normal investigation
    * Else if risk is Low → monitor
    * Else → log and ignore (informational)
    """)
    st.markdown('</div>', unsafe_allow_html=True)
