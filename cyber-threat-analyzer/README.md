# 🛡️ Cyber Threat Severity Analyzer

**Interactive Python Multi-Condition Cybersecurity Decision Engine**

## 📖 Project Overview
The **Cyber Threat Severity Analyzer** is an educational application designed to demonstrate the power of Python's `if / elif / else` multi-condition decision-making logic through a realistic cybersecurity scenario. 

Users input details about a potential security event, which are converted into a risk score. The Python backend then uses conditional logic to classify the severity of the threat, providing a detailed trace of how the decision was reached.

## ✨ Features
- **Deterministic Risk Scoring:** Translates qualitative security inputs into a quantitative score (0-100).
- **Interactive Multi-Condition Logic:** Directly demonstrates `if/elif/else` boundary evaluations.
- **Condition Trace:** Visually tracks the execution flow of the Python conditionals, showing which statements evaluated to True or False.
- **Boundary Testing:** One-click buttons to instantly test edge cases (e.g., 69 vs 70).
- **Glassmorphism UI:** A sleek, modern SOC-inspired dashboard with custom CSS.
- **Fully Responsive:** Adapts seamlessly to desktops, tablets, and mobile devices.

## 🛠️ Technology Stack
- **Language:** Python 3.11+
- **Framework:** Streamlit
- **Styling:** Custom CSS (Glassmorphism, Cyber-glow aesthetics)
- **Dependencies:** Minimal (only Streamlit and Python standard library)

## 🏗️ Architecture
```
cyber-threat-analyzer/
├── streamlit_app.py            # Main Streamlit application
├── requirements.txt            # Project dependencies
├── README.md                   # Documentation
├── src/                        
│   ├── __init__.py
│   ├── risk_engine.py          # Core logic for scoring and classification
│   └── validators.py           # Input validation (if applicable)
├── assets/                     
│   └── styles.css              # Custom UI styling
└── tests/                      
    ├── __init__.py
    └── test_risk_engine.py     # Unit tests for the boundary logic
```

## 🚀 Installation & Local Execution

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/cyber-threat-analyzer.git
   cd cyber-threat-analyzer
   ```

2. **Create and activate a virtual environment (optional but recommended):**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   streamlit run streamlit_app.py
   ```

## ☁️ Streamlit Cloud Deployment
This project is fully ready for deployment on **Streamlit Community Cloud**:
1. Push this repository to GitHub.
2. Log in to [Streamlit Community Cloud](https://share.streamlit.io/).
3. Click **New App**, select your repository, branch, and specify `streamlit_app.py` as the Main file path.
4. Click **Deploy**. No API keys or environment variables are required!

## 🔐 Cybersecurity Scope
**IMPORTANT:** This is an educational classification tool built for academic demonstration. 
- It **does not** perform real network scanning, exploitation, or penetration testing.
- It **does not** make unauthorized requests or execute shell commands.
- It is entirely safe to run locally or host publicly.

## 🧠 If/Elif/Else Explanation
The core of this application revolves around Python's decision flow:
```python
if risk_score >= 90:
    severity = "CRITICAL"
elif risk_score >= 70:
    severity = "HIGH"
...
```
- `if`: The first condition checked.
- `elif`: Checked only if the previous condition(s) are False.
- `else`: Executes as a fallback when all previous conditions are False.

The UI actively traces this execution flow so learners can visualize which condition was matched.

## 🧪 Testing
Unit tests are included to verify the logic around decision boundaries (e.g., ensuring a score of 69 is `MEDIUM` while 70 is `HIGH`).

To run the tests:
```bash
python -m unittest discover tests
```

## 🔮 Future Improvements
- Add more advanced risk frameworks (like CVSS).
- Export threat assessments to PDF/CSV.
- Implement user-defined conditional thresholds.
