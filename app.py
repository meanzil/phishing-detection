import importlib
import json
import os
import re
import textwrap
import streamlit as st

import detector
importlib.reload(detector)
from detector import analyze_email

import ai.ollama_cloud
importlib.reload(ai.ollama_cloud)
from ai.ollama_cloud import analyze_with_ollama_cloud, ollama_cloud_is_configured

st.set_page_config(
    page_title="AI Phishing Email Detective",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Helper function to render clean HTML without markdown indentation issues
def render_html(html: str):
    st.markdown(textwrap.dedent(html).strip(), unsafe_allow_html=True)

# Premium Modern Styling with Boxicons and Dark/Light Mode Glassmorphic Design
render_html(
    """
    <link rel="stylesheet" href="https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
        }
        code, pre {
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* Hero Header */
        .header-container {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(59, 130, 246, 0.08) 50%, rgba(139, 92, 246, 0.08) 100%);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 24px 28px;
            margin-bottom: 20px;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.08);
        }
        .header-title {
            font-size: 2.1rem;
            font-weight: 800;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .header-subtitle {
            font-size: 1.02rem;
            color: #94a3b8;
            max-width: 820px;
            line-height: 1.5;
        }

        /* Preset Badges */
        .preset-badge {
            font-size: 0.8rem;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 9999px;
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.3);
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        /* Glassmorphic Cards */
        .glass-card {
            background: rgba(30, 41, 59, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 16px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.12);
            backdrop-filter: blur(8px);
        }

        /* Risk Gauge Card */
        .risk-gauge-container {
            border-radius: 20px;
            padding: 24px 20px;
            text-align: center;
            margin-bottom: 20px;
            border: 1px solid rgba(255, 255, 255, 0.12);
            position: relative;
            overflow: hidden;
            box-shadow: 0 12px 36px rgba(0, 0, 0, 0.25);
        }
        .gauge-safe {
            background: radial-gradient(circle at top, rgba(16, 185, 129, 0.22) 0%, rgba(15, 23, 42, 0.88) 100%);
            border-color: rgba(16, 185, 129, 0.45);
        }
        .gauge-suspicious {
            background: radial-gradient(circle at top, rgba(245, 158, 11, 0.22) 0%, rgba(15, 23, 42, 0.88) 100%);
            border-color: rgba(245, 158, 11, 0.45);
        }
        .gauge-high {
            background: radial-gradient(circle at top, rgba(249, 115, 22, 0.25) 0%, rgba(15, 23, 42, 0.88) 100%);
            border-color: rgba(249, 115, 22, 0.5);
        }
        .gauge-critical {
            background: radial-gradient(circle at top, rgba(239, 68, 68, 0.3) 0%, rgba(15, 23, 42, 0.92) 100%);
            border-color: rgba(239, 68, 68, 0.6);
        }

        .risk-score-number {
            font-size: 3.8rem;
            font-weight: 800;
            line-height: 1;
            margin: 10px 0 2px 0;
            letter-spacing: -2px;
        }
        .score-safe { color: #10b981; text-shadow: 0 0 25px rgba(16, 185, 129, 0.5); }
        .score-suspicious { color: #f59e0b; text-shadow: 0 0 25px rgba(245, 158, 11, 0.5); }
        .score-high { color: #f97316; text-shadow: 0 0 25px rgba(249, 115, 22, 0.5); }
        .score-critical { color: #ef4444; text-shadow: 0 0 30px rgba(239, 68, 68, 0.6); }

        .risk-level-badge {
            display: inline-block;
            font-size: 1.05rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            padding: 7px 22px;
            border-radius: 9999px;
            margin-bottom: 10px;
        }
        .badge-safe { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
        .badge-suspicious { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
        .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
        .badge-critical { background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid #ef4444; animation: pulse 2s infinite; }

        @keyframes pulse {
            0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
            70% { transform: scale(1.03); box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
            100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }

        /* Custom Progress Bar */
        .progress-bar-bg {
            background: rgba(255, 255, 255, 0.1);
            height: 14px;
            border-radius: 9999px;
            overflow: hidden;
            margin: 14px auto;
            max-width: 480px;
            border: 1px solid rgba(255, 255, 255, 0.15);
        }
        .progress-bar-fill {
            height: 100%;
            border-radius: 9999px;
            transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
        }

        /* Pill tags container */
        .pills-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 8px;
            margin-top: 14px;
        }
        .metric-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 0.88rem;
            font-weight: 500;
            background: rgba(255, 255, 255, 0.07);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #f1f5f9;
        }

        /* Factor Cards */
        .factor-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
            transition: all 0.2s ease;
        }
        .factor-card:hover {
            border-color: rgba(59, 130, 246, 0.4);
            transform: translateY(-2px);
        }
        .factor-title {
            font-size: 0.98rem;
            font-weight: 600;
            color: #e2e8f0;
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }
        .factor-desc {
            font-size: 0.91rem;
            color: #94a3b8;
            line-height: 1.45;
        }

        /* Red flags & recommendations */
        .flag-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 14px;
            border-radius: 10px;
            background: rgba(239, 68, 68, 0.08);
            border-left: 3px solid #ef4444;
            margin-bottom: 8px;
            font-size: 0.92rem;
            color: #fca5a5;
        }
        .rec-item {
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 10px 14px;
            border-radius: 10px;
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid #10b981;
            margin-bottom: 8px;
            font-size: 0.92rem;
            color: #a7f3d0;
        }
    </style>
    """
)

# Header Section
render_html(
    """
    <div class="header-container">
        <div class="header-title">
            <i class='bx bx-shield-quarter'></i> AI Phishing Detection & Threat Intelligence
        </div>
        <div class="header-subtitle">
            Next-generation email threat detector powered by multi-factor heuristic checks and
            deep AI contextual reasoning. Accurately evaluates Subject Urgency, Sender Authenticity, Detail Submission Baits, and Malicious URLs.
        </div>
    </div>
    """
)

# Predefined Email Samples for Instant Testing
SAMPLE_EMAILS = {
    "🚨 PayPal Suspension": {
        "subject": "URGENT: Your PayPal Account Has Been Suspended!",
        "sender": "service-support@paypa1-security.info",
        "body": (
            "Dear Customer,\n\n"
            "We have detected unusual sign-in activity and unauthorized transactions on your PayPal account. "
            "For your security, your account access has been restricted immediately.\n\n"
            "You are required to verify your identity within 24 hours to restore full account privileges. "
            "Failure to act immediately will result in permanent account termination.\n\n"
            "Please click below to verify your login credentials:\n"
            "http://paypa1-security.info/login\n\n"
            "Sincerely,\nPayPal Fraud Prevention Department"
        ),
    },
    "📝 Details Submission Scam": {
        "subject": "Urgent: Mandatory Submission of Account Details Required",
        "sender": "account-verification@service-portal.info",
        "body": (
            "Dear Account Holder,\n\n"
            "Your account verification details are incomplete. "
            "To prevent permanent de-activation, you must submit your verification details and confirm your password immediately.\n\n"
            "Please complete the submission form here:\n"
            "http://portal-verification-submit.info/form?id=9021\n\n"
            "Submission deadline is within 12 hours of this notice.\n\n"
            "Security Team"
        ),
    },
    "⚠️ Overdue Invoice": {
        "subject": "Action Required: Overdue Invoice #INV-892110 Payment Failed",
        "sender": "billing-support-dept@gmail.com",
        "body": (
            "Attention Accounts Payable,\n\n"
            "Your previous payment failed. An outstanding balance of $3,450.00 is now overdue. "
            "To avoid late fees and immediate legal collection, confirm your payment details immediately.\n\n"
            "Review the invoice and submit payment here:\n"
            "http://192.168.1.105/invoices/download?id=892110\n\n"
            "Thank you,\nFinance Department"
        ),
    },
    "✅ Team Meeting Sync": {
        "subject": "Project Sprint Planning - Wednesday at 2:00 PM",
        "sender": "alex.morgan@company.com",
        "body": (
            "Hi team,\n\n"
            "Let's meet tomorrow at 2:00 PM in Conference Room B (or via the usual video link) "
            "to review our sprint backlog and prioritize the upcoming Q4 milestones.\n\n"
            "Please add any agenda topics to the shared workspace doc before the meeting:\n"
            "https://docs.google.com/document/d/1a2b3c4d5e/edit\n\n"
            "Best regards,\nAlex"
        ),
    },
}

# Session State Initialization for inputs
if "email_subject" not in st.session_state:
    st.session_state.email_subject = ""
if "email_sender" not in st.session_state:
    st.session_state.email_sender = ""
if "email_body" not in st.session_state:
    st.session_state.email_body = ""

# Quick Samples Row
st.markdown("<p style='font-weight:600; font-size:0.95rem; margin-bottom:8px; color:#cbd5e1;'>⚡ Load realistic test samples:</p>", unsafe_allow_html=True)
sample_cols = st.columns(len(SAMPLE_EMAILS))
for i, (name, data) in enumerate(SAMPLE_EMAILS.items()):
    with sample_cols[i]:
        if st.button(name, key=f"sample_{i}", use_container_width=True):
            st.session_state.email_subject = data["subject"]
            st.session_state.email_sender = data["sender"]
            st.session_state.email_body = data["body"]
            st.rerun()

st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

# Main Form Area
col_input, col_config = st.columns([2.7, 1.3])

with col_input:
    subject = st.text_input(
        "Email Subject Line",
        value=st.session_state.email_subject,
        placeholder="e.g. Urgent: Submit Your Verification Details to Avoid Suspension",
        help="Analyzed for urgency triggers, submission demands, panic cues, capitalization, and baiting.",
    )
    sender = st.text_input(
        "Sender Email Address",
        value=st.session_state.email_sender,
        placeholder="e.g. security-team@paypa1-update.com or support@company.com",
        help="Analyzed for domain authenticity, brand lookalikes (typosquatting), and free-mail impersonation.",
    )
    body = st.text_area(
        "Email Body Content",
        value=st.session_state.email_body,
        height=210,
        placeholder="Paste full email body including greetings, submission requests, deadlines, and embedded links...",
        help="Evaluated for credential harvesting, form submission demands, social engineering manipulation, and suspicious URLs.",
    )

with col_config:
    render_html(
        """
        <div class="glass-card" style="padding:16px;">
            <div style="font-weight:700; font-size:1.02rem; margin-bottom:10px; color:#f8fafc; display:flex; align-items:center; gap:8px;">
                <i class='bx bx-cog' style='color:#38bdf8; font-size:1.25rem;'></i> Detection & Model Settings
            </div>
        """
    )
    cloud_configured = ollama_cloud_is_configured()

    ai_platform = st.radio(
        "AI Platform",
        options=["Ollama Cloud", "Local Ollama"],
        index=0 if cloud_configured else 1,
        help="Choose whether to use Ollama Cloud (remote) or Local Ollama (running locally on port 11434).",
    )

    if ai_platform == "Ollama Cloud":
        if cloud_configured:
            render_html(
                """
                <div style="margin-bottom:8px;">
                    <span class="preset-badge" style="background:rgba(16, 185, 129, 0.15); color:#34d399; border-color:rgba(16, 185, 129, 0.3);">
                        <i class='bx bx-cloud-check'></i> Ollama Cloud Ready
                    </span>
                </div>
                """
            )
        else:
            render_html(
                """
                <div style="margin-bottom:8px;">
                    <span class="preset-badge" style="background:rgba(245, 158, 11, 0.15); color:#fbbf24; border-color:rgba(245, 158, 11, 0.3);">
                        <i class='bx bx-key'></i> API Key Missing in .env
                    </span>
                </div>
                """
            )
        selected_model = st.text_input(
            "Cloud Model",
            value=os.getenv("OLLAMA_MODEL", "gemma4:31b"),
            help="Ollama Cloud model name (e.g. gemma4:31b, llama3.3, mistral).",
        )
    else:
        render_html(
            """
            <div style="margin-bottom:8px;">
                <span class="preset-badge" style="background:rgba(59, 130, 246, 0.15); color:#60a5fa; border-color:rgba(59, 130, 246, 0.3);">
                    <i class='bx bx-server'></i> Local (127.0.0.1:11434)
                </span>
            </div>
            """
        )
        selected_model = st.text_input(
            "Local Model",
            value="llama3.2",
            help="Model installed in your local Ollama (e.g. llama3.2, mistral, gemma2, phi3).",
        )

    enable_ai = st.checkbox(
        "⚡ Enable AI Deep Analysis",
        value=True,
        help="Uses AI contextual reasoning to detect social engineering and psychological manipulation.",
    )

    render_html(
        """
        <div style="font-size:0.83rem; color:#94a3b8; line-height:1.45; margin-top:8px;">
            <b>Active Inspection Layers:</b><br>
            • Detail & credential submission traps<br>
            • Subject line psychological pressure<br>
            • Sender spoofing & lookalike domains<br>
            • Links, non-HTTPS & IP hostnames
        </div>
        </div>
        """
    )

    analyze_btn = st.button("🛡️ Analyze Email Security", type="primary", use_container_width=True)

st.divider()

# Execution & Analysis Workflow
if analyze_btn:
    if not (subject.strip() or sender.strip() or body.strip()):
        st.warning("⚠️ Please provide at least one field (Subject, Sender, or Email Body) to analyze.")
    else:
        # 1. Run Enhanced Rule-Based Heuristic Detection
        heuristic_res = analyze_email(subject=subject, sender=sender, body=body)
        h_score = heuristic_res["risk_score"]
        h_classification = heuristic_res["classification"]

        # 2. Run AI Deep Analysis if selected
        ai_res = None
        platform_mode = "local" if ai_platform == "Local Ollama" else "cloud"

        if enable_ai:
            if platform_mode == "cloud" and not cloud_configured:
                st.warning("OLLAMA_API_KEY is not configured in `.env`. Running with heuristic rule engine or switch to Local Ollama.")
            else:
                with st.spinner(f"🤖 Consulting {ai_platform} ({selected_model}) + Security Tools..."):
                    try:
                        raw_ai = analyze_with_ollama_cloud(
                            subject=subject,
                            sender=sender,
                            body=body,
                            platform=platform_mode,
                            custom_model=selected_model,
                        )
                        if isinstance(raw_ai, dict):
                            ai_res = raw_ai
                        elif isinstance(raw_ai, str):
                            json_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw_ai)
                            json_str = json_match.group(1).strip() if json_match else raw_ai.strip()
                            try:
                                ai_res = json.loads(json_str)
                            except Exception:
                                ai_res = {
                                    "ai_risk_score": 50,
                                    "ai_classification": "Suspicious",
                                    "confidence": "Medium",
                                    "attack_type": "Social Engineering",
                                    "summary": raw_ai[:200] + "...",
                                    "subject_analysis": "Subject inspected by AI.",
                                    "sender_analysis": "Sender verified by AI.",
                                    "content_analysis": "Content analyzed by AI.",
                                    "url_analysis": "URLs checked by AI.",
                                    "red_flags": [],
                                    "recommendations": ["Exercise caution when handling this message."],
                                }
                    except Exception as exc:
                        st.error(f"AI Analysis could not complete: {exc}")

        # 3. Calculate Overall Unified Risk Score
        if ai_res and isinstance(ai_res, dict) and "ai_risk_score" in ai_res:
            ai_score = int(ai_res.get("ai_risk_score", 0))
            if max(h_score, ai_score) >= 80:
                final_score = max(h_score, ai_score)
            else:
                final_score = round((0.35 * h_score) + (0.65 * ai_score))
            final_score = max(0, min(100, final_score))
            confidence = ai_res.get("confidence", "High")
            attack_type = ai_res.get("attack_type", "Phishing / Social Engineering" if final_score >= 50 else "Legitimate")
        else:
            final_score = h_score
            ai_score = None
            confidence = "Rule-Based"
            attack_type = "Suspicious Communication" if final_score >= 50 else "Standard Message"

        # Determine Unified Risk Classification & Visual Styles
        if final_score >= 85:
            risk_tier = "CRITICAL RISK"
            gauge_class = "gauge-critical"
            score_class = "score-critical"
            badge_class = "badge-critical"
            bar_color = "linear-gradient(90deg, #f97316, #ef4444, #b91c1c)"
            summary_desc = "High-confidence malicious email. Severe indicators of phishing, spoofing, or credential theft."
        elif final_score >= 60:
            risk_tier = "HIGH RISK"
            gauge_class = "gauge-high"
            score_class = "score-high"
            badge_class = "badge-high"
            bar_color = "linear-gradient(90deg, #f59e0b, #f97316, #ef4444)"
            summary_desc = "Significant phishing indicators detected. Strong social engineering pressure or deceptive links."
        elif final_score >= 30:
            risk_tier = "SUSPICIOUS"
            gauge_class = "gauge-suspicious"
            score_class = "score-suspicious"
            badge_class = "badge-suspicious"
            bar_color = "linear-gradient(90deg, #10b981, #f59e0b)"
            summary_desc = "Unusual characteristics found. Exercise caution and verify sender identity before interacting."
        else:
            risk_tier = "SAFE / LOW RISK"
            gauge_class = "gauge-safe"
            score_class = "score-safe"
            badge_class = "badge-safe"
            bar_color = "linear-gradient(90deg, #059669, #10b981, #34d399)"
            summary_desc = "No prominent phishing or spoofing indicators detected. Appears consistent with normal email."

        # RENDER MAIN RISK GAUGE
        ai_pill = f"<span class='metric-pill'><i class='bx bx-bot'></i> {ai_platform}: <b>{ai_score}/100</b> ({selected_model})</span>" if ai_score is not None else ""
        render_html(
            f"""
            <div class="risk-gauge-container {gauge_class}">
                <div class="risk-level-badge {badge_class}">
                    <i class='bx bx-error-circle'></i> {risk_tier}
                </div>
                <div class="risk-score-number {score_class}">
                    {final_score}<span style="font-size:2rem; opacity:0.6;">/100</span>
                </div>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill" style="width:{final_score}%; background:{bar_color};"></div>
                </div>
                <div style="font-size:1.08rem; color:#f1f5f9; font-weight:600; margin-top:8px;">
                    {summary_desc}
                </div>
                <div class="pills-container">
                    <span class="metric-pill"><i class='bx bx-check-shield'></i> Overall Score: <b>{final_score}/100</b></span>
                    <span class="metric-pill"><i class='bx bx-code-block'></i> Heuristic Rules: <b>{h_score}/100</b></span>
                    {ai_pill}
                    <span class="metric-pill"><i class='bx bx-target-lock'></i> Threat: <b>{attack_type}</b></span>
                    <span class="metric-pill"><i class='bx bx-badge-check'></i> Confidence: <b>{confidence}</b></span>
                </div>
            </div>
            """
        )

        # TABBED BREAKDOWN
        tab_action, tab_ai, tab_heuristics, tab_urls = st.tabs([
            "🎯 Threat Summary & Action Plan",
            "🤖 AI Multi-Factor Analysis",
            "⚙️ Heuristic Rules & Scoring",
            "🌐 Extracted URLs & Domains",
        ])

        with tab_action:
            col_sum, col_rec = st.columns(2)
            with col_sum:
                st.markdown("#### 🚨 Identified Red Flags & Indicators")
                all_flags = []
                if ai_res and isinstance(ai_res, dict) and ai_res.get("red_flags"):
                    all_flags.extend(ai_res["red_flags"])
                if heuristic_res.get("findings"):
                    for f in heuristic_res["findings"]:
                        if f not in all_flags:
                            all_flags.append(f)

                if all_flags:
                    for flag in all_flags:
                        render_html(
                            f"""
                            <div class="flag-item">
                                <i class='bx bx-error' style='font-size:1.2rem; flex-shrink:0; margin-top:1px;'></i>
                                <div>{flag}</div>
                            </div>
                            """
                        )
                else:
                    st.success("✅ No critical red flags were triggered.")

            with col_rec:
                st.markdown("#### 🛡️ Recommended Security Actions")
                recommendations = []
                if ai_res and isinstance(ai_res, dict) and ai_res.get("recommendations"):
                    recommendations.extend(ai_res["recommendations"])
                else:
                    if final_score >= 60:
                        recommendations = [
                            "Do not click any embedded links or open attachments.",
                            "Do not submit passwords, banking details, personal information, or 2FA codes.",
                            "Mark as Phishing/Spam in your email client immediately.",
                            "Report the message to your security operations team (SOC) or IT admin.",
                        ]
                    elif final_score >= 30:
                        recommendations = [
                            "Verify the sender address carefully through a separate communication channel.",
                            "Hover over URLs without clicking to verify the true destination domain.",
                            "Never submit credentials or personal information on unfamiliar pages.",
                        ]
                    else:
                        recommendations = [
                            "Standard precautions apply. Communication appears legitimate.",
                            "Always ensure sensitive transactions use verified official portals.",
                        ]

                for rec in recommendations:
                    render_html(
                        f"""
                        <div class="rec-item">
                            <i class='bx bx-check-shield' style='font-size:1.2rem; flex-shrink:0; margin-top:1px;'></i>
                            <div>{rec}</div>
                        </div>
                        """
                    )

        with tab_ai:
            if ai_res and isinstance(ai_res, dict):
                st.markdown("#### 🧠 Contextual Intelligence Breakdown")
                st.info(f"**Executive Summary:** {ai_res.get('summary', 'Analysis completed successfully.')}")

                col_ai_1, col_ai_2 = st.columns(2)
                with col_ai_1:
                    render_html(
                        f"""
                        <div class="factor-card">
                            <div class="factor-title">
                                <i class='bx bx-envelope' style='color:#38bdf8;'></i> Subject Line Analysis
                            </div>
                            <div class="factor-desc">{ai_res.get('subject_analysis', 'No subject anomalies noted.')}</div>
                        </div>
                        <div class="factor-card">
                            <div class="factor-title">
                                <i class='bx bx-user-pin' style='color:#a855f7;'></i> Sender Identity & Domain Analysis
                            </div>
                            <div class="factor-desc">{ai_res.get('sender_analysis', 'Sender domain verified.')}</div>
                        </div>
                        """
                    )
                with col_ai_2:
                    render_html(
                        f"""
                        <div class="factor-card">
                            <div class="factor-title">
                                <i class='bx bx-message-rounded-error' style='color:#f97316;'></i> Content & Social Engineering Tactics
                            </div>
                            <div class="factor-desc">{ai_res.get('content_analysis', 'Body inspected for pressure tactics and submission demands.')}</div>
                        </div>
                        <div class="factor-card">
                            <div class="factor-title">
                                <i class='bx bx-link' style='color:#ec4899;'></i> URL & Link Destination Analysis
                            </div>
                            <div class="factor-desc">{ai_res.get('url_analysis', 'No malicious link patterns identified.')}</div>
                        </div>
                        """
                    )
            else:
                st.info(
                    "AI analysis was not performed for this run. Check the **Enable AI Deep Analysis** box and ensure your "
                    "Ollama model and platform are configured to unlock deep multi-factor reasoning."
                )

        with tab_heuristics:
            st.markdown("#### ⚙️ Rule-Engine Component Scores")
            breakdown = heuristic_res.get("breakdown", {})
            b_col1, b_col2, b_col3, b_col4 = st.columns(4)
            b_col1.metric("Subject Risk", f"{breakdown.get('subject_score', 0)}/100")
            b_col2.metric("Sender Risk", f"{breakdown.get('sender_score', 0)}/100")
            b_col3.metric("Body Risk", f"{breakdown.get('body_score', 0)}/100")
            b_col4.metric("URL Risk", f"{breakdown.get('url_score', 0)}/100")

            st.markdown("#### 📋 Rule Triggers Detected")
            if heuristic_res["findings"]:
                for f in heuristic_res["findings"]:
                    st.write(f"• {f}")
            else:
                st.write("No indicators were detected by the static rules.")

        with tab_urls:
            st.markdown("#### 🔗 Extracted URLs & Destination Findings")
            extracted_urls = heuristic_res.get("urls", [])
            if extracted_urls:
                for u in extracted_urls:
                    st.code(u, language="text")
            else:
                st.write("No URLs found in the analyzed email.")
