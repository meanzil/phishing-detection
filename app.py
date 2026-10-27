import streamlit as st
from detector import analyze_email
from ai.ollama_cloud import analyze_with_ollama_cloud, ollama_cloud_is_configured

st.set_page_config(page_title="AI Phishing Detector", page_icon="🛡️", layout="wide")
st.title("AI-Powered Phishing Email Detector")
st.write(
    "Analyze email content using local heuristics and, optionally, "
    "Ollama Cloud AI supported by MCP security tools."
)

subject = st.text_input("Email subject")
sender = st.text_input("Sender email address")
body = st.text_area("Email body", height=250)

cloud_consent = st.checkbox(
    "I understand that the email subject, sender, and body will be sent "
    "to Ollama Cloud for AI analysis. Leave unchecked for local-only analysis.",
    value=False,
)

if st.button("Analyze email", type="primary"):
    if not (subject.strip() or sender.strip() or body.strip()):
        st.warning("Enter at least one email field to analyze.")
    else:
        result = analyze_email(subject, sender, body)
        st.subheader("Rule-based analysis")
        col1, col2 = st.columns(2)
        col1.metric("Risk score", f"{result['risk_score']}/100")
        col2.metric("Classification", result["classification"])
        st.info(result["note"])

        st.subheader("Detected indicators")
        if result["findings"]:
            for finding in result["findings"]:
                st.write(f"• {finding}")
        else:
            st.write("No indicators were detected by the current rules.")

        st.subheader("Extracted URLs")
        if result["urls"]:
            for url in result["urls"]:
                st.code(url)
        else:
            st.write("No URLs found.")

        if cloud_consent:
            if not ollama_cloud_is_configured():
                st.warning(
                    "Ollama Cloud API key is not configured. Copy .env.example to .env, "
                    "set OLLAMA_API_KEY, then restart the app."
                )
            else:
                with st.spinner("Calling local MCP security tools and Ollama Cloud..."):
                    try:
                        ai_assessment = analyze_with_ollama_cloud(
                            subject=subject, sender=sender, body=body
                        )
                    except RuntimeError as exc:
                        st.error(str(exc))
                    else:
                        st.subheader("AI assessment — Ollama Cloud + MCP")
                        st.markdown(ai_assessment)
                        st.caption(
                            "AI output can be wrong. Verify important findings before taking action."
                        )
        else:
            st.caption(
                "AI analysis was not sent to the cloud. Check the consent box above to enable it."
            )
