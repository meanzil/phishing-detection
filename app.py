import streamlit as st

from detector import analyze_email

st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
)
st.title("AI-Powered Phishing Email Detector")
st.write("Analyze email content for potential phishing indicators.")

subject = st.text_input("Email subject")
sender = st.text_input("Sender email address")
body = st.text_area("Email body", height=250)

if st.button("Analyze email", type="primary"):
    if not (subject.strip() or sender.strip() or body.strip()):
        st.warning("Enter at least one email field to analyze.")
    else:
        result = analyze_email(subject, sender, body)
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
