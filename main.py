from detector import analyze_email

subject = "Urgent Account Verification Required"
sender = "security@paypa1-example.com"
body = """
Your account will be suspended within 24 hours.
Verify your account immediately:
https://paypa1-example.com/verify
"""

result = analyze_email(subject, sender, body)
print("Classification:", result["classification"])
print("Risk score:", result["risk_score"], "/100")
print("\nFindings:")
for item in result["findings"]:
    print("-", item)
print("\nExtracted URLs:")
for url in result["urls"]:
    print("-", url)
