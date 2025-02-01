import streamlit as st
import re
from groq import Groq

# Set the title of the application
st.title("🔍 AI-Powered Secure Coding Practices Analyzer")

# Description
st.write("""
This tool analyzes your source code in real-time for common vulnerabilities and provides secure coding practices.
**Features:**
- **Language-Specific Detection Rules**
- **Real-Time Analysis**
- **AI-Powered Insights from Groq**
- **Severity Ratings**

Supported Languages: Python, JavaScript, C/C++.
""")

# Set your Groq API key
API_KEY = "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"
client = Groq(api_key=API_KEY)

# Language-specific vulnerability patterns and severity
language_rules = {
    "Python": {
        "SQL Injection": {
            "patterns": [r"execute\(['\"].*\+.*['\"]\)", r"cursor\.execute\(['\"].*\+.*['\"]\)"],
            "severity": "High",
            "remediation": "Use parameterized queries with libraries like SQLite or SQLAlchemy."
        },
        "Insecure API Calls": {
            "patterns": [r"requests\.get\(['\"]http://.*['\"]\)", r"requests\.post\(['\"]http://.*['\"]\)"],
            "severity": "Medium",
            "remediation": "Always use HTTPS for API requests."
        },
        "Command Injection": {
            "patterns": [r"os\.system\(['\"].*['\"]\)", r"subprocess\.call\(['\"].*['\"]\)"],
            "severity": "High",
            "remediation": "Avoid executing shell commands directly. Use libraries like `subprocess.run()` with safe arguments."
        },
    },
    "JavaScript": {
        "Cross-Site Scripting (XSS)": {
            "patterns": [r"document\.write\((.*)\)", r"innerHTML\s*="],
            "severity": "High",
            "remediation": "Sanitize user inputs using libraries like DOMPurify."
        },
        "Insecure API Calls": {
            "patterns": [r"fetch\(['\"]http://.*['\"]\)", r"ajax\(['\"]http://.*['\"]\)"],
            "severity": "Medium",
            "remediation": "Always use HTTPS for API calls."
        },
        "Eval Injection": {
            "patterns": [r"eval\((.*)\)"],
            "severity": "High",
            "remediation": "Avoid using `eval()`. Use safer alternatives like `JSON.parse()`."
        },
    },
    "C/C++": {
        "Command Injection": {
            "patterns": [r"system\(['\"].*['\"]\)", r"popen\(['\"].*['\"]\)"],
            "severity": "High",
            "remediation": "Avoid direct command execution. Use functions like `execvp()` or `execvpe()` for safer alternatives."
        },
        "Buffer Overflow": {
            "patterns": [r"gets\("],
            "severity": "High",
            "remediation": "Avoid using unsafe functions like `gets()`. Use `fgets()` instead."
        },
    }
}

# Function to analyze code for vulnerabilities
def analyze_code(code, language):
    st.write(f"🔍 Analyzing code for language: {language}")
    
    if language not in language_rules:
        return [{"type": "Unsupported Language", "severity": "Low", "remediation": "Language-specific analysis not available."}]

    rules = language_rules[language]
    issues = []

    for vuln_type, details in rules.items():
        for pattern in details["patterns"]:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            found_examples = set()
            for match in matches:
                found_examples.add(match.group())
            
            for example in found_examples:
                issues.append({
                    "type": vuln_type,
                    "severity": details["severity"],
                    "examples": [example],
                    "remediation": details["remediation"]
                })

    if not issues:
        st.write("✅ No vulnerabilities detected.")
    
    return issues

# Function to get AI-generated security insights
def get_ai_insights(code):
    try:
        st.subheader("🤖 AI-Powered Secure Code Analysis")

        messages = [
            {"role": "system", "content": "You are an AI-powered security code analyzer. Provide insights on security vulnerabilities."},
            {"role": "user", "content": f"Analyze this code for security issues:\n\n{code}"}
        ]

        completion = client.chat.completions.create(
            model="deepseek-r1-distill-llama-70b",
            messages=messages,
            temperature=0.6,
            max_completion_tokens=512,
            top_p=0.95,
            stream=True
        )

        ai_response = ""
        for chunk in completion:
            if hasattr(chunk, "choices") and chunk.choices:
                content = chunk.choices[0].delta.content
                if content:
                    ai_response += content
        
        return ai_response.strip() if ai_response else "⚠️ No response received from AI."

    except Exception as e:
        return f"❌ Error fetching AI insights: {str(e)}"

# Sidebar for selecting language and real-time editor
st.sidebar.title("⚙️ Settings")
language = st.sidebar.selectbox("📌 Select Language", ["Python", "JavaScript", "C/C++"])
st.sidebar.markdown("✍️ Write or paste your source code below:")

# Real-time code editor
code = st.sidebar.text_area("📝 Code Editor", height=300)

if code:
    st.subheader("📊 Analysis Results:")
    vulnerabilities = analyze_code(code, language)
    
    if vulnerabilities:
        for issue in vulnerabilities:
            st.warning(f"⚠️ **{issue['type']}** (Severity: {issue['severity']})")
            st.write("### Examples:")
            for example in issue["examples"]:
                st.code(example)
            st.write("### Suggested Remediation:")
            st.info(issue["remediation"])
            st.write("---")
    else:
        st.success("✅ No vulnerabilities detected. Your code appears secure!")

    # AI Insights
    ai_feedback = get_ai_insights(code)
    st.markdown("### 🤖 AI Insights:")
    st.info(ai_feedback)

# Footer
st.write("---")
st.write("🛡️ Developed with ❤️ using Python, Streamlit, and Groq AI.")

