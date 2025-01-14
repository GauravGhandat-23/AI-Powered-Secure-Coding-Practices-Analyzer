import streamlit as st
import re

# Set the title of the application
st.title("AI-Powered Secure Coding Practices Analyzer")

# Description
st.write("""
This tool analyzes your source code in real-time for common vulnerabilities and provides secure coding practices.
**Features:**
- **Language-Specific Detection Rules**
- **Real-Time Analysis**
- **Severity Ratings**

Supported Languages: Python, JavaScript, C/C++.
""")

# Language-specific vulnerability patterns and severity
language_rules = {
    "Python": {
        "sql_injection": {
            "patterns": [r"execute\(['\"].*\+.*['\"]\)", r"cursor\.execute\(['\"].*\+.*['\"]\)"],
            "severity": "High",
            "remediation": "Use parameterized queries with libraries like SQLite or SQLAlchemy."
        },
        "insecure_api": {
            "patterns": [r"requests\.get\(['\"]http://.*['\"]\)", r"requests\.post\(['\"]http://.*['\"]\)"],
            "severity": "Medium",
            "remediation": "Always use HTTPS for API requests."
        },
        "command_injection": {
            "patterns": [r"os\.system\(['\"].*['\"]\)", r"subprocess\.call\(['\"].*['\"]\)"],
            "severity": "High",
            "remediation": "Avoid executing shell commands directly. Use libraries like `subprocess.run()` with safe arguments."
        },
    },
    "JavaScript": {
        "xss": {
            "patterns": [r"document\.write\((.*)\)", r"innerHTML\s*="],
            "severity": "High",
            "remediation": "Sanitize user inputs using libraries like DOMPurify."
        },
        "insecure_api": {
            "patterns": [r"fetch\(['\"]http://.*['\"]\)", r"ajax\(['\"]http://.*['\"]\)"],
            "severity": "Medium",
            "remediation": "Always use HTTPS for API calls."
        },
        "eval_injection": {
            "patterns": [r"eval\((.*)\)"],
            "severity": "High",
            "remediation": "Avoid using `eval()`. Use safer alternatives like `JSON.parse()`."
        },
    },
    "C/C++": {
        "command_injection": {
            "patterns": [r"system\(['\"].*['\"]\)", r"popen\(['\"].*['\"]\)"],
            "severity": "High",
            "remediation": "Avoid direct command execution. Use functions like `execvp()` or `execvpe()` for safer alternatives."
        },
        "buffer_overflow": {
            "patterns": [r"gets\("],
            "severity": "High",
            "remediation": "Avoid using unsafe functions like `gets()`. Use `fgets()` instead."
        },
    }
}

# Function to analyze code for vulnerabilities
def analyze_code(code, language):
    st.image('logo.png', width=500)  # Add your logo image with a width of 200px
    st.write(f"Analyzing code for language: {language}")
    
    if language not in language_rules:
        return [{"type": "Unsupported Language", "severity": "Low", "remediation": "Language-specific analysis not available."}]
    
    rules = language_rules[language]
    issues = []
    
    for vuln_type, details in rules.items():
        st.write(f"Checking for: {vuln_type}")
        for pattern in details["patterns"]:
            st.write(f"Using pattern: {pattern}")
            matches = re.finditer(pattern, code, re.IGNORECASE)
            found_examples = set()  # To track unique examples
            for match in matches:
                found_examples.add(match.group())  # Add match to the set to avoid duplicates
            
            # Add unique examples to the issues list
            for example in found_examples:
                issues.append({
                    "type": vuln_type.replace("_", " ").title(),
                    "severity": details["severity"],
                    "examples": [example],
                    "remediation": details["remediation"]
                })
    
    if not issues:
        st.write("No vulnerabilities detected.")
    return issues

# Sidebar for selecting language and real-time editor
st.sidebar.title("Settings")
language = st.sidebar.selectbox("Select Language", ["Python", "JavaScript", "C/C++"])
st.sidebar.markdown("Write or paste your source code below:")

# Real-time code editor
code = st.sidebar.text_area("Code Editor", height=300)

if code:
    st.subheader("Analysis Results:")
    vulnerabilities = analyze_code(code, language)
    if vulnerabilities:
        for issue in vulnerabilities:
            st.warning(f"**{issue['type']}** (Severity: {issue['severity']})")
            st.write("### Examples:")
            for example in issue["examples"]:
                st.code(example)
            st.write("### Suggested Remediation:")
            st.info(issue["remediation"])
            st.write("---")
    else:
        st.success("No vulnerabilities detected. Your code appears secure!")

# Footer
st.write("---")
st.write("Developed with ❤️ using Python and Streamlit.")
