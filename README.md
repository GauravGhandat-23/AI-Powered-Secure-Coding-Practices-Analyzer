<h1 align="center"> 🛡️ 🔍 AI-Powered Secure Coding Practices Analyzer 🔍 🛡️ </h1>

![image](https://github.com/user-attachments/assets/c1c2521d-1743-488c-9ff0-741d392d19ca)


## Overview 📜

[![AI-Powered Secure Coding Practices Analyzer](https://img.shields.io/badge/AI--Powered%20Secure%20Coding%20Practices%20Analyzer-Active-blue)](https://ai-powered-secure-coding-practices-analyzer-d9gda3rgrdxfnsijkd.streamlit.app/)

This tool analyzes your source code in real-time for common vulnerabilities and enforces secure coding practices. It provides security analysis for popular programming languages such as **Python**, **JavaScript**, and **C/C++**. It identifies common vulnerabilities like **SQL Injection**, **XSS**, **Command Injection**, and **Insecure API Usage**, offering recommendations and remediation steps to ensure secure code.Powered by Groq AI, this tool enhances secure coding practices by detecting vulnerabilities and offering AI-generated security insights.

### Features ⚡

- **Language-Specific Detection Rules** 🗣️
- **Real-Time Vulnerability Detection** ⏱️
- **Severity Ratings** ⚠️
- **Remediation Suggestions** 🔧
- **AI-Powered Security Insights** 🤖

### Supported Languages 🌐

- **Python** 🐍
- **JavaScript** 🌍
- **C/C++** 💻

### 🤖 AI-Powered Insights

- The application utilizes Groq AI to provide additional insights into code security. The AI reviews the code and suggests improvements, ensuring best security practices are followed.

### 🔧 Technologies Used

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=Streamlit&logoColor=white)
![AI](https://img.shields.io/badge/AI-000000?style=for-the-badge&logo=ai&logoColor=white)
![Regex](https://img.shields.io/badge/Regex-0099FF?style=for-the-badge&logo=regex&logoColor=white)


## Installation 🚀

1. Clone the Repository :
   
    ```bash
    git clone https://github.com/yourusername/AI-Powered-Secure-Coding-Practices-Analyzer.git
    cd AI-Powered-Secure-Coding-Practices-Analyzer

2. Set Up a Virtual Environment : 🔧
Create and activate a virtual environment
    
    ```bash
    python -m venv venv
    source venv/bin/activate  # On macOS/Linux
    venv\Scripts\activate    # On Windows
    
3. Replace Groq api key in the client = **Groq(api_key="Groq api key")** line with your actual Groq API key. You can get your API key by signing up on Groq's platform.

   ```bash
   API_KEY = "your_api_key_here"
   client = Groq(api_key=API_KEY)
   
5. Install Dependencies : 📦
Install the required libraries

    ```bash
    pip install -r requirements.txt

4. Run the Application : 🚀
Once the dependencies are installed, run the Streamlit app

    ```bash
    streamlit run app.py
    
The app will start running on http://localhost:8501/.


## 📊 Usage 🧑‍💻

1. **Select a Programming Language** 🌟
   - Choose between Python, JavaScript, or C/C++ from the dropdown menu on the sidebar.

2. **Paste or Write Your Code** ✍️
   - Paste your source code in the provided code editor, or write your own code snippet.

3. **Analyze the Code** 🔍
   - The tool will automatically analyze the code and display any detected vulnerabilities along with:

- **Type of vulnerability**
  - Severity (Low, Medium, High)
  - Examples of the detected issue
  - Suggested Remediation
4. Get AI-powered insights to improve security practices.

## 🛡️ Security Vulnerabilities Detected

## 🔴 Python
- **SQL Injection**
- **Insecure API Calls**
- **Command Injection**

![python test_page-0001](https://github.com/user-attachments/assets/92e89f03-5a16-4c81-9a47-6eabc4777008)

![python test 1_page-0001](https://github.com/user-attachments/assets/99b7bcdb-ed7f-4ff3-b065-8a056cd21379)


## 🟠 JavaScript
- **Cross-Site Scripting (XSS)**
- **Insecure API Calls**
- **Eval Injection**

![javascript test_page-0001](https://github.com/user-attachments/assets/7f63bbcc-c5e3-486e-843d-2f95c177ba5e)

![javascript test 1_page-0001](https://github.com/user-attachments/assets/b02fb2ef-65b7-4723-adf7-822ce063480b)


## 🔵 C/C++
- **Command Injection**
- **Buffer Overflow**

![C C++ test_page-0001](https://github.com/user-attachments/assets/09b5ff63-e8ea-4030-a117-1f9dbfd85f9f)

![C C++ test 1_page-0001](https://github.com/user-attachments/assets/35978603-b642-45dd-b92c-c8531187e46b)


## Contributing 🤝

- Feel free to fork this repository, create an issue, or submit a pull request. All contributions are welcome!

## Credits 🙏

- **Streamlit** - for building real-time web apps with ease.
- **Regular Expressions (Regex)** - for vulnerability pattern matching.
- **Python, JavaScript, C/C++** - supported programming languages for analysis.

## Connect with Me 🌐

- 📧 [Email](mailto:gauravghandat12@gmail.com)
- 💼 [LinkedIn](www.linkedin.com/in/gaurav-ghandat-68a5a22b4)






   
