# 🔓 IDOR Scanner Tool

A lightweight and efficient Python-based tool to automate the detection of **Insecure Direct Object Reference (IDOR)** vulnerabilities in web applications. This tool is designed for **bug bounty hunters**, **penetration testers**, and **security researchers** to help quickly identify IDOR flaws in authenticated or unauthenticated endpoints.

---

## 🚀 Features

- ✅ Supports GET and POST methods  
- 🔑 Authenticated and unauthenticated testing  
- 🔁 Automatic parameter fuzzing (userID, docID, fileID, etc.)  
- 🕵️ Detects response changes (status code, content length, patterns)  
- 📊 Detailed logging and colored CLI output  
- 🔗 URL list input or single URL test mode  
- 🧠 Smart response comparison to reduce false positives

---

## 🧰 Requirements

- Python 3.6+
- `requests`
- `colorama`
- `argparse`

Install dependencies:

```bash
bash run.sh
