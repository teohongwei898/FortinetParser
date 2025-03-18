# Fortinet Log Parser

A command-line tool to parse **Fortinet Forward Traffic** and **VPN Event** logs, extracting meaningful insights.

## 🚀 Features

- **Supports both Forward Traffic & VPN Logs**
- **Multi-file processing** (can handle entire directories)
- **Automatic time zone extraction** (Formats times as `UTC+X`)
- **Handles traffic sessions correctly**, even when Fortinet reuses `sessionid`
- **Detects anomalies** like decreasing byte values
- **Outputs to an Excel file with detailed and summary sheets**
- **Customizable output location** using `-o`

---

## 📥 Installation

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/fortinet-log-parser.git
cd fortinet-log-parser

