# Fortinet Log Parser

A command-line tool to parse **Fortinet Forward Traffic** and **VPN User Event** logs, extracting meaningful insights.

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
git clone https://github.com/teohongwei898/fortinetparser.git
cd fortinetparser
```

### **2️⃣ Install Dependencies**

Make sure you have Python 3.6+ installed, then install required libraries:
```bash
pip install -r requirements.txt
```

### **⚡ Usage**
### **🔹 Basic Command**

To process a single log file:
```bash
python log_parser.py -t forward_traffic -f /path/to/forward_traffic.log
```
To process a directory of logs:
```bash
python log_parser.py -t vpn_event -d /path/to/logs/
```
To specify an output directory:
```bash
python log_parser.py -t forward_traffic -d /path/to/logs/ -o /path/to/output/
```
### **🔹 Arguments**
```bash
| Argument    | Short | Description                                         |
|------------|-------|-----------------------------------------------------|
| `--type`   | `-t`  | **Required**: Type of log file (`forward_traffic` or `vpn_event`) |
| `--directory` | `-d` | Path to a directory containing multiple log files |
| `--file`   | `-f`  | Path to a single log file                          |
| `--output` | `-o`  | *(Optional)* Directory to save the output XLSX file |

```
