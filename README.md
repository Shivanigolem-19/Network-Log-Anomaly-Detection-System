# Network Log Anomaly Detection System

## Overview
A Python-based project that analyzes server and network login logs to identify potentially suspicious activities.

## Features
- Reads and parses log files.
- Detects repeated failed login attempts.
- Analyzes IP addresses, usernames, and event types.
- Generates a timeline of suspicious activities.
- Creates security summary reports.

## Technologies Used
- Python
- File Handling
- Lists and Dictionaries
- `datetime`
- `collections.Counter`

## Project Files
- `main.py` — Main program.
- `sample_logs.txt` — Sample network log data.
- `users.txt` — User data used by the program.
- `security_report.txt` — Security summary report.
- `suspicious_activity.txt` — Suspicious activity report.

## How to Run
1. Install Python.
2. Download or clone this repository.
3. Open the project folder in VS Code.
4. Run the program using:

```
python main.py
```

## Disclaimer
This project is for educational purposes and uses sample data. It is not a replacement for a production security monitoring system.
