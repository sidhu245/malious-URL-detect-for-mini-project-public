[README.md](https://github.com/user-attachments/files/24217000/README.md)
# Malicious URL Detection Web Application

## Overview
ShieldScan is a simple, frontend-based web application designed to detect potentially malicious URLs. It uses rule-based pattern matching to analyze URLs for common security threats without the need for a backend server or AI/ML models. This project is developed for a BTech Cybersecurity mini-project.

## Features
- **User-Friendly Interface**: Modern, glassmorphism-inspired design.
- **Real-time Analysis**: Instant feedback upon scanning.
- **Rule-Based Detection**:
  - **Malicious**: Detects IP-based URLs and excessive special character usage (often used in obfuscation).
  - **Suspicious**: Detects common phishing keywords (e.g., 'login', 'bank') and known URL shorteners.
  - **Safe**: URLs that pass all checks.
- **Input Validation**: Ensures the user enters a valid URL format.

## Technologies Used
- **HTML5**: Structure of the application.
- **CSS3**: Styling, animations, and responsive layout.
- **JavaScript (ES6)**: Logic for URL parsing, validation, and pattern matching.

## How to Run
1. Download or clone the project folder.
2. Open the `index.html` file in any modern web browser (Chrome, Firefox, Edge, etc.).
3. No installation or server required.

## Detection Logic Breakdown
The application analyzes the input URL string against specific regular expressions and lists:
1. **IP Address Check**: Checks if the domain part is an IP address (often associated with direct malware hosting).
2. **Special Character Density**: Counts characters like `-`, `_`, `=`, `%`. A high count (>5) triggers a "Malicious" warning.
3. **Keyword Matching**: Scans for words often found in phishing links (e.g., 'secure', 'update', 'verify').
4. **Shortener detection**: Checks against a list of known link shortening domains.
5. **Length**: Flags unusually long URLs.

## Limitations
- **False Positives**: Legitimate URLs with many parameters or specific keywords might be flagged.
- **No Real-time Database**: Does not check against live blacklists (e.g., Google Safe Browsing).
- **Static Rules**: Cannot detect new, sophisticated obfuscation techniques that don't match the pre-defined patterns.

## Future Enhancements
- Integrate a real Threat Intelligence API (e.g., VirusTotal).
- Implement more complex regex patterns for phishing detection.
- Add a history feature to show previously scanned URLs.

## License
Educational Use Only.
