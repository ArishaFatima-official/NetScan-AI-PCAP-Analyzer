# NetScan – AI-Powered PCAP Security Analyzer

## Overview

NetScan is a Python-based network traffic analysis tool that automates the inspection of PCAP (Packet Capture) files and generates a comprehensive HTML security dashboard. It extracts packet-level information, analyzes network behavior, detects common security threats using rule-based heuristics, and presents the results through interactive visualizations.

The project was developed to simplify network forensic analysis by eliminating the need to manually inspect thousands of packets in tools such as Wireshark.

---

## Features

* 📂 Analyze any PCAP file
* 📊 Interactive HTML dashboard
* 📈 Network traffic visualizations
* 🚨 Automated security threat detection
* 🌐 Protocol distribution analysis
* 📡 Top talkers and conversation analysis
* 📦 Packet statistics and throughput metrics
* 🔍 Rule-based detection engine with remediation suggestions

---

## Security Detection

NetScan can identify several common network threats, including:

* ICMP Flood Detection
* TCP SYN Flood Detection
* TCP Port Scan Detection
* One-Way ICMP Communication
* Destination Unreachable & TTL Exceeded Events
* Oversized ICMP Packets (Possible ICMP Tunneling)
* Cleartext Protocol Usage (HTTP, FTP, Telnet, SMTP, POP3, IMAP)
* ARP Scan Detection
* Asymmetric Traffic Detection

Each finding includes:

* Severity Level
* Description
* Technical Details
* Suggested Mitigation Commands

---

## Technologies Used

* Python 3
* Scapy
* Matplotlib
* NumPy
* HTML & CSS
* Base64 Image Encoding

---

## Project Structure

```
NetScan/
│
├── pcap_analyzer.py
├── pcap_report/
│   └── dashboard.html
├── sample_pcaps/
├── screenshots/
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/NetScan-AI-PCAP-Analyzer.git
```

Install dependencies:

```bash
pip install scapy matplotlib numpy
```

---

## Usage

Run NetScan using:

```bash
python3 pcap_analyzer.py <file.pcap>
```

Example:

```bash
python3 pcap_analyzer.py sample.pcap
```

The generated dashboard will be saved as:

```
pcap_report/dashboard.html
```

Open the file in any modern web browser.

---

## Dashboard Includes

* Network Statistics
* Protocol Distribution
* Traffic Timeline
* Packet Size Analysis
* Top Talkers
* TTL Distribution
* Network Topology
* IP Conversations
* Packet Details
* Security Findings

---

## Screenshots

You can add screenshots of the dashboard here.

```
screenshots/dashboard-overview.png
screenshots/security-alerts.png
screenshots/network-analytics.png
```

---

## Future Improvements

* Machine Learning-based anomaly detection
* Real-time packet capture mode
* Multi-PCAP comparison
* TLS metadata analysis
* SIEM integration (Splunk, Elastic)
* Flask/FastAPI web interface

---

## License

This project is licensed under the MIT License.

---

## Author

**Ari**

If you found this project helpful, consider giving it a ⭐ on GitHub!
