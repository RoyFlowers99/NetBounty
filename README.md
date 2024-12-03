# NetBounty
**A Python-Based Network Reconnaissance and Vulnerability Scanner**

---

## Overview
**NetBounty** is a command-line tool designed for network reconnaissance and vulnerability scanning. It automates key stages of penetration testing by identifying active devices, services, open ports, and potential vulnerabilities in a given network. The tool replicates service identification capabilities similar to Nmap, while adding lightweight vulnerability enumeration by integrating real-time data from CVE and NIST APIs. This project highlights Python's versatility in cybersecurity applications and delivers a functional, user-friendly solution.

---

## Objectives
The primary goals of NetBounty are:
- To identify active devices, open ports, and running services within a network.
- To retrieve service banner information (e.g., HTTP, FTP, SSH versions).
- To cross-reference identified services and versions against public vulnerability databases for basic risk assessment.
- To generate comprehensive, easy-to-read reports in JSON and HTML formats.

---

## Key Features
1. **Device and Port Discovery**:
   - Perform network scans to identify active devices and their open ports.
   - Use ARP and ICMP requests for device discovery and `socket` for port scanning.

2. **Service Banner Grabbing**:
   - Retrieve service information (e.g., version details of HTTP, FTP, or SSH services) from open ports using `socket` or custom-crafted packets with `scapy`.

3. **Basic Vulnerability Identification**:
   - Query publicly available APIs (CVE and NIST) to identify vulnerabilities associated with detected services and versions.

4. **Reporting System**:
   - Generate tabular reports in HTML and JSON formats.
   - Provide an organized summary of scan results, including identified vulnerabilities, for easy review in a web browser.

---

## Technologies
NetBounty leverages the following Python libraries and tools:
- **Libraries**:
  - `scapy`: For crafting and analyzing network packets.
  - `socket`: For network communication and port scanning.
  - `os` and `subprocess`: For executing system-level commands.
  - `argparse`: For parsing command-line arguments.
  - `json` and `html`: For report generation.
- **External Tools**:
  - CVE and NIST APIs for vulnerability enumeration and risk assessment.

---

## Target Audience
NetBounty is designed for:
- Ethical hackers
- Penetration testers
- Network administrators

### Use Cases
- Enumerating a local network’s devices, services, and vulnerabilities.
- Testing lab environments for vulnerabilities.
- Automating reconnaissance tasks as part of an ethical hacking workflow.

---

## Challenges and Solutions
1. **Irrelevant or Excessive Data**:
   - Results may include unrelated or excessive data, reducing readability.
   - **Solution**: Implement filtering logic to narrow results by severity or specific software versions.

2. **Portability**:
   - Ensuring the tool operates seamlessly across Linux, Windows, and macOS.
   - **Solution**: Use cross-platform libraries and test on multiple platforms (e.g., using VMs).

3. **API Rate Limits**:
   - Public APIs often impose restrictions on the number of requests per minute or day.
   - **Solution**: Implement caching for frequent queries and retry logic with exponential backoff.

---

## Reporting and Output
NetBounty generates reports in the following formats:
- **HTML**: A browser-friendly table summarizing scan results and vulnerabilities.
- **JSON**: A structured, machine-readable format for integration with other tools or workflows.

---

## How to Use
1. Install the required dependencies in a Python virtual environment:
   ```bash
   pip install -r requirements.txt
