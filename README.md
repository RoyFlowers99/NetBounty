# NetBounty

NetBounty is a lightweight, portable tool designed to streamline and assist in network scanning, service identification, and vulnerability enumeration.

---

## Features
- **Network Scanning**: Identify live hosts and open ports.
- **Service Identification**: Determine running services on open ports.
- **Streamlined Vulnerability Enumeration**: Provide links to vulnerabilities on cve.mitre.org.

---

## Prerequisites

### Python
- Python 3.x is required. Install it from [python.org](https://www.python.org).

### Dependencies

- Install project dependencies:

      pip install -r requirements.txt

### Npcap (Windows)

   Npcap is required for network packet sniffing and Layer 2 operations on Windows.
   You can download Npcap by running the `npcap_inst.py` file in the `/src/` directory or from [npcap.com](https://npcap.com/dist/).
        
   During Installation:
   
   - Ensure "Install Npcap in WinPcap API-compatible mode" is selected.

---

## Installation

 - Clone the repository:

   `git clone https://github.com/RoyFlowers99/NetBounty.git`

   `cd NetBounty`

- Install Dependencies:

    - Create virtual environment

            python -m venv venv

    - Activate Virtual Environment 

            Windows:
            .\venv\Scripts\activate


            macOS/Linux: 
            source ./venv/bin/activate

    - Install dependencies with pip

            pip install -r requirements.txt

---

## Usage

   - Activate Virtual Environment 

                Windows:
                venv\Scripts\activate


                macOS/Linux: 
                source venv/bin/activate

        `python ./src/main.py`

        macOS and Linux users may have to run as sudo.

   - Follow the Prompts:

        - Enter an IP range to scan (in CIDR notation, e.g., 192.168.1.0/24).

        - Provide a list of ports to scan (comma-separated, e.g., 22,80,443).

   - View Results:

        A simple HTML report (report.html) will be created in the script's directory.

        The report includes:

                IP addresses
                ports
                service names 
                product names
                semantic versions
                clickable CVE search links

        The report automatically opens in the default web browser.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

This project relies on Npcap for network functionality. Npcap is not included with this software and must be installed separately. 
Please review Npcap's licensing terms at https://nmap.org/npsl/.