<img width="661" height="391" alt="email" src="https://github.com/user-attachments/assets/e4062faa-2c06-46aa-84b2-f3be6f9a1153" />


# Email Header Forensics

A Chrome browser extension designed to analyze suspicious emails through detailed header forensics.

The extension extracts sender information from email headers and performs comprehensive reputation checks using VirusTotal, IPinfo.io, and AbuseIPDB.

## Features

- Accurate extraction of sender IP address from raw email headers
- Real-time reputation checks across multiple threat intelligence platforms
- Authentication analysis (SPF, DKIM, DMARC)
- Risk scoring system
- Detection of suspicious scripts and links
- Geolocation and ASN information
- Detailed VirusTotal vendor analysis
- User-friendly interface for quick investigations

## How to Use

1. Open the suspicious email in your email client (Gmail, Outlook, etc.)
2. Click **Show Original** (Gmail) or equivalent option to view the raw message
3. Copy the complete email header
4. Open the **Email Header Forensics** extension
5. Paste the header into the provided field
6. Click **Analyze**
7. Review the detailed forensic report including IP reputation, location, risk assessment, and authentication results

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer Mode** in the top right corner
4. Click **Load unpacked** and select the extension folder
5. Pin the extension icon to your toolbar for easy access

## Configuration

You will need free API keys from the following services:

- [VirusTotal](https://www.virustotal.com/gui/join-us)
- [IPinfo.io](https://ipinfo.io/signup)
- [AbuseIPDB](https://www.abuseipdb.com/register)

After obtaining the keys:
1. Click the extension icon
2. Go to **Options**
3. Enter your API keys in the respective fields

## Technologies

- JavaScript
- Chrome Extensions API (Manifest V3)
- Email Header Parsing Logic
- REST API Integration

## Disclaimer

This tool is intended for educational purposes and legitimate email security investigations. Always respect privacy and use responsibly.

---

**Email Header Forensics Extension v1.0**
