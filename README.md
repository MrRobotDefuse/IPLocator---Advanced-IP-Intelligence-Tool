**IPhunter- Advanced IP Intelligence Tool**

**Description:**

This is a powerful OSINT tool for gathering detailed information about IP addresses. It extracts geolocation data, network information, threat intelligence, and performs port scanning - all without relying on any paid APIs. The tool is specifically designed for cybersecurity professionals, penetration testers, and digital investigators.

**Key Features:**
- Precise geolocation with street-level accuracy when possible
- Multiple data sources for comprehensive information
- Local time calculation based on timezone
- Port scanning capabilities
- Threat assessment from abuse databases
- Clean, professional output format
- Works on Termux and Pydroid3

**Installation (Termux):**

1. Update packages:
```bash
pkg update && pkg upgrade
```

2. Install required dependencies:
```bash
pkg install python git
```

3. Clone the repository:
```bash
git clone https://github.com/MrRobotDefuse/IPLocator.git
```

4. Navigate to the directory:
```bash
cd IPLocator
```
**Usage:**

Run the tool:
```bash
python iplocator.py
```

Enter the target IP address when prompted. The tool will gather and display all available information.

**Data Collected:**
- Country, region, city
- Precise coordinates
- Street address (when available)
- ISP and organization details
- Network information
- Local time in target location
- Open ports
- Abuse reports and threat score

**Notes:**
- The tool uses public data sources and web scraping techniques
- Some features depend on the availability of external services
- For educational purposes only

**License:**
MIT License - see LICENSE file for details
