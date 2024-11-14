# CHUD - Cybernetic Hacking Utility Daemon

**Enter the shadows.** CHUD is a formidable network reconnaissance tool crafted for those who dare to traverse the treacherous landscape of cybersecurity. Designed for the relentless hackers and cyber warriors, this tool empowers you to unearth the hidden secrets lurking within the digital abyss.


 ``` 
   ▄████▄   ██░ ██  █    ██ ▓█████▄ 
  ▒██▀ ▀█  ▓██░ ██▒ ██  ▓██▒▒██▀ ██▌
  ▒▓█    ▄ ▒██▀▀██░▓██  ▒██░░██   █▌
  ▒▓▓▄ ▄██▒░▓█ ░██ ▓▓█  ░██░░▓█▄   ▌
  ▒ ▓███▀ ░░▓█▒░██▓▒▒█████▓ ░▒████▓ 
  ░ ░▒ ▒  ░ ▒ ░░▒░▒░▒▓▒ ▒ ▒  ▒▒▓  ▒ 
    ░  ▒    ▒ ░▒░ ░░░▒░ ░ ░  ░ ▒  ▒ 
  ░         ░  ░░ ░ ░░░ ░ ░  ░ ░  ░ 
  ░ ░       ░  ░  ░   ░        ░
  ░                           ░
 ``` 


## Features
- **Port Scanning**: Expose the gaping vulnerabilities hidden in the shadows.
- **OS Detection**: Identify the operating systems that power your unsuspecting prey.
- **Service Version Detection**: Uncover the secrets of services running in the dark.
- **WHOIS Lookup**: Delve into the ownership details of domains shrouded in mystery.
- **DNS Enumeration**: Explore the DNS landscape for concealed resources.
- **Traceroute**: Map the twisted paths your packets traverse through the digital wasteland.
- **Ping Sweep**: Identify the living hosts that breathe in the network's underbelly.
- **Reverse DNS Lookup**: Transform IP addresses back into the shadows from whence they came.
- **Geolocation with Map Visualization**: Pinpoint the physical locations of your targets, revealing their hidden lairs.
- **Banner Grabbing**: Extract sensitive information from services, learning their darkest secrets.
- **SSL Certificate Scanning**: Evaluate the security of SSL certificates, exposing weaknesses.
- **HTTP Header Analysis**: Analyze HTTP headers for vulnerabilities and insights that could spell doom.
- **Shodan Integration**: Tap into the dark web of IoT devices, where chaos reigns.
- **Subdomain Enumeration**: Discover hidden subdomains lurking in the shadows, waiting to be exploited.
- **DDoS Testing (for authorized testing only)**: Test your defenses against the impending storm.

## Installation
**Warning:** **Sudo privileges are required to wield this tool. Ensure you possess the necessary administrative access to your system.**

1. Clone the repository:


 ``` bash
   git clone https://github.com/packetsn1ffer/chud.git
   cd chud
 ``` 


2. Create a virtual environment:


 ``` bash
   python -m venv venv
   source venv/bin/activate  # On Windows use venv\Scripts\activate
 ``` 


3. Install the required packages:


 ``` bash
   pip install -r requirements.txt
 ``` 


4. Install Nmap and Amass on your system:
   - For Windows: Use the official installers or package managers like Chocolatey.
   - For macOS: `brew install nmap amass`
   - For Linux: Use your distribution's package manager (e.g., `apt install nmap amass` for Ubuntu).

5. Download the GeoLite2-City database from MaxMind and update the path in the `perform_geolocation` function.

## Usage
Run the script with elevated privileges:


 ``` bash
sudo python chud.py
 ``` 


Follow the on-screen prompts to configure your scan and navigate the treacherous digital landscape.

## Disclaimer
**Use this tool with caution, and only on systems you have explicit permission to invade. The authors and developers of CHUD expressly disclaim all liability for any misuse, damage, or legal repercussions that may arise from wielding this tool. By using CHUD, you acknowledge that you are solely responsible for your actions and that you will comply with all applicable laws and regulations. Unauthorized use of this tool is forbidden and may lead to dire consequences. The cyber realm is a wild frontier; tread carefully, for the darkness is always watching.**

## License
[MIT License](LICENSE)