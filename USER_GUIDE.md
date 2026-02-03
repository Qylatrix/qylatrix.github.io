# 🎓 User Guide - CyberSec Learning Platform

## Quick Start Guide

### 1️⃣ First Time Setup

**Step 1: Register an Account**
- Navigate to: `http://localhost:5000`
- You'll be redirected to the login page
- Click "Register here" link
- Fill in your details:
  - Full Name
  - Username (unique)
  - Email address
  - Strong password (watch the strength indicator)
- Click "Create Account"
- You'll be redirected to login

**Step 2: Login**
- Enter your username and password
- Click "Login"
- You'll be taken to your personalized dashboard

### 2️⃣ Using the Dashboard

**Understanding Your Stats**
- ✅ **Lessons Completed**: Total number of lessons you've finished
- 🏆 **Achievements**: Badges earned for milestones
- ⏱️ **Minutes Learned**: Total time spent on lessons
- 🔥 **Overall Progress**: Your completion percentage

**Choosing a Learning Path**

🌱 **Beginner Level (Green)**
- Start here if you're new to cybersecurity
- 4 foundational lessons
- ~75 minutes total
- Topics: Basics, Networking, Linux, Passwords

⚡ **Intermediate Level (Orange)**
- For those with basic knowledge
- 5 practical lessons
- ~170 minutes total
- Topics: Scanning, Web Hacking, Exploitation

🚀 **Advanced Level (Red)**
- For experienced professionals
- 6 expert-level lessons
- ~265 minutes total
- Topics: Binary Exploitation, AD, Red Teaming

### 3️⃣ Taking Lessons

**Starting a Module**
1. Click "Start Learning" on any module card
2. You'll see the module overview with all lessons
3. Each lesson shows:
   - Lesson number and title
   - Duration estimate
   - Key topics covered

**Completing a Lesson**
1. Click on any lesson to start
2. Read through the content
3. Study code examples and commands
4. Practice in your own lab environment
5. Click "Mark as Complete" button at the bottom
6. Confirm to return to dashboard or continue

**Progress Tracking**
- Your progress is automatically saved
- Return anytime to continue where you left off
- All completed lessons are marked
- Stats update in real-time

### 4️⃣ Navigation Tips

**Top Navigation Bar**
- 📚 **Dashboard**: Return to main dashboard
- 🛠️ **Tools**: Access pentesting tools reference
- **User Avatar**: Shows your username initial
- **Logout**: Sign out of your account

**Back Buttons**
- Each lesson and module page has "← Back to Dashboard"
- Quick navigation to return home

**Footer Links**
- **GitHub**: Opens https://github.com/Qylatrix in new tab
- **LinkedIn**: Professional networking (new tab)

### 5️⃣ Learning Tips

**Best Practices**
1. **Follow the Order**: Complete lessons in sequence within each level
2. **Practice Hands-On**: Try commands in a safe lab environment
3. **Take Notes**: Use your favorite note-taking app alongside lessons
4. **Mark Complete Only When Done**: Be honest with your progress
5. **Review Regularly**: Revisit completed lessons to reinforce learning

**Recommended Learning Schedule**
- **Daily**: 30-60 minutes per day
- **Weekly**: Complete 2-3 lessons
- **Monthly Goal**: Finish one complete module

**Lab Environment Setup**
- Install VirtualBox or VMware
- Download Kali Linux
- Set up vulnerable VMs (Metasploitable, DVWA)
- Practice in isolated networks only!

### 6️⃣ Content Overview

**Beginner Module (4 lessons)**
```
1. Introduction to Cybersecurity (15 min)
   - CIA Triad, threat types, career paths

2. Networking Fundamentals (20 min)
   - OSI Model, TCP/IP, common ports

3. Linux Command Line Basics (25 min)
   - Essential commands, file permissions

4. Password Security & Hashing (15 min)
   - Best practices, hash types, cracking basics
```

**Intermediate Module (5 lessons)**
```
5. Reconnaissance & Information Gathering (30 min)
   - OSINT, passive/active recon

6. Network Scanning with Nmap (35 min)
   - Scan types, service detection, evasion

7. Web Application Vulnerabilities (40 min)
   - OWASP Top 10, SQL injection, XSS

8. Web Testing with Burp Suite (30 min)
   - Proxy, Repeater, Intruder, Scanner

9. Exploitation with Metasploit (35 min)
   - Framework basics, meterpreter, modules
```

**Advanced Module (6 lessons)**
```
10. Buffer Overflow Exploitation (45 min)
    - Stack overflows, shellcode, ROP

11. Active Directory Exploitation (50 min)
    - Kerberoasting, Pass-the-Hash, BloodHound

12. Privilege Escalation Techniques (40 min)
    - Linux & Windows privesc, kernel exploits

13. Wireless Network Security (35 min)
    - WPA2 cracking, evil twin attacks

14. Red Team Operations (55 min)
    - C2 frameworks, evasion, persistence

15. Threat Hunting & Detection (40 min)
    - Log analysis, SIEM, MITRE ATT&CK
```

### 7️⃣ Features in Each Lesson

**What You'll Find**
- 📋 **Topics Overview**: Key concepts covered
- 📝 **Detailed Content**: Explanations and theory
- 💻 **Code Examples**: Syntax-highlighted commands
- 📚 **Lists & Steps**: Organized learning
- ✓ **Completion Button**: Track your progress

**Code Blocks**
All commands are formatted for easy copying:
```
Example:
nmap -sV -sC 192.168.1.1
```

### 8️⃣ Social Features

**Connect with the Community**
- **GitHub**: View source code and contribute
- **LinkedIn**: Professional networking
- Links in footer of every page
- All links open in new tabs for convenience

### 9️⃣ Security & Privacy

**Your Data**
- Passwords are hashed with SHA-256
- Session-based authentication
- SQLite database stored locally
- No external data sharing

**Account Management**
- Create unique strong passwords
- Keep credentials secure
- Logout when finished
- Account created timestamp tracked

### 🔟 Troubleshooting

**Can't Login?**
- Verify username and password
- Usernames are case-sensitive
- Try registering if account doesn't exist

**Progress Not Saving?**
- Ensure you click "Mark as Complete"
- Check browser console for errors
- Refresh the page

**Page Not Loading?**
- Verify server is running: `python app.py`
- Check: http://localhost:5000
- Clear browser cache

**Forgot Password?**
- Currently no password reset feature
- Contact administrator or create new account

### 📚 Additional Resources

**Recommended Tools**
- Kali Linux (primary OS)
- Burp Suite Community
- Wireshark
- John the Ripper
- Metasploit Framework

**Practice Platforms**  
- HackTheBox
- TryHackMe
- VulnHub
- PentesterLab
- OverTheWire

**Certifications Aligned**
- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security CP)
- PNPT (Practical Network Penetration Tester)
- CompTIA Security+
- eJPT (Junior Penetration Tester)

### ⚠️ Important Reminders

**Legal & Ethical Use**
- ✅ Practice in authorized environments only
- ✅ Use virtual labs and CTF platforms
- ✅ Obtain written permission before testing
- ❌ Never test on systems you don't own
- ❌ Unauthorized access is illegal

**Learning Mindset**
- Be patient with yourself
- Security is a journey, not a destination
- Ask questions and research
- Join cybersecurity communities
- Stay updated with latest threats

### 🎯 Goals & Milestones

**Beginner Achievement**: Complete all beginner lessons
**Intermediate Achievement**: Finish 5/5 intermediate lessons
**Advanced Achievement**: Master all 6 advanced lessons
**Perfect Score**: 15/15 lessons completed

### 📞 Support

For issues or questions:
- Check the README.md file
- Review this user guide
- Visit GitHub: https://github.com/Qylatrix

---

**Happy Learning! 🚀**

Remember: "The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards." - Gene Spafford

Practice safely, learn ethically, hack responsibly! 🔒
