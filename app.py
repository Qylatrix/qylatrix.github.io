"""
🔥 Qylatrix - Comprehensive Cybersecurity Platform
For educational and authorized testing only!
"""

from flask import (
    Flask, render_template, jsonify, request,
    session, redirect, url_for, flash
)
import json
import os
import ssl
import urllib.request
import urllib.parse
from functools import wraps

import database
import learning_content

# -----------------------------------------------------------------------------
# App setup
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'pentest-agent-secret-key-2024'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KB_DIR = os.path.join(BASE_DIR, 'knowledge_base')

# -----------------------------------------------------------------------------
# SSL context (for external APIs)
# -----------------------------------------------------------------------------
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# -----------------------------------------------------------------------------
# Utility functions
# -----------------------------------------------------------------------------
def load_all_services():
    services = {}
    if os.path.exists(KB_DIR):
        for filename in os.listdir(KB_DIR):
            if filename.endswith('.json'):
                path = os.path.join(KB_DIR, filename)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        services[filename.replace('.json', '')] = json.load(f)
                except Exception as e:
                    print(f"Error loading {filename}: {e}")
    return services


def get_service(service_name):
    path = os.path.join(KB_DIR, f'{service_name}.json')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


# -----------------------------------------------------------------------------
# Database init
# -----------------------------------------------------------------------------
database.init_db()

# -----------------------------------------------------------------------------
# Auth helper
# -----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/academy')
def academy():
    return redirect(url_for('dashboard')) if 'user_id' in session else redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        result = database.create_user(
            data.get('username'),
            data.get('email'),
            data.get('password'),
            data.get('full_name', '')
        )
        return jsonify(result), (200 if result['success'] else 400)
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        user = database.verify_user(data.get('username'), data.get('password'))
        if not user:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

        session['user_id'] = user['id']
        session['username'] = user['username']
        return jsonify({'success': True, 'redirect': url_for('dashboard')})

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template(
        'dashboard.html',
        user=database.get_user_by_id(session['user_id']),
        progress=database.get_user_progress(session['user_id']),
        stats=database.get_user_stats(session['user_id']),
        modules=learning_content.get_all_modules()
    )


@app.route('/tools')
@login_required
def tools():
    return render_template('tools.html')


@app.route('/team')
def team():
    return render_template('team.html')


@app.route('/ctf-labs')
@login_required
def ctf_labs():
    return render_template('ctf_labs.html')


# =============================================================================
# API ROUTES
# =============================================================================

@app.route('/api/services')
def api_services():
    services = load_all_services()
    return jsonify([
        {
            'id': k,
            'name': v.get('name', k),
            'port': v.get('port', 'N/A'),
            'description': v.get('description', ''),
            'icon': v.get('icon', '🔧'),
            'category': v.get('category', 'services'),
            'technique_count': len(v.get('techniques', []))
        }
        for k, v in services.items()
    ])


@app.route('/api/service/<service_id>')
def api_service_detail(service_id):
    service = get_service(service_id)
    return jsonify(service) if service else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/search')
def api_search():
    q = request.args.get('q', '').lower()
    if not q:
        return jsonify([])

    results = []
    for sid, service in load_all_services().items():
        for tech in service.get('techniques', []):
            if q in json.dumps(tech).lower():
                results.append({'service_id': sid, 'technique': tech})

    return jsonify(results[:20])


@app.route('/api/cve/search')
def api_cve_search():
    q = request.args.get('q')
    if not q:
        return jsonify({'error': 'Query required'}), 400

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(q)}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Qylatrix/1.0'})
        with urllib.request.urlopen(req, context=ssl_context, timeout=10) as r:
            return jsonify(json.loads(r.read()))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# ENTRY POINT (LOCAL ONLY)
# =============================================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
