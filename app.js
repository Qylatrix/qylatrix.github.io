/**
 * 🛡️ SecureFolio - Pretam Saha
 * Cybersecurity Portfolio + Security Tools Platform
 */

// State management
let services = [];
let currentService = null;
let searchTimeout = null;

// DOM Elements
const servicesGrid = document.getElementById('services-grid');
const modalOverlay = document.getElementById('modal-overlay');
const modalTitle = document.getElementById('modal-title');
const modalBody = document.getElementById('modal-body');
const searchInput = document.getElementById('search-input');
const searchResults = document.getElementById('search-results');
const searchResultsBody = document.getElementById('search-results-body');
const scanTextarea = document.getElementById('scan-textarea');
const analyzeBtn = document.getElementById('analyze-btn');
const analysisResults = document.getElementById('analysis-results');

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    loadServices();
    setupEventListeners();
    setupNavigation();
    setupTabs();
    setupOnlineTools();
    initMatrixRain();
    initMouseTrail();
    initPreloader();
    initScrollProgress();
    initStatCounters();
    initScrollAnimations();
});

// ==================== PRELOADER ====================
function initPreloader() {
    const preloader = document.getElementById('preloader');
    if (!preloader) return;

    window.addEventListener('load', () => {
        setTimeout(() => {
            preloader.classList.add('hidden');
        }, 1800);
    });
}

// ==================== SCROLL PROGRESS BAR ====================
function initScrollProgress() {
    const progressBar = document.getElementById('scroll-progress');
    if (!progressBar) return;

    window.addEventListener('scroll', () => {
        const scrollTop = document.documentElement.scrollTop;
        const scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const progress = (scrollTop / scrollHeight) * 100;
        progressBar.style.width = progress + '%';
    });
}

// ==================== ANIMATED STAT COUNTERS ====================
function initStatCounters() {
    const statNumbers = document.querySelectorAll('.stat-number[data-count]');
    if (statNumbers.length === 0) return;

    const animateCounter = (element) => {
        const target = parseInt(element.getAttribute('data-count'));
        const duration = 2000;
        const step = target / (duration / 16);
        let current = 0;

        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            element.textContent = Math.floor(current);
        }, 16);
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.5 });

    statNumbers.forEach(stat => observer.observe(stat));
}

// ==================== SCROLL ANIMATIONS ====================
function initScrollAnimations() {
    const animatedElements = document.querySelectorAll('.service-premium-card, .stat-card-premium, .contact-card-premium');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 100);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.6s ease-out';
        observer.observe(el);
    });
}

// ==================== MATRIX RAIN ANIMATION ====================
function initMatrixRain() {
    const canvas = document.getElementById('matrix-rain');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Set canvas size
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Matrix characters (binary)
    const chars = '01';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);

    // Array to track y position of each column
    const drops = [];
    for (let i = 0; i < columns; i++) {
        drops[i] = Math.random() * -100;
    }

    // Colors for the rain (Electric Blue Branding)
    const colors = ['#00d4ff', '#0088ff', '#ffffff'];

    function draw() {
        // Semi-transparent black to create fade effect
        ctx.fillStyle = 'rgba(10, 14, 26, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = `${fontSize}px JetBrains Mono, monospace`;

        for (let i = 0; i < drops.length; i++) {
            // Random character
            const char = chars[Math.floor(Math.random() * chars.length)];

            // Random color with higher chance of green
            const colorIndex = Math.random() < 0.7 ? 0 : (Math.random() < 0.5 ? 1 : 2);
            ctx.fillStyle = colors[colorIndex];

            // Draw character
            const x = i * fontSize;
            const y = drops[i] * fontSize;
            ctx.fillText(char, x, y);

            // Reset drop when it reaches bottom or randomly
            if (y > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }

            // Move drop down
            drops[i] += 0.5 + Math.random() * 0.5;
        }
    }

    // Run animation
    setInterval(draw, 50);
}

// ==================== MOUSE TRAIL EFFECT ====================
function initMouseTrail() {
    const canvas = document.getElementById('mouse-trail');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    const particles = [];
    const maxParticles = 60;
    let mouseX = 0;
    let mouseY = 0;
    let isMouseMoving = false;
    let mouseTimeout;

    class Particle {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.size = Math.random() * 2 + 1;
            this.speedX = (Math.random() - 0.5) * 1;
            this.speedY = (Math.random() - 0.5) * 1;
        }
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            if (this.x > canvas.width || this.x < 0) this.speedX *= -1;
            if (this.y > canvas.height || this.y < 0) this.speedY *= -1;
            let dx = mouseX - this.x;
            let dy = mouseY - this.y;
            let distance = Math.sqrt(dx * dx + dy * dy);
            if (distance < 180) {
                this.x += dx * 0.01;
                this.y += dy * 0.01;
            }
        }
        draw() {
            ctx.fillStyle = 'rgba(0, 212, 255, 0.6)';
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
        }
    }

    for (let i = 0; i < maxParticles; i++) particles.push(new Particle());

    document.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        isMouseMoving = true;
        clearTimeout(mouseTimeout);
        mouseTimeout = setTimeout(() => isMouseMoving = false, 100);
    });

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (let i = 0; i < particles.length; i++) {
            particles[i].update();
            particles[i].draw();
            for (let j = i; j < particles.length; j++) {
                let dx = particles[i].x - particles[j].x;
                let dy = particles[i].y - particles[j].y;
                let dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 110) {
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 212, 255, ${1 - dist / 110})`;
                    ctx.lineWidth = 0.4;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }
            }
        }
        if (isMouseMoving) {
            ctx.beginPath();
            ctx.arc(mouseX, mouseY, 50, 0, Math.PI * 2);
            let grad = ctx.createRadialGradient(mouseX, mouseY, 0, mouseX, mouseY, 50);
            grad.addColorStop(0, 'rgba(0, 212, 255, 0.1)');
            grad.addColorStop(1, 'rgba(0, 212, 255, 0)');
            ctx.fillStyle = grad;
            ctx.fill();
        }
        requestAnimationFrame(animate);
    }
    animate();
}

// ==================== NAVIGATION ====================
function setupNavigation() {
    const navToggle = document.getElementById('nav-toggle');
    const navMenu = document.querySelector('.nav-menu');
    const menuOverlay = document.getElementById('menu-overlay');

    if (navToggle && navMenu && menuOverlay) {
        // Toggle menu
        navToggle.addEventListener('click', () => {
            navMenu.classList.toggle('active');
            menuOverlay.classList.toggle('active');
            document.body.style.overflow = navMenu.classList.contains('active') ? 'hidden' : '';
        });

        // Close menu when clicking overlay
        menuOverlay.addEventListener('click', () => {
            navMenu.classList.remove('active');
            menuOverlay.classList.remove('active');
            document.body.style.overflow = '';
        });
    }

    // Smooth scroll for nav links and close menu
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                if (navMenu) navMenu.classList.remove('active');
                if (menuOverlay) menuOverlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });

    // Navbar background on scroll
    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        if (window.scrollY > 100) {
            navbar.style.background = 'rgba(5, 8, 15, 0.98)';
        } else {
            navbar.style.background = 'rgba(5, 8, 15, 0.95)';
        }
    });
}

// ==================== TABS ====================
function setupTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;

            // Remove active from all
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Add active to clicked
            btn.classList.add('active');
            document.getElementById(`tab-${tabId}`).classList.add('active');
        });
    });
}

// ==================== SERVICES ====================
async function loadServices() {
    try {
        if (servicesGrid) {
            servicesGrid.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';
        }

        const response = await fetch('/api/services');
        services = await response.json();

        renderServices();
    } catch (error) {
        console.error('Error loading services:', error);
        if (servicesGrid) {
            servicesGrid.innerHTML = '<div class="no-results"><span>❌</span>Failed to load services</div>';
        }
    }
}

function renderServices() {
    if (!servicesGrid) return;

    if (services.length === 0) {
        servicesGrid.innerHTML = '<div class="no-results"><span>📭</span>No services available</div>';
        return;
    }

    servicesGrid.innerHTML = services.map(service => `
        <div class="service-card" data-service="${service.id}">
            <div class="service-card-header">
                <div class="service-icon">${service.icon}</div>
                <div class="service-info">
                    <h3>${service.name}</h3>
                    <div class="service-port">Port ${service.port}</div>
                </div>
            </div>
            <p class="service-description">${service.description}</p>
            <div class="service-stats">
                <div class="technique-count">
                    <span>🎯</span>
                    ${service.technique_count} Techniques
                </div>
                <button class="view-btn">View All →</button>
            </div>
        </div>
    `).join('');

    document.querySelectorAll('.service-card').forEach(card => {
        card.addEventListener('click', () => {
            const serviceId = card.dataset.service;
            openServiceModal(serviceId);
        });
    });
}

async function openServiceModal(serviceId) {
    try {
        const response = await fetch(`/api/service/${serviceId}`);
        const service = await response.json();

        if (service.error) {
            alert('Service not found');
            return;
        }

        currentService = service;

        modalTitle.innerHTML = `
            <span style="font-size: 1.5rem">${service.icon}</span>
            <div>
                <h2>${service.name}</h2>
                <div style="font-size: 0.8rem; color: var(--text-muted)">Port ${service.port || 'N/A'}</div>
            </div>
        `;

        modalBody.innerHTML = renderTechniques(service.techniques);
        setupTechniqueToggles();

        modalOverlay.classList.add('active');
        document.body.style.overflow = 'hidden';

    } catch (error) {
        console.error('Error loading service:', error);
        alert('Failed to load service details');
    }
}

function renderTechniques(techniques) {
    return techniques.map((technique, index) => `
        <div class="technique-card" data-technique="${technique.id}">
            <div class="technique-header">
                <div class="technique-info">
                    <div class="technique-number">${index + 1}</div>
                    <span class="technique-name">${technique.name}</span>
                </div>
                <div style="display: flex; align-items: center; gap: 0.75rem">
                    <span class="difficulty-badge ${technique.difficulty.toLowerCase()}">${technique.difficulty}</span>
                    <span class="expand-icon">▼</span>
                </div>
            </div>
            <div class="technique-content">
                <p class="technique-description">${technique.description}</p>
                
                ${technique.steps ? `
                <div class="steps-section">
                    <h4 class="steps-title">📋 Steps</h4>
                    <ul class="steps-list">
                        ${technique.steps.map(step => `<li>${step}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
                
                ${technique.commands ? `
                <div class="commands-section">
                    <h4 class="commands-title">⚡ Commands</h4>
                    ${technique.commands.map(cmd => `
                        <div class="command-block">
                            <div class="command-header">
                                <span class="command-tool">${cmd.tool}</span>
                                <button class="copy-btn" onclick="copyCommand(this, '${escapeHtml(cmd.command)}')">
                                    📋 Copy
                                </button>
                            </div>
                            <div class="command-code">${escapeHtml(cmd.command)}</div>
                            <div class="command-description">${cmd.description}</div>
                        </div>
                    `).join('')}
                </div>
                ` : ''}
                
                ${technique.tips ? `
                <div class="tips-section">
                    <h4 class="tips-title">💡 Pro Tips</h4>
                    <ul class="tips-list">
                        ${technique.tips.map(tip => `<li>${tip}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}
            </div>
        </div>
    `).join('');
}

function setupTechniqueToggles() {
    document.querySelectorAll('.technique-header').forEach(header => {
        header.addEventListener('click', () => {
            const card = header.closest('.technique-card');
            card.classList.toggle('expanded');
        });
    });
}

function copyCommand(btn, command) {
    const text = command.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

    navigator.clipboard.writeText(text).then(() => {
        btn.classList.add('copied');
        btn.innerHTML = '✅ Copied!';

        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = '📋 Copy';
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function closeModal() {
    modalOverlay.classList.remove('active');
    document.body.style.overflow = '';
    currentService = null;
}

// ==================== SEARCH ====================
async function performSearch(query) {
    if (!query || query.length < 2) {
        searchResults.classList.remove('active');
        return;
    }

    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        const results = await response.json();

        if (results.length === 0) {
            searchResultsBody.innerHTML = '<div class="no-results"><span>🔍</span>No techniques found</div>';
        } else {
            searchResultsBody.innerHTML = results.map(result => `
                <div class="search-result-item" data-service="${result.service_id}">
                    <span style="font-size: 1.5rem">${result.service_icon}</span>
                    <div style="flex: 1">
                        <strong>${result.technique.name}</strong>
                        <div style="font-size: 0.8rem; color: var(--text-muted)">${result.service_name}</div>
                    </div>
                    <span class="difficulty-badge ${result.technique.difficulty.toLowerCase()}">${result.technique.difficulty}</span>
                </div>
            `).join('');

            document.querySelectorAll('.search-result-item').forEach(item => {
                item.addEventListener('click', () => {
                    const serviceId = item.dataset.service;
                    openServiceModal(serviceId);
                    clearSearch();
                });
            });
        }

        searchResults.classList.add('active');

    } catch (error) {
        console.error('Search error:', error);
    }
}

function clearSearch() {
    if (searchInput) searchInput.value = '';
    if (searchResults) searchResults.classList.remove('active');
}

// ==================== SCAN ANALYZER ====================
async function analyzeScan() {
    const scanOutput = scanTextarea.value.trim();

    if (!scanOutput) {
        analysisResults.innerHTML = `
            <div class="results-placeholder">
                <span>⚠️</span>
                <p>Please paste your scan output first</p>
            </div>
        `;
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = 'Analyzing...';
    analysisResults.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_output: scanOutput })
        });

        const data = await response.json();

        if (data.detected_services.length === 0) {
            analysisResults.innerHTML = `
                <div class="results-placeholder">
                    <span>🤔</span>
                    <p>No known services detected in the scan output</p>
                </div>
            `;
        } else {
            analysisResults.innerHTML = `
                <div style="margin-bottom: 1rem">
                    <strong style="color: var(--accent-pink)">
                        🎯 ${data.detected_services.length} Services Detected
                    </strong>
                    <span style="color: var(--text-muted); font-size: 0.85rem">
                        (${data.total_techniques} techniques available)
                    </span>
                </div>
                ${data.detected_services.map(s => `
                    <div class="detected-service" onclick="openServiceModal('${s.service_id}')">
                        <div class="detected-service-info">
                            <span style="font-size: 1.25rem">${s.service_data.icon}</span>
                            <div>
                                <h4>${s.service_data.name}</h4>
                                <span>Port ${s.port}</span>
                            </div>
                        </div>
                        <div class="detected-techniques">
                            ${s.service_data.techniques.length} techniques →
                        </div>
                    </div>
                `).join('')}
            `;
        }

    } catch (error) {
        console.error('Analysis error:', error);
        analysisResults.innerHTML = `
            <div class="results-placeholder">
                <span>❌</span>
                <p>Analysis failed. Please try again.</p>
            </div>
        `;
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = '🔍 Analyze Scan';
    }
}

// ==================== ONLINE TOOLS ====================
function setupOnlineTools() {
    // CVE Search
    const cveSearchBtn = document.getElementById('cve-search-btn');
    const cveSearchInput = document.getElementById('cve-search-input');
    const cveResults = document.getElementById('cve-results');

    if (cveSearchBtn) {
        cveSearchBtn.addEventListener('click', async () => {
            const query = cveSearchInput.value.trim();
            if (!query) return;

            cveResults.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';

            try {
                const response = await fetch(`/api/cve/search?q=${encodeURIComponent(query)}`);
                const data = await response.json();

                if (data.error || !data.cves || data.cves.length === 0) {
                    cveResults.innerHTML = `
                        <div class="results-placeholder">
                            <span>🔍</span>
                            <p>No CVEs found for "${query}"</p>
                        </div>
                    `;
                } else {
                    cveResults.innerHTML = `
                        <div style="margin-bottom: 1rem; color: var(--text-muted)">
                            Found ${data.total} results (showing first ${data.cves.length})
                        </div>
                        ${data.cves.map(cve => `
                            <div class="cve-item">
                                <div class="cve-header">
                                    <span class="cve-id">${cve.id}</span>
                                    <span class="severity-badge ${cve.severity.toLowerCase()}">${cve.severity} (${cve.cvss})</span>
                                </div>
                                <p class="cve-description">${cve.description}</p>
                            </div>
                        `).join('')}
                    `;
                }
            } catch (error) {
                cveResults.innerHTML = `
                    <div class="results-placeholder">
                        <span>❌</span>
                        <p>Error searching CVEs. Check your connection.</p>
                    </div>
                `;
            }
        });

        cveSearchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') cveSearchBtn.click();
        });
    }

    // Payload Generator
    const generatePayloadBtn = document.getElementById('generate-payload-btn');
    const payloadResults = document.getElementById('payload-results');

    if (generatePayloadBtn) {
        generatePayloadBtn.addEventListener('click', async () => {
            const payloadType = document.getElementById('payload-type').value;
            const lhost = document.getElementById('payload-lhost').value;
            const lport = document.getElementById('payload-lport').value;

            payloadResults.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';

            try {
                const response = await fetch('/api/payload/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: payloadType, lhost, lport })
                });

                const data = await response.json();

                payloadResults.innerHTML = data.payloads.map(p => `
                    <div class="payload-item">
                        <div class="payload-header">
                            <span class="payload-name">${p.name}</span>
                            <button class="copy-btn" onclick="copyPayload(this, \`${p.payload.replace(/`/g, '\\`').replace(/\\/g, '\\\\')}\`)">📋 Copy</button>
                        </div>
                        <div class="payload-code">${escapeHtml(p.payload)}</div>
                    </div>
                `).join('');

            } catch (error) {
                payloadResults.innerHTML = `
                    <div class="results-placeholder">
                        <span>❌</span>
                        <p>Error generating payloads</p>
                    </div>
                `;
            }
        });
    }

    // Hash Identifier
    const identifyHashBtn = document.getElementById('identify-hash-btn');
    const hashResults = document.getElementById('hash-results');

    if (identifyHashBtn) {
        identifyHashBtn.addEventListener('click', async () => {
            const hashInput = document.getElementById('hash-input').value.trim();
            if (!hashInput) return;

            hashResults.innerHTML = '<div class="loading"><div class="loading-spinner"></div></div>';

            try {
                const response = await fetch('/api/hash/identify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hash: hashInput })
                });

                const data = await response.json();

                hashResults.innerHTML = `
                    <div style="margin-bottom: 1rem; color: var(--text-muted)">
                        Possible hash types for: <code style="color: var(--accent-blue)">${hashInput.substring(0, 32)}${hashInput.length > 32 ? '...' : ''}</code>
                    </div>
                    ${data.results.map(h => `
                        <div class="hash-item">
                            <span class="hash-name">${h.name}</span>
                            <div class="hash-codes">
                                <span>Hashcat: -m ${h.hashcat}</span>
                                <span>John: --format=${h.john}</span>
                            </div>
                        </div>
                    `).join('')}
                `;

            } catch (error) {
                hashResults.innerHTML = `
                    <div class="results-placeholder">
                        <span>❌</span>
                        <p>Error identifying hash</p>
                    </div>
                `;
            }
        });
    }
}

function copyPayload(btn, payload) {
    navigator.clipboard.writeText(payload).then(() => {
        btn.classList.add('copied');
        btn.innerHTML = '✅ Copied!';
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = '📋 Copy';
        }, 2000);
    });
}

// Encoder/Decoder
async function encodeText(operation) {
    const input = document.getElementById('encoder-input').value;
    const output = document.getElementById('encoder-output');

    if (!input) return;

    try {
        const response = await fetch('/api/decode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: input, operation })
        });

        const data = await response.json();
        output.value = data.result;

    } catch (error) {
        output.value = 'Error: ' + error.message;
    }
}

function copyOutput() {
    const output = document.getElementById('encoder-output');
    output.select();
    document.execCommand('copy');
    alert('Copied to clipboard!');
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    // Modal close
    const closeBtn = document.querySelector('.close-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeModal);
    }

    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) closeModal();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && modalOverlay && modalOverlay.classList.contains('active')) {
            closeModal();
        }
    });

    // Search
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                performSearch(e.target.value.trim());
            }, 300);
        });
    }

    // Clear search
    const clearSearchBtn = document.querySelector('.clear-search');
    if (clearSearchBtn) {
        clearSearchBtn.addEventListener('click', clearSearch);
    }

    // Analyze button
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', analyzeScan);
    }

    // Contact form
    const contactForm = document.getElementById('contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Thank you for your message! I will get back to you soon.');
            contactForm.reset();
        });
    }
}
