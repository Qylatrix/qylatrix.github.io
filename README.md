# Qylatrix - Comprehensive Cybersecurity Learning Platform

🔥 **Live Platform**: [Coming Soon]

## 🌟 Features

- **Interactive Learning Academy** - Learn cybersecurity from basics to advanced
- **CTF Practice Labs** - Hands-on challenges with scoring system
- **Tools Reference** - Comprehensive penetration testing toolkit
- **User Progress Tracking** - Track your learning journey
- **CVE & Exploit Search** - Real-time vulnerability database access
- **Payload Generator** - Generate various payloads for testing

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- pip

### Local Installation

1. **Clone the repository**
```bash
git clone https://github.com/Qylatrix/qylatrix.github.io.git
cd qylatrix.github.io
```

2. **Create virtual environment**
```bash
python -m venv .venv
```

3. **Activate virtual environment**
- Windows: `.venv\Scripts\activate`
- Linux/Mac: `source .venv/bin/activate`

4. **Install dependencies**
```bash
pip install -r requirements.txt
```

5. **Run the application**
```bash
python app.py
```

6. **Access the platform**
Open your browser and go to `http://localhost:5000`

## 📁 Project Structure

```
qylatrix/
├── app.py                 # Main Flask application
├── database.py            # Database management
├── learning_content.py    # Learning modules content
├── requirements.txt       # Python dependencies
├── knowledge_base/        # Cybersecurity knowledge files
├── static/
│   ├── css/              # Stylesheets
│   └── js/               # JavaScript files
└── templates/            # HTML templates
```

## 🌐 Deployment

This application can be deployed on:
- **Render** (Recommended - Free tier available)
- **Railway**
- **PythonAnywhere**
- **Heroku**

### Deploy to Render (Free)

1. Push your code to GitHub
2. Go to [render.com](https://render.com) and sign up
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Configure:
   - **Name**: qylatrix
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
6. Click "Create Web Service"

Your app will be live in minutes! 🎉

## 🔒 Security Notice

⚠️ **IMPORTANT**: This platform is designed for **educational purposes** and **authorized security testing only**. Unauthorized access to computer systems is illegal.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

## 📄 License

This project is for educational purposes only.

## 📧 Contact

- **GitHub**: [@Qylatrix](https://github.com/Qylatrix)
- **LinkedIn**: [Qylatrix](https://linkedin.com/company/qylatrix)

---

**Built with ❤️ by the Qylatrix Team**
