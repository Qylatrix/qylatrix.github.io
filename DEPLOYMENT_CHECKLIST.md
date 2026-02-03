# 📋 Deployment Checklist

## ✅ Files to Upload to GitHub

### Essential Files (Must Have):
- ✅ `app.py` - Main application
- ✅ `database.py` - Database functions
- ✅ `learning_content.py` - Learning modules
- ✅ `requirements.txt` - Dependencies
- ✅ `Procfile` - Deployment configuration
- ✅ `runtime.txt` - Python version
- ✅ `.gitignore` - Files to exclude
- ✅ `README.md` - Project documentation

### Folders to Upload:
- ✅ `templates/` - All HTML files
- ✅ `static/` - CSS, JS, images
- ✅ `knowledge_base/` - JSON knowledge files

### Files NOT to Upload (Already in .gitignore):
- ❌ `.venv/` - Virtual environment
- ❌ `users.db` - Database file (will be created fresh)
- ❌ `__pycache__/` - Python cache
- ❌ `.vscode/` - IDE settings

---

## 🚀 Deployment Steps

### Step 1: Push to GitHub
```bash
# Configure git (one-time)
git config --global user.name "Your Name"
git config --global user.email "your@email.com"

# Commit and push
git add .
git commit -m "Deploy Qylatrix platform"
git remote add origin https://github.com/Qylatrix/qylatrix.github.io.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy on Render.com
1. Go to https://render.com
2. Sign in with GitHub
3. New + → Web Service
4. Select your repository
5. Configure:
   - Name: `qylatrix`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   - Plan: Free
6. Click "Create Web Service"
7. Wait 3-5 minutes ⏱️
8. Your site is LIVE! 🎉

---

## 📁 What Each File Does

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application with all routes |
| `database.py` | User authentication & progress tracking |
| `learning_content.py` | Cybersecurity learning modules |
| `requirements.txt` | Python packages needed |
| `Procfile` | Tells hosting how to run your app |
| `runtime.txt` | Specifies Python version |
| `.gitignore` | Excludes unnecessary files from Git |
| `README.md` | Documentation for users |

---

## 🎯 After Deployment

### Test These Features:
- [ ] Homepage loads
- [ ] Register new account
- [ ] Login works
- [ ] Dashboard shows modules
- [ ] Learning modules load
- [ ] CTF Labs work
- [ ] Tools page displays
- [ ] Theme switcher works
- [ ] Mobile responsive design

### Share Your Platform:
- 🌐 Your URL: `https://qylatrix.onrender.com`
- 📱 Share on social media
- 💼 Add to LinkedIn
- 👨‍💻 Add to your resume/portfolio

---

## ⚠️ Important Notes

1. **Free Tier Sleep**: App sleeps after 15 min inactivity
   - First request takes 30-60 seconds to wake
   - This is normal for free tier

2. **Database Resets**: On free tier, database may reset
   - Upgrade to $7/month for persistence
   - Or use external PostgreSQL database

3. **Secret Key**: For production, change the secret key in `app.py`:
   ```python
   app.config['SECRET_KEY'] = 'your-super-secret-key-here'
   ```

---

## 🆘 Troubleshooting

### Build Failed?
- Check all files are committed
- Verify requirements.txt exists
- Check Python version compatibility

### App Not Starting?
- Check Render logs
- Verify Procfile exists
- Ensure gunicorn is in requirements.txt

### Database Errors?
- Database file will be created automatically
- On first deploy, no users exist (need to register)

---

## 🎉 Success Criteria

✅ Code pushed to GitHub  
✅ Render deployment successful  
✅ Can access your live URL  
✅ Can register and login  
✅ All features working  

**Congratulations! Your platform is LIVE! 🚀**
