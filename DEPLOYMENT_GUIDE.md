# 🚀 Complete Deployment Guide for Qylatrix

## Step 1: Push to GitHub

### 1.1 Configure Git (if not already done)
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 1.2 Commit Your Code
```bash
git add .
git commit -m "Initial commit: Qylatrix Platform"
```

### 1.3 Connect to Your Repository
```bash
git remote add origin https://github.com/Qylatrix/qylatrix.github.io.git
git branch -M main
```

### 1.4 Push to GitHub
```bash
git push -u origin main
```

**Note**: If your repository already has files, you might need to:
```bash
git pull origin main --allow-unrelated-histories
# Resolve any conflicts if they appear
git push -u origin main
```

---

## Step 2: Deploy to Render (Free Hosting)

### 2.1 Sign Up for Render
1. Go to [https://render.com](https://render.com)
2. Click **"Get Started"**
3. Sign up using your GitHub account (recommended)

### 2.2 Create a New Web Service
1. Click **"New +"** button in the top right
2. Select **"Web Service"**

### 2.3 Connect Your Repository
1. Click **"Connect account"** under GitHub
2. Authorize Render to access your repositories
3. Find and select **"Qylatrix/qylatrix.github.io"**
4. Click **"Connect"**

### 2.4 Configure Your Web Service
Fill in the following details:

- **Name**: `qylatrix` (or your preferred name)
- **Region**: Choose closest to your location
- **Branch**: `main`
- **Root Directory**: Leave blank
- **Runtime**: `Python 3`
- **Build Command**: 
  ```
  pip install -r requirements.txt
  ```
- **Start Command**: 
  ```
  gunicorn app:app --bind 0.0.0.0:$PORT
  ```
- **Plan**: Select **"Free"**

### 2.5 Environment Variables (Optional)
Click **"Advanced"** → **"Add Environment Variable"**

Add these if needed:
- `PYTHON_VERSION`: `3.11.0`
- `SECRET_KEY`: Generate a random secret key (for production security)

### 2.6 Deploy
1. Click **"Create Web Service"**
2. Wait 3-5 minutes for deployment
3. Your app will be live at: `https://qylatrix.onrender.com` (or your custom name)

---

## Step 3: Post-Deployment

### 3.1 Verify Everything Works
1. Open your deployed URL
2. Test registration and login
3. Check all features (Academy, CTF Labs, Tools)
4. Verify database persistence

### 3.2 Monitor Your App
- Go to Render Dashboard
- Click on your service
- View logs to monitor activity
- Check for any errors

### 3.3 Free Tier Limitations
⚠️ **Important**: Render's free tier:
- Spins down after 15 minutes of inactivity
- Takes 30-60 seconds to wake up on first request
- 750 hours/month free (plenty for testing)

To upgrade to paid (always-on): $7/month

---

## Step 4: Custom Domain (Optional)

### 4.1 Add Custom Domain in Render
1. Go to your service settings
2. Click **"Custom Domain"**
3. Add your domain (e.g., `qylatrix.com`)
4. Follow DNS configuration instructions

### 4.2 Update DNS Records
Add the CNAME record provided by Render to your domain registrar.

---

## Alternative Deployment Options

### Option A: Railway (Also Free)
1. Go to [railway.app](https://railway.app)
2. Sign in with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Railway auto-detects and deploys Flask apps

### Option B: PythonAnywhere (Free tier available)
1. Go to [pythonanywhere.com](https://www.pythonanywhere.com)
2. Create free account
3. Upload your code via Git
4. Configure WSGI file
5. More manual setup required

### Option C: Heroku ($5/month minimum)
1. Create Heroku account
2. Install Heroku CLI
3. Run:
   ```bash
   heroku create qylatrix
   git push heroku main
   ```

---

## Troubleshooting

### Database Issues
If database doesn't persist:
- Render free tier resets database on sleep
- Upgrade to paid tier for persistent storage
- Or use external database (PostgreSQL)

### Port Errors
Make sure your app.py uses:
```python
port = int(os.environ.get('PORT', 5000))
app.run(host='0.0.0.0', port=port)
```

### Module Not Found
- Check requirements.txt has all dependencies
- Rebuild on Render dashboard

---

## Files Required for Deployment

✅ **You have all these files**:
- `requirements.txt` - Python dependencies
- `Procfile` - Tells how to run the app
- `runtime.txt` - Python version
- `.gitignore` - Excludes unnecessary files
- `README.md` - Documentation

---

## Summary

1. **Push code to GitHub** ✓
2. **Deploy on Render (FREE)** ✓
3. **App goes live in 5 minutes** ✓
4. **Share your URL** ✓

Your platform will be accessible worldwide! 🌍

---

Need help? Check Render's documentation or feel free to ask!
