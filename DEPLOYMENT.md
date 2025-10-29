# 🚀 Deployment Guide

## Local Development

### 1. Run the Web App Locally
```bash
# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the web app
streamlit run web_app.py
```

The app will be available at: http://localhost:8501

## Cloud Deployment Options

### Option 1: Streamlit Cloud (Recommended - Free)

1. **Push to GitHub** (already done ✅)
2. **Go to** [share.streamlit.io](https://share.streamlit.io)
3. **Sign in** with GitHub
4. **Deploy** from your repository: `Subhadra-Mishra-iub/log-tracker`
5. **Select** `web_app.py` as the main file
6. **Deploy!** 🎉

### Option 2: Heroku

1. **Install Heroku CLI**
2. **Login**: `heroku login`
3. **Create app**: `heroku create your-app-name`
4. **Deploy**: `git push heroku main`
5. **Open**: `heroku open`

### Option 3: Railway

1. **Go to** [railway.app](https://railway.app)
2. **Connect** GitHub repository
3. **Deploy** automatically

### Option 4: Render

1. **Go to** [render.com](https://render.com)
2. **Create** new Web Service
3. **Connect** GitHub repository
4. **Configure**:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `streamlit run web_app.py --server.port=$PORT --server.address=0.0.0.0`

## Environment Variables

For production deployment, you may want to set:

```bash
# Email configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
FROM_EMAIL=your-email@gmail.com
FROM_PASSWORD=your-app-password

# Streamlit configuration
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
```

## Performance Considerations

- **File Size Limit**: Streamlit has a 200MB file upload limit
- **Memory Usage**: Large log files may require more memory
- **Processing Time**: ML analysis can take time for very large files

## Security Notes

- **File Uploads**: Files are processed temporarily and deleted
- **Email Credentials**: Use app passwords, not regular passwords
- **HTTPS**: Always use HTTPS in production

## Monitoring

- **Logs**: Check application logs for errors
- **Performance**: Monitor memory and CPU usage
- **Alerts**: Set up monitoring for the deployed application
