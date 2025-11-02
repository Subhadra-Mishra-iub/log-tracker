# 🚀 Quick Start Guide

## How It Works - Step by Step

### 1. **Upload Your Log File**
- Go to the web interface
- Click "Choose a log file" in the sidebar
- Upload any `.log` or `.txt` file with standard log format

### 2. **Automatic Analysis**
The system will:
- ✅ Parse your log file (extract timestamp, level, service, message)
- ✅ Extract features (message length, keywords, patterns)
- ✅ Run ML detection (Isolation Forest algorithm)
- ✅ Run pattern detection (rule-based for known issues)
- ✅ Generate visualizations and reports

### 3. **View Results**
- **Dashboard**: Interactive charts and metrics
- **Anomalies**: Detailed anomaly analysis with filtering
- **Analytics**: Time-based and statistical analysis
- **Raw Data**: Browse the original log data

### 4. **Download Reports**
- **CSV Report**: Detailed anomaly data
- **Alert Summary**: Text summary of critical issues

## 🌐 Web Interface Features

### **Upload & Configure**
- Drag & drop file upload
- Email alerts (optional)
- Analysis options (ML/Pattern detection)
- Sample data for testing

### **Interactive Dashboard**
- 📊 Log level distribution (pie chart)
- 🚨 Anomaly breakdown (bar chart)
- 🔧 Service activity (horizontal bar chart)
- ⏰ Time-based analysis (line chart)

### **Smart Filtering**
- Filter by anomaly type
- Filter by service
- Show anomalies only
- Adjust number of rows displayed

## 🎯 Supported Log Formats

### **Standard Format** (Recommended)
```
2024-01-15 10:30:15 INFO [UserService] User login successful: user_id=12345
2024-01-15 10:30:16 ERROR [DatabaseService] Connection timeout after 30s
2024-01-15 10:30:17 WARN [CacheService] High memory usage detected: 95%
```

### **Alternative Formats**
- Any format with timestamp, level, and message
- The system will attempt to parse and extract features

## 🚀 Deployment Options

### **Option 1: Streamlit Cloud (Easiest)**
1. Go to [share.streamlit.io](https://share.streamlit.io)
2. Sign in with GitHub
3. Deploy from `Subhadra-Mishra-iub/log-tracker`
4. Select `web_app.py` as main file
5. Deploy! 🎉

### **Option 2: Local Development**
```bash
# Clone repository
git clone https://github.com/Subhadra-Mishra-iub/log-tracker.git
cd log-tracker

# Setup environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run web app
streamlit run web_app.py
```

### **Option 3: Command Line**
```bash
# Analyze specific log file
python log_analyzer.py --log-file your_log_file.log

# With email alerts
python log_analyzer.py --log-file your_log_file.log --email your@email.com
```

## 📊 Sample Results

When you upload a log file, you'll see:

```
🔍 ANOMALY DETECTION SUMMARY
==================================================
📊 Total log entries scanned: 15,000
❗ Anomalies detected: 10,179
📈 Anomaly rate: 67.86%

📋 ANOMALY BREAKDOWN:
  • ERROR_LEVEL: 5,882
  • ML_DETECTED: 1,497
  • DATABASE_CONNECTION_ISSUE: 1,160
  • AUTH_FAILURE: 1,067
  • CRITICAL_RESOURCE_USAGE: 397
  • SLOW_QUERY: 176
```

## 🎯 Use Cases

### **SRE/DevOps Teams**
- Monitor application logs in real-time
- Detect issues before they impact users
- Generate automated alerts for critical problems

### **QA Teams**
- Analyze test logs for failures
- Identify patterns in test failures
- Generate reports for development teams

### **Data Teams**
- Analyze log patterns and trends
- Extract insights from system behavior
- Create dashboards for stakeholders

## 🔧 Customization

### **Add Custom Detection Rules**
```python
def detect_custom_anomalies(self):
    for log in self.logs_data:
        if 'your_custom_pattern' in log['message']:
            self.anomalies.append({
                'anomaly_type': 'CUSTOM_ISSUE',
                'confidence': 'High',
                # ... other fields
            })
```

### **Configure Email Alerts**
```python
email_config = {
    'from_email': 'alerts@yourcompany.com',
    'to_email': 'ops-team@yourcompany.com',
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'password': 'your_app_password'
}
```

## 🆘 Troubleshooting

### **Common Issues**
- **File too large**: Split into smaller files (200MB limit)
- **Parsing errors**: Check log format matches standard format
- **Memory issues**: Use smaller log files or increase memory

### **Performance Tips**
- Use pattern detection only for faster processing
- Process logs in batches for very large files
- Monitor memory usage during analysis

## 📞 Support

- **GitHub Issues**: [Create an issue](https://github.com/Subhadra-Mishra-iub/log-tracker/issues)
- **Email**: subhadramishrag@gmail.com
- **Documentation**: Check README.md for detailed information

---

**Ready to get started?** 🚀 Upload your first log file and see the magic happen!

