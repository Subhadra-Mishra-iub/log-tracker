#!/usr/bin/env python3
"""
Log Anomaly Checker - ML and pattern-based detection
"""

import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings
warnings.filterwarnings('ignore')

class LogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.logs_data = []
        self.anomalies = []
        self.stats = {}
        
    def parse_logs(self):
        print("📖 Parsing log file...")
        
        log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\w+) \[(\w+)\] (.+)'
        
        with open(self.log_file_path, 'r') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line:
                    continue
                    
                match = re.match(log_pattern, line)
                if match:
                    timestamp, level, service, message = match.groups()
                    
                    log_entry = {
                        'line_number': line_num,
                        'timestamp': datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S'),
                        'level': level,
                        'service': service,
                        'message': message,
                        'raw_line': line
                    }
                    
                    log_entry.update(self._extract_features(message))
                    self.logs_data.append(log_entry)
                else:
                    self.logs_data.append({
                        'line_number': line_num,
                        'timestamp': None,
                        'level': 'UNKNOWN',
                        'service': 'UNKNOWN',
                        'message': line,
                        'raw_line': line,
                        'is_malformed': True
                    })
        
        print(f"✅ Parsed {len(self.logs_data)} log entries")
        return self.logs_data
    
    def _extract_features(self, message):
        features = {
            'has_error_keywords': any(keyword in message.lower() for keyword in 
                                    ['error', 'failed', 'timeout', 'deadlock', 'exhausted', 'lost']),
            'has_warning_keywords': any(keyword in message.lower() for keyword in 
                                      ['warn', 'slow', 'miss', 'eviction', 'high', 'critical']),
            'has_success_keywords': any(keyword in message.lower() for keyword in 
                                      ['successful', 'hit', 'loaded', 'executed']),
            'message_length': len(message),
            'word_count': len(message.split()),
            'has_numbers': bool(re.search(r'\d+', message)),
            'has_urls': bool(re.search(r'http[s]?://', message)),
            'has_ips': bool(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', message)),
            'has_user_id': 'user_id=' in message,
            'has_execution_time': 'execution time' in message or 's execution' in message,
            'has_percentage': '%' in message,
            'has_memory_usage': 'memory usage' in message.lower(),
            'has_cpu_usage': 'cpu usage' in message.lower()
        }
        
        time_match = re.search(r'(\d+\.?\d*)s execution time', message)
        features['execution_time'] = float(time_match.group(1)) if time_match else 0
        
        pct_match = re.search(r'(\d+)%', message)
        features['percentage_value'] = int(pct_match.group(1)) if pct_match else 0
        
        return features
    
    def detect_anomalies_ml(self):
        print("🤖 Running ML anomaly detection...")
        
        if not self.logs_data:
            return []
        
        df = pd.DataFrame(self.logs_data)
        
        feature_columns = [
            'has_error_keywords', 'has_warning_keywords', 'has_success_keywords',
            'message_length', 'word_count', 'has_numbers', 'has_urls', 'has_ips',
            'has_user_id', 'has_execution_time', 'has_percentage', 'has_memory_usage',
            'has_cpu_usage', 'execution_time', 'percentage_value'
        ]
        
        for col in feature_columns:
            if col in df.columns:
                df[col] = df[col].fillna(0)
        
        X = df[feature_columns].values
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomaly_labels = iso_forest.fit_predict(X_scaled)
        
        for i, (idx, row) in enumerate(df.iterrows()):
            if anomaly_labels[i] == -1:
                self.anomalies.append({
                    'line_number': row['line_number'],
                    'timestamp': row['timestamp'],
                    'level': row['level'],
                    'service': row['service'],
                    'message': row['message'],
                    'anomaly_type': 'ML_DETECTED',
                    'confidence': 'High',
                    'raw_line': row['raw_line']
                })
        
        return self.anomalies
    
    def detect_anomalies_patterns(self):
        print("🔍 Running pattern-based anomaly detection...")
        
        pattern_anomalies = []
        
        for log in self.logs_data:
            if log.get('is_malformed'):
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'MALFORMED_LOG',
                    'confidence': 'High',
                    'raw_line': log['raw_line']
                })
                continue
            
            if log['level'] == 'ERROR':
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'ERROR_LEVEL',
                    'confidence': 'High',
                    'raw_line': log['raw_line']
                })
            
            if log.get('percentage_value', 0) > 90:
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'CRITICAL_RESOURCE_USAGE',
                    'confidence': 'High',
                    'raw_line': log['raw_line']
                })
            
            if log.get('execution_time', 0) > 3.0:
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'SLOW_QUERY',
                    'confidence': 'Medium',
                    'raw_line': log['raw_line']
                })
            
            if any(keyword in log['message'].lower() for keyword in 
                   ['connection timeout', 'connection pool exhausted', 'connection lost']):
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'DATABASE_CONNECTION_ISSUE',
                    'confidence': 'High',
                    'raw_line': log['raw_line']
                })
            
            if any(keyword in log['message'].lower() for keyword in 
                   ['invalid token', 'token expired', 'authentication failed']):
                pattern_anomalies.append({
                    'line_number': log['line_number'],
                    'timestamp': log['timestamp'],
                    'level': log['level'],
                    'service': log['service'],
                    'message': log['message'],
                    'anomaly_type': 'AUTH_FAILURE',
                    'confidence': 'High',
                    'raw_line': log['raw_line']
                })
        
        self.anomalies.extend(pattern_anomalies)
        return pattern_anomalies
    
    def calculate_statistics(self):
        print("📊 Calculating statistics...")
        
        if not self.logs_data:
            return {}
        
        df = pd.DataFrame(self.logs_data)
        
        self.stats = {
            'total_entries': len(self.logs_data),
            'info_count': len(df[df['level'] == 'INFO']),
            'warn_count': len(df[df['level'] == 'WARN']),
            'error_count': len(df[df['level'] == 'ERROR']),
            'unknown_count': len(df[df['level'] == 'UNKNOWN']),
            'unique_services': df['service'].nunique(),
            'time_span': (df['timestamp'].max() - df['timestamp'].min()).total_seconds() if df['timestamp'].notna().any() else 0,
            'anomaly_count': len(self.anomalies),
            'malformed_logs': len(df[df.get('is_malformed', False) == True]) if 'is_malformed' in df.columns else 0,
            'avg_message_length': df['message_length'].mean() if 'message_length' in df.columns else 0
        }
        
        return self.stats
    
    def generate_report(self):
        print("📋 Generating anomaly report...")
        
        if not self.anomalies:
            print("✅ No anomalies detected!")
            return
        
        anomalies_df = pd.DataFrame(self.anomalies)
        anomalies_df.to_csv('anomaly_report.csv', index=False)
        print(f"✅ Anomaly report saved to anomaly_report.csv")
        
        print(f"\n🔍 ANOMALY DETECTION SUMMARY")
        print(f"{'='*50}")
        print(f"📊 Total log entries scanned: {self.stats.get('total_entries', 0)}")
        print(f"❗ Anomalies detected: {self.stats.get('anomaly_count', 0)}")
        print(f"📈 Anomaly rate: {(self.stats.get('anomaly_count', 0) / self.stats.get('total_entries', 1)) * 100:.2f}%")
        
        if self.stats.get('anomaly_count', 0) > 0:
            print(f"\n📋 ANOMALY BREAKDOWN:")
            anomaly_types = anomalies_df['anomaly_type'].value_counts()
            for anomaly_type, count in anomaly_types.items():
                print(f"  • {anomaly_type}: {count}")
        
        return anomalies_df
    
    def create_visualizations(self):
        print("📊 Creating visualizations...")
        
        if not self.logs_data:
            print("❌ No data to visualize")
            return
        
        df = pd.DataFrame(self.logs_data)
        
        plt.style.use('seaborn-v0_8')
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('Log Analysis Dashboard', fontsize=16, fontweight='bold')
        
        level_counts = df['level'].value_counts()
        axes[0, 0].pie(level_counts.values, labels=level_counts.index, autopct='%1.1f%%', startangle=90)
        axes[0, 0].set_title('Log Level Distribution')
        
        service_counts = df['service'].value_counts().head(10)
        axes[0, 1].bar(range(len(service_counts)), service_counts.values)
        axes[0, 1].set_title('Top 10 Services by Log Count')
        axes[0, 1].set_xticks(range(len(service_counts)))
        axes[0, 1].set_xticklabels(service_counts.index, rotation=45, ha='right')
        
        if df['timestamp'].notna().any():
            df_with_time = df[df['timestamp'].notna()].copy()
            df_with_time['minute'] = df_with_time['timestamp'].dt.floor('min')
            timeline = df_with_time.groupby('minute').size()
            axes[1, 0].plot(timeline.index, timeline.values, marker='o', linewidth=2)
            axes[1, 0].set_title('Log Activity Over Time')
            axes[1, 0].set_xlabel('Time')
            axes[1, 0].set_ylabel('Log Count per Minute')
            axes[1, 0].tick_params(axis='x', rotation=45)
        
        if self.anomalies:
            anomalies_df = pd.DataFrame(self.anomalies)
            anomaly_counts = anomalies_df['anomaly_type'].value_counts()
            axes[1, 1].bar(range(len(anomaly_counts)), anomaly_counts.values)
            axes[1, 1].set_title('Anomaly Types Detected')
            axes[1, 1].set_xticks(range(len(anomaly_counts)))
            axes[1, 1].set_xticklabels(anomaly_counts.index, rotation=45, ha='right')
        else:
            axes[1, 1].text(0.5, 0.5, 'No Anomalies Detected', ha='center', va='center', 
                           transform=axes[1, 1].transAxes, fontsize=14)
            axes[1, 1].set_title('Anomaly Types Detected')
        
        plt.tight_layout()
        plt.savefig('log_analysis_dashboard.png', dpi=300, bbox_inches='tight')
        print("✅ Dashboard saved as log_analysis_dashboard.png")
        
        return fig
    
    def send_alerts(self, email_config=None):
        print("🚨 Generating alerts...")
        
        print(f"\n🚨 ALERT: {self.stats.get('anomaly_count', 0)} anomalies detected in log analysis!")
        
        alert_message = f"""
ALERT - Log Anomaly Detection Report
====================================
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Log Entries: {self.stats.get('total_entries', 0)}
Anomalies Detected: {self.stats.get('anomaly_count', 0)}
Anomaly Rate: {(self.stats.get('anomaly_count', 0) / self.stats.get('total_entries', 1)) * 100:.2f}%

Log Level Breakdown:
- INFO: {self.stats.get('info_count', 0)}
- WARN: {self.stats.get('warn_count', 0)}
- ERROR: {self.stats.get('error_count', 0)}
- UNKNOWN: {self.stats.get('unknown_count', 0)}

Critical Issues Found:
"""
        
        if self.anomalies:
            critical_anomalies = [a for a in self.anomalies if a.get('anomaly_type') in 
                                ['CRITICAL_RESOURCE_USAGE', 'DATABASE_CONNECTION_ISSUE', 'MALFORMED_LOG']]
            for anomaly in critical_anomalies[:5]:
                alert_message += f"- Line {anomaly['line_number']}: {anomaly['anomaly_type']} - {anomaly['message'][:100]}...\n"
        else:
            alert_message += "No critical issues detected.\n"
        
        with open('alerts.txt', 'w') as f:
            f.write(alert_message)
        
        print("✅ Alert saved to alerts.txt")
        
        if email_config:
            self._send_email_alert(alert_message, email_config)
        
        return alert_message
    
    def _send_email_alert(self, message, email_config):
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = email_config['to_email']
            msg['Subject'] = "Log Anomaly Alert - Critical Issues Detected"
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['from_email'], email_config['password'])
            text = msg.as_string()
            server.sendmail(email_config['from_email'], email_config['to_email'], text)
            server.quit()
            
            print(f"📧 Email alert sent to {email_config['to_email']}")
        except Exception as e:
            print(f"❌ Failed to send email alert: {e}")
    
    def run_analysis(self, email_config=None):
        print("🚀 Starting AI-Based Log Anomaly Analysis")
        print("=" * 50)
        
        self.parse_logs()
        self.detect_anomalies_ml()
        self.detect_anomalies_patterns()
        self.calculate_statistics()
        self.generate_report()
        self.create_visualizations()
        self.send_alerts(email_config)
        
        print("\n✅ Analysis complete!")
        print(f"📊 Check anomaly_report.csv for detailed results")
        print(f"📈 Check log_analysis_dashboard.png for visualizations")
        print(f"🚨 Check alerts.txt for alert summary")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='AI-Based Log Anomaly Checker')
    parser.add_argument('--log-file', default='logs.txt', help='Path to log file')
    parser.add_argument('--email', help='Email address for alerts (optional)')
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.log_file)
    
    email_config = None
    if args.email:
        import os
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        
        email_config = {
            'from_email': os.getenv('SMTP_FROM_EMAIL', 'subhadramishrag@gmail.com'),
            'to_email': args.email,
            'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': int(os.getenv('SMTP_PORT', '587')),
            'password': os.getenv('SMTP_PASSWORD', 'your_app_password')
        }
    
    analyzer.run_analysis(email_config)


if __name__ == "__main__":
    main()
