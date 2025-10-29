#!/usr/bin/env python3
"""
Streamlit Web App for AI-Based Log Anomaly Checker
Upload log files and get instant anomaly analysis with visualizations.
"""

import streamlit as st
import pandas as pd
import tempfile
import os
import time
from datetime import datetime
from log_analyzer import LogAnalyzer
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Page configuration
st.set_page_config(
    page_title="AI Log Anomaly Checker",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .anomaly-high {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .anomaly-medium {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .anomaly-low {
        background-color: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Header
    st.markdown('<h1 class="main-header">🔍 AI-Based Log Anomaly Checker</h1>', unsafe_allow_html=True)
    st.markdown("Upload your log files and get instant anomaly detection with ML-powered analysis!")
    
    # Sidebar
    with st.sidebar:
        st.header("📁 Upload Log File")
        
        # File uploader
        uploaded_file = st.file_uploader(
            "Choose a log file",
            type=['log', 'txt'],
            help="Upload a log file in standard format: YYYY-MM-DD HH:MM:SS LEVEL [SERVICE] MESSAGE"
        )
        
        # Email configuration
        st.header("📧 Email Alerts (Optional)")
        email = st.text_input("Email address for alerts", placeholder="your@email.com")
        
        # Analysis options
        st.header("⚙️ Analysis Options")
        show_ml_detection = st.checkbox("Enable ML Detection", value=True)
        show_pattern_detection = st.checkbox("Enable Pattern Detection", value=True)
        
        # Sample data
        st.header("🧪 Try Sample Data")
        if st.button("Load Sample Security Log"):
            # Create a temporary sample file
            sample_data = """2024-01-15 10:30:15 INFO [UserService] User login successful: user_id=12345
2024-01-15 10:30:16 ERROR [DatabaseService] Connection timeout after 30s
2024-01-15 10:30:17 WARN [CacheService] High memory usage detected: 95%
2024-01-15 10:30:18 ERROR [AuthService] Invalid token provided
2024-01-15 10:30:19 INFO [UserService] User profile loaded: user_id=12345
2024-01-15 10:30:20 ERROR [DatabaseService] Deadlock detected in transaction
2024-01-15 10:30:21 WARN [SystemService] Critical memory usage: 99%
2024-01-15 10:30:22 INFO [UserService] User logout successful: user_id=12345"""
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
                f.write(sample_data)
                uploaded_file = f.name
    
    # Main content area
    if uploaded_file is not None:
        # Process the uploaded file
        if isinstance(uploaded_file, str):
            # Sample data
            file_path = uploaded_file
            file_name = "Sample Security Log"
        else:
            # Real uploaded file
            file_name = uploaded_file.name
            
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.log', delete=False) as f:
                f.write(uploaded_file.getbuffer())
                file_path = f.name
        
        # Run analysis
        with st.spinner(f"Analyzing {file_name}..."):
            try:
                # Initialize analyzer
                analyzer = LogAnalyzer(file_path)
                
                # Parse logs
                analyzer.parse_logs()
                
                # Run detection based on options
                if show_ml_detection:
                    analyzer.detect_anomalies_ml()
                if show_pattern_detection:
                    analyzer.detect_anomalies_patterns()
                
                # Calculate statistics
                analyzer.calculate_statistics()
                
                # Generate report
                anomalies_df = analyzer.generate_report()
                
                # Clean up temporary file
                if isinstance(uploaded_file, str):
                    os.unlink(file_path)
                else:
                    os.unlink(file_path)
                
            except Exception as e:
                st.error(f"Error analyzing log file: {str(e)}")
                return
        
        # Display results
        st.success("✅ Analysis complete!")
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Total Log Entries",
                f"{analyzer.stats.get('total_entries', 0):,}",
                help="Total number of log entries processed"
            )
        
        with col2:
            anomaly_count = analyzer.stats.get('anomaly_count', 0)
            anomaly_rate = (anomaly_count / analyzer.stats.get('total_entries', 1)) * 100
            st.metric(
                "Anomalies Detected",
                f"{anomaly_count:,}",
                f"{anomaly_rate:.1f}%",
                help="Number and percentage of anomalies found"
            )
        
        with col3:
            error_count = analyzer.stats.get('error_count', 0)
            st.metric(
                "Error Logs",
                f"{error_count:,}",
                help="Number of ERROR level log entries"
            )
        
        with col4:
            unique_services = analyzer.stats.get('unique_services', 0)
            st.metric(
                "Unique Services",
                f"{unique_services}",
                help="Number of different services in the logs"
            )
        
        # Tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔍 Anomalies", "📈 Analytics", "📄 Raw Data"])
        
        with tab1:
            # Create visualizations
            create_dashboard(analyzer)
        
        with tab2:
            # Anomaly details
            show_anomaly_details(anomalies_df)
        
        with tab3:
            # Advanced analytics
            show_analytics(analyzer)
        
        with tab4:
            # Raw data
            show_raw_data(analyzer)
        
        # Download options
        st.header("📥 Download Results")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if anomalies_df is not None and not anomalies_df.empty:
                csv = anomalies_df.to_csv(index=False)
                st.download_button(
                    label="📊 Download Anomaly Report (CSV)",
                    data=csv,
                    file_name=f"anomaly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col2:
            st.download_button(
                label="📧 Download Alert Summary",
                data=create_alert_summary(analyzer),
                file_name=f"alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
        
        with col3:
            st.info("💡 Tip: Use the sample data to see how the system works!")
    
    else:
        # Welcome screen
        st.markdown("""
        ## 🚀 Welcome to AI Log Anomaly Checker!
        
        This tool uses **Machine Learning** and **pattern-based detection** to identify anomalies in your log files.
        
        ### ✨ Features:
        - **🤖 ML Detection**: Uses Isolation Forest algorithm for unsupervised anomaly detection
        - **🔍 Pattern Detection**: Rule-based detection for known critical issues
        - **📊 Visual Analytics**: Interactive charts and dashboards
        - **🚨 Smart Alerting**: Multi-level alert system
        - **📈 Real-time Analysis**: Process logs instantly
        
        ### 📝 Supported Log Format:
        ```
        2024-01-15 10:30:15 INFO [UserService] User login successful: user_id=12345
        2024-01-15 10:30:16 ERROR [DatabaseService] Connection timeout after 30s
        2024-01-15 10:30:17 WARN [CacheService] High memory usage detected: 95%
        ```
        
        ### 🎯 How to Use:
        1. **Upload** your log file using the sidebar
        2. **Configure** analysis options (ML/Pattern detection)
        3. **View** results in interactive dashboards
        4. **Download** detailed reports and alerts
        
        **Try the sample data first** to see how it works! 🧪
        """)

def create_dashboard(analyzer):
    """Create the main dashboard with visualizations"""
    
    # Log level distribution
    st.subheader("📊 Log Level Distribution")
    
    level_counts = {
        'INFO': analyzer.stats.get('info_count', 0),
        'WARN': analyzer.stats.get('warn_count', 0),
        'ERROR': analyzer.stats.get('error_count', 0),
        'UNKNOWN': analyzer.stats.get('unknown_count', 0)
    }
    
    # Create pie chart
    fig_pie = px.pie(
        values=list(level_counts.values()),
        names=list(level_counts.keys()),
        title="Log Level Distribution",
        color_discrete_map={
            'INFO': '#4CAF50',
            'WARN': '#FF9800', 
            'ERROR': '#F44336',
            'UNKNOWN': '#9E9E9E'
        }
    )
    st.plotly_chart(fig_pie, use_container_width=True)
    
    # Anomaly breakdown
    if analyzer.anomalies:
        st.subheader("🚨 Anomaly Breakdown")
        
        anomaly_df = pd.DataFrame(analyzer.anomalies)
        anomaly_counts = anomaly_df['anomaly_type'].value_counts()
        
        fig_bar = px.bar(
            x=anomaly_counts.values,
            y=anomaly_counts.index,
            orientation='h',
            title="Anomaly Types Detected",
            labels={'x': 'Count', 'y': 'Anomaly Type'}
        )
        fig_bar.update_layout(height=400)
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # Service activity
    if analyzer.logs_data:
        st.subheader("🔧 Service Activity")
        
        df = pd.DataFrame(analyzer.logs_data)
        service_counts = df['service'].value_counts().head(10)
        
        fig_service = px.bar(
            x=service_counts.values,
            y=service_counts.index,
            orientation='h',
            title="Top 10 Services by Log Count",
            labels={'x': 'Log Count', 'y': 'Service'}
        )
        fig_service.update_layout(height=400)
        st.plotly_chart(fig_service, use_container_width=True)

def show_anomaly_details(anomalies_df):
    """Show detailed anomaly information"""
    if anomalies_df is None or anomalies_df.empty:
        st.info("No anomalies detected! 🎉")
        return
    
    st.subheader("🔍 Detailed Anomaly Analysis")
    
    # Filter options
    col1, col2 = st.columns(2)
    
    with col1:
        anomaly_types = ['All'] + list(anomalies_df['anomaly_type'].unique())
        selected_type = st.selectbox("Filter by Anomaly Type", anomaly_types)
    
    with col2:
        services = ['All'] + list(anomalies_df['service'].unique())
        selected_service = st.selectbox("Filter by Service", services)
    
    # Apply filters
    filtered_df = anomalies_df.copy()
    
    if selected_type != 'All':
        filtered_df = filtered_df[filtered_df['anomaly_type'] == selected_type]
    
    if selected_service != 'All':
        filtered_df = filtered_df[filtered_df['service'] == selected_service]
    
    # Display anomalies
    st.write(f"Showing {len(filtered_df)} anomalies")
    
    for idx, row in filtered_df.head(20).iterrows():
        # Determine severity based on anomaly type
        if row['anomaly_type'] in ['CRITICAL_RESOURCE_USAGE', 'DATABASE_CONNECTION_ISSUE', 'MALFORMED_LOG']:
            css_class = "anomaly-high"
            icon = "🔴"
        elif row['anomaly_type'] in ['AUTH_FAILURE', 'SLOW_QUERY']:
            css_class = "anomaly-medium"
            icon = "🟡"
        else:
            css_class = "anomaly-low"
            icon = "🟢"
        
        st.markdown(f"""
        <div class="{css_class}">
            <strong>{icon} {row['anomaly_type']}</strong><br>
            <strong>Line {row['line_number']}</strong> | <strong>{row['service']}</strong><br>
            <em>{row['message'][:100]}{'...' if len(row['message']) > 100 else ''}</em>
        </div>
        """, unsafe_allow_html=True)

def show_analytics(analyzer):
    """Show advanced analytics"""
    st.subheader("📈 Advanced Analytics")
    
    if not analyzer.logs_data:
        st.info("No data available for analytics")
        return
    
    df = pd.DataFrame(analyzer.logs_data)
    
    # Time-based analysis
    if 'timestamp' in df.columns and df['timestamp'].notna().any():
        st.subheader("⏰ Time-based Analysis")
        
        df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        hourly_counts = df.groupby('hour').size()
        
        fig_time = px.line(
            x=hourly_counts.index,
            y=hourly_counts.values,
            title="Log Activity by Hour",
            labels={'x': 'Hour of Day', 'y': 'Log Count'}
        )
        st.plotly_chart(fig_time, use_container_width=True)
    
    # Message length analysis
    if 'message_length' in df.columns:
        st.subheader("📝 Message Length Analysis")
        
        fig_length = px.histogram(
            df,
            x='message_length',
            title="Distribution of Message Lengths",
            labels={'message_length': 'Message Length (characters)', 'count': 'Frequency'}
        )
        st.plotly_chart(fig_length, use_container_width=True)

def show_raw_data(analyzer):
    """Show raw log data"""
    st.subheader("📄 Raw Log Data")
    
    if not analyzer.logs_data:
        st.info("No log data available")
        return
    
    df = pd.DataFrame(analyzer.logs_data)
    
    # Display options
    col1, col2 = st.columns(2)
    
    with col1:
        max_rows = st.slider("Number of rows to display", 10, 1000, 100)
    
    with col2:
        show_anomalies_only = st.checkbox("Show anomalies only", value=False)
    
    # Filter data
    display_df = df.copy()
    
    if show_anomalies_only and analyzer.anomalies:
        anomaly_lines = [a['line_number'] for a in analyzer.anomalies]
        display_df = display_df[display_df['line_number'].isin(anomaly_lines)]
    
    # Display table
    st.dataframe(
        display_df[['line_number', 'timestamp', 'level', 'service', 'message']].head(max_rows),
        use_container_width=True
    )

def create_alert_summary(analyzer):
    """Create alert summary text"""
    alert_text = f"""
ALERT - Log Anomaly Detection Report
====================================
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Log Entries: {analyzer.stats.get('total_entries', 0)}
Anomalies Detected: {analyzer.stats.get('anomaly_count', 0)}
Anomaly Rate: {(analyzer.stats.get('anomaly_count', 0) / analyzer.stats.get('total_entries', 1)) * 100:.2f}%

Log Level Breakdown:
- INFO: {analyzer.stats.get('info_count', 0)}
- WARN: {analyzer.stats.get('warn_count', 0)}
- ERROR: {analyzer.stats.get('error_count', 0)}
- UNKNOWN: {analyzer.stats.get('unknown_count', 0)}

Critical Issues Found:
"""
    
    if analyzer.anomalies:
        critical_anomalies = [a for a in analyzer.anomalies if a.get('anomaly_type') in 
                            ['CRITICAL_RESOURCE_USAGE', 'DATABASE_CONNECTION_ISSUE', 'MALFORMED_LOG']]
        for anomaly in critical_anomalies[:5]:
            alert_text += f"- Line {anomaly['line_number']}: {anomaly['anomaly_type']} - {anomaly['message'][:100]}...\n"
    else:
        alert_text += "No critical issues detected.\n"
    
    return alert_text

if __name__ == "__main__":
    main()
