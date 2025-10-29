#!/usr/bin/env python3
"""
Log Generator Script
Creates multiple large log files with various patterns and anomalies for testing.
"""

import random
import datetime
from datetime import timedelta
import os

def generate_log_entry(timestamp, services, log_levels, patterns):
    """Generate a single log entry"""
    service = random.choice(services)
    level = random.choice(log_levels)
    
    # Choose a pattern based on level and service
    if level == 'ERROR':
        pattern = random.choice(patterns['error'])
    elif level == 'WARN':
        pattern = random.choice(patterns['warning'])
    else:
        pattern = random.choice(patterns['info'])
    
    # Add some randomness to the pattern
    user_id = random.randint(10000, 99999)
    execution_time = round(random.uniform(0.1, 5.0), 1)
    memory_usage = random.randint(20, 100)
    cpu_usage = random.randint(15, 95)
    eviction_count = random.randint(100, 5000)
    
    # Format the log entry
    message = pattern.format(
        user_id=user_id,
        execution_time=execution_time,
        memory_usage=memory_usage,
        cpu_usage=cpu_usage,
        eviction_count=eviction_count,
        timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S')
    )
    
    return f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {level} [{service}] {message}"

def generate_anomalous_log_entry(timestamp, services):
    """Generate an anomalous log entry"""
    service = random.choice(services)
    
    anomaly_patterns = [
        # Critical resource usage
        "CRITICAL: Memory usage at 99% - system may crash",
        "EMERGENCY: CPU usage at 100% - immediate attention required",
        "FATAL: Disk space at 1% - backup failed",
        
        # Database issues
        "ERROR: Database connection pool exhausted - 0 connections available",
        "ERROR: Deadlock detected in transaction - rollback required",
        "ERROR: Connection timeout after 60s - database unreachable",
        "ERROR: Primary database failed - failover to secondary",
        
        # Authentication failures
        "ERROR: Multiple authentication failures from IP 192.168.1.100",
        "ERROR: Brute force attack detected - account locked",
        "ERROR: Invalid token provided - potential security breach",
        
        # System errors
        "ERROR: Out of memory - process killed",
        "ERROR: File system read-only - data corruption possible",
        "ERROR: Network interface down - service unavailable",
        
        # Malformed logs (intentionally)
        "MALFORMED_LOG_ENTRY_WITHOUT_PROPER_FORMAT",
        "2024-01-15 10:30:15 ERROR [Service] Incomplete log entry",
        "ERROR [Service] Missing timestamp",
        "2024-01-15 10:30:15 [Service] Missing log level",
    ]
    
    pattern = random.choice(anomaly_patterns)
    level = 'ERROR' if 'ERROR' in pattern or 'CRITICAL' in pattern or 'FATAL' in pattern else 'WARN'
    
    return f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} {level} [{service}] {pattern}"

def generate_log_file(filename, num_entries, anomaly_rate=0.05):
    """Generate a log file with specified number of entries"""
    print(f"Generating {filename} with {num_entries:,} entries...")
    
    services = [
        'UserService', 'DatabaseService', 'CacheService', 'AuthService', 
        'SystemService', 'PaymentService', 'NotificationService', 'APIGateway',
        'LoadBalancer', 'WebServer', 'MicroService', 'QueueService'
    ]
    
    log_levels = ['INFO', 'WARN', 'ERROR']
    
    patterns = {
        'info': [
            "User login successful: user_id={user_id}",
            "Query executed successfully: SELECT * FROM users WHERE id={user_id}",
            "Cache hit for key: user_profile_{user_id}",
            "Token validation successful",
            "User profile loaded: user_id={user_id}",
            "User logout successful: user_id={user_id}",
            "Memory usage: {memory_usage}%",
            "CPU usage: {cpu_usage}%",
            "Request processed successfully",
            "Data synchronized successfully",
            "Configuration updated",
            "Service started successfully",
            "Health check passed",
            "Backup completed successfully"
        ],
        'warning': [
            "Slow query detected: {execution_time}s execution time",
            "Cache miss for key: user_preferences_{user_id}",
            "High memory usage detected: {memory_usage}%",
            "High CPU usage detected: {cpu_usage}%",
            "Cache eviction: {eviction_count} entries removed",
            "Connection pool at 80% capacity",
            "Disk space at 85% capacity",
            "Rate limit approaching: 90% of quota used",
            "Deprecated API endpoint accessed",
            "SSL certificate expires in 30 days"
        ],
        'error': [
            "Connection timeout after 30s",
            "Connection pool exhausted",
            "Invalid token provided",
            "Token expired",
            "Deadlock detected in transaction",
            "Transaction rollback required",
            "Connection lost to primary database",
            "Failover to secondary database",
            "Disk space low: {memory_usage}% remaining",
            "Backup failed: insufficient space",
            "Authentication failed for user {user_id}",
            "Database query failed: syntax error",
            "Service unavailable: dependency down",
            "Configuration validation failed"
        ]
    }
    
    # Start time
    start_time = datetime.datetime(2024, 1, 15, 8, 0, 0)
    
    with open(filename, 'w') as f:
        for i in range(num_entries):
            # Add some time progression
            timestamp = start_time + timedelta(seconds=i * random.randint(1, 5))
            
            # Generate anomalous entry with specified probability
            if random.random() < anomaly_rate:
                log_entry = generate_anomalous_log_entry(timestamp, services)
            else:
                log_entry = generate_log_entry(timestamp, services, log_levels, patterns)
            
            f.write(log_entry + '\n')
            
            # Progress indicator
            if (i + 1) % 10000 == 0:
                print(f"  Generated {i + 1:,} entries...")
    
    print(f"✅ Generated {filename} with {num_entries:,} entries")

def main():
    """Generate multiple log files for testing"""
    print("🚀 Generating multiple log files for testing...")
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Generate different types of log files
    log_files = [
        ('logs/application.log', 50000, 0.03),      # Normal application logs
        ('logs/database.log', 30000, 0.08),         # Database logs with more errors
        ('logs/system.log', 25000, 0.05),           # System logs
        ('logs/security.log', 15000, 0.12),         # Security logs with more anomalies
        ('logs/performance.log', 40000, 0.04),      # Performance monitoring logs
        ('logs/error.log', 20000, 0.15),            # Error-focused logs
        ('logs/access.log', 100000, 0.02),          # Large access log
        ('logs/combined.log', 200000, 0.06),        # Large combined log
    ]
    
    for filename, num_entries, anomaly_rate in log_files:
        generate_log_file(filename, num_entries, anomaly_rate)
    
    print("\n✅ All log files generated successfully!")
    print("\n📁 Generated files:")
    for filename, num_entries, anomaly_rate in log_files:
        file_size = os.path.getsize(filename) / (1024 * 1024)  # MB
        print(f"  • {filename}: {num_entries:,} entries, {file_size:.1f} MB, {anomaly_rate*100:.1f}% anomaly rate")

if __name__ == "__main__":
    main()
