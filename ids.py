#!/usr/bin/env python3
"""
Simple Intrusion Detection System (IDS)
Author: Matthew Hennion
Description:
This script analyzes authentication logs to detect
potential brute-force login attempts by counting
failed login events per IP address.
"""

from collections import defaultdict

# ===== CONFIGURATION =====
LOG_FILE = "auth.log"          # Path to log file
FAILED_LOGIN_KEYWORD = "Failed password"
ALERT_THRESHOLD = 5            # Number of failed attempts before alert

# =========================

def analyze_logs(log_file):
    """
    Reads a log file and counts failed login attempts by IP address.
    """
    failed_attempts = defaultdict(int)

    try:
        with open(log_file, "r") as file:
            for line in file:
                if FAILED_LOGIN_KEYWORD in line:
                    parts = line.split()
                    ip_address = parts[-4]  # Typical IP location in auth logs
                    failed_attempts[ip_address] += 1

    except FileNotFoundError:
        print(f"[ERROR] Log file '{log_file}' not found.")
        return {}

    return failed_attempts


def generate_alerts(failed_attempts):
    """
    Generates alerts for IPs exceeding the threshold.
    """
    print("\n--- IDS Scan Results ---\n")

    suspicious_activity = False

    for ip, count in failed_attempts.items():
        if count >= ALERT_THRESHOLD:
            print(f"[ALERT] Possible brute-force attack detected!")
            print(f"        IP Address: {ip}")
            print(f"        Failed Attempts: {count}\n")
            suspicious_activity = True

    if not suspicious_activity:
        print("No suspicious activity detected.")


def main():
    print("Starting Simple Python IDS...\n")

    failed_attempts = analyze_logs(LOG_FILE)

    if failed_attempts:
        generate_alerts(failed_attempts)

    print("\nIDS scan complete.")


if __name__ == "__main__":
    main()
