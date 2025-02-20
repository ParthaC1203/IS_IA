import requests
import ssl
import socket
import random
import hashlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.request import urlopen

# Dummy database of leaked credentials (Simulating compromised password scanning)
LEAKED_CREDENTIALS = {
    "user@example.com": "password123",
    "admin@test.com": "admin@123"
}

# Function to check if the website uses HTTPS
def check_https(url):
    return urlparse(url).scheme == "https"

# Function to check the SSL certificate (validity check)
def check_ssl(url):
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
        connection.connect((hostname, 443))
        cert = connection.getpeercert()
        return "✅ SSL certificate is valid" if cert else "⚠ No SSL certificate found"
    except Exception as e:
        return f"⚠ SSL certificate check failed: {e}"

# Function to check phishing indicators in a website
def check_phishing(url):
    try:
        html = urlopen(url)
        soup = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            if action and "login" in action.lower():
                return "⚠ Possible phishing form detected!"
        return "✅ No obvious phishing signs"
    except Exception as e:
        return f"⚠ Error checking phishing content: {e}"

# Function to check for malware signs
def check_malware(url):
    suspicious_keywords = ["malicious", "dangerous", ".exe", ".zip", "base64"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        return "⚠ Potential malware domain detected!"
    return "✅ No obvious malware signs"

# Function to check compromised passwords (Simulating dark web scanning)
def check_compromised_passwords(email):
    if email in LEAKED_CREDENTIALS:
        return f"⚠ Compromised password found for {email}!"
    return f"✅ No leaked credentials for {email}."

# Function to simulate a vulnerability scan
def check_vulnerabilities(url):
    known_vulnerabilities = ["Apache/2.2", "nginx/1.14", "PHP/5.6"]
    try:
        response = requests.get(url, timeout=5)
        server_header = response.headers.get("Server", "Unknown")
        if any(vuln in server_header for vuln in known_vulnerabilities):
            return f"⚠ Outdated server software detected: {server_header}"
        return "✅ No known vulnerabilities detected."
    except requests.RequestException as e:
        return f"⚠ Error checking vulnerabilities: {e}"

# Function to check website scanning for malware, blacklisting, and redirects
def check_website_security(url):
    security_issues = []
    
    try:
        html = urlopen(url).read().decode('utf-8')
        
        # Simulate spam/malware detection
        if "malware" in html or "spam" in html:
            security_issues.append("⚠ Website contains spam or malware!")

        # Simulate blacklist check
        blacklisted_sites = ["malicious-site.com", "hacked-website.net"]
        if urlparse(url).hostname in blacklisted_sites:
            security_issues.append("⚠ Website is blacklisted!")

        # Simulate malicious redirects
        if "window.location" in html and "evil.com" in html:
            security_issues.append("⚠ Website has malicious redirects!")

    except Exception as e:
        security_issues.append(f"⚠ Error scanning website: {e}")

    return security_issues if security_issues else ["✅ Website appears secure."]

# Function to simulate threat alerts
def threat_alerts():
    threats = [
        "🚨 New Phishing Scam: Fake login pages targeting banking users.",
        "🚨 CVE-2024-1234: Critical RCE vulnerability in Apache server!",
        "🚨 Ransomware Alert: New strain encrypting files via email attachments.",
    ]
    return random.choice(threats)

# Function to simulate an Incident Response Plan
def incident_response_plan():
    return [
        "🔹 Identify the breach and determine affected systems.",
        "🔹 Contain the incident by isolating affected networks.",
        "🔹 Eradicate the root cause (e.g., patch vulnerabilities).",
        "🔹 Recover and restore backups to resume operations.",
        "🔹 Perform a post-incident analysis and report findings."
    ]

# Function to run all security checks
def check_security(url, email):
    report = {
        "HTTPS": check_https(url),
        "SSL": check_ssl(url),
        "Phishing": check_phishing(url),
        "Malware": check_malware(url),
        "Compromised Passwords": check_compromised_passwords(email),
        "Vulnerabilities": check_vulnerabilities(url),
        "Website Security": check_website_security(url),
        "Threat Alert": threat_alerts(),
        "Incident Response Plan": incident_response_plan()
    }
    return report

# Main function
def main():
    url = input("Enter a website URL to check security (include http/https): ").strip()
    email = input("Enter an email to check for leaked credentials: ").strip()

    if not url.startswith('http://') and not url.startswith('https://'):
        print("⚠ Invalid URL! It must start with http:// or https://")
        return
    
    print("\n[🔍] Running Security Checks...\n")
    security_report = check_security(url, email)

    print("\n🔒 **Security Report**")
    print("-" * 40)
    
    for key, value in security_report.items():
        if isinstance(value, list):
            print(f"\n🔹 {key}:")
            for item in value:
                print(f"   - {item}")
        else:
            print(f"🔹 {key}: {value}")

    print("\n✅ Security Scan Completed.")

if __name__ == "__main__":
    main()
