import requests
import time
#Replace this with your actual VirusTotal API key
API_KEY = "9f5c1bf0c2172446291b54a2a3e73f6246fc0b1b0babf26e5d9964cad8bfdac7"
url_to_check = input("Enter the URL to scan: ")

# Step 1: Submit URL for scanning
scan_url = "https://www.virustotal.com/api/v3/urls"
headers = {
    "x-apikey": API_KEY
}

# VirusTotal requires URL in base64
import base64
url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

# Step 2: Submit the URL
response = requests.post(scan_url, headers=headers, data={"url": url_to_check})
if response.status_code != 200:
    print("Failed to submit URL for scanning:", response.text)
    exit()

print("URL submitted. Getting results...")

# Step 3: Retrieve analysis report
time.sleep(15)  # Wait before fetching the report (important for free-tier users)

analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
report = requests.get(analysis_url, headers=headers).json()

try:
    stats = report['data']['attributes']['last_analysis_stats']
    print("\nScan Results:")
    print(f"  Harmless: {stats['harmless']}")
    print(f"  Suspicious: {stats['suspicious']}")
    print(f"  Malicious: {stats['malicious']}")

    if stats['malicious'] > 0 or stats['suspicious'] > 0:
        print("⚠️  The URL may be unsafe!")
    else:
        print("✅ The URL appears to be safe.")
except KeyError:
    print("Error retrieving scan results.")