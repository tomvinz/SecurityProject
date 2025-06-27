from flask import Flask, render_template, request
import requests
import base64
import time

app = Flask(__name__)

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Replace with your actual VirusTotal API key

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url_to_check = request.form["url"]

        # Submit URL to VirusTotal
        submit_url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": API_KEY}
        data = {"url": url_to_check}

        submit_response = requests.post(submit_url, headers=headers, data=data)
        if submit_response.status_code != 200:
            result = f"Error submitting URL: {submit_response.text}"
            return render_template("index.html", result=result)

        # Encode URL to match VirusTotal format
        url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")

        # Give VT some time to scan (use time.sleep for demo purposes)
        time.sleep(15)

        # Retrieve scan report
        report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        report_response = requests.get(report_url, headers=headers).json()

        try:
            stats = report_response["data"]["attributes"]["last_analysis_stats"]
            harmless = stats["harmless"]
            suspicious = stats["suspicious"]
            malicious = stats["malicious"]

            if malicious > 0 or suspicious > 0:
                result = f"⚠️ Suspicious or Malicious URL\nHarmless: {harmless} | Suspicious: {suspicious} | Malicious: {malicious}"
            else:
                result = f"✅ Safe URL\nHarmless: {harmless} | Suspicious: {suspicious} | Malicious: {malicious}"
        except KeyError:
            result = "❌ Could not retrieve scan results."

    return render_template("index.html", result=result)
if __name__ == '__main__':
    app.run(debug=True)

