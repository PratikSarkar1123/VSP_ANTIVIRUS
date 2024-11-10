from flask import Flask, request, jsonify
import requests
import time
from flask_cors import CORS
import ssl
import socket

app = Flask(__name__)
CORS(app)

VIRUS_TOTAL_API_KEY = '8b6a980830eede8c19de15eca72859a968e854751e05178f6cd64c600db54b21'

def check_ssl_certificate(url):
    """Check if the SSL certificate of the URL is valid."""
    try:
        hostname = url.split("://")[-1].split("/")[0]  # Extract hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.version()  # If SSL handshake fails, it will raise an exception
        return True
    except Exception as e:
        print(f"SSL Certificate error for {url}: {e}")
        return False

def check_url_security(url):
    """Check if the URL is HTTP or HTTPS and validate SSL certificates."""
    if url.startswith('http://'):
        return "Insecure", None  # HTTP is less secure
    elif url.startswith('https://'):
        if not check_ssl_certificate(url):
            return "Suspicious", ["Invalid SSL certificate"]
    return "Secure", None  # Valid HTTPS

def check_url_virustotal(url):
    """Queries VirusTotal API for URL scanning and categorization."""
    vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': VIRUS_TOTAL_API_KEY, 'resource': url}
    response = requests.get(vt_url, params=params)

    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('positives', 0) > 0:
                virus_engines = [scan['result'] for scan in result['scans'].values() if scan['detected']]
                return "Suspicious", virus_engines
            return "Safe", None
        except ValueError:
            return "Error", None
    return "Error", None

def warn_user(suspicious_url, engines):
    """Sends warning messages to the user for suspicious URLs."""
    warning_message = f"Warning! The website '{suspicious_url}' is detected as suspicious. Detected by: {', '.join(engines)}"
    for _ in range(3):  # Send 3 warnings
        print(warning_message)
        time.sleep(5)  # Wait for 5 seconds between warnings

@app.route('/capture-url', methods=['POST'])
def capture_url():
    """Endpoint to capture URL requests and check them via VirusTotal."""
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    print(f"Checking URL: {url}")

    # Check URL security (HTTP/HTTPS and SSL validity)
    security_status, security_engines = check_url_security(url)
    if security_status == "Insecure":
        print(f"Warning: The URL '{url}' is insecure (HTTP).")
        warn_user(url, ["Insecure connection"])

    if security_status == "Suspicious":
        print(f"Warning: The URL '{url}' has an invalid SSL certificate.")
        warn_user(url, security_engines)

    # Check the URL with VirusTotal
    vt_status, vt_engines = check_url_virustotal(url)
    if vt_status == "Suspicious":
        warn_user(url, vt_engines)
        return jsonify({'status': 'Suspicious', 'url': url, 'engines': vt_engines})

    return jsonify({'status': 'Safe', 'url': url})

def monitor_web_traffic():
    """Function to start the web monitoring server."""
    app.run(port=5000)

# Uncomment to run the web server when this script is executed
# if __name__ == "__main__":
#     monitor_web_traffic()
