import requests
import json
import os
import re
import threading
import logging
import socket
import platform
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fpdf import FPDF
import random
import base64

# Logging configuration
logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

VULNERABILITY_GUIDES = {
    "Injection": "https://owasp.org/www-community/attacks/Injection",
    "Broken Authentication": "https://owasp.org/www-community/attacks/Authentication_and_Session_Management",
    "Sensitive Data Exposure": "https://owasp.org/www-community/attacks/Sensitive_Data_Exposure",
    "XML External Entities (XXE):": "https://owasp.org/www-community/attacks/XXE",
    "Broken Access Control": "https://owasp.org/www-community/attacks/Broken_Access_Control",
    "Security Misconfiguration": "https://owasp.org/www-community/attacks/Misconfiguration",
    "Cross-Site Scripting (XSS)": "https://owasp.org/www-community/attacks/xss/",
    "Insecure Deserialization": "https://owasp.org/www-community/attacks/Deserialization",
    "Using Components with Known Vulnerabilities": "https://owasp.org/www-community/attacks/Using_components_with_known_vulnerabilities",
    "Insufficient Logging & Monitoring": "https://owasp.org/www-community/attacks/Insufficient_logging_and_monitoring",
}

class WebScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})
        self.vulnerabilities = []
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.service_versions = {}
        self.os_info = "Unknown"

    def get_all_forms(self, url):
        try:
            response = self.session.get(url, timeout=5)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            logging.error(f"Error fetching forms: {e}")
            return []

    def log_vulnerability(self, vuln_type, url):
        guide = VULNERABILITY_GUIDES.get(vuln_type, "https://owasp.org/")
        self.vulnerabilities.append([vuln_type, url, guide])
        logging.info(f"{vuln_type} detected at {url}. Learn more: {guide}")

    def fuzz_payload(self, payload):
        mutations = [
            payload,
            payload.upper(),
            payload.lower(),
            payload.replace(" ", "%20"),
            base64.b64encode(payload.encode()).decode(),
            ''.join(random.sample(payload, len(payload)))
        ]
        return random.choice(mutations)

    def test_xss(self):
        advanced_payloads = ['<script>alert("XSS")</script>', '"><img src=x onerror=alert(1)>']
        for form in self.get_all_forms(self.base_url):
            form_url = urljoin(self.base_url, form.attrs.get("action", ""))
            for payload in advanced_payloads:
                fuzzed_payload = self.fuzz_payload(payload)
                data = {input_tag.attrs.get("name", ""): fuzzed_payload for input_tag in form.find_all("input")}
                try:
                    response = self.session.post(form_url, data=data, timeout=5)
                    if fuzzed_payload in response.text:
                        self.log_vulnerability("Cross-Site Scripting (XSS)", form_url)
                except Exception as e:
                    logging.error(f"Error testing XSS: {e}")

    def test_sqli(self):
        advanced_payloads = ["' OR '1'='1' -- ", "' OR '1'='1' #", "' OR 1=1--", "' OR 1=1#"]
        for payload in advanced_payloads:
            fuzzed_payload = self.fuzz_payload(payload)
            test_url = f"{self.base_url}?id={fuzzed_payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if any(keyword in response.text.lower() for keyword in ["sql", "syntax", "error", "database"]):
                    self.log_vulnerability("Injection", test_url)
            except Exception as e:
                logging.error(f"Error testing SQLi: {e}")

    def test_csrf(self):
        for form in self.get_all_forms(self.base_url):
            if not form.find("input", {"name": "csrf_token"}):
                self.log_vulnerability("CSRF", self.base_url)
                break

    def test_open_redirect(self):
        payloads = ["http://evil.com", "//evil.com"]
        for payload in payloads:
            test_url = f"{self.base_url}?redirect={payload}"
            try:
                response = self.session.get(test_url, allow_redirects=False, timeout=5)
                if response.status_code in [301, 302] and "evil.com" in response.headers.get("Location", ""):
                    self.log_vulnerability("Open Redirect", test_url)
            except Exception as e:
                logging.error(f"Error testing Open Redirect: {e}")

    def test_directory_traversal(self):
        payloads = ["../../../../etc/passwd", "../../../../../../../../etc/passwd"]
        for payload in payloads:
            test_url = f"{self.base_url}/{payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "root:x:0:0:" in response.text:
                    self.log_vulnerability("Directory Traversal", test_url)
            except Exception as e:
                logging.error(f"Error testing Directory Traversal: {e}")

    def test_command_injection(self):
        payloads = ["; id", "| id"]
        for payload in payloads:
            test_url = f"{self.base_url}?cmd={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "uid=" in response.text:
                    self.log_vulnerability("Command Injection", test_url)
            except Exception as e:
                logging.error(f"Error testing Command Injection: {e}")

    def test_rce(self):
        payloads = ["; echo RCE", "| echo RCE"]
        for payload in payloads:
            test_url = f"{self.base_url}?exec={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "RCE" in response.text:
                    self.log_vulnerability("Remote Code Execution (RCE)", test_url)
            except Exception as e:
                logging.error(f"Error testing RCE: {e}")

    def test_clickjacking(self):
        try:
            response = self.session.get(self.base_url, timeout=5)
            if "X-Frame-Options" not in response.headers:
                self.log_vulnerability("Clickjacking", self.base_url)
        except Exception as e:
            logging.error(f"Error testing Clickjacking: {e}")

    def test_insecure_deserialization(self):
        payload = '{"rce": "_import_(\'os\').system(\'id\')"}'
        test_url = f"{self.base_url}/deserialize"
        try:
            response = self.session.post(test_url, data=payload, timeout=5)
            if "uid=" in response.text:
                self.log_vulnerability("Insecure Deserialization", test_url)
        except Exception as e:
            logging.error(f"Error testing Insecure Deserialization: {e}")

    def test_security_misconfiguration(self):
        try:
            response = self.session.get(self.base_url, timeout=5)
            if "Server" in response.headers:
                self.log_vulnerability("Security Misconfiguration", self.base_url)
        except Exception as e:
            logging.error(f"Error testing Security Misconfiguration: {e}")

    def test_sensitive_data_exposure(self):
        try:
            response = self.session.get(self.base_url, timeout=5)
            if any(keyword in response.text for keyword in ["password", "credit card", "ssn"]):
                self.log_vulnerability("Sensitive Data Exposure", self.base_url)
        except Exception as e:
            logging.error(f"Error testing Sensitive Data Exposure: {e}")

    def test_broken_authentication(self):
        payloads = ["' OR 1=1--", "' OR '1'='1'"]
        for payload in payloads:
            test_url = f"{self.base_url}/login?username=admin&password={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "Welcome" in response.text:
                    self.log_vulnerability("Broken Authentication", test_url)
            except Exception as e:
                logging.error(f"Error testing Broken Authentication: {e}")

    def test_xxe(self):
        payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [<!ELEMENT foo ANY >
        <!ENTITY xee SYSTEM "file:///etc/passwd" >]>
        <foo>&xee;</foo>"""
        test_url = f"{self.base_url}/xml"
        headers = {"Content-Type": "application/xml"}
        try:
            response = self.session.post(test_url, data=payload, headers=headers, timeout=5)
            if "root:x:0:0:" in response.text:
                self.log_vulnerability("XML External Entities (XXE)", test_url)
        except Exception as e:
            logging.error(f"Error testing XXE: {e}")

    def test_ssrf(self):
        payload = "http://169.254.169.254/latest/meta-data/"
        test_url = f"{self.base_url}?url={payload}"
        try:
            response = self.session.get(test_url, timeout=5)
            if "instance-id" in response.text:
                self.log_vulnerability("Server-Side Request Forgery (SSRF)", test_url)
        except Exception as e:
            logging.error(f"Error testing SSRF: {e}")

    def test_broken_access_control(self):
        test_url = f"{self.base_url}/admin"
        try:
            response = self.session.get(test_url, timeout=5)
            if "Admin Panel" in response.text:
                self.log_vulnerability("Broken Access Control", test_url)
        except Exception as e:
            logging.error(f"Error testing Broken Access Control: {e}")

    def test_host_header_injection(self):
        headers = {"Host": "evil.com"}
        try:
            response = self.session.get(self.base_url, headers=headers, timeout=5)
            if "evil.com" in response.text:
                self.log_vulnerability("HTTP Host Header Injection", self.base_url)
        except Exception as e:
            logging.error(f"Error testing Host Header Injection: {e}")

    def test_logic_flaws(self):
        self.log_vulnerability("Business Logic Flaw", self.base_url)

    def port_scan(self, target_ip):
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    self.open_ports.append(port)
                    self.grab_banner(target_ip, port)
                else:
                    self.closed_ports.append(port)
                sock.close()
            except:
                self.filtered_ports.append(port)

    def grab_banner(self, ip, port):
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode().strip()
            self.service_versions[port] = banner
            sock.close()
        except:
            self.service_versions[port] = "Version Unknown"

    def detect_os(self, target_ip):
        try:
            response = os.popen(f"nmap -O {target_ip}").read()
            match = re.search(r"OS details: (.+)", response)
            if match:
                self.os_info = match.group(1)
            else:
                self.os_info = "OS information could not be determined."
        except:
            self.os_info = "No OS details available"

    def scan(self):
        parsed_url = urlparse(self.base_url)
        if not parsed_url.hostname:
            return [], [], [], [], {}, "Invalid URL"

        try:
            target_ip = socket.gethostbyname(parsed_url.hostname)
        except socket.gaierror:
            return [], [], [], [], {}, "Could not resolve host"

        threads = []
        for test in [
            self.test_sqli, self.test_broken_authentication, self.test_sensitive_data_exposure,
            self.test_xxe, self.test_broken_access_control, self.test_security_misconfiguration,
            self.test_xss, self.test_insecure_deserialization, self.test_logic_flaws
        ]:
            thread = threading.Thread(target=test)
            thread.start()
            threads.append(thread)

        port_thread = threading.Thread(target=self.port_scan, args=(target_ip,))
        port_thread.start()
        threads.append(port_thread)

        os_thread = threading.Thread(target=self.detect_os, args=(target_ip,))
        os_thread.start()
        threads.append(os_thread)

        for thread in threads:
            thread.join()

        return self.vulnerabilities, self.open_ports, self.closed_ports, self.filtered_ports, self.service_versions, self.os_info

def save_report(results, open_ports, closed_ports, filtered_ports, service_versions, os_info, file_name="scan_report"):
    file_path = f"{file_name}.pdf"

    try:
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, "Web Vulnerability Scan Report", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, "Vulnerabilities Found:", ln=True)
        pdf.set_font("Arial", size=12)
        if results:
            for vuln, url, guide in results:
                pdf.cell(200, 10, f"  - {vuln} at {url}".encode('latin-1', 'ignore').decode('latin-1'), ln=True)
                pdf.cell(200, 10, f"    More Info: {guide}".encode('latin-1', 'ignore').decode('latin-1'), ln=True)
            pdf.ln(5)
        else:
            pdf.cell(200, 10, "  No vulnerabilities found.", ln=True)
            pdf.ln(5)

        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, "Port Scan Results:", ln=True)
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, "  Open Ports: " + ', '.join(map(str, open_ports)), ln=True)
        pdf.cell(200, 10, "  Closed Ports: " + ', '.join(map(str, closed_ports)), ln=True)
        pdf.cell(200, 10, "  Filtered Ports: " + ', '.join(map(str, filtered_ports)), ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, "Service Versions:", ln=True)
        pdf.set_font("Arial", size=12)
        if service_versions:
            for port, version in service_versions.items():
                pdf.cell(200, 10, f"  Port {port}: {version}", ln=True)
        else:
            pdf.cell(200, 10, "  No service versions found.", ln=True)
        pdf.ln(5)

        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, "OS Detection:", ln=True)
        pdf.set_font("Arial", size=12)
        if os_info and os_info != "No OS details available":
            pdf.cell(200, 10, f"  Detected OS: {os_info}", ln=True)
        else:
            pdf.cell(200, 10, "  OS information could not be retrieved.", ln=True)
        pdf.ln(10)

        pdf.output(file_path, 'F')
        return file_path
    except Exception as e:
        return f"Error saving PDF: {e}"

def save_json_report(results, open_ports, closed_ports, filtered_ports, service_versions, os_info, target_url, file_name="scan_report"):
    report = {
        "target": target_url,
        "vulnerabilities": [
            {"type": vuln, "url": url, "guide": guide}
            for vuln, url, guide in results
        ],
        "ports": {
            "open": open_ports,
            "closed": closed_ports,
            "filtered": filtered_ports
        },
        "services": service_versions,
        "os_info": os_info
    }

    file_path = f"{file_name}.json"

    try:
        with open(file_path, "w") as f:
            json.dump(report, f, indent=4)
        return file_path
    except Exception as e:
        return f"Error saving JSON: {e}"

def process_with_ai(json_file, model="mistral"):
    import requests

    if not json_file or not os.path.exists(json_file):
        return "No JSON report to process with AI."

    with open(json_file, "r") as f:
        report_data = json.load(f)

    prompt = f"""
    You are an elite cybersecurity specialist and a full-stack developer with extensive experience in web application security. Your task is to act as an **AI-powered vulnerability scanner and auto-patcher**. You will analyze a detailed vulnerability scan report and generate a comprehensive security analysis.
    {json.dumps(report_data, indent=2)}

    **Instructions:**

    1.  **Vulnerability Triage and Filtering:**
        * Carefully review the entire scan report.
        * **Crucially, distinguish between real, exploitable vulnerabilities and potential false positives.** Use your expertise to filter out benign findings that do not pose a genuine security risk.

    2.  **Severity and Prioritization:**
        * For each validated vulnerability, assign an accurate severity rating: **Critical, High, Medium, or Low**.
        * Provide a clear, concise justification for the assigned severity level based on the potential impact and ease of exploitation.

    3.  **Risk Explanation:**
        * Provide a **human-readable explanation** of the risk associated with each vulnerability.
        * Explain what an attacker could achieve by exploiting this issue and the potential impact on the application's data, users, and integrity.

    4.  **Remediation and Code Fixes:**
        * Propose **exact and actionable remediation steps**. These must be specific and practical, not generic advice.
        * Recommendations should include **code fixes, security header configurations, database query changes, input validation rules, or other relevant server/framework configurations.**

    5.  **Auto-Patch Generation:**
        * For each vulnerability, **generate a code snippet that can be directly applied to patch the issue.**
        * The code should be in the correct language (e.g., Python, JavaScript, PHP, etc.) and format as determined by the context of the vulnerability.
        * If a vulnerability can be fixed with a configuration change (e.g., NGINX or Apache config), provide the exact configuration snippet.
        * **Add a comment to each code snippet explaining what it does and why it's a fix.**

    Return the report in a clear, structured format.
    """

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            }
        )

        if response.status_code != 200:
            return f"Ollama error: {response.text}"

        ai_output = response.json().get("response", "").strip()
        
        with open("ai_analysis.json", "w") as out:
            out.write(ai_output)

        return ai_output

    except Exception as e:
        return f"Ollama processing failed: {e}"