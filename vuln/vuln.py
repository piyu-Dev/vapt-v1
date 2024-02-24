import requests
import re
import validators
import dns.resolver
import builtwith
import ssl
import socket
import pickle
import base64
from bs4 import BeautifulSoup
from lxml import etree
from safety import scan as safe

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        # SSL context for handling HTTPS requests
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def check_injection(self):
        injection_patterns = [
            r'[\s\S]*\b(select|insert|update|delete|drop|union|exec|count|'
            r'chr|or|\bon|\blike|\bfrom|\bwhere|\bgroup by|\bhaving|\bunion all|\border by)\b[\s\S]*',
            r'[\s\S]*\b(rm -rf|mkdir|cd|ls|cat|chmod|nc|bash|sh|python|perl|ruby|telnet|wget|curl)\b[\s\S]*',
        ]
        for pattern in injection_patterns:
            if re.search(pattern, self.target_url, re.IGNORECASE):
                return True
        return False

    def check_auth_vulnerability(self):
        if not validators.url(self.target_url):
            print("URL is invalid")
            return False
        try:
            response = requests.get(self.target_url)
            if response.status_code ==  401:
                print("URL might be vulnerable to authentication bypass")
                return True
            elif response.status_code ==  200:
                print("URL is accessible without authentication")
                return True
            else:
                print("URL is secure")
                return False
        except requests.exceptions.RequestException as e:
            print(f"Error accessing URL: {e}")
            return False

    def is_sensitive_data_exposure_vulnerable(self):
        if not ssl.OPENSSL_VERSION:
            return True
        return False

    def check_xxe_vulnerability(self):
        try:
            response = requests.get(self.target_url)
            if response.status_code !=  200:
                print("Failed to fetch XML content from the URL.")
                return False
            parser = etree.XMLParser(resolve_entities=False)
            tree = etree.fromstring(response.content, parser=parser)
            for entity in tree.xpath('//*[starts-with(name(), "!ENTITY")]'):
                print("Potential XXE vulnerability detected: External entity found.")
                return True
            print("No XXE vulnerabilities detected.")
            return False
        except Exception as e:
            print(f"Error checking for XXE vulnerabilities: {e}")
            return False

    def check_broken_excess_control(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT  10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://www.example.com',
            'Origin': 'https://www.example.com',
            'Cache-Control': 'max-age=0',
        }
        payload = {
            'username': 'admin',
            'password': 'password',
        }
        try:
            response_get = requests.get(self.target_url, headers=headers)
            print(f"GET request response status code: {response_get.status_code}")
            response_post = requests.post(self.target_url, headers=headers, data=payload)
            print(f"POST request response status code: {response_post.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Error sending requests: {e}")

    def check_security_misconfiguration(self):
        try:
            response = requests.get(self.target_url)
            for cookie in response.cookies:
                if not cookie.secure:
                    print(f"Insecure Cookie Detected: {cookie.name}")
            if response.url.startswith('http://') and self.target_url.startswith('https://'):
                print("Insecure Content Delivery Detected: HTTPS content delivered over HTTP")
        except requests.exceptions.RequestException as e:
            print(f"Error checking for security misconfigurations: {e}")

    def check_cross_site_scripting(self):
        payload = "<script>alert('XSS')</script>"
        response = requests.post(self.target_url, data={"input": payload}, verify=False)
        if payload in response.text:
            print("Potential XSS vulnerability detected.")
        else:
            print("XSS vulnerability not detected.")

    def check_insecure_deserialization(self):
        class MaliciousObject:
            def __reduce__(self):
                return (eval, ('print("Insecure Deserialization Detected")',))
        serialized_payload = pickle.dumps(MaliciousObject())
        encoded_payload = base64.b64encode(serialized_payload).decode('utf-8')
        try:
            response = requests.post(self.target_url, data={'payload': encoded_payload})
            print(f"Response status code: {response.status_code}")
            print(response.text)
        except requests.exceptions.RequestException as e:
            print(f"Error sending request: {e}")



    def check_insufficient_logging_and_monitoring(self):
        try:
            response = requests.get(self.target_url)
            security_headers = {
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'X-XSS-Protection',
            }
            missing_headers = security_headers - set(response.headers.keys())
            if missing_headers:
                print(f"Potential insufficient logging and monitoring: Missing headers {missing_headers}")
            if "error" in response.text.lower():
                print("Potential insufficient logging and monitoring: Detailed error message detected")
            else:
                print("No detailed error messages detected")
        except requests.exceptions.RequestException as e:
            print(f"Error checking for insufficient logging and monitoring: {e}")

def main():
    target_url = input("Enter the target URL: ")
    scanner = VulnerabilityScanner(target_url)

    if scanner.check_injection():
        print("Potential injection vulnerability detected")

    if scanner.check_auth_vulnerability():
        print("Potential authentication vulnerability detected")

    if scanner.is_sensitive_data_exposure_vulnerable():
        print("Potential sensitive data exposure vulnerability detected")

    if scanner.check_xxe_vulnerability():
        print("Potential XXE vulnerability detected")

    if scanner.check_broken_excess_control():
        print("Potential broken excess control vulnerability detected")

    if scanner.check_security_misconfiguration():
        print("Potential security misconfiguration detected")

    if scanner.check_cross_site_scripting():
        print("Potential cross-site scripting vulnerability detected")

    if scanner.check_insecure_deserialization():
        print("Potential insecure deserialization vulnerability detected")


    if scanner.check_insufficient_logging_and_monitoring():
        print("Potential insufficient logging and monitoring detected")

if __name__ == "__main__":
    main()
