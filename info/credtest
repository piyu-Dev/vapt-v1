import requests

def perform_vapt(url):
    try:
        # Send a request to the website
        response = requests.get(url)
        if response.status_code == 200:
            print("Website is accessible.")

            # Check for common vulnerabilities
            check_for_vulnerabilities(response)
        else:
            print("Failed to access the website. Status code:", response.status_code)
    except Exception as e:
        print("An error occurred:", str(e))

def check_for_vulnerabilities(response):
    # Check for common vulnerabilities
    check_xss(response)
    check_sql_injection(response)
    # Add more vulnerability checks as needed

def check_xss(response):
    # Example: Check for Cross-Site Scripting (XSS) vulnerability
    if "<script>" in response.text:
        print("Potential XSS vulnerability found.")

def check_sql_injection(response):
    # Example: Check for SQL Injection vulnerability
    if "SQL syntax error" in response.text:
        print("Potential SQL Injection vulnerability found.")

# Example usage
url = input("Enter website URL: ")
perform_vapt(url)
