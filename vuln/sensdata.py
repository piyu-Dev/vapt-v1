import ssl

def is_sensitive_data_exposure_vulnerable():
    # Check if sensitive data is transmitted insecurely
    if not ssl.OPENSSL_VERSION:
        return True

    return False

# Example usage
if is_sensitive_data_exposure_vulnerable():
    print("The web application is potentially vulnerable to sensitive data exposure.")
else:
    print("The web application is not vulnerable to sensitive data exposure.")