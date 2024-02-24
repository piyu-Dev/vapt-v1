import os

def is_broken_authentication_vulnerable():
    # Check if passwords are stored in plaintext
    if os.path.exists('passwords.txt'):
        return True

    # Check if weak encryption algorithms are used
    if os.path.exists('weak_encryption.py'):
        return True

    # Check if HTTPS is not used
    if os.environ.get('HTTPS') != 'on':
        return True

    return False

# Example usage
if is_broken_authentication_vulnerable():
    print("The web application is potentially vulnerable to broken authentication.")
else:
    print("The web application is not vulnerable to broken authentication.")