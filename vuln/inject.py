import re

def is_injection_vulnerable(input_string):
    # Regular expression patterns to detect potential injection vulnerabilities
    injection_patterns = [
        r'[\s\S]*\b(select|insert|update|delete|drop|union|exec|count|'
        r'chr|or|\bon|\blike|\bfrom|\bwhere|\bgroup by|\bhaving|\bunion all|\border by)\b[\s\S]*',
        r'[\s\S]*\b(rm -rf|mkdir|cd|ls|cat|chmod|nc|bash|sh|python|perl|ruby|telnet|wget|curl)\b[\s\S]*',
    ]

    # Check if any of the injection patterns are present in the input string
    for pattern in injection_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True

    return False

# Example usage
input_string = "https://www.djsce.ac.in"
if is_injection_vulnerable(input_string):
    print("The input string is potentially injection vulnerable.")
else:
    print("The input string is not injection vulnerable.")