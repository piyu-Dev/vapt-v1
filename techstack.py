import requests
import re

def find_tech_stack(url):
    try:
        # Fetch the HTML content of the website
        response = requests.get(url)
        html_content = response.text
        
        # Define regular expressions to search for common technology stack indicators
        tech_stack_patterns = {
            'JavaScript': r'<script[^>]*src=["\']([^"\']+)["\'][^>]*></script>',
            'CSS': r'<link[^>]*href=["\']([^"\']+)["\'][^>]*>',
            'Frameworks': r'<(?:script|link)[^>]*(?:src|href)=["\'][^"\']*\/(angular|react|vue|django|laravel|rails)[^"\']*["\']',
            'Server-side': r'(?:Node.js|Express|Flask|Django|Rails)',
            'Database': r'(?:MySQL|PostgreSQL|MongoDB|SQLite)',
            'Web Server': r'(?:Apache|Nginx)',
            # Add more patterns as needed
        }
        
        # Search for technology stack indicators in the HTML content
        tech_stack_info = {}
        for stack_type, pattern in tech_stack_patterns.items():
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            if matches:
                tech_stack_info[stack_type] = matches

        return tech_stack_info
        
    except Exception as e:
        print(f"An error occurred: {e}")

def print_tech_stack(tech_stack):
    if tech_stack:
        print("Technology Stack:")
        for stack_type, technologies in tech_stack.items():
            print(f"{stack_type}:")
            for tech in technologies:
                print(f"  - {tech}")
    else:
        print("No technology stack information found.")

# Example usage
website_url = input('enter the url: ')
tech_stack = find_tech_stack(website_url)
print_tech_stack(tech_stack)
