import requests

def get_wayback_url(original_url):
    wayback_api_url = f"http://archive.org/wayback/available?url={original_url}"
    
    try:
        response = requests.get(wayback_api_url)
        response.raise_for_status()
        data = response.json()
        print(data)
        
        if 'closest' in data['archived_snapshots']:
            return data['archived_snapshots']['closest']['url']
        else:
            return "Wayback Machine doesn't have a snapshot for this URL."
    
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"


original_url = input("Enter the URL you want to retrieve from Wayback Machine: ")
wayback_url = get_wayback_url(original_url)
print("Wayback URL:", wayback_url)


