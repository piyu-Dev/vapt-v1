from googlesearch import search

def google_dork(query, num_results=10):
    """
    Perform Google dorking and print search results.

    Args:
    - query: The Google search query.
    - num_results: Number of search results to retrieve (default is 10).
    """
    try:
        # Perform Google search using the query
        search_results = search(query, num=num_results, stop=num_results)

        # Print the search results
        print(f"Google Dork Query: {query}")
        print("Search Results:")
        for i, result in enumerate(search_results, start=1):
            print(f"{i}. {result}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Example usage
    query = "site:djsce.ac.in filetype:pdf confidential"
    num_results = 50
    google_dork(query, num_results)
