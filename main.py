import argparse
import logging
import os
import re
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define constants for sensitive patterns
API_KEY_REGEX = r"(?:API_KEY|API key|api_key)\s*[:=]\s*[\"']?([A-Za-z0-9_-]+)[\"']?"
DB_CREDENTIAL_REGEX = r"(?:DB_PASSWORD|DB password|db_password)\s*[:=]\s*[\"']?([A-Za-z0-9_-]+)[\"']?"
IP_ADDRESS_REGEX = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Identifies code snippets and sensitive data exposed on public websites or repositories.")
    parser.add_argument("search_term", help="The search term to use (e.g., 'API_KEY in:github').  Use Google Dorks.")
    parser.add_argument("-o", "--output", help="Output file to save results (optional).", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (debug level).")
    return parser

def search_public_code(search_term):
    """
    Simulates searching public code repositories (e.g., via a search engine).
    This function is a placeholder and does not perform actual web searches.
    Replace this with actual search engine API calls.

    Args:
        search_term (str): The search term to use.

    Returns:
        list: A list of simulated search results (strings).  In reality, these would come from the search API.
    """
    # Placeholder for actual search engine API integration (e.g., Google Custom Search API)
    # Replace this with actual API calls to search public code repositories.
    # Example:
    #   results = google_search(search_term)
    #   return results

    # Simulate some results for testing purposes
    simulated_results = [
        f"Example result 1: API_KEY = 'abcdef12345'",
        f"Example result 2: DB_PASSWORD = 'securepassword'",
        f"Example result 3: Internal IP: 192.168.1.10",
        f"Example result 4: No sensitive data here.",
        f"Example result 5: API_KEY = 'ghijk67890' and IP 10.0.0.5",
    ]
    logging.info(f"Simulating search results for term: {search_term}")
    return simulated_results



def analyze_results(results):
    """
    Analyzes the search results for sensitive data.

    Args:
        results (list): A list of strings representing search results.

    Returns:
        dict: A dictionary containing lists of found API keys, database credentials, and IP addresses.
    """
    api_keys = []
    db_credentials = []
    ip_addresses = []

    for result in results:
        # Extract API keys
        api_key_matches = re.findall(API_KEY_REGEX, result)
        api_keys.extend(api_key_matches)

        # Extract database credentials
        db_credential_matches = re.findall(DB_CREDENTIAL_REGEX, result)
        db_credentials.extend(db_credential_matches)

        # Extract IP addresses
        ip_address_matches = re.findall(IP_ADDRESS_REGEX, result)
        ip_addresses.extend(ip_address_matches)

    return {
        "api_keys": list(set(api_keys)),  # Remove duplicates
        "db_credentials": list(set(db_credentials)),  # Remove duplicates
        "ip_addresses": list(set(ip_addresses)),  # Remove duplicates
    }


def save_results(results, output_file):
    """
    Saves the analysis results to a file.

    Args:
        results (dict): A dictionary containing the analysis results.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            f.write("API Keys:\n")
            for key in results["api_keys"]:
                f.write(f"- {key}\n")

            f.write("\nDatabase Credentials:\n")
            for cred in results["db_credentials"]:
                f.write(f"- {cred}\n")

            f.write("\nIP Addresses:\n")
            for ip in results["ip_addresses"]:
                f.write(f"- {ip}\n")

        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Error saving results to file: {e}")


def main():
    """
    Main function to execute the code exposure checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    search_term = args.search_term

    if not search_term:
        logging.error("Search term cannot be empty.")
        sys.exit(1)

    try:
        results = search_public_code(search_term)
        analysis_results = analyze_results(results)

        if analysis_results["api_keys"] or analysis_results["db_credentials"] or analysis_results["ip_addresses"]:
            logging.info("Potential sensitive data exposure found!")
            logging.info(f"API Keys: {analysis_results['api_keys']}")
            logging.info(f"Database Credentials: {analysis_results['db_credentials']}")
            logging.info(f"IP Addresses: {analysis_results['ip_addresses']}")

            if args.output:
                save_results(analysis_results, args.output)
        else:
            logging.info("No sensitive data exposure found.")


    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Example usage from within the code (for testing/demonstration)
    # To use from the command line, call this script like:
    # python main.py "API_KEY in:github" -o output.txt
    # You can also run it without the output flag if you just want to view in console.
    main()