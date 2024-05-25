import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, RetryError
from datetime import datetime
from urllib.parse import urlparse
import builtwith

# Initialize colorama
init(autoreset=True)

def log_output(message):
    if log_file:
        with open(log_file, 'a') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def read_subdomains(file):
    try:
        with open(file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
            if not subdomains:
                msg = "No subdomains found in the file."
                log_output(msg)
            return subdomains
    except FileNotFoundError:
        msg = f"File '{file}' not found."
        log_output(msg)
        return []
    except Exception as e:
        msg = f"An error occurred while reading the file: {e}"
        log_output(msg)
        return []

class RetryableHTTPError(requests.RequestException):
    pass

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10),
       retry=(retry_if_exception_type(RetryableHTTPError) | retry_if_exception_type(requests.ConnectionError)))
def get_response(subdomain):
    response = requests.get(f'http://{subdomain}', timeout=5)
    if response.status_code in [503]:
        raise RetryableHTTPError(f"Server error: {response.status_code} for url: {response.url}")
    response.raise_for_status()  # Raise an HTTPError for bad responses
    return response

def categorize_js_files(js_files, subdomain):
    internal_js = []
    external_js = []
    for js_file in js_files:
        if urlparse(js_file).netloc == '' or urlparse(js_file).netloc == subdomain:
            internal_js.append(js_file)
        else:
            external_js.append(js_file)
    return internal_js, external_js

def find_js_files(subdomain):
    try:
        response = get_response(subdomain)
        soup = BeautifulSoup(response.text, 'html.parser')
        js_files = [script['src'] for script in soup.find_all('script') if script.get('src')]
        return js_files
    except requests.RequestException:
        return []
    except RetryError:
        return []

def get_technologies(subdomain):
    try:
        tech_info = builtwith.builtwith(f'http://{subdomain}')
        return tech_info
    except Exception as e:
        msg = f"Error fetching technologies for {subdomain}: {e}"
        log_output(msg)
        return {}

def process_subdomain(subdomain):
    try:
        js_files = find_js_files(subdomain)
        if not js_files:
            return  # Skip printing and logging for subdomains with no JS files

        tech_info = get_technologies(subdomain)

        if tech_info:
            msg = f"\n{Fore.MAGENTA}Technologies used by {subdomain}:{Fore.RESET}"
            print(msg)
            log_output(f"Technologies used by {subdomain}:")
            for tech, items in tech_info.items():
                tech_msg = f"{Fore.CYAN}{tech}: {', '.join(items)}{Fore.RESET}"
                print(tech_msg)
                log_output(f"{tech}: {', '.join(items)}")

        if js_files:
            internal_js, external_js = categorize_js_files(js_files, subdomain)
            if internal_js:
                msg = f"\n{Fore.GREEN}Internal JavaScript files found in {subdomain}:{Fore.RESET}"
                print(msg)
                log_output(f"Internal JavaScript files found in {subdomain}:")
                for js_file in internal_js:
                    file_msg = f"{Fore.BLUE}{js_file}{Fore.RESET}"
                    print(file_msg)
                    log_output(js_file)

            if external_js:
                msg = f"\n{Fore.GREEN}External JavaScript files found in {subdomain}:{Fore.RESET}"
                print(msg)
                log_output(f"External JavaScript files found in {subdomain}:")
                for js_file in external_js:
                    file_msg = f"{Fore.BLUE}{js_file}{Fore.RESET}"
                    print(file_msg)
                    log_output(js_file)

    except Exception as e:
        msg = f"Unexpected error processing {subdomain}: {e}"
        log_output(msg)

def main():
    global log_file
    log_file = None

    parser = argparse.ArgumentParser(description='Find JavaScript files in subdomains and gather technology stack information.')
    parser.add_argument('--domain', type=str, help='Specify a single domain to check.')
    parser.add_argument('--file', type=str, default='subdomains.txt', help='File containing list of subdomains to check.')
    parser.add_argument('--output', type=str, help='File to save the output.')

    args = parser.parse_args()

    if args.output:
        log_file = args.output

    if args.domain:
        process_subdomain(args.domain)
    else:
        subdomains = read_subdomains(args.file)
        if not subdomains:
            return

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {executor.submit(process_subdomain, subdomain): subdomain for subdomain in subdomains}
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    future.result()
                except Exception as e:
                    msg = f"Error processing {subdomain}: {e}"
                    log_output(msg)

if __name__ == "__main__":
    main()
