import requests
import concurrent.futures
import json
import os
from  modules._recon_ import  load_json
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import trafilatura
from trafilatura.settings import use_config
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lsa import LsaSummarizer
from modules.build import send_request

custom_config = use_config()

# Network settings
custom_config.set("DEFAULT", "DOWNLOAD_TIMEOUT", "30")  # Drop request after 30 sec
custom_config.set("DEFAULT", "SLEEP_TIME", "5")  # Time between requests

# Input file size limits
custom_config.set("DEFAULT", "MAX_FILE_SIZE", "20000000")  # Max input file size (20MB)
custom_config.set("DEFAULT", "MIN_FILE_SIZE", "10")  # Min input file size

# Extraction settings
custom_config.set("DEFAULT", "MIN_EXTRACTED_SIZE", "250")  # Acceptable size in characters
custom_config.set("DEFAULT", "MIN_OUTPUT_SIZE", "1")  # Absolute min text output
custom_config.set("DEFAULT", "MIN_EXTRACTED_COMM_SIZE", "250")  # Min extracted comment size
custom_config.set("DEFAULT", "MIN_OUTPUT_COMM_SIZE", "1")  # Min output comment size
custom_config.set("DEFAULT", "EXTRACTION_TIMEOUT", "30")  # Prevent CPU overload, 0 to disable

# Deduplication settings
custom_config.set("DEFAULT", "MIN_DUPLCHECK_SIZE", "100")  # Min text size for deduplication
custom_config.set("DEFAULT", "MAX_REPETITIONS", "2")  # Max duplicates allowed

# Metadata settings
custom_config.set("DEFAULT", "EXTENSIVE_DATE_SEARCH", "on")  # Improve date detection

# Navigation settings
custom_config.set("DEFAULT", "EXTERNAL_URLS", "off")  # Ignore external URLs in feeds
custom_config.set("DEFAULT", "MAX_REDIRECTS", "2")
def extract_summary_from_html(url, num_sentences=5, save_path="./data/scan.json", max_retries=3):
    """Extracts summary, headings, CVE IDs, UNIX-like paths, and links from a webpage with undetectable headers."""

    headers_list = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "DNT": "1",
            "Referer": "https://www.google.com/",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache"
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
            "Accept-Language": "en-GB,en;q=0.8",
            "DNT": "1",
            "Referer": "https://www.bing.com/",
            "Cache-Control": "max-age=0",
        },
        {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Accept-Language": "fr-FR,fr;q=0.7",
            "Referer": "https://duckduckgo.com/",
            "TE": "Trailers",
            "Cache-Control": "no-store"
        }
    ]

    for attempt in range(max_retries):
        try:
            headers = headers_list[attempt % len(headers_list)]  # Rotate headers
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            break  # Exit loop if request is successful
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}. Attempt {attempt + 1} of {max_retries}")
            if attempt == max_retries - 1:
                return {"error": f"Failed to fetch page after {max_retries} attempts"}

    soup = BeautifulSoup(response.text, "html.parser")

    title = soup.title.text if soup.title else "No Title"
    headings = [h.get_text(strip=True) for h in soup.find_all(["h1", "h2", "h3"])]

    content = trafilatura.extract(response.text, config=custom_config) or "No content extracted"

    parser = PlaintextParser.from_string(content, Tokenizer("english"))
    summarizer = LsaSummarizer()
    summary = [str(sentence) for sentence in summarizer(parser.document, num_sentences)]

    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}')
    cve_ids = list(set(cve_pattern.findall(" ".join(summary))))

    file_path_pattern = re.compile(r'(?:\./|/)[\w./-]+')
    extracted_paths = list(set(file_path_pattern.findall(" ".join(headings + summary))))

    link_pattern = re.compile(r"https?://[^\s\"'>]+")
    extracted_links = list(set(link_pattern.findall(" ".join(summary))))

    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    try:
        with open(save_path, "r") as file:
            data = json.load(file)
            if not isinstance(data, dict):
                data = {}
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    data["p1"] = list(set(data.get("p1", []) + extracted_paths))
    data["p1_link"] = list(set(data.get("p1_link", []) + extracted_links))

    with open(save_path, "w") as file:
        json.dump(data, file, indent=4)

    return {
        "title": title,
        "headings": headings,
        "summary": summary,
        "cve_ids": cve_ids
    }



    
def fetch_url_p1(path,host):
    """Fetches a specific path on a target IP while using a custom Host header."""

    # Load scan.json
    data = load_json()

    # Extract target IP and custom host
    target_ip = data.get("target", "").strip()


    # Ensure we have a valid IP and custom host
    if not target_ip:
        return {"error": "No target IP found in scan.json"}
    if not host:
        return {"error": "No custom host found in scan.json"}

    # Construct the full URL
    url = f"http://{target_ip}{path}"

    # Headers with custom Host
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Host": host  # Set custom host while requesting the IP
    }

    try:
        response = requests.get(url, headers=headers, timeout=3)
        custom_url = f"http://{host}{path}"# Set timeout for efficiency
        send_request("url", custom_url , response.status_code)  # Live status update
        return {"type": "url", "value": url, "host": host, "status": response.status_code}

    except requests.exceptions.Timeout:
        print(f"Timeout Error: {url}")
        return {"type": "url", "value": url, "host": host, "status": "Timeout"}
    
    except requests.exceptions.ConnectionError:
        print(f"Connection Error: {url}")
        return {"type": "url", "value": url, "host": host, "status": "Connection Error"}
    
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {url} - {e.response.status_code}")
        return {"type": "url", "value": url, "host": host, "status": f"HTTP Error {e.response.status_code}"}
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {url} - {e}")
        return {"type": "url", "value": url, "host": host, "status": "Request Error"}


def fetch_url(path="/.git/"):
    """Fetches a specific path on a target IP while using a custom Host header."""

    # Load scan.json
    data = load_json()

    # Extract target IP and custom host
    target_ip = data.get("target", "").strip()
    custom_host = data.get("dns_host", "").strip()

    # Ensure we have a valid IP and custom host
    if not target_ip:
        return {"error": "No target IP found in scan.json"}
    if not custom_host:
        return {"error": "No custom host found in scan.json"}

    # Construct the full URL
    url = f"http://{target_ip}{path}"

    # Headers with custom Host
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Host": custom_host  # Set custom host while requesting the IP
    }

    try:
        response = requests.get(url, headers=headers, timeout=3)  # Set timeout for efficiency
        send_request("url", url, response.status_code)  # Live status update
        return {"type": "url", "value": url, "host": custom_host, "status": response.status_code}

    except requests.exceptions.Timeout:
        print(f"Timeout Error: {url}")
        return {"type": "url", "value": url, "host": custom_host, "status": "Timeout"}
    
    except requests.exceptions.ConnectionError:
        print(f"Connection Error: {url}")
        return {"type": "url", "value": url, "host": custom_host, "status": "Connection Error"}
    
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {url} - {e.response.status_code}")
        return {"type": "url", "value": url, "host": custom_host, "status": f"HTTP Error {e.response.status_code}"}
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {url} - {e}")
        return {"type": "url", "value": url, "host": custom_host, "status": "Request Error"}

def p1_url(scan_file="./data/scan.json"):
    """Checks response status for all URLs in 'p1_link' in scan.json (sequential execution)."""

    # Ensure scan.json exists
    if not os.path.exists(scan_file):
        return {"error": "scan.json not found"}

    # Load scan.json
    try:
        with open(scan_file, "r") as file:
            data = json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"error": "Invalid scan.json file"}

    # Extract URLs from 'p1_link'
    urls = data.get("p1_link", [])
    if not urls:
        return {"error": "No URLs found in 'p1_link' key"}

    results = []  # Store scan results

    # Process each URL
    for url in urls:
        parsed_url = urlparse(url)  # Parse the URL
        domain = parsed_url.netloc  # Extract domain (e.g., dev.linkvortex.htb)
        path = parsed_url.path or "/"  # Extract path (default to "/")

        # Fetch each URL with the extracted domain and path
        result = fetch_url_p1(path, domain)
        results.append(result)

    return results


def p1_dict(scan_file="./data/scan.json", max_threads=10):
    """Performs fast dictionary-based scanning using threading."""

    
    if not os.path.exists(scan_file):
        return {"error": "scan.json not found"}

    # Load scan.json
    try:
        with open(scan_file, "r") as file:
            data = json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"error": "Invalid scan.json file"}

    # Extract base URL
    base_url = data.get("dns_host") or data.get("target")
    if not base_url:
        return {"error": "No valid base URL (dns_host or target) found in scan.json"}

    # Ensure it's a valid HTTP/HTTPS URL
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    # Extract dictionary paths
    wordlist = data.get("p1", [])
    if not wordlist:
        return {"error": "No paths found in 'p1' key"}

    # Construct full URLs to scan
    urls = [f"{base_url}{path}" for path in wordlist]

    results = []  # Store scan results

    # Perform fast scanning using threading
    with concurrent.futures.ThreadPoolExecutor(max_threads) as executor:
        results = list(executor.map(fetch_url, urls))

    return results






