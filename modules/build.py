import bs4
import re
import requests
import concurrent.futures
import multiprocessing
import json
import os
import sys
import signal
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time

def bing_search(query, num_results=2):
    """Performs a Bing search and returns a list of top result URLs."""
    search_url = f"https://www.bing.com/search?q={query.replace(' ', '+')}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
    }

    response = requests.get(search_url, headers=headers)
    if response.status_code != 200:
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    
    return [li.select_one("h2 a")["href"] for li in soup.select("li.b_algo")[:num_results] if li.select_one("h2 a")]





def send_request(type, message,status=None):
    if status != None:
        payload = {"type":type,"value": message,'status':status}
    else:
        payload = {"type":type,"value": message}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post("http://127.0.0.1:12531/send_message", json=payload, headers=headers)
        response.raise_for_status()  # Raise an error for bad responses (4xx and 5xx)
        return response.json()  # Return the response JSON if available
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
    
class DirectoryScanner:
    def __init__(self, target_url, wordlist='./data/etc/common.txt', threads=None):
        self.target_url = target_url
        self.wordlist = wordlist
        self.threads = threads or (multiprocessing.cpu_count() * 2)
        self.executor = None
        self.results_file = "./data/scan.json"
        self.shutdown_flag = False
        
        # Header Rotation List
        self.headers_list = [
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.9",
                "Referer": "https://www.google.com/",
                "DNT": "1",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache"
            },
            {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
                "Accept-Language": "en-US,en;q=0.8",
                "Referer": "https://www.bing.com/",
                "Cache-Control": "max-age=0",
                "TE": "Trailers"
            },
            {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                "Accept-Language": "en-US,en;q=0.7",
                "Referer": "https://duckduckgo.com/",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1"
            }
        ]

        signal.signal(signal.SIGINT, self.cleanup)
        self.load_existing_results()

    def scan_directory(self, directory):
        if self.shutdown_flag:
            return None
        
        full_url = f"{self.target_url}/{directory}"
        print(f"[*] Scanning: {full_url}")

        for i, headers in enumerate(self.headers_list):
            try:
                response = requests.get(full_url, headers=headers, timeout=2, allow_redirects=False)
                if response.status_code in [200, 403, 401, 500]:
                    print(f"[+] Found: {full_url} ({response.status_code}) using headers {i+1}")
                    send_request("url", full_url, response.status_code)
                    self.append_result(full_url)
                    return full_url
            except requests.exceptions.RequestException as e:
                print(f"❌ Request failed for {full_url} with headers {i+1}: {e}")

        print(f"[-] No response for {full_url}, tried all headers.")
        return None

    def load_wordlist(self):
        if not os.path.exists(self.wordlist):
            print("Wordlist file not found!")
            return []
        with open(self.wordlist, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]

    def load_existing_results(self):
        if not os.path.exists("./data"):
            os.makedirs("./data")
        
        try:
            with open(self.results_file, "r", encoding="utf-8") as f:
                data = json.load(f)

                # ✅ Ensure `data` is a dictionary (not a list or other type)
                if not isinstance(data, dict):
                    print("⚠️ JSON data is not a dictionary. Resetting to empty dict.")
                    data = {}

        except (FileNotFoundError, json.JSONDecodeError):
            print("⚠️ File not found or JSON is invalid. Initializing to empty dict.")
            data = {}

        # ✅ Ensure "dict" key exists
        data.setdefault("dict", [])

        # ✅ Store found directories as a set
        self.found_dirs = set(data["dict"])

        # ✅ Save back to file to ensure consistency
        with open(self.results_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)


    def append_result(self, result):
        self.found_dirs.add(result)

        # Load existing data or initialize structure
        try:
            with open(self.results_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    data = {"dict": []}
        except (FileNotFoundError, json.JSONDecodeError):
            print("⚠️ Warning: scan.json is missing or corrupted. Resetting file.")
            data = {"dict": []}

        # Ensure 'dict' key exists
        if "dict" not in data or not isinstance(data["dict"], list):
            data["dict"] = []

        # Append new result only if it doesn't already exist
        if result not in data["dict"]:
            data["dict"].append(result)

        # Preserve existing metadata (date, target, dns_host) if available
        existing_metadata = {key: data[key] for key in ["date", "target", "dns_host"] if key in data}
        merged_data = {**existing_metadata, "dict": data["dict"]}

        # Save updated data back to scan.json
        with open(self.results_file, "w", encoding="utf-8") as f:
            json.dump(merged_data, f, indent=4)

        print(f"✅ Added {result} to scan.json")



    def run_scan(self):
        directories = self.load_wordlist()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as self.executor:
            futures = {self.executor.submit(self.scan_directory, dir): dir for dir in directories}
            try:
                for future in concurrent.futures.as_completed(futures):
                    if self.shutdown_flag:
                        break
                    future.result()
            except KeyboardInterrupt:
                print("\nScan interrupted. Saving results...")
                self.cleanup()
                sys.exit(1)
        print("\nScan complete. Found directories:")
        for directory in self.found_dirs:
            print(directory)

    def cleanup(self, signum=None, frame=None):
        print("\nStopping scan...")
        self.shutdown_flag = True
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
        sys.exit(0)


class WebSpider:
    def __init__(self, start_url, max_depth=2, timeout=5, scan_file="./data/scan.json"):
        self.start_url = start_url
        self.max_depth = max_depth
        self.timeout = timeout
        self.scan_file = scan_file  # JSON file to store results

        self.visited_urls = set()  # Tracks visited pages
        self.discovered_urls = set()  # Stores all unique URLs
        self.discovered_files = set()  # Stores specific file paths (.php, .pdf, .js, etc.)

        # Load existing scan data or create a new one
        self.load_scan_data()

    def load_scan_data(self):
        """Loads existing scan data or initializes it if missing."""
        if os.path.exists(self.scan_file):
            try:
                with open(self.scan_file, "r") as f:
                    data = json.load(f)
                if "dict" not in data:
                    data["dict"] = []  # Ensure "dict" key exists
            except (json.JSONDecodeError, IOError):
                print("⚠️ Warning: scan.json is corrupted. Resetting file.")
                data = {"dict": []}  # Reset file if corrupted
        else:
            data = {"dict": []}  # Create new structure if file is missing

        self.scan_data = data  # Store in memory

    def save_scan_data(self):
        """Saves updated scan results to the JSON file."""
        try:
            with open(self.scan_file, "w") as f:
                json.dump(self.scan_data, f, indent=4)
        except IOError as e:
            print(f"❌ Error saving scan results: {e}")

    def fetch_urls(self, target_url):
        """Send an HTTP request and extract all links, paths, and file references."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Referer": "https://www.google.com/",
            "DNT": "1",
        }
        try:
            response = requests.get(target_url, headers=headers, timeout=self.timeout)
            response.raise_for_status()  # Raises error for HTTP errors

            if "text/html" not in response.headers.get("Content-Type", ""):
                print(f"⚠️ Skipping non-HTML content: {target_url}")
                return set(), set()

            print(f"✅ Crawled: {target_url}")
            send_request('url', target_url, response.status_code)
            soup = BeautifulSoup(response.text, "html.parser")

            found_links, found_files = set(), set()
            for tag in soup.find_all(["a", "link", "script", "img", "iframe"]):
                link = tag.get("href") or tag.get("src")
                if link:
                    full_url = urljoin(target_url, link)
                    if re.search(r'\.(php|pdf|js|css|png|jpg|jpeg|gif|svg)$', full_url, re.IGNORECASE):
                        found_files.add(full_url)
                    else:
                        found_links.add(full_url)

            regex_links = re.findall(r"https?://[^\s\"'<>()]+", response.text)
            found_links.update(regex_links)

            return found_links, found_files

        except requests.exceptions.Timeout:
            print(f"⏳ Timeout: {target_url} - Skipping...")
        except requests.exceptions.ConnectionError:
            print(f"❌ Connection Error: {target_url} - Check network/DNS")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                print(f"⚠️ Bad Request (400): {target_url} - Possible invalid URL or input")
            elif 400 <= e.response.status_code < 500:
                print(f"⚠️ Client Error {e.response.status_code}: {target_url} - Skipping...")
            elif 500 <= e.response.status_code < 600:
                print(f"❗ Server Error {e.response.status_code}: {target_url} - Might retry later")
        except requests.exceptions.RequestException as e:
            print(f"❌ Failed to crawl: {target_url} - {e}")

        return set(), set()
    
    
    
    def crawl(self, url, depth=0):
        """Recursively crawl URLs up to max depth."""
        if depth > self.max_depth or url in self.visited_urls:
            return

        self.visited_urls.add(url)
        new_links, new_files = self.fetch_urls(url)

        self.discovered_urls.update(new_links)
        self.discovered_files.update(new_files)

        for link in new_links:
            if (
                link not in self.visited_urls
                and urlparse(link).netloc == urlparse(self.start_url).netloc  # Stay within the domain
            ):
                time.sleep(1)  # Respect server load
                self.crawl(link, depth + 1)  # Recursively crawl the new link

    def update_scan_data(self):
        """Update scan.json with extracted URLs & paths."""
        try:
            with open(self.scan_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict):
                    data = {"dict": []}
        except (FileNotFoundError, json.JSONDecodeError):
            print("⚠️ Warning: scan.json is missing or corrupted. Resetting file.")
            data = {"dict": []}

        # Ensure 'dict' key exists
        data.setdefault("dict", [])

        # Append new URLs & file paths only if they are not already present
        new_entries = list(set(self.discovered_urls | self.discovered_files) - set(data["dict"]))
        if new_entries:
            data["dict"].extend(new_entries)

        # Save updated data without overwriting existing entries
        with open(self.scan_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        print(f"✅ {len(new_entries)} new entries added to scan.json")


    def start(self):
            """Start the spider from the initial URL."""
            print(f"🚀 Starting crawl from: {self.start_url}")
            self.crawl(self.start_url)

            print("\n🔗 Extracted URLs:")
            for link in sorted(self.discovered_urls):
                send_request('url',link,200)

            print("\n📂 Extracted File Paths (.php, .pdf, .js, etc.):")
            for file in sorted(self.discovered_files):
                print(file)

            # Update scan.json
            self.update_scan_data()
            print("\n✅ Scan results saved to:", self.scan_file)