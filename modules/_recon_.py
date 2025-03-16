import re
import json
import requests
import concurrent.futures
from icmplib import ping ,exceptions
from bs4 import BeautifulSoup
from urllib.parse import urlparse,urljoin
import socket
import psutil
import scapy.all as scapy
import concurrent.futures
import os 
import hashlib

DEFAULT_TIMEOUT = 1



def extract_ip_address(sentence):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    

    match = re.search(ip_pattern, sentence)
    
    
    return match.group(0) if match else None

def is_target():
    data = load_json()
    if data["target"]:
        return True
    else:
        return False

def target_val():
    data = load_json()
    if data["target"]:
        return data["target"]
    else:
        return None
    
def return_hid():
    with open('./data/hid.json', 'r') as file:
        data =  json.load(file)
    return data['hid']
    
def dns_val():
    data = load_json()  # Replace with actual data retrieval
    return data.get("dns_host", "")  # Return "" if 'dns_host' is missing

def update_hid(new_data):
    # Load existing data from the JSON file
    with open('./data/hid.json', 'r') as file:
        data = json.load(file)
    
    # Update the 'hid' key with the new data
    data['hid'] = new_data
    
    # Write the updated data back to the JSON file
    with open('./data/hid.json', 'w') as file:
        json.dump(data, file, indent=4)  # Added indent for better readability
def load_json():

    filename = "./data/scan.json"
    if not os.path.exists(filename) or os.stat(filename).st_size == 0:
        return {"target": None}  # Return a default empty structure

    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        return {"target": None}  # Handle corruption safely

def alive_status(host):
    data = load_json()
    
    if data.get("target"):
        try:
            # Attempt to ping the host
            host_response = ping(host, count=2, interval=1, timeout=2, privileged=False)
            data["alive"] = host_response.is_alive
            save_json_content(data)
            return True
        except exceptions.NameLookupError:
            print(f"Error: The name '{host}' cannot be resolved.")
            data["alive"] = False  # Set alive status to False if the host cannot be resolved
            save_json_content(data)
            return False
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            data["alive"] = False  # Handle other exceptions
            save_json_content(data)
            return False
    else:
        return False
 

def is_valid_ip(ip):
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or not (0 <= int(octet) <= 255):
            return False
    return True

def save_to_json(ip_address):

    content = {
        "target": ip_address
        }
    
    filename = find_matching_file("./data/history",return_hid())+'.json'
    with open(filename, 'w') as file:
        json.dump(content, file, indent=4)
    print(f"IP address saved to {filename}")

def extract_server_info(banner):
    """Extract server version details from a banner."""
    lines = banner.split("\n")
    for line in lines:
        if "Server:" in line:
            return line.replace("Server:", "").strip()
        if "SSH-" in line or "HTTP/" in line:
            return line.strip()
    return "Unknown Version"



def get_all_ipv4():
    """Extract all non-local IPv4 addresses from active interfaces."""
    ipv4_addresses = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ipv4_addresses.append(addr.address)  # Collect all non-local IPv4s
    return ipv4_addresses

def scan_subnet(subnet):
    """Scan the given subnet and return a list of active hosts."""
    active_hosts = []
    arp_request = scapy.ARP(pdst=subnet)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast / arp_request
    answered_list = scapy.srp(arp_packet, timeout=1, verbose=False)[0]

    for sent, received in answered_list:
        active_hosts.append(received.psrc)
    
    return active_hosts

def check_port_80(ip):
    
    if is_target():
        data = load_json()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            if(sock.connect_ex((ip, 80)) == 0):
                data["http"] = True
            else:
                data["http"] = False
            save_json_content(data)
            return sock.connect_ex((ip, 80)) == 0
    return None

def fast_scan():
    ipv4_addresses = get_all_ipv4()
    
    if not ipv4_addresses:
        print("Could not determine any active IPv4 addresses.")
        return
    
    all_active_hosts = set()
    
    for ipv4 in ipv4_addresses:
        subnet = ".".join(ipv4.split(".")[:3]) + ".0/24"
        print(f"\nScanning subnet: {subnet} for active hosts...")
        
        active_hosts = scan_subnet(subnet)
        all_active_hosts.update(active_hosts)

    if not all_active_hosts:
        print("No active hosts found in any subnet.")
        return

    print(f"\nAll Active hosts: {list(all_active_hosts)}")

    print("\nScanning for hosts running port 80...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_port_80, all_active_hosts))

    port_80_hosts = [ip for ip in results if ip]

    if port_80_hosts:
        print("\nHosts running port 80:")
        for host in port_80_hosts:
            print(host)
    else:
        print("\nNo hosts found with port 80 open.")

def get_http_banner(url,host):
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    }
    try:
        url = "http://"+url+"/"
        response = requests.get(url,headers=headers, timeout=5)
        headers = response.headers

        server = headers.get('Server', 'Unknown')
        powered_by = headers.get('X-Powered-By', 'Unknown')
        if powered_by == 'Unknown':
            return server
        return server+" "+powered_by
    except requests.exceptions.RequestException as e:
        return(f"[-] Error retrieving banner: {e}")
    
def save_json_content(content):

    
    with open("./data/scan.json", 'w') as file:
        json.dump(content, file, indent=4)

    

def check_redirect(ip):
    """Check if the IP redirects to a domain."""
   
    try:
        response = requests.get(f"http://{ip}", allow_redirects=True, timeout=3)
        final_url = response.url
        parsed_domain = urlparse(final_url).netloc

        if parsed_domain and parsed_domain != ip:
            return parsed_domain, True

        soup = BeautifulSoup(response.text, "html.parser")
        meta_refresh = soup.find("meta", attrs={"http-equiv": "refresh"})
        
        if meta_refresh:
            content = meta_refresh.get("content", "")
            if "url=" in content:
                extracted_url = content.split("url=")[-1]
                parsed_meta_domain = urlparse(extracted_url).netloc
                if parsed_meta_domain:
                    return parsed_meta_domain, True
    except requests.exceptions.RequestException as e:
        error_message = str(e)

        # Extract domain if it's mentioned in the error
        if "host=" in error_message:
            parts = error_message.split("host=")
            if len(parts) > 1:
                extracted_host = parts[1].split(",")[0].strip("'")
                return extracted_host, True
        
    return "", False


def get_content_html(url):
    output_dir =f"./data/{url}/webpage"

    url = 'http://' + url + '/'
    os.makedirs(output_dir, exist_ok=True)
    resource_dirs = {"css": os.path.join(output_dir, "css"),
                     "js": os.path.join(output_dir, "js"),
                     "img": os.path.join(output_dir, "img")}
    
    # Create resource directories
    for dir_path in resource_dirs.values():
        os.makedirs(dir_path, exist_ok=True)

    # Function to determine the save directory based on resource type
    def get_resource_dir(tag, attr):
        if tag == 'link' and attr == 'href':
            return resource_dirs["css"]
        elif tag == 'script' and attr == 'src':
            return resource_dirs["js"]
        elif tag == 'img' and attr == 'src':
            return resource_dirs["img"]
        return output_dir

    # Function to download a resource
    def download_resource(resource_url, save_dir):
        try:
            response = requests.get(resource_url, stream=True)
            response.raise_for_status()
            filename = os.path.basename(urlparse(resource_url).path)
            if not filename:  # Handle cases where the URL ends with a '/'
                filename = "index.html" if "html" in response.headers.get('Content-Type', '') else "file"
            save_path = os.path.join(save_dir, filename)
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            return os.path.relpath(save_path, output_dir)  # Return relative path
        except requests.exceptions.RequestException:
            # Handle any errors silently (no print or raise)
            return None

    try:

        response = requests.get(url,headers={"Host":"2million.htb"})
        response.raise_for_status()
        html_content = response.text
        status_code = response.status_code 
    except requests.exceptions.RequestException:
        # Handle request exceptions silently, set status_code to None
        status_code = None
        html_content = ""

    # Parse the HTML if the content is available
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')

        # Download and update links for <link> (CSS), <script> (JS), and <img> (images)
        tags_to_download = {'link': 'href', 'script': 'src', 'img': 'src'}
        for tag, attr in tags_to_download.items():
            for element in soup.find_all(tag):
                resource_url = element.get(attr)
                if resource_url:
                    absolute_url = urljoin(url, resource_url)
                    save_dir = get_resource_dir(tag, attr)
                    downloaded_file = download_resource(absolute_url, save_dir)
                    if downloaded_file:
                        element[attr] = downloaded_file  

        # Save the modified HTML locally
        index_path = os.path.join(output_dir, 'index.html')
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(str(soup))

    return status_code 





