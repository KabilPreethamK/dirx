from modules.build import bing_search, DirectoryScanner, send_request, WebSpider
import re


import multiprocessing

from modules.subdomain import extract_summary_from_html

def recon_1(spider, query, target,domain):
    """Start directory scanning and web spidering in parallel if spider is True."""
    print(domain)
    if is_valid_domain(domain) and query:
    
        content = extract_summary_from_html(target)
        send_request("query",content)
        content = extract_summary_from_html(domain)
        send_request("query",content)

    dict_process = multiprocessing.Process(target=start_directory_scan, args=(target,))
    spid_process = multiprocessing.Process(target=start_web_spider, args=(target,))


    if spider:
        dict_process.start()
        spid_process.start()
        dict_process.join()
        spid_process.join()
    else:
        dict_process.start()
        dict_process.join()
        

def recon_2(spider, query, target):
    
    if is_valid_domain(target) and query:
       content = bing_search(target)
       for url in content:
           content = extract_summary_from_html(url)
           send_request("query",content)

       
    url = f"http://{target}/"
    dict_process = multiprocessing.Process(target=start_directory_scan, args=(url,))
    spid_process = multiprocessing.Process(target=start_web_spider, args=(url,))


    if spider:
        dict_process.start()
        spid_process.start()
        dict_process.join()
        spid_process.join()
    else:
        dict_process.start()
        dict_process.join()
        



def start_directory_scan(target):
    """Function to initialize and run DirectoryScanner."""
    clean_target = target.rstrip("/") 
    scanner = DirectoryScanner(target_url=clean_target,)
    scanner.run_scan()

def start_web_spider(target):
    clean_target = target.rstrip("/") 
    spider = WebSpider(clean_target)
    spider.start()
    
def is_valid_domain(domain):
    """Check if the input is a valid domain name."""
    # Regular expression for validating a domain name
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'  # Start with a valid character
        r'([A-Za-z]{2,}|[A-Za-z0-9-]{1,}\.[A-Za-z]{2,})$'  # Top-level domain
    )
    return bool(domain_pattern.match(domain))


