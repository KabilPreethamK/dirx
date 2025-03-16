import re
import json
from bs4 import BeautifulSoup, Comment
import requests
from nltk.tokenize import sent_tokenize, word_tokenize
from nltk import pos_tag
import os
import sys


# Detect if running inside a PyInstaller-built executable
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS  # PyInstaller extraction directory
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Function to retrieve HTML content
def htmlRetrival(url):
    myheaders = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Referer": "https://www.google.com/",
        "DNT": "1"  
    }
    
    data = requests.get(url, headers=myheaders, verify=False)
    
    if data.status_code == 200:
        soup = BeautifulSoup(data.text, "html.parser")
        return soup.prettify()  
    else:
        print(f"❌ Failed to retrieve the page. Status Code: {data.status_code}")
        return ""




def extract_relevant_text(html_content):
    soup = BeautifulSoup(html_content, "html.parser")

    # Remove style tags
    for tag in soup(["style"]):  
        tag.extract()

    # Extract HTML comments
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    extracted_comments = [comment.strip("<!-->") for comment in comments]

    # Extract visible text
    text_content = soup.get_text(separator=" ")
    text_content = re.sub(r"\s+", " ", text_content).strip()
    combined_text = text_content + " " + " ".join(comments)

    return combined_text, extracted_comments  

# Function to extract code snippets from HTML
def extract_code_snippets(html_content):
    soup = BeautifulSoup(html_content, "html.parser")
    code_snippets = set()

    for code_block in soup.find_all(["code", "pre", "script"]):
        code_text = code_block.get_text(separator="\n").strip()
        if len(code_text) > 3:
            code_snippets.add(code_text)

    return list(code_snippets)

# Function to extract data using regex
def classify_text(text):
    names = set()
    phone_numbers = set()
    email_ids = set()
    cve_data = set()
    urls = set()
    file_paths = set()
    
    email_pattern = r"[\w\.-]+@[\w\.-]+\.\w+"
    phone_pattern = r"\+?\d{1,3}[-\s]?\d{10}|\b\d{10}\b"
    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    url_pattern = r"https?://[\w\.-/]+|www\.[\w\.-]+|ftp://[\w\.-/]+"
    file_path_pattern = r"[a-zA-Z]:\\(?:[^\\/:?\"<>|]+\\)[^\\/:?\"<>|]|(/[^\s]+)+"

    # Extract emails, phone numbers, CVEs, URLs, file paths
    email_ids.update(re.findall(email_pattern, text))
    phone_numbers.update(re.findall(phone_pattern, text))
    cve_data.update(re.findall(cve_pattern, text))
    urls.update(re.findall(url_pattern, text))
    file_paths.update(re.findall(file_path_pattern, text))

    # Extract possible names using NLTK's POS tagging
    words = word_tokenize(text)
    tagged_words = pos_tag(words)
    
    for word, tag in tagged_words:
        if tag in ["NNP", "NNPS"]:  # Proper nouns
            names.add(word)

    return {
        "names": list(names),
        "phone_numbers": list(phone_numbers),
        "email_ids": list(email_ids),
        "cve_data": list(cve_data),
        "urls": list(urls),
        "file_paths": list(file_paths)
    }

# Function to find sentences containing classified data
def find_sentences_with_keywords(text, keywords, code_snippets):
    sentences = sent_tokenize(text)

    # Filter out sentences that exactly match code snippets
    filtered_sentences = [
        sentence for sentence in sentences
        if not any(re.fullmatch(re.escape(code.strip()), sentence.strip()) for code in code_snippets)
    ]

    # Find sentences containing any classified keywords
    matched_sentences = [
        sentence for sentence in filtered_sentences 
        if any(word in sentence for word in keywords)
    ]
    
    return list(set(matched_sentences))

# Function to process HTML content and extract structured data
def process_html_content(html_content, output_filename="output.json"):
    if not html_content:
        print("❌ No HTML content to process.")
        return

    filtered_text, extracted_comments = extract_relevant_text(html_content)
    code_snippets = extract_code_snippets(html_content)
    
    classified_data = classify_text(filtered_text)

    keywords = (
        classified_data["names"] + 
        classified_data["email_ids"] + 
        classified_data["phone_numbers"] + 
        classified_data["cve_data"] +
        classified_data["urls"] +
        classified_data["file_paths"]
    )
    sentences_with_keywords = find_sentences_with_keywords(filtered_text, keywords, code_snippets)

    data = {
        "sentences": sentences_with_keywords,
        "code_snippets": code_snippets,
        "classified_data": classified_data,
        "comments": extracted_comments
    }
    
    return data
