import requests
from pystyle import Colors, Write
from phonenumbers import geocoder, carrier
import phonenumbers
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
from dns import reversename
from email_validator import validate_email, EmailNotValidError
from urllib.parse import quote
import secrets
import json
from bs4 import BeautifulSoup
import re
from email.parser import Parser
import whois
import pyfiglet
from termcolor import colored
from tqdm import tqdm
from datetime import datetime
from pathlib import Path
import traceback
from email import message_from_string
from email.policy import default
import re
import hashlib
import magic
import stat
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2

import openpyxl
import docx
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from pptx import Presentation

from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from mutagen.mp4 import MP4
from mutagen.id3 import ID3
from mutagen.flac import FLAC
import wave
from mutagen.oggvorbis import OggVorbis
from tinytag import TinyTag

import trio
import httpx

import importlib





#default_color = Colors.cyan
#Head_Color = Colors.purple
#Exit_Color = Colors.yellow
#Error_Color = Colors.red
#Wait_Color = Colors.green

API_KEY = "AIzaSyAondv81wJMIhlMnUzmhsPJcw70CYsHAPM" #"ENTER GOOGLE CUSTOM SEARCH API KEY HERE"
CX = "509f2c6d7178d43ea"  #"ENTER GOOGLE CUSTOM SEARCH CX HERE"

HIBP_API_KEY =  "b6e4b60bbcfa4bc9b8fb8a714966c372" #"ENTER HAVE I BEEN PWNED API KEY HERE"


def read_settings():
    #Load settings from a JSON file.
    filename = "Settings/Colorcode.json"
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return {}

def write_settings(settings):
    #Save the settings to a JSON file.
    with open('Settings/Colorcode.json', 'w') as file:
        json.dump(settings, file)

def load_default_colors():
    #Load the default colors from settings.
    settings = read_settings()
    global default_color, Head_Color, Exit_Color, Error_Color,Wait_Color,Result_Color
    default_color = settings.get("default_color", Colors.cyan)
    Head_Color = settings.get("Head_Color", Colors.purple)
    Exit_Color = settings.get("Exit_Color", Colors.yellow)
    Error_Color = settings.get("Error_Color", Colors.red)
    Wait_Color = settings.get("Wait_Color", Colors.green)
    Result_Color = settings.get("Result_Color", Colors.white)


def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def waitmsg(msg):
    
    if(msg == ""):
        Write.Print("\n \U0001F422  Please wait while we process your request...\n", Wait_Color, interval=0)
    else:
        clear()
        Write.Print(f"\n \U0001F422  {msg}\n", Wait_Color, interval=0)

def press_zero():
     Write.Print("\n \u26A0  Press 0 and enter to cancel \n", Exit_Color, interval=0)
     Write.Print("\n", Exit_Color, interval=0)

def zero_pressed():
     Write.Print(" \U0001F438 Operation cancelled.\n", Error_Color, interval=0)

def wrap_text(text, width):
    # Manually wrap text to fit the specified width
    wrapped_lines = []
    while text:
        if len(text) <= width:
            wrapped_lines.append(text)
            break
        else:
            space_index = text.rfind(' ', 0, width)
            if space_index == -1:  # no space found, just split the text
                space_index = width
            wrapped_lines.append(text[:space_index])
            text = text[space_index:].lstrip()
    return wrapped_lines

def restart():
    Write.Input("\n 🐘 Press Enter to return to the main menu...", default_color, interval=0)
    clear()

def save_message():
    save_choice = Write.Input("\n \U0001F98B Do you want to save these details to a file? (y/n): ", default_color, interval=0).strip().lower()
    return save_choice

def save_details(data,NameData):
    try:
        #Ensure its string
        if not isinstance(data, str):
                data = str(data)
        
        cwd = os.getcwd()
        print(f"Current working directory is: {cwd}")

        #current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        #current_time = datetime.now().strftime("%A%B%d%Y%I:%M:%S %p")
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        #print(current_time)
    
        filename = f"Saves/{NameData}_{current_time}.txt"
        #print(f"the filename {filename}")
        #print(data)

        # Define the file path
        #file_path = Path(filename)

        # Write data to the file
        #file_path.write_text(data)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(data)

        Write.Print(f"\n \U0001F989 {NameData} details saved to {filename}\n", Wait_Color, interval=0)
    except Exception as e:
        #clear()
        Write.Print(f"\n \u2620 Error Saving {NameData} to file", Exit_Color, interval=0)

def get_ip_details(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        response.raise_for_status()
        return response.json()
    except:
        return None

def fetch_page_text(url, max_length=500):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    try:
        print(f"Fetching content from {url}")
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        # Remove unnecessary tags
        for tag_name in ["header", "footer", "nav", "aside", "script", "style", "noscript", "form"]:
            for t in soup.find_all(tag_name):
                t.decompose()

        # Extract text and truncate
        text = soup.get_text(separator=' ')
        text = ' '.join(text.split())
        truncated_text = text[:max_length]  # Truncate the text to desired length

        # Append the link to the source
        result_text = truncated_text + "... \n" #+ f"\n\nSource: {url}"

        return result_text if result_text else "No meaningful content found."
    except Exception as e:
        return f"Could not retrieve or parse the webpage content. \n {str(e)}"


def test_person_search():

    info_result = fetch_page_text(" ")
    Write.Print(info_result, Result_Color, interval=0)
    restart()

def person_search(first_name, last_name, city):

    waitmsg(f"Searching for {first_name} {last_name} in {city}...")

    if not API_KEY or not CX:
        ErrorString = ""
        if not API_KEY and not CX:       
            ErrorString = "Please enter a valid Google API Key and Custom Search Engine ID."
        elif not API_KEY:
            ErrorString = "Please enter a valid Google Search API Key."
        else:
            ErrorString = "Please enter a valid Custom Search Engine ID."

        Write.Print(ErrorString, Error_Color, interval=0)    
        return

    query = f"{first_name} {last_name} {city}"
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        'key': API_KEY,
        'cx': CX,
        'q': query,
        'num': 5
    }

    results_data = []
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if 'items' in data and len(data['items']) > 0:
            items = data['items'][:5]
            for idx, item in enumerate(items, start=1):
                first_result_url = item.get('link', None)
                if first_result_url:
                    page_text = fetch_page_text(first_result_url)
                    results_data.append((idx, page_text, first_result_url))
        else:
            results_data.append((1, "No results found.", None))
    except requests.exceptions.Timeout:
        results_data.append((1, "Request timed out.", None))
    except requests.exceptions.HTTPError as e:
        results_data.append((1, f"HTTP error: {e.response.status_code}", None))
    except Exception as e:
        results_data.append((1, f"Error: {str(e)}", None))

    clear()
    # Prepare the header of the summary
    info_text = f"""
╭─{' '*78}─╮
|{' '*29}Person Search Summary{' '*29}|
|{'='*80}|
| [+] > Name: {first_name} {last_name:<62}|
| [+] > Location: {city:<62}|
|{'-'*80}|
    """
    for idx, content, source_url in results_data:
        info_text += f"| Result #{idx:<2}{' '*(73-len(str(idx)))}|\n"
        info_text += f"|{'-'*78}|\n"
        lines = [content[i:i+78] for i in range(0, len(content), 78)]
        for line in lines:
            info_text += f"| {line:<78}|\n"
        if source_url:
            info_text += f"| Source: {source_url:<71}|\n"
        if idx != results_data[-1][0]:
            info_text += f"|{'='*78}|\n"
    info_text += f"╰─{' '*78}─╯"

    Write.Print(info_text, Result_Color, interval=0)

    save_choice = save_message()
    if save_choice == 'y':
            save_details(info_text, "Person_Search")
    restart()


def ip_info(ip):
    url = f"https://ipinfo.io/{ip}/json"

    waitmsg(f"Retrieving IP address info with {ip} ...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        loc = data.get('loc', 'None')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'None' else 'None'
        
       
       # Reverse DNS lookup
        try:
            rev_name = reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR")
            ptr_record = str(answers[0]).strip('.')
        except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.exception.DNSException) as e:
            ptr_record = f"Reverse DNS lookup skipped due to error: {str(e)}"


        ip_detailo = f"""
╭─────────────────────────────────────────────────────────────────────────────╮
│                                IP Details                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  IP Address           : {data.get('ip', 'None'):<51} │
│  City                 : {data.get('city', 'None'):<51} │
│  Region               : {data.get('region', 'None'):<51} │
│  Country              : {data.get('country', 'None'):<51} │
│  Postal/ZIP Code      : {data.get('postal', 'None'):<51} │
│  ISP                  : {data.get('org', 'None'):<51} │
│  Latitude, Longitude  : {loc:<51} │
│  Timezone             : {data.get('timezone', 'None'):<51} │
│  Google Maps Location : {maps_link:<51} │
│  Reverse DNS          : {ptr_record:<51} │
╰─────────────────────────────────────────────────────────────────────────────╯
"""
        Write.Print(ip_detailo, Result_Color, interval=0)

        
        save_choice = save_message()
        if save_choice == 'y':
            save_details(ip_detailo, "IP_address")

    except Exception as e:
        #clear()
        Write.Print(f"\n \u2620 Error retrieving IP address info. {str(e)}", Error_Color, interval=0)

    restart()

def fetch_social_urls(urls, title):
    def check_url(url):
        try:
            response = requests.get(url, timeout=10)
            status_code = response.status_code
            if status_code == 200:
                return f"\u2714 > {url:<50}|| Found"
            elif status_code == 404:
                return f"\u2718 > {url:<50}|| Not found"
            else:
                return f"\u2718 > {url:<50}|| Error: {status_code}"
        except requests.exceptions.Timeout:
            return f"\u2718 > {url:<50}|| Timeout"
        except requests.exceptions.ConnectionError:
            return f"\u2718 > {url:<50}|| Connection error"
        except requests.exceptions.RequestException:
            return f"\u2718 > {url:<50}|| Request error"
        except Exception:
            return f"\u2718 > {url:<50}|| Unexpected error"

    result_str = f"""

|{' '*27}{title}{' '*35}|
|{'='*80}|
"""
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(check_url, urls))
    
    found = [result for result in results if "Found" in result]
    not_found = [result for result in results if "Found" not in result]
    sorted_results = found + not_found

    for result in sorted_results:
        result_str += f"| {result:<78} |\n"
    result_str += f"╰─{' '*78}─╯"
    return result_str

def load_sites_from_file():
    """Load sites from a text file, each line representing a URL pattern."""
    try:
        file_path ="AccountSearch/list.txt"
        with open(file_path, 'r', encoding='utf-8') as file:
            sites = [line.strip() for line in file if line.strip()]
        return sites
    except FileNotFoundError:
        print(f"Error: {file_path} not found.")
        return []
    
def account_search(nickname):

    waitmsg(f"Searching for social media accounts with {nickname}...")

    sites = load_sites_from_file()

    urls = []
    for site_format in sites:
        if '{}' in site_format:
            url = site_format.format(nickname)
        else:
            url = site_format.rstrip('/') + '/' + nickname
        urls.append(url)

    search_results = fetch_social_urls(urls, " \U0001F43C Account Search")
    Write.Print(search_results, Result_Color, interval=0)
    save_choice = save_message()
    if save_choice == 'y':
        save_details(search_results, "Account_Search")

    restart()

def phone_info(phone_number):

    waitmsg(f"Retrieving phone number info with {phone_number}...")
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "en")
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Valid" if valid else "Invalid"
        phonetext = f"""
            \n
            |{'='*52}|
            |{' '*17}Phone number info{' '*18}|
            |{'='*52}|
            |  Number   || {phone_number:<38}|
            |  Country  || {country:<38}|
            |  Region   || {region:<38}|
            |  Operator || {operator:<38}|
            |  Validity || {validity:<38}|
            ╰─{' '*9}─╯╰─{' '*37}─╯\n"""

        Write.Print(phonetext, Result_Color, interval=0)

        save_choice = save_message()
        if save_choice == 'y':
            save_details(phonetext, "Phone_Number_Info")

    except phonenumbers.phonenumberutil.NumberParseException:
        clear()
        Write.Print(f"\n Error: invalid phone number format (+10000000000)", Error_Color, interval=0)

    restart()

def dns_lookup(domain):

    waitmsg(f"Retrieving DNS records for {domain}...")

    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"""

|{' '*33} DNS Lookup {' '*35}|
|{'='*80}|
"""
    result_output += f"| Domain: {domain:<67}|\n"
    for rtype in record_types:
        result_output += f"| \u2611 {rtype} Records: {' '*62}|\n"
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for ans in answers:
                if rtype == 'MX':
                    result_output += f"|    {ans.preference:<4} {ans.exchange:<70}|\n"
                else:
                    result_output += f"|    {str(ans):<76}|\n"
        except dns.resolver.NoAnswer:
            result_output += "|    No records found.\n"
        except dns.resolver.NXDOMAIN:
            result_output += "|    Domain does not exist.\n"
        except Exception:
            result_output += "|    Error retrieving records.\n"

        result_output += f"|{'='*80}|\n"

    result_output += whois_lookup(domain)

    clear()
    Write.Print(result_output, Result_Color, interval=0)

    save_choice = save_message()
    if save_choice == 'y':
        save_details(result_output, "DNS_Lookup")
    restart()

def split_into_chunks(text, width):
    """Splits the text into chunks of a specified width."""
    return [text[i:i+width] for i in range(0, len(text), width)]

def format_mx_records(mx_records, max_width):
    if mx_records:
        # Join MX records into a single string
        mx_records_joined = ", ".join(mx_records)
        # Split into manageable chunks if necessary
        return split_into_chunks(mx_records_joined, max_width)
    else:
        return ["None"]
    
def email_lookup(email_address):

    waitmsg(f"Retrieving email address info with {email_address}...")

    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        Write.Print(f" Invalid email format: {str(e)}", Error_Color, interval=0)
        restart()
        return

    mx_records = []
    try:
        answers = dns.resolver.resolve(email_domain, 'MX')
        for rdata in answers:
            mx_records.append(str(rdata.exchange))
    except:
        mx_records = []

    validity = "Likely Valid (MX found)" if mx_records else "No MX found (Might be invalid)"

    max_mx_width = 52  # Max width for displayed MX record or line

    mx_records_chunks = format_mx_records(mx_records, max_mx_width)
    
    mx_records_text = "\n".join(
        f"│ {'':<32}││ {chunk:<57}│" if i > 0 else f"|  MX Records:   ││ {chunk:<55}│"
        for i, chunk in enumerate(mx_records_chunks)
    )


    email_text = f"""
            
            │{'Email Info':^80}│
            │{'='*80}│
            │  Email:        ││ {'':<1} {email_address:<57}│
            │  Domain:       ││ {'':<1} {email_domain:<57}│
            {mx_records_text}
            │  Validity:     ││ {'':<1} {validity:<57}│
            
            """
    Write.Print(email_text, Result_Color, interval=0)

    #print("\n Test Phil \n")
    #email_Phlint(email_address)
    

    save_choice = save_message()
    if save_choice == 'y':
        save_details(email_text, "Email_LookUp")
    restart()

def email_Phlint(emailada):
    
    waitmsg(f"Retrieving accounts attached to email {emailada}...")
    results = []  # Shared list to store results
    logresult = ""
    def read_services_from_file(file_path):
        with open(file_path, 'r') as file:
            services = [line.strip() for line in file if line.strip()]
        return services
    
    async def perform_check(service_function, email, client, results):
        out = []
        try:
            await service_function(email, client, out)

            for result in out:
                if result["exists"]:
                    results.append(
                        f"| {result['name']:<15} || ({result['domain']:15}) |  \u2705 Email exists |\n"
                    )
                #else:
                #    results.append(
                #        f"| {result['name']:<31} || ({result['domain']:20}) |  Email does not exist |\n"
                #    )

        except Exception as e:
            results.append(
                f"| {service_function.__name__:<20} || (N/A) | error: {str(e):<32} |\n"
            )

    async def holehe(email):
        services_file = 'AccountSearch/services.txt'  # Path to your text file containing service module paths
        services = read_services_from_file(services_file)

        async with httpx.AsyncClient() as client:
            # Use a Trio nursery to run concurrent operations
            async with trio.open_nursery() as nursery:
                for service_path in services:
                    module_name = service_path.split('.')[-1]
                    try:
                        module = importlib.import_module(service_path)
                        service_function = getattr(module, module_name)
                        nursery.start_soon(perform_check, service_function, email, client, results)
                    except (ModuleNotFoundError, AttributeError) as e:
                        results.append(
                            f"| {module_name:<15} || (N/A)| error: {str(e):<42} |\n"
                        )

        # After all tasks complete, print results
        header = (
            f"│{'Email Accounts Info':^80}│\n"
            f"│{'='*80}│\n"
            f"│  Email:        ││ {'':<1} {email:<57}│\n"
            f"├{'─'*78}┤\n"
        )

        #print(header)
        logresult = header
        for result in results:
            #print(result)
            logresult+= result
        #print(f"╰─{'─'*78}─╯")
        logresult += (f"╰─{'─'*78}─╯")

        Write.Print(logresult, Result_Color, interval=0)

        save_choice = save_message()
        if save_choice == 'y':
            save_details(logresult, "Email_Accounts_LookUp")

    trio.run(holehe, emailada)

    
    restart()

def capture_email_input():
    
    Write.Print(" \U0001F989 Enter the raw email data. Then type 'END' on a new line and press Enter when finished:", default_color, interval=0)
    lines = []
    while True:
        line = input()
        if line.strip() == "0":
           
            return None  
        elif line.strip().upper() == "END":
            break
        lines.append(line)

    raw_data = "\n".join(lines)
    return raw_data


def analyze_email_raw_data(raw_data):
 
 waitmsg("Analyzing email raw data...")
 try:
        # Parse the raw email data using a robust email parser
        msg = message_from_string(raw_data, policy=default)

        # Extract basic header information
        from_ = msg.get("From", "")
        to_ = msg.get("To", "")
        subject_ = msg.get("Subject", "")
        date_ = msg.get("Date", "")

        #print("Debug:", f"From: {from_}, To: {to_}, Subject: {subject_}, Date: {date_}")

        received_lines = msg.get_all("Received", [])
        found_ips = []

        if received_lines:
            for line in received_lines:
                potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
                for ip in potential_ips:
                    if ip not in found_ips:
                        found_ips.append(ip)

        # Prepare and print the header summary
        header_text = f"""
|{' '*31}Email Analysis{' '*31}|
|{'='*75}|
|  From:      || {from_:<55}|
|  To:        || {to_:<55}|
|  Subject:   || {subject_:<55}|
|  Date:      || {date_:<55}|
|{'-'*75}|
"""
        if found_ips:
            header_text += "| Received Path (IPs found):\n"
            for ip in found_ips:
                header_text += f"|    {ip:<76}|\n"
        else:
            header_text += "| No IPs found in Received headers.\n"

        header_text += f"╰─{' '*78}─╯"
        Write.Print(header_text, Result_Color, interval=0)

        if found_ips:
            ip_details_header = f"""
|{' '*30}IP Geolocation Details{' '*30}|
|{'='*75}|
"""
            ip_details_summary = ""
            for ip in found_ips:
                data = get_ip_details(ip)
                if data is not None:
                    loc = data.get('loc', 'None')
                    ip_details_summary += f"| IP: {ip:<14}|| City: {data.get('city','N/A'):<15} Region: {data.get('region','N/A'):<15} Country: {data.get('country','N/A'):<4}|\n"
                    ip_details_summary += f"|    Org: {data.get('org','N/A'):<63}|\n"
                    ip_details_summary += f"|    Loc: {loc:<63}|\n"
                    ip_details_summary += "|"+ "-"*78 + "|\n"
                else:
                    ip_details_summary += f"| IP: {ip:<14}|| \u2620 Could not retrieve details.\n"
                    ip_details_summary += "|"+ "-"*78 + "|\n"
            ip_details_footer = f"| {' '*78} |"

            Write.Print(ip_details_header + ip_details_summary + ip_details_footer, Result_Color, interval=0)

        # SPF, DKIM, DMARC checks
        spf_result, dkim_result, dmarc_result = None, None, None
        spf_domain, dkim_domain = None, None
        auth_results = msg.get_all("Authentication-Results", [])
        from_domain = from_.split('@')[-1].strip() if '@' in from_ else ""

        if auth_results:
            for entry in auth_results:
                spf_match = re.search(r'spf=(pass|fail|softfail|neutral)', entry, re.IGNORECASE)
                if spf_match:
                    spf_result = spf_match.group(1)
                spf_domain_match = re.search(r'envelope-from=([^;\s]+)', entry, re.IGNORECASE)
                if spf_domain_match:
                    spf_domain = spf_domain_match.group(1)

                dkim_match = re.search(r'dkim=(pass|fail|none|neutral)', entry, re.IGNORECASE)
                if dkim_match:
                    dkim_result = dkim_match.group(1)
                dkim_domain_match = re.search(r'd=([^;\s]+)', entry, re.IGNORECASE)
                if dkim_domain_match:
                    dkim_domain = dkim_domain_match.group(1)

                dmarc_match = re.search(r'dmarc=(pass|fail|none)', entry, re.IGNORECASE)
                if dmarc_match:
                    dmarc_result = dmarc_match.group(1)

        spf_align = (from_domain.lower() == spf_domain.lower()) if from_domain and spf_domain else False
        dkim_align = (from_domain.lower() == dkim_domain.lower()) if from_domain and dkim_domain else False

        alignment_text = f"""
|{' '*30}SPF / DKIM / DMARC Checks{' '*29}|
|{'='*75}|
|  SPF  Result:   {spf_result if spf_result else 'Not found':<20}   Domain: {spf_domain if spf_domain else 'N/A':<20} Aligned: {spf_align}|
|  DKIM Result:   {dkim_result if dkim_result else 'Not found':<20} Domain: {dkim_domain if dkim_domain else 'N/A':<20} Aligned: {dkim_align}|
|  DMARC Result:  {dmarc_result if dmarc_result else 'Not found':<20}|

"""
        Write.Print(alignment_text, Result_Color, interval=0)
        save_choice = save_message()
        Total_String = header_text + "\n"+ ip_details_header + "\n" +  ip_details_summary + "\n"+ ip_details_footer  + "\n" + alignment_text
        if save_choice == 'y':
            save_details(Total_String, "Email_Raw_Info")

 except Exception as e: 
        Write.Print(f"An error occurred while analyzing the email raw data: {str(e)}", Error_Color, interval=0)
        traceback.print_exc()

 

 restart()

def haveibeenpwned_check(email):
    waitmsg(f"Checking Have I Been Pwned for {email}...")
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "ClatScope-Info-Tool"
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 200:
            breaches = resp.json()
            clear()
            results_text = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
|  Bad news! Your email was found in {len(breaches)} breach(es)                          |
|{'-'*80}|
"""
            max_width = 70  # Define a constant width for the content
            separator = f"|{'=' * (max_width + 12)}|\n"
            results_text = separator

            for index, breach in enumerate(breaches, start=1):
                breach_name = breach.get('Name', 'Unknown')
                domain = breach.get('Domain', 'Unknown')
                breach_date = breach.get('BreachDate', 'Unknown')
                added_date = breach.get('AddedDate', 'Unknown')
                pwn_count = breach.get('PwnCount', 'Unknown')
                data_classes = ", ".join(breach.get('DataClasses', []))

               

                results_text += f"| Breach #{index}: {breach_name:<{max_width}}|\n"
                results_text += f"|    Domain: {domain:<{max_width}}|\n"
                results_text += f"|    Breach Date: {breach_date:<{max_width-5}}|\n"
                results_text += f"|    Added Date:  {added_date:<{max_width-5}}|\n"
                results_text += f"|    PwnCount:    {pwn_count:<{max_width-5}}|\n"
                #results_text += f"|    Data Types:  {data_classes:<{max_width}}|\n"
                #results_text += f"|{'='*80}|\n"
                wrappeed = wrap_text(data_classes, max_width)
                for i, line in enumerate(wrappeed):
                    prefix = "Data Types: " if i == 0 else " " * 13
                    results_text += f"|    {prefix}{line:<{max_width-3}}|\n"

                results_text += separator

            results_text += f"\n END OF BREACHES\n"
            Write.Print(results_text, Result_Color, interval=0)

            
            save_choice = save_message()
            if save_choice == 'y':
                save_details(results_text, "Hv_Bn_Pwned")

        elif resp.status_code == 404:
            clear()
            msg = f"""

|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
|  \U0001F43C Good news! No breaches found for: {email:<48}|

"""
            Write.Print(msg, Result_Color, interval=0)

            save_choice = save_message()
            if save_choice == 'y':
                save_details(msg, "Hv_Bn_Pwned")
        else:
            clear()
            error_msg = f"""
\u2620 An error occurred: HTTP {resp.status_code}
Response: {resp.text}
"""
            Write.Print(error_msg, Colors.red, interval=0)
            

    except requests.exceptions.Timeout:
        clear()
        Write.Print("\u2620 Request timed out when contacting Have I Been Pwned.", Error_Color, interval=0)
    except Exception as e:
        clear()
        Write.Print(f"\u2620 An error occurred: {str(e)}", Error_Color, interval=0)

    restart()


def change_color(color_name):
    #clear()
    color_menu = """
╭─    ─╮╭─                     ─╮
|  №   ||         Color         |
|======||=======================|
| [1]  || Cyan                  |
| [2]  || Purple                |
| [3]  || Red                   |
| [4]  || Yellow                |
| [5]  || Blue                  |
| [6]  || White                 |
| [7]  || Black                 |
| [8]  || Green                 |
| [9]  || Gray                  |
| [10] || Light Red             |
| [11] || Light Green           |
| [12] || Orange                |
| [13] || Light Blue            |
| [14] || turquoise             |
| [15] || Pink                  |
| [16] || Dark Red              |
|------||-----------------------|
| [0]  || Back to settings menu |
╰─    ─╯╰─                     ─╯
"""
    Write.Print(color_menu, Result_Color, interval=0)

    color_choice = Write.Input("\n\n \U0001F989 > Enter Color to PIck or 0 to cancel: ", default_color, interval=0).strip()

    color_map = {
    "1": Colors.cyan,
    "2": Colors.purple,
    "3": Colors.red,
    "4": Colors.yellow,
    "5": Colors.blue,
    "6": Colors.white,
    "7": Colors.black,
    "8": Colors.green,
    "9": Colors.gray,
    "10": Colors.light_red,
    "11": Colors.light_green,
    "12": Colors.orange,
    "13": Colors.light_blue,
    "14": Colors.turquoise,
    "15": Colors.pink,
    "16": Colors.dark_red
}

    if color_choice in color_map:
        new_color = color_map[color_choice]
        globals()[color_name] = new_color  # Update the global color variable
        settings = read_settings()
        settings[color_name] = new_color
        write_settings(settings)
        clear()
        Write.Print(f"\U0001F98B {color_name.replace('_', ' ').title()} has been changed.\n", new_color, interval=0)
    elif color_choice == "0":
        return
    else:
        clear()
        Write.Print("\u2620 Invalid choice.\n", Error_Color, interval=0)

    restart()  


def whois_lookup(domain):
    who_summary = ""
    try:
        w = whois.whois(domain)  # Assuming 'whois' is correctly initialized
        #clear()

        domain_name = w.domain_name if w.domain_name else "N/A"
        registrar = w.registrar if w.registrar else "N/A"
        creation_date = w.creation_date if w.creation_date else "N/A"
        expiration_date = w.expiration_date if w.expiration_date else "N/A"
        updated_date = w.updated_date if w.updated_date else "N/A"
        name_servers = ", ".join(w.name_servers) if w.name_servers else "N/A"
        status = ", ".join(w.status) if w.status else "N/A"

        # Wrap name servers and statuses
        wrapped_Create_Date = wrap_text(str(creation_date), 52)
        wrapped_Exp_Date = wrap_text(str(expiration_date), 52)
        wrapped_Updat_Date = wrap_text(str(updated_date), 52)
        wrapped_name_servers = wrap_text(name_servers, 52)
        wrapped_status = wrap_text(status, 52)

        def format_wrapped_lines(lines, label):
            label_with_colon = label + ":"
            prefix_length = len(label_with_colon) + 8  # Includes "|| " and initial padding
            formatted_text = ""
            for i, line in enumerate(lines):
                if i == 0:
                    prefix = f"{label_with_colon:<20}|| "
                else:
                    # Leaves room for the prefix space alignment
                    prefix = ' ' * (prefix_length)
                
                formatted_text += f"|  {prefix}{line:<56}|\n"
            return formatted_text

        whois_text = f"""

|{' '*34}WHOIS Lookup{' '*31}|
|{'='*77}|
|    Domain Name:       || {str(domain_name):<51}|
|    Registrar:         || {str(registrar):<51}|
|{'-'*77}|
{format_wrapped_lines(wrapped_Create_Date, "Creation Date")}
{format_wrapped_lines(wrapped_Exp_Date, "Expiration Date")}
{format_wrapped_lines(wrapped_Updat_Date, "Updated Date")}
{format_wrapped_lines(wrapped_name_servers, "Name Servers")}
{format_wrapped_lines(wrapped_status, "Status")}

"""
        #Write.Print(whois_text, Colors.white, interval=0)

        #save_choice = save_message()
        #if save_choice == 'y':
        #    save_details(whois_text, "Domain_LookUp")

        who_summary = whois_text

    except Exception as e:
        #clear()
        #Write.Print(f" \u2620  WHOIS lookup error: {str(e)}", default_color, interval=0)
        who_summary = f" \u2620  WHOIS lookup error: {str(e)}"

    #restart()
    return who_summary

def pass_strength(password):
    

    score = 0
    if len(password) > 11:  #At Least 10 characters
        score += 1   
    if re.search(r'[A-Z]', password): #At Least 1 uppercase letter
        score += 1
    if re.search(r'[a-z]', password): #At Least 1 lowercase letter
        score += 1
    if re.search(r'\d', password): #At Least 1 digit
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password): #At Least 1 special character
        score += 1

    scoreboard = f"Password entered: {password}\n"    

    if score <= 2:
        scoreboard += "Too weak, add more characters and complexity."
    elif score < 5:
        scoreboard += "Needs work. "
    else:
        scoreboard += "Meets the standard, it will suffice  \U0001F427"

    def HIBP_Password(passp):
        # Hash the password using SHA-1
        sha1_password = hashlib.sha1(passp.encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        # Make a request to the PwnedPasswords API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)

        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        return 0
    
    count = HIBP_Password(password)



    if count:
        scoreboard += "\n" + (f"This password has been seen {count} times in data breaches.")
        scoreboard += "\n" + ("Change It .")
    else:
        if score >= 4:
            scoreboard += "\n" + ("This password hasn't been found in known data breaches. \n and seems good.")
        else:    
            scoreboard += "\n" +("This password hasn't been found in known data breaches. \n but needs work")


    return scoreboard    

def check_password(password=None):
    #clear()
    waitmsg("Checking password strength...") 
    if not password:
        clear()
        Write.Print(" Password cannot be empty Please enter the password.\n", Exit_Color, interval=0)
        restart()
        return

    strength = pass_strength(password)
    clear()
    Write.Print(" Password  Checker\n", Head_Color, interval=0)
    Write.Print(f"{strength}\n", default_color, interval=0)

    save_choice = save_message()
    if save_choice == 'y':
        save_details(strength, "Password_Checker")
    restart()

def fetch_what_myname():
    try:
        response = requests.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=10)
        response.raise_for_status()
        return response.json()
    except:
        Write.Print("\u2620 Failed to fetch data from WhatsMyName repository.\n", Error_Color, interval=0)
        return None

def check_site(site, username, headers):
    site_name = site["name"]
    uri_check = site["uri_check"].format(account=username)
    try:
        res = requests.get(uri_check, headers=headers, timeout=10)
        estring_pos = site["e_string"] in res.text
        estring_neg = site["m_string"] in res.text

        if res.status_code == site["e_code"] and estring_pos and not estring_neg:
            return site_name, uri_check
    except:
        pass
    return None

def generate_html_report(username, found_sites):
    html_content = f"""
    <html>
    <head>
        <title>Username Check Report for {username}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
        </style>
    </head>
    <body>
        <h1>Username Check Report for {username}</h1>
        <table>
            <tr>
                <th>Website Name</th>
                <th>Profile URL</th>
            </tr>"""
    for site_name, uri_check in found_sites:
        html_content += f"""
            <tr>
                <td>{site_name}</td>
                <td><a href="{uri_check}" target="_blank">{uri_check}</a></td>
            </tr>"""
    html_content += """
        </table>
    </body>
    </html>"""

    filename = f"Saves/username_report_{username}.html"
    with open(filename, "w") as report_file:
        report_file.write(html_content)

def username_check(username=None):
    clear()
    waitmsg("Checking username on multiple sites...")
    if not username:
        clear()
        Write.Print("\u2620 > No username provided.\n", Error_Color, interval=0)
        restart()
        return

    data = fetch_what_myname()
    if not data:
        restart()
        return

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
    }
    sites = data["sites"]
    total_sites = len(sites)
    found_sites = []

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_site, site, username, headers): site for site in sites}

            with tqdm(total=total_sites, desc="\U0001F422  Checking sites") as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            site_name, uri_check = result
                            found_sites.append((site_name, uri_check))
                            Write.Print(f"\U0001F43C Found on: {site_name}\n", default_color, interval=0)
                            Write.Print(f"\U0001F427 Profile URL: {uri_check}\n", default_color, interval=0)
                    except Exception:
                        pass
                    finally:
                        pbar.update(1)

        if found_sites:
            Write.Print(f"\n \U0001F427 > Username found on {len(found_sites)} sites!\n", default_color, interval=0)
            save_choice = save_message()
            if save_choice == 'y':
                generate_html_report(username, found_sites)
                Write.Print(f"\n \U0001F427 > Report saved: username_check_report_{username}.html\n", Exit_Color, interval=0)
        else:
            Write.Print(f"\n \U0001F427 > No results found for {username}.\n", Exit_Color, interval=0)

    except Exception as e:
        Write.Print(f"\u2620 > An error occurred: {str(e)}\n", Error_Color, interval=0)

    restart()

def reverse_phone_lookup(phone_number):
    query = phone_number
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        'key': API_KEY,
        'cx': CX,
        'q': query,
        'num': 5
    }

    waitmsg(f"Searching for phone number info with {phone_number}...")

    results_data = []
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if 'items' in data and len(data['items']) > 0:
            items = data['items'][:5]
            for idx, item in enumerate(items, start=1):
                page_url = item.get('link')
                if page_url:
                    page_text = fetch_page_text(page_url)
                    results_data.append((idx, page_url, page_text))
        else:
            results_data.append((1, None, "No results found."))
    except requests.exceptions.Timeout:
        results_data.append((1, None, "Request timed out."))
    except requests.exceptions.HTTPError as e:
        results_data.append((1, None, f"HTTP error: {e.response.status_code}"))
    except Exception as e:
        results_data.append((1, None, f"Error: {str(e)}"))

    clear()
    info_text = f"""
╭─{' '*78}─╮
|{' '*28}Reverse Phone Lookup{' '*28}|
|{'='*80}|
|    Phone: {phone_number:<66}|
|{'-'*80}|
"""
    for idx, link, content in results_data:
        info_text += f"| Result #{idx:<2}{' '*(73-len(str(idx)))}|\n"
        if link:
            truncated_link = (link[:75] + "...") if len(link) > 75 else link
            info_text += f"| Link: {truncated_link:<72}|\n"
        info_text += f"|{'-'*78}|\n"
        lines = [content[i:i+78] for i in range(0, len(content), 78)]
        for line in lines:
            info_text += f"| {line:<78}|\n"
        if idx != results_data[-1][0]:
            info_text += f"|{'='*78}|\n"
    info_text += f"╰─{' '*78}─╯"
    Write.Print(info_text, Result_Color, interval=0)
    restart()


def check_ssl_cert(domain):
    clear()
    Write.Print("SSL Certificate Search\n", Head_Color, interval=0)

    waitmsg(f"Checking for SSL Certificate {domain} ...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'N/A')
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('commonName', 'N/A')

        not_before = cert['notBefore']
        not_after = cert['notAfter']
        not_before_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")

        info_text = f"""

|{' '*29}SSL Certificate Info{' '*29}|
|{'='*78}|
|  Domain:       ||  {domain:<58}|
|  Issued To:    ||  {issued_to:<58}|
|  Issued By:    ||  {issued_by:<58}|
|  Valid From:   ||  {str(not_before_dt):<58}|
|  Valid Until:  ||  {str(not_after_dt):<58}|

"""
        Write.Print(info_text, Result_Color, interval=0)
        save_choice = save_message()
        if save_choice == 'y':
            save_details(info_text, "SSL_Certificate")

    except ssl.SSLError as e:
        Write.Print(f" SSL Error: {str(e)}\n", Colors.red, interval=0)
    except socket.timeout:
        Write.Print(" Connection timed out.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f" An error occurred retrieving SSL cert info: {str(e)}\n", Colors.red, interval=0)

    restart()


def check_robots_and_sitemap(domain):
    """
    Attempt to retrieve robots.txt and sitemap.xml from the target domain
    to see if they exist and display or parse interesting contents.
    """
    urls = [
        f"https://{domain}/robots.txt",
        f"https://{domain}/sitemap.xml"
    ]
    result_text = f"""

|{' '*32}Site Discovery{' '*32}|
|{'='*80}|
|   Domain:    {domain:<66}|
|{'-'*80}|
"""
    waitmsg(f"Check Robots and Sitemap from {domain}....")

    for resource_url in urls:
        try:
            resp = requests.get(resource_url, timeout=10)
            if resp.status_code == 200:
                lines = resp.text.split('\n')
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: 200 (OK)\n"
                result_text += f"|{'-'*80}|\n"
                snippet = "\n".join(lines[:10])
                snippet_lines = snippet.split('\n')
                for sline in snippet_lines:
                    trunc = sline[:78]
                    result_text += f"| {trunc:<78}|\n"
                if len(lines) > 10:
                    result_text += "| ... (truncated)\n"
            else:
                result_text += f"| Resource: {resource_url:<66}|\n"
                result_text += f"| Status: {resp.status_code}\n"
            result_text += f"|{'='*80}|\n"
        except requests.exceptions.RequestException as e:
            result_text += f"| Resource: {resource_url}\n"
            result_text += f"| Error: {str(e)}\n"
            result_text += f"|{'='*80}|\n"

    
    Write.Print(result_text, Result_Color, interval=0)
    save_choice = save_message()
    if save_choice == 'y':
            save_details(result_text, "Sitemap_RobotsTxt")
    restart()


def check_dnsbl(ip_address):
    
   
    waitmsg(f"Checking whether the IP{ip_address} is listed in common DNS blacklists (DNSBLs)")

    dnsbl_list = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org"
    ]

    reversed_ip = ".".join(ip_address.split(".")[::-1])
    results = []

    for dnsbl in dnsbl_list:
        query_domain = f"{reversed_ip}.{dnsbl}"
        try:
            answers = dns.resolver.resolve(query_domain, 'A')
            for ans in answers:
                results.append((dnsbl, str(ans)))
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except Exception as e:
            results.append((dnsbl, f"Error: {str(e)}"))

    report = f"""

|{' '*27}DNS BlackList Check{' '*28}|
|{'='*75}|
|  IP: {ip_address:<67}|
|{'-'*75}|
"""
    if results:
        report += "| The IP is listed on the following DNSBL(s):\n"
        for dnsbl, answer in results:
            report += f"|   {dnsbl:<25} -> {answer:<45}|\n"
    else:
        report += "| The IP is NOT listed on the tested DNSBL(s).\n"

    clear()
    Write.Print(report, Result_Color, interval=0)
    save_choice = save_message()
    if save_choice == 'y':
            save_details(report, "DNSBL_Check")
    restart()


def fetch_webpage_metadata(url):
   
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    waitmsg(f" Checking {url} web metadata")
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        title_tag = soup.find("title")
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_keyw = soup.find("meta", attrs={"name": "keywords"})

        title = title_tag.get_text(strip=True) if title_tag else "N/A"
        description = meta_desc["content"] if meta_desc and "content" in meta_desc.attrs else "N/A"
        keywords = meta_keyw["content"] if meta_keyw and "content" in meta_keyw.attrs else "N/A"

        result_text = f"""

|{' '*27}Webpage Metadata{' '*30}|
|{'='*80}|
|  URL:         || {url:<58}|
|  Title:       || {title:<58}|
|  Description: || {description:<58}|
|  Keywords:    || {keywords:<58}|

"""
        Write.Print(result_text, Result_Color, interval=0)
        save_choice = save_message()
        if save_choice == 'y':
            save_details(result_text, "Web_Metadata")
    except Exception as e:
        Write.Print(f" Error fetching metadata: {str(e)}\n", Error_Color, interval=0)

    restart()

def read_file_metadata(file_path):

    file_path = file_path.strip().strip('"').strip("'")
    
    waitmsg(f"Checking MetaData 0f \n {file_path} ...")

    def timeConvert(atime):
        dt = atime
        newtime = datetime.fromtimestamp(dt)
        return newtime.date()
        
    def sizeFormat(size):
         newsize= format(size/1024, ".2f")
         return newsize + " KB"

    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} does not exist.")
        
        Dfile = os.stat(file_path)

        file_size = sizeFormat(Dfile.st_size) 

        file_name = os.path.basename(file_path)
        
        max_length = 60  # Set maximum length
        
        file_creation_time = timeConvert(Dfile.st_birthtime)
        file_modification_time = timeConvert(Dfile.st_mtime)
        file_last_Access_Date = timeConvert(Dfile.st_atime)

        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        metaData_extra = []
        author = None
        owner = Dfile.st_uid


        def get_permission_string(file_mode):
                # Define rwx attributes
                permissions = [
                    stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR,  # Owner permissions
                    stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP,  # Group permissions
                    stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH   # Others permissions
                ]

                # Generate a readable string for permissions
                labels = ['Owner', 'Group', 'Other']
                permission_descriptions = []
                
                for i, label in enumerate(labels):
                    read = 'Yes' if file_mode & permissions[i * 3] else 'No'
                    write = 'Yes' if file_mode & permissions[i * 3 + 1] else 'No'
                    execute = 'Yes' if file_mode & permissions[i * 3 + 2] else 'No'
                    description = f"{label} {{Read: {read}, Write: {write}, Execute: {execute}}}"
                    permission_descriptions.append(description)

                return ', '.join(permission_descriptions)
        
        def gps_extract(exif_dict):
            gps_metadata = exif_dict['GPSInfo']

            #latitudinal information
            #positive latitudes are north of the equator, negative latitudes are south of the equator
            lat_ref_num = 0
            if gps_metadata['GPSLatitudeRef'] == 'N':
                lat_ref_num += 1
            if gps_metadata['GPSLatitudeRef'] == 'S':
                lat_ref_num -= 1

            lat_list = [float(num) for num in gps_metadata['GPSLatitude']]
            lat_coordiante = (lat_list[0]+lat_list[1]/60+lat_list[2]/3600) * lat_ref_num

            #longitudinal information
            #positive longitudes are east of the prime meridian, negative longitudes are west of the prime meridian
            long_ref_num = 0
            if gps_metadata['GPSLongitudeRef'] == 'E':
                long_ref_num += 1
            if gps_metadata['GPSLongitudeRef'] == 'W':
                long_ref_num -= 1

            long_list = [float(num) for num in gps_metadata['GPSLongitude']]
            long_coordiante = (long_list[0]+long_list[1]/60+long_list[2]/3600) * long_ref_num

            
            #return the latitude and longitude as a tuple
            return (lat_coordiante,long_coordiante)

        #permissions = oct(stat.S_IMODE(Dfile.st_mode))
        permissions = get_permission_string(Dfile.st_mode)
       
        
        if(file_type.startswith("image")):
            with Image.open(file_path) as img:
                #tags = img.tag_v2
                metaData_extra.append(f"|{' '*32}Image MetaData{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")

                # extract other basic metadata
                info_dict = {
                    "Filename": img.filename,
                    "Image Size": img.size,
                    "Image Height": img.height,
                    "Image Width": img.width,
                    "Image Format": img.format,
                    "Image Mode": img.mode     
                    
                }

                for label,value in info_dict.items():
                    metaData_extra.append(f"|  {str(label):<10}: ||  {str(value)[:max_length]:<60}|")

                if img.format == 'TIFF':
                    for tag_id, value in img.tag_v2.items():
                        tag_name = TAGS.get(tag_id, tag_id)
                        metaData_extra.append(f"|  {str(tag_name):<10}: ||  {str(value)[:max_length]:<60}|")

                elif(file_path.endswith('.png')): 
                     for key, value in img.info.items():
                        metaData_extra.append(f"|  {str(key):<10}: ||  {str(value)[:max_length]:<60}|")
                else:        
                    imdata = img._getexif()
                    if imdata: 
                        #Get General Metadata
                        #{file_path:<60}
                        for tag_id in imdata:
                            # get the tag name, instead of human unreadable tag id
                            tag = TAGS.get(tag_id, tag_id)
                            data = imdata.get(tag_id)

                            if(tag == "GPSInfo"):
                                gps = gps_extract(imdata)
                                metaData_extra.append(f"|  GPS Coordinates: ||  {gps}  |")
                                continue

                            # decode bytes 
                            if isinstance(data, bytes):
                                try:
                                    data = data.decode('utf-8', errors='ignore')  # Ignore encoding errors
                                except UnicodeDecodeError:
                                    data = '<Unintelligible Data>'
                    
                            #print(f"{tag:25}: {data}")
                            metaData_extra.append(f"|  {str(tag):<10}: ||  {str(data)[:max_length]:<60}|")
            
                    else:
                        metaData_extra.append("No EXIF data found.")    
                    

        elif(file_type == "application/pdf"):
            with open(file_path, "rb") as pdf_file:
                pdf_reader = PyPDF2.PdfReader(pdf_file)
                #author = pdf_reader.getDocumentInfo().author
                #author = pdf_reader.
                pdf_data = pdf_reader.metadata
                metaData_extra.append(f"|{' '*32}PDF Metadata{' '*32}|")
                metaData_extra.append(f"|{'-'*78}|")
                if pdf_data:
                    for key, value in pdf_data.items():
                        metaData_extra.append(f"|  {str(key):<10}:  || {str(value)[:max_length]:<60}|")

                    if pdf_reader.is_encrypted:
                        metaData_extra.append(f"|  Encrypted: || Yes      |")
                    else:
                        metaData_extra.append(f"|  Encrypted: || No      |")
                else:
                    metaData_extra.append("No PDF metadata found.")
                 
        elif(file_path.endswith(('.doc', '.docx'))):
            doc = docx.Document(file_path)
            core_properties = doc.core_properties
            doc_metadata = f"""
|{' '*32}Document Properties{' '*32}
|{'='*78}|
| Title:   || {str(core_properties.title) :<60}|
| Author:  || {str(core_properties.author) :<60}| 
| Subject: || {str(core_properties.subject) :<60}|
| Keywords:|| {str(core_properties.keywords) :<60}|
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created: || {str(core_properties.created) :<60}|
| Modified:|| {str(core_properties.modified) :<60}|
| Category:|| {str(core_properties.category) :<60}|
| Content Status: || {str(core_properties.content_status) :<60}|
| Version: || {str(core_properties.version) :<60}|
| Revision: || {str(core_properties.revision) :<60}|
| Comments: || {str(core_properties.comments) :<60}|
            """

            metaData_extra.append(doc_metadata)    

        elif(file_path.endswith(('.xlsx', '.xlsm'))):
          
                # Load the workbook
                workbook = openpyxl.load_workbook(file_path, data_only=True)
                
                # Access metadata
                properties = workbook.properties
                
                excel_metadata = f"""
|{' '*32}Excel Document Properties{' '*32}
|{'='*78}|
| Title:        || {str(properties.title) :<60}|
| Author:       || {str(properties.creator) :<60}|
| Keywords:     || {str(properties.keywords) :<60}|
| Last Modified By: || {str(properties.lastModifiedBy) :<60}|
| Created:      || {str(properties.created) :<60}|
| Modified:     || {str(properties.modified) :<60}|
| Category:     || {str(properties.category) :<60}|
| Description:  || {str(properties.description) :<60}|
                """
                metaData_extra.append(excel_metadata)    

        elif(file_path.endswith(('.pptx', '.pptm'))):
            try:
                # Load the PowerPoint presentation
                presentation = Presentation(file_path)
                
                
                core_properties = presentation.core_properties

                pptx_metadata = f"""
|{' '*32}PowerPoint Document Properties{' '*31}|
|{'='*78}|
| Title:            || {str(core_properties.title) :<60}|
| Author:           || {str(core_properties.author) :<60}|
| Keywords:         || {str(core_properties.keywords) :<60}|
| Last Modified By: || {str(core_properties.last_modified_by) :<60}|
| Created:          || {str(core_properties.created) :<60}|
| Modified:         || {str(core_properties.modified) :<60}|
| Category:         || {str(core_properties.category) :<60}|
| Description:      || {str(core_properties.subject) :<60}|
                """

                
                metaData_extra.append(pptx_metadata)
                
            except Exception as e:  
                metaData_extra.append(f"[Error] Could not read PowerPoint metadata: {e}")

        elif(file_type.startswith("audio")):
            try:
                    
                    metaData_extra.append(f"|{' '*32}Audio MetaData{' '*32}|")
                    metaData_extra.append(f"|{'-'*78}|")
                     

                    tinytim = TinyTag.get(file_path)

                    if(tinytim):
                        metaData_extra.append(f"|  Title:    || {str(tinytim.title)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Artist:   || {str(tinytim.artist)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Genre:    || {str(tinytim.genre)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Album:    || {str(tinytim.album)[:max_length]:<60}|")
                        metaData_extra.append(f"| Year Released: || {str(tinytim.year)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Composer: || {str(tinytim.composer)[:max_length]:<60}|")
                        metaData_extra.append(f"|  AlbumArtist: || {str(tinytim.albumartist)[:max_length]:<60}|")
                        metaData_extra.append(f"|  TrackTotal: || {str(tinytim.track_total)[:max_length]:<60}|")
                        metaData_extra.append(f"|  Duration: || {f'{tinytim.duration:.2f} seconds':<60}|")
                        metaData_extra.append(f"|  Bitrate:  || {str(tinytim.bitrate) + ' kbps':<60}|")
                        metaData_extra.append(f"|  Sample Rate: || {str(tinytim.samplerate) + ' Hz':<60}|")
                        metaData_extra.append(f"|  Channels: || {str(tinytim.channels):<60}|")





                    if(file_path.endswith('.mp3')):
                        audio = MP3(file_path, ID3=ID3)
                    elif(file_path.endswith('.wav')):
                        audio = wave.open(file_path, 'rb')
                    elif(file_path.endswith('.flac')):
                        audio = FLAC(file_path)
                    elif(file_path.endswith('.ogg')):
                        audio = OggVorbis(file_path)
                    elif(file_path.endswith(('.m4a', '.mp4'))):
                        audio = MP4(file_path)
                    else:
                        audio = None
                    
                    if(audio is None):
                        metaData_extra.append(" \U0001F427 Cant Read Audio File for metadata.\n Unsopported")
                    else:
                        if hasattr(audio, 'items') and audio.items():
                            for tag, value in audio.items():
                                metaData_extra.append(f"|  {str(tag):<10}: ||  {str(value)[:max_length]:<60}|")

                            # Extract specific metadata based on format
                            #if isinstance(audio, MP3) or isinstance(audio, FLAC) or isinstance(audio, OggVorbis) or isinstance(audio, MP4):
                            #        if hasattr(audio.info, 'bitrate'):
                            #            metaData_extra.append(f"|  Bitrate:  || {str(audio.info.bitrate // 1000) + ' kbps':<60}|")

                            #        metaData_extra.append(f"|  Length: || {str(f'{audio.info.length:.2f}') + ' seconds':<60}|")

                            #        if hasattr(audio.info, 'channels'):
                            #            metaData_extra.append(f"|  Channels: || {str(audio.info.channels):<60}|")

                            #        metaData_extra.append(f"|  Sample Rate: || {str(audio.info.sample_rate) + ' Hz':<60}|")
                        
            except Exception as e:
                metaData_extra.append(f"Error processing file: {str(e)}")      
                    



        clear()
        #Write.Print(f"Creation data {file_creation_time}", Colors.green, interval=0)
        

        
        metadata_summary = f"""
|{' '*32}File Metadata{' '*33}|
|{'='*78}|
|  File Path:   || {file_path:<60}|
|  File Name:   || {file_name:<60}|
|  File Size:   || {file_size:<60}|
|  File Type:   || {file_type:<60}|
|  Permission:  || {permissions:<60}|

|  Created:     || {str(file_creation_time):<60}|
|  Modified:    || {str(file_modification_time):<60}|
|  Last Access: || {str(file_last_Access_Date):60}|
"""

        metadata_summary += "\n".join(metaData_extra)

        metadata_summary += "\n" + "="*78 + "\n"
       
        Write.Print(metadata_summary, Result_Color, interval=0)

        
        save_choice = save_message()
        if save_choice == 'y':
            save_details(metadata_summary, "File_Metadata")

    except Exception as e:    
        Write.Print(f" \u2620 Error reading file metadata: {str(e)}",Error_Color, interval=0)
    
    restart()

def hudson_rock_email():
    #clear()

    emaila = Write.Input("\U0001F989 Enter email to check infection status: ", default_color, interval=0)

    waitmsg(f"Checking email {emaila} Infection status")

    try:
        v = validate_email(emaila)
        emailrs = v.email
        Write.Print(f" Valid email: {emailrs}", Wait_Color, interval=0)
    except EmailNotValidError as e:
        Write.Print(f" Invalid email format: {str(e)}", Error_Color, interval=0)
        restart()
        return
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email"
        params = {"email": emaila}
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        #clear()
        Write.Print(f"\n\U0001F43C Hudson Rock email infection check results for {emaila}:\n", Wait_Color, interval=0)
        #Write.Print(json.dumps(data, indent=2), Colors.white, interval=0)


        messageData = data['message']
        HudsonRock_Summary = f"""
|{' '*32}HudsonRock Email Summary{' '*33}|
|{'='*78}|
|  Email:   || {emailrs:<60}|
|                           |
|  Message:  
        {messageData}

|{'-'*78}|
"""

        stealers = data.get('stealers', [])
        
        # Check if the stealers list is empty
        if not stealers:
            #print("Stealers: None")
            HudsonRock_Summary += f"""|  Stealers: || {('None'):<60}|\n"""
        else:
            #print("Stealers:")
           # Initialize the table string
            table_str = f"{'=' * 80}\n| {'Stealers Data':^76} |\n{'=' * 80}\n"

            # Iterate over stealers and format each as a row in the table
            for i, stealer in enumerate(stealers, start=1):
                antiviruses = ', '.join(stealer.get('antiviruses', []))
                top_passwords = ', '.join(stealer.get('top_passwords', []))
                top_logins= ', '.join(stealer.get('top_logins', []))
                table_str += (
                    f"| {'Stealer':<15} | {i:<60}|\n"
                    f"| {'-' * 78}|\n"
                    f"| {'Computer Name':<15} | {stealer.get('computer_name', 'Unknown'):<60}|\n"
                    f"| {'Operating System':<15} | {stealer.get('operating_system', 'Unknown'):<60}|\n"
                    f"| {'Malware Path':<15} | {stealer.get('malware_path', 'Unknown'):<60}|\n"
                    f"| {'Date Compromised':<15} | {stealer.get('date_compromised', 'Unknown'):<60}|\n"
                    f"| {'IP Address':<15} | {stealer.get('ip', 'Unknown'):<60}|\n"
                    f"| {'Antiviruses':<15} | {antiviruses:<60}|\n"
                    f"| {'Top Passwords':<15} | {top_passwords:<60}|\n"
                    f"| {'Top Logins':<15} | {top_logins:<60}|\n"
                    f"{'-' * 80}\n"
                )
             #Write.Print(table_str, Colors.white, interval=0)       
            HudsonRock_Summary += table_str 
       

        HudsonRock_Summary += f""" 
|{'='*78}|
|  Total Corporate Services:   || {(data['total_corporate_services']):<60}|
|  Total User Services:   || {(data['total_user_services']):<60}|
|{'-'*78}|
        
        """



        Write.Print(HudsonRock_Summary, Result_Color, interval=0)
        save_choice = save_message()
        if save_choice == 'y':
            save_details(HudsonRock_Summary, "HudosnRock_Email") 
    except requests.exceptions.Timeout:
        #clear()
        Write.Print(" Request timed out when contacting Hudson Rock.\n", Error_Color, interval=0)
    except Exception as e:
        #clear()
        Write.Print(f" Error: {str(e)}", Error_Color, interval=0)

       
    restart()

def hudson_rock_domain():
    domainola = Write.Input("\U0001F989 Enter domain to check infection status: ", default_color, interval=0)

    if not domainola:
        clear()
        Write.Print("\u2620 No domain provided.\n", Error_Color, interval=0)
        restart()
        return
    waitmsg(f"Checking Infection status of {domainola}");
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
        params = {"domain": domainola}
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        #clear()
        Write.Print(f"\n \U0001F43C Hudson Rock domain infection check results for {domainola}:\n", Wait_Color, interval=0)
        #Write.Print(json.dumps(data, indent=2), Colors.white, interval=0)

        #Write.Print(f"\n \U0001F422 Checking Domain {domainola}:\n", Colors.green, interval=0)


        #messageData = data['message']
        HudsonRock_Summary = f"""
|{' '*32}HudsonRock Domain Summary{' '*33}|
|{'='*78}|
|  Total:   || {(data['total']):<60}|
| Total Stealers: || {(data['totalStealers']):<40}|
|  Employees:   || {(data['employees']):<60}|
|  Users:   || {(data['users']):<60}|
|  Third Parties:   || {(data['third_parties']):<60}|
|  Logo:   || {(data['logo']):<60}|
|{'-'*78}|
"""

        #Write.Print(f"\n \U0001F422 Check ii", Colors.green, interval=0)
        dataii = data.get('data', [])
        
        # Check if the stealers list is empty
        if not dataii:
            #print("Stealers: None")
            HudsonRock_Summary += f"""|  Data: || {('None'):<60}|\n"""
        else:
            #print("Stealers:")
           # Initialize the table string
            table_str = f"{'=' * 80}\n| {'Data':^76} |\n{'=' * 80}\n"

            # Process each list of URLs
            all_categories = ['employees_urls', 'clients_urls', 'all_urls']
            for category in all_categories:
                urls = data['data'].get(category, [])
                if urls:
                    table_str += f"\n| {category.replace('_', ' ').title():<78} |\n{'-' * 80}\n"
                    for i, url_data in enumerate(urls, start=1):
                        table_str += (
                            f"| {'Entry':<15} | {i:<60}|\n"
                            f"| {'Occurrence':<15} | {url_data.get('occurrence', 'Unknown'):<60}|\n"
                            f"| {'Type':<15} | {url_data.get('type', 'Unknown'):<60}|\n"
                            f"| {'URL':<15} | {url_data.get('url', 'Unknown'):<60}|\n"
                            f"{'-' * 80}\n"
                        )
                    #Write.Print(table_str, Colors.white, interval=0)       
                    HudsonRock_Summary += table_str 
       
       
        HudsonRock_Summary += f""" 
|{'='*78}|
|  Total Urls:   || {(data['totalUrls']):<60}|
|{'-'*78}|
        
        """

        stats = data.get('stats', [])

        if not stats:
            HudsonRock_Summary += f"|  No stats available.\n"
        else:
            employees_urls = stats['employees_urls']
            clients_urls = stats['clients_urls']
            employees_count = stats['employees_count']
            clients_count = stats['clients_count']

            # Format the employee URLs and counts
            table_str += f"\n| {'Employees URLs and Counts':<78} |\n{'-' * 80}\n"
            for i, (url, count) in enumerate(zip(employees_urls, employees_count), start=1):
                table_str += (
                    f"| {'Entry':<15} | {i:<60}|\n"
                    f"| {'URL':<15} | {url:<60}|\n"
                    f"| {'Count':<15} | {count:<60}|\n"
                    f"{'-' * 80}\n"
                )

            # Format the client URLs and counts
            table_str += f"\n| {'Clients URLs and Counts':<78} |\n{'-' * 80}\n"
            for i, (url, count) in enumerate(zip(clients_urls, clients_count), start=1):
                table_str += (
                    f"| {'Entry':<15} | {i:<60}|\n"
                    f"| {'URL':<15} | {url:<60}|\n"
                    f"| {'Count':<15} | {count:<60}|\n"
                    f"{'-' * 80}\n"
                )
    
            
            HudsonRock_Summary += f"""
|{'='*78}|
|{' '*32}Stats Summary{' '*33}|
|{'-'*78}|
|  Total Employees:   || {(stats['totalEmployees']):<40}|
|  Total Users: || {(stats['totalUsers']):<40}|
 """
            HudsonRock_Summary += table_str


            HudsonRock_Summary += f"| {'Shopify Status':<15} | {('Yes' if data['is_shopify'] else 'No'):<60}|\n"
            HudsonRock_Summary += f"| {'Last Employee Compromised':<27} | {data['last_employee_compromised']:<46}|\n"
            HudsonRock_Summary += f"| {'Last User Compromised':<27} | {data['last_user_compromised']:<46}|\n"

             # Password Statistics Section
            HudsonRock_Summary += f"\n{'-' * 80}\n| {'Employee Password Stats':<78} |\n{'-' * 80}\n"
            emp_pass = data['employeePasswords']

            if(emp_pass is None):
                HudsonRock_Summary += f"|  Employee Passwords: || {('None'):<60}|\n"
            else:  
                HudsonRock_Summary += f"""
|{' '*16}Employee Passwords Summary {' '*16}|
| {'Total':<24} | {emp_pass['totalPass']:<51}|"
| {'Too Weak':<24} | Qty: {emp_pass['too_weak']['qty']}, Perc: {emp_pass['too_weak']['perc']}%<40 |"
| {'Weak':<24} | Qty: {emp_pass['weak']['qty']}, Perc: {emp_pass['weak']['perc']}%<40 |"
| {'Medium':<24} | Qty: {emp_pass['medium']['qty']}, Perc: {emp_pass['medium']['perc']}%<40 |"
| {'Strong':<24} | Qty: {emp_pass['strong']['qty']}, Perc: {emp_pass['strong']['perc']}%<40 |"
"""

            HudsonRock_Summary += f"\n{'-' * 80}\n| {'User Password Stats':<78} |\n{'-' * 80}\n"

            
            user_pass = data['userPasswords']
            if(user_pass is None):
                HudsonRock_Summary += f"|  User Passwords: || {('None'):<60}|\n"
            else:
                HudsonRock_Summary += f"""
|{' '*16}User Passwords Summary {' '*16}|
| {'Total':<24} | {user_pass['totalPass']:<51}|"
| {'Too Weak':<24} | Qty: {user_pass['too_weak']['qty']}, Perc: {user_pass['too_weak']['perc']}%<40 |"
| {'Weak':<24} | Qty: {user_pass['weak']['qty']}, Perc: {user_pass['weak']['perc']}%<40 |\n"
| {'Medium':<24} | Qty: {user_pass['medium']['qty']}, Perc: {user_pass['medium']['perc']}%<40 |"
| {'Strong':<24} | Qty: {user_pass['strong']['qty']}, Perc: {user_pass['strong']['perc']}%<40 |"

            """
            
            # Antivirus Section
            antiviruses = data['antiviruses']

            if antiviruses is None:
                HudsonRock_Summary += f"|  Antiviruses: || {('None'):<60}|\n"
            else:    
                HudsonRock_Summary += f"\n{'-' * 80}\n| {'Antivirus Stats':<78} |\n{'-' * 80}\n"
                HudsonRock_Summary += (
                    f"| {'Total':<24} | {antiviruses['total']:<51}|\n"
                    f"| {'Found':<24} | {antiviruses['found']}%{' ':<59}|\n"
                    f"| {'Not Found':<24} | {antiviruses['not_found']}%{' ':<59}|\n"
                    f"| {'Free':<24} | {antiviruses['free']}%{' ':<59}|\n"
                )     

                # Antivirus List
                if 'list' in antiviruses:
                    HudsonRock_Summary += f"\n| {'Antivirus Details':<78} |\n{'-' * 80}\n"
                    for av in antiviruses['list']:
                        HudsonRock_Summary += f"| {av['name']:<60} | Count: {av['count']:<10}|\n"

            # Stealer Families
            stealer_families = data['stealerFamilies']
            if stealer_families is None:
                HudsonRock_Summary += f"|  stealerFamilies: || {('None'):<60}|\n"
            else:               
                HudsonRock_Summary += f"\n{'-' * 80}\n| {'Stealer Families':<78} |\n{'-' * 80}\n"
                HudsonRock_Summary += f"| {'Total':<15} | {stealer_families['total']:<60}|\n"
                for name, count in stealer_families.items():
                    if name != 'total':
                        HudsonRock_Summary += f"| {name:<30} | {count:<46}|\n"
            
            third_party = data['thirdPartyDomains']
           
            #Write.Print(f"\n \U0001F422 Check iii", Colors.green, interval=0)
            if not third_party:  # Check if the list is empty
                HudsonRock_Summary += f"| Third Party Domains:|| {'None':<60}|\n"
            else:
                HudsonRock_Summary += f"\n{'-' * 80}\n| {'Third Party Domains':<78} |\n{'-' * 80}\n"
                for entry in third_party:
                    domain = entry.get('domain') or 'Unknown'
                    occurrence = entry.get('occurrence', 0)
                    # Ensure domain is string and occurrence is converted to string for formatting
                    HudsonRock_Summary += f"| {'Domain':<15} | {str(domain):<50} | Occurrence: {str(occurrence):<9}|\n"

        
        Write.Print(HudsonRock_Summary, Result_Color, interval=0)
        save_choice = save_message()
        if save_choice == 'y':
            save_details(HudsonRock_Summary, "HudosnRock_Domain") 
    except requests.exceptions.Timeout:
        #clear()
        Write.Print(" Request timed out when contacting Hudson Rock.\n", Error_Color, interval=0)
    except Exception as e:
        #clear()
        Write.Print(f" Error: {str(e)}", Error_Color, interval=0)

       
    restart()

def hudson_rock_username():

        username = Write.Input(" \U0001F989 Enter username to check infection status: ", default_color, interval=0).strip()
        if not username:
            clear()
            Write.Print(" No username provided.\n", Error_Color, interval=0)
            restart()
            return
        
        waitmsg(f"Checking for infection status of username {username}")
        try:
            url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username"
            params = {"username": username}
            resp = requests.get(url, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
           
            HudsonRock_Summary = f"""
             
{' '*32}HudsonRock Username Summary{' '*33}|
|{'='*78}|
"""
            
            # Message section
            HudsonRock_Summary += f"\n{'=' * 80}\n"
            HudsonRock_Summary += f"Message: {data['message']}\n"
            HudsonRock_Summary += f"{'=' * 80}\n\n"
            
            # Stealers details
            stealers = data.get('stealers', [])
            if not stealers:
                HudsonRock_Summary += "Stealers: None\n"
            else:
                for i, stealer in enumerate(stealers, start=1):
                    antiviruses = stealer.get('antiviruses')
                    antivirus_str = ', '.join(antiviruses) if isinstance(antiviruses, list) else antiviruses
                    
                    HudsonRock_Summary += f"Stealer {i}:\n"
                    HudsonRock_Summary += f"{'=' * 70}\n"
                    HudsonRock_Summary += (
                        f"  Family: {stealer.get('stealer_family', 'Unknown')}\n"
                        f"  Computer Name: {stealer.get('computer_name', 'Unknown')}\n"
                        f"  OS: {stealer.get('operating_system', 'Unknown')}\n"
                        f"  Date Compromised: {stealer.get('date_compromised', 'Unknown')}\n"
                        f"  IP Address: {stealer.get('ip', 'Unknown')}\n"
                        f"  Malware Path: {stealer.get('malware_path', 'Unknown')}\n"
                        f"  Antiviruses: {antivirus_str}\n"
                        f"  Total Corporate Services: {stealer.get('total_corporate_services', 0)}\n"
                        f"  Total User Services: {stealer.get('total_user_services', 0)}\n"
                        f"  Top Passwords: {', '.join(stealer.get('top_passwords', []))}\n"
                        f"  Top Logins: {', '.join(stealer.get('top_logins', []))}\n"
                    )
                    HudsonRock_Summary += f"{'-' * 70}\n\n"
            
            # Total Services
            HudsonRock_Summary += f"{'=' * 80}\n"
            HudsonRock_Summary += f"Total Corporate Services: {data.get('total_corporate_services', 0)}\n"
            HudsonRock_Summary += f"Total User Services: {data.get('total_user_services', 0)}\n"
            HudsonRock_Summary += f"{'=' * 80}\n"



            Write.Print(HudsonRock_Summary, Result_Color, interval=0)
            save_choice = save_message()
            if save_choice == 'y':
                save_details(HudsonRock_Summary, "HudsonRock_UserName") 
        except requests.exceptions.Timeout:
            #clear()
            Write.Print(" Request timed out when contacting Hudson Rock.\n", Error_Color, interval=0)
        except Exception as e:
            #clear()
            Write.Print(f" Error: {str(e)}", Error_Color, interval=0)

        
        restart()

def hudson_rock_ip():
    ip_address = Write.Input(" \U0001F989 Enter IP address to check infection status: ", default_color, interval=0).strip()
    if not ip_address:
        clear()
        Write.Print("\u2620 > No IP provided.\n", Error_Color, interval=0)
        restart()
        return
    waitmsg(f"Checking Ip Address {ip_address} for infection status")
    try:
        url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-ip"
        params = {"ip": ip_address}
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        clear()
        #Write.Print(f"\n[+] Hudson Rock IP infection check results for {ip_address}:\n", Colors.green, interval=0)
        #Write.Print(json.dumps(data, indent=2), Colors.white, interval=0)

         # Create summary table
        hudson_summary = f"|{' '*15}HudsonRock IP Address Summary{' '*17}|"
        
        # Message section
        hudson_summary += f"\n{'=' * 80}\n"
        hudson_summary += f"IP Address: {ip_address}"
        hudson_summary += f"\n{'-' * 80}\n"
        hudson_summary += f"Message: {data['message']}\n"
        hudson_summary += f"{'=' * 80}\n\n"
        
        # Stealers details
        stealers = data.get('stealers', [])
        if not stealers:
            hudson_summary += "Stealers: None\n"
        else:
            for i, stealer in enumerate(stealers, start=1):
                antivirus_list = stealer.get('antiviruses', [])
                antivirus_str = ', '.join(antivirus_list) if antivirus_list else "None"
                
                hudson_summary += f"Stealer {i}:\n"
                hudson_summary += f"{'=' * 20}\n"
                hudson_summary += (
                    f"  Computer Name: {stealer.get('computer_name', 'Unknown')}\n"
                    f"  IP Address: {stealer.get('ip', 'Unknown')}\n"
                    f"  OS: {stealer.get('operating_system', 'Unknown')}\n"
                    f"  Date Compromised: {stealer.get('date_compromised', 'Unknown')}\n"
                    f"  Malware Path: {stealer.get('malware_path', 'Unknown')}\n"
                    f"  Antiviruses: {antivirus_str}\n"
                    f"  Total Corporate Services: {stealer.get('total_corporate_services', 0)}\n"
                    f"  Total User Services: {stealer.get('total_user_services', 0)}\n"
                    f"  Top Passwords: {', '.join(stealer.get('top_passwords', []))}\n"
                    f"  Top Logins: {', '.join(filter(None, stealer.get('top_logins', [])))}\n"
                )
                hudson_summary += f"{'-' * 20}\n\n"
        
        # Total Services
        hudson_summary += f"{'=' * 80}\n"
        hudson_summary += f"Total Corporate Services: {data.get('total_corporate_services', 0)}\n"
        hudson_summary += f"Total User Services: {data.get('total_user_services', 0)}\n"
        hudson_summary += f"{'=' * 80}\n"

        Write.Print(hudson_summary, Result_Color, interval=0)

        save_choice = save_message()
        if save_choice == 'y':
                save_details(hudson_summary, "HudsonRock_IP") 
    except requests.exceptions.Timeout:
        clear()
        Write.Print(" Request timed out when contacting Hudson Rock.\n", default_color, interval=0)
    except Exception as e:
        clear()
        Write.Print(f" Error: {str(e)}", Error_Color, interval=0)
    restart()

def Front_Page():

            T = "OLA" 
            P = "Osint"
            ASCII_art_1 = pyfiglet.figlet_format(T, font='isometric1')
            colored_ASCII_art_1 = colored(ASCII_art_1, 'green')  # Change 'cyan' to any color you prefer
            ASCII_art_2 = pyfiglet.figlet_format(P, font='isometric1')
            colored_ASCII_art_2 = colored(ASCII_art_2, 'green')  # Change 'cyan' to any color you prefer

            print(colored_ASCII_art_1)
            #print("\n")
            print(colored_ASCII_art_2)
                  
            author = f" \u0398 By Olamide Owolabi "
            Write.Print(author + "\n OSint Tool\n", Result_Color, interval=0)



def main():
    while True:
        try:
            clear()

            load_default_colors()
            Front_Page()
            
           
            menu = """
╔═════════════════════════════════════════════════════════════════════════════════════════╗
║  №   │      Function          │ Description                                             ║
╠══════╪════════════════════════╪═════════════════════════════════════════════════════════╣
║ [1]  │ IP Address Search      │ Gathers IP address info                                 ║
║ [2]  │ Account Search         │ Gathers profiles from various websites                  ║
║ [3]  │ Phone Search           │ Gathers phone number info                               ║
║ [4]  │ DNS Search             │ Gathers DNS records, whois info                         ║
║ [5]  │ Email Search           │ Gathers MX info for an email                            ║
║ [6]  │ Email Search Accounts  │ Gathers Accounts where the email is registered          ║
║ [7]  │ Person Name Search     │ Gathers Person related info based on Google Search      ║
║ [8]  │ Email Raw Data Search  │ Gathers info from an email raw data                     ║
║ [9]  │ Email Breach Search    │ Gathers email data breach info (HIBP)                   ║
║ [11] │ Password Analyzer      │ Analyzes password strength and checks for data breaches ║
║ [12] │ Username Search        │ Gathers accounts that utilizes Username                 ║
║ [13] │ Reverse Phone Search   │ Gathers references to a phone number using Google Search║
║ [14] │ SSL Cert Search        │ Gathers basic SSL certificate details                   ║
║ [15] │ Robots.txt/Sitemap     │ Gathers robots.txt & sitemap.xml info                   ║
║ [16] │ DNSBL Check            │ Gathers IPDNS blacklist info                            ║
║ [17] │ Web Metadata Info      │ Gathers meta tags and more from a webpage               ║
║ [18] │ File Metadata Info     │ Gathers meta data from local file path                  ║
| [19] | HR Email Search        │ Gathers infostealer email infection data (Hudson Rock)  ║
| [20] | HR Domain Search       │ Gathers infostealer domain infection data (Hudson Rock) ║
| [21] | HR User Search         │ Gathers infostealer username infection data (Hudson Rock)║
| [22] | HR IP Search           │ Gathers infostealer IP address infection data (Hudson Rock)║
╠══════╪════════════════════════╪═════════════════════════════════════════════════════════╣
║ [0]  │ Exit                   │ Exit the program                                        ║
║ [99] │ Settings               │ Customize tool                                          ║
╚═════════════════════════════════════════════════════════════════════════════════════════╝
"""
            Write.Print(menu, Colors.white, interval=0)

            choice = Write.Input("[?] >  ", default_color, interval=0).strip()

            if choice == "1":
                clear()
                Write.Print(" IP Address Search \n", Head_Color, interval=0)
                press_zero()

                ip = Write.Input(" \U0001F989 Please enter IP-Address: " , default_color, interval=0)

                if ip == "0":
                    clear()
                    zero_pressed()
                    continue

                if not ip:
                    clear()
                    Write.Print(" \U0001F98B Enter IP Address\n", Error_Color, interval=0)
                    continue
                ip_info(ip)

            elif choice == "2":
                clear()
                Write.Print(" Username Account Search \n", Head_Color, interval=0)
                
                press_zero()
                nickname = Write.Input(" \U0001F989 Enter a Username: ", default_color, interval=0)
                
                Write.Print(" \U0001F422 Conducting deep account search...\n", default_color, interval=0)

                if nickname == "0":
                    clear()
                    zero_pressed()
                    continue

                if not nickname:
                    clear()
                    Write.Print(" \U0001F989 Enter username\n", Error_Color, interval=0)
                    continue
                account_search(nickname)

            elif choice == "3":
                clear()
                Write.Print(" Phone Number Search \n", Head_Color, interval=0)
                press_zero()
                phone_number = Write.Input(" \U0001F989 Enter a valid Phone number:", default_color, interval=0)
                
                if phone_number == "0":
                   clear()
                   zero_pressed()
                   continue

                if not phone_number:
                    clear()
                    Write.Print(" Enter phone number\n", default_color, interval=0)
                    continue
                phone_info(phone_number)

            elif choice == "4":
                clear()
                Write.Print(" Domain Search \n", Head_Color, interval=0)
                press_zero()
                domain = Write.Input(" \U0001F989 Enter Domain: \n  ", default_color, interval=0)
                
                if domain == "0":
                   clear()
                   zero_pressed()
                   continue

                if not domain:
                    clear()
                    Write.Print(" Enter domain\n", default_color, interval=0)
                    continue
                Write.Print(" \U0001F422 Retrieving DNS records...\n", default_color, interval=0)
                dns_lookup(domain)

            elif choice == "5":
                clear()
                Write.Print(" Email Search \n", Head_Color, interval=0)

                press_zero()
                email = Write.Input(" \U0001F989 Enter a valid Email: ", default_color, interval=0)

                if email == "0":
                   clear()
                   zero_pressed()
                   continue

                if not email:
                    clear()
                    Write.Print(" Enter email\n", default_color, interval=0)
                    continue
                email_lookup(email)

            elif choice == "6":
                clear()
                Write.Print(" Email to Registered Accounts Search \n", Head_Color, interval=0)

                press_zero()
                email = Write.Input(" \U0001F989 Enter a valid Email: ", default_color, interval=0)

                if email == "0":
                   clear()
                   zero_pressed()
                   continue

                if not email:
                    clear()
                    Write.Print(" Enter email\n", default_color, interval=0)
                    continue
                email_Phlint(email)    

            elif choice == "7":
                clear()
                Write.Print(" Person Search with location \n", Head_Color, interval=0)
                press_zero()

                Write.Print("\n", Head_Color, interval=0)

               
                first_name = Write.Input(" \U0001F989 First Name: ", default_color, interval=0)
                last_name = Write.Input(" \U0001F989 Last Name: ", default_color, interval=0)
                city = Write.Input(" \U0001F989 City/Location: ", default_color, interval=0)

                if "0" in [first_name, last_name, city]:
                    clear()
                    continue


                if not first_name or not last_name:
                    clear()
                    Write.Print(" Enter first and last name\n", default_color, interval=0)
                    continue
                Write.Print(" Searching the given name and location...\n", default_color, interval=0)
                #test_person_search()
                person_search(first_name, last_name, city)


            elif choice == "8":
                clear()
                Write.Print(" Email Raw Data Search \n", Head_Color, interval=0)

                press_zero()
                
               
                
                while True:
                    email_data = capture_email_input()

                    if email_data is None:
                        zero_pressed()  # Call the zeroPress function when input is canceled
                        continue
                    if not email_data.strip():
                        print(" No email data provided.\n")
                        continue

                    try:
                        analyze_email_raw_data(email_data)
                    except Exception as e:
                        print(f"An error occurred while analyzing the email data: {e}")

            elif choice == "9":
                clear()
                Write.Print(" Email Breach Check\n", Head_Color, interval=0)
                press_zero()

                email = Write.Input(" \U0001F989 Enter an Email to check if breached ", default_color, interval=0)

                if email == "0":
                     clear()
                     zero_pressed()
                     continue
                if not email:
                    clear()
                    Write.Print(" Enter email\n", default_color, interval=0)
                    continue
                haveibeenpwned_check(email)
     
            elif choice == "11":
                Write.Print(" Password  Checker\n", Head_Color, interval=0)
                press_zero()
                password = Write.Input(" \U0001F989 Enter password to evaluate strength:\n", default_color, interval=0)
                if password == "0":
                    clear()
                    zero_pressed()
                else:
                 check_password(password)

            elif choice == "12":
                clear()
                Write.Print(" Username Check\n", Head_Color, interval=0)
                press_zero()
                usernam =  Write.Input(" \U0001F989 Enter Username to search: ", default_color, interval=0)
                
                if usernam == "0":
                    clear()
                    zero_pressed()
                else:
                    username_check(usernam.strip())

            elif choice == "13":
                clear()
                Write.Print("Phone Number reverse Lookup\n", Head_Color, interval=0)
                press_zero()

                phone_number = Write.Input("Enter Phone number: ", default_color, interval=0)
                
                if phone_number == "0":
                    clear()
                    zero_pressed()
                    continue
                
                if not phone_number:
                    clear()
                    Write.Print(" Enter phone number\n", default_color, interval=0)
                    continue
                reverse_phone_lookup(phone_number)

            
            elif choice == "14":
                clear()
                Write.Print("SSL Certificate Search\n", Head_Color, interval=0)
                press_zero() 
                


                domain = Write.Input("Enter Domain for SSL check: ", default_color, interval=0)

                if domain == "0":
                    clear()
                    zero_pressed()
                    continue

                if not domain:
                    clear()
                    Write.Print(" Enter a domain\n", default_color, interval=0)
                    continue
                check_ssl_cert(domain)

            elif choice == "15":
                clear()
                Write.Print(" Robot text lookup and Sitemap \n", Head_Color, interval=0)
                press_zero()

                domain = Write.Input(" \U0001F989 Enter Domain to check for robots.txt & sitemap: ", default_color, interval=0)
                
                if domain == "0":
                    clear()
                    zero_pressed()
                
                if not domain:
                    clear()
                    Write.Print(" Enter a domain\n", default_color, interval=0)
                    continue
                check_robots_and_sitemap(domain)

            elif choice == "16":
                clear()
                Write.Print(" DNSBL Check \n", Head_Color, interval=0)
                press_zero()
                ip_address = Write.Input(" \U0001F989 Enter IP address to check DNSBL: ", default_color, interval=0)

                if ip_address == "0":
                    clear()
                    zero_pressed()
                    continue

                if not ip_address:
                    clear()
                    Write.Print(" Enter an IP address\n", default_color, interval=0)
                    continue
                check_dnsbl(ip_address)

            elif choice == "17":
                clear()
                Write.Print(" Web Metadata Info \n", Head_Color, interval=0)
                press_zero()

                url = Write.Input(" \U0001F989 URL for metadata extraction: (include https:// )", default_color, interval=0)
                if url == "0":
                    clear()
                    zero_pressed()
                    continue

                if not url:
                    clear()
                    Write.Print("  Enter a URL with https:// \n", default_color, interval=0)
                    continue
                fetch_webpage_metadata(url)

            elif choice == "18":
                clear()
                Write.Print(" File Metadata Info \n", Head_Color, interval=0)
                press_zero()

                file_path = Write.Input(" \U0001F989 Enter the path to the file: ", default_color, interval=0)
                if file_path == "0":
                    clear()
                    zero_pressed()
                    continue

                if not file_path:
                    clear()
                    Write.Print("  Enter a valid file path\n", default_color, interval=0)
                    #continue
                read_file_metadata(file_path)   

            elif choice == "19":
                clear()
                Write.Print(" Hudson Rock Email Check \n", Head_Color, interval=0)
                press_zero()

                hudson_rock_email()   

            elif choice == "20":
                clear()
                Write.Print(" Hudson Rock Domain Check \n", Head_Color, interval=0)
                press_zero()

               # hudson_rock_email()     
                hudson_rock_domain() 

            elif choice == "21":
                clear()
                Write.Print(" Hudson Rock UserName Check \n", Head_Color, interval=0)
                press_zero()
             
                hudson_rock_username() 

            elif choice == "22":
                clear()
                Write.Print(" Hudson Rock Ip Address Check \n", Head_Color, interval=0)
                press_zero()
             
                hudson_rock_ip()   

            elif choice == "0":
                clear()
                Write.Print("\n \U0001F6AA Exiting...", Exit_Color, interval=0)
                exit()

            elif choice == "99":
                settings()

            else:
                clear()
                Write.Print(" \u2620 Invalid input.\n", Error_Color, interval=0)

        except KeyboardInterrupt:
            clear()
            Write.Print(" \u26A0 Exiting on user request...\n", Exit_Color, interval=0)
            exit()

def settings():
    while True:
        try:
            clear()
            Front_Page()

            settings_menu = """                                ─
|  №   ||       Setting       ||                Description                |
|======||=====================||===========================================|
| [1]  || Change default      || Customize the default theme color         |
| [2]  || Change header       || Customize the Header color                |
| [3]  || Change exit         || Customize the Exit message color          |
| [4]  || Change Error        || Customize the Error message color         |
| [5]  || Change Wait         || Customize the Wait message color          |
| [6]  || Change Result       || Customize the color of the outputs        |
|------||---------------------||-------------------------------------------|
| [0]  || Back to menu        || Exit the settings                         |


"""
            Write.Print(settings_menu, Result_Color, interval=0)

            settings_choice = Write.Input("[?] >  ", default_color, interval=0).strip()

            if settings_choice == "1":
                change_color("default_color")
            elif settings_choice == "2":
                change_color("Head_Color")
            elif settings_choice == "3":
                change_color("Exit_Color")
            elif settings_choice == "4":
                change_color("Error_Color")
            elif settings_choice == "5":
                change_color("Wait_Color")
            elif settings_choice == "6":
                change_color("Result_Color")    
            elif settings_choice == "0":
                return
            else:
                clear()
                Write.Print(" Invalid input.\n", Error_Color, interval=0)

        except KeyboardInterrupt:
            clear()
            Write.Print("  Exiting on user request...\n", Exit_Color, interval=0)
            exit()

if __name__ == "__main__":
    main()
