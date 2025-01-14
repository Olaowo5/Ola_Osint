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


default_color = Colors.cyan
Head_Color = Colors.purple
Exit_Color = Colors.yellow
Error_Color = Colors.red

API_KEY = "ENTER GOOGLE CUSTOM SEARCH API KEY HERE"
CX = "ENTER GOOGLE CUSTOM SEARCH CX HERE"
CLIENT_ID = "ENTER GOOGLE CUSTOM SEARCH CLIENT ID HERE"
HIBP_API_KEY = "ENTER HAVE I BEEN PWNED API KEY HERE"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def restart():
    Write.Input("\nPress Enter to return to the main menu...", default_color, interval=0)
    clear()

def save_details(data,NameData):
    try:
        #Ensure its string
        if not isinstance(data, str):
                data = str(data)
        
        cwd = os.getcwd()
        print(f"Current working directory is: {cwd}")

        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        print(current_time)
    
        filename = f"Saves/{NameData}_{current_time}.txt"
        print(f"the filename {filename}")
        print(data)

        # Define the file path
        #file_path = Path(filename)

        # Write data to the file
        #file_path.write_text(data)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(data)

        Write.Print(f"\n {NameData} details saved to {filename}\n", Colors.green, interval=0)
    except Exception as e:
        #clear()
        Write.Print(f"\n Error Saving {NameData} to file", default_color, interval=0)

def get_ip_details(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        response.raise_for_status()
        return response.json()
    except:
        return None

def person_search(first_name, last_name, city):
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
                    results_data.append((idx, page_text))
        else:
            results_data.append((1, "No results found."))
    except requests.exceptions.Timeout:
        results_data.append((1, "Request timed out."))
    except requests.exceptions.HTTPError as e:
        results_data.append((1, f"HTTP error: {e.response.status_code}"))
    except Exception as e:
        results_data.append((1, f"Error: {str(e)}"))

    clear()
    info_text = f"""
╭─{' '*78}─╮
|{' '*29}Person Search Summary{' '*29}|
|{'='*80}|
| [+] > Name: {first_name} {last_name:<62}|
| [+] > Location: {city:<62}|
|{'-'*80}|
"""
    for idx, content in results_data:
        info_text += f"| Result #{idx:<2}{' '*(73-len(str(idx)))}|\n"
        info_text += f"|{'-'*78}|\n"
        lines = [content[i:i+78] for i in range(0, len(content), 78)]
        for line in lines:
            info_text += f"| {line:<78}|\n"
        if idx != results_data[-1][0]:
            info_text += f"|{'='*78}|\n"
    info_text += f"╰─{' '*78}─╯"
    Write.Print(info_text, Colors.white, interval=0)
    restart()

def fetch_page_text(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36)"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")

        for tag_name in ["header", "footer", "nav", "aside", "script", "style", "noscript", "form"]:
            for t in soup.find_all(tag_name):
                t.decompose()

        text = soup.get_text(separator=' ')
        text = ' '.join(text.split())
        return text if text else "No meaningful content found."
    except Exception:
        return "Could not retrieve or parse the webpage content."

def ip_info(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        loc = data.get('loc', 'None')
        maps_link = f"https://www.google.com/maps?q={loc}" if loc != 'None' else 'None'

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
╰────────────────────────────────────────────────────────────────────────────╯
"""
        Write.Print(ip_detailo, Colors.white, interval=0)

        # Ask the user if they want to save the details to a file
        #save_choice = Write.Input("\n[?] > Do you want to save these details to a file? (y/n): ", default_color, interval=0).strip().lower()
        #if save_choice == 'y':
        save_details(ip_detailo, "IP_address")

    except Exception as e:
        #clear()
        Write.Print("\n[!] > Error retrieving IP address info.", default_color, interval=0)

    restart()

def fetch_social_urls(urls, title):
    def check_url(url):
        try:
            response = requests.get(url, timeout=10)
            status_code = response.status_code
            if status_code == 200:
                return f"[+] > {url:<50}|| Found"
            elif status_code == 404:
                return f"[-] > {url:<50}|| Not found"
            else:
                return f"[-] > {url:<50}|| Error: {status_code}"
        except requests.exceptions.Timeout:
            return f"[-] > {url:<50}|| Timeout"
        except requests.exceptions.ConnectionError:
            return f"[-] > {url:<50}|| Connection error"
        except requests.exceptions.RequestException:
            return f"[-] > {url:<50}|| Request error"
        except Exception:
            return f"[-] > {url:<50}|| Unexpected error"

    result_str = f"""
╭─{' '*78}─╮
|{' '*27}{title}{' '*27}|
|{'='*80}|
"""
    with ThreadPoolExecutor() as executor:
        results = list(executor.map(check_url, urls))
    for result in results:
        result_str += f"| {result:<78} |\n"
    result_str += f"╰─{' '*78}─╯"
    return result_str

def deep_account_search(nickname):
    sites = [
        "https://google.com/{}",
        "https://youtube.com/@{}",
        "https://facebook.com/{}",
        "https://wikipedia.org/wiki/User:{}",
        "https://instagram.com/{}",
        "https://reddit.com/user/{}",
        "https://{}.tumblr.com",
        "https://medium.com/@{}",
        "https://www.quora.com/profile/{}",
        "https://bing.com/{}",
        "https://x.com/{}",
        "https://yandex.ru/{}",
        "https://whatsapp.com/{}",
        "https://yahoo.com/{}",
        "https://amazon.com/{}",
        "https://duckduckgo.com/{}",
        "https://yahoo.co.jp/{}",
        "https://tiktok.com/@{}",
        "https://msn.com/{}",
        "https://netflix.com/{}",
        "https://weather.com/{}",
        "https://live.com/{}",
        "https://naver.com/{}",
        "https://microsoft.com/{}",
        "https://twitch.tv/{}",
        "https://office.com/{}",
        "https://vk.com/{}",
        "https://pinterest.com/{}",
        "https://discord.com/{}",
        "https://aliexpress.com/{}",
        "https://github.com/{}",
        "https://adobe.com/{}",
        "https://rakuten.co.jp/{}",
        "https://ikea.com/{}",
        "https://bbc.co.uk/{}",
        "https://amazon.co.jp/{}",
        "https://speedtest.net/{}",
        "https://samsung.com/{}",
        "https://healthline.com/{}",
        "https://medlineplus.gov/{}",
        "https://roblox.com/users/{}/profile",
        "https://cookpad.com/{}",
        "https://indiatimes.com/{}",
        "https://mercadolivre.com.br/{}",
        "https://britannica.com/{}",
        "https://merriam-webster.com/{}",
        "https://hurriyet.com.tr/{}",
        "https://steamcommunity.com/id/{}",
        "https://booking.com/{}",
        "https://support.google.com/{}",
        "https://bbc.com/{}",
        "https://playstation.com/{}",
        "https://ebay.com/usr/{}",
        "https://poki.com/{}",
        "https://nike.com/{}",
        "https://walmart.com/{}",
        "https://medicalnewstoday.com/{}",
        "https://gov.uk/{}",
        "https://nhs.uk/{}",
        "https://detik.com/{}",
        "https://cricbuzz.com/{}",
        "https://nih.gov/{}",
        "https://uol.com.br/{}",
        "https://ilovepdf.com/{}",
        "https://clevelandclinic.org/{}",
        "https://cnn.com/{}",
        "https://globo.com/{}",
        "https://nytimes.com/{}",
        "https://taboola.com/{}",
        "https://pornhub.com/users/{}",
        "https://redtube.com/users/{}",
        "https://xnxx.com/profiles/{}",
        "https://brazzers.com/profile/{}",
        "https://xhamster.com/users/{}",
        "https://onlyfans.com/{}",
        "https://xvideos.es/profiles/{}",
        "https://xvideos.com/profiles/{}",
        "https://chaturbate.com/{}",
        "https://redgifs.com/users/{}",
        "https://tinder.com/{}",
        "https://pof.com/{}",
        "https://match.com/{}",
        "https://eharmony.com/{}",
        "https://bumble.com/{}",
        "https://okcupid.com/{}",
        "https://Badoo.com/{}",
        "https://dating.com/{}",
        "https://trello.com/{}",
        "https://mapquest.com/{}",
        "https://zoom.com/{}",
        "https://apple.com/{}",
        "https://dropbox.com/{}",
        "https://weibo.com/{}",
        "https://wordpress.com/{}",
        "https://cloudflare.com/{}",
        "https://salesforce.com/{}",
        "https://fandom.com/{}",
        "https://paypal.com/{}",
        "https://soundcloud.com/{}",
        "https://forbes.com/{}",
        "https://theguardian.com/{}",
        "https://hulu.com/{}",
        "https://stackoverflow.com/users/{}",
        "https://businessinsider.com/{}",
        "https://huffpost.com/{}",
        "https://booking.com/{}",
        "https://bleacherreport.com/{}",
        "https://pastebin.com/u/{}",
        "https://producthunt.com/@{}",
        "https://pypi.org/user/{}",
        "https://slideshare.com/{}",
        "https://strava.com/athletes/{}",
        "https://tldrlegal.com/{}",
        "https://t.me/{}",
        "https://last.fm/user{}",
        "https://data.typeracer.com/pit/profile?user={}",
        "https://tryhackme.com/p/{}",
        "https://trakt.tv/users/{}",
        "https://scratch.mit.edu/users/{}",
        "https://replit.com?{}",
        "https://hackaday.io/{}",
        "https://freesound.org/people{{",
        "https://hub.docker.com/u/{}",
        "https://disqus.com/{}",
        "https://www.codecademy.com/profiles/{}",
        "https://www.chess.com/member/{}",
        "https://bitbucket.org/{}",
        "https://www.twitch.tv?{}",
        "https://wikia.com/wiki/User:{}",
        "https://steamcommunity.com/groups{}",
        "https://keybase.io?{}",
        "http://en.gravatar.com/{}",
        "https://vk.com/{}",
        "https://deviantart.com/{}",
        "https://www.behance.net/{}",
        "https://vimeo.com/{}:",
        "https://www.youporn.com/user/{}",
        "https://profiles.wordpress.org/{}",
        "https://vimeo.com/{}",
        "https://tryhackme.com/p/{}",
        "https://www.scribd.com/{}",
        "https://myspace.com/{}",
        "https://genius.com/{}",
        "https://genius.com/artists/{}",
        "https://www.flickr.com/people/{}",
        "https://www.fandom.com/u/{}",
        "https://www.chess.com/member/{}",
        "https://buzzfeed.com/{}",
        "https://www.buymeacoffee.com/{}",
        "https://about.me/{}",
        "https://discussions.apple.com/profile/{}",
        "https://giphy.com/{}",
        "https://scholar.harvard.edu/{}",
        "https://www.instructables.com/member/{}",
        "http://www.wikidot.com/user:info/{}",
        "https://www.youporn.com/user/{}",
        "https://account.xbox.com/en-us/profile?gamertag={}",
        "https://profiles.wordpress.org/{}",
        "https://vimeo.com/{}",
        "https://tryhackme.com/p/{}",
        "https://torrentgalaxy.to/profile/{}",
        "https://www.scribd.com/{}",
        "https://myspace.com/{}",
        "https://hackerone.com/{}",
        "https://www.hackerearth.com/@{}",
        "https://genius.com/{}",
        "https://genius.com/artists/{}",
        "https://www.flickr.com/people/{}",
        "https://www.fandom.com/u/{}",
        "https://www.chess.com/member/{}",
        "https://buzzfeed.com/{}",
        "https://www.buymeacoffee.com/{}",
        "https://about.me/{}",
        "https://discussions.apple.com/profile/{}",
        "https://archive.org/details/@{}",
        "https://giphy.com/{}",
        "https://scholar.harvard.edu/{}",
        "https://www.instructables.com/member/{}",
        "http://www.wikidot.com/user:info/{}",
        "https://dribbble.com/{}",
        "https://500px.com/{}",
        "https://{}.blogspot.com",
        "https://{}.wordpress.com",
        "https://disqus.com/by/{}",
        "https://steamcommunity.com/id{}",
        "https://{}.livejournal.com",
        "https://www.codecademy.com/profiles/{}",
        "https://www.khanacademy.org/profile/{}",
        "https://bitbucket.org/{}/",
        "https://sourceforge.net/u/{}/profile/",
        "https://www.gog.com/u/{}",
        "https://www.dailymotion.com/{}",
        "https://myanimelist.net/profile/{}",
        "https://archiveofourown.org/users/{}",
        "https://www.slideshare.net/{}",
        "https://letterboxd.com/{}/",
        "https://runkeeper.com/{}/profile",
        "https://www.mapmyrun.com/profile/{}",
        "https://patreon.com/{}",
        "https://{}.bandcamp.com",
        "https://www.producthunt.com/@{}",
        "https://about.me/{}",
        "https://www.scribd.com/{}",
        "https://www.mixcloud.com/{}/",
        "https://keybase.io/{}",
        "https://www.houzz.com/user/{}",
        "https://www.couchsurfing.com/people{}",
        "https://mix.com/{}",
        "https://medium.com/@{}",
        "https://getpocket.com/@{}",
        "https://www.instructables.com/member/{}/",
        "https://colorlib.com/author{}/",
        "https://en.gravatar.com/{}",
        "https://www.kaggle.com/{}",
        "https://replit.com/@{}",
        "https://scratch.mit.edu/users/{}/",
        "https://www.alik.cz/u/{}",
        "https://www.munzee.com/m/{}",
        "https://boardgamegeek.com/user/{}",
        "https://ok.ru/{}",
        "https://www.youporn.com/user/{}",
        "https://account.xbox.com/en-us/profile?gamertag={}",
        "https://profiles.wordpress.org/{}",
        "https://vimeo.com/{}",
        "https://tryhackme.com/p/{}",
        "https://torrentgalaxy.to/profile/{}",
        "https://www.scribd.com/{}",
        "https://www.patreon.com/{}",
        "https://myspace.com/{}",
        "https://genius.com/{}",
        "https://genius.com/artists/{}",
        "https://www.flickr.com/people/{}",
        "https://www.fandom.com/u/{}",
        "https://www.chess.com/member/{}",
        "https://buzzfeed.com/{}",
        "https://www.buymeacoffee.com/{}",
        "https://about.me/{}",
        "https://discussions.apple.com/profile/{}",
        "https://archive.org/details/@{}",
        "https://giphy.com/{}",
        "https://scholar.harvard.edu/{}",
        "https://www.instructables.com/member/{}",
        "http://www.wikidot.com/user:info/{}",
        "https://erome.com/{}",
        "https://www.alik.cz/u/{}",
        "https://rblx.trade/p/{}",
        "https://www.paypal.com/paypalme/{}",
        "https://hackaday.io/{}",
        "https://connect.garmin.com/modern/profile/{}",
    ]
    urls = []
    for site_format in sites:
        if '{}' in site_format:
            url = site_format.format(nickname)
        else:
            url = site_format.rstrip('/') + '/' + nickname
        urls.append(url)

    search_results = fetch_social_urls(urls, "Deep Account Search")
    Write.Print(search_results, Colors.white, interval=0)
    restart()

def phone_info(phone_number):
    try:
        parsed_number = phonenumbers.parse(phone_number)
        country = geocoder.country_name_for_number(parsed_number, "en")
        region = geocoder.description_for_number(parsed_number, "en")
        operator = carrier.name_for_number(parsed_number, "en")
        valid = phonenumbers.is_valid_number(parsed_number)
        validity = "Valid" if valid else "Invalid"
        phonetext = f"""
\n
╭─{' '*50}─╮
|{' '*17}Phone number info{' '*18}|
|{'='*52}|
| [+] > Number   || {phone_number:<33}|
| [+] > Country  || {country:<33}|
| [+] > Region   || {region:<33}|
| [+] > Operator || {operator:<33}|
| [+] > Validity || {validity:<33}|
╰─{' '*15}─╯╰─{' '*31}─╯\n"""

        Write.Print(phonetext, Colors.white, interval=0)

    except phonenumbers.phonenumberutil.NumberParseException:
        clear()
        Write.Print(f"\n[!] > Error: invalid phone number format (+10000000000)", default_color, interval=0)

    restart()

def dns_lookup(domain):
    record_types = ['A', 'CNAME', 'MX', 'NS']
    result_output = f"""
╭─{' '*78}─╮
|{' '*33} DNS Lookup {' '*33}|
|{'='*80}|
"""
    for rtype in record_types:
        result_output += f"| [+] > {rtype} Records: {' '*62}|\n"
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

    result_output += f"╰─{' '*78}─╯"
    Write.Print(result_output, Colors.white, interval=0)
    restart()

def email_lookup(email_address):
    try:
        v = validate_email(email_address)
        email_domain = v.domain
    except EmailNotValidError as e:
        Write.Print(f"[!] > Invalid email format: {str(e)}", default_color, interval=0)
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

    email_text = f"""
╭─{' '*78}─╮
|{' '*34}Email Info{' '*34}|
|{'='*80}|
| [+] > Email:        || {email_address:<52}|
| [+] > Domain:       || {email_domain:<52}|
| [+] > MX Records:   || {", ".join(mx_records) if mx_records else "None":<52}|
| [+] > Validity:     || {validity:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(email_text, Colors.white, interval=0)
    restart()

def reverse_dns(ip):
    try:
        rev_name = reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        ptr_record = str(answers[0]).strip('.')
    except:
        ptr_record = "No PTR record found"

    rdns_text = f"""
╭─{' '*78}─╮
|{' '*33}Reverse DNS Lookup{' '*33}|
|{'='*80}|
| [+] > IP:     || {ip:<60}|
| [+] > Host:   || {ptr_record:<60}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
    Write.Print(rdns_text, Colors.white, interval=0)
    restart()

def analyze_email_header(raw_headers):
    parser = Parser()
    msg = parser.parsestr(raw_headers)
    from_ = msg.get("From", "")
    to_ = msg.get("To", "")
    subject_ = msg.get("Subject", "")
    date_ = msg.get("Date", "")
    received_lines = msg.get_all("Received", [])

    found_ips = []
    if received_lines:
        for line in received_lines:
            potential_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
            for ip in potential_ips:
                if ip not in found_ips:
                    found_ips.append(ip)

    header_text = f"""
╭─{' '*78}─╮
|{' '*31}Email Header Analysis{' '*31}|
|{'='*80}|
| [+] > From:      || {from_:<55}|
| [+] > To:        || {to_:<55}|
| [+] > Subject:   || {subject_:<55}|
| [+] > Date:      || {date_:<55}|
|{'-'*80}|
"""
    if found_ips:
        header_text += "| [+] > Received Path (IPs found):\n"
        for ip in found_ips:
            header_text += f"|    {ip:<76}|\n"
    else:
        header_text += "| [+] > No IPs found in Received headers.\n"

    header_text += f"╰─{' '*78}─╯"
    Write.Print(header_text, Colors.white, interval=0)

    if found_ips:
        ip_details_header = f"""
╭─{' '*78}─╮
|{' '*30}IP Geolocation Details{' '*30}|
|{'='*80}|
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
                ip_details_summary += f"| IP: {ip:<14}|| [!] Could not retrieve details.\n"
                ip_details_summary += "|"+ "-"*78 + "|\n"
        ip_details_footer = f"╰─{' '*78}─╯"

        Write.Print(ip_details_header + ip_details_summary + ip_details_footer, Colors.white, interval=0)

    spf_result, dkim_result, dmarc_result = None, None, None
    spf_domain, dkim_domain = None, None
    auth_results = msg.get_all("Authentication-Results", [])
    from_domain = ""
    if "@" in from_:
        from_domain = from_.split("@")[-1].strip(">").strip()

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

    spf_align = False
    dkim_align = False
    if from_domain and spf_domain:
        spf_align = from_domain.lower() == spf_domain.lower()
    if from_domain and dkim_domain:
        dkim_align = from_domain.lower() == dkim_domain.lower()

    alignment_text = f"""
╭─{' '*78}─╮
|{' '*30}SPF / DKIM / DMARC Checks{' '*29}|
|{'='*80}|
| [+] > SPF  Result:   {spf_result if spf_result else 'Not found':<20}   Domain: {spf_domain if spf_domain else 'N/A':<20} Aligned: {spf_align}|
| [+] > DKIM Result:   {dkim_result if dkim_result else 'Not found':<20} Domain: {dkim_domain if dkim_domain else 'N/A':<20} Aligned: {dkim_align}|
| [+] > DMARC Result:  {dmarc_result if dmarc_result else 'Not found':<20}|
╰─{' '*78}─╯
"""
    Write.Print(alignment_text, Colors.white, interval=0)
    restart()

def haveibeenpwned_check(email):
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
| [!] > Bad news! Your email was found in {len(breaches)} breach(es)                          |
|{'-'*80}|
"""
            for index, breach in enumerate(breaches, start=1):
                breach_name = breach.get('Name', 'Unknown')
                domain = breach.get('Domain', 'Unknown')
                breach_date = breach.get('BreachDate', 'Unknown')
                added_date = breach.get('AddedDate', 'Unknown')
                pwn_count = breach.get('PwnCount', 'Unknown')
                data_classes = ", ".join(breach.get('DataClasses', []))

                results_text += f"| Breach #{index}: {breach_name:<66}|\n"
                results_text += f"|    Domain: {domain:<71}|\n"
                results_text += f"|    Breach Date: {breach_date:<65}|\n"
                results_text += f"|    Added Date:  {added_date:<65}|\n"
                results_text += f"|    PwnCount:    {pwn_count:<65}|\n"
                results_text += f"|    Data Types:  {data_classes:<65}|\n"
                results_text += f"|{'='*80}|\n"
            results_text += f"╰─{' '*78}─╯"
            Write.Print(results_text, Colors.white, interval=0)

        elif resp.status_code == 404:
            clear()
            msg = f"""
╭─{' '*78}─╮
|{' '*30}Have I Been Pwned?{' '*30}|
|{'='*80}|
| [!] > Good news! No breaches found for: {email:<48}|
╰─{' '*78}─╯
"""
            Write.Print(msg, Colors.white, interval=0)
        else:
            clear()
            error_msg = f"""
[!] > An error occurred: HTTP {resp.status_code}
Response: {resp.text}
"""
            Write.Print(error_msg, Colors.red, interval=0)

    except requests.exceptions.Timeout:
        clear()
        Write.Print("[!] > Request timed out when contacting Have I Been Pwned.", default_color, interval=0)
    except Exception as e:
        clear()
        Write.Print(f"[!] > An error occurred: {str(e)}", default_color, interval=0)

    restart()

def change_color():
    global default_color
    clear()
    color_menu = """
╭─    ─╮╭─                     ─╮
|  №   ||         Color         |
|======||=======================|
| [1]  || Red                   |
| [2]  || Blue                  |
| [3]  || Green                 |
| [4]  || Yellow                |
| [5]  || Cyan                  |
| [6]  || White                 |
|------||-----------------------|
| [0]  || Back to settings menu |
╰─    ─╯╰─                     ─╯
"""
    Write.Print(color_menu, Colors.white, interval=0)

    color_choice = Write.Input("\n\n[?] >  ", default_color, interval=0).strip()

    color = {
        "1": Colors.red,
        "2": Colors.blue,
        "3": Colors.green,
        "4": Colors.yellow,
        "5": Colors.cyan,
        "6": Colors.white
    }

    if color_choice in color:
        default_color = color[color_choice]
        clear()
        Write.Print("[!] > Colour has been changed.\n", default_color, interval=0)
    elif color_choice == "0":
        settings()
    else:
        clear()
        Write.Print("[!] > Invalid choice.\n", Colors.red, interval=0)
    restart()

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        clear()

        domain_name = w.domain_name if w.domain_name else "N/A"
        registrar = w.registrar if w.registrar else "N/A"
        creation_date = w.creation_date if w.creation_date else "N/A"
        expiration_date = w.expiration_date if w.expiration_date else "N/A"
        updated_date = w.updated_date if w.updated_date else "N/A"
        name_servers = ", ".join(w.name_servers) if w.name_servers else "N/A"
        status = ", ".join(w.status) if w.status else "N/A"

        whois_text = f"""
╭─{' '*78}─╮
|{' '*34}WHOIS Lookup{' '*34}|
|{'='*80}|
| [+] > Domain Name:       || {str(domain_name):<52}|
| [+] > Registrar:         || {str(registrar):<52}|
| [+] > Creation Date:     || {str(creation_date):<52}|
| [+] > Expiration Date:   || {str(expiration_date):<52}|
| [+] > Updated Date:      || {str(updated_date):<52}|
| [+] > Name Servers:      || {name_servers:<52}|
| [+] > Status:            || {status:<52}|
╰─{' '*23}─╯╰─{' '*51}─╯
"""
        Write.Print(whois_text, Colors.white, interval=0)

    except Exception as e:
        clear()
        Write.Print(f"[!] > WHOIS lookup error: {str(e)}", default_color, interval=0)

    restart()

def check_password_strength(password):
    txt_file_path = os.path.join(os.path.dirname(__file__), "passwords.txt")
    if os.path.isfile(txt_file_path):
        try:
            with open(txt_file_path, "r", encoding="utf-8") as f:
                common_words = f.read().splitlines()
            for word in common_words:
                if word and word in password:
                    return "Weak password (may contain common phrase, term, word, sequence, etc)"
        except Exception:
            pass

    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1

    if score <= 2:
        return "Weak password (may contain common phrase, term, word, sequence, etc)"
    elif 3 <= score <= 4:
        return "Moderate password (room for improvement)"
    else:
        return "Strong password"

def password_strength_tool(password=None):
    clear() 
    if not password:
        clear()
        Write.Print("[!] > Password cannot be empty Please enter the password.\n", default_color, interval=0)
        restart()
        return

    strength = check_password_strength(password)
    clear()
    Write.Print(f"Password Strength: {strength}\n", Colors.white, interval=0)
    restart()

def fetch_wmn_data():
    try:
        response = requests.get("https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json", timeout=10)
        response.raise_for_status()
        return response.json()
    except:
        Write.Print("[!] > Failed to fetch data from WhatsMyName repository.\n", Colors.red, interval=0)
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

    with open(f"username_check_report_{username}.html", "w") as report_file:
        report_file.write(html_content)

def username_check(username=None):
    clear()
   
    if not username:
        clear()
        Write.Print("[!] > No username provided.\n", Error_Color, interval=0)
        restart()
        return

    data = fetch_wmn_data()
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

            with tqdm(total=total_sites, desc="Checking sites") as pbar:
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            site_name, uri_check = result
                            found_sites.append((site_name, uri_check))
                            Write.Print(f"[+] Found on: {site_name}\n", Colors.green, interval=0)
                            Write.Print(f"[+] Profile URL: {uri_check}\n", Colors.green, interval=0)
                    except Exception:
                        pass
                    finally:
                        pbar.update(1)

        if found_sites:
            Write.Print(f"\n[!] > Username found on {len(found_sites)} sites!\n", Colors.green, interval=0)
            generate_html_report(username, found_sites)
            Write.Print(f"\n[!] > Report saved: username_check_report_{username}.html\n", Colors.green, interval=0)
        else:
            Write.Print(f"[!] > No results found for {username}.\n", Colors.red, interval=0)

    except Exception as e:
        Write.Print(f"[!] > An error occurred: {str(e)}\n", Colors.red, interval=0)

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
| [+] > Phone: {phone_number:<66}|
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
    Write.Print(info_text, Colors.white, interval=0)
    restart()


def check_ssl_cert(domain):
    """
    Fetch SSL certificate information for a given domain using Python's
    built-in ssl and socket libraries.
    """
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
╭─{' '*78}─╮
|{' '*33}SSL Certificate Info{' '*32}|
|{'='*80}|
| [+] > Domain:       {domain:<58}|
| [+] > Issued To:    {issued_to:<58}|
| [+] > Issued By:    {issued_by:<58}|
| [+] > Valid From:   {str(not_before_dt):<58}|
| [+] > Valid Until:  {str(not_after_dt):<58}|
╰─{' '*78}─╯
"""
        Write.Print(info_text, Colors.white, interval=0)

    except ssl.SSLError as e:
        Write.Print(f"[!] > SSL Error: {str(e)}\n", Colors.red, interval=0)
    except socket.timeout:
        Write.Print("[!] > Connection timed out.\n", Colors.red, interval=0)
    except Exception as e:
        Write.Print(f"[!] > An error occurred retrieving SSL cert info: {str(e)}\n", Colors.red, interval=0)

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
╭─{' '*78}─╮
|{' '*32}Site Discovery{' '*32}|
|{'='*80}|
| [+] > Domain:  {domain:<63}|
|{'-'*80}|
"""

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

    result_text += f"╰─{' '*78}─╯"
    Write.Print(result_text, Colors.white, interval=0)
    restart()


def check_dnsbl(ip_address):
    """
    Checks whether an IP is listed in common DNS blacklists (DNSBLs).
    This does not require an external API — only DNS queries.
    """
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
╭─{' '*78}─╮
|{' '*33}DNSBL Check{' '*34}|
|{'='*80}|
| [+] > IP: {ip_address:<67}|
|{'-'*80}|
"""
    if results:
        report += "| The IP is listed on the following DNSBL(s):\n"
        for dnsbl, answer in results:
            report += f"|   {dnsbl:<25} -> {answer:<45}|\n"
    else:
        report += "| The IP is NOT listed on the tested DNSBL(s).\n"

    report += f"╰─{' '*78}─╯"
    Write.Print(report, Colors.white, interval=0)
    restart()


def fetch_webpage_metadata(url):
    """
    Fetch webpage metadata like <title>, meta description, and keywords.
    Uses BeautifulSoup, no external APIs required.
    """
    headers = {
        "User-Agent": "Mozilla/5.0"
    }
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
╭─{' '*78}─╮
|{' '*31}Webpage Metadata{' '*31}|
|{'='*80}|
| [+] > URL:         {url:<58}|
| [+] > Title:       {title:<58}|
| [+] > Description: {description:<58}|
| [+] > Keywords:    {keywords:<58}|
╰─{' '*78}─╯
"""
        Write.Print(result_text, Colors.white, interval=0)
    except Exception as e:
        Write.Print(f"[!] > Error fetching metadata: {str(e)}\n", Colors.red, interval=0)

    restart()




def main():
    while True:
        try:
            clear()
            
            T = "OLA" #input("Enter Text you want to convert to ASCII art : ")
            P = "MIDE"
            ASCII_art_1 = pyfiglet.figlet_format(T, font='isometric1')
            colored_ASCII_art_1 = colored(ASCII_art_1, 'green')  # Change 'cyan' to any color you prefer
            ASCII_art_2 = pyfiglet.figlet_format(P, font='isometric1')
            colored_ASCII_art_2 = colored(ASCII_art_2, 'green')  # Change 'cyan' to any color you prefer

            print(colored_ASCII_art_1)
            #print("\n")
            print(colored_ASCII_art_2)
                  
            author = "🛡️ By Olamide Owolabi - Hello World! 🛡️"
            Write.Print(author + "\n[C.I.T]\n OSint Info Tool\n", Colors.white, interval=0)

            menu = """
╔════════════════════════════════════════════════════════════════════════════╗
║  №   │      Function          │ Description                                ║
╠══════╪════════════════════════╪════════════════════════════════════════════╣
║ [1]  │ IP Address Search      │ Retrieves IP address info                  ║
║ [2]  │ Deep Account Search    │ Retrieves profiles from various websites   ║
║ [3]  │ Phone Search           │ Retrieves phone number info                ║
║ [4]  │ DNS Search             │ Retrieves DNS records (A, CNAME, MX, NS)   ║
║ [5]  │ Email Search           │ Retrieves MX info for an email             ║
║ [6]  │ Person Name Search     │ Retrieves extensive person-related data    ║
║ [7]  │ Reverse DNS Search     │ Retrieves PTR records for an IP address    ║
║ [8]  │ Email Header Search    │ Retrieves info from an email header        ║
║ [9]  │ Email Breach Search    │ Retrieves email data breach info (HIBP)    ║
║ [10] │ WHOIS Search           │ Retrieves domain registration data         ║
║ [11] │ Password Analyzer      │ Retrieves password strength rating         ║
║ [12] │ Username Search        │ Retrieves usernames from online accounts   ║
║ [13] │ Reverse Phone Search   │ Retrieves references to a phone number     ║
║ [14] │ SSL Cert Search        │ Retrieves basic SSL certificate details    ║
║ [15] │ Robots.txt/Sitemap     │ Retrieves robots.txt & sitemap.xml info    ║
║ [16] │ DNSBL Check            │ Retrieves IPDNS blacklist info             ║
║ [17] │ Web Metadata Info      │ Retrieves meta tags and more from a webpage║
╠══════╪════════════════════════╪════════════════════════════════════════════╣
║ [0]  │ Exit                   │ Exit the program                           ║
║ [99] │ Settings               │ Customize tool                             ║
╚════════════════════════════════════════════════════════════════════════════╝
"""
            Write.Print(menu, Colors.white, interval=0)

            choice = Write.Input("[?] >  ", default_color, interval=0).strip()

            if choice == "1":
                clear()
                Write.Print("IP Address Search \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                Write.Print("Press 0 and enter to cancel \n", Exit_Color, interval=0)
                ip = Write.Input("Please enter IP-Address: " , default_color, interval=0)

                if ip == "0":
                    clear()
                    continue

                if not ip:
                    clear()
                    Write.Print("[!] > Enter IP Address\n", Error_Color, interval=0)
                    continue
                ip_info(ip)

            elif choice == "2":
                clear()
                Write.Print("Username Account Search \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                nickname = Write.Input("Enter a Username or Press 0 and enter to cancel: ", default_color, interval=0)
                
                Write.Print("[!] > Conducting deep account search...\n", default_color, interval=0)

                if nickname == "0":
                    clear()
                    continue

                if not nickname:
                    clear()
                    Write.Print("[!] > Enter username\n", Error_Color, interval=0)
                    continue
                deep_account_search(nickname)

            elif choice == "3":
                clear()
                Write.Print("Phone Number Search \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                phone_number = Write.Input("Enter a valid Phone number Or Press \n"+
                                            "'0' and enter to cancel: ", default_color, interval=0)
                
                if phone_number == "0":
                   clear()
                   continue

                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter phone number\n", default_color, interval=0)
                    continue
                phone_info(phone_number)

            elif choice == "4":
                clear()
                Write.Print("Domain Search \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                domain = Write.Input("Enter Domain \n "
                                     + " Or Press 0 and enter to cancel ", default_color, interval=0)
                
                if domain == "0":
                   clear()
                   continue

                if not domain:
                    clear()
                    Write.Print("[!] > Enter domain\n", default_color, interval=0)
                    continue
                Write.Print("[!] > Retrieving DNS records...\n", default_color, interval=0)
                dns_lookup(domain)

            elif choice == "5":
                clear()
                Write.Print("Email Search \n", Head_Color, interval=0)

                Write.Print("\n", Head_Color, interval=0) 
                email = Write.Input("Enter a valid Email or Press '0' and enter to cancel ", default_color, interval=0)

                if email == "0":
                   clear()
                   Write.Print("[!] > Operation cancelled.\n", Error_Color, interval=0)
                   continue

                if not email:
                    clear()
                    Write.Print("[!] > Enter email\n", default_color, interval=0)
                    continue
                email_lookup(email)

            elif choice == "6":
                clear()
                Write.Print("Person Search with location \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0)
                Write.Print("Press 'O' and enter to cancel", default_color, interval=0)

                Write.Print("\n", Head_Color, interval=0)

               
                first_name = Write.Input("[?] > First Name: ", default_color, interval=0)
                last_name = Write.Input("[?] > Last Name: ", default_color, interval=0)
                city = Write.Input("[?] > City/Location: ", default_color, interval=0)

                if "0" in [first_name, last_name, city]:
                    clear()
                    continue


                if not first_name or not last_name:
                    clear()
                    Write.Print("[!] > Enter first and last name\n", default_color, interval=0)
                    continue
                Write.Print("[!] > Searching the given name and location...\n", default_color, interval=0)
                person_search(first_name, last_name, city)

            elif choice == "7":
                clear()
                Write.Print("Reverse DNS Search \n", Head_Color, interval=0)

                Write.Print("\n", Head_Color, interval=0) 

                ip = Write.Input("Enter IP Address for Reverse DNS or \n"
                                  + "Press 0 and enter to cancel", default_color, interval=0)
                
                if ip == "0":
                   clear()
                   continue

                if not ip:
                    clear()
                    Write.Print("[!] > Enter IP address\n", default_color, interval=0)
                    continue
                reverse_dns(ip)

            elif choice == "8":
                clear()
                Write.Print("Email Header Search \n", Head_Color, interval=0)

                Write.Print("\n", Head_Color, interval=0) 
                Write.Print(" Paste the raw email headers below (end with an empty line):\n", default_color, interval=0)
                Write.Print("Or Press 0 and enter to cancel:\n", default_color, interval=0)
                lines = []
                while True:
                    line = input()
                    if line.strip() == "0":
                        clear()
                        Write.Print("[!] > Operation cancelled.\n", Error_Color, interval=0)
                        break
                    if not line.strip():
                        break
                    lines.append(line)
                raw_headers = "\n".join(lines)
                if not raw_headers.strip():
                    clear()
                    Write.Print("[!] > No email headers provided.\n", default_color, interval=0)
                    continue
                analyze_email_header(raw_headers)

            elif choice == "9":
                clear()
                Write.Print("Email Breach Check\n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                email = Write.Input("Enter an Email to check if breached \n"
                                    +"Or Press 0 and enter to cancel", default_color, interval=0)

                if email == "0":
                     clear()
                     Write.Print("[!] > Operation cancelled.\n", Error_Color, interval=0)
                     continue
                if not email:
                    clear()
                    Write.Print("[!] > Enter email\n", default_color, interval=0)
                    continue
                haveibeenpwned_check(email)

            elif choice == "10":
                clear()
                Write.Print("Domain for WHOIS lookup\n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                domain = Write.Input("Enter a Domain pr Press 0 to Cancel ", default_color, interval=0)

                if domain == "0":
                    clear()
                    continue

                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain\n", default_color, interval=0)
                    continue
                whois_lookup(domain)

            elif choice == "11":
                password = Write.Input("[!] > Enter password to evaluate strength or press 0 to cancel:\n", default_color, interval=0)
                if password == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                else:
                 password_strength_tool(password)

            elif choice == "12":
                clear()
                Write.Print("Username Check\n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                usernam =  Write.Print("Enter Username to search \n"
                                      +"Or Press 0 and enter to cancel ", default_color, interval=0)
                
                if usernam == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue

                username_check(usernam.strip())

            elif choice == "13":
                clear()
                Write.Print("Phone Number reverse Lookup\n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 

                phone_number = Write.Input("Enter Phone number or Press 0 and enter to cancel ", default_color, interval=0)
                
                if phone_number == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue
                
                if not phone_number:
                    clear()
                    Write.Print("[!] > Enter phone number\n", default_color, interval=0)
                    continue
                reverse_phone_lookup(phone_number)

            
            elif choice == "14":
                clear()
                Write.Print("SSL Certificate Search\n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                Write.Print("Press '0' and enter to cancel\n", default_color, interval=0)


                domain = Write.Input("Enter Domain for SSL check: ", default_color, interval=0)

                if domain == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue

                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain\n", default_color, interval=0)
                    continue
                check_ssl_cert(domain)

            elif choice == "15":
                clear()
                Write.Print("Robot text lookup and Sitemap \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                Write.Print("Press '0' and enter to cancel\n", default_color, interval=0)

                domain = Write.Input("Enter Domain to check for robots.txt & sitemap: ", default_color, interval=0)
                
                if domain == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue
                
                if not domain:
                    clear()
                    Write.Print("[!] > Enter a domain\n", default_color, interval=0)
                    continue
                check_robots_and_sitemap(domain)

            elif choice == "16":
                clear()
                Write.Print("DNSBL Check \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                Write.Print("Press '0' and enter to cancel\n", default_color, interval=0)
                ip_address = Write.Input("Enter IP address to check DNSBL: ", default_color, interval=0)

                if ip_address == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue

                if not ip_address:
                    clear()
                    Write.Print("[!] > Enter an IP address\n", default_color, interval=0)
                    continue
                check_dnsbl(ip_address)

            elif choice == "17":
                clear()
                Write.Print("Web Metadata Info \n", Head_Color, interval=0)
                Write.Print("\n", Head_Color, interval=0) 
                Write.Print("Press '0' and enter to cancel\n", default_color, interval=0)

                url = Write.Input("[?] > URL for metadata extraction: ", default_color, interval=0)
                if url == "0":
                    clear()
                    Write.Print("[!] > Operation cancelled.\n", default_color, interval=0)
                    continue

                if not url:
                    clear()
                    Write.Print("[!] > Enter a URL\n", default_color, interval=0)
                    continue
                fetch_webpage_metadata(url)

            elif choice == "0":
                clear()
                Write.Print("\n[!] > Exiting...", Error_Color, interval=0)
                exit()

            elif choice == "99":
                settings()

            else:
                clear()
                Write.Print("[!] > Invalid input.\n", Error_Color, interval=0)

        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", Error_Color, interval=0)
            exit()

def settings():
    while True:
        try:
            clear()
            print("\033[1;31m   ██████╗██╗        █████╗ ████████╗███████╗")
            print("   ██╔════╝██║       ██╔══██╗╚══██╔══╝██╔════╝")
            print("   ██║     ██║       ███████║   ██║   ███████╗")
            print("   ██║     ██║       ██╔══██║   ██║   ╚════██║")
            print("   ██████╗ ███████╗  ██║  ██║   ██║   ███████║")
            print("   ╚═════╝ ╚══════╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝\033[0m")
            print("\033[1;34mC       L      A       T       S       C       O       P       E\033[0m   \033[1;31m(Version 1.0.0)\033[0m")
            author = "🛡️ By Olamide Owolabi - Hello World! 🛡️"
            Write.Print(author + "\n[C.I.T]\nClatScope Info Tool\n", Colors.yellow, interval=0)

            settings_menu = """╭─    ─╮╭─                   ─╮╭─                                         ─╮
|  №   ||       Setting       ||                Description                |
|======||=====================||===========================================|
| [1]  || Theme change        || Customize the theme
|------||---------------------||-------------------------------------------
| [0]  || Back to menu        || Exit the settings
╰─    ─╯╰─                   ─╯╰─                                         ─╯
"""
            Write.Print(settings_menu, Colors.white, interval=0)

            settings_choice = Write.Input("[?] >  ", default_color, interval=0).strip()

            if settings_choice == "1":
                change_color()
            elif settings_choice == "0":
                return
            else:
                clear()
                Write.Print("[!] > Invalid input.\n", default_color, interval=0)

        except KeyboardInterrupt:
            clear()
            Write.Print("[!] > Exiting on user request...\n", default_color, interval=0)
            exit()

if __name__ == "__main__":
    main()
