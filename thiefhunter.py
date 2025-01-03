import argparse, requests, time, re, warnings, tldextract, urllib3, os, difflib, logging, random, threading, signal, sys, subprocess, shlex, pprint
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, parse_qsl, urlencode, urlunparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed

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


banner = f'''

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
            #print(f"{M}[Info] {G}Outgoing ip (--sqlmap, --dalfox and --nuclei): {stdout.strip()}")
            
            outgoing_ip = stdout.strip()
            print(f"{M}[Info] {G}Outgoing ip (--sqlmap, --dalfox and --nuclei): {outgoing_ip}")


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
############################################## Scan urls / domains ############################################
###############################################################################################################


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


# Target subdomains enum
def subreponse(domain):
    global proxies
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }    
    
    url = f"https://crt.sh/?q={domain}"
    try:

        if torusage == "yes":
            proxies = tor_proxies
     
        
        response = requests.get(url, proxies=proxies, headers=headers)
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
        print(f"{M}[!] {G}No subdomains found for {Y}{domain}")
        return

    print(f"{M}[!] {G}Subdomains for {Y}{domain}")
    print(f"{M}[?] {G}Source : {Y}crt.sh")
    print("-" * 50)
    
    for cert in certificates.values():
        test_url = f"http://{cert['common_name']}"  # HTTP default        
        try:
            
            if torusage == "yes":
                proxies = tor_proxies
         
            
            test_response = requests.get(test_url, proxies=proxies, headers=headers, timeout=10)
            status = test_response.status_code
            statuscode = test_response.status_code
            statusV = "/"
            if status == 403 or status == 200:
                if detect_login_page(test_response.text):
                    status = f"login page [{R}{statuscode}{G}]"            
            
        except requests.exceptions.Timeout as e:
            status = f"Timedout [{R}{statuscode}{G}]"
            if verbosity == "yes":
                statusV = e
            test_url = "/"
        except requests.exceptions.ConnectionError as e:
            if "getaddrinfo failed" in str(e):
                status = f"DNS resolution failed [{R}{statuscode}{G}]"
                if verbosity == "yes":
                    statusV = e
            else:
                status = f"Connection error [{R}{statuscode}{G}]"
                if verbosity == "yes":
                    statusV = e
            test_url = "/"
        except requests.exceptions.RequestException as e:
            status = f"Unexpected error [{R}{statuscode}{G}]"
            if verbosity == "yes":
                statusV = e
            test_url = "/"
            
        print(f"{G}[+] {Y}Common Name    : {C}{cert['common_name']}")
        print(f"{G}[+] {Y}Logged At      : {G}{cert['logged_at']}")
        print(f"{G}[+] {Y}More Infos     : {G}https://crt.sh/?id={cert['cert_id']}{Y}")
        print(f"{G}[+] {Y}Satus          : {G}{status}{Y}")
        
        if verbosity == "yes":
            print(f"{G}[+] {Y}Satus verbose  : {G}{statusV}{Y}")
            
        print(f"{G}[+] {Y}Direct URL     : {G}{test_url}{Y}")
        print("-" * 50)
        
        time.sleep(1)


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


def tag_plugins_themes_and_versions(url):

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


    # Extrait la version si elle existe
    version_match = re.search(r'\?ver=([\d.]+)', url)
    version_tag = f"{Y}[{name} {R}{version_match.group(1)}{Y}]" if version_match else ""

    if verbosity == "yes":
        final_result = f"{M}{tag} {version_tag} {G}{url}"
    else:
        final_result = f"{M}{tag} {version_tag}"
        
    return final_result

def detect_version_meta(soup):
    meta_tag = soup.find('meta', attrs={'name': 'generator'})
    if meta_tag and 'WordPress' in meta_tag['content']:
        return meta_tag['content']
    return "Meta version: unknown ..."

def detect_version_assets(soup):
    links = soup.find_all('link', href=True) + soup.find_all('script', src=True)
    for tag in links:
        href = tag.get('href') or tag.get('src')
        if '?ver=' in href:
            version = href.split('?ver=')[-1]
            return version
    return "Assets: unknown ..."

def detect_version_readme(url):
    response = requests.get(f"{url}/readme.html")
    if response.status_code == 200:
        if "WordPress" in response.text:
            lines = response.text.splitlines()
            for line in lines:
                if "WordPress" in line:
                    return line.strip()
    return "readme.html not found"

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
    response = requests.get(f"{url}/wp-json/")
    if response.status_code == 200:
        try:
            data = response.json()
            if 'generator' in data.get('meta', {}):
                return data['meta']['generator']
        except ValueError:
            pass  # JSON malformé
    return "API REST désactivée ou version non détectée"

def detect_plugins_and_themes(soup):
    links = soup.find_all('link', href=True) + soup.find_all('script', src=True)
    plugins_or_themes = []
    for tag in links:
        href = tag.get('href') or tag.get('src')
        if '/wp-content/plugins/' in href or '/wp-content/themes/' in href:
            plugins_or_themes.append(tag_plugins_themes_and_versions(href))
    return plugins_or_themes



def enumerate_users_via_wp_json(url):
    print(f"{M}[Info] {G}Looking for usernames")
    try:
        api_url = f"{url.rstrip('/')}/wp-json/wp/v2/users"
        response = requests.get(api_url, timeout=15)
        
        if response.status_code == 200:
            try:
                users = response.json()
                if isinstance(users, list) and users:
                    print(f"{M}[+] {G}Users found")
                    for user in users:
                        username = user.get('name', 'Unknown')
                        user_id = user.get('id', 'Unknown')
                        slug = user.get('slug', 'Unknown')
                        print(f" - ID : {user_id}, Username : {R}{username}{G}, Slug : {R}{slug}{G}")
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




def display_results(result):
    print(f"{M}[Meta Tag Version]{G} : {result['meta']}")
    print(f"{M}[Assets Version]{G}   : {result['assets']}")
    print(f"{M}[Readme Version]{G}   : {result['readme']}")
    print(f"{M}[API Version]{G}      : {result['api']}")
    print(f"\n{M}[Info] {G}Plugins and Themes Detected")
    for item in result['plugins_and_themes']:
        print(f"{item}")


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
            print(f"{M}[Error] {R}Unable to access the site")
            print("")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')

        result = {
            "meta": detect_version_meta(soup),
            "assets": detect_version_assets(soup),
            "readme": detect_version_readme(url),
            "api": detect_version_api(url),
            "plugins_and_themes": detect_plugins_and_themes(soup)
        }

        # Afficher les résultats
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
                if any(keyword in response_text for keyword in sensitive_keywords):
                    print(f"{G}[+] {Y}{keyword} {G}detected for : {C}{target_url}")
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
        print(f"\n{M}[+] {G}Domain information")
        response = requests.get(url, timeout=10) 
        if response.status_code == 200:
            data = response.json()
            print_rdap_info(data)
        elif response.status_code == 404:
            print(f"{M}[Info] {G}No information available for this domain ({response.status_code})")
        else:
            print(f"{M}[Error] {R}Unexpected error : HTTP Status {response.status_code}")
    except requests.RequestException as e:
        print(f"{M}[Error] {R}{e}")

def print_rdap_info(data):
    print(f"{M}[Info] {G}Domain name : {Y}{data.get('ldhName', 'N/A')}")
    
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


# Function to audit a page by its URL
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
        print(f"\n{M}[Info] {C}Basic audit report for : {url}\n")
        print(f"{M}[+] {G}Headers info...")
        # Print all response headers
        for header, value in response.headers.items():
            print(f"{G}{header}: {Y}{value}")
        print("")
        
        print(f"{M}[+] {G}Searching for click-hijacking vulnerabilities...")
        hijacking = check_clickjacking_protection(url)
        print(hijacking)        
        print("")
        
        print(f"{M}[+] {G}Code review...")
        
        result = analyze_response(response, url)

        # Display audit report
        for key, value in result.items():
            if not isinstance(value, list):
                print(f"{M}[{key}] {G}{value}")

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
    parser.add_argument("-w", "--wayback", action="store_true", help="Include Wayback Machine URLs")
    parser.add_argument("-r", "--robots", action="store_true", help="Try to extract urls from robots.txt and sitemap.xml")
    parser.add_argument("-n", "--normalize", action="store_true", 
                        help="Normalize common parameters into a unique format, such as 'id=X' to prevent duplicates (ex : id=1256 ; id=15 ; id=897)")
    parser.add_argument("-a", "--show-all", action="store_true", help="extract all links")
    parser.add_argument("--exclude", nargs='+',
                        help="Exclude specifics parameters like id=X or ?image=X or something.php (ex : --exclude image,id,php)", default=[])
    parser.add_argument("-o", "--output", help="Output file to save extracted results (-e ; -w ; --robots)")                    
    parser.add_argument("-wp", "--wordpress", action="store_true", help="Basic Wordpress scan")
    parser.add_argument("-s", '--subdomains', action="store_true", help=f"Enum target subdomains")
    parser.add_argument("-t", '--traversal', action="store_true", help=f"Try to exploit path traversal. Payloads into payloads/traversal.txt")
    parser.add_argument("-op", '--open-redirect', action="store_true", help=f"Try to exploit path open redirect. Payloads into payloads/open_redirect.txt")
    parser.add_argument("-cr", '--crlf', action="store_true", help=f"Try to exploit crlf injection. Payloads into payloads/crlf.txt")
    parser.add_argument("-i", '--infos', action="store_true", help=f"Check basics webpage infos (headers, vulnerable source or sinks, Click-Hijacking, ...)")
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
        parser.error("You must specify at least one of the arguments: --url or --file")

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
                token_file_path = "install_paths\wpscan_token.txt" 
                with open(token_file_path, "r") as token_file:
                    token = token_file.read().strip()
                if token:
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
        print(f"{M}[Info] {G}Crawling {args.url} ...")
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
            "wp-content/",
            "wp-content/uploads/",
            "wp-json/wp/v2/users",
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
        subreponse(base_domain)


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
        fetch_rdap_info(base_domain)
        
        
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
                    default_wpscan_command = [wpscan_path_expanded, "--url", args.url] # one url to scan

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
