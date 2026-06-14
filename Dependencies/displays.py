import os, traceback
from colorama import init, Fore, Style
from pathlib import Path


M = Fore.MAGENTA
W = Fore.WHITE
R = Fore.RED
Y = Fore.YELLOW
G = Fore.GREEN
C = Fore.CYAN


banner = rf'''

{C} _   _     _       __ {W} _                 {R} _            
{C}| |_| |__ (_) ___ / _|{W}| |__  _   _ _ __  {R}| |_ ___ _ __ 
{C}| __| '_ \| |/ _ \ |_ {W}| '_ \| | | | '_ \ {R}| __/ _ \ '__|
{C}| |_| | | | |  __/  _|{W}| | | | |_| | | | |{R}| ||  __/ |   
{C} \__|_| |_|_|\___|_|  {W}|_| |_|\__,_|_| |_|{R} \__\___|_| {Y}v2   
                                         {Y}<{C}raphaelthief{Y}>{G}               
'''

help_menu = f'''
{Y}═══════════════════════════════════════════════════════════════════════
            {C}Automated Bug Hunting and Pentesting Tool   █{W}█{R}█
{Y}═══════════════════════════════════════════════════════════════════════

{G}Usage:
    {Y}python3 thiefhunter.py [options]


GENERAL OPTIONS
───────────────────────────────────────────────────────────────────────{G}
  {C}-h, --help{G}
      Show default help menu

  {C}-hh{G}
      Show advanced help menu with examples and notes

  {C}-nc, --no-clean{G}
      Do not clean the CLI screen before execution
      Keep previous terminal outputs and commands visible

  {C}-v, --verbose{G}
      Enable verbose/debug output
      Useful for troubleshooting, stack traces and file locations

  {C}-t, --timeout <seconds>{G}
      HTTP request timeout (default: 15)

      Notes:
          Some modules internally override timeout values
          depending on request complexity or remote latency


{Y}PROXY / NETWORK
───────────────────────────────────────────────────────────────────────{G}
  {C}-p, --proxy <proxy>{G}
      Use custom proxy

      Examples:
          --proxy http://127.0.0.1:8080
          --proxy http://user:pass@host:port

      Features:
          - Supports HTTP/HTTPS proxies
          - SOCKS proxies supported through dependencies
          - DNS resolution through proxy when possible
          - Reduces DNS leak risks

      Warning:
          Some enterprise environments may require
          local DNS resolution outside the proxy

  {C}--tor{G}
      Force Tor SOCKS proxy usage

      Default:
          127.0.0.1:9050

      Notes:
          - Requires Tor service running locally
          - Uses SOCKS5h to avoid DNS leaks
          - If Tor runs on another port, edit:
                Dependencies/get_request.py


{Y}TARGETS
───────────────────────────────────────────────────────────────────────{G}
  {C}-u, --url <url>{G}
      Single target URL

      Example:
          -u https://target.com

  {C}-f, --file <file>{G}
      File containing multiple targets

      Supported format:
          One URL per line

      Example:
          -f targets.txt


{Y}REQUEST CUSTOMIZATION
───────────────────────────────────────────────────────────────────────{G}
  {C}--random-headers{G}
      Use random User-Agent headers from payload files

      Useful for:
          - bypassing weak protections
          - avoiding repetitive fingerprints
          - testing detection capabilities
          - reducing correlation between requests

  {C}--headers "Header=Value,Header2=Value2"{G}
      Custom HTTP headers

      Example:
          --headers "Authorization=Bearer TOKEN,Accept=application/json"

  {C}-c, --cookies "name=value,name2=value2"{G}
      Custom cookies

      Example:
          --cookies "session=abc123,token=xyz"

  {C}-X, --method GET,POST,PUT,DELETE{G}
      HTTP method

      Default:
          GET


{Y}JWT ANALYSIS
───────────────────────────────────────────────────────────────────────{G}
  {C}--jwt <token>{G}
      Analyze, mutate and validate JWT Bearer Tokens

      Supported algorithms:
          - HS256 / HS384 / HS512
          - RS256 / RS384 / RS512
          - ES256 / ES384 / ES512
          - EdDSA

      Features:
          - Decode JWT header and payload
          - Detect weak algorithms
          - Check expiration and timestamps
          - Detect "alg:none" usage
          - Identify common JWT misconfigurations
          - Detect JWT family automatically
          - Interactive attack playground
          - Generate malicious JWT variations
          - Re-sign modified payloads
          - Generate embedded JWK tokens
          - Generate Hashcat cracking commands
          - Test algorithm confusion vectors
          - Test kid/jku/x5u header injections

      Supported attack vectors:
          - payload mutation (invalid signature)
          - payload mutation (re-sign)
          - alg:none bypass
          - alg case fuzzing
          - kid path traversal
          - kid NULL byte injection
          - jku injection
          - x5u injection
          - embedded JWK injection
          - RS256 -> HS256 confusion
          - offline HMAC cracking support

      Notes:
          - RSA confusion attacks require public key input
          - Re-sign attacks require secret/private key
          - Hashcat mode used:
                16500
          - Interactive prompts are displayed when
            additional user input is required

      Example:
          --jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

      Example with vulnerable RS256 target:
          python3 thiefhunter.py --jwt TOKEN

      Example hashcat attack:
          hashcat -m 16500 JWT_TOKEN rockyou.txt --force


{Y}RECON / ENUMERATION
───────────────────────────────────────────────────────────────────────{G}
  {C}-e, --extract <depth>{G}
      Crawl and extract URLs containing parameters

      Features:
          - Recursive crawling
          - Parameterized endpoint extraction
          - Static assets filtering
          - Image/media exclusion by default

      Example:
          --extract 2

  {C}-w, --wayback{G}
      Extract URLs from Wayback Machine archives

  {C}--exclude <ext1,ext2>{G}
      Exclude extensions from Wayback results

      Example:
          --exclude png,jpg,css,js

  {C}--show-all{G}
      Show all Wayback URLs

      Default behavior:
          Only parameterized URLs are displayed

      Useful for:
          - discovering deprecated endpoints
          - old admin panels
          - forgotten APIs
          - hidden resources

  {C}--wtf <depth>{G}
      Deep scan for exposed information

      Extracts:
          - emails
          - phone numbers (french numbers 06/07)
          - API keys
          - secrets
          - tokens
          - robots.txt entries

      Useful for:
          - frontend secret leaks
          - exposed JSON responses
          - accidental information disclosure

      Example:
          --wtf 3

  {C}--sub, --subdomains{G}
      Enumerate subdomains

      Sources:
          - DNSDumpster
          - VirusTotal API
          - crt.sh
          - custom tool wordlist

      Notes:
          - VirusTotal API key needed
          - DNSDumpster API key needed
          - crt.sh can be unstable
          - Multiple retries are automatically performed
          - If no token is provided, subdomain enumeration will rely only on crt.sh 
            and brute-force fuzzing using the tool's built-in subdomain wordlist.

  {C}--dir{G}
      Enumeration and testing of common directories and sensitive files
      from the target domain root.

      Levels:
        1 - Low
        2 - Moderate
        3 - Medium
        4 - High
        
        Higher levels increase the number of paths tested.

      Default: 1

  {C}--bypass-403{G}
      Tests common 403/401 access control bypass techniques against the supplied URL.

      Includes:
        - Path normalization bypasses
        - Encoded path variations
        - Suffix and extension tricks
        - Header-based bypasses
        - Host and IP spoofing headers
        - Reverse proxy misconfigurations

      Results are classified by severity:
        LOW     - Response differs from baseline
        MEDIUM  - Redirects or authentication changes
        HIGH    - Successful access (200/2xx)

      Example:
        --url https://target.com/admin --bypass-403

  {C}--tld{G}
      Enumerate a domain's DNS extensions to identify a related parent domain or detect the presence of clones


{Y}VULNERABILITY ANALYSIS
───────────────────────────────────────────────────────────────────────{G}
  {C}--vln, --vuln{G}
      Detect vulnerable technologies and associated CVEs

      Detection sources:
          - Wappalyzer
          - WebTech
          - custom regex fingerprints

      CVE / exploit mapping:
          - Search-Vulns
          - CPE generation
          - exploit correlation

  {C}--exp, --exploit-search <query>{G}
      Manual exploit and vulnerability search

      Supported formats:

      Technology + Version:
          --exploit-search "PHP 8.1"

      CVE:
          --exploit-search CVE-2024-3566

      CPE:
          --exploit-search cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*

  {C}--audit{G}
      Perform basic security audit

      Checks include:
          - missing security headers
          - weak TLS configuration
          - dangerous HTTP methods
          - insecure configurations
          - common hardening issues


{Y}WEB VULNERABILITY TESTING
───────────────────────────────────────────────────────────────────────{G}
  {C}--trav, --traversal{G}
      Try detecting path traversal vulnerabilities

      Supported targets:
          - user supplied endpoints
          - auto-discovered endpoints (crawl depth=2)

      Detection features:
          - Linux payloads
          - Windows payloads
          - URL encoded traversals
          - double encoded traversals
          - NULL byte payloads
          - path normalization bypasses
          - context-based payload generation
          - web root traversal payloads

      Automatic checks:
          - OS fingerprinting from HTTP headers
          - static resource filtering
          - parameter discovery
          - suspicious endpoint detection
          - extension extraction for NULL byte attacks

      Common targeted parameters:
          - file
          - path
          - filename
          - image
          - template
          - page
          - folder
          - manifest
          - download

      Vulnerability indicators:
          - /etc/passwd disclosure
          - win.ini disclosure
          - Linux account signatures
          - Windows configuration leaks

      Supported payload families:
          - classic traversal
          - encoded traversal
          - double encoded traversal
          - double encoded traversal
          - mixed slash traversal
          - UTF-8 bypass payloads
          - NULL byte injections

      Post-exploitation helpers:
          - existing file enumeration
          - root path discovery
          - web directory traversal testing
          - HTTP 200 response collection

      Notes:
          - Static assets are ignored automatically
          - Crawling is limited to allowed domains
          - Non-HTML responses are skipped during crawl
          - Traversal payloads adapt to detected OS
          - Duplicate endpoints are automatically filtered

      Example:
          https://target.com/?file=test

      Example usage:
          python3 thiefhunter.py -u "https://target.com/?file=test" --trav
          python3 thiefhunter.py -u "https://target.com/" --trav

  {C}--ord, --open-redirect{G}
      Try open redirect vulnerabilities

      Works on:
          - supplied endpoint
          - auto-crawled endpoints (depth=2)

      Example:
          https://target.com/?redirect=test

  {C}--crlf{G}
      Try detecting CRLF injections

      Notes:
          - Header-based testing
          - Detection-oriented
          - Not intended for operational exploitation

  {C}--waf{G}
      Detect Web Application Firewall protections

      Features:
          - fingerprinting
          - detection scoring
          - heuristic analysis

      Recommendation:
          Use with --verbose for detailed scoring
          and manual verification assistance

  {C}--commit{G}
      Detect personnal and professionnals emails from public GitHub repos from the target username

      Purpose:
          Find personal data directly associated with the developers. An email address can be used 
          to correlate passwords leaked by the user, or from those leaks, identify a pattern in how 
          the person or the target’s technical teams create passwords


{Y}AUTOMATION
───────────────────────────────────────────────────────────────────────{G}
  {C}--batch{G}
      Automation of default user inputs. Script execution without any user interaction, for example 
      by automatically handling prompts related to --traversal or --subdomains during successful 
      tests that would normally ask whether the user wants to proceed further with the testing


{Y}EXAMPLES
───────────────────────────────────────────────────────────────────────{G}
  Basic security audit:
      {Y}python3 thiefhunter.py -u https://target.com --audit{G}

  Crawl and extract URLs:
      {Y}python3 thiefhunter.py -u https://target.com -e 2{G}

  Extract Wayback URLs:
      {Y}python3 thiefhunter.py -u https://target.com --wayback{G}

  Wayback with exclusions:
      {Y}python3 thiefhunter.py -u https://target.com --wayback --exclude jpg,png,css{G}

  Deep secret scan:
      {Y}python3 thiefhunter.py -u https://target.com --wtf 3{G}

  JWT analysis:
      {Y}python3 thiefhunter.py --jwt TOKEN{G}

  Exploit search:
      {Y}python3 thiefhunter.py --exploit-search "Apache 2.4.49"{G}

  Through Burp Suite:
      {Y}python3 thiefhunter.py -u https://target.com --proxy http://127.0.0.1:8080 --vln{G}

  Through Tor:
      {Y}python3 thiefhunter.py -u https://target.com --tor --traversal{G}

  Path traversal testing:
      {Y}python3 thiefhunter.py -u "https://target.com/?file=test" --trav{G}

  Open redirect testing:
      {Y}python3 thiefhunter.py -u "https://target.com/?redirect=test" --ord{G}

{Y}═══════════════════════════════════════════════════════════════════════{G}
'''


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print(banner)

def highlight(text, color=R):
    return f"{color}{text}{W}"

def isargsok(args, what):
    if what == "need_url":
        if not args.url and not args.file:
            print(f"{R}[Error] args --url or --file missingk")
            print(f"{W}   --> Skipping...\n")
            return False

    if what == "need_commit":
        if not args.commit:
            print(f"{R}[Error] args --commit missingk")
            print(f"{W}   --> Skipping...\n")
            return False

    if what == "need_wayback_or_extract":
        if not (args.wayback or args.extract):
            print(f"{R}[Error] args --wayback missing")
            print(f"{W}   --> Skipping...\n")
            return False
    return True

def no_clean(args):
    if not args.no_clean:
        clear_screen()
    print_banner()


def handle_error(e, context=None, verbose=False):
    error_type = type(e).__name__
    error_message = str(e)
    prefix = f"{R}[ERROR] {context} -> " if context else f"{R}[ERROR] "
    if verbose and isinstance(e, BaseException):
        tb = traceback.extract_tb(e.__traceback__)[-1]
        filename = tb.filename
        line = tb.lineno
        print(
            f"{prefix}{error_type}: {error_message} "
            f"(file={filename}, line={line}){W}"
        )
    else:
        print(f"{prefix}{error_type}: {W}{error_message}{W}")


def init_env_file(args):
    env_content = """\
DNSDUMPSTER_API_KEY=
VIRUSTOTAL_API_KEY=
WORDFENCE_API_KEY=
SEARCH_VULNS_API_KEY=
GITHUB_API_KEY=
"""
    if args.verbose:
        print(f"{Y}[!] {W}Checking .env file status...")
        
    env_file = Path(".env")
    if not env_file.exists():
        if args.verbose:
            print(f"{Y}[*] {W}Creating .env file. Add your API KEYS")
            
        env_file.write_text(env_content, encoding="utf-8")
    print()    
