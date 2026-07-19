# thiefhunter v2

ThiefHunter is an offensive security framework designed for real-world reconnaissance, vulnerability research and adaptive web exploitation.
Built for pentesters, bug bounty hunters and auditors, it focuses on high signal enumeration, low-noise OPSEC, and context-aware attack automation.
The tool focusses on adaptive offensive automation with practical OPSEC awareness.

![Main menu](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/Main.png "Main menu")

To see the account menu and the features related to the ```-hh``` menu, scroll to the end of this description.

## Installation
```
pip install -r requirements.txt && playwright install
```
For optimal use of the features, make sure to provide the various free API keys from the .env file :
```
DNSDUMPSTER_API_KEY=
VIRUSTOTAL_API_KEY=
WORDFENCE_API_KEY=
SEARCH_VULNS_API_KEY=
GITHUB_API_KEY=
```
- DNSDUMPSTER : https://dnsdumpster.com/developer/
  
  -> Used to enumerate subdomains ```--subdomains```
  
- VIRUSTOTAL : https://www.virustotal.com/
  
  -> Used to enumerate subdomains ```--subdomains```

- WORDFENCE : https://www.wordfence.com/
  
  -> Used for enumerating CVEs and exploits related to application versions (Wordpress) ```--vln```

- SEARCHVULNS : https://search-vulns.com/api/setup
  
  -> Used for enumerating CVEs and exploits related to application versions ```--vln and --exp```

- GITHUB : https://github.com/
  
  -> Used for enumerating GitHub profiles to discover emails used in commits ```--commits```




## Key Features
### Save results
You can save the CLI output directly to a JSON file using the `--save` option.

- Use ```--save``` to automatically save results with a default filename (based on the domain name)
- Use ```--save <FILE_NAME.json>``` to specify a custom output filename


### Advanced Vulnerability Enumeration
Wordfence API Integration (No WPScan-style token limitations)
ThiefHunter leverages the Wordfence vulnerability intelligence API for WordPress vulnerability enumeration.

Advantages:
- no WPScan token quota limitations
- scalable enumeration
- plugin/theme vulnerability correlation
- continuous CVE intelligence integration

This allows large-scale WordPress audits without artificial API restrictions.

It is strongly recommended to use the free APIs provided in the .env file to obtain working results for this feature!


### Hybrid Technology Detection Engine
Technology identification combines multiple layers:
- deprecated but still extremely effective Wappalyzer fingerprints
- WebTech API
- custom manual regex fingerprinting
- contextual version extraction

This hybrid approach significantly improves:
- framework detection
- CMS identification
- version accuracy
- hidden technology discovery

![Version detection](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/vuln_function_versions_detection.png "Version detection")


### Intelligent CVE & Exploit Correlation
After technology enumeration, ThiefHunter uses the Search-Vulns project to:
- generate accurate CPEs
- identify relevant CVEs
- correlate public exploits
- reduce false positive mappings

Instead of dumping generic CVEs, the framework attempts to identify the most relevant attack surface based on detected versions and technologies.

![CVE and EXPLOITS detection](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/vuln_function_CVE_detection.png "CVE and EXPLOITS detection")


============================================================================================

**This section is entirely based on the high-quality work of ra1nb0rn, using the API available here: https://search-vulns.com/**

I was responsible for handling communication with its API and displaying the results through the CVE_vuln_displayer.py module

Project repository available here: https://github.com/ra1nb0rn/search_vulns

### Credits: ```ra1nb0rn```

============================================================================================


### Adaptive Path Traversal Engine
The traversal engine was designed around real exploitation behavior rather than simple payload spraying.

The traversal module achieved:

100% successful exploitation coverage across PortSwigger path traversal labs using adaptive payload generation and contextual mutation.

Features include:
- Linux payloads
- Windows payloads
- mixed slash bypasses
- UTF-8 traversal variants
- double URL encoding
- NULL byte injections
- path normalization bypasses
- extension-aware payload generation
- OS-aware mutation logic

The engine automatically adapts based on:
- detected operating system
- endpoint context
- parameter naming
- response signatures
- discovered file extensions

instead of blindly replaying static payload lists.

![Traversal detection](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/traversal_detection.png "Traversal detection")

![Adaptive enum](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/Traversal_valid_enum.png "Adaptive enum")

![Traversal display](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/Traversal_result_display.png "Traversal display")


### Subdomain Enumeration Engine
ThiefHunter includes layered subdomain enumeration with duplicate filtering and source prioritization.

```--wtf``` Passive Discovery

During deep scans, the framework can identify subdomains directly from:
- HTML source code
- JavaScript files
- frontend assets
- leaked API references

This often reveals internal or forgotten infrastructure missed by classic enumeration tools.

```--subdomain``` Enumeration Strategy

Enumeration order:
- DNSDumpster (API)
- crt.sh
- VirusTotal (API)
- manual sensitive subdomain bruteforce

crt.sh instability is handled through:
- automatic retries
- repeated 502 recovery attempts
- resilient fallback logic
(up to 10 retries automatically)


### Sensitive Subdomain Discovery
If public sources fail to enumerate critical infrastructure, ThiefHunter performs additional detection against sensitive targets such as:
- admin panels
- VPN gateways
- staging environments
- CI/CD endpoints
- internal APIs
- developer platforms


### Offensive JWT Toolkit
ThiefHunter includes a dedicated JWT attack module capable of:
- decoding
- validation
- mutation
- re-signing
- algorithm confusion testing
- malicious token generation

Supported attacks:
- alg:none
- RS256 → HS256 confusion
- kid path traversal
- kid NULL byte injection
- jku injection
- x5u injection
- embedded JWK injection
- signature bypass attempts
- offline HMAC cracking support

Supported algorithms:
- HS256 / HS384 / HS512
- RS256 / RS384 / RS512
- ES256 / ES384 / ES512
- EdDSA

![JWT displayer](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/JWT_display.png "JWT displayer")

![JWT sub modification](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/JWT_edit_sub.png "JWT sub modification")

![JWT jwk injection](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/JWT_jwk_injection.png "JWT jwk injection")

![JWT jwk display](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/JWT_jwk_injection_output.png "JWT jwk display")



### OPSEC & Tor-Oriented Networking
A strong focus was placed on operational security and DNS leak prevention.
The framework prioritizes:
```
SOCKS_PROXY = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}
```

```
sock = socks.socksocket()
sock.set_proxy(
    socks.SOCKS5,
    "127.0.0.1",
    9050,
    rdns=True
)
```

Using socks5h ensures:
- remote DNS resolution
- reduced DNS leak risks
- improved anonymity consistency
- Native Tor Validation

The ```--tor``` option includes:
- automatic Tor routing
- SOCKS5 proxy enforcement
- DNS-through-proxy resolution
- Tor usage verification through TorProject APIs

The framework attempts to prevent common OPSEC mistakes frequently overlooked in offensive tooling.


### Centralized Request Architecture
All HTTP requests are centralized into a dedicated dependency layer.

Advantages:
- simplified maintenance
- unified proxy handling
- easier TLS management
- consistent headers/session logic
- centralized OPSEC controls

This architecture also prepares future improvements around:
- persistent sessions
- TLS fingerprint reduction
- request normalization
- reduced negotiation overhead
while already minimizing unnecessary requests whenever possible.


### Additional Modules
- Web Application Firewall detection
- CRLF injection testing
- Open Redirect testing
- Wayback Machine extraction
- recursive crawling
- secret leakage detection
- GitHub commit email intelligence
- security header auditing
- TLS configuration auditing
- dangerous HTTP method detection
- and more...

![Github extraction](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/github_OPSEC.png "Github extraction")

![Github OPSEC emails](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/github_OPSEC_diplay.png "Github OPSEC emails")


## Complete Feature Overview
```
═══════════════════════════════════════════════════════════════════════
            Automated Bug Hunting and Pentesting Tool   
═══════════════════════════════════════════════════════════════════════

Usage:
    python3 thiefhunter.py [options]


GENERAL OPTIONS
───────────────────────────────────────────────────────────────────────
  -h, --help
      Show default help menu

  -hh
      Show advanced help menu with examples and notes

  -nc, --no-clean
      Do not clean the CLI screen before execution
      Keep previous terminal outputs and commands visible

  -v, --verbose
      Enable verbose/debug output
      Useful for troubleshooting, stack traces and file locations

  -t, --timeout <seconds>
      HTTP request timeout (default: 15)

      Notes:
          Some modules internally override timeout values
          depending on request complexity or remote latency


PROXY / NETWORK
───────────────────────────────────────────────────────────────────────
  -p, --proxy <proxy>
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

  --tor
      Force Tor SOCKS proxy usage

      Default:
          127.0.0.1:9050

      Notes:
          - Requires Tor service running locally
          - Uses SOCKS5h to avoid DNS leaks
          - If Tor runs on another port, edit:
                Dependencies/get_request.py


TARGETS
───────────────────────────────────────────────────────────────────────
  -u, --url <url>
      Single target URL

      Example:
          -u https://target.com

  -f, --file <file>
      File containing multiple targets

      Supported format:
          One URL per line

      Example:
          -f targets.txt


REQUEST CUSTOMIZATION
───────────────────────────────────────────────────────────────────────
  --random-headers
      Use random User-Agent headers from payload files

      Useful for:
          - bypassing weak protections
          - avoiding repetitive fingerprints
          - testing detection capabilities
          - reducing correlation between requests

  --headers "Header=Value,Header2=Value2"
      Custom HTTP headers

      Example:
          --headers "Authorization=Bearer TOKEN,Accept=application/json"

  -c, --cookies "name=value,name2=value2"
      Custom cookies

      Example:
          --cookies "session=abc123,token=xyz"

  -X, --method GET,POST,PUT,DELETE
      HTTP method

      Default:
          GET


JWT ANALYSIS
───────────────────────────────────────────────────────────────────────
  --jwt <token>
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


RECON / ENUMERATION
───────────────────────────────────────────────────────────────────────
  -e, --extract <depth>
      Crawl and extract URLs containing parameters

      Features:
          - Recursive crawling
          - Parameterized endpoint extraction
          - Static assets filtering
          - Image/media exclusion by default

      Example:
          --extract 2

  -w, --wayback
      Extract URLs from Wayback Machine archives

  --exclude <ext1,ext2>
      Exclude extensions from Wayback results

      Example:
          --exclude png,jpg,css,js

  --show-all
      Show all Wayback URLs

      Default behavior:
          Only parameterized URLs are displayed

      Useful for:
          - discovering deprecated endpoints
          - old admin panels
          - forgotten APIs
          - hidden resources

  --wtf <depth>
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

  --sub, --subdomains
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

  --dir
      Enumeration and testing of common directories and sensitive files
      from the target domain root.

      Levels:
        1 - Low
        2 - Moderate
        3 - Medium
        4 - High
        
        Higher levels increase the number of paths tested.

      Default: 1

  --bypass-403
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

  --tld
      Enumerate a domain's DNS extensions to identify a related parent domain or detect the presence of clones

  --favicon
      Retrieves the target favicon and computes its MurmurHash3 (Shodan-compatible).

      Displays:
        - Favicon hash
        - Shodan search filter
        - Direct Shodan search URL
        - Censys search URL

      Useful for:
        - Identifying related assets
        - Finding servers sharing the same favicon
        - Infrastructure reconnaissance

      Example:
        --url https://target.com --favicon


VULNERABILITY ANALYSIS
───────────────────────────────────────────────────────────────────────
  --vln, --vuln
      Detect vulnerable technologies and associated CVEs

      Detection sources:
          - Wappalyzer
          - WebTech
          - custom regex fingerprints

      CVE / exploit mapping:
          - Search-Vulns
          - CPE generation
          - exploit correlation

  --exp, --exploit-search <query>
      Manual exploit and vulnerability search

      Supported formats:

      Technology + Version:
          --exploit-search "PHP 8.1"

      CVE:
          --exploit-search CVE-2024-3566

      CPE:
          --exploit-search cpe:2.3:a:sudo_project:sudo:1.8.2:*:*:*:*:*:*:*

  --audit
      Perform basic security audit

      Checks include:
          - missing security headers
          - weak TLS configuration
          - dangerous HTTP methods
          - insecure configurations
          - common hardening issues


WEB VULNERABILITY TESTING
───────────────────────────────────────────────────────────────────────
  --trav, --traversal
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

  --ord, --open-redirect
      Try open redirect vulnerabilities

      Works on:
          - supplied endpoint
          - auto-crawled endpoints (depth=2)

      Example:
          https://target.com/?redirect=test

  --crlf
      Try detecting CRLF injections

      Notes:
          - Header-based testing
          - Detection-oriented
          - Not intended for operational exploitation

  --waf
      Detect Web Application Firewall protections

      Features:
          - fingerprinting
          - detection scoring
          - heuristic analysis

      Recommendation:
          Use with --verbose for detailed scoring
          and manual verification assistance

  --commit
      Detect personnal and professionnals emails from public GitHub repos from the target username

      Purpose:
          Find personal data directly associated with the developers. An email address can be used 
          to correlate passwords leaked by the user, or from those leaks, identify a pattern in how 
          the person or the target’s technical teams create passwords


BASIC AUTH FUZZING
───────────────────────────────────────────────────────────────────────
 --basic-auth
      Fuzz HTTP Basic Authentication credentials

      Features:
          - username/password wordlist support
          - single credential testing
          - HTTP Basic Auth header generation
          - authentication response analysis
          - valid credential detection
          - WAF/firewall block detection
          - request and response debugging
          - fuzzing statistics and progress tracking

      Usage:
          Supports direct values or files:
              --user admin
              --password password

          or wordlists:
              --user @users.txt
              --password @passwords.txt

      Detection:
          Identifies authentication differences based on:
              - HTTP status codes
              - server responses
              - access behavior changes

      Recommendation:
          Use with --verbose for detailed request attempts and response analysis


WORDPRESS FUZZING
───────────────────────────────────────────────────────────────────────
 --wordpress
      Enumerate WordPress users and test authentication methods

      Features:
          - WordPress user enumeration
          - REST API user discovery
          - author ID enumeration (?author=)
          - author sitemap enumeration
          - oEmbed user detection
          - WordPress version detection
          - XML-RPC detection
          - system.multicall vulnerability detection (< WordPress 4.4)
          - wp-login.php authentication
          - XML-RPC authentication
          - adaptive rate limiting
          - WAF/firewall detection
          - progress tracking
          - single credentials or wordlists
          - automatic authentication method selection

      Usage:
          Enumeration only:
              --wordpress / -wp

          Test a single account:
              --wordpress --user admin --password password123

          Use wordlists both usernames and passwords:
              --wordpress --user @file/to/users.txt --password @file/to/passwords.txt

          Use wordlists with one username:
              --wordpress --user admin --password @file/to/passwords.txt

      Detection:
          Enumerates users using:
              - REST API endpoints
              - oEmbed endpoint
              - author archives
              - author sitemaps

          Detects authentication surface:
              - wp-login.php
              - xmlrpc.php
              - system.multicall availability

      Recommendation:
          Use with --verbose to display every endpoint, request,
          detected authentication method and WordPress version.


AUTOMATION
───────────────────────────────────────────────────────────────────────
  --batch
      Automation of default user inputs. Script execution without any user interaction, for example 
      by automatically handling prompts related to --traversal or --subdomains during successful 
      tests that would normally ask whether the user wants to proceed further with the testing


EXAMPLES
───────────────────────────────────────────────────────────────────────
  Basic security audit:
      python3 thiefhunter.py -u https://target.com --audit

  Crawl and extract URLs:
      python3 thiefhunter.py -u https://target.com -e 2

  Extract Wayback URLs:
      python3 thiefhunter.py -u https://target.com --wayback

  Wayback with exclusions:
      python3 thiefhunter.py -u https://target.com --wayback --exclude jpg,png,css

  Deep secret scan:
      python3 thiefhunter.py -u https://target.com --wtf 3

  JWT analysis:
      python3 thiefhunter.py --jwt TOKEN

  Exploit search:
      python3 thiefhunter.py --exploit-search "Apache 2.4.49"

  Through Burp Suite:
      python3 thiefhunter.py -u https://target.com --proxy http://127.0.0.1:8080 --vln

  Through Tor:
      python3 thiefhunter.py -u https://target.com --tor --traversal

  Path traversal testing:
      python3 thiefhunter.py -u "https://target.com/?file=test" --trav

  Open redirect testing:
      python3 thiefhunter.py -u "https://target.com/?redirect=test" --ord

  Basic Auth fuzzing:
      python3 thiefhunter.py -u "https://target.com/login" --basicauth -U admin -P "@\path\to\your passwords.txt" --batch -v

═══════════════════════════════════════════════════════════════════════
```



## Disclaimer
ThiefHunter v2 is a penetration testing and bug hunting tool designed exclusively for ethical hacking and authorized security assessments. Misuse of this tool for illegal purposes, unauthorized attacks, or activities outside the scope of the law is strictly prohibited.


By using ThiefHunter v2, you agree to the following :

You will only use this tool on systems and networks you own or have explicit permission to test.

You acknowledge that unauthorized use may violate local, national, or international laws.

The creator of ThiefHunter is not responsible for any damages, legal consequences, or ethical violations resulting from the misuse of this tool.

Always prioritize responsible, legal, and ethical behavior when performing security testing.


