# thiefhunter v2

ThiefHunter is an offensive security framework designed for real-world reconnaissance, vulnerability research and adaptive web exploitation.
Built for pentesters, bug bounty hunters and auditors, it focuses on high signal enumeration, low-noise OPSEC, and context-aware attack automation.
The tool focusses on adaptive offensive automation with practical OPSEC awareness.

![Main menu](https://raw.githubusercontent.com/raphaelthief/thiefhunter/refs/heads/main/Screens/Main.png "Main menu")

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
### Advanced Vulnerability Enumeration
Wordfence API Integration (No WPScan-style token limitations)
ThiefHunter leverages the Wordfence vulnerability intelligence API for WordPress vulnerability enumeration.

Advantages:
- no WPScan token quota limitations
- scalable enumeration
- plugin/theme vulnerability correlation
- continuous CVE intelligence integration

This allows large-scale WordPress audits without artificial API restrictions.


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


## Disclaimer
ThiefHunter v2 is a penetration testing and bug hunting tool designed exclusively for ethical hacking and authorized security assessments. Misuse of this tool for illegal purposes, unauthorized attacks, or activities outside the scope of the law is strictly prohibited.


By using ThiefHunter v2, you agree to the following :

You will only use this tool on systems and networks you own or have explicit permission to test.

You acknowledge that unauthorized use may violate local, national, or international laws.

The creator of ThiefHunter is not responsible for any damages, legal consequences, or ethical violations resulting from the misuse of this tool.

Always prioritize responsible, legal, and ethical behavior when performing security testing.


