# thiefhunter


ThiefHunter is a bug hunting and penetration testing tool designed to identify security vulnerabilities efficiently. It combines advanced crawling, URL analysis, and vulnerability exploitation techniques, making it a versatile tool


![Main menu](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/Main.JPG "Main menu")



## Key Features

- Targeted URL Scanning : Crawl and analyze target URLs to extract links, detect sensitive parameters, and uncover vulnerabilities
- Batch Scanning : Support for scanning multiple URLs loaded from a file, with tailored options for various vulnerability types
- Customizable HTTP Requests :
    - Randomized user-agent headers for realistic simulations
    - Custom cookie support
    -  Proxy and Tor network integration for anonymity


- Vulnerability Detection :
    - Path Traversal : Automated testing using predefined payloads
    - Open Redirects : Payload injection to identify unsafe redirects
    - CRLF Injection : Check for header injection vulnerabilities
    - Clickjacking : Assess X-Frame-Options and Content Security Policy headers


- WordPress Scanning :
    - Identify plugins, themes, and their versions
    - Enumerate usernames through exposed API endpoints
    - Detect WordPress version from metadata, assets, and accessible files


- Comprehensive Link Analysis :
    - Extract URLs from Wayback Machine, robots.txt, and sitemap.xml
    - Normalize and deduplicate query parameters to streamline results
    - Highlight URLs with sensitive parameters or specific extensions (ex : .php)


- Integrated Tools :
    - SQLmap for SQL injection testing (https://github.com/sqlmapproject/sqlmap)
    - Dalfox for XSS vulnerability checks (https://github.com/hahwul/dalfox)
    - Nuclei for advanced template-based scans (https://github.com/projectdiscovery/nuclei)
    - Wpscan for advanced wordpress scans (https://github.com/wpscanteam/wpscan)


- IP Configuration Check : Validate and display global IP configurations, including Tor-based setups
- Verbose Output and Logging : Enable detailed logs for in-depth analysis and troubleshooting



## Setup

The usage of external tools depends on the .txt files located in the install_paths folder
You only need to specify the installation directories of third-party programs in these files for their integration



## Usage

``` bash
python thiefhunter.py [OPTIONS]
```


![help](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/help.JPG "help")



## Exemples

``` bash
python thiefhunter.py -u https://example.com -e --normalize
```

![normalize](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/normalize.JPG "normalize")


``` bash
python thiefhunter.py -u https://example.com -e --normalize --exclude php
```

![exclude](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/exclude.JPG "exclude")



``` bash
python thiefhunter.py -u https://example.com --ip-check
```

- Exemple 1 : No use of Tor or other external tools

![ex1](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/checkip1.JPG "ex1")


- Exemple 2 : Usage of the internal Tor proxy within ThiefHunter but no usage for external programs triggered by thiefHunter

![ex2](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/checkip2.JPG "ex2")


- Exemple 3 : Use of Tor via an external program (ex : Torsocks) with Tor's exit IP applied to external programs triggered by thiefHunter

![ex3](https://github.com/raphaelthief/thiefhunter/blob/main/Pic/checkip3.JPG "ex3")



## Disclaimer


ThiefHunter is a penetration testing and bug hunting tool designed exclusively for ethical hacking and authorized security assessments. Misuse of this tool for illegal purposes, unauthorized attacks, or activities outside the scope of the law is strictly prohibited.


By using ThiefHunter, you agree to the following :

You will only use this tool on systems and networks you own or have explicit permission to test.
You acknowledge that unauthorized use may violate local, national, or international laws.
The creator of ThiefHunter is not responsible for any damages, legal consequences, or ethical violations resulting from the misuse of this tool.
Always prioritize responsible, legal, and ethical behavior when performing security testing.


