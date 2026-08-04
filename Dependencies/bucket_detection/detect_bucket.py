import tldextract, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request
from Dependencies.save_output import add_result

# Drop theses subdomains if extra_words from --subdomains
EXCLUDED_LABELS = {
    "www",
    "mail",
    "smtp",
    "imap",
    "pop",
    "mx",
    "mx0",
    "mx1",
    "mx2",
    "mx3",
    "ns",
    "ns1",
    "ns2",
}


def load_wordlist(path):
    words = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                words.append(line)

    except FileNotFoundError:
        print(f"{R}[-] Wordlist not found: {path}")
    return words


def normalize_domain(domain):
    domain = domain.lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    domain = domain.replace("www.", "")
    extracted = tldextract.extract(domain)
    return {
        "fqdn": domain,
        "root": f"{extracted.domain}.{extracted.suffix}",
        "name": extracted.domain
    }


def generate_bucket_names(domain, wordlist, extra_words=None):
    if extra_words:
        cleaned_words = set()
        for sub in extra_words:
            if sub.endswith("." + domain):
                prefix = sub[:-len(domain)-1]
            else:
                prefix = sub

            label = prefix.split(".")[0]
            if label and label not in EXCLUDED_LABELS:
                cleaned_words.add(label)
                
        wordlist = list(set(wordlist) | cleaned_words)
        
    domains = normalize_domain(domain)
    candidates = set()
    bases = [
        domains["root"],
        domains["name"]
    ]

    candidates.add(domains["fqdn"])
    candidates.add(domains["root"])
    candidates.add(domains["name"])
    
    for base in bases:
        for word in wordlist:
            candidates.add(f"{word}-{base}")
            candidates.add(f"{word}.{base}")
            candidates.add(f"{word}{base}")
    
    for word in wordlist:
        candidates.add(f"{domains["name"]}{word}")
        candidates.add(f"{domains["name"]}-{word}")
    
    return candidates


def scan_azure_container(storage_account, container, args):
    url = f"https://{storage_account}.blob.core.windows.net/{container}"

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.6",
    }
    
    r = get_request(args, url, headers=headers, timeout=10)
    if r is None or isinstance(r, str):
        return

    body = r.text
    if r.status_code == 200:
        listing = "<EnumerationResults" in body

        tqdm.write(f"{G}[200] Azure container public {R}{storage_account}/{container} {W}{url}")

        if args.save:
            add_result("Cloud", {
                "type": "cloud_bucket",
                "data": {
                    "provider": "Azure Blob",
                    "storage_account": storage_account,
                    "container": container,
                    "url": url,
                    "status": 200,
                    "public": True,
                    "listing": listing
                }
            })

    elif r.status_code == 403:
        tqdm.write(f"{Y}[403] Azure container private {R}{storage_account}/{container}{W}")
        if args.save:
            add_result("Cloud", {
                "type": "cloud_bucket",
                "data": {
                    "provider": "Azure Blob",
                    "storage_account": storage_account,
                    "container": container,
                    "url": url,
                    "status": 403,
                    "public": False,
                    "listing": False
                }
            })

    elif r.status_code == 404:
        if args.verbose:
            tqdm.write(f"{W}[{r.status_code}] {url}")

    else:
        if args.verbose:  
            tqdm.write(f"{Y}[{r.status_code}] {W}{url}")


def scan_request(provider, bucket, url, args, words, pbar, executor, futures):
    if args.tor:
        timeout = getattr(args, "timeout", 15)
    else:
        timeout = getattr(args, "timeout", 10)

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "fr-FR,fr;q=0.6",
    }

    r = get_request(args, url, headers=headers, timeout=timeout)
   
    if args.verbose:
        if not r or isinstance(r, str):
            tqdm.write(f"{W}[NO RESPONSE] {url}")
        
    if r is None or isinstance(r, str):
        return

    if provider == "AWS S3":
        body = r.text
        listing = "</ListBucketResult>" in body
        
        if "NoSuchBucket" in body:
            if args.verbose:
                tqdm.write(f"{W}[404] AWS S3 bucket {bucket} {url}")
            return

        if r.status_code == 200:
            if "</ListBucketResult>" in body:
                tqdm.write(f"{G}[200] AWS S3 public listing {R}{bucket} {W}{url}")
            else:
                tqdm.write(f"{G}[200] AWS S3 public listing {R}{bucket} {W}{url}")

            if args.save:
                add_result("Cloud", {
                    "type": "cloud_bucket",
                    "data": {
                        "source": "bucket_enum",
                        "provider": "AWS S3",
                        "bucket": bucket,
                        "url": url,
                        "status": 200,
                        "public": True,
                        "listing": listing
                    }
                })

        elif r.status_code == 403:
            tqdm.write(f"{Y}[403] AWS S3 exists but private {R}{bucket} {W}{url}")
            if args.save:
                add_result("Cloud", {
                    "type": "cloud_bucket",
                    "data": {
                        "source": "bucket_enum",
                        "provider": "AWS S3",
                        "bucket": bucket,
                        "url": url,
                        "status": 403,
                        "public": False,
                        "listing": False
                    }
                })

        else:
            if args.verbose:
                tqdm.write(f"{Y}[{r.status_code}] {W}{url}")

    elif provider == "Azure Blob":
        if r.status_code in (200, 403):
            public = r.status_code == 200
            tqdm.write(f"{G}[FOUND] Azure Blob {R}{bucket} {W}{url}")
            if args.save:
                add_result("Cloud", {
                    "type": "cloud_bucket",
                    "data": {
                        "source": "bucket_enum",
                        "provider": "Azure Blob",
                        "bucket": bucket,
                        "url": url,
                        "status": r.status_code,
                        "public": public,
                        "listing": False
                    }
                })
                
        elif r.status_code == 400:
            tqdm.write(f"{Y}[400] Azure storage account found {R}{bucket} {W}{url}")
            if args.save:
                add_result("Cloud", {
                    "type": "cloud_bucket",
                    "data": {
                        "source": "bucket_enum",
                        "provider": "Azure Blob",
                        "bucket": bucket,
                        "url": url,
                        "status": r.status_code,
                        "public": False,
                        "listing": False
                    }
                })
                
            new_tasks = len(words)
            pbar.total += new_tasks
            pbar.refresh()
            for container in words:
                future = executor.submit(scan_azure_container, bucket, container, args)
                futures.append(future)

        elif r.status_code == 404:
            if args.verbose:  
                tqdm.write(f"{W}[{r.status_code}] {W}{url}")
                
    else:
        if args.verbose:  
            tqdm.write(f"{Y}[{r.status_code}] {W}{url}")


def dobucket(args, extracted_domain, extra_words=None):
    if args.tor:
        print(
            f"{Y}[!] {W}Tor may cause false {R}S3 errors{W}. "
            "Some exit nodes can return 'NoSuchBucket' for public AWS buckets.\n"
            "    --> Try changing your Tor circuit and retry or disable --tor"
        )

    words = load_wordlist("Dependencies/Payloads/bucket_enum.txt")
    buckets = generate_bucket_names(extracted_domain, words, extra_words)
    requests = []
    for bucket in buckets:
        requests.append(("AWS S3", bucket, f"https://{bucket}.s3.amazonaws.com/"))
        requests.append(("AWS S3", bucket, f"https://s3.amazonaws.com/{bucket}/"))
        requests.append(("Azure Blob", bucket, f"https://{bucket}.blob.core.windows.net/"))

    print(f"{Y}[!] {W}Generated {Y}{len(buckets)} {W}bucket candidates")
    print(f"{Y}[!] {W}Performing {Y}{len(requests)} {W}HTTP requests (this may increase by up to {Y}{len(words)} {W}requests per Azure storage account found)")
    workers = 25
    with tqdm(total=len(requests), desc="HTTP requests", unit="req") as pbar:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for provider, bucket, url in requests:
                future = executor.submit(scan_request, provider, bucket, url, args, words, pbar, executor, futures)
                futures.append(future)

            while futures:
                done = []
                for future in as_completed(futures):
                    done.append(future)

                    try:
                        future.result()
                    except Exception as e:
                        handle_error(e)

                    pbar.update(1)

                for future in done:
                    futures.remove(future)