import random
from functools import lru_cache

FALSE_FLAG_PROFILES = {
    "ru": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "ru-RU,ru;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 YaBrowser/26.1.5.557 Yowrix/2.5",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 OPR/139.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0",
        ],
    },
    "cn": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 QQBrowser/13.5.40440.400",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 360SE/2.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Baidu/16.0.0.0",
        ],
    },
    "us": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.2 Safari/605.1.15",
        ],
    },
    "ph": {
        "platform": "Android",
        "mobile": True,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "en-PH,en;q=0.9",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Linux; Android 14; Infinix X6821B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Redmi 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Samsung SM-A155F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; TECNO SPARK 20) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14;itel itel P55) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
        ],
    },
    "ir": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="156", "Google Chrome";v="156", "Not=A?Brand";v="24"',
        "accept_lang": "fa-IR,fa;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 OPR/138.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0",
        ],
    },
    "br": {
        "platform": "Android",
        "mobile": True,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "pt-BR,pt;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Linux; Android 14; SM-A155F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Moto G84 5G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 15; Pixel 8a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Samsung SM-A356B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
        ],
    },
    "in": {
        "platform": "Android",
        "mobile": True,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "hi-IN,hi;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Linux; Android 14; Redmi 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 13; Samsung SM-A255F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 15; OnePlus 12R) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 14; Realme 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Vivo V27) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36",
        ],
    },
    "de": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "de-DE,de;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 OPR/139.0.0.0",
        ],
    },
    "tr": {
        "platform": "Windows",
        "mobile": False,
        "ch_ua": '"Chromium";v="157", "Google Chrome";v="157", "Not=A?Brand";v="24"',
        "accept_lang": "tr-TR,tr;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate, br, zstd",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "uas": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 OPR/139.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0",
        ],
    },
}

@lru_cache(maxsize=None) # Same UAS profile in logs
def get_false_flag_headers(country: str):
    profile = FALSE_FLAG_PROFILES.get(country.lower())
    if not profile:
        raise ValueError(f"Unknown country: {country}")

    ua = random.choice(profile["uas"])
    return {
        "User-Agent": ua,
        "Accept": profile["accept"],
        "Accept-Language": profile["accept_lang"],
        "Accept-Encoding": profile["accept_encoding"],
        "Sec-CH-UA": profile["ch_ua"],
        "Sec-CH-UA-Platform": f'"{profile["platform"]}"',
        "Sec-CH-UA-Mobile": "?1" if profile["mobile"] else "?0",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
