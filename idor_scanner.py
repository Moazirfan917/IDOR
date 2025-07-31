#!/usr/bin/env python3
import sys, os, re, json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from tqdm import tqdm

if len(sys.argv) < 2:
    print("Usage: python3 idor_scanner.py https://target.site/login https://target.site/start USERNAME PASSWORD")
    sys.exit(1)

LOGIN_URL = sys.argv[1]
START_URL = sys.argv[2]
USERNAME = sys.argv[3]
PASSWORD = sys.argv[4]

OUTPUT = "idor_report.json"

def login(session):
    if USERNAME.lower() == "none" or PASSWORD.lower() == "none":
        print("[INFO] Skipping login step as username or password is set to 'none'.")
        return

    try:
        r = session.get(LOGIN_URL, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        data = {tag['name']: tag.get('value', '') for tag in soup.select('form input')}
        data.update({'username': USERNAME, 'password': PASSWORD})
        session.post(LOGIN_URL, data=data)
        print("[INFO] Login attempt finished.")
    except Exception as e:
        print(f"[!] Login step failed: {e}")


def crawl(session, start_url):
    to_scan, seen = [start_url], set()
    urls = []
    while to_scan:
        url = to_scan.pop()
        if url in seen or urlparse(url).netloc != urlparse(start_url).netloc:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=10)
        except Exception:
            continue
        soup = BeautifulSoup(r.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            link = urljoin(start_url, a['href'])
            to_scan.append(link)
        urls.append(url)
    return urls

def extract_params(url):
    qs = parse_qs(urlparse(url).query)
    return [k for k, v in qs.items() if any(re.fullmatch(r'\d+|[0-9a-fA-F\-]{8,}', x) for x in v)]

def fuzz_url(session, original, param):
    qs = parse_qs(urlparse(original).query)
    base = original.split('?')[0]
    results = []
    for delta in [1, -1]:
        v = qs[param][0]
        if v.isdigit():
            newv = str(int(v) + delta)
        else:
            continue
        qs[param] = newv
        newurl = f"{base}?{urlencode(qs, doseq=True)}"
        try:
            r = session.get(newurl, timeout=10)
            results.append({'url': newurl, 'status': r.status_code, 'len': len(r.text)})
        except Exception:
            continue
    return results

def screenshot(url):
    opts = Options()
    opts.headless = True
    driver = webdriver.Chrome(options=opts)
    driver.get(url)
    path = f"screenshots/{urlparse(url).path.strip('/').replace('/', '_') or 'root'}.png"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    driver.save_screenshot(path)
    driver.quit()
    return path

os.makedirs('screenshots', exist_ok=True)
sess = requests.Session()
login(sess)
urls = crawl(sess, START_URL)

findings = []
for url in tqdm(urls):
    params = extract_params(url)
    for p in params:
        base = fuzz_url(sess, url, p)
        if not base:
            continue
        if base[0]['len'] != base[1]['len']:
            cap = screenshot(url)
            findings.append({'param': p, 'url': url, 'fuzz': base, 'screenshot': cap})

with open(OUTPUT, 'w') as f:
    json.dump(findings, f, indent=2)

print(f"\n✅ Scan complete. {len(findings)} potential IDORs found.")
print(f"📝Report: {OUTPUT}")
