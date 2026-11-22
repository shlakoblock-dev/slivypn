import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
import re
import sys
import os
import subprocess
import zipfile
import shutil
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import requests

# --- ИСТОЧНИКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
OUTPUT_FILE = "sub.txt"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v1.8.13/Xray-linux-64.zip"

# --- СЛОВАРЬ СТРАН ---
COUNTRY_MAP = {
    "🇩🇪": "Германия", "🇷🇺": "Россия", "🇺🇸": "США", "🇳🇱": "Нидерланды",
    "🇫🇮": "Финляндия", "🇸🇪": "Швеция", "🇫🇷": "Франция", "🇬🇧": "Британия",
    "🇯🇵": "Япония", "🇸🇬": "Сингапур", "🇹🇷": "Турция", "🇵🇱": "Польша",
    "🇺🇦": "Украина", "🇰🇿": "Казахстан", "🇨🇭": "Швейцария", "🇮🇹": "Италия",
    "🇦🇹": "Австрия", "🇪🇸": "Испания", "🇨🇦": "Канада", "🇭🇰": "Гонконг",
    "🇰🇷": "Корея", "🇧🇷": "Бразилия", "🇦🇺": "Австралия", "🇮🇳": "Индия",
    "🇨🇿": "Чехия", "🇱🇹": "Литва", "🇱🇻": "Латвия", "🇪🇪": "Эстония",
    "🇲🇩": "Молдова", "🇦🇲": "Армения", "🇬🇪": "Грузия", "🇦🇿": "Азербайджан",
    "🇧🇾": "Беларусь", "🇰🇬": "Киргизия", "🇺🇿": "Узбекистан", "🇲🇳": "Монголия",
    "🇲🇽": "Мексика", "🇦🇷": "Аргентина", "🇨🇱": "Чили", "🇿🇦": "ЮАР",
    "🇦🇪": "ОАЭ", "🇮🇱": "Израиль", "🇸🇦": "Саудовская Аравия", "🇶🇦": "Катар",
    "🇮🇩": "Индонезия", "🇲🇾": "Малайзия", "🇹🇭": "Таиланд", "🇻🇳": "Вьетнам",
    "🇵🇭": "Филиппины", "🇳🇿": "Новая Зеландия", "🇮🇪": "Ирландия", "🇵🇹": "Португалия",
    "🇬🇷": "Греция", "🇷🇴": "Румыния", "🇧🇬": "Болгария", "🇭🇺": "Венгрия",
    "🇸🇰": "Словакия", "🇸🇮": "Словения", "🇭🇷": "Хорватия", "🇷🇸": "Сербия",
    "🇧🇦": "Босния", "🇲🇰": "Македония", "🇦🇱": "Албания", "🇲🇪": "Черногория"
}

BAD_PREFIXES = ["104.", "172.6", "172.7", "188.114.", "141.101.", "141.193.", "162.158.", "198.41."]

def log(msg):
    print(msg)
    sys.stdout.flush()

def get_configs_from_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                if '://' in decoded: content = decoded
            except: pass
            return [line.strip() for line in content.splitlines() if '://' in line]
    except Exception as e:
        log(f"[ОШИБКА ИСТОЧНИКА] {url[:40]}... : {e}")
        return []

def rename_server(uri):
    parts = uri.split('#')
    host = ""
    try:
        parsed = urllib.parse.urlparse(uri)
        host = parsed.hostname or ""
    except: pass

    if len(parts) > 1:
        decoded_name = urllib.parse.unquote(parts[1])
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', decoded_name)
        if flag_match:
            flag = flag_match.group(0)
            country = COUNTRY_MAP.get(flag, "Неизвестно")
            return parts[0] + '#' + urllib.parse.quote(f"{flag} {country} [{host}]".strip())
    return parts[0] + '#' + urllib.parse.quote(f"🌍 Неизвестно [{host}]")

def parse_uri_to_xray(uri):
    try:
        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        
        outbound = {
            "protocol": parsed.scheme,
            "settings": {},
            "streamSettings": {"network": params.get('type', ['tcp'])[0]}
        }
        
        sec = params.get('security', ['none'])[0]
        if sec == 'tls':
            outbound['streamSettings']['security'] = 'tls'
            if 'sni' in params: outbound['streamSettings']['tlsSettings'] = {"serverName": params['sni'][0]}
        elif sec == 'reality':
            outbound['streamSettings']['security'] = 'reality'
            outbound['streamSettings']['realitySettings'] = {
                "publicKey": params.get('pbk', [''])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "serverName": params.get('sni', [''])[0],
                "shortId": params.get('sid', [''])[0]
            }

        if parsed.scheme == 'vless':
            outbound['settings'] = {
                "vnext": [{
                    "address": parsed.hostname,
                    "port": parsed.port,
                    "users": [{"id": parsed.username, "encryption": "none", "flow": params.get('flow', [''])[0]}]
                }]
            }
        elif parsed.scheme == 'vmess':
            b64 = uri[8:]
            if "?" in b64: b64 = b64.split("?")[0]
            data = json.loads(base64.b64decode(b64 + "==").decode('utf-8'))
            outbound['settings'] = {
                "vnext": [{
                    "address": data['add'],
                    "port": int(data['port']),
                    "users": [{"id": data['id'], "alterId": int(data.get('aid', 0)), "security": data.get('scy', 'auto')}]
                }]
            }
            if data.get('net') == 'ws':
                outbound['streamSettings']['network'] = 'ws'
                outbound['streamSettings']['wsSettings'] = {"path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}
                if data.get('tls') == 'tls':
                    outbound['streamSettings']['security'] = 'tls'
                    outbound['streamSettings']['tlsSettings'] = {"serverName": data.get('sni', '')}
        return outbound
    except Exception:
        return None

def main():
    log("Скачиваем и готовим Xray...")
    os.makedirs("xray_bin", exist_ok=True)
    xray_zip = "xray.zip"
    if not os.path.exists(xray_zip) and not os.path.exists("xray_bin/xray"):
        urllib.request.urlretrieve(XRAY_URL, xray_zip)
        with zipfile.ZipFile(xray_zip, 'r') as zip_ref:
            zip_ref.extractall("xray_bin")
        os.chmod("xray_bin/xray", 0o755)

    raw_configs = []
    for url in SOURCE_URLS:
        raw_configs.extend(get_configs_from_url(url))

    filtered = [rename_server(c) for c in raw_configs if c.startswith("vless://") or c.startswith("vmess://")]
    log(f"Всего серверов: {len(filtered)}")

    inbounds, outbounds, rules, valid_uris = [], [], [], []
    
    for i, uri in enumerate(filtered):
        host = urllib.parse.urlparse(uri).hostname if uri.startswith("vless") else "vmess"
        if any(host.startswith(b) for b in BAD_PREFIXES): continue

        out = parse_uri_to_xray(uri)
        if not out: continue
        
        port = 20000 + len(valid_uris)
        out['tag'] = f"proxy_{port}"
        outbounds.append(out)
        
        inbounds.append({"listen": "127.0.0.1", "port": port, "protocol": "socks", "tag": f"socks_{port}"})
        rules.append({"type": "field", "inboundTag": [f"socks_{port}"], "outboundTag": f"proxy_{port}"})
        valid_uris.append(uri)

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": rules}
    }
    
    with open("xray_config.json", "w") as f:
        json.dump(config, f)

    log("Запускаем Xray...")
    proc = subprocess.Popen(["./xray_bin/xray", "-c", "xray_config.json"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3) # Даем Xray подняться

    def test_port(uri, port):
        try:
            proxies = {'http': f'socks5h://127.0.0.1:{port}', 'https': f'socks5h://127.0.0.1:{port}'}
            start = time.time()
            r = requests.head('https://www.gstatic.com/generate_204', proxies=proxies, timeout=4)
            if r.status_code == 204:
                return uri, (time.time() - start) * 1000
        except:
            return None, -1
        return None, -1

    log("Тестируем порты...")
    alive = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(test_port, uri, 20000+i) for i, uri in enumerate(valid_uris)]
        for f in futures:
            u, p = f.result()
            if u: alive.append((u, p))

    proc.terminate()
    log(f"Живых серверов: {len(alive)}")

    alive.sort(key=lambda x: x[1])
    final_uris, country_counts = [], defaultdict(int)
    
    for uri, ping in alive:
        if len(final_uris) >= 15: break
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', urllib.parse.unquote(uri.split('#')[1]) if '#' in uri else "")
        flag = flag_match.group(0) if flag_match else "Unknown"
        if country_counts[flag] >= 3: continue
        final_uris.append(uri)
        country_counts[flag] += 1
        log(f"[В СПИСКЕ] {urllib.parse.unquote(uri.split('#')[1])} | Пинг: {ping:.0f}ms")

    header = "#profile-title: Sлiвы VPN ~ Drun Tier\n#profile-update-interval: 1\n#profile-desc: Подписка автообновляется. Нажми Обновить.\n"
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(final_uris))
    log("Файл сохранен!")

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
