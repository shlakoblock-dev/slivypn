import time
import urllib.request
import base64
import socket
import ssl
import json
import urllib.parse
import statistics
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# --- ИСТОЧНИКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
OUTPUT_FILE = "sub.txt"

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

# Префиксы Cloudflare (через них VPN не пашет)
BAD_IPS = ["104.", "172.6", "172.7", "188.114."]

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
            new_name = f"{flag} {country} [{host}]".strip()
            return parts[0] + '#' + urllib.parse.quote(new_name)
    return parts[0] + '#' + urllib.parse.quote(f"🌍 Неизвестно [{host}]")

def get_all_configs():
    all_configs = set()
    for url in SOURCE_URLS:
        configs = get_configs_from_url(url)
        for c in configs:
            all_configs.add(rename_server(c))
    return list(all_configs)

def get_host_port_sni(uri):
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            if "?" in b64: b64 = b64.split("?")[0]
            data = json.loads(base64.b64decode(b64 + "==").decode('utf-8'))
            return data.get("add"), int(data.get("port")), data.get("sni", data.get("host", data.get("add")))
        except: return None, None, None
    elif "://" in uri:
        try:
            parsed = urllib.parse.urlparse(uri)
            query = urllib.parse.parse_qs(parsed.query)
            sni = query.get('sni', [None])[0] or query.get('host', [None])[0] or parsed.hostname
            return parsed.hostname, int(parsed.port), sni
        except: pass
    return None, None, None

def tls_ping_with_sni(host, port, sni):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=1.5) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                return (time.time() - start) * 1000
    except:
        return -1

def check_server(uri):
    # 1. Отсеиваем CDN
    for bad in BAD_IPS:
        if bad in uri:
            return None, -1

    host, port, sni = get_host_port_sni(uri)
    if not host or not port or not sni:
        return None, -1

    # 2. Проверяем 3 раза
    pings = []
    success = 0
    for _ in range(3):
        ping = tls_ping_with_sni(host, port, sni)
        if ping > 0:
            pings.append(ping)
            success += 1
        time.sleep(0.1)

    # Условие: 2 успешных TLS-хендшейка из 3
    if success >= 2:
        avg_ping = statistics.mean(pings)
        if avg_ping < 300: # Немного подняли, иначе выживших не будет
            return uri, avg_ping
            
    return None, -1

def main():
    log("="*40)
    log("[START] Начинаем процесс обновления подписки")
    log("="*40)
    
    log("[1/3] Скачиваем конфиги...")
    raw_configs = get_all_configs()
    if not raw_configs:
        log("[ERROR] Не удалось скачать ни одного конфига.")
        return

    # Оставляем только VLESS и VMESS
    filtered_configs = [c for c in raw_configs if c.startswith("vless://") or c.startswith("vmess://")]
    log(f"   Всего серверов после фильтра протоколов: {len(filtered_configs)}")

    log(f"[2/3] Проверяем TLS/Reality доступность (всего {len(filtered_configs)} шт)...")
    all_alive = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_uri = {executor.submit(check_server, uri): uri for uri in filtered_configs}
        
        completed = 0
        for future in future_to_uri:
            completed += 1
            if completed % 50 == 0:
                log(f"   ... проверено {completed} из {len(filtered_configs)}")
                
            result_uri, avg_ping = future.result()
            if result_uri:
                all_alive.append((result_uri, avg_ping))

    log(f"   Успешно прошли проверку: {len(all_alive)} серверов.")

    # --- ЭТАП 3: ФИЛЬТРАЦИЯ И СОРТИРОВКА ---
    log(f"[3/3] Фильтрация и сортировка...")
    all_alive.sort(key=lambda x: x[1])
    
    final_uris = []
    country_counts = defaultdict(int)
    MAX_PER_COUNTRY = 3
    TARGET_COUNT = 25
    
    for uri, ping in all_alive:
        if len(final_uris) >= TARGET_COUNT:
            break
            
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', urllib.parse.unquote(uri.split('#')[1]) if '#' in uri else "")
        flag = flag_match.group(0) if flag_match else "Unknown"
        
        if country_counts[flag] >= MAX_PER_COUNTRY:
            continue
            
        final_uris.append(uri)
        country_counts[flag] += 1
        
        name = urllib.parse.unquote(uri.split('#')[1]) if '#' in uri else "Без имени"
        log(f"   [В СПИСКЕ] {name} | Пинг: {ping:.0f}ms")

    log(f"[DONE] Отобрано {len(final_uris)} лучших серверов.")
    
    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется и чекает пинг. Просто нажми Обновить.\n"
    )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(final_uris))
        
    log(f"[SAVE] Файл {OUTPUT_FILE} успешно записан.")

if __name__ == "__main__":
    main()

if __name__ == "__main__":
    main()
