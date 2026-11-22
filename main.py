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
    if len(parts) > 1:
        decoded_name = urllib.parse.unquote(parts[1])
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', decoded_name)
        if flag_match:
            flag = flag_match.group(0)
            country = COUNTRY_MAP.get(flag, "Сервер")
            host = ""
            try:
                parsed = urllib.parse.urlparse(uri)
                host = parsed.hostname or ""
            except: pass
            new_name = f"{flag} {country} [{host}]".strip()
            return parts[0] + '#' + urllib.parse.quote(new_name)
    return uri

def get_all_configs():
    all_configs = set()
    for url in SOURCE_URLS:
        configs = get_configs_from_url(url)
        if configs:
            log(f"[OK] Загружено {len(configs)} ссылок из {url.split('/')[-1]}")
        for c in configs:
            all_configs.add(rename_server(c))
    return list(all_configs)

def get_host_port(uri):
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            if "?" in b64: b64 = b64.split("?")[0]
            data = json.loads(base64.b64decode(b64 + "==").decode('utf-8'))
            return data.get("add"), int(data.get("port"))
        except: return None
    elif "://" in uri:
        try:
            parsed = urllib.parse.urlparse(uri)
            if parsed.hostname and parsed.port:
                return parsed.hostname, int(parsed.port)
        except: pass
    return None

def tcp_ping_once(host_port):
    if not host_port: return -1
    host, port = host_port
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=1.0):
            return (time.time() - start) * 1000
    except:
        return -1

def tls_handshake_ping(host_port):
    if not host_port: return -1
    host, port = host_port
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=1.0) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return (time.time() - start) * 1000
    except:
        return -1

def check_server(uri, host_port):
    if not host_port: return None, -1
    
    # ЭТАП 1: Быстрая проверка
    if tcp_ping_once(host_port) <= 0:
        return None, -1
    
    # ЭТАП 2: Глубокая проверка
    tcp_success = 0
    tls_success = 0
    pings = []
    
    for _ in range(3):
        tcp = tcp_ping_once(host_port)
        if tcp > 0:
            tcp_success += 1
            tls = tls_handshake_ping(host_port)
            if tls > 0:
                tls_success += 1
                pings.append(tcp)
        time.sleep(0.05)
    
    if tcp_success >= 3 and tls_success >= 2 and pings:
        avg_ping = statistics.mean(pings)
        if avg_ping < 150:
            return uri, avg_ping
            
    return None, -1

def extract_country_flag(uri):
    """Достает флаг страны из имени сервера для группировки"""
    parts = uri.split('#')
    if len(parts) > 1:
        decoded_name = urllib.parse.unquote(parts[1])
        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', decoded_name)
        if flag_match:
            return flag_match.group(0)
    return "Unknown"

def main():
    log("="*40)
    log("[START] Начинаем процесс обновления подписки")
    log("="*40)
    
    log("[1/4] Скачиваем конфиги...")
    raw_configs = get_all_configs()
    if not raw_configs:
        log("[ERROR] Не удалось скачать ни одного конфига.")
        return

    log(f"[2/4] Парсим {len(raw_configs)} серверов...")
    parsed_data = []
    for uri in raw_configs:
        hp = get_host_port(uri)
        if hp:
            parsed_data.append((uri, hp))

    log(f"[3/4] Проверяем доступность и пинг (всего {len(parsed_data)} шт)...")
    
    # Здесь храним кортежи: (uri, avg_ping)
    all_alive = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_uri = {executor.submit(check_server, uri, hp): uri for uri, hp in parsed_data}
        
        completed = 0
        for future in future_to_uri:
            completed += 1
            if completed % 50 == 0:
                log(f"   ... проверено {completed} из {len(parsed_data)}")
                
            try:
                result_uri, avg_ping = future.result()
                if result_uri:
                    all_alive.append((result_uri, avg_ping))
            except Exception as e:
                log(f"   [ОШИБКА ПОТОКА] {e}")

    log(f"[4/4] Фильтрация и сортировка...")
    log(f"   Всего живых серверов: {len(all_alive)}")
    
    # 1. Сортируем всех живых по возрастанию пинга (самые быстрые в начале)
    all_alive.sort(key=lambda x: x[1])
    
    # 2. Отбираем топ-25 с ограничением в 3 сервера на страну
    final_uris = []
    country_counts = defaultdict(int)
    MAX_PER_COUNTRY = 3
    TARGET_COUNT = 25
    
    for uri, ping in all_alive:
        if len(final_uris) >= TARGET_COUNT:
            break # Набрали 25 штук, останавливаемся
            
        flag = extract_country_flag(uri)
        
        # Если этой страны уже 3 штуки - пропускаем
        if country_counts[flag] >= MAX_PER_COUNTRY:
            continue
            
        # Добавляем сервер
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
