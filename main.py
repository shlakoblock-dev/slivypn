import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path

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

# --- БЛОК ПОДСЕТЕЙ CLOUDFLARE ---
BAD_PREFIXES = [
    "104.", "172.6", "172.7", "188.114.", "141.101.", "141.193.", 
    "162.158.", "198.41.", "190.93.", "197.234.", "108.162.", 
    "131.0.72.", "103.21.", "103.22.", "103.31.", "173.245."
]

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

def main():
    log("="*40)
    log("[START] Начинаем процесс обновления подписки")
    log("="*40)
    
    log("[1/4] Скачиваем конфиги...")
    raw_configs = get_all_configs()
    if not raw_configs:
        log("[ERROR] Не удалось скачать ни одного конфига.")
        return

    log(f"[2/4] Быстрый TCP-отсев и фильтр Cloudflare...")
    tcp_alive = []
    for uri in raw_configs:
        if not (uri.startswith("vless://") or uri.startswith("vmess://")):
            continue
            
        hp = get_host_port(uri)
        if not hp: continue
        
        host = hp[0]
        # Выкидываем Cloudflare
        is_bad = False
        for bad in BAD_PREFIXES:
            if host.startswith(bad):
                is_bad = True
                break
        if is_bad: continue
            
        if tcp_ping_once(hp) > 0:
            tcp_alive.append(uri)
    
    log(f"   Осталось после фильтров: {len(tcp_alive)} серверов.")

    if not tcp_alive:
        log("[ERROR] Ни один сервер не прошел проверку.")
        return

    log(f"[3/4] Запускаем РЕАЛЬНЫЙ Xray-тест (через gstatic.com)...")
    
    try:
        from python_v2ray.downloader import BinaryDownloader
        from python_v2ray.tester import ConnectionTester
        from python_v2ray.config_parser import parse_uri
    except ImportError:
        log("[ERROR] Библиотека python-v2ray не установлена. Добавь 'python-v2ray' в requirements.txt")
        return

    project_root = Path("./")
    downloader = BinaryDownloader(project_root)
    downloader.ensure_all()

    # ВАЖНО: Указываем тестовый URL как в Happ!
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine"),
        test_url="https://www.gstatic.com/generate_204" # <--- ВОТ ОНО
    )

    parsed_data = []
    for uri in tcp_alive:
        p = parse_uri(uri)
        if p:
            parsed_data.append((uri, p))

    all_alive = []
    chunk_size = 10 # Проверяем по 10 штук, чтобы не вешать систему
    
    for i in range(0, len(parsed_data), chunk_size):
        chunk = parsed_data[i:i + chunk_size]
        uris = [x[0] for x in chunk]
        configs = [x[1] for x in chunk]
        
        try:
            results = tester.test_uris(configs)
            if results:
                for j, res in enumerate(results):
                    if res.get('status') == 'success' and res.get('ping_ms', -1) > 0:
                        all_alive.append((uris[j], res['ping_ms']))
        except Exception:
            # Если Xray подавился этой пачкой (таймаут или битый конфиг), пропускаем
            pass
            
        time.sleep(0.5)

    log(f"   Xray подтвердил работу {len(all_alive)} серверов.")

    # --- ЭТАП 4: ФИЛЬТРАЦИЯ И СОРТИРОВКА ---
    log(f"[4/4] Фильтрация и сортировка...")
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
        log(f"   [В СПИСКЕ] {name} | Реальный пинг: {ping:.0f}ms")

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
