import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
from concurrent.futures import ThreadPoolExecutor

# --- СЮДА ДОБАВЛЯЙ ССЫЛКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
# ----------------------------

OUTPUT_FILE = "sub.txt"

def get_configs_from_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                if '://' in decoded:
                    content = decoded
            except:
                pass
            lines = [line.strip() for line in content.splitlines() if '://' in line]
            return lines
    except Exception as e:
        print(f"[ОШИБКА] {url[:30]}... : {e}")
        return []

def get_all_configs():
    all_configs = set()
    for url in SOURCE_URLS:
        configs = get_configs_from_url(url)
        for c in configs:
            all_configs.add(c)
    return list(all_configs)

def get_host_port(uri):
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            if "?" in b64: b64 = b64.split("?")[0]
            decoded = base64.b64decode(b64 + "==").decode('utf-8')
            data = json.loads(decoded)
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
        with socket.create_connection((host, port), timeout=1.5):
            return (time.time() - start) * 1000
    except:
        return -1

def check_server(uri, host_port):
    pings = []
    successes = 0
    for _ in range(5):
        ping = tcp_ping_once(host_port)
        if ping > 0:
            pings.append(ping)
            successes += 1
        time.sleep(0.05)
    
    if successes >= 4:
        avg_ping = statistics.mean(pings)
        if avg_ping < 3000:
            return uri, avg_ping
    return None, -1

def main():
    print("Скачиваем конфиги...")
    raw_configs = get_all_configs()
    if not raw_configs:
        print("Нет конфигов!")
        return

    parsed_data = []
    for uri in raw_configs:
        hp = get_host_port(uri)
        if hp:
            parsed_data.append((uri, hp))

    print(f"Пингуем {len(parsed_data)} серверов...")
    good_uris = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_uri = {executor.submit(check_server, uri, hp): uri for uri, hp in parsed_data}
        for future in future_to_uri:
            result_uri, avg_ping = future.result()
            if result_uri:
                good_uris.append(result_uri)

    # --- ФОРМИРУЕМ ФАЙЛ С ЗАГОЛОВКАМИ ---
    # Шапка для Happ
    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется и чекает пинг. Просто нажми Обновить.\n"
    )

    # Собираем всё вместе (заголовки + сервера)
    full_content = header + "\n".join(good_uris)
    
    # Конвертируем в Base64 (Happ требует этого для метаданных)
    encoded_content = base64.b64encode(full_content.encode('utf-8')).decode('utf-8')
    
    # Записываем закодированный текст в файл
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(encoded_content)
        
    print(f"Готово! {len(good_uris)} серверов упаковано в Base64.")

if __name__ == "__main__":
    main()
