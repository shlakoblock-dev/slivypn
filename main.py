import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
from concurrent.futures import ThreadPoolExecutor

# --- СЮДА ДОБАВЛЯЙ СВОИ ССЫЛКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    # "https://github.com/другой-ник/другой-репо/raw/main/configs.txt"
]
# --------------------------------

OUTPUT_FILE = "sub.txt"

def get_configs_from_url(url):
    """Скачивает и парсит один источник"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            
            # Пытаемся раскодировать base64, если это подписка
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                if '://' in decoded:
                    content = decoded
            except:
                pass
            
            # Ищем только строки с конфигами
            lines = [line.strip() for line in content.splitlines() if '://' in line]
            print(f"[{url[:30]}...] Найдено {len(lines)} конфигов.")
            return lines
    except Exception as e:
        print(f"[ОШИБКА] Не удалось скачать {url[:30]}... : {e}")
        return []

def get_all_configs():
    """Собирает конфиги со всех источников в один список (без дублей)"""
    all_configs = set() # set автоматически убирает дубликаты
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
    if not host_port:
        return -1
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
    print("Скачиваем конфиги со всех источников...")
    raw_configs = get_all_configs()
    if not raw_configs:
        print("Нет конфигов! Проверь ссылки в SOURCE_URLS.")
        return

    print(f"\nВсего уникальных конфигов: {len(raw_configs)}. Извлекаем IP и порты...")
    
    parsed_data = []
    for uri in raw_configs:
        hp = get_host_port(uri)
        if hp:
            parsed_data.append((uri, hp))

    print(f"Запускаем 5-кратный параллельный пинг для {len(parsed_data)} серверов...\n")
    
    good_uris = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_uri = {executor.submit(check_server, uri, hp): uri for uri, hp in parsed_data}
        
        completed = 0
        for future in future_to_uri:
            uri = future_to_uri[future]
            completed += 1
            
            if completed % 10 == 0 or completed == len(parsed_data):
                print(f"Проверено {completed} из {len(parsed_data)}...")
                
            try:
                result_uri, avg_ping = future.result()
                if result_uri:
                    print(f"[OK] {result_uri[:30]}... | Средний пинг: {avg_ping:.0f}ms")
                    good_uris.append(result_uri)
            except Exception:
                pass

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(good_uris))
        
    print(f"\nГотово! Отфильтровано {len(good_uris)} серверов. Записано в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
