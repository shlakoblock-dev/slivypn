import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# --- СЮДА ДОБАВЛЯЙ ССЫЛКИ НА СЫРЫЕ КОНФИГИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
# ----------------------------------------------

OUTPUT_FILE = "sub.txt"

# --- Параметры проверки ---
INITIAL_PING_ATTEMPTS = 3
INITIAL_SUCCESS_THRESHOLD = 2
INITIAL_PING_THRESHOLD_MS = 1000
INITIAL_TIMEOUT_SEC = 2.5

FINAL_PING_ATTEMPTS = 5
FINAL_SUCCESS_THRESHOLD = 4
FINAL_PING_THRESHOLD_MS = 200
FINAL_TIMEOUT_SEC = 1.5

TOP_N_SERVERS_TO_RECHECK = 20 # Увеличим пул для финальной проверки, чтобы было из чего выбирать до 10
MAX_OUTPUT_SERVERS = 10       # Максимальное количество серверов на выходе
# --------------------------


def get_configs_from_url(url):
    """Скачивает и декодирует конфиги из указанного URL."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore')
            
            if '\n' not in content.strip() and (content.strip().startswith("vmess://") or content.strip().startswith("vless://")):
                try:
                    b64_content = content.strip()
                    missing_padding = len(b64_content) % 4
                    if missing_padding:
                        b64_content += '=' * (4 - missing_padding)
                        
                    decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                    if '://' in decoded:
                        content = decoded
                except Exception as e:
                    print(f"[WARN] Не удалось декодировать {url[:30]}... как base64: {e}")
            
            lines = [line.strip() for line in content.splitlines() if '://' in line]
            return lines
    except Exception as e:
        print(f"[ОШИБКА] Не удалось скачать {url[:30]}... : {e}")
        return []

def get_all_configs():
    """Собирает все уникальные конфиги из всех указанных URL."""
    all_configs = set()
    print(f"Скачиваем конфиги из {len(SOURCE_URLS)} источников...")
    for url in SOURCE_URLS:
        configs = get_configs_from_url(url)
        print(f"[FETCH] Из {url} получено {len(configs)} строк.")
        for c in configs:
            all_configs.add(c)
    return list(all_configs)

def get_host_port(uri):
    """Извлекает хост и порт из URI (vmess, vless)."""
    if uri.startswith("vmess://"):
        try:
            b64_part = uri[8:].split("?")[0]
            missing_padding = len(b64_part) % 4
            if missing_padding:
                b64_part += '=' * (4 - missing_padding)
            
            decoded = base64.b64decode(b64_part).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            return data.get("add"), int(data.get("port"))
        except Exception: 
            return None
    elif uri.startswith("vless://"):
        try:
            parsed = urllib.parse.urlparse(uri)
            hostname = parsed.hostname
            port = parsed.port
            if not port:
                port = 443
            return hostname, port
        except Exception: 
            pass
    return None

def tcp_ping_once(host_port, timeout=INITIAL_TIMEOUT_SEC):
    """Выполняет один TCP пинг к хосту:порту."""
    if not host_port: return -1
    host, port = host_port
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            return (time.time() - start) * 1000 # Возвращаем пинг в миллисекундах
    except (socket.timeout, ConnectionRefusedError, OSError): 
        return -1
    except Exception: 
        return -1

def check_server(uri, host_port, attempts, success_threshold, ping_threshold, timeout):
    """
    Проверяет доступность сервера, выполняя несколько пингов.
    Возвращает URI, средний пинг, и список всех успешных пингов, если сервер прошел проверку.
    """
    pings = []
    successes = 0
    
    for _ in range(attempts): 
        ping = tcp_ping_once(host_port, timeout=timeout)
        if ping > 0:
            pings.append(ping)
            successes += 1
        time.sleep(0.1) 
    
    if successes >= success_threshold: 
        if pings: 
            avg_ping = statistics.mean(pings)
            if avg_ping < ping_threshold: 
                return uri, avg_ping, pings
    return None, -1, []

def initial_check(parsed_data, executor):
    """Выполняет начальную проверку серверов."""
    print(f"Начальная проверка {len(parsed_data)} серверов...")
    futures = {executor.submit(check_server, uri, hp, 
                               INITIAL_PING_ATTEMPTS, INITIAL_SUCCESS_THRESHOLD, 
                               INITIAL_PING_THRESHOLD_MS, INITIAL_TIMEOUT_SEC): uri 
               for uri, hp in parsed_data}
    
    initial_good_servers = []
    processed_count = 0
    total_servers = len(parsed_data)

    for future in as_completed(futures):
        uri = futures[future]
        try:
            result_uri, avg_ping, _ = future.result()
            if result_uri:
                initial_good_servers.append((result_uri, avg_ping))
        except Exception as exc:
            print(f'[ERROR] {uri[:70]}... сгенерировал исключение: {exc}')
        
        processed_count += 1
        if processed_count % 50 == 0 or processed_count == total_servers:
            print(f"  Проверено: {processed_count}/{total_servers} (Найдено рабочих: {len(initial_good_servers)})")
            sys.stdout.flush() 

    initial_good_servers.sort(key=lambda item: item[1]) # Сортируем по среднему пингу
    return initial_good_servers

def final_check(servers_to_recheck, executor):
    """Выполняет финальную, более строгую проверку выбранных серверов."""
    if not servers_to_recheck:
        return []
        
    print(f"\nФинальная проверка {len(servers_to_recheck)} лучших серверов...")
    futures = {executor.submit(check_server, uri, hp, 
                               FINAL_PING_ATTEMPTS, FINAL_SUCCESS_THRESHOLD, 
                               FINAL_PING_THRESHOLD_MS, FINAL_TIMEOUT_SEC): uri 
               for uri, hp in servers_to_recheck}

    final_good_servers = []
    processed_count = 0
    total_servers = len(servers_to_recheck)

    for future in as_completed(futures):
        uri = futures[future]
        try:
            result_uri, avg_ping, _ = future.result()
            if result_uri:
                final_good_servers.append((result_uri, avg_ping))
        except Exception as exc:
            print(f'[ERROR] {uri[:70]}... сгенерировал исключение: {exc}')
        
        processed_count += 1
        if processed_count % 10 == 0 or processed_count == total_servers:
            print(f"  Проверено: {processed_count}/{total_servers} (Найдено рабочих: {len(final_good_servers)})")
            sys.stdout.flush()

    final_good_servers.sort(key=lambda item: item[1]) # Сортируем по среднему пингу
    return final_good_servers

def main():
    """Основная функция: собирает, парсит, пингует и сохраняет рабочие серверы."""
    raw_configs = get_all_configs()
    if not raw_configs:
        print("Нет конфигов для обработки!")
        return

    parsed_data = []
    print("Парсим адреса и порты...")
    for uri in raw_configs:
        hp = get_host_port(uri)
        if hp:
            parsed_data.append((uri, hp))
        else:
            print(f"[WARN] Не удалось распарсить URI: {uri[:70]}...")

    if not parsed_data:
        print("Не удалось распарсить ни одного сервера!")
        return

    good_uris_with_ping = []
    
    with ThreadPoolExecutor(max_workers=60) as executor: 
        # 1. Начальная проверка
        initial_results = initial_check(parsed_data, executor)
        
        # 2. Выбираем ТОП N серверов для финальной проверки
        # Увеличил TOP_N_SERVERS_TO_RECHECK, чтобы было из чего выбирать до MAX_OUTPUT_SERVERS
        servers_for_final_check = initial_results[:TOP_N_SERVERS_TO_RECHECK]
        
        # 3. Финальная проверка
        final_results = final_check(servers_for_final_check, executor)
        
        # 4. Берем ТОП M из финально проверенных, но не более MAX_OUTPUT_SERVERS
        good_uris_with_ping = final_results[:MAX_OUTPUT_SERVERS]

    # --- ФОРМИРУЕМ ФАЙЛ С ЗАГОЛОВКАМИ ---
    profile_title = "Sliwy VPN"
    profile_desc = "Подписка автообновляется, проверяет пинг. Просто нажми Обновить и проверь пинг."

    header = (
        f"#profile-title: {profile_title}\n"
        "#profile-update-interval: 1\n"
        f"#profile-desc: {profile_desc}\n"
    )

    # Извлекаем только URI после сортировки
    good_uris = [item[0] for item in good_uris_with_ping]
    
    full_content = header + "\n".join(good_uris)
    
    # Кодируем весь контент в Base64
    encoded_content = base64.b64encode(full_content.encode('utf-8')).decode('utf-8')
    
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(encoded_content)
        print(f"\nГотово! {len(good_uris)} лучших серверов упаковано в Base64 и сохранено в {OUTPUT_FILE}.")
        print(f"Найдено {len(good_uris)} серверов после строгой проверки (максимум {MAX_OUTPUT_SERVERS}).")
    except Exception as e:
        print(f"[ОШИБКА] Не удалось записать в файл {OUTPUT_FILE}: {e}")

if __name__ == "__main__":
    main()
