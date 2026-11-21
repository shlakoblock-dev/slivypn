import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
from concurrent.futures import ThreadPoolExecutor

# --- СЮДА ДОБАВЛЯЙ ССЫЛКИ НА СЫРЫЕ КОНФИГИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    # Добавлена вторая ссылка. Замени на реальную ссылку, если нужна другая.
    # Пример: "https://raw.githubusercontent.com/someuser/somevpnlist/main/sub.txt"
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt" 
]
# ----------------------------------------------

OUTPUT_FILE = "sub.txt"

def get_configs_from_url(url):
    """Скачивает и декодирует конфиги из указанного URL."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        # Увеличиваем таймаут для скачивания, если ссылки медленные
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8', errors='ignore') # Игнорируем ошибки декодирования
            
            # Пытаемся декодировать как base64, если это одна строка, похожая на vmess/vless
            # Проверяем, что это не обычный текстовый файл со множеством строк
            if '\n' not in content.strip() and (content.strip().startswith("vmess://") or content.strip().startswith("vless://")):
                try:
                    # Автоматически добавляем padding '=' если нужно
                    b64_content = content.strip()
                    missing_padding = len(b64_content) % 4
                    if missing_padding:
                        b64_content += '=' * (4 - missing_padding)
                        
                    decoded = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
                    if '://' in decoded:
                        content = decoded # Если декодировалось успешно, используем декодированный текст
                except Exception as e:
                    print(f"[WARN] Не удалось декодировать {url[:30]}... как base64: {e}")
                    # Если ошибка, продолжаем с оригинальным content
            
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
            b64_part = uri[8:].split("?")[0] # Берем часть до '?'
            # Автоматически добавляем padding '=' если нужно
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
            # Если порт не указан, vless по умолчанию использует 443
            if not port:
                port = 443
            return hostname, port
        except Exception: 
            pass
    return None

def tcp_ping_once(host_port):
    """Выполняет один TCP пинг к хосту:порту."""
    if not host_port: return -1
    host, port = host_port
    try:
        start = time.time()
        # Увеличиваем таймаут TCP соединения
        with socket.create_connection((host, port), timeout=2.5) as sock:
            # Можно отправить пустой байт, чтобы убедиться, что соединение активно
            # sock.sendall(b'\n') 
            return (time.time() - start) * 1000 # Возвращаем пинг в миллисекундах
    except (socket.timeout, ConnectionRefusedError, OSError): # Ловим основные ошибки соединения
        return -1
    except Exception: # Ловим любые другие неожиданные ошибки
        return -1

def check_server(uri, host_port):
    """
    Проверяет доступность сервера, выполняя несколько пингов.
    Возвращает URI и средний пинг, если сервер прошел проверку.
    """
    pings = []
    successes = 0
    
    # Выполняем 3 попытки пинга
    for _ in range(5): 
        ping = tcp_ping_once(host_port)
        if ping > 0:
            pings.append(ping)
            successes += 1
        # Небольшая задержка между попытками
        time.sleep(0.1) 
    
    # Условия: >= 2 успешных попыток из 3, и средний пинг < 1000ms
    if successes >= 4: 
        if pings: # Убедимся, что список pings не пуст
            avg_ping = statistics.mean(pings)
            if avg_ping < 250: # Порог среднего пинга
                return uri, avg_ping
    return None, -1

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
            print(f"[WARN] Не удалось распарсить URI: {uri[:70]}...") # Увеличил длину вывода для отладки

    if not parsed_data:
        print("Не удалось распарсить ни одного сервера!")
        return

    print(f"Пингуем {len(parsed_data)} серверов (3 попытки, >=2 успеха, <1000ms средний пинг)...")
    good_uris_with_ping = []
    
    # Используем ThreadPoolExecutor для параллельной проверки
    # max_workers можно настроить, но 60 обычно хорошо работает
    with ThreadPoolExecutor(max_workers=60) as executor: 
        future_to_uri = {executor.submit(check_server, uri, hp): uri for uri, hp in parsed_data}
        
        processed_count = 0
        total_servers = len(parsed_data)
        
        for future in future_to_uri:
            result_uri, avg_ping = future.result()
            if result_uri:
                good_uris_with_ping.append((result_uri, avg_ping))
            
            processed_count += 1
            if processed_count % 50 == 0 or processed_count == total_servers: # Выводим прогресс каждые 50 серверов или в конце
                print(f"Обработано: {processed_count}/{total_servers}")

    # Сортируем по среднему пингу (ascending)
    good_uris_with_ping.sort(key=lambda item: item[1])

    # Извлекаем только URI после сортировки
    good_uris = [item[0] for item in good_uris_with_ping]

    # --- ФОРМИРУЕМ ФАЙЛ С ЗАГОЛОВКАМИ (с русскими и английскими буквами) ---
    # Название "сливы VPN"
    profile_title = "Sлiвы VPN" # Можно добавить больше вариаций, если нужно
    profile_desc = "Подписка автообновляется, проверяет пинг. Просто нажми Обновить и проверь пинг."

    header = (
        f"#profile-title: {profile_title}\n"
        "#profile-update-interval: 1\n"
        f"#profile-desc: {profile_desc}\n"
    )

    full_content = header + "\n".join(good_uris)
    
    # Кодируем весь контент в Base64
    encoded_content = base64.b64encode(full_content.encode('utf-8')).decode('utf-8')
    
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(encoded_content)
        print(f"Готово! {len(good_uris)} серверов упаковано в Base64 и сохранено в {OUTPUT_FILE}.")
    except Exception as e:
        print(f"[ОШИБКА] Не удалось записать в файл {OUTPUT_FILE}: {e}")

if __name__ == "__main__":
    main()
