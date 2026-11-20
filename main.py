import os
import time
import urllib.request
import base64
import socket
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import statistics

SOURCE_URL = "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub"
OUTPUT_FILE = "sub.txt"

def get_source_configs():
    try:
        req = urllib.request.Request(SOURCE_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                if '://' in decoded:
                    content = decoded
            except:
                pass
            return [line.strip() for line in content.splitlines() if '://' in line]
    except Exception as e:
        print(f"Ошибка скачивания: {e}")
        return []

def get_host_port(uri):
    """Вытаскиваем IP и порт из ссылки"""
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

def tcp_ping(host_port):
    """Проверка открыт ли порт (TCP Handshake)"""
    if not host_port:
        return -1
    host, port = host_port
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=1.5):
            return (time.time() - start) * 1000
    except:
        return -1

def main():
    print("--- ЭТАП 1: Быстрый TCP-тест ---")
    raw_configs = get_source_configs()
    if not raw_configs:
        return

    parsed_data = []
    for uri in raw_configs:
        hp = get_host_port(uri)
        if hp:
            parsed_data.append((uri, hp))

    print(f"Всего серверов: {len(parsed_data)}. Проверяем порты...")
    
    alive_data = []
    # Проверяем TCP параллельно в 50 потоков
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_data = {executor.submit(tcp_ping, hp): (uri, hp) for uri, hp in parsed_data}
        for future in future_to_data:
            uri, hp = future_to_data[future]
            ping = future.result()
            if ping > 0 and ping < 2000: # Порт открыт и отвечает быстро
                alive_data.append((uri, ping))

    print(f"Порты открыты у {len(alive_data)} серверов.")

    # Сортируем по TCP-пингу (самые быстрые в начале)
    alive_data.sort(key=lambda x: x[1])
    
    # Берем топ-100 самых быстрых, чтобы python-v2ray не сдох по таймауту
    top_alive = alive_data[:100]
    top_uris = [data[0] for data in top_alive]

    print(f"\n--- ЭТАП 2: Точный пинг через Xray (Топ-{len(top_uris)}) ---")
    
    # Импортируем тяжелые библиотеки только сейчас
    from python_v2ray.downloader import BinaryDownloader
    from python_v2ray.tester import ConnectionTester
    from python_v2ray.config_parser import parse_uri

    project_root = Path("./")
    downloader = BinaryDownloader(project_root)
    downloader.ensure_all()
    
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine")
    )

    parsed_configs = [parse_uri(uri) for uri in top_uris]
    parsed_configs = [p for p in parsed_configs if p]

    good_uris = []
    
    # Тестируем пачкой (python-v2ray умеет тестировать список)
    try:
        results = tester.test_uris(parsed_configs)
        
        # Сопоставляем результаты с URI
        for i, res in enumerate(results):
            if i >= len(top_uris): break
            
            real_ping = res.get('ping_ms', -1)
            if real_ping > 0 and real_ping < 3000:
                print(f"[OK] {top_uris[i][:30]}... | TCP: {top_alive[i][1]:.0f}ms | Real: {real_ping:.0f}ms")
                good_uris.append(top_uris[i])
            else:
                print(f"[DEAD] {top_uris[i][:30]}... | Real Ping не прошел")
                
    except Exception as e:
        print(f"Ошибка при точном тесте: {e}")
        # Если Xray упал, берем хотя бы те, что прошли TCP
        good_uris = top_uris

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(good_uris))
        
    print(f"\nГотово! В итоговый файл записано {len(good_uris)} серверов.")

if __name__ == "__main__":
    main()
