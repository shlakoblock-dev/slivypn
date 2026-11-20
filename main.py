import os
import time
import statistics
import urllib.request
import base64
from pathlib import Path

# Внимание: для работы на GitHub Actions нужна библиотека python-v2ray
# Мы установим её через файл requirements.txt (см. ниже)

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

def main():
    print("Скачиваем конфиги...")
    raw_configs = get_source_configs()
    if not raw_configs:
        print("Нет конфигов!")
        return

    # Импортируем здесь, чтобы не падало, если библиотеки нет
    from python_v2ray.downloader import BinaryDownloader
    from python_v2ray.tester import ConnectionTester
    from python_v2ray.config_parser import parse_uri

    print(f"Найдено {len(raw_configs)} конфигов. Начинаем тест...")
    
    project_root = Path("./")
    downloader = BinaryDownloader(project_root)
    downloader.ensure_all()
    tester = ConnectionTester(
        vendor_path=str(project_root / "vendor"),
        core_engine_path=str(project_root / "core_engine")
    )
    
    # Сопоставляем индексы
    parsed = []
    valid_indices = []
    for i, uri in enumerate(raw_configs):
        p = parse_uri(uri)
        if p:
            parsed.append(p)
            valid_indices.append(i)

    good_uris = []

    # Тестируем каждый сервер (можно поставить 10 пингов для каждого, 
    # но учти, что GitHub Actions может выдать таймаут, если серверов слишком много).
    # Сделаем по 3 пинга для скорости, чтобы уложиться в лимиты.
    for idx, config in zip(valid_indices, parsed):
        pings = []
        successes = 0
        
        for _ in range(3): # Пингуем 3 раза
            try:
                result = tester.test_uris([config])
                if result and result[0].get('ping_ms', -1) > 0:
                    pings.append(result[0]['ping_ms'])
                    successes += 1
            except:
                pass
            time.sleep(0.1)
        
        # Твой фильтр: хотя бы 2 удачных из 3, и средний пинг < 3000
        if successes >= 2 and pings:
            avg = statistics.mean(pings)
            if avg < 3000:
                print(f"[OK] {raw_configs[idx][:30]}... | Пинг: {avg:.0f}ms")
                good_uris.append(raw_configs[idx])
            else:
                print(f"[SLOW] {raw_configs[idx][:30]}... | Пинг: {avg:.0f}ms")
        else:
            print(f"[DEAD] {raw_configs[idx][:30]}...")

    # Сохраняем результат
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(good_uris))
        
    print(f"Готово! Отфильтровано {len(good_uris)} серверов.")

if __name__ == "__main__":
    main()
