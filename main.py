import time
import urllib.request
import base64
import socket
import json
import urllib.parse
import statistics
import re
from concurrent.futures import ThreadPoolExecutor

# --- СЮДА ДОБАВЛЯЙ ССЫЛКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt" # <-- ВСТАВЬ СЮДА ССЫЛКУ НА JSON ОТ АЕТРИС
]
# ----------------------------

OUTPUT_FILE = "sub.txt"

def get_configs_from_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode('utf-8')
            
            # Если это JSON (Aetris)
            if content.strip().startswith("{"):
                print(f"[JSON] Обнаружен JSON от {url}")
                try:
                    json_data = json.loads(content)
                    proxy_out = None
                    if "outbounds" in json_data:
                        proxy_out = next((o for o in json_data["outbounds"] if o.get("protocol") in ["vless", "vmess"]), None)
                    
                    if proxy_out:
                        settings = proxy_out.get("settings", {})
                        stream = proxy_out.get("streamSettings", {})
                        
                        ip = settings.get("address")
                        port = settings.get("port")
                        uid = settings.get("id")
                        
                        # Парсим имя и флаг
                        remarks = json_data.get("remarks", "")
                        flag = ""
                        country = "Сервер"
                        
                        flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', remarks)
                        if flag_match:
                            flag = flag_match.group(0)
                            
                        country_map = {
                            "🇩🇪": "Германия", "🇷🇺": "Россия", "🇺🇸": "США", "🇳🇱": "Нидерланды",
                            "🇫🇮": "Финляндия", "🇸🇪": "Швеция", "🇫🇷": "Франция", "🇬🇧": "Британия",
                            "🇯🇵": "Япония", "🇸🇬": "Сингапур", "🇹🇷": "Турция", "🇵🇱": "Польша",
                            "🇺🇦": "Украина", "🇰🇿": "Казахстан", "🇨🇭": "Швейцария", "🇮🇹": "Италия",
                            "🇦🇹": "Австрия", "🇪🇸": "Испания", "🇨🇦": "Канада", "🇭🇰": "Гонконг",
                            "🇰🇷": "Корея", "🇧🇷": "Бразилия", "🇦🇺": "Австралия", "🇮🇳": "Индия"
                        }
                        
                        if flag in country_map:
                            country = country_map[flag]
                            
                        final_name = f"{flag} {country} [{ip}]".strip()
                        
                        # Собираем URI
                        if proxy_out.get("protocol") == "vless":
                            net = stream.get("network", "tcp")
                            sec = stream.get("security", "none")
                            
                            params = [f"type={net}", f"security={sec}"]
                            
                            if sec == "reality":
                                reality = stream.get("realitySettings", {})
                                if reality.get("serverName"): params.append(f"sni={reality['serverName']}")
                                if reality.get("publicKey"): params.append(f"pbk={reality['publicKey']}")
                                if reality.get("shortId"): params.append(f"sid={reality['shortId']}")
                                if reality.get("fingerprint"): params.append(f"fp={reality['fingerprint']}")
                                
                            if settings.get("flow"):
                                params.append(f"flow={settings['flow']}")
                                
                            uri = f"vless://{uid}@{ip}:{port}?{'&'.join(params)}#{urllib.parse.quote(final_name)}"
                            return [uri]
                except Exception as e:
                    print(f"Ошибка парсинга JSON: {e}")
                    return []
            
            # Если это обычный текст (Пиздюк)
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                if '://' in decoded: content = decoded
            except: pass
            
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
    
    # Фильтр: минимум 3 успеха из 5, средний пинг <= 1000
    if successes >= 4:
        avg_ping = statistics.mean(pings)
        if avg_ping <= 150:
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
        
        completed = 0
        for future in future_to_uri:
            completed += 1
            if completed % 10 == 0:
                print(f"Проверено {completed} из {len(parsed_data)}...")
                
            result_uri, avg_ping = future.result()
            if result_uri:
                good_uris.append(result_uri)

    # --- ФОРМИРУЕМ ФАЙЛ С ЗАГОЛОВКАМИ (БЕЗ BASE64) ---
    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется и чекает пинг. Просто нажми Обновить.\n"
    )

    # Просто склеиваем текст
    full_content = header + "\n".join(good_uris)
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(full_content)
        
    print(f"Готово! {len(good_uris)} серверов записано в открытом виде.")

if __name__ == "__main__":
    main()
