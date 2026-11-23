import requests
import re
import socket
import base64
import json
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor
from countryflag.core import CountryFlag

# --- НАСТРОЙКИ ---
URLS = [
    "https://raw.githubusercontent.com/PizdukMod/PizdukVPN/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://raw.githubusercontent.com/s0ulcoil/HavenVPN/refs/heads/main/Haven",
    "https://raw.githubusercontent.com/korol5028/korol-vpn/main/Pohyu.txt"
]
OUTPUT_FILE = "sub.txt"
TIMEOUT = 2.0
BLACKLIST = ["cloudflare", "chatgpt", "openai", "google", "microsoft", "amazon", "aws", "cdn"]

cf = CountryFlag()

# Регулярка для поиска ВСЕХ типов конфигов
PATTERN = r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+|ssr://[^\s]+|hysteria://[^\s]+|hysteria2://[^\s]+|hy2://[^\s]+|tuic://[^\s]+|socks://[^\s]+|http://[^\s]+|https://[^\s]+|wireguard://[^\s]+)'

def fetch_content(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        text = r.text.strip()
        if not any(text.startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria", "tuic", "socks", "http", "wireguard"]):
            try:
                text = base64.b64decode(text + "==").decode('utf-8', errors='ignore')
            except:
                pass
        return text
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return ""

def extract_configs(text):
    return re.findall(PATTERN, text, re.IGNORECASE)

def get_host_port(config):
    try:
        if config.startswith("vmess://"):
            data = json.loads(base64.b64decode(config[8:] + "==").decode('utf-8'))
            return data.get("add"), int(data.get("port", 443))
        elif config.startswith("ssr://"):
            # SSR: ssr://base64(host:port:protocol:method:obfs:pass)
            decoded = base64.b64decode(config[6:] + "==").decode('utf-8', errors='ignore')
            parts = decoded.split(':')
            if len(parts) >= 2:
                return parts[0], int(parts[1])
        elif config.startswith(("wireguard://")):
            # WG: wireguard://...#name
            parsed = urlparse(config)
            return parsed.hostname, parsed.port or 51820
        else:
            # Стандартные URL-схемы (vless, trojan, ss, hysteria2, tuic и т.д.)
            parsed = urlparse(config)
            return parsed.hostname, parsed.port or (443 if parsed.scheme in ['http', 'https', 'vless', 'trojan'] else 80)
    except:
        pass
    return None, None

def check_port(host, port):
    if not host or not port:
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            return sock.connect_ex((host, int(port))) == 0
    except:
        return False

def extract_flags_from_name(name):
    flag_pattern = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
    return flag_pattern.findall(name)

def get_country_name(flag_emoji):
    try:
        pairs = cf.reverse_lookup([flag_emoji])
        if pairs and pairs[0][1]:
            return pairs[0][1]
    except:
        pass
    return None

def process_config(config):
    host, port = get_host_port(config)
    if not host or not port:
        return None

    if any(bad in host.lower() for bad in BLACKLIST):
        return None

    if not check_port(host, port):
        return None

    name = ""
    # Вытаскиваем название для каждого типа
    if config.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(config[8:] + "==").decode('utf-8'))
            name = data.get("ps", "")
        except:
            pass
    elif config.startswith("ssr://"):
        try:
            decoded = base64.b64decode(config[6:] + "==").decode('utf-8', errors='ignore')
            if "?" in decoded:
                params = decoded.split("?")[1]
                # В SSR имя часто в base64 в параметре remarks
                for p in params.split("&"):
                    if p.startswith("remarks="):
                        name = base64.b64decode(p[8:] + "==").decode('utf-8', errors='ignore')
        except:
            pass
    else:
        parsed = urlparse(config)
        name = unquote(parsed.fragment) if parsed.fragment else ""

    flags = extract_flags_from_name(name)
    if not flags:
        return None # Оставляем только те, где есть флаг

    country_names = []
    for f in flags[:2]:
        c_name = get_country_name(f)
        if c_name:
            country_names.append(f"{f} {c_name}")
        else:
            country_names.append(f)

    new_name = " -> ".join(country_names)

    # Сборка конфига обратно
    if config.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(config[8:] + "==").decode('utf-8'))
            data["ps"] = new_name
            return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
        except:
            return None
    elif config.startswith("ssr://"):
        try:
            # Самая сложная замена для SSR (нужно декодить/кодить параметры)
            decoded = base64.b64decode(config[6:] + "==").decode('utf-8', errors='ignore')
            base_part, params = decoded.split("?") if "?" in decoded else (decoded, "")
            new_params = []
            if params:
                for p in params.split("&"):
                    if p.startswith("remarks="):
                        new_params.append("remarks=" + base64.b64encode(new_name.encode()).decode().rstrip("="))
                    else:
                        new_params.append(p)
            new_decoded = base_part + ("?" + "&".join(new_params) if new_params else "")
            return "ssr://" + base64.b64encode(new_decoded.encode()).decode().rstrip("=")
        except:
            return None
    else:
        base_url = config.split('#')[0]
        return f"{base_url}#{new_name}"

def main():
    all_configs = []
    for url in URLS:
        print(f"Загрузка: {url}")
        content = fetch_content(url)
        configs = extract_configs(content)
        print(f"  Найдено конфигов: {len(configs)}")
        all_configs.extend(configs)

    print(f"Всего конфигов до проверки: {len(all_configs)}")
    print("Проверка портов и фильтрация (может занять время)...")

    valid_configs = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(process_config, all_configs)
        for res in results:
            if res:
                valid_configs.append(res)

    print(f"Осталось после фильтрации: {len(valid_configs)}")

    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется. Нажми Обновить.\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for conf in valid_configs:
            f.write(conf + "\n")

    print(f"Готово! Сохранено в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
