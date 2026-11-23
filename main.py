import requests
import re
import socket
import base64
import json
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
URLS = [
    "https://raw.githubusercontent.com/PizdukMod/PizdukVPN/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://raw.githubusercontent.com/s0ulcoil/HavenVPN/refs/heads/main/Haven",
    "https://raw.githubusercontent.com/korol5028/korol-vpn/main/Pohyu.txt",
    "https://raw.githubusercontent.com/Buffetbarko/Universal-Proxy-Config-Parser-/main/whitelist_vpn.txt"
]
OUTPUT_FILE = "sub.txt"
TIMEOUT = 2.0
BLACKLIST = ["cloudflare", "chatgpt", "openai", "google", "microsoft", "amazon", "aws", "cdn"]

# ОГРОМНЫЙ СЛОВАРЬ СТРАН (Флаг: Название)
COUNTRY_NAMES = {
    "🇷🇺": "Россия", "🇺🇸": "США", "🇩🇪": "Германия", "🇳🇱": "Нидерланды", "🇫🇷": "Франция",
    "🇬🇧": "Великобритания", "🇯🇵": "Япония", "🇰🇷": "Корея", "🇨🇳": "Китай", "🇭🇰": "Гонконг",
    "🇸🇬": "Сингапур", "🇨🇦": "Канада", "🇦🇺": "Австралия", "🇧🇷": "Бразилия", "🇮🇳": "Индия",
    "🇹🇷": "Турция", "🇮🇹": "Италия", "🇪🇸": "Испания", "🇵🇱": "Польша", "🇺🇦": "Украина",
    "🇰🇿": "Казахстан", "🇧🇾": "Беларусь", "🇫🇮": "Финляндия", "🇸🇪": "Швеция", "🇳🇴": "Норвегия",
    "🇩🇰": "Дания", "🇨🇭": "Швейцария", "🇦🇹": "Австрия", "🇧🇪": "Бельгия", "🇮🇪": "Ирландия",
    "🇵🇹": "Португалия", "🇬🇷": "Греция", "🇨🇿": "Чехия", "🇸🇰": "Словакия", "🇭🇺": "Венгрия",
    "🇷🇴": "Румыния", "🇧🇬": "Болгария", "🇷🇸": "Сербия", "🇭🇷": "Хорватия", "🇸🇮": "Словения",
    "🇪🇪": "Эстония", "🇱🇻": "Латвия", "🇱🇹": "Литва", "🇲🇩": "Молдова", "🇬🇪": "Грузия",
    "🇦🇲": "Армения", "🇦🇿": "Азербайджан", "🇺🇿": "Узбекистан", "🇰🇬": "Киргизия", "🇹🇯": "Таджикистан",
    "🇹🇲": "Туркменистан", "🇲🇳": "Монголия", "🇻🇳": "Вьетнам", "🇹🇭": "Таиланд", "🇮🇩": "Индонезия",
    "🇲🇾": "Малайзия", "🇵🇭": "Филиппины", "🇵🇰": "Пакистан", "🇧🇩": "Бангладеш", "🇱🇰": "Шри-Ланка",
    "🇳🇵": "Непал", "🇦🇫": "Афганистан", "🇮🇷": "Иран", "🇮🇶": "Ирак", "🇸🇾": "Сирия",
    "🇱🇧": "Ливан", "🇮🇱": "Израиль", "🇯🇴": "Иордания", "🇸🇦": "Саудовская Аравия", "🇦🇪": "ОАЭ",
    "🇶🇦": "Катар", "🇰🇼": "Кувейт", "🇧🇭": "Бахрейн", "🇴🇲": "Оман", "🇾🇪": "Йемен",
    "🇪🇬": "Египет", "🇲🇦": "Марокко", "🇩🇿": "Алжир", "🇹🇳": "Тунис", "🇱🇾": "Ливия",
    "🇸🇩": "Судан", "🇪🇹": "Эфиопия", "🇰🇪": "Кения", "🇳🇬": "Нигерия", "🇬🇭": "Гана",
    "🇿🇦": "ЮАР", "🇦🇷": "Аргентина", "🇨🇱": "Чили", "🇨🇴": "Колумбия", "🇵🇪": "Перу",
    "🇻🇪": "Венесуэла", "🇪🇨": "Эквадор", "🇺🇾": "Уругвай", "🇵🇾": "Парагвай", "🇧🇴": "Боливия",
    "🇲🇽": "Мексика", "🇨🇺": "Куба", "🇩🇴": "Доминикана", "🇵🇦": "Панама", "🇨🇷": "Коста-Рика",
    "🇬🇹": "Гватемала", "🇭🇳": "Гондурас", "🇸🇻": "Сальвадор", "🇳🇮": "Никарагуа", "🇭🇹": "Гаити",
    "🇯🇲": "Ямайка", "🇹🇹": "Тринидад и Тобаго", "🇧🇸": "Багамы", "🇧🇧": "Барбадос", "🇧🇿": "Белиз",
    "🇳🇿": "Новая Зеландия", "🇫🇯": "Фиджи", "🇵🇬": "Папуа-Новая Гвинея", "🇸🇧": "Соломоновы о-ва",
    "🇻🇺": "Вануату", "🇼🇸": "Самоа", "🇹🇴": "Тонга", "🇰🇮": "Кирибати", "🇲🇭": "Маршалловы о-ва",
    "🇫🇲": "Микронезия", "🇵🇼": "Палау", "🇳🇷": "Науру", "🇹🇻": "Тувалу", "🇨🇰": "О-ва Кука",
    "🇳🇺": "Ниуэ", "🇵🇳": "Питкэрн", "🇹🇰": "Токелау", "🇪🇺": "Евросоюз", "🇺🇳": "ООН"
}

PATTERN = r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+|ssr://[^\s]+|hysteria://[^\s]+|hysteria2://[^\s]+|hy2://[^\s]+|tuic://[^\s]+|socks://[^\s]+|http://[^\s]+|https://[^\s]+|wireguard://[^\s]+)'

def fetch_content(url):
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        text = r.text.strip()
        configs = re.findall(PATTERN, text, re.IGNORECASE)
        if configs:
            return text
        
        try:
            decoded = base64.b64decode(text + "==").decode('utf-8', errors='ignore')
            return decoded
        except:
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
            decoded = base64.b64decode(config[6:] + "==").decode('utf-8', errors='ignore')
            parts = decoded.split(':')
            if len(parts) >= 2:
                return parts[0], int(parts[1])
        elif config.startswith(("wireguard://")):
            parsed = urlparse(config)
            return parsed.hostname, parsed.port or 51820
        else:
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
    # Берем из нашего словаря, если нет — оставляем только флаг
    return COUNTRY_NAMES.get(flag_emoji, None)

def process_config(config):
    host, port = get_host_port(config)
    if not host or not port:
        return None

    if any(bad in host.lower() for bad in BLACKLIST):
        return None

    if not check_port(host, port):
        return None

    name = ""
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
        return None

    country_names = []
    for f in flags[:2]:
        c_name = get_country_name(f)
        if c_name:
            country_names.append(f"{f} {c_name}")
        else:
            country_names.append(f) # Если страны нет в словаре, просто флаг

    new_name = " -> ".join(country_names)

    if config.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(config[8:] + "==").decode('utf-8'))
            data["ps"] = new_name
            return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
        except:
            return None
    elif config.startswith("ssr://"):
        try:
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
    print("Проверка портов и фильтрация...")

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
