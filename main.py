import time
import urllib.request
import base64
import json
import urllib.parse
import re
import sys
import os
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ИСТОЧНИКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
OUTPUT_FILE = "sub.txt"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v1.8.13/Xray-linux-64.zip"
TEST_URL = "https://www.gstatic.com/generate_204"

MAX_SERVERS       = 20      # сколько серверов оставить в итоге
PER_COUNTRY_LIMIT = 3       # макс. серверов на одну страну
TEST_TIMEOUT      = 5       # сек на один сервер
MAX_WORKERS       = 50      # параллельных тестов
BASE_PORT         = 20000

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

BAD_PREFIXES = ["104.", "172.6", "172.7", "188.114.", "141.101.", "141.193.", "162.158.", "198.41."]
FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')


def log(msg):
    print(msg, flush=True)


# ---------- helpers ----------

def b64decode_any(s: str) -> bytes:
    """base64 + urlsafe + padding fix."""
    s = s.strip().replace('-', '+').replace('_', '/')
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def get_host(uri: str) -> str:
    if uri.startswith(("vless://", "trojan://", "ss://")):
        try:
            return urllib.parse.urlparse(uri).hostname or ""
        except Exception:
            return ""
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            if "?" in b64:
                b64 = b64.split("?", 1)[0]
            data = json.loads(b64decode_any(b64).decode("utf-8"))
            return data.get("add", "")
        except Exception:
            return ""
    return ""


def get_configs_from_url(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8")
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                if "://" in decoded:
                    content = decoded
            except Exception:
                pass
            return [line.strip() for line in content.splitlines() if "://" in line]
    except Exception as e:
        log(f"[ОШИБКА ИСТОЧНИКА] {url[:40]}... : {e}")
        return []


def rename_server(uri: str) -> str:
    parts = uri.split("#", 1)
    host = get_host(uri)
    original = ""
    if len(parts) > 1:
        try:
            original = urllib.parse.unquote(parts[1])
        except Exception:
            original = ""

    flag_match = FLAG_RE.search(original)
    if flag_match:
        flag = flag_match.group(0)
        country = COUNTRY_MAP.get(flag, "Неизвестно")
        new_name = f"{flag} {country} [{host}]"
    elif original.strip():
        new_name = f"🌍 {original.strip()[:40]} [{host}]"
    else:
        new_name = f"🌍 Неизвестно [{host}]"
    return parts[0] + "#" + urllib.parse.quote(new_name)


# ---------- URI -> Xray outbound ----------

def parse_uri_to_xray(uri: str):
    try:
        if uri.startswith("vless://"):
            return _parse_vless(uri)
        if uri.startswith("vmess://"):
            return _parse_vmess(uri)
    except Exception:
        return None
    return None


def _parse_vless(uri: str):
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query)

    net = params.get("type", ["tcp"])[0]
    sec = params.get("security", ["none"])[0]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": parsed.username,
                    "encryption": "none",
                    "flow": params.get("flow", [""])[0],
                }],
            }]
        },
        "streamSettings": {"network": net},
    }
    stream = outbound["streamSettings"]

    # --- security ---
    if sec == "tls":
        tls = {"serverName": params.get("sni", [parsed.hostname])[0]}
        if "alpn" in params:
            tls["alpn"] = params["alpn"][0].split(",")
        if params.get("fp", [""])[0]:
            tls["fingerprint"] = params["fp"][0]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "publicKey":   params.get("pbk", [""])[0],
            "fingerprint": params.get("fp", ["chrome"])[0],
            "serverName":  params.get("sni", [""])[0],
            "shortId":     params.get("sid", [""])[0],
            "spiderX":     params.get("spx", ["/"])[0],
        }

    # --- transport ---
    if net == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": params.get("host", [parsed.hostname])[0]},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0],
            "multiMode": params.get("mode", [""])[0] == "multi",
        }
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "path": params.get("path", ["/"])[0],
            "host": params.get("host", [parsed.hostname])[0].split(","),
        }
    elif net == "tcp" and params.get("headerType", [""])[0] == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [params.get("path", ["/"])[0]],
                    "headers": {"Host": [params.get("host", [parsed.hostname])[0]]},
                },
            }
        }

    return outbound


def _parse_vmess(uri: str):
    b64 = uri[8:]
    if "?" in b64:
        b64 = b64.split("?", 1)[0]
    data = json.loads(b64decode_any(b64).decode("utf-8"))

    net = data.get("net", "tcp")
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{
                    "id": data["id"],
                    "alterId": int(data.get("aid", data.get("alterId", 0))),
                    "security": data.get("scy", data.get("security", "auto")),
                }],
            }]
        },
        "streamSettings": {"network": net},
    }
    stream = outbound["streamSettings"]

    if data.get("tls") == "tls":
        stream["security"] = "tls"
        tls = {"serverName": data.get("sni", "") or data.get("host", "")}
        if data.get("alpn"):
            tls["alpn"] = data["alpn"].split(",") if isinstance(data["alpn"], str) else data["alpn"]
        if data.get("fp"):
            tls["fingerprint"] = data["fp"]
        stream["tlsSettings"] = tls

    if net == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", "")},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", "")}
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "path": data.get("path", "/"),
            "host": [h.strip() for h in data.get("host", "").split(",") if h.strip()],
        }
    elif net == "tcp" and data.get("type") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [data.get("path", "/")],
                    "headers": {"Host": [data.get("host", "")]},
                },
            }
        }

    return outbound


# ---------- main ----------

def ensure_xray() -> str:
    log("Скачиваем и готовим Xray...")
    os.makedirs("xray_bin", exist_ok=True)
    xray_bin = os.path.join("xray_bin", "xray")
    xray_zip = "xray.zip"

    if not os.path.exists(xray_bin):
        if not os.path.exists(xray_zip):
            urllib.request.urlretrieve(XRAY_URL, xray_zip)
        with zipfile.ZipFile(xray_zip, "r") as z:
            z.extractall("xray_bin")

    os.chmod(xray_bin, 0o755)
    return xray_bin


def test_port(uri: str, port: int):
    try:
        proxies = {
            "http":  f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        start = time.time()
        r = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TEST_TIMEOUT,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False,
        )
        try:
            elapsed = (time.time() - start) * 1000
            if r.status_code == 204:
                return uri, elapsed
        finally:
            r.close()
    except Exception:
        pass
    return None, -1


def main():
    xray_bin = ensure_xray()

    # 1) Загрузка и фильтрация
    raw_configs = []
    for url in SOURCE_URLS:
        raw_configs.extend(get_configs_from_url(url))

    filtered = [
        rename_server(c) for c in raw_configs
        if c.startswith(("vless://", "vmess://"))
    ]
    log(f"Всего серверов: {len(filtered)}")

    # 2) Сборка Xray-конфига
    inbounds, outbounds, rules, valid_uris = [], [], [], []
    for uri in filtered:
        host = get_host(uri)
        if host and any(host.startswith(b) for b in BAD_PREFIXES):
            continue

        out = parse_uri_to_xray(uri)
        if not out:
            continue

        port = BASE_PORT + len(valid_uris)
        out["tag"] = f"proxy_{port}"
        outbounds.append(out)

        inbounds.append({
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "tag": f"socks_{port}",
            "settings": {"auth": "noauth", "udp": False},
        })
        rules.append({
            "type": "field",
            "inboundTag": [f"socks_{port}"],
            "outboundTag": f"proxy_{port}",
        })
        valid_uris.append(uri)

    log(f"Подготовлено конфигов: {len(valid_uris)}")
    if not valid_uris:
        log("Нет валидных серверов — выходим.")
        return

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": rules},
    }
    with open("xray_config.json", "w") as f:
        json.dump(config, f)

    # 3) Запуск Xray и тестирование
    log("Запускаем Xray...")
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", "xray_config.json"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
import time
import urllib.request
import base64
import json
import urllib.parse
import re
import sys
import os
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- ИСТОЧНИКИ ---
SOURCE_URLS = [
    "https://github.com/PizdukMod/PizdukVPN/raw/refs/heads/main/sub",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt"
]
OUTPUT_FILE = "sub.txt"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v1.8.13/Xray-linux-64.zip"
TEST_URL = "https://www.gstatic.com/generate_204"

MAX_SERVERS        = 20
PER_COUNTRY_LIMIT  = 3
TEST_TIMEOUT       = 8       # увеличил с 5 до 8 — на медленных серверах может не хватать
MAX_WORKERS        = 20      # уменьшил с 50 до 20 — 384 порта одновременно могут перегрузить сеть
BASE_PORT          = 20000
DEBUG              = True    # <-- главный рубильник подробных логов

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

BAD_PREFIXES = ["104.", "172.6", "172.7", "188.114.", "141.101.", "141.193.", "162.158.", "198.41."]
FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

_stats = {
    "parse_fail": 0,
    "bad_prefix": 0,
    "test_ok": 0,
    "test_timeout": 0,
    "test_conn_err": 0,
    "test_proxy_err": 0,
    "test_other": 0,
}


def log(msg, level="INFO"):
    prefix = {"INFO": "", "DEBUG": "[dbg] ", "WARN": "⚠️  ", "ERR": "❌ "}.get(level, "")
    print(f"{prefix}{msg}", flush=True)


def dbg(msg):
    if DEBUG:
        log(msg, "DEBUG")


# ---------- helpers ----------

def b64decode_any(s: str) -> bytes:
    s = s.strip().replace('-', '+').replace('_', '/')
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def get_host(uri: str) -> str:
    if uri.startswith(("vless://", "trojan://", "ss://")):
        try:
            return urllib.parse.urlparse(uri).hostname or ""
        except Exception:
            return ""
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:]
            if "?" in b64:
                b64 = b64.split("?", 1)[0]
            data = json.loads(b64decode_any(b64).decode("utf-8"))
            return data.get("add", "")
        except Exception:
            return ""
    return ""


def get_configs_from_url(url):
    log(f"→ Загружаем источник: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8")
            raw_len = len(content)
            dbg(f"    получено {raw_len} байт")
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                if "://" in decoded:
                    content = decoded
                    dbg(f"    содержимое было base64 — распаковано в {len(content)} байт")
            except Exception:
                pass
            lines = [line.strip() for line in content.splitlines() if "://" in line]
            log(f"    ✓ извлечено {len(lines)} URI")
            return lines
    except Exception as e:
        log(f"[ОШИБКА ИСТОЧНИКА] {url[:60]}... : {e}", "ERR")
        return []


def rename_server(uri: str) -> str:
    parts = uri.split("#", 1)
    host = get_host(uri)
    original = ""
    if len(parts) > 1:
        try:
            original = urllib.parse.unquote(parts[1])
        except Exception:
            pass

    flag_match = FLAG_RE.search(original)
    if flag_match:
        flag = flag_match.group(0)
        country = COUNTRY_MAP.get(flag, "Неизвестно")
        new_name = f"{flag} {country} [{host}]"
    elif original.strip():
        new_name = f"🌍 {original.strip()[:40]} [{host}]"
    else:
        new_name = f"🌍 Неизвестно [{host}]"
    return parts[0] + "#" + urllib.parse.quote(new_name)


# ---------- URI -> Xray outbound ----------

def parse_uri_to_xray(uri: str):
    try:
        if uri.startswith("vless://"):
            return _parse_vless(uri)
        if uri.startswith("vmess://"):
            return _parse_vmess(uri)
    except Exception as e:
        _stats["parse_fail"] += 1
        dbg(f"parse fail: {uri[:60]}... → {e}")
        return None
    return None


def _parse_vless(uri: str):
    parsed = urllib.parse.urlparse(uri)
    params = urllib.parse.parse_qs(parsed.query)

    net = params.get("type", ["tcp"])[0]
    sec = params.get("security", ["none"])[0]

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": parsed.hostname,
                "port": parsed.port,
                "users": [{
                    "id": parsed.username,
                    "encryption": "none",
                    "flow": params.get("flow", [""])[0],
                }],
            }]
        },
        "streamSettings": {"network": net},
    }
    stream = outbound["streamSettings"]

    if sec == "tls":
        tls = {"serverName": params.get("sni", [parsed.hostname])[0]}
        if "alpn" in params:
            tls["alpn"] = params["alpn"][0].split(",")
        if params.get("fp", [""])[0]:
            tls["fingerprint"] = params["fp"][0]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif sec == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "publicKey":   params.get("pbk", [""])[0],
            "fingerprint": params.get("fp", ["chrome"])[0],
            "serverName":  params.get("sni", [""])[0],
            "shortId":     params.get("sid", [""])[0],
            "spiderX":     params.get("spx", ["/"])[0],
        }

    if net == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": params.get("host", [parsed.hostname])[0]},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0],
            "multiMode": params.get("mode", [""])[0] == "multi",
        }
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "path": params.get("path", ["/"])[0],
            "host": params.get("host", [parsed.hostname])[0].split(","),
        }
    elif net == "tcp" and params.get("headerType", [""])[0] == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [params.get("path", ["/"])[0]],
                    "headers": {"Host": [params.get("host", [parsed.hostname])[0]]},
                },
            }
        }
    return outbound


def _parse_vmess(uri: str):
    b64 = uri[8:]
    if "?" in b64:
        b64 = b64.split("?", 1)[0]
    data = json.loads(b64decode_any(b64).decode("utf-8"))

    net = data.get("net", "tcp")
    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": data["add"],
                "port": int(data["port"]),
                "users": [{
                    "id": data["id"],
                    "alterId": int(data.get("aid", data.get("alterId", 0))),
                    "security": data.get("scy", data.get("security", "auto")),
                }],
            }]
        },
        "streamSettings": {"network": net},
    }
    stream = outbound["streamSettings"]

    if data.get("tls") == "tls":
        stream["security"] = "tls"
        tls = {"serverName": data.get("sni", "") or data.get("host", "")}
        if data.get("alpn"):
            tls["alpn"] = data["alpn"].split(",") if isinstance(data["alpn"], str) else data["alpn"]
        if data.get("fp"):
            tls["fingerprint"] = data["fp"]
        stream["tlsSettings"] = tls

    if net == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", "")},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", "")}
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "path": data.get("path", "/"),
            "host": [h.strip() for h in data.get("host", "").split(",") if h.strip()],
        }
    elif net == "tcp" and data.get("type") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [data.get("path", "/")],
                    "headers": {"Host": [data.get("host", "")]},
                },
            }
        }
    return outbound


# ---------- проверки окружения ----------

def preflight_checks(xray_bin):
    """Проверяем всё, что может сломать тест, ещё до запуска Xray."""
    log("=" * 50)
    log("PREFLIGHT CHECKS")
    log("=" * 50)

    # 1. Бинарь на месте и исполняемый
    if not os.path.exists(xray_bin):
        log(f"Xray binary не найден: {xray_bin}", "ERR")
        return False
    st = os.stat(xray_bin)
    log(f"✓ Xray binary: {xray_bin} ({st.st_size} байт, mode={oct(st.st_mode)})")

    # 2. Версия Xray (заодно проверит, что бинарь рабочий)
    try:
        r = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=10)
        log(f"✓ xray version: rc={r.returncode}")
        for line in (r.stdout + r.stderr).strip().splitlines()[:3]:
            log(f"    {line}")
        if r.returncode != 0:
            log("Xray version вернул не 0 — бинарь вероятно битый", "WARN")
    except Exception as e:
        log(f"Xray не запускается: {e}", "ERR")
        return False

    # 3. Сеть до тестового URL без прокси
    log(f"→ Проверка {TEST_URL} напрямую (без прокси)...")
    try:
        t0 = time.time()
        r = requests.get(TEST_URL, timeout=10, stream=True)
        r.close()
        log(f"✓ Прямое подключение OK: HTTP {r.status_code} за {(time.time()-t0)*1000:.0f}ms")
    except Exception as e:
        log(f"Прямое подключение провалилось: {e}", "WARN")
        log("    Это означает, что машина сама не может достучаться до gstatic.", "WARN")
        log("    Значит тест через прокси тем более не пройдёт.", "WARN")

    # 4. Проверка что SOCKS5 через requests вообще работает (заглушка)
    dbg(f"requests версия: {requests.__version__}")
    dbg(f"SOCKS support: {'PySocks' if _has_socks() else 'НЕТ (pip install PySocks)'}")

    return True


def _has_socks():
    try:
        import socks  # noqa
        return True
    except ImportError:
        return False


# ---------- main ----------

def ensure_xray() -> str:
    log("Скачиваем и готовим Xray...")
    os.makedirs("xray_bin", exist_ok=True)
    xray_bin = os.path.join("xray_bin", "xray")
    xray_zip = "xray.zip"

    if not os.path.exists(xray_bin):
        if not os.path.exists(xray_zip):
            log(f"→ Скачиваем {XRAY_URL}")
            urllib.request.urlretrieve(XRAY_URL, xray_zip)
            log(f"✓ Скачано {os.path.getsize(xray_zip)} байт")
        with zipfile.ZipFile(xray_zip, "r") as z:
            log(f"→ Распаковка, файлов: {len(z.namelist())}")
            z.extractall("xray_bin")

    os.chmod(xray_bin, 0o755)
    return xray_bin


def test_port(uri: str, port: int):
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else uri[:40]
    proxies = {
        "http":  f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}",
    }
    try:
        start = time.time()
        r = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TEST_TIMEOUT,
            stream=True,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=False,
        )
        try:
            elapsed = (time.time() - start) * 1000
            code = r.status_code
        finally:
            r.close()

        if code == 204:
            _stats["test_ok"] += 1
            dbg(f"✓ port {port} {name} → 204 за {elapsed:.0f}ms")
            return uri, elapsed
        else:
            _stats["test_other"] += 1
            dbg(f"✗ port {port} {name} → HTTP {code} (не 204)")
            return None, -1

    except requests.exceptions.ProxyError as e:
        _stats["test_proxy_err"] += 1
        dbg(f"✗ port {port} {name} → ProxyError: {str(e)[:120]}")
    except requests.exceptions.ConnectTimeout as e:
        _stats["test_timeout"] += 1
        dbg(f"✗ port {port} {name} → ConnectTimeout")
    except requests.exceptions.ReadTimeout as e:
        _stats["test_timeout"] += 1
        dbg(f"✗ port {port} {name} → ReadTimeout")
    except requests.exceptions.ConnectionError as e:
        _stats["test_conn_err"] += 1
        dbg(f"✗ port {port} {name} → ConnectionError: {str(e)[:120]}")
    except Exception as e:
        _stats["test_other"] += 1
        dbg(f"✗ port {port} {name} → {type(e).__name__}: {str(e)[:120]}")
    return None, -1


def main():
    xray_bin = ensure_xray()
    if not preflight_checks(xray_bin):
        return

    # 1) Загрузка и фильтрация
    log("=" * 50)
    log("ЗАГРУЗКА КОНФИГОВ")
    log("=" * 50)
    raw_configs = []
    for url in SOURCE_URLS:
        raw_configs.extend(get_configs_from_url(url))
    log(f"Всего получено строк с '://': {len(raw_configs)}")

    # Показать какие типы протоколов пришли
    proto_count = defaultdict(int)
    for c in raw_configs:
        if "://" in c:
            proto_count[c.split("://", 1)[0]] += 1
    log(f"По протоколам: {dict(proto_count)}")

    filtered = [
        rename_server(c) for c in raw_configs
        if c.startswith(("vless://", "vmess://"))
    ]
    log(f"После фильтра vless/vmess: {len(filtered)}")
    for i, u in enumerate(filtered[:3]):
        log(f"  пример {i+1}: {u[:100]}...")

    # 2) Сборка Xray-конфига
    log("=" * 50)
    log("ПАРСИНГ И СБОРКА КОНФИГА")
    log("=" * 50)
    inbounds, outbounds, rules, valid_uris = [], [], [], []
    for uri in filtered:
        host = get_host(uri)
        if host and any(host.startswith(b) for b in BAD_PREFIXES):
            _stats["bad_prefix"] += 1
            continue

        out = parse_uri_to_xray(uri)
        if not out:
            continue

        port = BASE_PORT + len(valid_uris)
        out["tag"] = f"proxy_{port}"
        outbounds.append(out)

        inbounds.append({
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "tag": f"socks_{port}",
            "settings": {"auth": "noauth", "udp": False},
        })
        rules.append({
            "type": "field",
            "inboundTag": [f"socks_{port}"],
            "outboundTag": f"proxy_{port}",
        })
        valid_uris.append(uri)

    log(f"Успешно распарсено: {len(valid_uris)}")
    log(f"Отфильтровано (bad prefix): {_stats['bad_prefix']}")
    log(f"Ошибок парсинга: {_stats['parse_fail']}")

    if not valid_uris:
        log("Нет валидных серверов — выходим.", "ERR")
        return

    # Сводка по транспортам — понадобится если всё падает
    net_count = defaultdict(int)
    for o in outbounds:
        net_count[o["streamSettings"].get("network", "?")] += 1
    log(f"По транспортам: {dict(net_count)}")

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": rules},
    }
    with open("xray_config.json", "w") as f:
        json.dump(config, f, indent=2)
    log(f"Конфиг сохранён: xray_config.json ({os.path.getsize('xray_config.json')} байт)")

    # 3) ВАЛИДАЦИЯ конфига — если Xray её не пройдёт, он не запустится
    log("=" * 50)
    log("ВАЛИДАЦИЯ КОНФИГА XRAY")
    log("=" * 50)
    r = subprocess.run(
        [xray_bin, "run", "-test", "-c", "xray_config.json"],
        capture_output=True, text=True, timeout=30,
    )
    log(f"rc={r.returncode}")
    if r.stdout.strip():
        for line in r.stdout.strip().splitlines():
            log(f"  stdout: {line}")
    if r.stderr.strip():
        for line in r.stderr.strip().splitlines():
            log(f"  stderr: {line}", "WARN" if r.returncode == 0 else "ERR")

    if r.returncode != 0:
        log("Xray НЕ принял конфиг. Тест бессмысленен.", "ERR")
        log("Смотри вывод выше — там конкретная ошибка.", "ERR")
        return

    # 4) Запуск Xray с сохранением лога
    log("=" * 50)
    log("ЗАПУСК XRAY")
    log("=" * 50)
    xray_log = open("xray_run.log", "w")
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", "xray_config.json"],
        stdout=xray_log,
        stderr=subprocess.STDOUT,
    )
    log(f"Xray PID: {proc.pid}")
    time.sleep(3)

    if proc.poll() is not None:
        log(f"Xray УПАЛ сразу после старта (rc={proc.returncode}).", "ERR")
        xray_log.close()
        log("--- последние строки xray_run.log ---")
        with open("xray_run.log") as f:
            for line in f.readlines()[-30:]:
                log(f"  {line.rstrip()}", "ERR")
        return

    log("✓ Xray работает")

    # Проверка что порты реально слушаются
    log("→ Проверка что SOCKS-порты слушаются...")
    try:
        listen_out = subprocess.run(
            ["ss", "-tln"], capture_output=True, text=True, timeout=5,
        ).stdout
        listening = sum(1 for line in listen_out.splitlines() if f":{BASE_PORT}" in line or any(
            f":{BASE_PORT+i}" in line for i in range(0, 5)
        ))
        log(f"✓ Найдено listening-портов в диапазоне {BASE_PORT}..{BASE_PORT+len(valid_uris)}: {listening}")
    except FileNotFoundError:
        log("ss не установлен — пропускаю проверку портов", "WARN")
    except Exception as e:
        log(f"Ошибка проверки портов: {e}", "WARN")

    # 5) Тестирование
    log("=" * 50)
    log(f"ТЕСТИРОВАНИЕ ({len(valid_uris)} серверов, workers={MAX_WORKERS}, timeout={TEST_TIMEOUT}s)")
    log("=" * 50)
    alive = []
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(test_port, uri, BASE_PORT + i): i
                for i, uri in enumerate(valid_uris)
            }
            done = 0
            for f in as_completed(futures):
                done += 1
                if done % 50 == 0:
                    log(f"  обработано {done}/{len(valid_uris)}, живых: {len(alive)}")
                try:
                    u, p = f.result()
                    if u:
                        alive.append((u, p))
                except Exception as e:
                    dbg(f"future exception: {e}")
    finally:
        log("Останавливаем Xray...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass
        xray_log.close()

    # 6) Статистика
    log("=" * 50)
    log("ИТОГИ")
    log("=" * 50)
    log(f"Живых: {_stats['test_ok']}")
    log(f"ProxyError (Xray не смог открыть соединение): {_stats['test_proxy_err']}")
    log(f"ConnectTimeout: {_stats['test_timeout']}")
    log(f"ConnectionError (SOCKS отвалился): {_stats['test_conn_err']}")
    log(f"Другие ошибки / HTTP != 204: {_stats['test_other']}")

    if not alive:
        log("Ни один сервер не прошёл тест.", "ERR")
        log("Посмотри xray_run.log — там ошибки Xray по каждому outbound (если warning-уровень достаточно подробный).", "ERR")
        log("А также обрати внимание на раздел PREFLIGHT — если прямое подключение до gstatic падало, тест через прокси тем более не пройдёт.", "ERR")
        return

    alive.sort(key=lambda x: x[1])
    final_uris, country_counts = [], defaultdict(int)

    for uri, ping in alive:
        if len(final_uris) >= MAX_SERVERS:
            break
        name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
        flag_match = FLAG_RE.search(name)
        flag = flag_match.group(0) if flag_match else "🌍"

        if country_counts[flag] >= PER_COUNTRY_LIMIT:
            continue

        final_uris.append(uri)
        country_counts[flag] += 1
        log(f"[В СПИСКЕ] {name} | {ping:.0f}ms")

    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется. Нажми Обновить.\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(final_uris))
    log(f"Файл {OUTPUT_FILE} сохранён ({len(final_uris)} серверов)!")


if __name__ == "__main__":
    main()
