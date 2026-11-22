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
    time.sleep(3)

    alive = []
    try:
        log("Тестируем серверы...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(test_port, uri, BASE_PORT + i)
                for i, uri in enumerate(valid_uris)
            ]
            for f in futures:
                try:
                    u, p = f.result()
                    if u:
                        alive.append((u, p))
                except Exception:
                    pass
    finally:
        log("Останавливаем Xray...")
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass
        try:
            os.remove("xray_config.json")
        except OSError:
            pass

    log(f"Живых серверов: {len(alive)}")
    if not alive:
        log("Мёртвых серверов нет — файл не сохранён.")
        return

    # 4) Сортировка и отбор
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
        log(f"[В СПИСКЕ] {name} | Пинг: {ping:.0f}ms")

    # 5) Запись
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
