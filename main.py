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
XRAY_URL    = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
TEST_URL    = "https://www.gstatic.com/generate_204"

MAX_SERVERS       = 20
PER_COUNTRY_LIMIT = 3
TEST_TIMEOUT      = 8
MAX_WORKERS       = 20
BASE_PORT         = 20000
DEBUG             = True

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
}

BAD_PREFIXES = ["104.", "172.6", "172.7", "188.114.", "141.101.", "141.193.", "162.158.", "198.41."]
FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
WHITESPACE_RE = re.compile(r'\s+')

_stats = defaultdict(int)


def log(msg, level="INFO"):
    prefix = {"INFO": "", "WARN": "[WARN] ", "ERR": "[ERR] "}.get(level, "")
    print(prefix + str(msg), flush=True)


def dbg(msg):
    if DEBUG:
        print("[dbg] " + str(msg), flush=True)


# ---------- base64 / helpers ----------

def b64decode_any(s):
    """Универсальный base64: URL-safe, URL-encoded, без padding."""
    s = s.strip()
    # URL-encoding в URI (например %2B -> +, %3D -> =)
    try:
        s = urllib.parse.unquote(s)
    except Exception:
        pass
    # URL-safe -> standard
    s = s.replace('-', '+').replace('_', '/')
    # Убираем внутренние пробелы/переносы
    s = WHITESPACE_RE.sub('', s)

    pad = (-len(s)) % 4
    if pad == 3:
        # len % 4 == 1 — невозможно в валидном base64, значит один лишний символ
        dbg("b64: len%4==1, обрезаем хвостовой символ")
        s = s[:-1]
        pad = (-len(s)) % 4
    s += "=" * pad
    return base64.b64decode(s, validate=False)


def get_host(uri):
    if uri.startswith(("vless://", "trojan://", "ss://")):
        try:
            return urllib.parse.urlparse(uri).hostname or ""
        except Exception:
            return ""
    if uri.startswith("vmess://"):
        try:
            b64 = uri[8:].split("?", 1)[0]
            data = json.loads(b64decode_any(b64).decode("utf-8"))
            return data.get("add", "")
        except Exception:
            return ""
    return ""


def get_configs_from_url(url):
    log("-> Загружаем: " + url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                if "://" in decoded:
                    content = decoded
            except Exception:
                pass
            lines = [line.strip() for line in content.splitlines() if "://" in line]
            log("    OK: " + str(len(lines)) + " URI")
            return lines
    except Exception as e:
        log("[ОШИБКА] " + url[:60] + " : " + str(e), "ERR")
        return []


def rename_server(uri):
    parts = uri.split("#", 1)
    host = get_host(uri)
    original = ""
    if len(parts) > 1:
        try:
            original = urllib.parse.unquote(parts[1])
        except Exception:
            pass

    m = FLAG_RE.search(original)
    if m:
        flag = m.group(0)
        country = COUNTRY_MAP.get(flag, "Неизвестно")
        new_name = flag + " " + country + " [" + host + "]"
    elif original.strip():
        new_name = "🌍 " + original.strip()[:40] + " [" + host + "]"
    else:
        new_name = "🌍 Неизвестно [" + host + "]"
    return parts[0] + "#" + urllib.parse.quote(new_name)


# ---------- URI -> Xray outbound ----------

def parse_uri_to_xray(uri):
    try:
        if uri.startswith("vless://"):
            return _parse_vless(uri)
        if uri.startswith("vmess://"):
            return _parse_vmess(uri)
    except Exception as e:
        _stats["parse_fail"] += 1
        dbg("parse fail: " + uri[:80] + " -> " + str(e))
        return None
    return None


def _apply_stream_settings(outbound, net, params_like):
    """Заполняет transport-specific секции. params_like — dict или dict-like."""
    stream = outbound["streamSettings"]
    get = params_like.get

    def first(key, default=""):
        v = get(key, default)
        if isinstance(v, list):
            return v[0] if v else default
        return v if v is not None else default

    if net == "ws":
        stream["wsSettings"] = {
            "path": first("path", "/"),
            "headers": {"Host": first("host", "")},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": first("serviceName", ""),
            "multiMode": first("mode", "") == "multi",
        }
    elif net in ("h2", "http"):
        stream["httpSettings"] = {
            "path": first("path", "/"),
            "host": [h.strip() for h in first("host", "").split(",") if h.strip()],
        }
    elif net == "xhttp":
        # XHTTP (новый транспорт Xray 24.9.30+)
        stream["xhttpSettings"] = {
            "path": first("path", "/"),
            "host": first("host", ""),
            "mode": first("mode", "auto"),
        }
    elif net == "raw":
        # raw = новый alias для tcp в свежих Xray
        if first("headerType", "") == "http":
            stream["rawSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [first("path", "/")],
                        "headers": {"Host": [first("host", "")]},
                    },
                }
            }
    elif net == "tcp":
        if first("headerType", "") == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [first("path", "/")],
                        "headers": {"Host": [first("host", "")]},
                    },
                }
            }


def _parse_vless(uri):
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

    _apply_stream_settings(outbound, net, params)
    return outbound


def _parse_vmess(uri):
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

    _apply_stream_settings(outbound, net, data)
    return outbound


# ---------- Xray / checks ----------

def ensure_xray():
    log("Скачиваем и готовим Xray (latest)...")
    os.makedirs("xray_bin", exist_ok=True)
    xray_bin = os.path.join("xray_bin", "xray")
    xray_zip = "xray.zip"

    if not os.path.exists(xray_bin):
        if not os.path.exists(xray_zip):
            log("-> Скачиваем " + XRAY_URL)
            urllib.request.urlretrieve(XRAY_URL, xray_zip)
            log("OK скачано " + str(os.path.getsize(xray_zip)) + " байт")
        with zipfile.ZipFile(xray_zip, "r") as z:
            z.extractall("xray_bin")

    os.chmod(xray_bin, 0o755)
    return xray_bin


def _has_socks():
    try:
        import socks  # noqa
        return True
    except ImportError:
        return False


def preflight_checks(xray_bin):
    log("=" * 50)
    log("PREFLIGHT CHECKS")
    log("=" * 50)

    if not os.path.exists(xray_bin):
        log("Xray binary не найден", "ERR")
        return False

    try:
        r = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=10)
        log("xray version rc=" + str(r.returncode))
        for line in (r.stdout + r.stderr).strip().splitlines()[:2]:
            log("    " + line)
        # Проверим что xhttp поддерживается
        test_cfg = {"inbounds": [], "outbounds": [
            {"protocol": "freedom", "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/"}}}
        ]}
        with open("/tmp/_xtest.json", "w") as f:
            json.dump(test_cfg, f)
        rt = subprocess.run([xray_bin, "run", "-test", "-c", "/tmp/_xtest.json"],
                            capture_output=True, text=True, timeout=15)
        if rt.returncode == 0:
            log("✓ Xray поддерживает xhttp")
        else:
            log("⚠️ Xray НЕ поддерживает xhttp — удалите xray_bin/ и перезапустите", "WARN")
    except Exception as e:
        log("Xray не запускается: " + str(e), "ERR")
        return False

    try:
        t0 = time.time()
        r = requests.get(TEST_URL, timeout=10, stream=True)
        r.close()
        log("✓ Прямое подключение: HTTP " + str(r.status_code) + " за " + str(int((time.time()-t0)*1000)) + "ms")
    except Exception as e:
        log("Прямое подключение провалилось: " + str(e), "WARN")

    dbg("requests: " + requests.__version__ + ", PySocks: " + str(_has_socks()))
    return True


def test_port(uri, port):
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else uri[:40]
    proxies = {
        "http":  "socks5h://127.0.0.1:" + str(port),
        "https": "socks5h://127.0.0.1:" + str(port),
    }
    try:
        start = time.time()
        r = requests.get(TEST_URL, proxies=proxies, timeout=TEST_TIMEOUT, stream=True,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=False)
        try:
            elapsed = (time.time() - start) * 1000
            code = r.status_code
        finally:
            r.close()

        if code == 204:
            _stats["test_ok"] += 1
            dbg("OK port " + str(port) + " " + name + " -> 204 за " + str(int(elapsed)) + "ms")
            return uri, elapsed
        _stats["test_other"] += 1
        dbg("FAIL port " + str(port) + " " + name + " -> HTTP " + str(code))
    except requests.exceptions.ProxyError as e:
        _stats["test_proxy_err"] += 1
        dbg("FAIL port " + str(port) + " " + name + " -> ProxyError: " + str(e)[:100])
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout):
        _stats["test_timeout"] += 1
        dbg("FAIL port " + str(port) + " " + name + " -> Timeout")
    except requests.exceptions.ConnectionError as e:
        _stats["test_conn_err"] += 1
        dbg("FAIL port " + str(port) + " " + name + " -> ConnError: " + str(e)[:100])
    except Exception as e:
        _stats["test_other"] += 1
        dbg("FAIL port " + str(port) + " " + name + " -> " + type(e).__name__)
    return None, -1


# ---------- main ----------

def main():
    xray_bin = ensure_xray()
    if not preflight_checks(xray_bin):
        return

    log("=" * 50)
    log("ЗАГРУЗКА КОНФИГОВ")
    log("=" * 50)
    raw = []
    for url in SOURCE_URLS:
        raw.extend(get_configs_from_url(url))
    log("Всего строк: " + str(len(raw)))

    proto = defaultdict(int)
    for c in raw:
        if "://" in c:
            proto[c.split("://", 1)[0]] += 1
    log("Протоколы: " + str(dict(proto)))

    filtered = [rename_server(c) for c in raw if c.startswith(("vless://", "vmess://"))]
    log("После фильтра vless/vmess: " + str(len(filtered)))

    log("=" * 50)
    log("СБОРКА КОНФИГА")
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
        out["tag"] = "proxy_" + str(port)
        outbounds.append(out)
        inbounds.append({
            "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "tag": "socks_" + str(port),
            "settings": {"auth": "noauth", "udp": False},
        })
        rules.append({
            "type": "field",
            "inboundTag": ["socks_" + str(port)],
            "outboundTag": "proxy_" + str(port),
        })
        valid_uris.append(uri)

    log("Валидных: " + str(len(valid_uris)))
    log("Плохой prefix: " + str(_stats["bad_prefix"]) + ", ошибок парсинга: " + str(_stats["parse_fail"]))

    if not valid_uris:
        log("Нет валидных серверов — выходим", "ERR")
        return

    net_count = defaultdict(int)
    for o in outbounds:
        net_count[o["streamSettings"].get("network", "?")] += 1
    log("Транспорты: " + str(dict(net_count)))

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"protocol": "freedom", "tag": "direct"}],
        "routing": {"rules": rules},
    }
    with open("xray_config.json", "w") as f:
        json.dump(config, f, indent=2)
    log("Конфиг сохранён (" + str(os.path.getsize("xray_config.json")) + " байт)")

    log("=" * 50)
    log("ВАЛИДАЦИЯ")
    log("=" * 50)
    r = subprocess.run([xray_bin, "run", "-test", "-c", "xray_config.json"],
                       capture_output=True, text=True, timeout=30)
    log("rc=" + str(r.returncode))
    if r.stdout.strip():
        for line in r.stdout.strip().splitlines():
            log("  " + line)
    if r.stderr.strip():
        for line in r.stderr.strip().splitlines():
            log("  " + line, "WARN" if r.returncode == 0 else "ERR")

    if r.returncode != 0:
        log("Xray НЕ принял конфиг — стоп", "ERR")
        return

    log("=" * 50)
    log("ЗАПУСК XRAY")
    log("=" * 50)
    xray_log = open("xray_run.log", "w")
    proc = subprocess.Popen(
        [xray_bin, "run", "-c", "xray_config.json"],
        stdout=xray_log, stderr=subprocess.STDOUT,
    )
    log("Xray PID: " + str(proc.pid))
    time.sleep(3)

    if proc.poll() is not None:
        log("Xray упал сразу (rc=" + str(proc.returncode) + ")", "ERR")
        xray_log.close()
        with open("xray_run.log") as f:
            for line in f.readlines()[-30:]:
                log("  " + line.rstrip(), "ERR")
        return

    log("✓ Xray работает")

    log("=" * 50)
    log("ТЕСТИРОВАНИЕ (" + str(len(valid_uris)) + " серверов, workers=" + str(MAX_WORKERS) + ")")
    log("=" * 50)
    alive = []
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {ex.submit(test_port, u, BASE_PORT + i): i for i, u in enumerate(valid_uris)}
            done = 0
            for f in as_completed(futures):
                done += 1
                if done % 50 == 0:
                    log("  обработано " + str(done) + "/" + str(len(valid_uris)) + ", живых: " + str(len(alive)))
                try:
                    u, p = f.result()
                    if u:
                        alive.append((u, p))
                except Exception:
                    pass
    finally:
        log("Останавливаем Xray...")
        try:
            proc.terminate(); proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass
        xray_log.close()

    log("=" * 50)
    log("ИТОГИ")
    log("=" * 50)
    log("Живых: " + str(_stats["test_ok"]))
    log("ProxyError: " + str(_stats["test_proxy_err"]))
    log("Timeout: " + str(_stats["test_timeout"]))
    log("ConnError: " + str(_stats["test_conn_err"]))
    log("Другое/HTTP!=204: " + str(_stats["test_other"]))

    if not alive:
        log("Ни один не прошёл. Смотри xray_run.log", "ERR")
        return

    alive.sort(key=lambda x: x[1])
    final_uris, country_counts = [], defaultdict(int)

    for uri, ping in alive:
        if len(final_uris) >= MAX_SERVERS:
            break
        name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
        m = FLAG_RE.search(name)
        flag = m.group(0) if m else "🌍"
        if country_counts[flag] >= PER_COUNTRY_LIMIT:
            continue
        final_uris.append(uri)
        country_counts[flag] += 1
        log("[В СПИСКЕ] " + name + " | " + str(int(ping)) + "ms")

    header = (
        "#profile-title: Sлiвы VPN ~ Drun Tier\n"
        "#profile-update-interval: 1\n"
        "#profile-desc: Подписка автообновляется. Нажми Обновить.\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header + "\n".join(final_uris))
    log("Файл " + OUTPUT_FILE + " сохранён (" + str(len(final_uris)) + " серверов)!")


if __name__ == "__main__":
    main()
