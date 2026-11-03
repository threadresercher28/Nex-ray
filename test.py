#!/usr/bin/env python3
"""Happ-style VPN client (tkinter) для Xray / Sing-box.

Возможности: подписки (авто-обновление, трафик/срок, HWID-заголовки), сохранение
серверов и настроек, ручной / «быстрейший» / round-robin выбор, failover,
реальный TCP-пинг и глубокий тест через ядро, системный прокси, маршрутизация,
импорт по deeplink (happ://, v2raytun://, incy:// ...), отчёт в JSON на API.
"""
import base64
import hashlib
import http.client
import json
import logging
import math
import os
import platform
import queue
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import tkinter as tk
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox
from urllib.parse import urlparse, parse_qs, unquote, urljoin

APP_NAME = "Happ-style VPN"
APP_VERSION = "3.0.0"
IS_WIN = os.name == "nt"
APP_DIR = Path(os.environ.get("APPDATA") or (Path.home() / ".config")) / "HappStyleVPN"
APP_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = APP_DIR / "state.json"

REPORT_API = "https://slander127.x10.mx/api/kivn-help.php"
WHITELIST_DOMAINS = ("music.yandex.ru", "maps.yandex.ru", "max.ru")
VERIFY_HOST, VERIFY_PATH = "www.gstatic.com", "/generate_204"
DEEPLINK_SCHEMES = {"happ", "v2raytun", "incy", "clash", "clashmeta", "sing-box", "v2rayng",
                    "hiddify", "streisand", "v2box", "shadowrocket", "nekoray", "karing"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("HappStyleVPN")


class QueueLogHandler(logging.Handler):
    def __init__(self, q):
        super().__init__()
        self.q = q
        self.setFormatter(logging.Formatter("%(asctime)s  %(message)s", datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            self.q.put_nowait((record.levelname, self.format(record)))
        except Exception:
            pass


# ===================================================================
# 1. ТЕКСТ: флаги-эмодзи в именах серверов
# ===================================================================
# Флаги (пары региональных индикаторов, U+1F1E6..1F1FF) лежат вне BMP: на части сборок
# Tcl/Tk это падает («character above the range U+0000-U+FFFF»), на Windows они
# рисуются как две буквы, на Linux — квадраты. Поэтому флаг превращаем в код страны.
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")


def country_code(s: str) -> str:
    s = s or ""
    m = FLAG_RE.search(s)
    if m:
        return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in m.group())
    m = re.search(r"\[([A-Za-z]{2})\]", s) or re.match(r"^\s*([A-Z]{2})[\s|_\-:]", s)
    return m.group(1).upper() if m else "--"


def clean_name(s: str) -> str:
    s = FLAG_RE.sub("", s or "")
    s = "".join(ch for ch in s if ord(ch) <= 0xFFFF and ch not in "\ufe0f\u200d\u200b\u200e\u200f\ufffd" and ch.isprintable())
    return re.sub(r"\s+", " ", s).strip(" |-_:")


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for u in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or u == "ТБ":
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024


# ===================================================================
# 2. ПАРСЕРЫ
# ===================================================================
def _finish(p: dict, uri: str) -> dict:
    p["uri"] = uri
    p["id"] = hashlib.sha1(uri.encode("utf-8")).hexdigest()[:12]
    p["name"] = clean_name(p["remark"]) or f"{p['host']}:{p['port']}"
    p["cc"] = country_code(p["remark"])
    return p


def _q(params, key, default=""):
    return params.get(key, [default])[0]


def parse_vless(uri):
    try:
        u = urlparse(uri)
        if u.scheme != "vless":
            return None
        pr = parse_qs(u.query)
        return {"type": "vless", "remark": unquote(u.fragment) or f"{u.hostname}:{u.port}",
                "uuid": u.username, "host": u.hostname, "port": u.port or 443,
                "security": _q(pr, "security", "none"),
                "sni": _q(pr, "sni") or _q(pr, "host") or u.hostname,
                "fp": _q(pr, "fp"), "pbk": _q(pr, "pbk"), "sid": _q(pr, "sid"), "spx": _q(pr, "spx"),
                "flow": _q(pr, "flow"), "alpn": _q(pr, "alpn"),
                "insecure": _q(pr, "allowInsecure") in ("1", "true"),
                "network": _q(pr, "type", "tcp"), "path": _q(pr, "path", "/"),
                "ws_host": _q(pr, "host"), "service_name": _q(pr, "serviceName")}
    except Exception as e:
        logger.debug(f"VLESS parse error: {e}")


def parse_vmess(uri):
    if not uri.startswith("vmess://"):
        return None
    try:
        b64 = uri[len("vmess://"):].split("#", 1)[0].strip()
        raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        text = raw.decode("utf-8", errors="replace")      # мусорные байты в имени не ломают разбор
        d, _ = json.JSONDecoder().raw_decode(text[text.index("{"):])   # хвост после JSON игнорируется
        return {"type": "vmess", "remark": d.get("ps", "") or f"{d.get('add')}:{d.get('port')}",
                "uuid": d.get("id"), "host": d.get("add"), "port": int(d.get("port") or 443),
                "security": d.get("tls", "none") if d.get("tls") else "none",
                "sni": d.get("sni", "") or d.get("host", "") or d.get("add"),
                "fp": d.get("fp", ""), "alpn": d.get("alpn", ""), "insecure": False,
                "network": d.get("net", "tcp"), "path": d.get("path", "/"), "ws_host": d.get("host", ""),
                "service_name": d.get("path", ""), "alter_id": int(d.get("aid") or 0)}
    except Exception as e:
        logger.debug(f"VMess parse error: {e}")


def parse_trojan(uri):
    try:
        u = urlparse(uri)
        if u.scheme != "trojan":
            return None
        pr = parse_qs(u.query)
        return {"type": "trojan", "remark": unquote(u.fragment) or f"{u.hostname}:{u.port}",
                "password": unquote(u.username or ""), "host": u.hostname, "port": u.port or 443,
                "security": _q(pr, "security", "tls"), "sni": _q(pr, "sni") or u.hostname,
                "fp": _q(pr, "fp"), "alpn": _q(pr, "alpn"),
                "insecure": _q(pr, "allowInsecure") in ("1", "true"),
                "network": _q(pr, "type", "tcp"), "path": _q(pr, "path", "/"),
                "ws_host": _q(pr, "host"), "service_name": _q(pr, "serviceName")}
    except Exception as e:
        logger.debug(f"Trojan parse error: {e}")


def parse_ss(uri):
    try:
        if not uri.startswith("ss://"):
            return None
        body, remark = uri[5:], ""
        if "#" in body:
            body, remark = body.split("#", 1)
            remark = unquote(remark)
        body = body.split("?", 1)[0]
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            if ":" not in userinfo:
                userinfo = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
            method, password = userinfo.split(":", 1)
        else:
            dec = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
            userinfo, hostport = dec.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        return {"type": "ss", "remark": remark or f"{host}:{port}", "method": unquote(method),
                "password": unquote(password), "host": host.strip("[]"), "port": int(port)}
    except Exception as e:
        logger.debug(f"SS parse error: {e}")


def parse_hysteria2(uri):
    try:
        u = urlparse(uri)
        if u.scheme not in ("hysteria2", "hy2"):
            return None
        pr = parse_qs(u.query)
        return {"type": "hysteria2", "remark": unquote(u.fragment) or f"{u.hostname}:{u.port}",
                "password": unquote(u.username or ""), "host": u.hostname, "port": u.port or 443,
                "sni": _q(pr, "sni") or u.hostname, "insecure": _q(pr, "insecure") in ("1", "true"),
                "obfs": _q(pr, "obfs"), "obfs_password": _q(pr, "obfs-password")}
    except Exception as e:
        logger.debug(f"Hysteria2 parse error: {e}")


def parse_uri(uri: str):
    uri = uri.strip()
    for fn in (parse_vless, parse_vmess, parse_trojan, parse_ss, parse_hysteria2):
        r = fn(uri)
        if r and r.get("host"):
            return _finish(r, uri)
    return None


def parse_subscription(content: str) -> list:
    content = content.strip()
    try:
        dec = base64.b64decode(content + "=" * (-len(content) % 4)).decode("utf-8")
        if "://" in dec:
            content = dec
    except Exception:
        pass
    out, seen, bad = [], set(), 0
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            p = parse_uri(line)
            if p and p["id"] not in seen:
                seen.add(p["id"])
                out.append(p)
            elif not p and "://" in line:
                bad += 1
    if bad:
        logger.warning(f"Пропущено нераспознанных ссылок: {bad}")
    return out


def extract_sub_url(link: str):
    """happ://add/https://... , v2raytun://import/..., incy://..., clash://install-config?url=..."""
    scheme = urlparse(link).scheme.lower()
    if scheme in DEEPLINK_SCHEMES:
        i = link.find("http")
        if i >= 0:
            return unquote(link[i:])
        logger.warning(f"Ссылка {scheme}:// не содержит URL подписки (зашифрованные ссылки не поддерживаются).")
    return None


# ===================================================================
# 3. КОНФИГИ ЯДЕР
# ===================================================================
def _xray_stream(p):
    net, sec = p.get("network", "tcp"), p.get("security", "none")
    s = {"network": net}
    if sec == "tls":
        t = {"serverName": p.get("sni", ""), "allowInsecure": bool(p.get("insecure"))}
        if p.get("fp"): t["fingerprint"] = p["fp"]
        if p.get("alpn"): t["alpn"] = p["alpn"].split(",")
        s["security"], s["tlsSettings"] = "tls", t
    elif sec == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {"serverName": p.get("sni", ""), "fingerprint": p.get("fp") or "chrome",
                                "publicKey": p.get("pbk", ""), "shortId": p.get("sid", ""), "spiderX": p.get("spx", "")}
    host = p.get("ws_host") or p.get("sni", "")
    if net == "ws":
        s["wsSettings"] = {"path": p.get("path", "/"), "headers": {"Host": host}}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": p.get("service_name", "")}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": p.get("path", "/"), "host": host}
    elif net in ("xhttp", "splithttp"):
        s["network"] = "xhttp"
        s["xhttpSettings"] = {"path": p.get("path", "/"), "host": host}
    return s


def build_xray_outbound(p):
    t = p["type"]
    if t == "vless":
        out = {"protocol": "vless", "settings": {"vnext": [{"address": p["host"], "port": p["port"], "users": [
            {"id": p["uuid"], "encryption": "none", "flow": p.get("flow", "")}]}]}}
    elif t == "vmess":
        out = {"protocol": "vmess", "settings": {"vnext": [{"address": p["host"], "port": p["port"], "users": [
            {"id": p["uuid"], "alterId": p.get("alter_id", 0), "security": "auto"}]}]}}
    elif t == "trojan":
        out = {"protocol": "trojan", "settings": {"servers": [{"address": p["host"], "port": p["port"], "password": p["password"]}]}}
    elif t == "ss":
        return {"protocol": "shadowsocks", "settings": {"servers": [{"address": p["host"], "port": p["port"], "method": p["method"], "password": p["password"]}]}}
    else:
        raise ValueError(f"Xray не поддерживает {t}")
    out["streamSettings"] = _xray_stream(p)
    return out


def build_singbox_outbound(p):
    t = p["type"]
    base = {"tag": "proxy", "server": p["host"], "server_port": p["port"]}
    if t == "vless":
        out = {**base, "type": "vless", "uuid": p["uuid"]}
        if p.get("flow"): out["flow"] = p["flow"]
    elif t == "vmess":
        out = {**base, "type": "vmess", "uuid": p["uuid"], "alter_id": p.get("alter_id", 0), "security": "auto"}
    elif t == "trojan":
        out = {**base, "type": "trojan", "password": p["password"]}
    elif t == "ss":
        out = {**base, "type": "shadowsocks", "method": p["method"], "password": p["password"]}
    elif t == "hysteria2":
        out = {**base, "type": "hysteria2", "password": p["password"],
               "tls": {"enabled": True, "server_name": p.get("sni", ""), "insecure": bool(p.get("insecure"))}}
        if p.get("obfs"):
            out["obfs"] = {"type": p["obfs"], "password": p.get("obfs_password", "")}
        return out
    else:
        raise ValueError(t)
    if p.get("security") in ("tls", "reality"):
        tls = {"enabled": True, "server_name": p.get("sni", ""), "insecure": bool(p.get("insecure"))}
        if p.get("fp"): tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
        if p.get("alpn"): tls["alpn"] = p["alpn"].split(",")
        if p["security"] == "reality":
            tls["reality"] = {"enabled": True, "public_key": p.get("pbk", ""), "short_id": p.get("sid", "")}
            tls.setdefault("utls", {"enabled": True, "fingerprint": "chrome"})
        out["tls"] = tls
    net, host = p.get("network", "tcp"), p.get("ws_host") or p.get("sni", "")
    if net == "ws":
        out["transport"] = {"type": "ws", "path": p.get("path", "/"), "headers": {"Host": host}}
    elif net == "grpc":
        out["transport"] = {"type": "grpc", "service_name": p.get("service_name", "")}
    elif net == "httpupgrade":
        out["transport"] = {"type": "httpupgrade", "path": p.get("path", "/"), "host": host}
    return out


def _direct_domains(r):
    items = [d.strip() for d in re.split(r"[,\s]+", r.get("direct_domains", "") or "") if d.strip()]
    if r.get("bypass_ru"):
        items += ["ru", "xn--p1ai", "su"]
    return [d.replace("domain:", "") for d in items]


PRIVATE_CIDRS = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                 "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"]


def find_asset(name):
    """Ищет geoip.dat / geosite.dat (нужны Xray только для geoip:/geosite: правил)."""
    dirs = [Path(__file__).resolve().parent, APP_DIR, APP_DIR / "cores", Path("/usr/share/xray"),
            Path("/usr/local/share/xray"), Path("/usr/share/v2ray"), Path("/usr/local/share/v2ray")]
    if os.environ.get("XRAY_LOCATION_ASSET"):
        dirs.insert(0, Path(os.environ["XRAY_LOCATION_ASSET"]))
    return next((d for d in dirs if (d / name).is_file()), None)


def build_xray_config(p, socks_port, http_port=None, routing=None):
    r = routing or {}
    inbounds = [{"tag": "socks-in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                 "settings": {"auth": "noauth", "udp": True}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}}]
    if http_port:
        inbounds.append({"tag": "http-in", "listen": "127.0.0.1", "port": http_port, "protocol": "http", "settings": {}})
    out = build_xray_outbound(p)
    out["tag"] = "proxy"
    rules = []
    if r.get("bypass_lan"):
        rules.append({"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "direct"})
    if r.get("adblock"):
        if find_asset("geosite.dat"):
            rules.append({"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"})
        else:
            logger.warning("Блокировка рекламы пропущена: не найден geosite.dat.")
    dd = _direct_domains(r)
    if dd:
        rules.append({"type": "field", "domain": [f"domain:{d}" for d in dd], "outboundTag": "direct"})
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": [out, {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules}}


def build_singbox_config(p, socks_port, http_port=None, routing=None):
    r = routing or {}
    rules = []
    if r.get("bypass_lan"):
        rules.append({"ip_is_private": True, "outbound": "direct"})
    dd = _direct_domains(r)
    if dd:
        rules.append({"domain_suffix": dd, "outbound": "direct"})
    return {"log": {"level": "warn"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [build_singbox_outbound(p), {"type": "direct", "tag": "direct"}],
            "route": {"rules": rules, "final": "proxy"}}


def build_config(core, p, socks_port, http_port=None, routing=None):
    fn = build_xray_config if core == "xray" else build_singbox_config
    return fn(p, socks_port, http_port, routing)


# ===================================================================
# 4. ЯДРА
# ===================================================================
CORE_SPECS = {"xray": ("Xray", "xray", "XRAY_BINARY"), "singbox": ("Sing-box", "sing-box", "SINGBOX_BINARY")}


class CoreManager:
    def __init__(self, key: str, quiet: bool = False):
        self.key, self.quiet = key, quiet
        self.name, self.binary_name, self.env_var = CORE_SPECS[key]
        self._process = None
        self._running = False

    def find_binary(self):
        env = os.environ.get(self.env_var)
        if env and Path(env).is_file():
            return env
        names = [self.binary_name + ".exe", self.binary_name] if IS_WIN else [self.binary_name]
        dirs = [Path(__file__).resolve().parent, APP_DIR, APP_DIR / "cores"] + [Path(x) for x in os.environ.get("PATH", "").split(os.pathsep) if x]
        for d in dirs:
            for n in names:
                c = d / n
                if c.is_file() and os.access(c, os.X_OK):
                    return str(c)
        return None

    def start(self, config: dict, cfg_name: str) -> bool:
        if self._running:
            return False
        binary = self.find_binary()
        if not binary:
            logger.error(f"Бинарник '{self.binary_name}' не найден (положи рядом со скриптом или в {APP_DIR}).")
            return False
        cfg = APP_DIR / f"{cfg_name}.json"
        cfg.write_text(json.dumps(config, indent=2), encoding="utf-8")
        try:
            env = dict(os.environ)
            asset = find_asset("geoip.dat") or find_asset("geosite.dat")
            if asset:
                env["XRAY_LOCATION_ASSET"] = str(asset)
            self._process = subprocess.Popen(
                [binary, "run", "-c", str(cfg)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env, cwd=str(APP_DIR),
                creationflags=subprocess.CREATE_NO_WINDOW if IS_WIN else 0)
            self._running = True
            threading.Thread(target=self._read_output, args=(self._process,), daemon=True).start()
            threading.Thread(target=self._monitor, args=(self._process,), daemon=True).start()
            if not self.quiet:
                logger.info(f"{self.name} запущен (PID {self._process.pid}).")
            return True
        except Exception as e:
            logger.error(f"Ошибка запуска {self.name}: {e}")
            self._process, self._running = None, False
            return False

    # «context canceled» и т.п. — штатный шум при закрытии соединений, в лог не пускаем
    NOISE = re.compile(r"context canceled|operation was canceled|upload closed|download closed|use of closed|broken pipe", re.I)

    def _read_output(self, proc):
        sec, cnt = 0, 0
        try:
            for line in proc.stdout:
                if not line.strip() or self.quiet or self.NOISE.search(line):
                    continue
                now = int(time.time())
                if now != sec:
                    sec, cnt = now, 0
                cnt += 1
                if cnt <= 5:
                    logger.info(f"[{self.name}] {line.rstrip()}")
                elif cnt == 6:
                    logger.info(f"[{self.name}] ... (часть строк скрыта)")
        except Exception:
            pass

    def _monitor(self, proc):
        try:
            proc.wait()
        except Exception:
            pass
        if proc is self._process:
            self._running = False
            if not self.quiet:
                logger.info(f"{self.name} завершил работу.")

    def stop(self):
        proc = self._process
        if not proc:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        except Exception as e:
            logger.error(f"Ошибка остановки {self.name}: {e}")
        finally:
            self._process, self._running = None, False

    def is_running(self) -> bool:
        if self._running and self._process and self._process.poll() is not None:
            self._running = False
        return self._running


# ===================================================================
# 5. СЕТЬ
# ===================================================================
def tcp_ping(host, port, timeout=3.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout):
            return max(1, int((time.perf_counter() - t) * 1000))
    except Exception:
        return None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout, alive=None) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if alive and not alive():
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except Exception:
            time.sleep(0.15)
    return False


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("socks eof")
        buf += c
    return buf


def socks5_connect(proxy_port, host, port, timeout):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout)
    s.settimeout(timeout)
    try:
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise ConnectionError("socks handshake")
        h = host.encode("idna")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        _, rep, _, atyp = _recv_exact(s, 4)
        if rep != 0:
            raise ConnectionError(f"socks reply {rep}")
        n = {1: 4, 4: 16}.get(atyp)
        if n is None:
            n = _recv_exact(s, 1)[0]
        _recv_exact(s, n + 2)
        return s
    except Exception:
        s.close()
        raise


def _open(host, port, socks_port, timeout, tls=True):
    sock = socks5_connect(socks_port, host, port, timeout) if socks_port else socket.create_connection((host, port), timeout)
    sock.settimeout(timeout)
    if tls:
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            raise
    return sock


def http_head(host, path="/", socks_port=None, timeout=6.0):
    """HEAD по HTTPS (напрямую или через SOCKS5). -> (ok, status, ms)"""
    t = time.perf_counter()
    try:
        s = _open(host, 443, socks_port, timeout)
        try:
            s.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode())
            line = s.recv(256).split(b"\r\n", 1)[0].decode("latin-1")
        finally:
            s.close()
        return True, int(line.split()[1]), int((time.perf_counter() - t) * 1000)
    except Exception:
        return False, None, None


def http_request(method, url, headers=None, body=None, socks_port=None, timeout=15.0, max_redirects=5):
    """HTTP(S) без системных прокси; опционально через локальный SOCKS5. -> (status, headers, body)"""
    for _ in range(max_redirects + 1):
        u = urlparse(url)
        tls = u.scheme == "https"
        port = u.port or (443 if tls else 80)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        sock = _open(u.hostname, port, socks_port, timeout, tls)
        conn = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(u.hostname, port, timeout=timeout)
        conn.sock = sock
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            data, st = r.read(), r.status
            hdr = {k.lower(): v for k, v in r.getheaders()}
        finally:
            conn.close()
        if st in (301, 302, 303, 307, 308) and hdr.get("location") and method == "GET":
            url = urljoin(url, hdr["location"])
            continue
        return st, hdr, data
    raise RuntimeError("слишком много редиректов")


def check_whitelist(socks_port=None) -> dict:
    with ThreadPoolExecutor(len(WHITELIST_DOMAINS)) as ex:
        res = list(ex.map(lambda d: (d, http_head(d, "/", socks_port, 6.0)), WHITELIST_DOMAINS))
    return {d: {"ok": ok, "status": st, "ms": ms} for d, (ok, st, ms) in res}


def _p_ipapi(d):
    if d.get("status") != "success": return {}
    a = (d.get("as") or "").split()
    return {"ip": d.get("query", ""), "asn": a[0] if a else "", "isp": d.get("isp", ""), "org": d.get("org", ""),
            "country_code": d.get("countryCode", ""), "mobile": bool(d.get("mobile"))}


def _p_ipwho(d):
    if d.get("success") is False: return {}
    c = d.get("connection") or {}
    return {"ip": d.get("ip", ""), "asn": f"AS{c['asn']}" if c.get("asn") else "", "isp": c.get("isp", ""),
            "org": c.get("org", ""), "country_code": d.get("country_code", ""), "mobile": None}


def _p_ipinfo(d):
    org = d.get("org", "")
    parts = org.split(" ", 1)
    name = parts[1] if len(parts) > 1 else org
    return {"ip": d.get("ip", ""), "asn": parts[0] if parts[0].startswith("AS") else "", "isp": name, "org": name,
            "country_code": d.get("country", ""), "mobile": None}


def get_ip_info(socks_port=None) -> dict:
    for url, fn in (("http://ip-api.com/json/?fields=status,query,as,isp,org,countryCode,mobile", _p_ipapi),
                    ("https://ipwho.is/", _p_ipwho), ("https://ipinfo.io/json", _p_ipinfo)):
        try:
            st, _, body = http_request("GET", url, {"User-Agent": "curl/8.0"}, None, socks_port, 8)
            if st == 200:
                d = fn(json.loads(body))
                if d.get("ip"):
                    return d
        except Exception:
            continue
    return {}


def detect_network_type(mobile_hint=None) -> str:
    fallback = "LTE" if mobile_hint else "UNKNOWN"
    try:
        if sys.platform.startswith("linux"):
            iface = None
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":
                    iface = f[0]
                    break
            if iface:
                if Path(f"/sys/class/net/{iface}/wireless").exists() or Path(f"/sys/class/net/{iface}/phy80211").exists():
                    return "WI-FI"
                if re.match(r"(wwan|rmnet|ppp|ccmni|usb\d)", iface):
                    return "LTE"
                return "LTE" if mobile_hint else "ETHERNET"
        elif IS_WIN:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, errors="replace",
                                 creationflags=subprocess.CREATE_NO_WINDOW, timeout=5).stdout
            out = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
            if re.search(r"^\s*SSID\s*:\s*\S+", out, re.M):
                return "WI-FI"
            return "LTE" if mobile_hint else "ETHERNET"
        elif sys.platform == "darwin":
            r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5).stdout
            m = re.search(r"interface:\s*(\S+)", r)
            if m:
                w = subprocess.run(["networksetup", "-getairportnetwork", m.group(1)], capture_output=True, text=True, timeout=5).stdout
                return "WI-FI" if "Current Wi-Fi Network" in w else ("LTE" if mobile_hint else "ETHERNET")
    except Exception:
        pass
    return fallback


def _gs(*args):
    subprocess.run(["gsettings", "set", *args], capture_output=True, timeout=5)


def set_system_proxy(enable: bool, port: int) -> bool:
    try:
        if IS_WIN:
            import winreg, ctypes
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
            if enable:
                winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;192.168.*;<local>")
            winreg.CloseKey(k)
            ctypes.windll.Wininet.InternetSetOptionW(0, 39, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, 37, 0, 0)
        elif sys.platform == "darwin":
            svcs = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True).stdout.splitlines()[1:]
            for svc in (s for s in svcs if s and not s.startswith("*")):
                if enable:
                    for c in ("-setwebproxy", "-setsecurewebproxy"):
                        subprocess.run(["networksetup", c, svc, "127.0.0.1", str(port)], capture_output=True)
                else:
                    for c in ("-setwebproxystate", "-setsecurewebproxystate"):
                        subprocess.run(["networksetup", c, svc, "off"], capture_output=True)
        elif shutil.which("gsettings"):
            if enable:
                for sch in ("http", "https"):
                    _gs(f"org.gnome.system.proxy.{sch}", "host", "127.0.0.1")
                    _gs(f"org.gnome.system.proxy.{sch}", "port", str(port))
                _gs("org.gnome.system.proxy", "mode", "manual")
            else:
                _gs("org.gnome.system.proxy", "mode", "none")
        else:
            logger.warning("Системный прокси не поддерживается на этой ОС.")
            return False
        logger.info(f"Системный прокси: {'ВКЛ 127.0.0.1:' + str(port) if enable else 'выкл'}")
        return True
    except Exception as e:
        logger.error(f"Системный прокси: {e}")
        return False


# ===================================================================
# 6. ХРАНИЛИЩЕ
# ===================================================================
DEFAULT_SETTINGS = {
    "core": "xray", "mode": "manual", "socks_port": 10808, "system_proxy": False,
    "bypass_lan": True, "bypass_ru": False, "adblock": False, "direct_domains": "",
    "auto_connect": False, "auto_reconnect": True, "verify_connect": True,
    "update_on_start": True, "sub_interval_h": 12, "rr_interval_min": 0,
    "report_consent": None, "auto_report": True, "report_interval_min": 30,
    "sub_user_agent": "Happ/2.0.0",
}


class Store:
    def __init__(self):
        self.lock = threading.RLock()
        self.data = {"settings": dict(DEFAULT_SETTINGS), "subscriptions": [], "servers": [], "stats": {},
                     "selected": None, "rr_index": 0, "hwid": uuid.uuid4().hex, "pending_report": None}
        self.load()

    def load(self):
        try:
            d = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            for k, v in d.items():
                if k == "settings":
                    self.data["settings"].update(v)
                else:
                    self.data[k] = v
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.error(f"Не удалось прочитать state.json: {e}")

    def save(self):
        with self.lock:
            try:
                tmp = STATE_FILE.with_suffix(".tmp")
                tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1), encoding="utf-8")
                tmp.replace(STATE_FILE)
            except Exception as e:
                logger.error(f"Сохранение state.json: {e}")

    def set_stat(self, pid, ping, method):
        with self.lock:
            old = self.data["stats"].get(pid) or {}
            ok = ping is not None
            if method == "tcp" and old.get("method") == "deep" and time.time() - old.get("ts", 0) < 3600:
                ok = old.get("ok")            # свежий глубокий тест важнее TCP
                self.data["stats"][pid] = {**old, "ts": time.time()}
                return
            self.data["stats"][pid] = {"ping": ping, "ok": ok, "ts": time.time(), "method": method}


# ===================================================================
# 7. UI-КОМПОНЕНТЫ
# ===================================================================
C = {"bg": "#0b0b0e", "bg2": "#131318", "surface": "#1c1c22", "surface_light": "#2a2a33",
     "text": "#ffffff", "text_dim": "#8e8e98", "accent": "#4a6cf7", "connected": "#34c759",
     "disconnected": "#636370", "error": "#ff453a", "warning": "#ff9f0a", "border": "#2c2c34"}


def blend(a, b, t):
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x * t + y * (1 - t)) for x, y in zip(ca, cb))


class Toggle(tk.Canvas):
    def __init__(self, parent, var, bg):
        super().__init__(parent, width=46, height=26, bg=bg, highlightthickness=0, cursor="hand2")
        self.var = var
        self.bind("<Button-1>", lambda e: var.set(not var.get()))
        var.trace_add("write", lambda *a: self._draw())
        self._draw()

    def _draw(self):
        self.delete("all")
        on = bool(self.var.get())
        col = C["accent"] if on else C["surface_light"]
        self.create_oval(1, 1, 25, 25, fill=col, outline=col)
        self.create_oval(21, 1, 45, 25, fill=col, outline=col)
        self.create_rectangle(13, 1, 33, 25, fill=col, outline=col)
        x = 23 if on else 3
        self.create_oval(x, 3, x + 20, 23, fill="#ffffff", outline="#ffffff")


class Segmented(tk.Frame):
    def __init__(self, parent, options, var):
        super().__init__(parent, bg=C["surface"])
        self.var, self.btns = var, {}
        for label, val in options:
            b = tk.Label(self, text=label, font=("Helvetica", 10, "bold"), padx=8, pady=7, cursor="hand2")
            b.pack(side="left", expand=True, fill="x", padx=2, pady=2)
            b.bind("<Button-1>", lambda e, v=val: var.set(v))
            self.btns[val] = b
        var.trace_add("write", lambda *a: self._paint())
        self._paint()

    def _paint(self):
        for v, b in self.btns.items():
            sel = v == self.var.get()
            b.configure(bg=C["accent"] if sel else C["surface"], fg="#fff" if sel else C["text_dim"])


# ===================================================================
# 8. ПРИЛОЖЕНИЕ
# ===================================================================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(APP_NAME)
        root.configure(bg=C["bg"])
        root.geometry("420x820")
        root.minsize(400, 760)

        self.store = Store()
        self.cores = {k: CoreManager(k) for k in CORE_SPECS}
        self.state = "disconnected"
        self.current = None
        self.active_core = None
        self.connected_at = None
        self._angle = 0
        self._cancel = threading.Event()
        self._task_lock = threading.Lock()
        self._reconnect_fail = 0
        self._last_report = 0.0
        self._last_sub_check = time.time()
        self._last_pending = 0.0
        self._updating = set()
        self.row_map = []
        self.client_cache = (0.0, {})

        self.uiq = queue.Queue()
        self.log_queue = queue.Queue()
        logger.addHandler(QueueLogHandler(self.log_queue))

        self._build_ui()
        self._pump()
        self._tick_fast()
        self._tick_slow()
        self._tick_log()
        self.refresh_list()
        self._update_home()
        self.root.after(600, self._startup)

    # ---------- общие ----------
    def post(self, fn):
        self.uiq.put(fn)

    def _pump(self):
        try:
            while True:
                self.uiq.get_nowait()()
        except queue.Empty:
            pass
        except Exception:
            logger.exception("UI error")
        self.root.after(40, self._pump)

    def s(self, key):
        return self.store.data["settings"][key]

    def font(self, size=11, bold=False):
        return ("Helvetica", size, "bold" if bold else "normal")

    def all_profiles(self):
        res = []
        for sub in self.store.data["subscriptions"]:
            res += sub["profiles"]
        return res + self.store.data["servers"]

    def profile_by_id(self, pid):
        return next((p for p in self.all_profiles() if p["id"] == pid), None)

    def stat(self, p):
        return self.store.data["stats"].get(p["id"]) or {}

    def routing(self):
        return {k: self.s(k) for k in ("bypass_lan", "bypass_ru", "adblock", "direct_domains")}

    def core_for(self, p):
        return "singbox" if p["type"] == "hysteria2" else self.s("core")

    def http_port(self, core):
        sp = int(self.s("socks_port"))
        return sp if core == "singbox" else sp + 1

    def _bind(self, key, var):
        def cb(*a):
            try:
                v = var.get()
            except tk.TclError:
                return
            self.store.data["settings"][key] = v
            self.store.save()
        var.trace_add("write", cb)

    # ---------- построение UI ----------
    def _build_ui(self):
        top = tk.Frame(self.root, bg=C["bg"])
        top.pack(fill="x", padx=18, pady=(14, 4))
        tk.Label(top, text="Happ", font=self.font(20, True), fg=C["text"], bg=C["bg"]).pack(side="left")
        self.top_info = tk.Label(top, text="", font=self.font(9), fg=C["text_dim"], bg=C["bg"])
        self.top_info.pack(side="right")

        self.nav = tk.Frame(self.root, bg=C["bg2"])
        self.nav.pack(side="bottom", fill="x")
        self.body = tk.Frame(self.root, bg=C["bg"])
        self.body.pack(fill="both", expand=True, padx=18)

        self.pages, self.nav_btns = {}, {}
        for pid, icon, label in (("home", "⌂", "Главная"), ("servers", "☰", "Серверы"), ("route", "⇆", "Маршрут"),
                                 ("settings", "⚙", "Настройки"), ("log", "≣", "Лог")):
            b = tk.Label(self.nav, text=f"{icon}\n{label}", font=self.font(9, True), fg=C["text_dim"], bg=C["bg2"],
                         pady=8, cursor="hand2")
            b.pack(side="left", expand=True, fill="x")
            b.bind("<Button-1>", lambda e, p=pid: self.show_page(p))
            self.nav_btns[pid] = b
            self.pages[pid] = tk.Frame(self.body, bg=C["bg"])

        self.mode_var = tk.StringVar(value=self.s("mode"))
        self.core_var = tk.StringVar(value=self.s("core"))
        self._bind("mode", self.mode_var)
        self._bind("core", self.core_var)

        self._build_home()
        self._build_servers()
        self._build_route()
        self._build_settings()
        self._build_log()
        self.show_page("home")

    def show_page(self, pid):
        for p, f in self.pages.items():
            f.pack_forget()
            self.nav_btns[p].configure(fg=C["accent"] if p == pid else C["text_dim"])
        self.pages[pid].pack(fill="both", expand=True)

    def _build_home(self):
        f = self.pages["home"]
        self.power = tk.Canvas(f, width=200, height=200, bg=C["bg"], highlightthickness=0, cursor="hand2")
        self.power.pack(pady=(14, 4))
        self.power.bind("<Button-1>", lambda e: self.toggle_connection())
        self.status_label = tk.Label(f, text="Не подключено", font=self.font(15, True), fg=C["text_dim"], bg=C["bg"])
        self.status_label.pack()
        self.timer_label = tk.Label(f, text="", font=self.font(10), fg=C["text_dim"], bg=C["bg"])
        self.timer_label.pack(pady=(2, 12))

        card = tk.Frame(f, bg=C["surface"], padx=14, pady=10)
        card.pack(fill="x", pady=(0, 10))
        self.cc_badge = tk.Label(card, text="--", font=self.font(12, True), fg="#fff", bg=C["accent"], width=4, pady=6)
        self.cc_badge.pack(side="left")
        mid = tk.Frame(card, bg=C["surface"])
        mid.pack(side="left", fill="x", expand=True, padx=12)
        self.node_name = tk.Label(mid, text="Сервер не выбран", font=self.font(12, True), fg=C["text"], bg=C["surface"], anchor="w")
        self.node_name.pack(fill="x")
        self.node_sub = tk.Label(mid, text="Открой «Серверы» и добавь подписку", font=self.font(9), fg=C["text_dim"], bg=C["surface"], anchor="w")
        self.node_sub.pack(fill="x")

        tk.Label(f, text="Режим выбора сервера", font=self.font(9, True), fg=C["text_dim"], bg=C["bg"], anchor="w").pack(fill="x")
        Segmented(f, (("Вручную", "manual"), ("Быстрейший", "fastest"), ("Round-robin", "round_robin")), self.mode_var).pack(fill="x", pady=(3, 10))
        tk.Label(f, text="Ядро", font=self.font(9, True), fg=C["text_dim"], bg=C["bg"], anchor="w").pack(fill="x")
        Segmented(f, (("Xray", "xray"), ("Sing-box", "singbox")), self.core_var).pack(fill="x", pady=(3, 10))
        self.stats_label = tk.Label(f, text="", font=self.font(9), fg=C["text_dim"], bg=C["bg"], justify="left")
        self.stats_label.pack(anchor="w")

    def _btn(self, parent, text, cmd, accent=False, danger=False):
        bg = C["accent"] if accent else C["surface_light"]
        fg = C["error"] if danger else "#fff"
        b = tk.Label(parent, text=text, font=self.font(10, True), bg=bg, fg=fg, padx=10, pady=8, cursor="hand2")
        b.bind("<Button-1>", lambda e: cmd())
        b.bind("<Enter>", lambda e: b.configure(bg=blend(bg, "#ffffff", 0.85)))
        b.bind("<Leave>", lambda e: b.configure(bg=bg))
        return b

    def _build_servers(self):
        f = self.pages["servers"]
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_list())
        e = tk.Entry(f, textvariable=self.search_var, font=self.font(11), bg=C["surface"], fg=C["text"],
                     insertbackground="#fff", relief="flat", highlightthickness=1, highlightbackground=C["border"], highlightcolor=C["accent"])
        e.pack(fill="x", ipady=7, pady=(4, 8))
        lf = tk.Frame(f, bg=C["surface"])
        lf.pack(fill="both", expand=True)
        self.listbox = tk.Listbox(lf, font=("Courier", 10), bg=C["surface"], fg=C["text"], selectbackground=C["accent"],
                                  selectforeground="#fff", relief="flat", highlightthickness=0, borderwidth=0, activestyle="none")
        sb = tk.Scrollbar(lf, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.listbox.pack(fill="both", expand=True, padx=4, pady=4)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        self.listbox.bind("<Double-Button-1>", lambda e: self.connect_selected())
        self.task_label = tk.Label(f, text="", font=self.font(9), fg=C["text_dim"], bg=C["bg"], anchor="w")
        self.task_label.pack(fill="x", pady=(6, 2))
        for row in ((("+ Добавить", self.add_dialog, True), ("Обновить подписки", lambda: self.update_subscriptions(True), False)),
                    (("Пинг (TCP)", self.run_tcp_test, False), ("Глубокий тест", self.run_deep_test, False)),
                    (("Отправить отчёт", self.report_now, False), ("Удалить", self.delete_selected, False))):
            r = tk.Frame(f, bg=C["bg"])
            r.pack(fill="x", pady=2)
            for i, (t, c, acc) in enumerate(row):
                self._btn(r, t, c, accent=acc, danger=(t == "Удалить")).pack(side="left", expand=True, fill="x", padx=(0 if i == 0 else 3, 0))

    def _row(self, parent, title, desc, widget_fn):
        box = tk.Frame(parent, bg=C["surface"], padx=12, pady=8)
        box.pack(fill="x", pady=3)
        left = tk.Frame(box, bg=C["surface"])
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text=title, font=self.font(11, True), fg=C["text"], bg=C["surface"], anchor="w").pack(fill="x")
        if desc:
            tk.Label(left, text=desc, font=self.font(8), fg=C["text_dim"], bg=C["surface"], anchor="w", justify="left", wraplength=250).pack(fill="x")
        widget_fn(box).pack(side="right")

    def _toggle_row(self, parent, key, title, desc, on_change=None):
        var = tk.BooleanVar(value=bool(self.s(key)))
        self._bind(key, var)
        if on_change:
            var.trace_add("write", lambda *a: on_change(var.get()))
        self._row(parent, title, desc, lambda p: Toggle(p, var, C["surface"]))
        return var

    def _entry_row(self, parent, key, title, desc, width=10, kind="str"):
        var = tk.IntVar(value=self.s(key)) if kind == "int" else tk.StringVar(value=self.s(key))
        self._bind(key, var)
        self._row(parent, title, desc, lambda p: tk.Entry(p, textvariable=var, width=width, font=self.font(10), bg=C["surface_light"],
                                                          fg=C["text"], insertbackground="#fff", relief="flat", justify="center"))

    def _build_route(self):
        f = self.pages["route"]
        tk.Label(f, text="Маршрутизация", font=self.font(15, True), fg=C["text"], bg=C["bg"], anchor="w").pack(fill="x", pady=(6, 8))
        self._toggle_row(f, "bypass_lan", "Обход локальных сетей", "Локальные адреса идут напрямую")
        self._toggle_row(f, "bypass_ru", "Обход .ru / .рф / .su", "Эти домены идут напрямую")
        self._toggle_row(f, "adblock", "Блокировка рекламы", "Только Xray (нужен geosite.dat)")
        self._entry_row(f, "direct_domains", "Свои домены напрямую", "Через запятую: example.com, site.org", 18)
        tk.Label(f, text="Изменения применяются при следующем подключении.", font=self.font(8), fg=C["text_dim"], bg=C["bg"]).pack(anchor="w", pady=6)

    def _build_settings(self):
        f = self.pages["settings"]
        tk.Label(f, text="Настройки", font=self.font(15, True), fg=C["text"], bg=C["bg"], anchor="w").pack(fill="x", pady=(6, 4))
        self._toggle_row(f, "system_proxy", "Системный прокси", "Включать при подключении",
                         lambda v: self.state == "connected" and threading.Thread(target=set_system_proxy, args=(v, self.http_port(self.active_core)), daemon=True).start())
        self._toggle_row(f, "auto_connect", "Автоподключение", "При запуске приложения")
        self._toggle_row(f, "auto_reconnect", "Автопереподключение", "Если ядро упало — следующий сервер")
        self._toggle_row(f, "verify_connect", "Проверка при подключении", "HEAD через прокси, иначе — failover")
        self._toggle_row(f, "update_on_start", "Обновлять подписки при старте", "")
        self._entry_row(f, "sub_interval_h", "Обновление подписок, ч", "Интервал авто-обновления", 5, "int")
        self._entry_row(f, "rr_interval_min", "Ротация round-robin, мин", "0 — только при подключении", 5, "int")
        self._entry_row(f, "socks_port", "SOCKS-порт", "HTTP = порт+1 (Xray)", 7, "int")
        self._entry_row(f, "sub_user_agent", "User-Agent подписок", "", 14)
        self.report_var = tk.BooleanVar(value=self.s("report_consent") is True)
        self.report_var.trace_add("write", lambda *a: self._on_report_toggle())
        self._row(f, "Отчёт на сервер", "IP/ASN/ISP, тип сети, ОС, белые домены и ссылки серверов",
                  lambda p: Toggle(p, self.report_var, C["surface"]))
        self._entry_row(f, "report_interval_min", "Период отчёта, мин", "", 5, "int")
        r = tk.Frame(f, bg=C["bg"])
        r.pack(fill="x", pady=6)
        self._btn(r, "Отправить сейчас", self.report_now, accent=True).pack(side="left", expand=True, fill="x", padx=(0, 3))
        self._btn(r, "Белые домены", self.run_whitelist).pack(side="left", expand=True, fill="x")

    def _build_log(self):
        f = self.pages["log"]
        self.log_text = tk.Text(f, font=("Courier", 8), bg=C["bg2"], fg="#b6f7c1", relief="flat", wrap="word", state="disabled", borderwidth=0)
        self.log_text.pack(fill="both", expand=True, pady=(6, 6))
        for lvl, col in (("WARNING", C["warning"]), ("ERROR", C["error"])):
            self.log_text.tag_configure(lvl, foreground=col)
        self._btn(f, "Очистить", lambda: (self.log_text.configure(state="normal"), self.log_text.delete("1.0", "end"), self.log_text.configure(state="disabled"))).pack(fill="x")

    def _tick_log(self):
        try:
            while True:
                lvl, msg = self.log_queue.get_nowait()
                self.log_text.configure(state="normal")
                self.log_text.insert("end", msg + "\n", lvl)
                if int(self.log_text.index("end-1c").split(".")[0]) > 1500:
                    self.log_text.delete("1.0", "300.0")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(250, self._tick_log)

    # ---------- кнопка питания ----------
    def _draw_power(self):
        c = self.power
        c.delete("all")
        col = {"disconnected": C["disconnected"], "connecting": C["warning"], "connected": C["connected"], "error": C["error"]}[self.state]
        c.create_oval(10, 10, 190, 190, outline=blend(col, C["bg"], 0.35), width=2, fill=C["bg2"])
        c.create_oval(24, 24, 176, 176, outline=col, width=4, fill=C["surface"])
        if self.state == "connecting":
            c.create_arc(10, 10, 190, 190, start=-self._angle * 6, extent=110, style="arc", outline=col, width=5)
        c.create_arc(70, 72, 130, 132, start=125, extent=290, style="arc", outline=col, width=7)
        c.create_line(100, 62, 100, 102, fill=col, width=7, capstyle="round")

    def set_state(self, state, msg=None):
        self.state = state
        texts = {"disconnected": ("Не подключено", C["text_dim"]), "connecting": ("Подключение...", C["warning"]),
                 "connected": ("Подключено", C["connected"]), "error": (msg or "Ошибка", C["error"])}
        t, col = texts[state]
        self.status_label.configure(text=t, fg=col)
        if state != "connected":
            self.connected_at = None
            self.timer_label.configure(text="")
        self._draw_power()
        self._update_home()

    def _update_home(self):
        p = self.current if self.state == "connected" else self.profile_by_id(self.store.data["selected"])
        if p:
            st = self.stat(p)
            ping = f" · {st['ping']} мс" if st.get("ping") else ""
            self.cc_badge.configure(text=p["cc"])
            self.node_name.configure(text=p["name"][:30])
            core = {"xray": "Xray", "singbox": "Sing-box"}[self.active_core if self.state == "connected" else self.core_for(p)]
            self.node_sub.configure(text=f"{p['type'].upper()}{ping} · {core}")
        else:
            self.cc_badge.configure(text="--")
            self.node_name.configure(text="Сервер не выбран")
            self.node_sub.configure(text="Открой «Серверы» и добавь подписку")
        profs = self.all_profiles()
        okc = sum(1 for x in profs if self.stat(x).get("ok") is True)
        bad = sum(1 for x in profs if self.stat(x).get("ok") is False)
        self.stats_label.configure(text=f"Подписок: {len(self.store.data['subscriptions'])}   Серверов: {len(profs)}\nРабочих: {okc}   Нерабочих: {bad}")
        self.top_info.configure(text=f"v{APP_VERSION}")

    def _tick_fast(self):
        self._angle += 1
        if self.state == "connecting":
            self._draw_power()
        if self.connected_at and self._angle % 16 == 0:
            e = int(time.time() - self.connected_at)
            self.timer_label.configure(text=f"{e // 3600:02d}:{e % 3600 // 60:02d}:{e % 60:02d}")
        self.root.after(60, self._tick_fast)

    # ---------- список серверов ----------
    def refresh_list(self):
        q = self.search_var.get().strip().lower()
        lb = self.listbox
        lb.delete(0, "end")
        self.row_map = []
        groups = []
        for sub in self.store.data["subscriptions"]:
            groups.append((sub, sub["profiles"]))
        if self.store.data["servers"]:
            groups.append((None, self.store.data["servers"]))
        sel = self.store.data["selected"]
        for sub, profs in groups:
            shown = [p for p in profs if not q or q in p["name"].lower() or q in p["host"].lower()]
            if q and not shown:
                continue
            title = sub["name"] if sub else "Мои серверы"
            info = sub.get("info") if sub else None
            if info and info.get("total"):
                used = info.get("upload", 0) + info.get("download", 0)
                title += f" · {fmt_bytes(used)}/{fmt_bytes(info['total'])}"
            if info and info.get("expire"):
                title += " · до " + datetime.fromtimestamp(info["expire"]).strftime("%d.%m.%y")
            lb.insert("end", f"▎{title}")
            lb.itemconfig(lb.size() - 1, fg=C["accent"])
            self.row_map.append(("sub", sub))
            for p in shown:
                st = self.stat(p)
                if st.get("ok") is False:
                    ptxt, col = "  ✖", C["error"]
                elif st.get("ping"):
                    ms = st["ping"]
                    ptxt, col = f"{ms:>4}мс", (C["connected"] if ms < 150 else C["warning"] if ms < 350 else "#ff7a45")
                else:
                    ptxt, col = "  ···", C["text_dim"]
                mark = "●" if p["id"] == sel else " "
                lb.insert("end", f"{mark}[{p['cc']}] {p['name'][:22]:<22} {ptxt}")
                lb.itemconfig(lb.size() - 1, fg=col)
                self.row_map.append(("srv", p))
                if p["id"] == sel:
                    lb.selection_set(lb.size() - 1)
        self._update_home()

    def _on_select(self, e):
        idx = self.listbox.curselection()
        if not idx or idx[0] >= len(self.row_map):
            return
        kind, obj = self.row_map[idx[0]]
        if kind == "srv":
            self.store.data["selected"] = obj["id"]
            self.store.save()
            self.refresh_list()

    def selected_row(self):
        idx = self.listbox.curselection()
        return self.row_map[idx[0]] if idx and idx[0] < len(self.row_map) else (None, None)

    def delete_selected(self):
        kind, obj = self.selected_row()
        if kind is None:
            return
        if self.state in ("connected", "connecting"):
            messagebox.showinfo("Удаление", "Сначала отключись.")
            return
        d = self.store.data
        if kind == "sub":
            if obj is None or not messagebox.askyesno("Подписка", f"Удалить подписку «{obj['name']}» и все её серверы?"):
                return
            d["subscriptions"].remove(obj)
        else:
            for sub in d["subscriptions"]:
                if obj in sub["profiles"]:
                    sub["profiles"].remove(obj)
            if obj in d["servers"]:
                d["servers"].remove(obj)
            if d["selected"] == obj["id"]:
                d["selected"] = None
        self.store.save()
        self.refresh_list()

    # ---------- добавление ----------
    def add_dialog(self):
        top = tk.Toplevel(self.root)
        top.title("Добавить")
        top.configure(bg=C["bg"])
        top.geometry("380x270")
        top.transient(self.root)
        tk.Label(top, text="Ссылка на подписку или серверы", font=self.font(11, True), fg=C["text"], bg=C["bg"]).pack(anchor="w", padx=14, pady=(12, 4))
        txt = tk.Text(top, height=8, font=("Courier", 9), bg=C["surface"], fg=C["text"], insertbackground="#fff", relief="flat", wrap="char")
        txt.pack(fill="both", expand=True, padx=14)
        try:
            clip = self.root.clipboard_get().strip()
            if "://" in clip:
                txt.insert("1.0", clip)
        except tk.TclError:
            pass

        def ok():
            v = txt.get("1.0", "end").strip()
            top.destroy()
            if v:
                self.add_input(v)
        r = tk.Frame(top, bg=C["bg"])
        r.pack(fill="x", padx=14, pady=10)
        self._btn(r, "Добавить", ok, accent=True).pack(side="left", expand=True, fill="x", padx=(0, 3))
        self._btn(r, "Отмена", top.destroy).pack(side="left", expand=True, fill="x")

    def add_input(self, text: str):
        added_srv, new_subs = [], []
        direct = [ln.strip() for ln in text.splitlines() if ln.strip()]
        for ln in direct:
            url = extract_sub_url(ln) or (ln if ln.lower().startswith(("http://", "https://")) else None)
            if url:
                if not any(s["url"] == url for s in self.store.data["subscriptions"]):
                    sub = {"id": uuid.uuid4().hex[:8], "name": urlparse(url).hostname or "Подписка", "url": url,
                           "profiles": [], "info": {}, "updated": 0, "interval_h": None}
                    self.store.data["subscriptions"].append(sub)
                    new_subs.append(sub)
                continue
            p = parse_uri(ln)
            if p:
                added_srv.append(p)
            else:
                added_srv += parse_subscription(ln)
        known = {p["id"] for p in self.all_profiles()}
        for p in added_srv:
            if p["id"] not in known:
                self.store.data["servers"].append(p)
                known.add(p["id"])
        if not added_srv and not new_subs:
            messagebox.showerror("Ошибка", "Не удалось распознать ссылку.")
            return
        self.store.save()
        self.refresh_list()
        logger.info(f"Добавлено: подписок {len(new_subs)}, серверов {len(added_srv)}")
        if new_subs:
            self.update_subscriptions(True, only=new_subs)

    # ---------- подписки ----------
    def _vpn_socks(self):
        return int(self.s("socks_port")) if self.state == "connected" else None

    def fetch_subscription(self, sub):
        h = {"User-Agent": self.s("sub_user_agent"), "x-hwid": self.store.data["hwid"], "x-device-os": platform.system(),
             "x-ver-os": platform.release(), "x-device-model": platform.node() or "PC", "Accept": "*/*"}
        try:
            st, hdr, body = http_request("GET", sub["url"], h, None, None, 20)
        except Exception as e:
            if self._vpn_socks():
                st, hdr, body = http_request("GET", sub["url"], h, None, self._vpn_socks(), 20)
            else:
                raise e
        if st != 200:
            raise RuntimeError(f"HTTP {st}")
        return hdr, parse_subscription(body.decode("utf-8", "ignore"))

    def update_subscriptions(self, force=False, only=None):
        subs = only or list(self.store.data["subscriptions"])
        if not subs:
            if force:
                logger.info("Подписок нет.")
            return

        def work():
            for sub in subs:
                age = time.time() - sub.get("updated", 0)
                limit = (sub.get("interval_h") or self.s("sub_interval_h") or 12) * 3600
                if not force and age < limit:
                    continue
                if sub["id"] in self._updating:
                    continue
                self._updating.add(sub["id"])
                try:
                    hdr, profs = self.fetch_subscription(sub)
                    if not profs:
                        raise RuntimeError("пустая подписка")
                    self.post(lambda s=sub, h=hdr, p=profs: self._apply_sub(s, h, p))
                except Exception as e:
                    logger.error(f"Подписка «{sub['name']}»: {e}")
                finally:
                    self._updating.discard(sub["id"])
        threading.Thread(target=work, daemon=True).start()

    def _apply_sub(self, sub, hdr, profs):
        title = hdr.get("profile-title", "")
        if title.startswith("base64:"):
            try:
                title = base64.b64decode(title[7:] + "===").decode("utf-8", "ignore")
            except Exception:
                title = ""
        if title:
            sub["name"] = clean_name(title) or sub["name"]
        info = {}
        for part in hdr.get("subscription-userinfo", "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                try:
                    info[k] = int(float(v))
                except ValueError:
                    pass
        sub["info"] = info
        try:
            sub["interval_h"] = int(hdr["profile-update-interval"]) or None
        except (KeyError, ValueError):
            pass
        sub["profiles"], sub["updated"] = profs, time.time()
        self.store.save()
        self.refresh_list()
        logger.info(f"Подписка «{sub['name']}»: серверов {len(profs)}")

    # ---------- тесты ----------
    def run_task(self, name, fn):
        if not self._task_lock.acquire(blocking=False):
            logger.warning("Уже идёт другая проверка.")
            return

        def wrap():
            try:
                fn()
            except Exception:
                logger.exception(name)
            finally:
                self._task_lock.release()
                self.post(lambda: self.task_label.configure(text=""))
        threading.Thread(target=wrap, daemon=True).start()

    def _progress(self, text):
        self.post(lambda: self.task_label.configure(text=text))

    def tcp_test(self, profs, only_stale=0):
        todo = [p for p in profs if p["type"] != "hysteria2" and time.time() - self.stat(p).get("ts", 0) >= only_stale]
        if not todo:
            return
        done = 0
        with ThreadPoolExecutor(32) as ex:
            for p, ms in ex.map(lambda p: (p, tcp_ping(p["host"], p["port"], 3)), todo):
                self.store.set_stat(p["id"], ms, "tcp")
                done += 1
                if done % 8 == 0:
                    self._progress(f"TCP-пинг {done}/{len(todo)}")
        self.store.save()
        self.post(self.refresh_list)

    def run_tcp_test(self):
        self.run_task("tcp", lambda: (self.tcp_test(self.all_profiles()), self._after_test()))

    def _after_test(self):
        if self.s("report_consent") is True and self.s("auto_report"):
            self._report_worker()

    def deep_one(self, p):
        key = self.core_for(p)
        cm = CoreManager(key, quiet=True)
        port = free_port()
        try:
            cfg = build_config(key, p, port, None, None)
        except Exception:
            return None
        name = f"test_{port}"
        try:
            if not cm.start(cfg, name) or not wait_port(port, 5, cm.is_running):
                return None
            ok, st, ms = http_head(VERIFY_HOST, VERIFY_PATH, port, 8)
            return ms if ok and st and 200 <= st < 400 else None
        finally:
            cm.stop()
            (APP_DIR / f"{name}.json").unlink(missing_ok=True)

    def deep_test(self):
        profs = self.all_profiles()
        if not profs:
            return
        for k in {self.core_for(p) for p in profs}:
            if not CoreManager(k).find_binary():
                logger.error(f"Для глубокого теста нужен бинарник {CORE_SPECS[k][1]}.")
                return
        done = 0
        with ThreadPoolExecutor(6) as ex:
            for p, ms in ex.map(lambda p: (p, self.deep_one(p)), profs):
                self.store.set_stat(p["id"], ms, "deep")
                done += 1
                self._progress(f"Глубокий тест {done}/{len(profs)}")
                if done % 5 == 0:
                    self.post(self.refresh_list)
        self.store.save()
        self.post(self.refresh_list)
        logger.info("Глубокий тест завершён.")

    def run_deep_test(self):
        self.run_task("deep", lambda: (self.deep_test(), self._after_test()))

    def run_whitelist(self):
        def work():
            res = check_whitelist(self._vpn_socks())
            for d, v in res.items():
                logger.info(f"HEAD {d}: {'OK ' + str(v['status']) + ' ' + str(v['ms']) + 'мс' if v['ok'] else 'недоступен'}")
        threading.Thread(target=work, daemon=True).start()
        self.show_page("log")

    # ---------- подключение ----------
    def toggle_connection(self):
        if self.state in ("connecting", "connected"):
            self.disconnect()
        else:
            self.start_connect()

    def connect_selected(self):
        if self.state != "disconnected" and self.state != "error":
            self.disconnect(then=lambda: self._force_manual_connect())
        else:
            self._force_manual_connect()

    def _force_manual_connect(self):
        self.mode_var.set("manual")
        self.start_connect()

    def candidates(self):
        mode, profs, d = self.s("mode"), self.all_profiles(), self.store.data
        if mode == "manual":
            p = self.profile_by_id(d["selected"])
            return [p] if p else []
        alive = [p for p in profs if self.stat(p).get("ok") is not False]
        if mode == "fastest":
            known = sorted([p for p in alive if self.stat(p).get("ping")], key=lambda p: self.stat(p)["ping"])
            return (known + [p for p in alive if p not in known])[:6]
        if not alive:
            return []
        n = len(alive)
        i = d.get("rr_index", 0) % n
        return (alive[i:] + alive[:i])[:6]

    def start_connect(self):
        if self.state == "connecting":
            return
        self._cancel.clear()
        self.set_state("connecting")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _stop_all(self):
        for cm in self.cores.values():
            cm.stop()

    def _connect_worker(self):
        try:
            if self.s("mode") != "manual":
                self._progress("Выбор сервера...")
                self.tcp_test(self.all_profiles(), only_stale=120)
            cands = self.candidates()
            if not cands:
                return self.post(lambda: self._connect_fail("Нет серверов для подключения"))
            socks = int(self.s("socks_port"))
            for p in cands:
                if self._cancel.is_set():
                    return
                key = self.core_for(p)
                self._stop_all()
                try:
                    cfg = build_config(key, p, socks, self.http_port(key) if key == "xray" else None, self.routing())
                except Exception as e:
                    logger.error(f"Конфиг для «{p['name']}»: {e}")
                    continue
                self.post(lambda p=p: (self.cc_badge.configure(text=p["cc"]), self.node_name.configure(text=p["name"][:30])))
                cm = self.cores[key]
                if not cm.start(cfg, f"{key}_active"):
                    if not cm.find_binary():
                        return self.post(lambda: self._connect_fail(f"Не найден {CORE_SPECS[key][1]}"))
                    continue
                if not wait_port(socks, 6, cm.is_running):
                    logger.warning(f"«{p['name']}»: ядро не открыло порт")
                    cm.stop()
                    continue
                if self.s("verify_connect"):
                    ok, st, ms = http_head(VERIFY_HOST, VERIFY_PATH, socks, 8)
                    if not (ok and st and 200 <= st < 400):
                        logger.warning(f"«{p['name']}»: проверка не пройдена, пробую следующий")
                        self.store.set_stat(p["id"], None, "deep")
                        cm.stop()
                        continue
                    self.store.set_stat(p["id"], ms, "deep")
                if self._cancel.is_set():
                    cm.stop()
                    return
                return self.post(lambda p=p, k=key: self._connected(p, k))
            self.post(lambda: self._connect_fail("Ни один сервер не ответил"))
        except Exception as e:
            logger.exception("connect")
            self.post(lambda: self._connect_fail(str(e)))

    def _connected(self, p, key):
        self.current, self.active_core, self.connected_at = p, key, time.time()
        self._reconnect_fail = 0
        d = self.store.data
        if self.s("mode") == "round_robin":
            alive = [x for x in self.all_profiles() if self.stat(x).get("ok") is not False]
            d["rr_index"] = (alive.index(p) + 1) if p in alive else 0
        elif self.s("mode") == "fastest":
            d["selected"] = p["id"]
        self.store.save()
        self.set_state("connected")
        self.refresh_list()
        logger.info(f"Подключено: [{p['cc']}] {p['name']} ({key})")
        if self.s("system_proxy"):
            threading.Thread(target=set_system_proxy, args=(True, self.http_port(key)), daemon=True).start()

    def _connect_fail(self, msg):
        self._stop_all()
        self.current = None
        self.set_state("error", msg[:28])
        logger.error(msg)
        if "Не найден" in msg:
            messagebox.showerror("Ядро", f"{msg}.\nПоложи бинарник рядом со скриптом или в:\n{APP_DIR}")

    def disconnect(self, then=None):
        self._cancel.set()
        was = self.state

        def work():
            self._stop_all()
            if self.s("system_proxy"):
                set_system_proxy(False, 0)

            def fin():
                self.current, self.active_core = None, None
                self.set_state("disconnected")
                if then:
                    then()
            self.post(fin)
        if was != "disconnected":
            threading.Thread(target=work, daemon=True).start()
        elif then:
            then()

    # ---------- периодические задачи ----------
    def _tick_slow(self):
        now = time.time()
        try:
            if self.state == "connected":
                key = self.active_core
                if key and not self.cores[key].is_running():
                    logger.warning("Ядро неожиданно завершилось.")
                    if self.s("auto_reconnect") and self._reconnect_fail < 3:
                        self._reconnect_fail += 1
                        self._rotate()
                    else:
                        self._stop_all()
                        self.set_state("error", "Ядро остановилось")
                elif self.s("mode") == "round_robin" and int(self.s("rr_interval_min") or 0) > 0 \
                        and self.connected_at and now - self.connected_at >= int(self.s("rr_interval_min")) * 60:
                    logger.info("Round-robin: переключаю на следующий сервер.")
                    self._rotate()
            if now - self._last_sub_check > 600:
                self._last_sub_check = now
                self.update_subscriptions(False)
            consent = self.s("report_consent") is True
            if consent and self.s("auto_report") and now - self._last_report > max(5, int(self.s("report_interval_min") or 30)) * 60 \
                    and self.state != "connecting":
                self._last_report = now
                self.run_task("report", lambda: (self.tcp_test(self.all_profiles(), only_stale=300), self._report_worker()))
            if consent and self.store.data.get("pending_report") and now - self._last_pending > 600:
                self._last_pending = now
                threading.Thread(target=self._report_worker, args=(True,), daemon=True).start()
        except Exception:
            logger.exception("tick")
        self.root.after(5000, self._tick_slow)

    def _rotate(self, advance=True):
        self._cancel.clear()
        self._stop_all()
        self.set_state("connecting")
        threading.Thread(target=self._connect_worker, daemon=True).start()

    def _startup(self):
        if self.s("report_consent") is None:
            self._ask_consent()
        if self.s("update_on_start"):
            self.update_subscriptions(True)
        if self.s("auto_connect") and self.all_profiles():
            self.root.after(2500, self.start_connect)
        if self.s("report_consent") is True and self.s("auto_report"):
            self._last_report = time.time()
            self.run_task("report", lambda: (self.tcp_test(self.all_profiles()), self._report_worker()))

    # ---------- отчёт ----------
    DISCLOSURE = ("Приложение может отправлять отчёт на сервер\n" + REPORT_API + "\n\n"
                  "Что уходит:\n• IP, ASN, страна, провайдер (ISP/ORG)\n• тип сети (Wi-Fi/LTE) и ОС\n"
                  "• доступность music.yandex.ru, maps.yandex.ru, max.ru\n"
                  "• ССЫЛКИ рабочих и нерабочих серверов — они содержат ключи доступа!\n\n"
                  "Разрешить отправку?")

    def _ask_consent(self) -> bool:
        ok = messagebox.askyesno("Отчёт о серверах", self.DISCLOSURE)
        self.store.data["settings"]["report_consent"] = bool(ok)
        self.store.save()
        self.report_var.set(bool(ok))
        return bool(ok)

    def _on_report_toggle(self):
        want = self.report_var.get()
        cur = self.s("report_consent") is True
        if want == cur:
            return
        if want and not messagebox.askyesno("Отчёт о серверах", self.DISCLOSURE):
            self.report_var.set(False)
            return
        self.store.data["settings"]["report_consent"] = want
        self.store.save()

    def report_now(self):
        if self.s("report_consent") is not True and not self._ask_consent():
            return
        self.run_task("report", lambda: (self.tcp_test(self.all_profiles(), only_stale=300), self._report_worker(True)))
        self.show_page("log")

    def collect_client(self):
        ts, cached = self.client_cache
        if time.time() - ts < 600 and cached:
            return cached
        info = get_ip_info(self._vpn_socks() if self.state == "connected" else None)
        wl = check_whitelist()
        client = {"asn": info.get("asn", ""), "country_code": info.get("country_code", ""), "isp": info.get("isp", ""),
                  "org": info.get("org", ""), "ip": info.get("ip", ""),
                  "network_type": detect_network_type(info.get("mobile")), "os": platform.platform(),
                  "whitelist_domains": {d: v["ok"] for d, v in wl.items()}}
        self.client_cache = (time.time(), client)
        return client

    def build_report(self):
        working, bad, methods = [], [], set()
        for p in self.all_profiles():
            st = self.stat(p)
            if st.get("ok") is None:
                continue
            (working if st["ok"] else bad).append(p["uri"])
            methods.add(st.get("method"))
        return {"client": self.collect_client(),
                "servers": {"working": list(dict.fromkeys(working)), "not_working": list(dict.fromkeys(bad))},
                "meta": {"app": APP_NAME, "version": APP_VERSION, "sent_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                         "check_method": "deep" if "deep" in methods else "tcp"}}

    def _post_report(self, payload, socks=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        st, _, resp = http_request("POST", REPORT_API, {"Content-Type": "application/json; charset=utf-8",
                                                         "User-Agent": f"HappStyleVPN/{APP_VERSION}"}, body, socks, 15)
        return 200 <= st < 300, f"HTTP {st} {resp[:120].decode('utf-8', 'ignore')}"

    def _report_worker(self, pending_only=False):
        payload = self.store.data.get("pending_report") if pending_only else None
        payload = payload or self.build_report()
        try:
            ok, info = self._post_report(payload)
        except Exception as e:
            ok, info = False, str(e)
            if self._vpn_socks():
                try:
                    ok, info = self._post_report(payload, self._vpn_socks())
                    info += " (через VPN)"
                except Exception as e2:
                    info = f"{e}; через VPN: {e2}"
        if ok:
            self.store.data["pending_report"] = None
            self.store.save()
            logger.info(f"Отчёт отправлен: {info}")
            return
        logger.error(f"API недоступен: {info}")
        wl = check_whitelist()
        reach = [d for d, v in wl.items() if v["ok"]]
        detail = ", ".join(f"{d}={'OK' if v['ok'] else 'нет'}" for d, v in wl.items())
        if len(reach) == len(wl):
            logger.warning(f"HEAD-проверка: {detail}. Белые домены доступны — сеть есть, проблема именно с API.")
        elif reach:
            logger.warning(f"HEAD-проверка: {detail}. Доступны только часть доменов.")
        else:
            logger.warning(f"HEAD-проверка: {detail}. Белые домены недоступны — нет интернета.")
        self.store.data["pending_report"] = payload
        self.store.save()
        logger.info("Отчёт сохранён, повторю позже.")

    # ---------- завершение ----------
    def shutdown(self):
        logger.info("Завершение работы...")
        try:
            self._cancel.set()
            self._stop_all()
            if self.s("system_proxy") and self.state == "connected":
                set_system_proxy(False, 0)
            self.store.save()
        finally:
            self.root.destroy()


def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.shutdown)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        app.shutdown()


if __name__ == "__main__":
    main()
