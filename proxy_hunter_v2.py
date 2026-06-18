#!/usr/bin/env python3
"""
PROXY HUNTER v2 — Research-Grade Open Proxy Detection Framework
================================================================

Perubahan utama dari v1:
  1. DETECTION-VECTOR TRACKING
     - Setiap proxy yang ditemukan mencatat "vektor deteksi" apa yang
       mengungkapnya: banner, handshake-success, response-pattern, dll.
     - Memungkinkan analisis: "sinyal apa yang paling sering membongkar
       open proxy di internet?" → berguna untuk defensive research.

  2. OPTIMASI ASYNC
     - save_results() kini non-blocking (aiofiles + run_in_executor).
     - Debounced save (max 1 save per N detik), bukan setiap 10 proxy.
     - Session dibuka via `async with` (aman dari leak).
     - Per-source rate limit + retry exponential backoff.
     - User-Agent rotation untuk menghindari pemblokiran sumber.

  3. PEMBATASAN YANG DIPERLONGGAR (tapi tetap aman)
     - MAX_CONCURRENT dapat di-override via CLI (default 1000).
     - SCAN_RANDOM_IPS di-enable via CLI flag --random-scan N.
     - Filter BOGON TETAP DIPERTAHANKAN — ini bukan pembatasan performa,
       melainkan pengaman agar tidak memindai infrastruktur internal/
       kritis (10.0.0.0/8, 127.0.0.0/8, dll). Men-on-kan ini = bug.

PERINGATAN HUKUM & ETIKA (tidak berubah dari v1):
  - Hanya gunakan untuk riset yang sah & authorized.
  - Memindai IP milik pihak lain tanpa izin dapat melanggar hukum
    (UU ITE Pasal 30 di Indonesia, CFAA di AS, dsb).
  - Pertimbangkan untuk memindai hanya subnet yang Anda miliki izin.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import aiohttp
except ImportError:
    sys.stderr.write("[!] aiohttp tidak terinstall. Jalankan: pip install aiohttp aiofiles\n")
    sys.exit(1)

try:
    import aiofiles
    HAS_AIOFILES = True
except ImportError:
    HAS_AIOFILES = False
    sys.stderr.write("[!] aiofiles tidak terinstall; fallback ke blocking I/O.\n")


# ======================== KONFIGURASI DEFAULT ========================
DEFAULT_CONFIG = {
    "TIMEOUT": 8,
    "MAX_CONCURRENT": 1000,         # naik dari 500 → 1000 (dapat di-override CLI)
    "TEST_URL": "http://httpbin.org/ip",
    "TEST_URL_HTTPS": "https://httpbin.org/ip",
    "OUTPUT_DIR": "proxy_hunter_out",
    "OUTPUT_TXT": "working_proxies.txt",
    "OUTPUT_JSONL": "working_proxies.jsonl",   # streaming JSON Lines
    "OUTPUT_JSON": "working_proxies_detail.json",
    "OUTPUT_VECTORS": "detection_vectors.json", # analisis vektor deteksi
    "PROXY_PORTS": [
        80, 81, 3128, 8000, 8080, 8118, 8888, 9090,
        1080, 1081, 4145, 1085,
        3124, 3127, 4481, 65103,
        9999, 16379, 53281,
    ],
    "SCAN_BATCH_SIZE": 500,         # naik dari 200
    "USER_AGENTS": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "curl/7.88.1",
    ],
    "SAVE_DEBOUNCE_SEC": 5,         # max 1 save per 5 detik
    "SOURCE_TIMEOUT": 20,
    "SOURCE_CONCURRENCY": 50,       # paralel fetch antar sumber
    "SOURCE_RETRIES": 2,
    "SOURCE_BACKOFF_BASE": 1.5,
}

# Sumber daftar proxy publik (diperbarui: hapus yang return HTML)
PROXY_SOURCES = [
    # ProxyScrape
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all",
    # TheSpeedX
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    # clarketm
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    # roosterkid
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    # Monosans
    "https://raw.githubusercontent.com/Monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/Monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/Monosans/proxy-list/main/proxies/socks5.txt",
    # ShiftyTR
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    # openproxylist
    "https://api.openproxylist.xyz/http.txt",
    "https://api.openproxylist.xyz/https.txt",
    "https://api.openproxylist.xyz/socks4.txt",
    "https://api.openproxylist.xyz/socks5.txt",
    # NOTE: proxynova.com dihapus dari v1 karena return HTML, bukan plain text.
]

# ======================== BOGON / SAFETY FILTER ========================
def build_excluded_networks():
    """
    Network yang TIDAK boleh dipindai. Ini bukan pembatasan performa —
    ini pengaman wajib agar scanner tidak:
      - Memindai infrastruktur internal (10/8, 192.168/16, 172.16/12)
      - Memindai loopback (127/8)
      - Memindai link-local (169.254/16)
      - Memindai multicast/reserved (224/4, 240/4)
      - Memindai benchmark/test net (198.18/15, 192.0.2/24, dll)
    """
    excluded = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
        "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    ]
    return [ipaddress.ip_network(n) for n in excluded]


EXCLUDED_NETS = build_excluded_networks()


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return False
        for net in EXCLUDED_NETS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


def random_public_ipv4() -> str:
    while True:
        ip_int = random.randint(1, 0xFFFFFFFF - 1)
        ip_str = str(ipaddress.ip_address(ip_int))
        if is_public_ip(ip_str):
            return ip_str


# ======================== DATA MODEL ========================
@dataclass
class DetectionResult:
    """Hasil deteksi satu proxy, termasuk vektor deteksi untuk riset."""
    proxy: str
    protocol: str                      # http | https | socks4 | socks5
    ip: str
    port: int
    seen_ip: str                       # IP yang dilihat server target
    anonymity: str                     # transparent | anonymous | elite | unknown
    detected_at: str                   # ISO timestamp
    latency_ms: float                  # waktu deteksi
    detection_vectors: list[str] = field(default_factory=list)
    # Contoh vektor:
    #   "http-get-200"        — HTTP GET via proxy berhasil 200
    #   "https-connect-200"   — HTTPS CONNECT via proxy berhasil 200
    #   "socks5-handshake-ok" — SOCKS5 greeting + CONNECT sukses
    #   "socks4-handshake-ok" — SOCKS4 CONNECT reply 0x5A
    #   "banner-matched"      — banner sesuai pola proxy (Squid, etc.)
    #   "origin-leaked"       — field "origin" ter-parse dari response
    source: str = "unknown"            # dari sumber mana proxy ini (untuk random scan: "random")


# ======================== SOCKS HANDSHAKE ========================
async def socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           target_host: str, target_port: int) -> bool:
    writer.write(b"\x05\x01\x00")  # greeting: no auth
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp != b"\x05\x00":
        return False
    try:
        ip_bytes = socket.inet_aton(target_host)
        writer.write(b"\x05\x01\x00\x01" + ip_bytes + struct.pack(">H", target_port))
    except OSError:
        host_bytes = target_host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", target_port))
    await writer.drain()
    reply = await reader.readexactly(4)
    if reply[1] != 0x00:
        return False
    atyp = reply[3]
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    elif atyp == 0x04:
        await reader.readexactly(18)
    return True


async def socks4_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                           target_host: str, target_port: int) -> bool:
    try:
        ip_bytes = socket.inet_aton(target_host)
    except OSError:
        return False
    writer.write(b"\x04\x01" + struct.pack(">H", target_port) + ip_bytes + b"\x00")
    await writer.drain()
    resp = await reader.readexactly(8)
    return resp[1] == 0x5A


# ======================== ANONYMITY CLASSIFICATION ========================
def classify_anonymity(seen_ip: str, proxy_ip: str) -> str:
    if seen_ip in ("unknown", ""):
        return "unknown"
    if seen_ip == proxy_ip:
        return "transparent"
    if proxy_ip in seen_ip:
        return "anonymous"
    return "elite"


# ======================== TRUE HTTPS PROXY (TLS-IN-TLS) ========================
def _test_true_https_proxy_sync(host: str, port: int, source: str,
                                t0: float, ua: str) -> Optional[DetectionResult]:
    """
    Versi sinkron: tes 'true HTTPS proxy' (proxy itu sendiri pakai TLS).

    Menggunakan raw socket + ssl module SECARA PENUH (bukan asyncio.open_connection)
    untuk menghindari konflik ownership socket antara asyncio event loop dan ssl.
    Fungsi ini dijalankan via asyncio.to_thread() dari test_true_https_proxy().

    Alur:
      1. socket.create_connection (TCP ke host:port)
      2. ctx.wrap_socket — TLS layer #1 (client → proxy)
      3. Kirim CONNECT httpbin.org:443
      4. Baca respons 200 Connection Established
      5. ctx2.wrap_socket — TLS layer #2 (client → target, melalui proxy)
         → ini TLS-in-TLS, di-handle ssl module (bukan asyncio) → tidak picu warning
      6. Kirim HTTPS request GET /ip
      7. Parse JSON {origin: "..."}

    Semua operasi memakai socket.settimeout() sehingga tidak ada hang.
    """
    test_host = urlparse(DEFAULT_CONFIG["TEST_URL_HTTPS"]).hostname
    test_port = 443
    timeout_s = DEFAULT_CONFIG["TIMEOUT"]
    vectors = ["https-proxy-tls-attempt"]

    raw_sock = None
    tls_sock = None
    tls_sock2 = None
    try:
        # 1. TCP connect (sinkron, dengan timeout)
        raw_sock = socket.create_connection((host, port), timeout=timeout_s)
        raw_sock.settimeout(timeout_s)

        # 2. TLS handshake ke proxy (layer #1)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        vectors.append("https-proxy-tls-handshake-ok")

        # 3. CONNECT request di dalam tunnel TLS
        connect_req = (
            f"CONNECT {test_host}:{test_port} HTTP/1.1\r\n"
            f"Host: {test_host}:{test_port}\r\n"
            f"User-Agent: {ua}\r\n\r\n"
        ).encode()
        tls_sock.sendall(connect_req)

        # 4. Baca respons CONNECT (cari status 200)
        resp_data = b""
        while b"\r\n\r\n" not in resp_data:
            chunk = tls_sock.recv(4096)
            if not chunk:
                return None
            resp_data += chunk
            if len(resp_data) > 8192:
                return None
        status_line = resp_data.split(b"\r\n", 1)[0].decode(errors="ignore")
        if " 200 " not in status_line and not status_line.endswith(" 200"):
            return None
        vectors.append("https-proxy-connect-200")

        # 5. TLS handshake ke target (layer #2 — TLS-in-TLS)
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        tls_sock2 = ctx2.wrap_socket(tls_sock, server_hostname=test_host)
        vectors.append("https-proxy-target-tls-ok")

        # 6. HTTPS GET /ip
        http_req = (
            f"GET /ip HTTP/1.1\r\nHost: {test_host}\r\n"
            f"User-Agent: {ua}\r\nConnection: close\r\n\r\n"
        ).encode()
        tls_sock2.sendall(http_req)
        body = b""
        while True:
            try:
                chunk = tls_sock2.recv(4096)
            except (ssl.SSLError, OSError):
                break
            if not chunk:
                break
            body += chunk
            if len(body) > 16384:
                break
        text = body.decode(errors="ignore")

        seen_ip = "https-tls-ok"
        if "origin" in text:
            try:
                json_part = text[text.find("{"):text.rfind("}") + 1]
                seen_ip = json.loads(json_part).get("origin", "unknown")
                vectors.append("origin-leaked")
            except Exception:
                pass

        latency = (time.monotonic() - t0) * 1000
        return DetectionResult(
            proxy=f"{host}:{port}",
            protocol="https-tls",   # true HTTPS proxy (TLS to proxy itself)
            ip=host, port=port,
            seen_ip=seen_ip,
            anonymity=classify_anonymity(seen_ip, host),
            detected_at=datetime.now(timezone.utc).isoformat(),
            latency_ms=round(latency, 1),
            detection_vectors=vectors,
            source=source,
        )
    except (socket.timeout, OSError, ssl.SSLError):
        return None
    finally:
        # Tutup socket dalam urutan layer terluar → terdalam.
        # Penting: raw_sock TIDAK perlu di-close terpisah karena sudah di-wrap
        # oleh tls_sock (close tls_sock otomatis close underlying raw_sock).
        for s in (tls_sock2, tls_sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        # raw_sock hanya perlu di-close jika TLS handshake gagal sebelum wrap
        if tls_sock is None and raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


async def test_true_https_proxy(host: str, port: int, sem: asyncio.Semaphore,
                                source: str, t0: float, ua: str
                                ) -> Optional[DetectionResult]:
    """
    Async wrapper untuk _test_true_https_proxy_sync.
    Menjalankan tes di thread pool (asyncio.to_thread) sehingga:
      - Tidak memblokir event loop
      - Tidak ada konflik socket ownership antara asyncio dan ssl module
      - Tidak memicu RuntimeWarning TLS-in-TLS dari aiohttp
    """
    async with sem:
        return await asyncio.to_thread(
            _test_true_https_proxy_sync, host, port, source, t0, ua
        )


# ======================== PROXY DETECTION ========================
async def detect_proxy_type(host: str, port: int, session: aiohttp.ClientSession,
                           sem: asyncio.Semaphore, source: str = "unknown"
                           ) -> Optional[DetectionResult]:
    """
    Coba deteksi apakah host:port adalah open proxy.
    Mengembalikan DetectionResult jika ya, None jika tidak.
    Setiap jalur deteksi menambahkan label ke detection_vectors.

    Strategi deteksi (berurutan, return saat pertama berhasil):

      A. HTTP PROXY (proxy plaintext, dapat CONNECT ke target HTTPS)
         - Tes 1: proxy=http://host:port, target=http://httpbin.org/ip
         - Tes 2: proxy=http://host:port, target=https://httpbin.org/ip (via CONNECT)
         - Tidak memicu TLS-in-TLS (TLS hanya terjadi antara client-target, bukan client-proxy)
         - Mayoritas "HTTPS proxy" di daftar publik adalah tipe ini

      B. TRUE HTTPS PROXY (proxy itu sendiri pakai TLS) — Python >= 3.11 saja
         - Dilakukan via raw socket + ssl module (bukan aiohttp https:// proxy URL)
         - Menghindari RuntimeWarning TLS-in-TLS dari aiohttp
         - Vektor: https-proxy-tls-handshake-ok

      C. SOCKS5 / SOCKS4 (existing)
    """
    timeout = aiohttp.ClientTimeout(total=DEFAULT_CONFIG["TIMEOUT"])
    test_host = urlparse(DEFAULT_CONFIG["TEST_URL"]).hostname
    test_port = 80
    ua = random.choice(DEFAULT_CONFIG["USER_AGENTS"])
    t0 = time.monotonic()

    # ---- A. HTTP PROXY: tes ke target HTTP & HTTPS (selalu via http:// proxy URL) ----
    # Selalu pakai http:// sebagai proxy URL. aiohttp akan otomatis issue CONNECT
    # untuk target HTTPS. Ini MENGHINDARI TLS-in-TLS (warning Python <3.11).
    for target_scheme, test_url in [("http", DEFAULT_CONFIG["TEST_URL"]),
                                    ("https", DEFAULT_CONFIG["TEST_URL_HTTPS"])]:
        proxy_url = f"http://{host}:{port}"
        vectors = [f"http-proxy-{target_scheme}-attempt"]
        try:
            async with sem:
                async with session.get(
                    test_url,
                    proxy=proxy_url,
                    timeout=timeout,
                    headers={"User-Agent": ua},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        vectors.append(f"http-proxy-{target_scheme}-200")
                        if target_scheme == "https":
                            vectors.append("http-proxy-connect-ok")
                        try:
                            data = await resp.json()
                            seen_ip = data.get("origin", "unknown")
                            vectors.append("origin-leaked")
                            latency = (time.monotonic() - t0) * 1000
                            return DetectionResult(
                                proxy=f"{host}:{port}",
                                protocol=target_scheme,
                                # "http" = HTTP proxy ke target HTTP
                                # "https" = HTTP proxy ke target HTTPS (via CONNECT)
                                ip=host, port=port,
                                seen_ip=seen_ip,
                                anonymity=classify_anonymity(seen_ip, host),
                                detected_at=datetime.now(timezone.utc).isoformat(),
                                latency_ms=round(latency, 1),
                                detection_vectors=vectors,
                                source=source,
                            )
                        except Exception:
                            pass
        except Exception:
            pass

    # ---- B. TRUE HTTPS PROXY (TLS to proxy itself) — Python >= 3.11 ----
    # Tes kasus jarang: proxy itu sendiri memerlukan TLS. Dilakukan via raw socket
    # + ssl module untuk menghindari RuntimeWarning aiohttp TLS-in-TLS.
    if sys.version_info >= (3, 11):
        res = await test_true_https_proxy(host, port, sem, source, t0, ua)
        if res is not None:
            return res

    # ---- SOCKS5 ----
    try:
        async with sem:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=DEFAULT_CONFIG["TIMEOUT"])
            try:
                ok = await asyncio.wait_for(
                    socks5_handshake(reader, writer, test_host, test_port),
                    timeout=DEFAULT_CONFIG["TIMEOUT"],
                )
                if ok:
                    req = (f"GET /ip HTTP/1.1\r\nHost: {test_host}\r\n"
                           f"User-Agent: {ua}\r\nConnection: close\r\n\r\n")
                    writer.write(req.encode())
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(4096), timeout=DEFAULT_CONFIG["TIMEOUT"])
                    body = raw.decode(errors="ignore")
                    seen_ip = "socks5-ok"
                    vectors = ["socks5-handshake-ok"]
                    if "origin" in body:
                        try:
                            json_part = body[body.find("{"):body.rfind("}") + 1]
                            seen_ip = json.loads(json_part).get("origin", "unknown")
                            vectors.append("origin-leaked")
                        except Exception:
                            pass
                    latency = (time.monotonic() - t0) * 1000
                    return DetectionResult(
                        proxy=f"{host}:{port}",
                        protocol="socks5",
                        ip=host, port=port,
                        seen_ip=seen_ip,
                        anonymity="elite" if seen_ip not in ("socks5-ok", "unknown") else "unknown",
                        detected_at=datetime.now(timezone.utc).isoformat(),
                        latency_ms=round(latency, 1),
                        detection_vectors=vectors,
                        source=source,
                    )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    except Exception:
        pass

    # ---- SOCKS4 ----
    try:
        async with sem:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=DEFAULT_CONFIG["TIMEOUT"])
            try:
                ok = await asyncio.wait_for(
                    socks4_handshake(reader, writer, test_host, test_port),
                    timeout=DEFAULT_CONFIG["TIMEOUT"],
                )
                if ok:
                    req = (f"GET /ip HTTP/1.1\r\nHost: {test_host}\r\n"
                           f"User-Agent: {ua}\r\nConnection: close\r\n\r\n")
                    writer.write(req.encode())
                    await writer.drain()
                    raw = await asyncio.wait_for(reader.read(4096), timeout=DEFAULT_CONFIG["TIMEOUT"])
                    body = raw.decode(errors="ignore")
                    seen_ip = "socks4-ok"
                    vectors = ["socks4-handshake-ok"]
                    if "origin" in body:
                        try:
                            json_part = body[body.find("{"):body.rfind("}") + 1]
                            seen_ip = json.loads(json_part).get("origin", "unknown")
                            vectors.append("origin-leaked")
                        except Exception:
                            pass
                    latency = (time.monotonic() - t0) * 1000
                    return DetectionResult(
                        proxy=f"{host}:{port}",
                        protocol="socks4",
                        ip=host, port=port,
                        seen_ip=seen_ip,
                        anonymity="elite" if seen_ip not in ("socks4-ok", "unknown") else "unknown",
                        detected_at=datetime.now(timezone.utc).isoformat(),
                        latency_ms=round(latency, 1),
                        detection_vectors=vectors,
                        source=source,
                    )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    except Exception:
        pass

    return None


# ======================== SOURCE AGGREGATION ========================
async def fetch_source(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore
                      ) -> tuple[str, list[str]]:
    """Fetch satu sumber dengan retry + backoff."""
    last_err = None
    for attempt in range(DEFAULT_CONFIG["SOURCE_RETRIES"] + 1):
        try:
            async with sem:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=DEFAULT_CONFIG["SOURCE_TIMEOUT"]),
                    headers={"User-Agent": random.choice(DEFAULT_CONFIG["USER_AGENTS"])},
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        lines = [l.strip() for l in text.splitlines() if l.strip()]
                        return url, lines
                    last_err = f"HTTP {resp.status}"
        except Exception as e:
            last_err = str(e)
        if attempt < DEFAULT_CONFIG["SOURCE_RETRIES"]:
            await asyncio.sleep(DEFAULT_CONFIG["SOURCE_BACKOFF_BASE"] ** attempt)
    sys.stderr.write(f"    [src-err] {url}: {last_err}\n")
    return url, []


async def gather_from_sources() -> tuple[list[str], dict[str, int]]:
    """Ambil proxy dari semua sumber. Return (unique_proxies, per_source_count)."""
    print(f"[*] Mengambil proxy dari {len(PROXY_SOURCES)} sumber "
          f"(konkurensi antar-sumber={DEFAULT_CONFIG['SOURCE_CONCURRENCY']})...")
    connector = aiohttp.TCPConnector(limit=DEFAULT_CONFIG["SOURCE_CONCURRENCY"], ssl=False)
    sem = asyncio.Semaphore(DEFAULT_CONFIG["SOURCE_CONCURRENCY"])
    per_source: dict[str, int] = {}
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_source(session, url, sem) for url in PROXY_SOURCES]
        results = await asyncio.gather(*tasks)

    seen: set[str] = set()
    valid: list[str] = []
    for url, lines in results:
        n = 0
        for p in lines:
            # parsing lebih ketat: hanya "ip:port"
            if ":" not in p:
                continue
            parts = p.rsplit(":", 1)
            if len(parts) != 2 or not parts[1].isdigit():
                continue
            if not is_public_ip(parts[0]):
                continue
            key = f"{parts[0]}:{parts[1]}"
            if key in seen:
                continue
            seen.add(key)
            valid.append(key)
            n += 1
        per_source[url] = n

    print(f"[+] Total proxy unik & valid: {len(valid)}")
    return valid, per_source


# ======================== STORAGE (NON-BLOCKING) ========================
class ResultStore:
    """
    Async storage: tulis JSONL incremental (append), dan re-build summary
    TXT + JSON + vector-analysis saat save() dipanggil (debounced).
    """
    def __init__(self, output_dir: str):
        self.dir = Path(output_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.txt_path = self.dir / DEFAULT_CONFIG["OUTPUT_TXT"]
        self.jsonl_path = self.dir / DEFAULT_CONFIG["OUTPUT_JSONL"]
        self.json_path = self.dir / DEFAULT_CONFIG["OUTPUT_JSON"]
        self.vectors_path = self.dir / DEFAULT_CONFIG["OUTPUT_VECTORS"]
        self._last_save = 0.0
        self._lock = asyncio.Lock()

    async def append_one(self, r: DetectionResult):
        """Tulis satu hasil ke JSONL segera (append-only, crash-safe)."""
        line = json.dumps(asdict(r)) + "\n"
        if HAS_AIOFILES:
            async with aiofiles.open(self.jsonl_path, "a") as f:
                await f.write(line)
        else:
            await asyncio.to_thread(self._append_sync, line)

    def _append_sync(self, line: str):
        with open(self.jsonl_path, "a") as f:
            f.write(line)

    async def save_summary(self, results: list[DetectionResult], force: bool = False):
        """Debounced save: tidak lebih dari 1x per SAVE_DEBOUNCE_SEC."""
        async with self._lock:
            now = time.monotonic()
            if not force and (now - self._last_save) < DEFAULT_CONFIG["SAVE_DEBOUNCE_SEC"]:
                return
            self._last_save = now
            # Jalankan I/O blocking di thread pool
            await asyncio.to_thread(self._save_summary_sync, results)

    def _save_summary_sync(self, results: list[DetectionResult]):
        # TXT
        with open(self.txt_path, "w") as f:
            for r in results:
                f.write(f"{r['proxy']}\n") if isinstance(r, dict) else f.write(f"{r.proxy}\n")
        # JSON detail
        data = [asdict(r) if not isinstance(r, dict) else r for r in results]
        with open(self.json_path, "w") as f:
            json.dump(data, f, indent=2)
        # Vector analysis (untuk riset: vektor mana yang paling produktif)
        vector_counts: dict[str, int] = {}
        protocol_counts: dict[str, int] = {}
        anonymity_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        latencies: list[float] = []
        for r in data:
            for v in r["detection_vectors"]:
                vector_counts[v] = vector_counts.get(v, 0) + 1
            protocol_counts[r["protocol"]] = protocol_counts.get(r["protocol"], 0) + 1
            anonymity_counts[r["anonymity"]] = anonymity_counts.get(r["anonymity"], 0) + 1
            source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1
            latencies.append(r["latency_ms"])
        analysis = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_proxies": len(data),
            "by_protocol": protocol_counts,
            "by_anonymity": anonymity_counts,
            "by_source": source_counts,
            "by_detection_vector": dict(sorted(vector_counts.items(), key=lambda x: -x[1])),
            "latency_stats": {
                "min_ms": min(latencies) if latencies else 0,
                "max_ms": max(latencies) if latencies else 0,
                "mean_ms": round(sum(latencies) / len(latencies), 1) if latencies else 0,
                "p50_ms": round(sorted(latencies)[len(latencies) // 2], 1) if latencies else 0,
            },
        }
        with open(self.vectors_path, "w") as f:
            json.dump(analysis, f, indent=2)


# ======================== STATS PRINTER ========================
async def stats_printer(stats: dict, store: ResultStore, results: list):
    """Cetak statistik periodik + trigger debounced save."""
    while not stats.get("stop"):
        print(f"[stat] selesai={stats['done']} | ditemukan={stats['found']} | "
              f"rate={stats.get('rate_per_sec', 0):.1f}/s")
        await store.save_summary(results)
        await asyncio.sleep(10)


# ======================== TEST PROXY LIST ========================
async def test_proxy_list(proxies: list[str], session: aiohttp.ClientSession,
                          sem: asyncio.Semaphore, store: ResultStore,
                          stats: dict, results: list):
    total = len(proxies)
    print(f"[*] Menguji {total} proxy dari daftar sumber...")

    async def test_one(proxy_str: str):
        host, port_s = proxy_str.rsplit(":", 1)
        port = int(port_s)
        res = await detect_proxy_type(host, port, session, sem, source="aggregated")
        if res:
            results.append(res)
            stats["found"] += 1
            await store.append_one(res)
            print(f"[+] {res.proxy} [{res.protocol}/{res.anonymity}] "
                  f"lat={res.latency_ms}ms vec={res.detection_vectors} "
                  f"[{stats['done']}/{total}]")
        stats["done"] += 1

    # Process dalam chunk agar gather tidak terlalu besar
    chunk_size = DEFAULT_CONFIG["SCAN_BATCH_SIZE"]
    t_start = time.monotonic()
    for i in range(0, total, chunk_size):
        chunk = proxies[i:i + chunk_size]
        await asyncio.gather(*[test_one(p) for p in chunk])
        elapsed = max(time.monotonic() - t_start, 0.001)
        stats["rate_per_sec"] = stats["done"] / elapsed
        print(f"    ...{stats['done']}/{total} | rate={stats['rate_per_sec']:.1f}/s")


# ======================== RANDOM IP SCAN ========================
async def scan_random_ips(count: int, session: aiohttp.ClientSession,
                          sem: asyncio.Semaphore, store: ResultStore,
                          stats: dict, results: list):
    """
    Pindai `count` IP publik acak di seluruh ruang IPv4 (di luar bogon).
    OPT-IN via CLI --random-scan N.
    """
    print(f"[*] Memindai {count} IP acak di ruang IPv4 publik...")
    batch_size = DEFAULT_CONFIG["SCAN_BATCH_SIZE"]
    t_start = time.monotonic()

    async def scan_one_ip_port(host: str, port: int):
        res = await detect_proxy_type(host, port, session, sem, source="random")
        if res:
            results.append(res)
            stats["found"] += 1
            await store.append_one(res)
            print(f"[+] RANDOM {res.proxy} [{res.protocol}/{res.anonymity}] "
                  f"lat={res.latency_ms}ms vec={res.detection_vectors}")
        stats["done"] += 1

    total_done = 0
    for batch_start in range(0, count, batch_size):
        batch_n = min(batch_size, count - batch_start)
        tasks = []
        for _ in range(batch_n):
            ip = random_public_ipv4()
            port = random.choice(DEFAULT_CONFIG["PROXY_PORTS"])
            tasks.append(scan_one_ip_port(ip, port))
        await asyncio.gather(*tasks)
        total_done += batch_n
        elapsed = max(time.monotonic() - t_start, 0.001)
        stats["rate_per_sec"] = total_done / elapsed
        print(f"    ...{total_done}/{count} | ditemukan: {stats['found']} | "
              f"rate={stats['rate_per_sec']:.1f}/s")


# ======================== CLI ========================
def parse_args():
    p = argparse.ArgumentParser(
        description="PROXY HUNTER v2 — Research-Grade Open Proxy Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONFIG["MAX_CONCURRENT"],
                   help=f"Max koneksi paralel (default: {DEFAULT_CONFIG['MAX_CONCURRENT']})")
    p.add_argument("--timeout", type=int, default=DEFAULT_CONFIG["TIMEOUT"],
                   help=f"Timeout per koneksi, detik (default: {DEFAULT_CONFIG['TIMEOUT']})")
    p.add_argument("--output-dir", type=str, default=DEFAULT_CONFIG["OUTPUT_DIR"],
                   help=f"Directory output (default: {DEFAULT_CONFIG['OUTPUT_DIR']})")
    p.add_argument("--random-scan", type=int, default=0,
                   help="Jumlah IP acak untuk dipindai (OPT-IN, default: 0 = off). "
                        "HANYA untuk riset pada subnet yang Anda miliki izin.")
    p.add_argument("--no-sources", action="store_true",
                   help="Lewati tahap agregasi dari sumber publik")
    p.add_argument("--sources-only", action="store_true",
                   help="Hanya agregasi dari sumber, tanpa random scan")
    return p.parse_args()


# ======================== MAIN ========================
async def async_main(args):
    DEFAULT_CONFIG["MAX_CONCURRENT"] = args.concurrency
    DEFAULT_CONFIG["TIMEOUT"] = args.timeout
    DEFAULT_CONFIG["OUTPUT_DIR"] = args.output_dir

    print("=" * 72)
    print("   PROXY HUNTER v2 — Research-Grade Open Proxy Detection")
    print("   ⚠  Hanya untuk riset/edukasi yang sah & authorized")
    print("=" * 72)
    print(f"   Waktu mulai : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Konkurensi  : {DEFAULT_CONFIG['MAX_CONCURRENT']}")
    print(f"   Timeout     : {DEFAULT_CONFIG['TIMEOUT']}s")
    print(f"   Random scan : {args.random_scan} IP")
    print(f"   Output dir  : {DEFAULT_CONFIG['OUTPUT_DIR']}")
    print("=" * 72)

    sem = asyncio.Semaphore(DEFAULT_CONFIG["MAX_CONCURRENT"])
    connector = aiohttp.TCPConnector(
        limit=DEFAULT_CONFIG["MAX_CONCURRENT"],
        ssl=False,
        force_close=True,
        enable_cleanup_closed=True,
    )
    store = ResultStore(DEFAULT_CONFIG["OUTPUT_DIR"])
    results: list[DetectionResult] = []
    stats = {"done": 0, "found": 0, "rate_per_sec": 0.0, "stop": False}

    stat_task = asyncio.create_task(stats_printer(stats, store, results))

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Agregasi dari sumber publik
            if not args.no_sources:
                proxies, per_source = await gather_from_sources()
                if per_source:
                    print("[*] Distribusi per sumber:")
                    for url, n in sorted(per_source.items(), key=lambda x: -x[1]):
                        print(f"      {n:6d}  {url}")
                if proxies:
                    stats["done"] = 0
                    await test_proxy_list(proxies, session, sem, store, stats, results)
                await store.save_summary(results, force=True)

            # 2. Random IPv4 scan (OPT-IN)
            if args.random_scan > 0 and not args.sources_only:
                stats["done"] = 0
                await scan_random_ips(args.random_scan, session, sem, store, stats, results)
                await store.save_summary(results, force=True)

    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh pengguna. Menyimpan hasil...")
        await store.save_summary(results, force=True)
    finally:
        stats["stop"] = True
        stat_task.cancel()
        try:
            await stat_task
        except asyncio.CancelledError:
            pass

    # Ringkasan akhir
    await store.save_summary(results, force=True)
    print("\n" + "=" * 72)
    print(f"   Total proxy berfungsi: {len(results)}")
    by_proto: dict[str, int] = {}
    for r in results:
        by_proto[r.protocol] = by_proto.get(r.protocol, 0) + 1
    for k, v in by_proto.items():
        print(f"     - {k:8s}: {v}")
    print(f"   Output dir  : {DEFAULT_CONFIG['OUTPUT_DIR']}/")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_TXT']}")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_JSONL']}  (streaming, crash-safe)")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_JSON']}")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_VECTORS']}  (analisis vektor deteksi)")
    print("=" * 72)


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Keluar.")
        sys.exit(0)
