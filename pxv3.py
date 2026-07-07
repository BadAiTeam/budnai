#!/usr/bin/env python3
"""
PROXY HUNTER v3 — Research-Grade Open Proxy Detection Framework
================================================================

Perubahan utama dari v1 → v2 → v3:

  v1 → v2:
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

  v2 → v3 (upgrade ini):
  4. PROTOCOL IDENTIFICATION + CONNECTION PROTOCOL PERSISTENCE
     - Setiap DetectionResult kini menyimpan field baru `connection_protocol`
       yang menjelaskan transport layer yang DIPAKAI untuk mencapai proxy:
         * "tcp-plain"     — TCP biasa ke proxy (HTTP proxy & SOCKS)
         * "tcp-tunneled"  — TCP ke proxy + HTTP CONNECT tunnel ke target HTTPS
         * "tcp-tls"       — TCP + TLS layer #1 ke proxy itu sendiri (true HTTPS proxy)
       - Membedakan dari field `protocol` (http/https/https-tls/socks4/socks5)
         yang menjelaskan protocol APLIKASI proxy.
     - Output working_proxies.txt di-upgrade:
         * Baris lama (v2): `1.2.3.4:8080`
         * Baris baru (v3): `http://1.2.3.4:8080  # conn=tcp-tunneled anon=elite lat=123.4ms src=aggregated`
       - Format utama `protocol://host:port` kompatibel dengan curl/requests/aiohttp.
       - Metadata setelah `#` tidak mengganggu parser standar (bisa di-strip).
     - detection_vectors.json kini menambahkan bucket `by_connection_protocol`
       untuk analisis distribusi transport layer.

  Semua fungsi lain (source aggregation, multi-processing, random scan,
  debounced save, bogon filter, SOCKS handshake, anonymity classification,
  CLI args) TIDAK diubah — konsistensi tetap terjaga.

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
import multiprocessing
import os
import random
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
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
    "MAX_CONCURRENT": 1000,         # per worker process (dapat di-override CLI)
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
    # ======================== MULTI-PROCESSING ========================
    # Jumlah worker process. Default 0 = auto (gunakan semua CPU core).
    # Set ke 1 untuk mempertahankan mode single-process (lama).
    # Di mesin 24-core: --workers 24 → 24 worker × 1000 concurrent = 24.000 paralel
    "WORKERS": 0,
    "TLS_THREADPOOL_SIZE": 32,      # thread pool per worker untuk TLS handshake
                                    # (true HTTPS proxy test pakai asyncio.to_thread)
    "WORKER_CHUNK_SIZE": 200,       # ukuran chunk proxy per worker (load balancing)
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
    protocol: str                      # http | https | https-tls | socks4 | socks5
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
    # ====== v3: connection_protocol (transport layer yang DIPAKAI ke proxy) ======
    # Membedakan dari `protocol` (protocol APLIKASI proxy).
    #   "tcp-plain"     — TCP biasa ke proxy (HTTP proxy & SOCKS4/5)
    #   "tcp-tunneled"  — TCP ke proxy + HTTP CONNECT tunnel ke target HTTPS
    #   "tcp-tls"       — TCP + TLS layer #1 ke proxy itu sendiri (true HTTPS proxy)
    connection_protocol: str = "tcp-plain"


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
            # v3: true HTTPS proxy — TCP + TLS layer #1 ke proxy itu sendiri
            connection_protocol="tcp-tls",
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
                            # v3: klasifikasi transport layer
                            #   - target HTTP  : TCP biasa ke proxy
                            #   - target HTTPS : TCP ke proxy + CONNECT tunnel
                            conn_proto = "tcp-tunneled" if target_scheme == "https" else "tcp-plain"
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
                                connection_protocol=conn_proto,
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
                        # v3: SOCKS5 — TCP biasa ke proxy
                        connection_protocol="tcp-plain",
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
                        # v3: SOCKS4 — TCP biasa ke proxy
                        connection_protocol="tcp-plain",
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
        # ====== v3: TXT dengan format protocol://ip:port + metadata ======
        # Format lama (v2): "1.2.3.4:8080"
        # Format baru (v3): "http://1.2.3.4:8080  # conn=tcp-tunneled anon=elite lat=123.4ms src=aggregated"
        #
        # Tujuan:
        #   1. Baris utama `protocol://host:port` langsung dipakai oleh
        #      curl --proxy, requests.proxies, aiohttp proxy=, dll.
        #   2. Metadata setelah '#' bisa diabaikan parser (di-split '#' bila perlu)
        #      namun memberi konteks lengkap untuk riset/manual review.
        #   3. Backward compatible: parser lama yang hanya baca ip:port
        #      cukup strip prefix "protocol://" dan suffix "# ..." .
        with open(self.txt_path, "w") as f:
            for r in results:
                # r bisa berupa DetectionResult (single-process) atau dict (multi-process aggregator)
                if isinstance(r, dict):
                    proto = r.get("protocol", "http")
                    proxy_str = r.get("proxy", "")
                    conn = r.get("connection_protocol", "tcp-plain")
                    anon = r.get("anonymity", "unknown")
                    lat = r.get("latency_ms", 0)
                    src = r.get("source", "unknown")
                else:
                    proto = r.protocol
                    proxy_str = r.proxy
                    conn = r.connection_protocol
                    anon = r.anonymity
                    lat = r.latency_ms
                    src = r.source
                # Sanitasi proto: hindari "https-tls://" (bukan skema standar);
                # gunakan "https://" sebagai prefix URL karena connection-nya TLS.
                # Nilai proto asli (https-tls) tetap tersimpan di JSONL/JSON.
                url_scheme = "https" if proto in ("https", "https-tls") else proto
                line = (f"{url_scheme}://{proxy_str}  "
                        f"# conn={conn} anon={anon} "
                        f"lat={lat}ms src={src} proto={proto}\n")
                f.write(line)
        # JSON detail
        data = [asdict(r) if not isinstance(r, dict) else r for r in results]
        with open(self.json_path, "w") as f:
            json.dump(data, f, indent=2)
        # Vector analysis (untuk riset: vektor mana yang paling produktif)
        vector_counts: dict[str, int] = {}
        protocol_counts: dict[str, int] = {}
        anonymity_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        connection_protocol_counts: dict[str, int] = {}  # v3
        latencies: list[float] = []
        for r in data:
            for v in r["detection_vectors"]:
                vector_counts[v] = vector_counts.get(v, 0) + 1
            protocol_counts[r["protocol"]] = protocol_counts.get(r["protocol"], 0) + 1
            anonymity_counts[r["anonymity"]] = anonymity_counts.get(r["anonymity"], 0) + 1
            source_counts[r["source"]] = source_counts.get(r["source"], 0) + 1
            # v3: agregasi by connection_protocol
            cp = r.get("connection_protocol", "tcp-plain")
            connection_protocol_counts[cp] = connection_protocol_counts.get(cp, 0) + 1
            latencies.append(r["latency_ms"])
        analysis = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_proxies": len(data),
            "by_protocol": protocol_counts,
            "by_connection_protocol": dict(sorted(  # v3
                connection_protocol_counts.items(), key=lambda x: -x[1]
            )),
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
            print(f"[+] {res.proxy} [{res.protocol}/{res.anonymity}/{res.connection_protocol}] "
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
            print(f"[+] RANDOM {res.proxy} [{res.protocol}/{res.anonymity}/{res.connection_protocol}] "
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


# ======================== WORKER PROCESS (MULTI-PROCESSING) ========================
def _worker_process_main(
    worker_id: int,
    proxy_chunk: list[str],
    config_snapshot: dict,
    output_dir: str,
    stats_queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
) -> None:
    """
    Entry point untuk satu worker process.

    Tiap worker:
      1. Setup asyncio loop sendiri
      2. Buat aiohttp session sendiri
      3. Buat ResultStore sendiri → tulis ke worker_<id>.jsonl (hindari race)
      4. Tes proxy_chunk dengan konkurensi MAX_CONCURRENT
      5. Kirim statistik periodik ke stats_queue (untuk agregasi main)
      6. Kirim hasil deteksi ke result_queue (untuk append ke JSONL global)

    Worker TIDAK melakukan agregasi sumber (itu di main process).
    Worker TIDAK melakukan random scan (juga di main process atau dibagi).

    Args:
      worker_id         : ID worker (0-based)
      proxy_chunk       : daftar "ip:port" yang akan diuji worker ini
      config_snapshot   : snapshot DEFAULT_CONFIG (dari main, untuk konsistensi)
      output_dir        : directory output utama
      stats_queue       : queue untuk kirim (done, found, rate) ke main
      result_queue      : queue untuk kirim DetectionResult dict ke main
    """
    # Update config global di worker process
    global DEFAULT_CONFIG
    DEFAULT_CONFIG.update(config_snapshot)

    # Output JSONL khusus worker (untuk crash recovery)
    worker_jsonl = Path(output_dir) / f"worker_{worker_id:03d}.jsonl"

    async def _worker_async():
        sem = asyncio.Semaphore(DEFAULT_CONFIG["MAX_CONCURRENT"])
        connector = aiohttp.TCPConnector(
            limit=DEFAULT_CONFIG["MAX_CONCURRENT"],
            ssl=False,
            force_close=True,
            enable_cleanup_closed=True,
        )

        # Thread pool khusus untuk TLS handshake (true HTTPS proxy test)
        # Ini memungkinkan banyak TLS handshake paralel di thread terpisah
        loop = asyncio.get_running_loop()
        tls_executor = ThreadPoolExecutor(
            max_workers=DEFAULT_CONFIG["TLS_THREADPOOL_SIZE"],
            thread_name_prefix=f"w{worker_id}-tls",
        )
        loop.set_default_executor(tls_executor)

        # ResultStore worker (untuk crash recovery)
        store = ResultStore(output_dir)
        store.jsonl_path = worker_jsonl  # override ke file worker

        # Stats lokal
        local_stats = {"done": 0, "found": 0, "rate_per_sec": 0.0}
        t_start = time.monotonic()

        async with aiohttp.ClientSession(connector=connector) as session:
            total = len(proxy_chunk)

            async def test_one(proxy_str: str):
                host, port_s = proxy_str.rsplit(":", 1)
                port = int(port_s)
                res = await detect_proxy_type(
                    host, port, session, sem,
                    source=f"aggregated-w{worker_id}"
                )
                if res:
                    local_stats["found"] += 1
                    await store.append_one(res)
                    # Kirim ke main untuk agregasi (dict, bukan object, untuk pickle)
                    result_queue.put(asdict(res))
                local_stats["done"] += 1

            chunk_size = DEFAULT_CONFIG["WORKER_CHUNK_SIZE"]
            for i in range(0, total, chunk_size):
                chunk = proxy_chunk[i:i + chunk_size]
                await asyncio.gather(*[test_one(p) for p in chunk])
                elapsed = max(time.monotonic() - t_start, 0.001)
                local_stats["rate_per_sec"] = local_stats["done"] / elapsed
                # Kirim heartbeat stats ke main
                stats_queue.put({
                    "worker_id": worker_id,
                    "done": local_stats["done"],
                    "found": local_stats["found"],
                    "rate": local_stats["rate_per_sec"],
                    "total": total,
                })

        # Final stats
        stats_queue.put({
            "worker_id": worker_id,
            "done": local_stats["done"],
            "found": local_stats["found"],
            "rate": local_stats["rate_per_sec"],
            "total": len(proxy_chunk),
            "final": True,
        })
        tls_executor.shutdown(wait=False)

    try:
        asyncio.run(_worker_async())
    except Exception as e:
        sys.stderr.write(f"[worker {worker_id}] error: {e}\n")
        stats_queue.put({"worker_id": worker_id, "error": str(e), "final": True})


async def _stats_aggregator(stats_queue: multiprocessing.Queue, n_workers: int,
                            store: ResultStore, results: list, stop_event: asyncio.Event):
    """
    Async task di main process: baca stats_queue, cetak ringkasan periodik.
    Berhenti saat n_workers worker mengirim pesan 'final'.
    """
    finals_received = 0
    last_print = 0.0
    totals = {i: {"done": 0, "found": 0, "rate": 0.0, "total": 0} for i in range(n_workers)}

    while finals_received < n_workers and not stop_event.is_set():
        try:
            # Non-blocking poll queue dari thread executor
            msg = await asyncio.get_event_loop().run_in_executor(
                None, lambda: stats_queue.get(timeout=1.0)
            )
        except Exception:
            # queue.Empty atau timeout
            continue

        if msg is None:
            continue
        wid = msg.get("worker_id", -1)
        if "error" in msg:
            print(f"[!] Worker {wid} error: {msg['error']}")
            finals_received += 1
            continue
        if wid in totals:
            totals[wid] = msg
        if msg.get("final"):
            finals_received += 1

        # Cetak ringkasan setiap ~3 detik
        now = time.monotonic()
        if now - last_print > 3.0:
            total_done = sum(t["done"] for t in totals.values())
            total_found = sum(t["found"] for t in totals.values())
            total_target = sum(t["total"] for t in totals.values())
            rate_sum = sum(t["rate"] for t in totals.values())
            print(f"[stat] workers={n_workers} | selesai={total_done}/{total_target} "
                  f"| ditemukan={total_found} | rate={rate_sum:.1f}/s "
                  f"(per-worker avg={rate_sum/max(n_workers,1):.1f}/s)")
            last_print = now

    print(f"[stat] Semua worker selesai.")


async def _result_aggregator(result_queue: multiprocessing.Queue, store: ResultStore,
                             results: list, stop_event: asyncio.Event,
                             expected_count: int = None):
    """
    Async task di main process: baca result_queue, append ke JSONL global
    dan tambahkan ke list results. Berhenti saat stop_event diset.
    """
    n = 0
    while not stop_event.is_set():
        try:
            r = await asyncio.get_event_loop().run_in_executor(
                None, lambda: result_queue.get(timeout=0.5)
            )
        except Exception:
            continue
        if r is None:
            break
        # r adalah dict (sudah di-asdict oleh worker)
        results.append(r)  # simpan sebagai dict untuk konsistensi dengan save_summary
        n += 1
        if expected_count and n >= expected_count:
            break
    print(f"[result-aggregator] {n} hasil dikumpulkan.")


def _split_proxies_for_workers(proxies: list[str], n_workers: int) -> list[list[str]]:
    """
    Bagi daftar proxy ke n worker. Round-robin untuk distribusi merata.
    (Round-robin lebih baik daripada chunk contiguous karena proxy dari
    sumber yang sama cenderung punya pola respons serupa — round-robin
    menyebar beban.)
    """
    chunks: list[list[str]] = [[] for _ in range(n_workers)]
    for i, p in enumerate(proxies):
        chunks[i % n_workers].append(p)
    return chunks


def run_multiprocess(args, proxies: list[str]) -> list[dict]:
    """
    Jalankan multi-process: bagi proxies ke N worker, tiap worker jalankan
    asyncio loop sendiri. Hasil dikumpulkan ke JSONL global.

    Fungsi ini dapat dipanggil dari sync ATAU async context (auto-detect).
    """
    n_workers = args.workers if args.workers > 0 else multiprocessing.cpu_count()
    print(f"\n[*] Mode MULTI-PROCESS: {n_workers} worker × "
          f"{DEFAULT_CONFIG['MAX_CONCURRENT']} concurrent = "
          f"{n_workers * DEFAULT_CONFIG['MAX_CONCURRENT']} koneksi paralel maksimal")
    print(f"[*] TLS thread pool per worker: {DEFAULT_CONFIG['TLS_THREADPOOL_SIZE']} threads")
    print(f"[*] Total proxy akan diuji: {len(proxies)}")

    # Bagi proxy ke worker (round-robin)
    chunks = _split_proxies_for_workers(proxies, n_workers)
    for i, c in enumerate(chunks):
        print(f"    worker {i:2d}: {len(c)} proxy")

    # Snapshot config untuk worker
    config_snapshot = dict(DEFAULT_CONFIG)
    output_dir = DEFAULT_CONFIG["OUTPUT_DIR"]

    # Queue antar-process — gunakan default context (fork pada Linux)
    # Spawn context bermasalah dengan semaphore pickle di beberapa env
    ctx = multiprocessing.get_context("fork") if sys.platform != "win32" \
          else multiprocessing.get_context("spawn")
    stats_queue = ctx.Queue()
    result_queue = ctx.Queue()

    # Start workers
    processes = []
    for wid in range(n_workers):
        p = ctx.Process(
            target=_worker_process_main,
            args=(wid, chunks[wid], config_snapshot, output_dir,
                  stats_queue, result_queue),
            name=f"proxy-worker-{wid}",
        )
        p.start()
        processes.append(p)

    # Main: aggregator + tunggu worker
    store = ResultStore(output_dir)
    results: list[dict] = []
    stop_event = asyncio.Event()

    async def _main_async():
        # Start aggregator
        stats_task = asyncio.create_task(
            _stats_aggregator(stats_queue, n_workers, store, results, stop_event)
        )
        result_task = asyncio.create_task(
            _result_aggregator(result_queue, store, results, stop_event,
                               expected_count=len(proxies))
        )

        # Tunggu semua worker process selesai (blocking, jalankan di thread)
        loop = asyncio.get_running_loop()
        for p in processes:
            await loop.run_in_executor(None, p.join)

        # Beri kesempatan aggregator menghabiskan sisa queue
        await asyncio.sleep(2.0)
        stop_event.set()

        # Drain sisa result_queue
        try:
            while True:
                r = result_queue.get_nowait()
                if r is not None:
                    results.append(r)
        except Exception:
            pass

        stats_task.cancel()
        result_task.cancel()
        try:
            await stats_task
        except asyncio.CancelledError:
            pass
        try:
            await result_task
        except asyncio.CancelledError:
            pass

    # Auto-detect: jika sudah dalam running loop, jangan pakai asyncio.run()
    try:
        loop = asyncio.get_running_loop()
        # Sudah ada running loop — buat task dan tunggu
        # (saat dipanggil dari demo yang async)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(asyncio.run, _main_async())
            future.result()
    except RuntimeError:
        # Tidak ada running loop — safe untuk asyncio.run()
        asyncio.run(_main_async())

    # Save final summary
    try:
        loop = asyncio.get_running_loop()
        # Sudah dalam loop — jalankan save_summary di thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(asyncio.run, store.save_summary(results, force=True))
            future.result()
    except RuntimeError:
        asyncio.run(store.save_summary(results, force=True))

    return results


# ======================== CLI ========================
def parse_args():
    p = argparse.ArgumentParser(
        description="PROXY HUNTER v3 — Research-Grade Open Proxy Detection "
                    "(+ protocol identification & connection_protocol persistence)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONFIG["MAX_CONCURRENT"],
                   help=f"Max koneksi paralel PER WORKER (default: {DEFAULT_CONFIG['MAX_CONCURRENT']})")
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
    # ====== Multi-processing ======
    p.add_argument("--workers", type=int, default=DEFAULT_CONFIG["WORKERS"],
                   help="Jumlah worker process (default: 0 = auto, semua CPU core). "
                        "Set 1 untuk mode single-process (lama). "
                        "Di mesin 24-core: --workers 24 untuk gunakan semua core.")
    p.add_argument("--tls-threads", type=int,
                   default=DEFAULT_CONFIG["TLS_THREADPOOL_SIZE"],
                   help=f"Thread pool per worker untuk TLS handshake "
                        f"(default: {DEFAULT_CONFIG['TLS_THREADPOOL_SIZE']})")
    p.add_argument("--worker-chunk", type=int,
                   default=DEFAULT_CONFIG["WORKER_CHUNK_SIZE"],
                   help=f"Ukuran chunk proxy per worker batch (default: "
                        f"{DEFAULT_CONFIG['WORKER_CHUNK_SIZE']})")
    return p.parse_args()


# ======================== MAIN ========================
async def async_main(args):
    DEFAULT_CONFIG["MAX_CONCURRENT"] = args.concurrency
    DEFAULT_CONFIG["TIMEOUT"] = args.timeout
    DEFAULT_CONFIG["OUTPUT_DIR"] = args.output_dir
    DEFAULT_CONFIG["TLS_THREADPOOL_SIZE"] = args.tls_threads
    DEFAULT_CONFIG["WORKER_CHUNK_SIZE"] = args.worker_chunk

    # Resolve workers: 0 = auto
    n_workers = args.workers if args.workers > 0 else multiprocessing.cpu_count()

    print("=" * 72)
    print("   PROXY HUNTER v3 — Research-Grade Open Proxy Detection")
    print("   v3: + protocol identification & connection_protocol persistence")
    print("   ⚠  Hanya untuk riset/edukasi yang sah & authorized")
    print("=" * 72)
    print(f"   Waktu mulai : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   CPU core    : {multiprocessing.cpu_count()}")
    print(f"   Worker proc : {n_workers}")
    print(f"   Concurrent  : {DEFAULT_CONFIG['MAX_CONCURRENT']} / worker "
          f"× {n_workers} = {DEFAULT_CONFIG['MAX_CONCURRENT'] * n_workers} total")
    print(f"   TLS threads : {DEFAULT_CONFIG['TLS_THREADPOOL_SIZE']} / worker "
          f"× {n_workers} = {DEFAULT_CONFIG['TLS_THREADPOOL_SIZE'] * n_workers} total")
    print(f"   Timeout     : {DEFAULT_CONFIG['TIMEOUT']}s")
    print(f"   Random scan : {args.random_scan} IP")
    print(f"   Output dir  : {DEFAULT_CONFIG['OUTPUT_DIR']}")
    print("=" * 72)

    # 1. Agregasi dari sumber publik (selalu di main process, 1x)
    proxies: list[str] = []
    if not args.no_sources:
        proxies, per_source = await gather_from_sources()
        if per_source:
            print("[*] Distribusi per sumber:")
            for url, n in sorted(per_source.items(), key=lambda x: -x[1]):
                print(f"      {n:6d}  {url}")

    # 2. Random IPv4 scan (OPT-IN) — generate di main, distribusi ke worker
    if args.random_scan > 0 and not args.sources_only:
        print(f"[*] Generate {args.random_scan} IP acak untuk random scan...")
        for _ in range(args.random_scan):
            ip = random_public_ipv4()
            port = random.choice(DEFAULT_CONFIG["PROXY_PORTS"])
            proxies.append(f"{ip}:{port}")

    if not proxies:
        print("[!] Tidak ada proxy untuk diuji.")
        return

    # 3. Pilih mode: single atau multi-process
    if n_workers == 1:
        # Mode single-process (kompatibilitas mundur)
        print(f"\n[*] Mode SINGLE-PROCESS (workers=1)")
        sem = asyncio.Semaphore(DEFAULT_CONFIG["MAX_CONCURRENT"])
        connector = aiohttp.TCPConnector(
            limit=DEFAULT_CONFIG["MAX_CONCURRENT"],
            ssl=False, force_close=True, enable_cleanup_closed=True,
        )
        loop = asyncio.get_running_loop()
        loop.set_default_executor(ThreadPoolExecutor(
            max_workers=DEFAULT_CONFIG["TLS_THREADPOOL_SIZE"],
            thread_name_prefix="tls",
        ))
        store = ResultStore(DEFAULT_CONFIG["OUTPUT_DIR"])
        results: list[DetectionResult] = []
        stats = {"done": 0, "found": 0, "rate_per_sec": 0.0, "stop": False}
        stat_task = asyncio.create_task(stats_printer(stats, store, results))
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                await test_proxy_list(proxies, session, sem, store, stats, results)
        except KeyboardInterrupt:
            print("\n[!] Dihentikan oleh pengguna. Menyimpan hasil...")
        finally:
            stats["stop"] = True
            stat_task.cancel()
            try:
                await stat_task
            except asyncio.CancelledError:
                pass
        await store.save_summary(results, force=True)
    else:
        # Mode MULTI-PROCESS
        results = run_multiprocess(args, proxies)

    # 4. Ringkasan akhir
    print("\n" + "=" * 72)
    print(f"   Total proxy berfungsi: {len(results)}")
    by_proto: dict[str, int] = {}
    by_conn: dict[str, int] = {}  # v3
    for r in results:
        if isinstance(r, dict):
            proto = r["protocol"]
            conn = r.get("connection_protocol", "tcp-plain")
        else:
            proto = r.protocol
            conn = r.connection_protocol
        by_proto[proto] = by_proto.get(proto, 0) + 1
        by_conn[conn] = by_conn.get(conn, 0) + 1
    print("   By protocol (aplikasi):")
    for k, v in by_proto.items():
        print(f"     - {k:10s}: {v}")
    print("   By connection_protocol (transport — v3):")
    for k, v in sorted(by_conn.items(), key=lambda x: -x[1]):
        print(f"     - {k:14s}: {v}")
    print(f"   Output dir  : {DEFAULT_CONFIG['OUTPUT_DIR']}/")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_TXT']}  (v3: protocol://ip:port + metadata)")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_JSONL']}  (streaming, crash-safe)")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_JSON']}")
    print(f"     - {DEFAULT_CONFIG['OUTPUT_VECTORS']}  (analisis vektor deteksi + by_connection_protocol)")
    if n_workers > 1:
        print(f"     - worker_*.jsonl  ({n_workers} file per-worker)")
    print("=" * 72)


if __name__ == "__main__":
    args = parse_args()
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Keluar.")
        sys.exit(0)
