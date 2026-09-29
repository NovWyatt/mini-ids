# Học Network Security & IDS qua mini-IDS

Tài liệu này biến mã nguồn mini-IDS thành một giáo trình: từ đọc từng gói tin, hiểu từng kiểu tấn công, tới tự viết rule, detector và đánh giá mô hình ML. Mọi ngưỡng, tên trường và đường dẫn dưới đây đều lấy từ code hiện tại. Khi bạn sửa code, hãy sửa tài liệu theo.

**Mục lục**

1. [Cách dùng tài liệu này](#s1)
2. [Nền tảng mạng cần nắm](#s2)
3. [IDS là gì](#s3)
4. [Từng detector](#s4)
5. [Thực hành với Wireshark](#s5)
6. [Bài tập theo cấp độ](#s6)
7. [An toàn & pháp lý](#s7)
8. [Đi tiếp](#s8)

---

<a id="s1"></a>
## 1. Cách dùng tài liệu này

Mỗi mục đi theo một vòng: **khái niệm → code hiện thực nó → cách tự nhìn thấy nó** (Wireshark, demo, pytest). Đừng chỉ đọc: mở file được link, chạy lệnh, đổi một con số rồi quan sát kết quả thay đổi ra sao. Phần 4 và phần 6 là trọng tâm; phần 2 và 3 là nền để hiểu chúng.

### 1.1 Chuẩn bị

```powershell
cd "C:\Users\Wyatt\Desktop\mini IDS"
.venv\Scripts\activate                 # từ đây "python" là python của venv
python -m mini_ids info                # 12 detector, 17 rule, MITRE ID
python -m mini_ids demo --open         # traffic giả lập + dashboard http://127.0.0.1:8800
python -m pytest                       # toàn bộ test phải xanh trước khi bạn sửa gì
```

Không activate venv thì thay `python` bằng `.venv\Scripts\python.exe`. Nếu cài package dạng editable (`pip install -e .`, hoặc `pip install -e ".[dev]"` để có pytest), bạn có thể gõ gọn `mini-ids <lệnh>`. Tài liệu dùng `python -m mini_ids <lệnh>` vì cách này luôn chạy được.

| Lệnh | Việc làm | Tuỳ chọn hay dùng |
|---|---|---|
| `demo` | Traffic giả lập theo thời gian thực + dashboard, không cần Npcap | `--scenarios a,b`, `--warmup 35`, `--gap 10`, `--seed` |
| `live -i IFACE` | Bắt gói thật từ card mạng (cần Npcap) | `-f "BPF filter"` |
| `replay FILE` | Phân tích file `.pcap`/`.pcapng` | `--speed 0` (nhanh nhất) hoặc `1` (thời gian thực) |
| `gen-pcap [OUT]` | Ghi pcap chứa 16 kịch bản tấn công (mặc định `captures/demo-attacks.pcap`) | `--seed 1337`, `--warmup 60`, `--gap 10`, `--scenarios` |
| `interfaces` | Liệt kê card mạng | |
| `alerts` | Đọc alert đã lưu trong SQLite | `--demo`, `-s high`, `-d dns`, `--search`, `-n 30` |
| `train FILE` | Train Isolation Forest từ pcap traffic bình thường | `-o models/x.json` |
| `intel update` | Tải blacklist IP từ feed threat intel miễn phí | |
| `info` | Liệt kê detector, rule, MITRE ATT&CK | |

`demo`, `live`, `replay` dùng chung: `-c/--config`, `--no-web`, `--host`, `--port`, `--open`, `-q`, `-v`.

**Cấu hình xếp lớp** ([config.py](../mini_ids/config.py)): `config/default.yaml` → bị đè bởi `config/local.yaml` (nếu có, đã nằm trong `.gitignore`) → bị đè bởi file truyền qua `--config`. Lệnh `demo` tự dùng `config/demo.yaml`; `replay` và `live` chỉ dùng nó khi bạn truyền `--config config/demo.yaml`. Pytest thì bỏ qua `local.yaml` (`Config.load(..., use_local=False)` trong [conftest.py](../tests/conftest.py)) để kết quả test không phụ thuộc cấu hình riêng trên máy bạn; muốn thấy tác động của `local.yaml` hãy chạy `demo` hoặc `replay`.

### 1.2 Lộ trình tổng quan

| Cấp độ | Bạn học được | File chính | Kiểm chứng bằng |
|---|---|---|---|
| 1. Đọc gói tin | Tầng TCP/IP, cờ TCP, UDP/ICMP/ARP/DNS, 5-tuple, flow | [packet.py](../mini_ids/packet.py), [flows.py](../mini_ids/flows.py), [synthetic.py](../mini_ids/capture/synthetic.py) | Wireshark + `gen-pcap` |
| 2. Phát hiện bằng ngưỡng | Cửa sổ trượt, đếm giá trị khác nhau, tỉ lệ, FP/FN | [utils.py](../mini_ids/utils.py), [portscan.py](../mini_ids/detectors/portscan.py), [flood.py](../mini_ids/detectors/flood.py), [bruteforce.py](../mini_ids/detectors/bruteforce.py), [arp.py](../mini_ids/detectors/arp.py) | [test_detectors.py](../tests/test_detectors.py) |
| 3. Signature & threat intel | Rule kiểu Snort, IOC, DNS tunneling/DGA | [rules.yaml](../config/rules.yaml), [signatures.py](../mini_ids/detectors/signatures.py), [blacklist.py](../mini_ids/detectors/blacklist.py), [dns.py](../mini_ids/detectors/dns.py) | [test_signatures.py](../tests/test_signatures.py) |
| 4. Hành vi, thống kê, vận hành | Beacon (CV), exfil, EWMA z-score, dedup, evidence | [beacon.py](../mini_ids/detectors/beacon.py), [exfil.py](../mini_ids/detectors/exfil.py), [anomaly.py](../mini_ids/detectors/anomaly.py), [manager.py](../mini_ids/manager.py), [evidence.py](../mini_ids/evidence.py) | [test_integration.py](../tests/test_integration.py), dashboard |
| 5. ML & đánh giá | Isolation Forest, feature, precision/recall, so sánh với Suricata/Zeek | [iforest.py](../mini_ids/iforest.py), [ml.py](../mini_ids/detectors/ml.py) | [test_ml.py](../tests/test_ml.py), bài tập 14–18 |

### 1.3 Kiến trúc trong 30 giây

```
nguồn gói: live / replay / demo                       mini_ids/capture/
        │ gói Scapy
        ▼
from_scapy() ──► PacketInfo                           mini_ids/packet.py
        ├──► TrafficStats (số liệu dashboard)          mini_ids/stats.py
        ├──► EvidenceBuffer (ring 5000 gói gần nhất)   mini_ids/evidence.py
        └──► 12 detector: process(pkt) mỗi gói, tick(now) ~1 lần/giây
                   │ Alert
                   ▼
             AlertManager: dedup/cooldown, ghi evidence .pcap    mini_ids/manager.py
                   ▼
     sinks: console · logs/*.jsonl · SQLite · webhook             mini_ids/sinks.py
                   ▼
     dashboard FastAPI + WebSocket (127.0.0.1:8800)               mini_ids/web/server.py
```

- Hợp đồng của detector nằm trong [base.py](../mini_ids/detectors/base.py): `process()` chạy cho **mọi** gói nên phải nhanh; `tick()` dọn state cũ và xử lý việc theo chu kỳ.
- Khi replay, "thời gian" là thời gian ghi trong gói tin chứ không phải đồng hồ máy. [engine.py](../mini_ids/engine.py) gọi `tick()` mỗi khi thời gian gói vượt sang giây mới, nhờ vậy replay file 1 giờ trong vài giây vẫn cho kết quả như chạy thật.
- Muốn thêm detector: viết class kế thừa `Detector` rồi thêm vào `ALL` trong [detectors/\_\_init\_\_.py](../mini_ids/detectors/__init__.py).

---

<a id="s2"></a>
## 2. Nền tảng mạng cần nắm

### 2.1 Mô hình TCP/IP và `PacketInfo`

| Tầng | Giao thức trong dự án | Trường `PacketInfo` tương ứng |
|---|---|---|
| Link (L2) | Ethernet, ARP | `src_mac`, `dst_mac`, `arp_op`, `arp_hwsrc` |
| Internet (L3) | IPv4, IPv6, ICMP | `src`, `dst`, `ttl` (IPv6: hop limit), `icmp_type`, `icmp_code` |
| Transport (L4) | TCP, UDP | `proto`, `sport`, `dport`, `flags` |
| Application (L7) | DNS, HTTP, FTP, SSH, TLS... | `payload` (tối đa `capture.max_payload` = 2048 byte), `dns_*` |

[packet.py](../mini_ids/packet.py) chuẩn hoá gói Scapy thành `PacketInfo` **đúng một lần**, sau đó mọi detector dùng chung. Nhờ vậy detector không phụ thuộc Scapy và test có thể tự dựng gói giả bằng hàm `pkt()` trong [conftest.py](../tests/conftest.py), ví dụ `pkt(ts=100, dport=22)` là một gói TCP SYN tới port 22.

| Giao thức | `proto` | Trường được điền trong `from_scapy()` |
|---|---|---|
| TCP | `"TCP"` | `src`, `dst`, `sport`, `dport`, `flags` (vd `"S"`, `"SA"`, `"PA"`, `"FPU"`), `ttl`, `payload` |
| UDP | `"UDP"` | `sport`, `dport`, `payload`; nếu có lớp DNS thì thêm `dns_*` |
| DNS (trên UDP) | `"UDP"` | `dns_qname` (có dấu chấm cuối, vd `"github.com."`), `dns_qtype`, `dns_rcode`, `dns_response` |
| ICMP | `"ICMP"` | `icmp_type`, `icmp_code`, `payload`; `sport`/`dport` là `None` |
| ICMPv6 | `"ICMPv6"` | `icmp_type` |
| ARP | `"ARP"` | `arp_op`, `src` = psrc, `dst` = pdst, `arp_hwsrc`; không có `ttl` |
| Mọi gói | | `ts`, `length` (cả frame), `src_mac`, `dst_mac`, `raw` (gói Scapy gốc, để ghi evidence) |

Các property tiện dụng: `is_syn` (có S, không có A), `is_synack`, `is_rst`, `is_dns_query`.

### 2.2 TCP: bắt tay 3 bước và cờ

```
Client                                   Server
  │── SYN (S), seq=x ──────────────────────►│  "tôi muốn kết nối"
  │◄──────────── SYN/ACK (SA), ack=x+1 ─────│  port MỞ
  │── ACK (A) ─────────────────────────────►│  kết nối đã thiết lập
  │── PSH/ACK (PA) + dữ liệu ──────────────►│
  │── FIN/ACK (FA) ────────────────────────►│  đóng kết nối
  │
  │   Nếu port ĐÓNG, server trả RST/ACK (RA) thay cho SA.
```

| Chữ (Scapy) | Cờ | Bit | Vai trò |
|---|---|---|---|
| F | FIN | 0x01 | Kết thúc gửi dữ liệu |
| S | SYN | 0x02 | Mở kết nối, đồng bộ số thứ tự |
| R | RST | 0x04 | Huỷ ngay kết nối / từ chối port đóng |
| P | PSH | 0x08 | Đẩy dữ liệu lên ứng dụng ngay |
| A | ACK | 0x10 | Xác nhận đã nhận |
| U | URG | 0x20 | Dữ liệu khẩn (gần như không còn dùng) |

- Tổ hợp bình thường: `S`, `SA`, `A`, `PA`, `FA`, `R`/`RA`.
- Tổ hợp **bất thường**, client thật không bao giờ gửi: **NULL** (không cờ, `tcp.flags == 0x000`), **FIN đơn lẻ** (`0x001`), **XMAS** = FIN+PSH+URG (`0x029`, "sáng đèn như cây thông Noel"). Theo RFC 793, port đóng sẽ trả RST cho các gói này còn port mở thì im lặng, nên kẻ tấn công đoán được trạng thái port mà không cần bắt tay đầy đủ (`nmap -sN/-sF/-sX`). Windows trả RST trong mọi trường hợp nên kỹ thuật này kém hiệu quả trên Windows.
- `flags` là chuỗi Scapy như `"FPU"`. Hàm `stealth_scan_type()` so sánh dạng **tập hợp**, nên thứ tự chữ không quan trọng.
- "Half-open": SYN gửi đi mà không hoàn tất ACK. Đây là nền của cả SYN scan (`nmap -sS` gửi RST ngay sau khi nhận SA) lẫn SYN flood.

### 2.3 UDP

- Không bắt tay, không cờ. "Port mở" chỉ đoán được qua phản hồi của ứng dụng, hoặc qua ICMP *port unreachable* (type 3, code 3) nếu port đóng.
- Port hay gặp: DNS 53, NTP 123, mDNS 5353, QUIC 443/udp.
- Port tạm (ephemeral) của client: IANA quy định 49152–65535 (Windows dùng dải này, `SyntheticTraffic.eport()` cũng vậy); Linux mặc định 32768–60999.
- Hệ quả trong code: gói UDP **trả lời** từ port dịch vụ (`sport < 1024`, vd DNS 53, QUIC 443) về nhiều port tạm của client trông giống "dò nhiều port", nên [portscan.py](../mini_ids/detectors/portscan.py) bỏ qua chúng (`test_udp_responses_are_not_counted`).

### 2.4 ICMP

| type | Ý nghĩa |
|---|---|
| 8 | Echo request (ping) |
| 0 | Echo reply |
| 3 | Destination unreachable (code 3 = port unreachable) |
| 11 | Time exceeded (traceroute dựa vào cái này) |

ICMP **không có port**. Trong flow table, mọi ping giữa 2 host rơi vào cùng một khoá `(ICMP, A, 0, B, 0)` và gộp thành một "flow" dài bất thường, nên ML bỏ qua ICMP, còn `IcmpDetector` chuyên trách phần này. Payload ping mặc định: Windows 32 byte, Linux 56 byte.

### 2.5 ARP

- Hỏi "IP này là MAC nào?" trong LAN. Request (`op=1`, "who-has 192.168.1.1? tell 192.168.1.20") gửi broadcast `ff:ff:ff:ff:ff:ff`; reply (`op=2`, "192.168.1.1 is-at 00:11:22:33:44:01") gửi unicast.
- **ARP không có xác thực**: máy nhận chấp nhận cả reply không ai hỏi (gratuitous ARP) và ghi đè cache. Đây là gốc rễ của ARP spoofing / MITM.
- Trong `PacketInfo`: `src` = psrc (IP mà gói khai), `arp_hwsrc` = MAC mà gói khai. MAC này có thể khác MAC nguồn của khung Ethernet; detector tin vào `arp_hwsrc` vì đó là thứ nạn nhân ghi vào cache.
- ARP chỉ tồn tại trong một broadcast domain. Sensor phải nằm trong cùng LAN (hoặc nhận bản sao qua SPAN/mirror port) mới thấy được.

### 2.6 DNS

- Query và response đi qua UDP 53, dùng chung ID; bit QR = 0 là query, 1 là response.
- `qtype`: A = 1, MX = 15, TXT = 16, AAAA = 28.
- `rcode`: 0 NOERROR, 2 SERVFAIL, **3 NXDOMAIN** (tên không tồn tại).
- Giới hạn: mỗi label tối đa 63 byte, cả tên tối đa khoảng 253 ký tự.
- Trong dự án, DNS chỉ được parse trong nhánh UDP của `from_scapy()`. DNS qua TCP/53 không được soi, còn DNS-over-HTTPS (DoH, port 443) thì hoàn toàn vô hình với IDS mạng.

### 2.7 5-tuple và flow

5-tuple = (protocol, IP nguồn, port nguồn, IP đích, port đích). [flows.py](../mini_ids/flows.py) sắp xếp hai đầu mút trong khoá (`FlowTable._key`) nên hai chiều của cùng một kết nối gộp thành **một flow hai chiều**; chiều "fwd" là chiều của gói đầu tiên nhìn thấy. Flow kết thúc khi im lặng quá `flow_idle_timeout` (15 s, demo 5 s), hoặc bị đẩy ra khi bảng vượt 50.000 flow. Đây cũng là cách NetFlow/IPFIX, Zeek `conn.log` và CICFlowMeter làm việc.

| # | Feature | Ý nghĩa | Tấn công hay làm lệch |
|---|---|---|---|
| 0 | `log_duration` | log(1 + thời lượng giây) | Reverse shell kéo dài, exfil |
| 1–2 | `log_fwd_pkts`, `log_bwd_pkts` | log số gói mỗi chiều | Scan (1 gói đi, 0–1 gói về) |
| 3–4 | `log_fwd_bytes`, `log_bwd_bytes` | log số byte mỗi chiều | Exfil (chiều đi rất lớn) |
| 5 | `mean_fwd_size` | byte trung bình mỗi gói chiều đi | Exfil, tunnel |
| 6 | `syn_ratio` | số gói có SYN / tổng số gói | SYN flood, scan (= 1.0) |
| 7 | `rst` | 1 nếu có RST | Scan vào port đóng |
| 8 | `fin` | 1 nếu có FIN | Kết nối bị bỏ dở |
| 9 | `no_reply` | 1 nếu chiều về không có gói nào | Scan, flood từ IP giả |
| 10 | `dport_class` | 0: < 1024, 1: < 49152, 2: còn lại | Port lạ (4444, 3333) |
| 11 | `proto` | 0 TCP, 1 UDP | |

Vì sao dùng `log1p`: số byte/gói có phân phối đuôi dài; nếu không lấy log, một flow 60 MB sẽ đẩy mọi flow khác dồn về một góc và nhát cắt ngẫu nhiên của Isolation Forest mất tác dụng.

### 2.8 `home_net` và external

`home_net` trong [default.yaml](../config/default.yaml) gồm 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918) và fe80::/10, tương đương `$HOME_NET`/`$EXTERNAL_NET` trong Snort/Suricata. Exfil (trong → ngoài), beacon (trong → ngoài), rule có `src_net`/`dst_net` đều dựa vào nó. `home_net` sai thì các detector này hoặc mù, hoặc báo nhầm. Ví dụ: mạng nhà bạn có IPv6 công khai (2001:...) thì phải thêm prefix đó vào.

Địa chỉ trong dữ liệu giả lập ([synthetic.py](../mini_ids/capture/synthetic.py)):

| Vai trò | Địa chỉ |
|---|---|
| Gateway + DNS resolver | 192.168.1.1 (MAC thật `00:11:22:33:44:01`) |
| Web server nội bộ | 192.168.1.10 |
| Máy trạm | 192.168.1.20, .30, .40 |
| Máy nội bộ bị chiếm quyền | 192.168.1.66 |
| Kẻ tấn công / C2 | 198.51.100.0/24 (TEST-NET-2) và 203.0.113.0/24 (TEST-NET-3), dải dành cho tài liệu theo RFC 5737, không bao giờ được định tuyến trên Internet |
| SYN flood | IP ngẫu nhiên, mô phỏng IP giả mạo |
| MAC kẻ tấn công ARP | `de:ad:be:ef:00:01` |

---

<a id="s3"></a>
## 3. IDS là gì

### 3.1 NIDS và HIDS

| | NIDS (Network IDS) | HIDS (Host IDS) |
|---|---|---|
| Nhìn vào | Gói tin trên dây mạng | Log, tiến trình, file, registry trên từng máy |
| Ví dụ | Suricata, Snort, Zeek, **mini-IDS** | Wazuh/OSSEC, Sysmon + SIEM, EDR |
| Mạnh | Một sensor thấy cả mạng; kẻ tấn công khó xoá dấu vết trên dây | Thấy cả nội dung đã giải mã, lệnh đã chạy |
| Yếu | Mù trước traffic mã hoá; cần đặt sensor đúng chỗ | Phải cài agent lên từng máy; malware có thể tắt agent |

### 3.2 IDS và IPS

IDS đứng **bên cạnh** luồng dữ liệu (nhận bản sao) và chỉ cảnh báo. IPS đứng **trên đường đi** (inline) và chặn được gói. mini-IDS là IDS thuần: không chặn, không gửi gì vào mạng. Với IPS, một false positive nghĩa là chặn nhầm người dùng thật, nên rule dùng cho IPS phải khắt khe hơn nhiều.

### 3.3 Ba (bốn) cách phát hiện

| Cách | Ý tưởng | Trong dự án | Mạnh | Yếu |
|---|---|---|---|---|
| Signature | So khớp mẫu đã biết | [signatures.py](../mini_ids/detectors/signatures.py), [blacklist.py](../mini_ids/detectors/blacklist.py) | Chính xác, giải thích được ("khớp rule 1000006") | Mù zero-day, mù TLS, né được bằng encode |
| Heuristic hành vi | Đếm hành vi trong cửa sổ thời gian | portscan, flood, arp, dns, bruteforce, beacon, exfil | Bắt được cả biến thể mới của cùng hành vi | Phải chỉnh ngưỡng theo từng mạng; né được bằng chậm hoặc phân tán |
| Anomaly thống kê | Học "bình thường", báo khi lệch xa | [anomaly.py](../mini_ids/detectors/anomaly.py) | Không cần biết trước tấn công | FP khi mạng đổi thói quen; baseline có thể bị "đầu độc" |
| ML không giám sát | Mô hình nhiều chiều học từ flow | [ml.py](../mini_ids/detectors/ml.py) | Bắt tổ hợp lạ mà không rule nào mô tả | Khó giải thích, phụ thuộc dữ liệu học, không thấy nội dung |

Không cách nào đủ một mình. Phần 4.12 cho thấy bằng số liệu thật rằng ML không phân biệt được SSH brute force, DGA hay SQLi với flow bình thường, trong khi signature và detector chuyên biệt bắt chúng dễ dàng.

### 3.4 Đo chất lượng: TP, FP, FN, TN

| | IDS báo | IDS im lặng |
|---|---|---|
| **Có tấn công thật** | True Positive (TP) | False Negative (FN): lọt |
| **Không có tấn công** | False Positive (FP): báo nhầm | True Negative (TN) |

- **Precision** = TP / (TP + FP): trong các alert, bao nhiêu phần trăm là thật.
- **Recall** = TP / (TP + FN): trong các cuộc tấn công, bắt được bao nhiêu phần trăm.
- **Base rate**: giả sử mạng có 1.000.000 flow/ngày, chỉ 10 flow là tấn công, và IDS có tỉ lệ báo nhầm chỉ 0,1%. Khi đó có khoảng 1.000 FP/ngày; dù bắt đủ 10 flow thật, precision cũng chỉ ≈ 10/1010 ≈ 1%. Vì vậy IDS thực tế ưu tiên giảm FP.
- Ví dụ từ chính dự án: ngưỡng ML ban đầu là 0,66 và cho khoảng **4 FP mỗi 3 phút** traffic bình thường; ngưỡng được nâng lên 0,70. Test `test_normal_traffic_is_quiet` trong [test_integration.py](../tests/test_integration.py) giữ cam kết "3 phút traffic sạch = 0 alert, kể cả ML".

### 3.5 Alert fatigue và dedup (`AlertManager`)

Một cú SYN flood 1.500 gói có thể sinh 1.000 alert giống hệt nhau. Analyst ngập trong đó sẽ bỏ qua cả alert thật. Hiện tượng này gọi là **alert fatigue**. [manager.py](../mini_ids/manager.py) xử lý như sau:

1. Mỗi alert có khoá `(detector, key)`. `key` do detector chọn, vd portscan dùng `v:{src}->{dst}`, signature dùng `{sid}:{src}->{dst}`.
2. Nếu đã có alert cùng khoá và `0 <= ts - ts_của_alert_đầu < cooldown_seconds` (60 s) thì **không tạo alert mới**: chỉ tăng `count`, cập nhật `last_seen` và tăng bộ đếm `suppressed`.
3. Cooldown tính từ **alert đầu tiên**, không trượt theo lần mới nhất, nên tấn công kéo dài vẫn sinh 1 alert mới mỗi 60 s: đủ để biết nó còn tiếp diễn mà không gây ngập.
4. `flush()` đẩy `count` đã gộp xuống sink (SQLite, dashboard); khoá được dọn khi im lặng quá 2 × cooldown.

Khi replay pcap demo, "Vertical port scan" hiện 1 dòng với `count` 101 (120 port, alert từ port thứ 20 trở đi), còn SYN flood hiện 1 dòng với count khoảng 1.000.

**Chọn `key` là một quyết định thiết kế.** Key quá mịn thì vẫn ngập; key quá thô thì gộp mất các cuộc tấn công khác nhau. Ví dụ thật: ML gom alert theo đích (`dst:192.168.1.10`). Alert ML đầu tiên mở lúc portscan/stealth scan (t≈60–70) "nuốt" luôn các flow bất thường của SYN flood tới cùng web server trong 60 giây sau đó. Dashboard chỉ còn 1 dòng "Flow bất thường (ML)" với `count` lớn hơn 1, dù thực ra có 2–3 cuộc tấn công khác nhau.

### 3.6 Evidence và triage bằng pcap

IDS chỉ nói "có vấn đề"; analyst phải xác minh (triage). [evidence.py](../mini_ids/evidence.py) giữ ring buffer 5.000 gói gần nhất (`evidence.buffer_packets`). Khi có alert **mới**, [manager.py](../mini_ids/manager.py) chờ thêm `evidence.delay_seconds` (mặc định 5 giây) rồi mới lọc gói liên quan và ghi ra `evidence/<id>.pcap` (demo: `evidence/demo/`). Lý do chờ: lúc alert bật thường mới thấy phần đầu cuộc tấn công. Quy tắc lọc:

- Alert có cả `src` và `dst`: chỉ lấy hội thoại giữa 2 bên.
- Alert chỉ có 1 bên (vd SYN flood phân tán có `src=None`): lấy mọi gói dính tới bên đó, nên lẫn cả traffic bình thường.
- Không có IP nào (vd anomaly không xác định được thủ phạm): không có pcap.
- Tối đa 400 gói (`max_packets_per_alert`), chỉ gồm gói tới **5 giây sau** alert đầu tiên. Ví dụ: alert "FTP login cleartext" bật ở dòng `USER admin`; nhờ ghi trễ, dòng `PASS` đến ngay sau vẫn có trong pcap (test `test_evidence_includes_packets_after_alert`). Nhưng tấn công kéo dài hơn cửa sổ đó (SYN flood nhiều phút) thì phần sau chỉ làm tăng `count`. Hệ thống thật như Suricata pcap-log hay Arkime lưu full packet capture để khắc phục điều này.
- Evidence được ghi trễ nên file JSONL (ghi ngay lúc alert) chưa có đường dẫn `pcap`; SQLite và dashboard thì được cập nhật khi pcap xong.

Quy trình triage gợi ý: đọc mô tả và trường `evidence` của alert → mở pcap bằng Wireshark → trả lời "đây là TP hay FP, vì sao?" → đánh dấu "đã xử lý" (ack) trên dashboard.

### 3.7 MITRE ATT&CK

ATT&CK (attack.mitre.org) là "từ điển" hành vi kẻ tấn công: **tactic** là mục tiêu (Discovery, Credential Access, Command and Control...), **technique** là cách làm, có ID như `T1046`. Gắn ID giúp alert của mọi công cụ nói cùng một ngôn ngữ và giúp bạn thấy mình đang mù ở tactic nào. `python -m mini_ids info` in ra bảng này.

| Detector | Technique | Tactic |
|---|---|---|
| portscan | T1046 Network Service Discovery | Discovery |
| synflood | T1498 Network DoS, T1499 Endpoint DoS | Impact |
| icmp | T1018 Remote System Discovery, T1498, T1095 Non-Application Layer Protocol | Discovery, Impact, C2 |
| arp | T1557.002 ARP Cache Poisoning | Credential Access, Collection |
| dns | T1071.004 DNS, T1568.002 DGA, T1048 | Command and Control, Exfiltration |
| bruteforce | T1110 Brute Force | Credential Access |
| blacklist | T1071 Application Layer Protocol | Command and Control |
| signatures | Theo từng rule: T1190, T1059, T1040, T1571, T1496... | Initial Access, Execution, C2, Impact... |
| beacon | T1071, T1573 Encrypted Channel | Command and Control |
| exfil | T1048, T1041 | Exfiltration |
| anomaly | T1498 | Impact |
| ml | (không gán sẵn, vì ML không biết "loại" tấn công) | |

### 3.8 Bản thân IDS cũng là mục tiêu

IDS parse dữ liệu **do kẻ tấn công kiểm soát**: tên DNS, payload HTTP, User-Agent. Những chuỗi đó đi thẳng vào alert, log và dashboard. Dự án phòng thủ nhiều lớp:

- **XSS vào dashboard**: nếu giao diện hiển thị alert bằng `innerHTML`, kẻ tấn công chỉ cần gửi request `GET /<img src=x onerror=...>` là mã JS chạy trong trình duyệt của analyst. [app.js](../mini_ids/web/static/app.js) không bao giờ dùng `innerHTML` cho nội dung alert, mọi thứ dựng bằng DOM + `textContent`. Thêm vào đó, [server.py](../mini_ids/web/server.py) gửi header `Content-Security-Policy` (`script-src 'self'`, `frame-ancestors 'none'`) và `X-Content-Type-Options: nosniff`; `test_api` kiểm tra header CSP.
- Dashboard **không có đăng nhập** và mặc định chỉ nghe `127.0.0.1`. Đừng chạy `--host 0.0.0.0` trên mạng dùng chung.
- API tải pcap chỉ phục vụ file nằm trong thư mục evidence (chống path traversal, `test_pcap_download_rejects_paths_outside_evidence`).
- Model ML lưu bằng JSON chứ không phải pickle, vì nạp pickle có thể thực thi code tuỳ ý.
- Chống cạn tài nguyên: FlowTable tối đa 50.000 flow (SYN flood từ IP giả tạo **một flow mỗi gói**), hàng đợi webhook tối đa 200, và `Engine` bắt exception của từng detector để một gói dị dạng không làm sập cả IDS.

---

<a id="s4"></a>
## 4. Từng detector

Mỗi mục theo cùng khuôn: **Tấn công là gì · Dấu hiệu trên mạng · Cách code phát hiện · Tham số & tinh chỉnh · False positive · Kẻ tấn công né ra sao · MITRE · Wireshark**. Phần "né" chỉ ở mức khái niệm, để bạn biết điểm mù cần vá. Wireshark filter áp dụng cho `captures/demo-attacks.pcap` (phần 5). Mọi tham số nằm dưới `detectors.<tên>` trong [default.yaml](../config/default.yaml).

Cả 12 detector dựa trên 3 cấu trúc trong [utils.py](../mini_ids/utils.py): `WindowCounter` (đếm sự kiện trong `window` giây gần nhất), `WindowDistinct` (đếm số giá trị **khác nhau**) và `WindowSum` (cộng dồn byte). Hiểu 3 class này là hiểu 80% phần ngưỡng.

### 4.1 Port scan: [portscan.py](../mini_ids/detectors/portscan.py)

- **Tấn công:** trinh sát xem host nào mở dịch vụ nào (nmap, masscan) trước khi khai thác.
- **Dấu hiệu:** một nguồn chạm nhiều port trên một host (vertical), hoặc cùng một port trên nhiều host (horizontal); nhiều RST/ACK trả về từ port đóng; gói có tổ hợp cờ vô lý.
- **Cách code phát hiện:**
  - Chỉ đếm TCP SYN thuần (`is_syn`) và UDP không phải DNS response; bỏ UDP có `sport < 1024 <= dport` (đó là response).
  - Vertical: `WindowDistinct` khoá `(src, dst)` → tập `dport`. Nếu ≥ `vertical_threshold` trong `window` giây → **high**.
  - Horizontal: khoá `(src, dport)` → tập `dst`. Nếu ≥ `horizontal_threshold` → **high**, trừ port trong `horizontal_ignore_ports`.
  - Stealth: `stealth_scan_type(flags)` trả `NULL`/`FIN`/`XMAS` → **medium** ngay từ gói đầu (dedup theo `stealth:{type}:{src}`).
- **Tham số:** `window: 10`, `vertical_threshold: 20`, `horizontal_threshold: 20`, `horizontal_ignore_ports: [53, 80, 123, 443, 853, 5353]`. Tăng `window` bắt được scan chậm hơn nhưng tốn RAM hơn và dễ FP hơn; giảm ngưỡng bắt được scan "top 10 port".
- **False positive:** trình duyệt nói chuyện với hàng chục host trên 443 (vì vậy 443 bị bỏ qua khi xét horizontal, xem `test_normal_browsing_is_not_a_scan`); response UDP của DNS/QUIC; scanner lỗ hổng hoặc hệ thống giám sát hợp lệ của chính bạn; BitTorrent/P2P; NAT gateway có nhiều người dùng sau một IP.
- **Né:** quét chậm hơn cửa sổ 10 s (nmap `-T0`/`-T1`), chia nhỏ qua nhiều IP nguồn hoặc dùng decoy, chỉ quét dưới 20 port, idle scan qua máy "zombie". Hướng vá: thêm cửa sổ dài với ngưỡng riêng, gộp theo dải /24 nguồn, đếm tỉ lệ RST trả về.
- **MITRE:** T1046 (quét từ Internet vào còn ứng với T1595 Active Scanning).
- **Wireshark:**

| Filter | Thấy gì |
|---|---|
| `ip.src == 198.51.100.23 && tcp.flags.syn == 1 && tcp.flags.ack == 0` | 120 SYN tới 120 port khác nhau trong ~2,4 s |
| `ip.src == 192.168.1.10 && tcp.flags.reset == 1` | Port đóng trả RST/ACK |
| `tcp.flags == 0x029` | XMAS (FIN+PSH+URG) |
| `tcp.flags == 0x000` | NULL |
| `tcp.flags == 0x001` | FIN đơn lẻ |

### 4.2 SYN flood: `SynFloodDetector` trong [flood.py](../mini_ids/detectors/flood.py)

- **Tấn công:** DoS bằng hàng loạt SYN không bao giờ hoàn tất bắt tay. Server giữ kết nối half-open tới khi backlog đầy. IP nguồn thường bị giả mạo nên SYN/ACK trả về bị thất lạc.
- **Dấu hiệu:** tốc độ SYN tới một `(dst, dport)` rất cao; gần như không có ACK hoàn tất; số IP nguồn khác nhau cực lớn, mỗi IP chỉ một gói.
- **Cách code phát hiện:** đếm SYN thuần theo `(dst, dport)`; đếm ACK thuần (`flags == "A"`) tới cùng đích; đếm số nguồn khác nhau.
  - `rate = n_syn / window`; báo khi `rate >= rate_threshold` **và** `completion = n_ack / n_syn <= max_completion_ratio`.
  - Từ 50 nguồn trở lên: tiêu đề "phân tán / IP giả mạo", mức **critical**, `src=None` (không đổ lỗi cho một IP vì IP là giả).
- **Tham số:** `window: 5`, `rate_threshold: 100` (SYN/s), `max_completion_ratio: 0.3`. Hai điều kiện AND giúp web server bận (nhiều SYN nhưng bắt tay hoàn tất) không bị báo (`test_busy_server_with_completed_handshakes_is_ok`). Đây là mẫu thiết kế giảm FP đáng nhớ.
- **False positive:** dịch vụ chết khiến client gửi lại SYN liên tục; load test của chính bạn; health check dày đặc từ load balancer.
- **Né:** flood tầng ứng dụng có hoàn tất bắt tay (HTTP flood, Slowloris) khiến completion cao và detector này mù; ACK flood/UDP flood; rải dưới ngưỡng trên nhiều đích. Phòng thủ thật: SYN cookies, rate limit, dịch vụ chống DDoS phía nhà mạng.
- **MITRE:** T1498, T1499 (cụ thể SYN flood là T1499.001 OS Exhaustion Flood).
- **Wireshark:** `tcp.dstport == 80 && tcp.flags.syn == 1 && tcp.flags.ack == 0`. Statistics → Conversations → IPv4 cho thấy khoảng 1.500 IP nguồn, mỗi IP 1 gói; I/O Graph có đỉnh tại t≈80.

### 4.3 ICMP flood, ping sweep, ICMP tunnel: `IcmpDetector` trong [flood.py](../mini_ids/detectors/flood.py)

- **Tấn công:** ping sweep để tìm máy đang sống (trinh sát); ping flood (DoS); ICMP tunnel giấu dữ liệu trong payload echo.
- **Dấu hiệu:** một nguồn gửi echo-request tới nhiều IP liên tiếp; rất nhiều echo-request/s tới một đích; payload lớn bất thường.
- **Cách code phát hiện:**
  - Flood: `WindowCounter` theo `dst`, `rate >= flood_rate` → **high**.
  - Sweep: `WindowDistinct` nguồn → đích, `>= sweep_threshold` trong `sweep_window` → **medium**.
  - Payload: `len(payload) >= large_payload` với mọi ICMP type → **low** (T1095).
- **Tham số:** `window: 5`, `flood_rate: 50`, `sweep_window: 10`, `sweep_threshold: 15`, `large_payload: 1024`.
- **False positive:** hệ thống giám sát (Zabbix, PRTG, Uptime Kuma) ping nhiều host định kỳ, là FP kinh điển của ping sweep; code chưa có allowlist nguồn, đây là bài tập tốt. `ping -l 1472` khi dò MTU tạo payload lớn.
- **Né:** trong LAN dùng ARP scan thay ping (ArpSpoofDetector bắt ARP scan từ 50 IP), TCP ping (`nmap -PS443`), quét chậm; tunnel dùng payload nhỏ và tốc độ thấp.
- **MITRE:** T1018 (sweep), T1498 (flood), T1095 (tunnel).
- **Wireshark:** `icmp.type == 8 && ip.src == 192.168.1.66` (sweep 40 IP từ .2 tới .41), `icmp.type == 8 && ip.src == 203.0.113.50` (600 ping trong 2,4 s), `icmp && data.len >= 1024` (gói 1.400 byte).

### 4.4 ARP spoofing: [arp.py](../mini_ids/detectors/arp.py)

- **Tấn công:** kẻ trong LAN gửi ARP reply giả "192.168.1.1 is-at <MAC của tôi>". Nạn nhân gửi mọi traffic ra Internet qua máy kẻ tấn công (MITM) để nghe lén hoặc sửa nội dung. Công cụ: arpspoof, ettercap, bettercap.
- **Dấu hiệu:** một IP đổi MAC; một MAC nhận là chủ nhiều IP; nhiều reply không ai hỏi; bảng ARP "lật" qua lại giữa MAC thật và giả khi gateway thật cũng lên tiếng.
- **Cách code phát hiện:** học bảng `ip → mac` từ mọi gói ARP (bỏ `0.0.0.0` và MAC toàn 0 hoặc toàn f):
  - IP đã biết mà MAC khác → **high** "IP đổi địa chỉ MAC".
  - Một MAC khai ≥ `multi_ip_threshold` IP → **medium**.
  - Reply (`op 2`) từ một MAC ≥ `reply_flood_threshold` trong `window` → **medium**.
  - Request (`op 1`) từ một IP tới ≥ `scan_threshold` IP khác nhau → **low** "ARP scan" (T1018).
  - Bảng đã học xem được ở `/api/arp` trên dashboard.
- **Tham số:** `window: 10`, `reply_flood_threshold: 30`, `scan_threshold: 50`, `multi_ip_threshold: 5`. Kịch bản `arp_spoof` chỉ gửi 12 reply nên **không** chạm ngưỡng flood; alert đến từ quy tắc "đổi MAC", với count ≥ 2 vì reply ARP thật của gateway trong nền làm bảng lật lại.
- **False positive:** DHCP cấp lại IP cũ cho máy khác (bảng không bao giờ hết hạn); failover VRRP/HSRP; router proxy-ARP hoặc máy chạy nhiều IP; thay card mạng; Wi-Fi repeater.
- **Né:** đầu độc **trước** khi IDS bật, khiến IDS học MAC giả làm chuẩn (baseline poisoning); gửi reply unicast chỉ tới một nạn nhân trên switch, sensor không có SPAN sẽ không thấy; gửi ít reply dưới ngưỡng flood. Phòng thủ thật: Dynamic ARP Inspection + DHCP snooping trên switch, ARP tĩnh cho gateway trên máy quan trọng, dùng TLS/HSTS để MITM không đọc được nội dung.
- **MITRE:** T1557.002; T1018 cho ARP scan.
- **Wireshark:** `arp.opcode == 2`, `arp.src.hw_mac == de:ad:be:ef:00:01`, và `arp.duplicate-address-detected`: Wireshark tự phát hiện một IP có hai MAC (xem thêm Analyze → Expert Information).

### 4.5 DNS tunneling và DGA: [dns.py](../mini_ids/detectors/dns.py)

- **Tấn công:**
  - **DNS tunneling/exfil:** dữ liệu mã hoá base32/hex nhét vào subdomain, gửi tới name server do kẻ tấn công kiểm soát (iodine, dnscat2). DNS gần như luôn được firewall cho đi ra.
  - **DGA:** malware sinh hàng trăm domain giả ngẫu nhiên mỗi ngày; chỉ vài domain được đăng ký làm C2, số còn lại trả NXDOMAIN.
- **Dấu hiệu:** query rất dài; subdomain có entropy cao; nhiều subdomain **khác nhau** dưới cùng base domain; nhiều query TXT; một client nhận nhiều NXDOMAIN.
- **Cách code phát hiện** (bỏ qua domain trong `allow_domains`):
  - Dài: `len(qname) > max_query_length` hoặc có label dài hơn 50 → **medium**.
  - Entropy Shannon `H = −Σ pᵢ·log₂ pᵢ` trên phần subdomain (bỏ dấu chấm), chỉ khi dài ≥ `entropy_min_length`; `H >= entropy_threshold` → **medium**. Tên người đặt như `mail` có H < 2,5; chuỗi base32 ngẫu nhiên có H > 3,8 (`test_entropy`).
  - Tunneling: `WindowDistinct` khoá `(client, base_domain)` → subdomain, ≥ `unique_subdomain_threshold` → **high**.
  - TXT: ≥ `txt_threshold` query TXT từ một client → **medium**.
  - DGA: đếm response có `rcode == 3` theo client (là `dst` của response), ≥ `nxdomain_threshold` → **high**.
  - `base_domain()` xấp xỉ eTLD+1 bằng một danh sách hậu tố nhỏ (`com.vn`, `co.uk`...), không phải Public Suffix List đầy đủ.
- **Tham số:** `max_query_length: 60`, `entropy_min_length: 20`, `entropy_threshold: 3.8`, `window: 60`, `unique_subdomain_threshold: 40`, `nxdomain_threshold: 20`, `txt_threshold: 30`, `allow_domains: [cloudfront.net, akamaiedge.net, googlevideo.com, amazonaws.com, windowsupdate.com, in-addr.arpa, ip6.arpa]`.
- **False positive:** CDN/cloud có subdomain dài và ngẫu nhiên (lý do tồn tại `allow_domains`); antivirus tra hash qua DNS; mail server tra DNSBL; ứng dụng cấu hình sai sinh NXDOMAIN hàng loạt; search suffix khiến máy thử `host.corp.local` trước rồi mới tới `host`.
- **Né:** tunnel chậm (ít subdomain mỗi phút), rải qua nhiều base domain, label ngắn; DGA dùng từ điển (entropy thấp) thì chỉ còn đếm NXDOMAIN bắt được; DoH/DoT khiến IDS không thấy query; DNS qua TCP/53 là điểm mù hiện tại của `packet.py`.
- **MITRE:** T1071.004, T1568.002, T1048.
- **Wireshark:** `dns.qry.type == 16` (TXT), `dns.qry.name contains "data-sync"`, `len(dns.qry.name) > 60`, `dns.flags.rcode == 3` (NXDOMAIN). Statistics → DNS cho phân bố qtype/rcode.

Kịch bản `dns_tunnel` gửi 54 query TXT tới `*.t.data-sync.example` và làm bật cả 4 loại alert (dài, entropy, TXT, tunneling), nên bạn thấy rõ các tín hiệu độc lập cộng hưởng như thế nào.

### 4.6 Brute-force đăng nhập: [bruteforce.py](../mini_ids/detectors/bruteforce.py)

- **Tấn công:** đoán mật khẩu tự động (Hydra, Medusa, ncrack) vào SSH, RDP, FTP, SMB, DB; hoặc password spraying (một mật khẩu thử cho nhiều tài khoản).
- **Dấu hiệu:** SSH/RDP được mã hoá nên không đọc được mật khẩu, nhưng "hình dạng" traffic lộ ra: rất nhiều kết nối TCP mới, ngắn, giống hệt nhau tới cùng `(dst, port)`.
- **Cách code phát hiện:** đếm SYN thuần tới port trong `ports`, khoá `(src, dst, dport)`; ≥ `threshold` trong `window` → **high** "Brute-force <dịch vụ>".
- **Tham số:** `window: 60`, `threshold: 15`, `ports: {21: FTP, 22: SSH, 23: Telnet, 25: SMTP, 110: POP3, 143: IMAP, 445: SMB, 1433: MSSQL, 3306: MySQL, 3389: RDP, 5432: PostgreSQL, 5900: VNC}`.
- **False positive:** script tự động hợp lệ (Ansible, CI chạy `git` qua SSH, rsync backup), mail client mở nhiều kết nối IMAP, máy chia sẻ file qua SMB, ứng dụng không dùng connection pool tới MySQL/PostgreSQL.
- **Né:** "low and slow" (vài phút một lần, luôn dưới 15/60 s); phân tán qua botnet; thử nhiều mật khẩu trong một kết nối (OpenSSH cho tối đa `MaxAuthTries` = 6 lần mặc định) nên số kết nối ít hơn số lần đoán; spraying qua nhiều host (khoá có `dst`). Phòng thủ bổ sung ở phía host: fail2ban/CrowdSec đọc log đăng nhập, tắt đăng nhập SSH bằng mật khẩu, MFA.
- **Tại sao ML không bắt được:** mỗi flow brute force là handshake → vài gói → đóng, y hệt một phiên SSH ngắn bình thường. Tấn công nằm ở **tần suất theo thời gian**, không nằm trong hình dạng một flow.
- **MITRE:** T1110 (T1110.001 Password Guessing, T1110.003 Password Spraying).
- **Wireshark:** `tcp.dstport == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0` (25 SYN, cách nhau 0,4 s) và `ssh.protocol` (banner `SSH-2.0-libssh_0.10.6`: client là thư viện libssh chứ không phải OpenSSH, một manh mối về công cụ).

### 4.7 Threat intel (blacklist): [blacklist.py](../mini_ids/detectors/blacklist.py)

- **Tấn công:** không phải một kỹ thuật cụ thể, mà là máy nội bộ liên lạc với hạ tầng độc hại **đã biết** (C2, phishing, botnet).
- **Dấu hiệu:** IP nguồn/đích hoặc domain được query khớp IOC (Indicator of Compromise).
- **Cách code phát hiện:** `NetSet` (hỗ trợ IP lẻ và CIDR, có cache) nạp từ `ip_files`; kiểm tra IP đích trước rồi IP nguồn. Domain khớp khi trùng hoặc là subdomain (`domain_matches`: `update.malware-c2.example` khớp, `notmalware-c2.example` thì không). Chỉ xét DNS **query**.
- **Tham số:** `ip_files: [config/blacklist_ips.txt, config/intel_ips.txt]`, `domain_files: [config/blacklist_domains.txt]`. `python -m mini_ids intel update` tải abuse.ch Feodo Tracker và Emerging Threats compromised IPs vào `config/intel_ips.txt`.
- **False positive:** IOC cũ (IP đã đổi chủ); IP của CDN hoặc shared hosting (một IP chứa hàng nghìn website); domain đã bị nhà nghiên cứu sinkhole; feed kém chất lượng.
- **Né:** dùng hạ tầng mới chưa lên feed, fast-flux, domain fronting qua CDN. Đây chính là "Pyramid of Pain" của David Bianco: IP và domain rất dễ đổi, còn hành vi (TTP) mới khó đổi, và đó là lý do cần các detector hành vi.
- **MITRE:** T1071.
- **Wireshark:** `ip.addr == 203.0.113.66`, `dns.qry.name contains "malware-c2"`, `dns.a == 203.0.113.66`.

### 4.8 Signature rules: [signatures.py](../mini_ids/detectors/signatures.py) + [rules.yaml](../config/rules.yaml)

- **Tấn công được phủ:** web (SQLi UNION và tautology, XSS, path traversal, đọc `/etc/passwd`, Log4Shell, Shellshock, command injection, User-Agent của công cụ scan); thông tin đăng nhập cleartext (FTP, HTTP Basic, Telnet); C2/policy (port 4444/1337/31337, IRC, Tor, Stratum mining, SMB ra Internet).
- **Dấu hiệu:** chuỗi hoặc regex đặc trưng trong payload, kết hợp điều kiện header (proto, port, hướng mạng).
- **Cách code phát hiện:** `Rule.from_dict()` biên dịch rule. `match()` kiểm tra theo thứ tự rẻ trước, đắt sau: proto → `dst_port` → `src_port` → `min_payload` → `src_net`/`dst_net` → `content` (**tất cả** phải xuất hiện) → `regex`. Các điểm tinh tế:
  - `nocase: true` là mặc định: content bị hạ chữ thường, regex biên dịch với `IGNORECASE | MULTILINE` (nên `^` khớp đầu mỗi dòng).
  - Rule có content/regex mặc định `min_payload: 1`.
  - Rule **chỉ theo port** (không có payload) chỉ báo ở gói SYN, không báo mọi gói (`test_port_rule_fires_on_syn_only`).
  - Chỉ xét TCP/UDP/ICMP. Alert mang `sid` và `payload_snippet` (160 byte đầu).
- **So sánh với Snort/Suricata** (rule 1000001):

```
alert tcp any any -> any [80,8000,8080,8888] (msg:"SQL Injection: UNION SELECT"; flow:to_server,established; pcre:"/union(\s|%20|\+|\/\*.*?\*\/)+(all(\s|%20|\+)+)?select/i"; classtype:web-application-attack; sid:1000001; rev:1;)
```

```yaml
- id: 1000001
  name: "SQL Injection: UNION SELECT"
  severity: high
  proto: tcp
  dst_port: [80, 8000, 8080, 8888]
  regex: 'union(\s|%20|\+|/\*.*?\*/)+(all(\s|%20|\+)+)?select'
  mitre: [T1190]
```

| mini-IDS | Snort / Suricata |
|---|---|
| `id` | `sid` |
| `name` | `msg` |
| `proto` | giao thức ở header rule (`tcp`, `udp`, `icmp`, `ip`) |
| `src_net` / `dst_net`: `home`, `external`, `any` | `$HOME_NET`, `$EXTERNAL_NET`, `any` |
| `src_port` / `dst_port` | port ở header rule |
| `content` (list, AND) | nhiều `content:"...";` |
| `nocase` | `nocase;` |
| `regex` | `pcre:"/.../i";` |
| `min_payload` | `dsize:>N;` |
| `severity` | `priority` / `classtype` |
| `mitre` | `metadata: mitre_technique_id ...` (có trong rule ET) |
| (chưa có) | `flow:established,to_server`, `threshold`/`detection_filter`, buffer `http.uri`/`http.header`, `offset`/`depth`/`distance`/`within`, `flowbits` |

- **Hạn chế quan trọng:** so khớp **từng gói**, không ráp dòng TCP (stream reassembly), nên payload bị chia ở ranh giới 2 segment sẽ lọt; không chuẩn hoá HTTP (không URL-decode), vì vậy rule phải tự liệt kê `%20`, `+`, `/**/`; mù trước HTTPS.
- **False positive:** tài liệu hoặc diễn đàn có chứa chuỗi `<script>`; scanner bảo mật bạn tự chạy. Regex SQLi đòi khoảng trắng/encode giữa `union` và `select` nên URL `/docs/union-station-select-menu` không bị báo (`test_benign_http_is_quiet`).
- **Né:** double-encode (`%2555NION`), chèn comment/đổi hoa thường, chia gói, dùng HTTPS, biến thể chưa có rule (zero-day). Phòng thủ thật: engine có reassembly + normalization (buffer `http.uri` của Suricata), WAF, vá lỗi.
- **Trùng rule là chuyện thường:** 7 request của kịch bản `web_attacks` sinh 9 alert. Request path traversal khớp cả 1000004 lẫn 1000005 (`/etc/passwd`); request Shellshock khớp thêm 1000009 vì payload chứa `/bin/bash -c`.
- **MITRE:** theo từng rule: T1190, T1189, T1083, T1005, T1059, T1595.002, T1040, T1571, T1071, T1090.003, T1496, T1021.002.
- **Wireshark:**

| Filter | Thấy gì |
|---|---|
| `http.request.uri contains "UNION"` | SQLi UNION SELECT |
| `http.request.uri matches "(?i)union.*select"` | Như trên, không phân biệt hoa thường |
| `http.request.uri contains "%20OR%201=1"` | SQLi tautology |
| `http.request.uri contains "<script>"` | XSS |
| `http.request.uri contains "../"` | Path traversal |
| `frame contains "${jndi"` | Log4Shell |
| `http.user_agent contains "() {"` | Shellshock |
| `http.user_agent contains "sqlmap"` | Công cụ scan |
| `ftp.request.command == "PASS"` | Mật khẩu FTP cleartext |
| `tcp.port == 4444` | Reverse shell (chuột phải → Follow → TCP Stream để đọc lệnh `whoami`) |
| `frame contains "mining.subscribe"` | Stratum mining |

### 4.9 C2 beaconing: [beacon.py](../mini_ids/detectors/beacon.py)

- **Tấn công:** sau khi nhiễm, implant (Cobalt Strike, Sliver, Metasploit...) "gọi về nhà" theo chu kỳ để nhận lệnh.
- **Dấu hiệu:** kết nối mới lặp lại tới cùng `(dst, port)` với khoảng cách đều tăm tắp; payload nhỏ và cỡ giống nhau.
- **Cách code phát hiện:** chỉ xét TCP SYN thuần từ `home_net` ra ngoài, `dport` không thuộc `allow_ports`; bỏ SYN cách lần trước dưới 0,5 s (retransmit). Lưu 20 mốc gần nhất theo `(src, dst, dport)`; khi đủ `min_events` mốc thì tính các khoảng cách Δ:
  - trung bình μ phải nằm trong `[min_interval, max_interval]`;
  - **CV = σ / μ** (hệ số biến thiên) ≤ `max_cv` → **high**.
  - Ví dụ: C2 cứ 2 s ±2% có CV ≈ 0,01. Người dùng thật có khoảng cách gần phân phối mũ, mà phân phối mũ có σ = μ nên CV ≈ 1 (`test_beacon_regular_vs_random`).
- **Tham số:** `min_events: 6`, `min_interval: 1.0`, `max_interval: 3600`, `max_cv: 0.1`, `allow_ports: [53, 123]`.
- **False positive:** phần mềm hợp lệ polling định kỳ: kiểm tra cập nhật, telemetry, heartbeat của agent giám sát/antivirus, thiết bị IoT báo trạng thái. Cần allowlist theo đích hoặc ứng dụng.
- **Né:** jitter lớn (Cobalt Strike cho cấu hình jitter theo %) đẩy CV vượt 0,1; ngủ rất lâu (lịch sử bị xoá khi im lặng quá 2 × `max_interval`); đổi IP C2 liên tục (khoá chứa `dst`); giữ một kết nối lâu dài (không có SYN mới); dùng UDP/QUIC/DNS. Hướng vá: phân tích dài hạn (RITA), histogram khoảng cách, độ đều của kích thước payload, JA3/JA4.
- **MITRE:** T1071, T1573.
- **Wireshark:** `ip.dst == 203.0.113.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0`, rồi View → Time Display Format → "Seconds Since Previous Displayed Packet": cột Time hiện khoảng 2,0 ở mọi dòng. Kịch bản có 9 kết nối; alert bật ở kết nối thứ 6 (t≈170).

### 4.10 Data exfiltration: [exfil.py](../mini_ids/detectors/exfil.py)

- **Tấn công:** sau khi chiếm quyền, kẻ tấn công gom dữ liệu rồi đẩy ra ngoài, thường qua HTTPS tới cloud storage hoặc máy chủ riêng.
- **Dấu hiệu:** một host nội bộ gửi lượng byte ra một đích bên ngoài lớn bất thường trong thời gian ngắn; upload lớn hơn download rất nhiều.
- **Cách code phát hiện:** `WindowSum` khoá `(src, dst)` với `src ∈ home_net` và `dst ∉ home_net`; cộng `pkt.length` (cả header) của mọi giao thức trừ ARP; tổng ≥ `threshold_bytes` trong `window` → **high**. Chỉ chiều đi ra (tải về nhiều không bị báo, xem `test_exfil`).
- **Tham số:** `window: 300`, `threshold_bytes: 50000000` (50 MB/5 phút); [demo.yaml](../config/demo.yaml) hạ xuống 5 MB vì kịch bản chỉ đẩy khoảng 6 MB. Ngưỡng đúng phụ thuộc từng máy: máy chủ backup khác hẳn laptop kế toán.
- **False positive:** backup cloud (OneDrive, Google Drive), upload video, gửi file lớn qua chat, `git push` repo lớn, cuộc gọi video HD (upload khoảng 2 Mbps × 300 s ≈ 75 MB, đã vượt 50 MB).
- **Né:** "low and slow" (vài MB mỗi giờ); chia qua nhiều đích (khoá theo `dst`); đẩy lên dịch vụ cloud hợp lệ đã được allowlist; exfil qua DNS/ICMP (các detector khác lo).
- **MITRE:** T1048, T1041 (dùng dịch vụ web/cloud: T1567).
- **Wireshark:** `ip.src == 192.168.1.30 && ip.dst == 198.51.100.200`. Statistics → Conversations → IPv4, sắp theo "Bytes A → B": khoảng 6 MB trong 3 s. Gói 40 KB lớn hơn MTU 1.500 thực tế, vì dữ liệu giả lập được đơn giản hoá cho gọn.

### 4.11 Traffic spike (EWMA z-score): [anomaly.py](../mini_ids/detectors/anomaly.py)

- **Tấn công:** bất cứ thứ gì làm lưu lượng vọt lên: flood, exfil lớn, worm lây lan, scan tốc độ cao. Detector này không cần biết trước tấn công.
- **Dấu hiệu:** số gói/giây (pps) hoặc byte/giây (bps) vượt xa mức thường ngày.
- **Cách code phát hiện:** mỗi giây là một điểm dữ liệu. EWMA ước lượng trung bình và phương sai "trôi" theo thời gian:

```
μ  ← μ + α·(x − μ)
σ² ← (1 − α)·(σ² + α·(x − μ_cũ)²)
z  = (x − μ) / max(σ, σ_min)       σ_min = max(min_std_ratio·μ, 1)   (bps: 1000)
```

  - Chỉ báo sau `warmup` giây học, khi (`z_pps >= z_threshold` **và** pkts ≥ `min_pps`) hoặc (`z_bps >= z_threshold` **và** bytes ≥ `min_bps`) → **medium**.
  - Chỉ nêu "thủ phạm" nếu một nguồn chiếm ≥ 50% số gói của giây đó (flood từ IP giả thì không ai trội).
  - **Chống baseline poisoning:** giây bất thường chỉ được học với `α/20`. Một cú flood không kéo baseline lên, nhưng nếu mức traffic mới kéo dài (vd tải file lớn) thì baseline vẫn dần thích nghi: trí nhớ hiệu dụng khoảng 1/α = 20 s cho giây thường và khoảng 400 s cho giây bất thường.
  - `σ_min` tồn tại vì mạng cực ổn định có σ ≈ 0, khi đó thay đổi nhỏ nhất cũng cho z khổng lồ. `MAX_GAP = 60` ngăn pcap có khoảng trống dài bị "lấp" bằng hàng nghìn giây rỗng.
- **Tham số:** `alpha: 0.05`, `warmup: 60` (demo 20), `z_threshold: 5.0`, `min_pps: 200`, `min_bps: 1000000`, `min_std_ratio: 0.1`. α lớn thì thích nghi nhanh nhưng dễ bị "dạy hư"; `min_pps`/`min_bps` chặn báo động trên mạng nhỏ, nơi z cao mà giá trị tuyệt đối vô hại.
- **False positive:** Windows Update, tải game, backup ban đêm, và nói chung mọi thứ "lớn nhưng hợp lệ"; nhịp ngày đêm (một baseline chung không biết tính mùa vụ).
- **Né:** tăng dần từ từ để baseline đi theo; giữ mỗi giây dưới `min_pps`/`min_bps`; và quan trọng nhất: phần lớn xâm nhập thật không tạo nhiều traffic.
- **MITRE:** T1498.
- **Wireshark:** Statistics → I/O Graphs, khoảng 1 s: đỉnh ở t≈80 (synflood), t≈100 (icmp_flood); đổi trục Y sang Bytes để thấy đỉnh exfil ở t≈190.

### 4.12 ML: Isolation Forest trên flow: [ml.py](../mini_ids/detectors/ml.py), [iforest.py](../mini_ids/iforest.py), [flows.py](../mini_ids/flows.py)

**Mục tiêu:** bắt flow "lạ" mà không rule nào mô tả. Đây là học **không giám sát**: chỉ cần traffic bình thường để học, không cần nhãn tấn công.

**Isolation Forest** (Liu, Ting & Zhou, 2008), viết tay bằng numpy:

- Điểm bất thường thì "ít và khác", nên bị **cô lập sau rất ít nhát cắt ngẫu nhiên**. Điểm bình thường nằm giữa đám đông phải cắt nhiều lần mới tách riêng được.
- Mỗi cây lấy ψ = `sample_size` (256) mẫu, chọn ngẫu nhiên một feature có min < max và một ngưỡng ngẫu nhiên trong [min, max], chia đôi, lặp lại tới khi cô lập hoặc chạm độ sâu ⌈log₂ψ⌉ = 8. Có `n_trees` = 100 cây.
- Điểm: `s(x) = 2^(−E[h(x)] / c(ψ))`, trong đó `c(ψ) = 2(ln(ψ−1) + γ) − 2(ψ−1)/ψ ≈ 10,24` với ψ = 256.
- Đọc số: E[h] = c(ψ) cho s = 0,5 (bình thường); s = 0,70 ứng với E[h] ≈ 5,3 nhát cắt; E[h] → 0 cho s → 1.
- `path_lengths()` đi cây cho mọi mẫu cùng lúc (vector hoá). Model lưu dạng JSON.

**Pipeline trong `MLAnomalyDetector`:**

1. `process()` chỉ đưa TCP/UDP vào `FlowTable` (ICMP bị bỏ, xem 2.4).
2. `tick()` lấy các flow đã hết hạn. Chưa có model và `auto_train: true` thì gom `train_flows` (300; demo 250) flow đầu phiên → `train_model()` → lưu `model_file`. Hoặc train trước bằng `python -m mini_ids train normal.pcap`.
3. Có model rồi thì chấm điểm từng flow (tối đa 5.000 flow mỗi tick).
4. **Ngưỡng** = `max(min_score, p99)`: `min_score` = 0,70, p99 là phân vị 99 của điểm trên chính dữ liệu học. Ngưỡng 0,66 trước đây cho khoảng 4 FP mỗi 3 phút nên đã được nâng lên.
5. **Gom alert:** một nguồn có ≥ 3 đích bất thường thì gom theo nguồn (scan/sweep); còn lại gom theo đích (flood từ IP giả). Mức **medium** nếu `s >= ngưỡng + 0,05` hoặc nhóm có ≥ 10 flow, còn lại **low**.
6. **Giải thích (explainability):** z-score từng feature so với trung bình lúc học; nêu 3 feature lệch nhất cùng các feature nằm ngoài miền đã học. Analyst cần biết *vì sao* model nghi ngờ.

**Novelty check: vá hai điểm mù của Isolation Forest.** `combined_scores()` cộng thêm `NOVELTY_WEIGHT = 0.08` cho **mỗi** feature nằm ngoài `[min, max]` đã học (±10% biên), điểm tối đa 1,0.

- *Điểm mù 1: feature hằng số.* iForest chỉ cắt trên feature có min < max trong mẫu. Cờ RST bằng 0 ở **mọi** flow bình thường, nên feature `rst` không bao giờ được chọn để cắt, và flow scan có RST = 1 không bị cô lập nhanh hơn chút nào. Khi replay, alert ML của kịch bản portscan ghi đúng lý do: `rst ngoài miền đã học`, `log_bwd_bytes ngoài miền đã học`.
- *Điểm mù 2: ngoại lai theo một trục.* Điểm chỉ lệch mạnh ở 1 chiều và bình thường ở 11 chiều còn lại sẽ có điểm yếu, vì phần lớn nhát cắt chọn chiều mà điểm đó nằm giữa đám đông (`test_novelty_check_covers_axis_aligned_outlier`). Extended Isolation Forest cắt bằng siêu phẳng xiên để giảm thiên lệch theo trục.

**Điều ML không làm được: bài học quan trọng nhất của mục này.** Khi thử trên các kịch bản, flow-level ML **không tách được** SSH brute force, DGA và web attack (SQLi, XSS...) khỏi flow bình thường:

- Mỗi flow brute force chỉ là một phiên SSH ngắn; mỗi query DGA là một cặp DNS query/response bình thường; request SQLi có hình dạng flow y hệt một request HTTP. Tấn công nằm ở **tần suất** hoặc **nội dung**, không nằm trong 12 con số của một flow.
- Ngược lại, ML nổi bật ở những gì làm méo hình dạng flow: scan (RST, không phản hồi), SYN flood (`syn_ratio` = 1), exfil (`mean_fwd_size` z ≈ 3000), reverse shell, FTP, mining (port lạ, thời lượng lạ).
- Vì thế IDS thật luôn **kết hợp signature + detector chuyên biệt + anomaly + ML**.

**Hạn chế khác:** nếu lúc học mạng đã bị xâm nhập, model coi traffic độc là bình thường; model học trên mạng này không dùng được cho mạng khác (bài tập 15); ML cho ra "điểm nghi ngờ", không phải kết luận.

**Tham số:** `model_file: models/iforest.json` (demo `models/iforest-demo.json`), `auto_train: true`, `train_flows: 300`, `flow_idle_timeout: 15`, `min_score: 0.70`, `n_trees: 100`, `sample_size: 256`. Muốn học lại từ đầu thì xoá file model.

**Wireshark:** trường `example` của alert ML cho 5-tuple. Lọc bằng `ip.addr == A && tcp.port == P`, rồi Statistics → Conversations để so thời lượng và số byte với các flow xung quanh.

---

<a id="s5"></a>
## 5. Thực hành với Wireshark

### 5.1 Sinh file pcap

```powershell
python -m mini_ids gen-pcap captures/demo-attacks.pcap
```

Lệnh chỉ **ghi file**, không gửi gói nào ra mạng. Mặc định `--seed 1337 --warmup 60 --gap 10`, được khoảng 25.000 gói trong 240 giây: 60 giây đầu chỉ có traffic bình thường (HTTPS, DNS, HTTP nội bộ, NTP, ARP, ping), sau đó kịch bản thứ *i* (đếm từ 0, theo thứ tự trong `SyntheticTraffic.scenarios`) bắt đầu tại **60 + 10·i giây**. Lệnh cũng in sẵn bảng này ra màn hình. Muốn một file chỉ chứa vài kịch bản: `--scenarios portscan,dga`.

Gói đầu tiên nằm ở t = 0, nên cột Time mặc định của Wireshark ("Seconds Since Beginning of Capture") khớp đúng bảng dưới. Để lọc đúng khung của một kịch bản: `frame.time_relative >= 60 && frame.time_relative < 70`.

| t (s) | Kịch bản | Ai → ai | Filter gợi ý | mini-IDS báo (replay với demo.yaml) |
|---|---|---|---|---|
| 60 | `portscan` | 198.51.100.23 → 192.168.1.10 | `ip.src == 198.51.100.23` | Vertical port scan (high) |
| 70 | `stealth_scan` | 198.51.100.24 → .10 | `tcp.flags == 0x029` | TCP XMAS / NULL / FIN scan (medium) |
| 80 | `synflood` | IP giả ngẫu nhiên → .10:80 | `tcp.dstport == 80 && tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN flood phân tán (critical) + Traffic tăng đột biến |
| 90 | `ping_sweep` | 192.168.1.66 → .2 tới .41 | `icmp.type == 8 && ip.src == 192.168.1.66` | Ping sweep (medium) |
| 100 | `icmp_flood` | 203.0.113.50 → .10 | `icmp.type == 8 && ip.src == 203.0.113.50` | ICMP ping flood (high) + ICMP payload lớn (low) |
| 110 | `ssh_bruteforce` | 203.0.113.77 → .10:22 | `tcp.dstport == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0` | Brute-force SSH (high) |
| 120 | `dns_tunnel` | 192.168.1.30 → DNS .1 | `dns.qry.type == 16` | DNS tunneling (high) + dài / entropy / TXT (medium) |
| 130 | `dga` | 192.168.1.20 ↔ DNS .1 | `dns.flags.rcode == 3` | Quá nhiều NXDOMAIN (high) |
| 140 | `arp_spoof` | MAC `de:ad:be:ef:00:01` giả làm .1 | `arp.opcode == 2` | ARP spoofing: IP đổi MAC (high) |
| 150 | `web_attacks` | 198.51.100.99 → .10:80 | `http.request` | 9 alert signature (SQLi, XSS, traversal, Log4Shell, Shellshock...) |
| 160 | `c2_beacon` | 192.168.1.20 → 203.0.113.200:8443 | `ip.addr == 203.0.113.200` | Beaconing định kỳ (high), bật ở t≈170 |
| 170 | `reverse_shell` | 192.168.1.66 → 203.0.113.44:4444 | `tcp.port == 4444` | Rule 1000201 port reverse shell (high) |
| 180 | `blacklist` | 192.168.1.40 → 203.0.113.66 | `ip.addr == 203.0.113.66` | Domain + IP trong blacklist (high) |
| 190 | `exfil` | 192.168.1.30 → 198.51.100.200:443 | `ip.dst == 198.51.100.200` | Nghi exfiltration (high) + Traffic tăng đột biến |
| 200 | `ftp_cleartext` | 192.168.1.20 → 203.0.113.21:21 | `ftp` | FTP login cleartext (medium) |
| 210 | `crypto_mining` | 192.168.1.40 → 203.0.113.150:3333 | `frame contains "mining"` | Crypto-mining Stratum (high) |

Ngoài các alert trên, ML thường báo thêm "Flow bất thường (ML)" ở portscan/stealth_scan, dns_tunnel, reverse_shell, exfil, ftp_cleartext (có khi cả c2_beacon, crypto_mining, tuỳ model đang dùng), nhưng không báo ở ssh_bruteforce, dga, web_attacks (xem 4.12).

### 5.2 Các công cụ Wireshark nên dùng

| Công cụ | Menu | Dùng để |
|---|---|---|
| Protocol Hierarchy | Statistics → Protocol Hierarchy | Xem tỉ lệ TCP/UDP/DNS/HTTP/ARP; giao thức lạ nổi lên ngay |
| Conversations | Statistics → Conversations | Tab IPv4/TCP, sắp theo Packets/Bytes: thấy 120 hội thoại của portscan, khoảng 1.500 nguồn SYN flood, 6 MB exfil |
| Endpoints | Statistics → Endpoints | Host nào nói nhiều nhất (top talkers) |
| I/O Graphs | Statistics → I/O Graphs | Thêm đồ thị với filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` và `icmp.type == 8`; đổi Y sang Bytes để thấy exfil |
| DNS | Statistics → DNS | Phân bố qtype, rcode (TXT, NXDOMAIN) |
| Follow Stream | Chuột phải → Follow → TCP Stream | Đọc nguyên văn phiên FTP (`PASS hunter2`), reverse shell (`whoami`), request SQLi |
| Expert Information | Analyze → Expert Information | Cảnh báo có sẵn của Wireshark, vd ARP trùng địa chỉ |
| Cột tuỳ chỉnh | Chuột phải lên trường → Apply as Column | Thêm cột `dns.qry.name`, `http.user_agent`... |
| Khoảng cách thời gian | View → Time Display Format → Seconds Since Previous Displayed Packet | Đo chu kỳ beacon |

### 5.3 Replay bằng mini-IDS và so sánh

```powershell
python -m mini_ids replay captures/demo-attacks.pcap --config config/demo.yaml
```

- Mở http://127.0.0.1:8800 để xem alert. Replay mặc định chạy nhanh nhất có thể (nhanh hơn thời gian thực nhiều lần); đọc xong file thì dashboard vẫn mở tới khi bạn bấm Ctrl+C. Thêm `--speed 1` để phát lại theo thời gian thực và xem biểu đồ chạy; thêm `--no-web` nếu chỉ muốn đọc ở console.
- Vì sao cần `config/demo.yaml`: traffic giả lập ngắn hơn thực tế nên profile này hạ ngưỡng exfil xuống 5 MB, rút `anomaly.warmup` còn 20 s, dùng model ML riêng (`models/iforest-demo.json`, học từ 250 flow, idle timeout 5 s) và ghi log riêng (`logs/demo-alerts.jsonl`, `logs/demo.db`, `evidence/demo/`). Thử replay **không** kèm `--config`: exfil sẽ không bị báo (6 MB < 50 MB), một false negative do ngưỡng (bài tập 5).
- Xem lại alert: `python -m mini_ids alerts --demo -s high` hoặc `python -m mini_ids alerts --demo -d dns`.
- Đọc `logs/demo-alerts.jsonl`: mỗi dòng có `timestamp`, `event_type: "alert"` như EVE JSON của Suricata, cộng `detector`, `title`, `severity`, `src`, `dst`, `mitre`, `evidence`, `count`, `pcap`.
- Đối chiếu: mỗi alert, tìm lại đúng gói trong Wireshark bằng filter ở bảng 5.1. Nếu bạn không tự giải thích được vì sao một alert bật, đó là lúc đọc lại code của detector đó.

### 5.4 Mở evidence pcap của một alert

1. Trên dashboard, bấm vào một alert để mở ngăn chi tiết, rồi bấm **"Tải pcap"** (file `mini-ids-<id>.pcap`). Hoặc mở thẳng `evidence/demo/<id>.pcap`.
2. Mở bằng Wireshark. Hãy thử 3 alert để thấy 3 kiểu evidence (xem 3.6):
   - *FTP login cleartext*: hội thoại 192.168.1.20 ↔ 203.0.113.21, có cả `USER admin` lẫn `PASS hunter2` (evidence ghi trễ 5 giây). Dùng *Follow → TCP Stream* để đọc cả phiên đăng nhập.
   - *SYN flood phân tán*: alert chỉ có `dst`, nên pcap chứa mọi gói dính tới 192.168.1.10, lẫn cả HTTP bình thường. Bạn phải tự lọc bằng `tcp.flags.syn == 1 && tcp.flags.ack == 0`.
   - *Traffic tăng đột biến* trong lúc SYN flood: không xác định được thủ phạm nên không có pcap.
3. Với mỗi pcap, viết 2–3 câu kết luận TP/FP như một analyst thật, rồi bấm "Đánh dấu đã xử lý".

---

<a id="s6"></a>
## 6. Bài tập theo cấp độ

Trước khi bắt đầu, nên `git init` rồi commit để dễ hoàn tác. Sau mỗi bài: `python -m pytest` phải xanh (trừ khi bài yêu cầu cố ý làm đỏ một test để quan sát), và dọn `config/local.yaml` nếu bạn đã tạo (pytest không đọc file này, nhưng `demo`/`replay` thì có).

Mẹo cho các bài cần cấu hình riêng: tạo `config/lab.yaml` để không đụng log và model của demo:

```yaml
# config/lab.yaml: chỉ ghi các key cần đổi
logging: {alerts_jsonl: lab-alerts.jsonl, database: lab.db}
evidence: {dir: evidence/lab}
detectors:
  ml: {model_file: models/iforest-lab.json}
```

### Cấp 1: Quan sát

**BT1. Giải phẫu gói tin.**
- *Mục tiêu:* hiểu `from_scapy()` biến gói Scapy thành `PacketInfo` ra sao.
- *Gợi ý:* xem `test_from_scapy_tcp_http` và `test_from_scapy_dns_arp_icmp` trong [test_integration.py](../tests/test_integration.py). Viết test mới dựng `Ether()/IP()/TCP(flags="FPU")` và `TCP(flags="")`, chạy `from_scapy()`, rồi đưa `info.flags` vào `stealth_scan_type()` ([portscan.py](../mini_ids/detectors/portscan.py)).
- *Kiểm chứng:* `python -m pytest -k stealth` xanh; giải thích được vì sao `"FA"` không phải FIN scan.

**BT2. Săn dấu vết trong pcap.**
- *Mục tiêu:* tự tìm cả 16 kịch bản trong Wireshark **trước khi** xem alert.
- *Gợi ý:* bảng 5.1. Trả lời: mật khẩu FTP là gì? Chu kỳ beacon bao nhiêu giây? Có bao nhiêu subdomain khác nhau dưới `data-sync.example`? Port nào của web server đang mở (dựa vào SYN/ACK trong portscan)?
- *Kiểm chứng:* so với `python -m mini_ids alerts --demo -n 60`; beacon ≈ 2 s, 54 query TXT.

### Cấp 2: Ngưỡng, FP và FN

**BT3. Tìm điểm gãy của portscan.**
- *Mục tiêu:* thấy tận mắt FN khi ngưỡng quá cao và FP khi bỏ bớt ngoại lệ.
- *Gợi ý (FN):* trong `config/lab.yaml` thêm `portscan: {vertical_threshold: 121}` dưới `detectors`. Chạy `python -m mini_ids gen-pcap captures/scan.pcap --scenarios portscan` rồi `python -m mini_ids replay captures/scan.pcap --config config/lab.yaml --no-web`. Kịch bản chạm đúng 120 port: ngưỡng 121 thì im lặng, 120 thì bật ở port cuối cùng. ML có còn báo không? Đó là "defense in depth".
- *Gợi ý (FP):* copy `test_normal_browsing_is_not_a_scan` trong [test_detectors.py](../tests/test_detectors.py) thành test mới, thêm dòng `cfg.override({"detectors": {"portscan": {"horizontal_ignore_ports": [53, 123]}}})` trước khi tạo `PortScanDetector(cfg)`.
- *Kiểm chứng:* test mới **đỏ**: 40 kết nối HTTPS bình thường bị coi là horizontal scan. Đó là lý do port 443 nằm trong danh sách ngoại lệ mặc định.

**BT4. Brute-force "low and slow".**
- *Mục tiêu:* chứng minh một điểm mù bằng test, rồi vá nó.
- *Gợi ý:* trong [test_detectors.py](../tests/test_detectors.py), viết test gửi 40 SYN tới port 22, cách nhau 5 s (`pkt(ts=100 + i * 5, dport=22)`), rồi `assert run(det, ...) == []`: mỗi cửa sổ 60 s chứa tối đa 13 lần (dưới ngưỡng 15) nên `BruteForceDetector` lọt. Sau đó vá: thêm `WindowCounter` thứ hai với cửa sổ dài (vd 30 lần/1 giờ, tham số mới `long_window`, `long_threshold`), đổi test thành kỳ vọng có alert.
- *Kiểm chứng:* test mới xanh và `test_ssh_bruteforce` vẫn xanh.

**BT5. Ngưỡng phụ thuộc môi trường.**
- *Mục tiêu:* hiểu vì sao cùng một pcap cho kết quả khác nhau theo config.
- *Gợi ý:* `python -m mini_ids replay captures/demo-attacks.pcap --no-web` (config mặc định, log vào `logs/ids.db`), so với lần chạy có `--config config/demo.yaml`. Exfil biến mất (50 MB so với 5 MB). Sau đó mở một capture thật trên máy bạn (bài 17), dùng Statistics → Conversations tìm lượng upload lớn nhất trong 5 phút, rồi đề xuất `threshold_bytes` cho mạng nhà bạn.
- *Kiểm chứng:* `python -m mini_ids alerts -d exfil` (mặc định) so với `python -m mini_ids alerts --demo -d exfil`.

### Cấp 3: Signature, kịch bản, detector đầu tiên

**BT6. Rule: brute force trang đăng nhập WordPress.**
- *Mục tiêu:* viết rule YAML và hiểu vì sao cần "đếm".
- *Gợi ý:* thêm vào [rules.yaml](../config/rules.yaml):

```yaml
- id: 1000301
  name: "WordPress login POST"
  severity: low
  proto: tcp
  dst_port: [80, 8000, 8080, 8888]
  regex: '^POST /wp-login\.php'
  mitre: [T1110.001]
  description: "POST tới wp-login.php; count cao trong 60 s = dò mật khẩu."
```

  Rule YAML chưa có `threshold` như Suricata (`threshold: type threshold, track by_src, count 10, seconds 60;`), nên chính `count` do `AlertManager` gộp đóng vai "đếm số lần thử". Mở rộng (cấp 4): thêm trường `threshold` vào `Rule` và `SignatureDetector`.
- *Kiểm chứng:* thêm case vào `ATTACKS` trong [test_signatures.py](../tests/test_signatures.py): `(1000301, 80, b"POST /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\nlog=admin&pwd=1")`. Trong Wireshark dùng `http.request.method == "POST" && http.request.uri contains "wp-login.php"`.

**BT7. Rule: Bearer token lộ qua HTTP.**
- *Mục tiêu:* phát hiện token API đi qua kênh không mã hoá (T1040).
- *Gợi ý:* rule với `content: ["authorization: bearer "]` (viết thường vì `nocase` mặc định bật), `dst_port` là các port HTTP, `severity: medium`, `mitre: [T1040]`. So sánh với rule 1000102 (HTTP Basic). Nghĩ thêm: vì sao rule này vô dụng với HTTPS, và IDS nên làm gì với token đã lộ?
- *Kiểm chứng:* test dương tính với `Authorization: Bearer eyJ...`; test âm tính với `Authorization: Basic ...` (không được bật rule mới, nhưng vẫn bật 1000102). Wireshark: `http.authorization contains "Bearer"`.

**BT8. Thêm kịch bản vào bộ giả lập.**
- *Mục tiêu:* mỗi tấn công mới đều phải có dữ liệu thử và test hồi quy.
- *Gợi ý:* trong [synthetic.py](../mini_ids/capture/synthetic.py) viết `sc_wp_bruteforce(self, t)` theo mẫu `sc_web_attacks`: 20 lần `TcpConv(self, "198.51.100.77", 46000 + i, WEB_SERVER, 80)`, handshake, `c.client(...)` gửi `POST /wp-login.php`, `c.server(...)` trả `200 OK`, `c.close(...)`. Đăng ký ở **cuối** dict `self.scenarios`: `"wp_bruteforce": (self.sc_wp_bruteforce, ["signatures"], "Dò mật khẩu WordPress")`. Thêm ở cuối để thời điểm của 16 kịch bản cũ không đổi.
- *Kiểm chứng:* `SCENARIOS` trong [test_integration.py](../tests/test_integration.py) tự nhận kịch bản mới: `python -m pytest tests/test_integration.py -k wp_bruteforce`. `test_no_alert_before_attacks` vẫn phải xanh.

**BT9. Detector mới: SSH trên port lạ.**
- *Mục tiêu:* viết detector hoàn chỉnh đầu tiên.
- *Gợi ý:* tạo `mini_ids/detectors/ssh_port.py`:

```python
from mini_ids.detectors.base import Detector


class SshNonStandardPortDetector(Detector):
    name = "ssh_port"
    title = "SSH trên port lạ"
    description = "Banner SSH xuất hiện trên port khác 22 (backdoor, tunnel, né firewall)."
    mitre = ["T1571"]

    def process(self, pkt):
        if pkt.proto != "TCP" or not pkt.payload.startswith(b"SSH-"):
            return ()
        if 22 in (pkt.sport, pkt.dport):
            return ()
        return [self.alert(
            pkt, title=self.title, severity="medium", key=f"{pkt.src}<->{pkt.dst}",
            src=pkt.src, dst=pkt.dst,
            description=f"Banner {pkt.payload[:40]!r} trên {pkt.sport}->{pkt.dport}.",
            sport=pkt.sport, dport=pkt.dport)]
```

  Thêm class vào `ALL` trong [detectors/\_\_init\_\_.py](../mini_ids/detectors/__init__.py); thêm `ssh_port: {enabled: true}` vào `detectors` trong config (không bắt buộc, vì `enabled` mặc định là true).
- *Kiểm chứng:* test với `pkt(dport=2222, flags="PA", payload=b"SSH-2.0-OpenSSH_9.6\r\n")` có alert, còn `dport=22` thì không; `test_normal_traffic_is_quiet` vẫn xanh. Wireshark: `frame contains "SSH-2.0" && !(tcp.port == 22)`.

### Cấp 4: Detector nâng cao

**BT10. DHCP starvation và rogue DHCP.**
- *Mục tiêu:* mở rộng parser và viết detector cho tầng mà dự án chưa phủ.
- *Gợi ý:* thêm trường `dhcp_type` và `dhcp_chaddr` vào `PacketInfo`; trong `from_scapy()` đọc `BOOTP.chaddr` và option `message-type` của lớp `DHCP` (`scapy.layers.dhcp`). Starvation: số `chaddr` khác nhau gửi DISCOVER (type 1) trong 10 s vượt ngưỡng (công cụ kiểu Yersinia làm cạn pool). Rogue DHCP: OFFER (type 2) từ IP không nằm trong allowlist `dhcp_servers`. MITRE T1557.003.
- *Kiểm chứng:* test dựng `Ether()/IP(src="0.0.0.0", dst="255.255.255.255")/UDP(sport=68, dport=67)/BOOTP(chaddr=...)/DHCP(options=[("message-type", "discover"), "end"])` với 50 MAC ngẫu nhiên. Wireshark: `dhcp.option.dhcp == 1`.

**BT11. Blacklist theo TLS SNI.**
- *Mục tiêu:* soi được domain đích của HTTPS mà không giải mã.
- *Gợi ý:* ClientHello là gói TLS đầu tiên của client, SNI nằm ở dạng rõ:

```
Record:     0x16 | version(2) | length(2)
Handshake:  0x01 (ClientHello) | length(3) | client_version(2) | random(32)
            | session_id_len(1) + session_id | cipher_suites_len(2) + ... | compression_len(1) + ...
            | extensions_len(2) | { ext_type(2) | ext_len(2) | ext_data } ...
SNI (ext_type 0x0000): list_len(2) | name_type(1) = 0 | name_len(2) | host_name
```

  Parse từ `pkt.payload`, luôn kiểm tra biên trước khi đọc (dữ liệu do kẻ tấn công kiểm soát), rồi so với danh sách domain bằng `domain_matches()` trong [utils.py](../mini_ids/utils.py). Thực tế cần biết: ClientHello của trình duyệt mới (key share hậu lượng tử) có thể vượt một segment TCP; Encrypted Client Hello (ECH) giấu luôn SNI. MITRE T1071.001.
- *Kiểm chứng:* test với ClientHello dựng tay (hoặc bằng `scapy.layers.tls`) chứa SNI `update.malware-c2.example`; test với payload cụt/dị dạng không được ném exception. Wireshark: `tls.handshake.extensions_server_name contains "malware"`.

**BT12. TTL bất thường (dấu hiệu giả mạo IP).**
- *Mục tiêu:* dùng một trường header ít ai để ý.
- *Gợi ý:* TTL ban đầu thường là 64 (Linux/macOS), 128 (Windows), 255 (thiết bị mạng); TTL quan sát = TTL ban đầu − số hop. Học TTL phổ biến của mỗi IP nguồn (vd 20 gói đầu), báo khi một gói "cùng IP" lệch ≥ 5 hop: gói giả mạo đến từ vị trí mạng khác. **Lưu ý:** `SyntheticTraffic.ip()` gán cho mỗi host ngoài một TTL cố định (chọn từ `[52, 116, 118, 243]` theo `crc32` của IP). Phiên bản đầu từng chọn TTL ngẫu nhiên cho **mỗi gói**, khiến detector TTL báo nhầm hàng loạt: bài học thật là dữ liệu thử thiếu thực tế sinh ra FP "giả". Thử tạm đổi lại thành ngẫu nhiên để tự thấy hiện tượng đó.
- *Kiểm chứng:* unit test với `pkt(ttl=...)`; `test_normal_traffic_is_quiet` vẫn xanh khi bật detector mới. Wireshark: `ip.src == X` và thêm cột `ip.ttl`.

**BT13. Né và vá beacon detector.**
- *Mục tiêu:* đóng vai "red team" với chính detector của mình, rồi cải tiến nó.
- *Gợi ý:* trong `sc_c2_beacon`, đổi jitter `self.rng.uniform(0.98, 1.02)` thành `(0.6, 1.4)`. CV lúc đó khoảng 0,23 > 0,1 nên beacon lọt. Thử các hướng vá rồi đo FP: nâng `max_cv` lên 0,3; dùng độ lệch tuyệt đối trung vị (MAD) thay cho σ; xét độ đều của **kích thước payload** thay vì chỉ thời gian.
- *Kiểm chứng:* `python -m pytest tests/test_integration.py -k c2_beacon` đỏ sau khi đổi jitter và xanh sau khi vá; `test_beacon_regular_vs_random` (phần "human") vẫn phải im lặng.

### Cấp 5: ML, đánh giá, vận hành

**BT14. Đo precision/recall trên bộ kịch bản.**
- *Mục tiêu:* biến "có vẻ chạy tốt" thành con số.
- *Gợi ý:* lưu file `eval_scenarios.py` ở thư mục gốc dự án (dựa trên fixture `attack_run` của [test_integration.py](../tests/test_integration.py)) rồi chạy `python eval_scenarios.py`:

```python
import os, tempfile
from mini_ids.config import PROJECT_ROOT, Config
from mini_ids.capture.synthetic import SyntheticTraffic
from mini_ids.engine import Engine
from mini_ids.manager import AlertManager

START, WARMUP, GAP = 1_700_000_000.0, 60.0, 10.0
cfg = Config.load(PROJECT_ROOT / "config" / "demo.yaml")
cfg.override({"detectors": {"ml": {"model_file": os.path.join(tempfile.mkdtemp(), "m.json")}}})
gen = SyntheticTraffic(seed=1337, start=START)
names = list(gen.scenarios)
am = AlertManager(cooldown=60)          # không sink, không evidence: không ghi gì ra đĩa
eng = Engine(cfg, am)
for p in gen.timeline(warmup=WARMUP, gap=GAP, scenarios=names):
    eng.process_raw(p)
eng.finish()

tp, fp, found = 0, 0, set()
for a in am.recent:
    i = int((a.ts - START - WARMUP) // GAP)
    name = names[i] if 0 <= i < len(names) else None
    if name and a.detector in gen.scenarios[name][1]:
        tp += 1
        found.add(name)
    else:
        fp += 1
print(f"precision={tp / max(tp + fp, 1):.2f}  recall={len(found)}/{len(names)}")
```

  Rồi thảo luận: alert `anomaly` lúc SYN flood hay alert `ml` lúc exfil bị script tính là FP vì không nằm trong "detector mong đợi"; chúng có thật sự là FP không? Định nghĩa ground truth chính là phần khó nhất khi đánh giá IDS. Tiếp theo quét `ml.min_score` qua 0,60 / 0,66 / 0,70 / 0,80 và vẽ precision theo recall. Đếm thêm FP trên traffic sạch như `test_normal_traffic_is_quiet` (`timeline(duration=180, warmup=10_000, scenarios=[])`).
- *Kiểm chứng:* với cấu hình hiện tại, script in khoảng `precision=0.78  recall=16/16` (seed 1337, model học mới). Với `min_score` 0,66, số alert trên 3 phút traffic sạch phải tăng lên (quay lại lý do ngưỡng hiện tại là 0,70).

**BT15. Train ML trên traffic của chính bạn + thí nghiệm ablation.**
- *Mục tiêu:* hiểu dữ liệu học quyết định model, và mỗi phần của thiết kế đóng góp gì.
- *Gợi ý:* bắt 30–60 phút traffic bình thường trên mạng nhà bạn bằng Wireshark, lưu `captures/home-normal.pcapng`, rồi `python -m mini_ids train captures/home-normal.pcapng -o models/iforest-home.json` (cần ít nhất 50 flow, nên hơn 500; lệnh in score trung vị và p99). Chép `config/demo.yaml` thành `config/lab-ml.yaml`, đổi `ml.model_file` sang model mới và đổi tên log, rồi replay `demo-attacks.pcap`. Bạn sẽ thấy nhiều flow nền giả lập bị coi là lạ: model học ở mạng này không chuyển sang mạng khác (domain shift), cùng lý do model train trên CICIDS2017 thường kém trên mạng thật. Ablation: đặt `NOVELTY_WEIGHT = 0` trong [ml.py](../mini_ids/detectors/ml.py), chạy lại script BT14 và xem ML còn báo portscan không.
- *Kiểm chứng:* với `NOVELTY_WEIGHT = 0`, `test_novelty_check_covers_axis_aligned_outlier` đỏ như dự đoán. Khôi phục giá trị 0.08 sau khi xong.

**BT16. Cảnh báo qua Discord/Telegram.**
- *Mục tiêu:* đưa alert tới nơi con người thật sự nhìn.
- *Gợi ý:* tạo `config/local.yaml` (đã nằm trong `.gitignore`, **không bao giờ commit token**):

```yaml
alerting:
  webhook:
    enabled: true
    kind: discord                 # discord | slack | telegram | generic
    url: "https://discord.com/api/webhooks/<id>/<token>"
    min_severity: high
# Telegram: kind: telegram, url: "https://api.telegram.org/bot<TOKEN>/sendMessage",
#           telegram_chat_id: "<chat id>"
```

  `WebhookSink` trong [sinks.py](../mini_ids/sinks.py) gửi bằng một thread riêng, cách nhau ít nhất 1 s, hàng đợi tối đa 200, để mạng chậm không làm nghẽn IDS. Bảo mật: nội dung alert có thể chứa chuỗi do kẻ tấn công kiểm soát (vd tên DNS), nên payload Discord đã kèm `"allowed_mentions": {"parse": []}` để không ai lợi dụng IDS ping `@everyone`. Bài mở rộng: kiểm tra Slack/Telegram có cơ chế tương tự không.
- *Kiểm chứng:* `python -m mini_ids demo --scenarios synflood,ssh_bruteforce --warmup 25`: tin nhắn tới trong khoảng một phút.

**BT17. Bắt gói thật (live capture).**
- *Mục tiêu:* đối mặt với traffic thật và FP thật.
- *Gợi ý:* cài Wireshark (tick "Install Npcap") hoặc Npcap riêng. Nếu lúc cài chọn "Restrict Npcap driver's access to Administrators only" thì phải mở terminal bằng quyền Administrator. Chạy `python -m mini_ids interfaces` để lấy tên card, rồi `python -m mini_ids live -i "Wi-Fi"` (có thể thêm `-f "tcp or udp or icmp or arp"`). Dùng máy bình thường 30–60 phút; ghi lại mọi alert, phân loại TP/FP, và tinh chỉnh trong `config/local.yaml` (vd thêm domain vào `dns.allow_domains`). Lưu ý ML sẽ tự học từ 300 flow đầu phiên và lưu `models/iforest.json`; nếu lúc đó mạng có gì bất thường thì model học luôn cái bất thường đó.
- *Kiểm chứng:* một "nhật ký tinh chỉnh" gồm alert, kết luận, thay đổi config, lý do. Chỉ tự tạo traffic đáng ngờ (vd dùng nmap) nhắm vào **máy/VM của chính bạn** (xem phần 7).

**BT18. So sánh với Suricata và Zeek trên cùng pcap.**
- *Mục tiêu:* đặt mini-IDS cạnh công cụ công nghiệp.
- *Gợi ý:* trên Linux/WSL: `sudo suricata-update` (tải bộ rule ET Open), rồi `suricata -r captures/demo-attacks.pcap -l out/ -k none`. Lọc alert: `jq -c 'select(.event_type=="alert") | [.timestamp, .alert.signature, .src_ip, .dest_ip]' out/eve.json`. Với Zeek: `zeek -C -r captures/demo-attacks.pcap`, rồi đọc `conn.log` (cột `conn_state`: `S0` = SYN không phản hồi, gần với feature `no_reply`; `REJ` = bị RST từ chối), `dns.log` (`rcode_name` NXDOMAIN, `qtype_name` TXT), `http.log`, `ftp.log`. Ví dụ: `cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state | sort | uniq -c | sort -rn | head`.
- *Kiểm chứng:* một bảng 16 dòng (kịch bản × mini-IDS / Suricata ET Open / Zeek log) và 3 câu trả lời: kịch bản nào Suricata bắt mà mini-IDS lọt, và ngược lại; vì sao (stream reassembly, parser giao thức, hay phân tích hành vi theo thời gian)? Viết lại rule 1000001 bằng cú pháp Suricata dùng buffer `http.uri`.

---

<a id="s7"></a>
## 7. An toàn & pháp lý

- **Chỉ bắt gói và kiểm thử trên mạng, thiết bị của chính bạn, hoặc khi có cho phép bằng văn bản** ghi rõ phạm vi (dải IP), thời gian và kỹ thuật được dùng. Wi-Fi quán cà phê, trường học, công ty (kể cả khi bạn là nhân viên nhưng không có phê duyệt của bộ phận IT/an ninh) đều **không** phải nơi để thử.
- Bắt gói trên mạng dùng chung đồng nghĩa với thu thập dữ liệu cá nhân của người khác (tên miền họ truy cập, nội dung không mã hoá). Hãy báo trước cho người dùng chung mạng và xoá pcap khi không còn cần.
- Tham khảo pháp luật Việt Nam (tóm tắt thông tin, **không phải tư vấn pháp lý**):
  - **Luật An ninh mạng 2018** (Luật số 24/2018/QH14, hiệu lực từ 01/01/2019) quy định các hành vi bị nghiêm cấm trên không gian mạng, trong đó có tấn công mạng và xâm nhập trái phép.
  - **Bộ luật Hình sự 2015 (sửa đổi, bổ sung 2017)**, **Điều 289**: Tội xâm nhập trái phép vào mạng máy tính, mạng viễn thông hoặc phương tiện điện tử của người khác. Các điều liên quan: Điều 286 (phát tán chương trình tin học gây hại), Điều 287 (cản trở hoặc gây rối loạn hoạt động mạng máy tính, gần với DoS/flood), Điều 288 (đưa hoặc sử dụng trái phép thông tin mạng).
  - Văn bản pháp luật có thể được sửa đổi, hợp nhất hoặc thay thế; hãy tra bản hiện hành trên vbpl.vn hoặc thuvienphapluat.vn.
- **Dự án được thiết kế để an toàn khi học:**
  - Bộ giả lập [synthetic.py](../mini_ids/capture/synthetic.py) chỉ **dựng gói trong bộ nhớ**: `demo` đưa gói thẳng vào engine, `gen-pcap` chỉ ghi file. Trong `mini_ids/` không có lời gọi gửi gói nào (`send`, `sendp`, `sr1`...).
  - IP kẻ tấn công thuộc dải tài liệu RFC 5737; domain độc hại dùng TLD `.example` (RFC 2606).
  - `live` chỉ nghe (passive). Hai chỗ duy nhất kết nối ra Internet là `intel update` (tải feed) và webhook (nếu bạn bật).
- **Bảo vệ dữ liệu mà IDS thu được:** `evidence/*.pcap` và `logs/` chứa payload thật (mật khẩu cleartext, cookie, lịch sử DNS). Chúng đã nằm trong `.gitignore`; đừng đăng pcap thật lên GitHub hoặc diễn đàn. Nếu cần chia sẻ, hãy ẩn danh hoá trước (vd TraceWrangler, `tcprewrite`). Dashboard không có đăng nhập, nên chỉ để ở `127.0.0.1`.
- Các mục "Kẻ tấn công né ra sao" trong tài liệu nhằm giúp người phòng thủ biết điểm mù cần vá, không phải hướng dẫn tấn công hệ thống của người khác.

---

<a id="s8"></a>
## 8. Đi tiếp

| Chủ đề | Vì sao nên học tiếp |
|---|---|
| **Suricata** | IDS/IPS đa luồng với parser giao thức, stream reassembly và bộ rule ET Open. Log EVE JSON (`event_type`, `timestamp`) chính là hình mẫu của `logs/*.jsonl` trong dự án, nên bạn sẽ thấy quen ngay. |
| **Zeek** | Không chủ yếu dựa trên signature mà sinh log giàu ngữ cảnh cho từng giao thức (`conn.log`, `dns.log`, `http.log`, `ssl.log`) cùng ngôn ngữ script riêng; `conn.log` là phiên bản công nghiệp của `flows.py`, là nền của threat hunting. |
| **Snort 3** | IDS/IPS kinh điển, nguồn gốc cú pháp rule mà `rules.yaml` mô phỏng; Snort 3 viết lại đa luồng, cấu hình bằng Lua. |
| **Sigma** | Định dạng rule chung cho **log** (SIEM), chuyển được sang truy vấn Splunk/Elastic; là bước tiếp theo sau network detection: detection engineering trên log host. |
| **ELK / Wazuh / Security Onion** | Lưu trữ, tìm kiếm, tương quan alert ở quy mô lớn. Wazuh bổ sung HIDS; Security Onion gom sẵn Suricata + Zeek + Elastic thành một phòng lab NSM hoàn chỉnh. |
| **JA3 / JA4** | Fingerprint TLS ClientHello để nhận diện client (malware, công cụ) mà không cần giải mã. JA4 ra đời một phần vì Chrome xáo trộn thứ tự extension TLS, làm JA3 kém ổn định. |
| **NetFlow / IPFIX** | Bản ghi flow do router/switch xuất ra, dùng khi không thể lưu full pcap (doanh nghiệp, ISP). `FlowTable` và 12 feature là phiên bản thu nhỏ. |
| **Extended Isolation Forest** | Hariri và cộng sự: cắt bằng siêu phẳng ngẫu nhiên thay vì song song trục, giảm điểm mù "ngoại lai theo một trục" ở mục 4.12. Thử viết lại `_grow()` trong `iforest.py`. |
| **CICIDS2017** | Dataset có nhãn (pcap + flow CSV từ CICFlowMeter) với DoS, DDoS, brute force, web attack, botnet, port scan: đo precision/recall trên dữ liệu thật hơn. Đã có nghiên cứu chỉ ra lỗi gán nhãn, nên ưu tiên bản đã sửa. |
| **UNSW-NB15** | Dataset của UNSW Canberra với 9 nhóm tấn công và 49 feature, sinh bằng IXIA PerfectStorm: kiểm tra model có tổng quát hoá sang một mạng khác hay không. |

Đọc thêm: *The Practice of Network Security Monitoring* (Richard Bejtlich) cho tư duy NSM; *Applied Network Security Monitoring* (Chris Sanders, Jason Smith) cho quy trình thu thập, phát hiện và phân tích; RITA (Active Countermeasures) để xem phân tích beacon ở quy mô thật trên log Zeek.
